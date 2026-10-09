# ocsf-audit

An audit sink for the Praxis Policy Engine that emits each decision as an
**OCSF API Activity event** (class 6003, with the `ai_operation` and
`security_control` profiles), optionally wrapped in a tamper-evident
**attestation chain** and DSSE-signed. Same contract as the `audit-logger`
reference sink: observation only, always allow, factory plus hook wiring.
The record shape is the difference:

| | `audit-logger` | `ocsf-audit` |
|---|---|---|
| Output | free-form JSON line | OCSF API Activity event |
| Verifiability | none | hash chain (`fingerprint` to `prev_event`), DSSE-signed (ECDSA P-256) |
| Schema | ad hoc | OCSF, so a SIEM ingests it without a bespoke parser |

The engine produces the decision; this sink makes it portable and verifiable
offline, without the engine having to own a schema. The record format is
specified host-independently as
[AID-EMIT-1](https://github.com/Levaj2000/AI-Identity/blob/395d64ed8bea695896af1557e530b0065145f593/docs/specs/aid-emit-1.md),
and the three `SAMPLE-OUTPUT*.md` files next to this README are its
conformance vectors.

## What a record carries

[`src/ocsf.rs`](src/ocsf.rs) is the executable mapping. In outline:

- **Base event.** `class_uid` 6003, `activity_id` from the content (2 Read
  for resources, prompts and tools with `readOnlyHint`; 99 Other with
  `activity_name` "Invoke Tool" or "Completion"), `time`, `severity_id`,
  `metadata.correlation_uid` from the conversation id, `metadata.uid` when
  chaining is on.
- **The ruling** (`security_control`). Deny: `action_id` 2 / `disposition_id`
  2 with the violation at `status_code` / `status_detail`. Allow after a
  modification: `action_id` 4. Plain allow: 1 / 1. A post-hook observation
  with no ruling: 3 Observed / 17 Logged.
- **Mapped objects.** `actor` (subject, roles, groups), `ai_agent` and its
  lineage, `ai_model` and `message_context`, `delegation` with its chain,
  `tool`, `api.request.uid` and `resource`.
- **`unmapped`.** Fields with no native OCSF home, under their source names:
  `cmf.completion.stop_reason`, `cmf.mcp`, `cmf.framework`,
  `cmf.security.labels`, `cmf.workload_identity`, `cmf.request.request_id`.
  And the decision facts: `cpex.decision` (verdict, the ordered per-plugin
  steps with the full action vocabulary including `deny_ignored` and
  `aborted`, a flat `deny_ignored` flag), `cpex.span`,
  `cpex.taint.input_labels`, `cpex.content` (the engine's entry and
  emission digests) and `cpex.stream` (`epoch`, `stream_id`, `stream_seq`,
  `emission_seq`). All of it is inside the hashed bytes, so the decision
  facts are tamper-evident. The `cpex.*` and `cmf.*` prefixes are pinned by
  AID-EMIT-1 and do not follow the engine's name.
- **`attestation_list[0]`** when `chain: true`: `uid`, `chain_uid`,
  `authority_uid`, `prev_event` (the predecessor's uid, `type_uid` and
  fingerprint), `fingerprint` (SHA-256 over the JCS canonical bytes of the
  whole event minus `fingerprint` and `signatures`) and, with a key,
  `signatures`. The signature bytes and the key id ride at
  `unmapped.signature_b64` / `unmapped.signature_key_id` until
  [ocsf-schema#1709](https://github.com/ocsf/ocsf-schema/pull/1709) gives
  them a schema home.

## Wiring

Omit `hooks:` and the plugin attaches as an audit sink
(`Plugin::as_audit_handler`), firing at every pipeline verdict, denials
included, with the executor's finalized `DecisionLog`:

```yaml
engine_settings:
  # Optional. Names the host, so the executor stamps its streams as
  # gw-1:decision / gw-1:effect. The epoch is deliberately not a YAML value
  # (a static file epoch cannot stay monotonic across boots); a host that
  # supplies one sets engine_settings.audit_epoch in code before load_config.
  audit_stream_namespace: gw-1

plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    mode: audit
    capabilities:
      - read_subject
      - read_agent
      - read_delegation
      - read_labels
    config:
      destination: stderr        # or: tracing
      chain: true                # fingerprint chain, record_integrity profile
      signing: dsse              # or: none (chained but unsigned)
      signing_key_pem_path: /etc/praxis/ocsf-signing.pem   # PKCS#8 P-256
      signing_key_id: prod-2026-10         # JWKS kid -> unmapped.signature_key_id
      authority_uid: org-f3576cf6          # the party the signing key belongs to
      chain_uid: org-f3576cf6              # stable chain id across the deployment
```

**Declare the capabilities.** A sink is filtered on the same terms as any
other plugin: the engine hands it a view built from its own `plugins:`
entry. Of the slots this sink maps, `request`, `mcp` and `completion` are
ungated, but the subject, `agent`, `delegation` and the security labels
each sit behind a read capability. Omit one and the records still emit,
still chain and still verify, carrying no `actor`, `ai_agent` or
`delegation` block and no labels. That is a silent evidence loss rather
than a load error: a verifier cannot tell "no delegation occurred" from
"the sink was not permitted to see it". Declare all four unless a
deployment deliberately withholds one.

**Listing hooks** turns the plugin into a CMF post-hook observer on those
hooks instead. That path sees allowed traffic only, since a denied request
never reaches a post hook, and a hook-listed instance deliberately does not
also attach as a sink, so one invocation never emits twice. Register prompt
hooks on `cmf.prompt_post_invoke`, the name the runtime dispatches; a
handler on `cmf.prompt_post_fetch` never fires.

[`examples/panic_drive.rs`](examples/panic_drive.rs) is the runnable form of
the sink wiring: a `PolicyEngine` loading exactly this shape through
`load_config`, with a plugin that panics, so the record it emits is a real
fail-closed deny on the host-named stream.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `destination` | `stderr` | One JSON object per line to stderr, or `tracing` at target `ocsf.audit`. |
| `product_name`, `vendor_name` | AI Identity OCSF Audit / AI Identity | `metadata.product`. |
| `chain` | `true` | Attach the attestation and declare `record_integrity`. |
| `chain_uid` | derived from the plugin name | `attestation.chain_uid`. Set it for a chain that survives restarts. |
| `signing` | `none` | `none` (chained, unsigned) or `dsse`. |
| `signing_key_pem`, `signing_key_pem_path` | unset | Exactly one, for `signing: dsse`. PKCS#8 P-256; a missing key fails startup rather than emitting unsigned records. |
| `signing_key_id` | unset | JWKS `kid`, stamped at `unmapped.signature_key_id`. |
| `authority_uid` | unset | The authority the key belongs to. Inside the hashed bytes; set it whenever signing is on. |
| `include_gap_fields` | `true` | Emit the `cmf.*` fields under `unmapped`. |

## Verifying a record offline

A verifier needs the emitted JSON, the authority's public key, and this
rule, which [`src/sign.rs`](src/sign.rs) implements as `signing_input`:

1. Remove `attestation_list[0].fingerprint` and `.signatures`.
2. Remove `unmapped.signature_b64` and `unmapped.signature_key_id`, and
   `unmapped` itself if that leaves it empty.
3. Serialize per RFC 8785 (sorted keys, compact). The set-derived arrays
   are already sorted at build time, so the emitted event is canonical.
4. SHA-256 of those bytes is `fingerprint.value`; the DSSE signature
   verifies over `"DSSEv1" SP 31 SP application/vnd.ocsf.event+json SP
   LEN(bytes) SP bytes`.

Because `prev_event` and the attestation's own identity are inside the
hashed bytes, a spliced, reordered or renumbered record changes its own
fingerprint and breaks every later link. `emit_sample` runs this loop and
prints the result as `// verify` lines; `SAMPLE-OUTPUT.md` carries the
Python form.

## Examples and conformance vectors

Timestamps, stream stamps and the demo signing key are fixed, so each run
reproduces its vector byte for byte.

| Example | Vector | Shows |
|---|---|---|
| `emit_sample` | `SAMPLE-OUTPUT.md` | Two chained, signed post-hook records and the offline verification loop. |
| `decision_sink_demo` | `SAMPLE-OUTPUT-DECISIONS.md` | The five rulings: allow, allow after modification, deny, suppressed deny with an aborted branch, and a delegated mandate draw. |
| `provenance_demo` | `SAMPLE-OUTPUT-PROVENANCE.md` | The `cpex.content` digests under the engine's keyed and unkeyed schemes, with the keys and bytes to recompute them. |
| `demo_stream` | | NDJSON driver with the stream stamps taken from the environment, for runners that need an epoch boundary between processes. |
| `panic_drive` | | A real plugin panic through `PolicyEngine`, landing as a `plugin_panic` deny on the host-named stream. |

```sh
cargo run -p praxis-policy-plugin-ocsf-audit --example emit_sample
cargo run -p praxis-policy-plugin-ocsf-audit --example decision_sink_demo
cargo run -p praxis-policy-plugin-ocsf-audit --example provenance_demo
cargo run -p praxis-policy-plugin-ocsf-audit --example panic_drive 2>panic.ndjson
```

The `emits_required_ocsf_base_fields` test checks structural conformance
only; validation against the published OCSF schema is not part of this
crate.
