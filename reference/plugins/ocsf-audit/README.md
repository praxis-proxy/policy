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
| Schema | ad hoc | OCSF API Activity shape, with the [deviations from 1.9.0](#known-deviations-from-ocsf-190) listed below |

The engine produces the decision; this sink makes it portable and verifiable
offline, without the engine having to own a schema. The record format is
specified host-independently as
[AID-EMIT-1](https://github.com/Levaj2000/AI-Identity/blob/abc7bd887c0af23081d83f083319208b5f50987e/docs/specs/aid-emit-1.md),
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
  And the decision facts: `aid.decision` (verdict, the ordered per-plugin
  steps with the full action vocabulary including `deny_ignored` and
  `aborted`, a flat `deny_ignored` flag), `aid.span`,
  `aid.taint.input_labels`, `aid.content` (the engine's entry and
  emission digests) and `aid.stream` (`epoch`, `stream_id`, `stream_seq`,
  `emission_seq`). All of it is inside the hashed bytes, so the decision
  facts are tamper-evident. The `aid.*` and `cmf.*` prefixes are pinned by
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
  # gw-1:decision / gw-1:effect (this sink renders the decision stream
  # only; see below). The epoch is deliberately not a YAML value
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
      - read_workload
    config:
      exporters:                 # every record goes to each, byte for byte
        - { kind: file, path: /var/log/praxis/ocsf.ndjson, fsync: batch }
        - { kind: stderr }
      chain: true                # fingerprint chain, record_integrity profile
      signing: dsse              # or: none (chained but unsigned)
      signing_key_pem_path: /etc/praxis/ocsf-signing.pem   # PKCS#8 P-256
      signing_key_id: prod-2026-10         # JWKS kid -> unmapped.signature_key_id
      authority_uid: org-f3576cf6          # the party the signing key belongs to
      chain_uid: gw-1-2026-10-12           # one value per process, never shared by replicas
```

**Declare the capabilities.** A sink is filtered on the same terms as any
other plugin: the engine hands it a view built from its own `plugins:`
entry. Of the slots this sink maps, `request`, `mcp` and `completion` are
ungated, but the subject, `agent`, `delegation`, the security labels and
the caller's workload identity each sit behind a read capability. Omit one
and the records still emit, still chain and still verify, carrying no
`actor`, `ai_agent` or `delegation` block, no labels, or no
`cmf.workload_identity`. That is a silent evidence loss rather than a load
error: a verifier cannot tell "no delegation occurred" from "the sink was
not permitted to see it". Declare all five unless a deployment
deliberately withholds one.

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

**Decisions only.** The sink implements the decision entry point of
`AuditHandler` and leaves `on_effect` at its ignoring default, so no
`EffectRecord`, intent or outcome, token mints included, becomes an OCSF
event. The `gw-1:effect` stream the executor stamps never reaches this
sink's output; a deployment that needs it keeps the engine's effect log or
the `audit-logger` sink beside this one. Rendering effects as
class-correct OCSF events is a separate change.

## Chain scope

A chain lives for one process. `ChainState` starts at sequence zero with no
predecessor on every start, nothing is persisted, and the record and
attestation uids are `<chain_uid>-<seq>` and `<chain_uid>-att-<seq>`. So:

- uids are unique only within one process, and every process start is a
  new chain whose genesis record has no `prev_event`;
- two processes sharing a `chain_uid`, a restart or a replica, mint the
  same uids from `<chain_uid>-000000` up, and a consumer deduplicating by
  `metadata.uid` (AID-EMIT-1 section 6) discards the later records as
  replays;
- the default, `ocsf-chain-<plugin name>-<random>`, is minted per
  process, so records from different processes never share a uid; the
  cost is that nothing ties one process's chain to the next.

A configured `chain_uid` is yours to keep per process: do not share one
across replicas or reuse one after a restart. Tying one process's chain to
the next, which means a persisted sequence and a uid format that carries
the generation, is an AID-EMIT-1 revision rather than a change here, since
the uid is inside the hashed bytes.

**Ordering.** The chain lock covers sequence allocation and
canonicalization; signing and the write happen after it is released, so two
concurrent records can reach the destination in the opposite order from
their chain positions. Order by `prev_event` (or `aid.stream.stream_seq`),
never by arrival.

**Stalled output.** The sink awaits each write on the request path, but runs
its exporters on a blocking worker. The
engine's audit timeout can therefore release a request if that destination
stalls. At most four writes per emitter can remain in flight; later callbacks
wait for a slot before advancing the chain, and can time out while waiting.
A timed-out write can still finish later, so consumers must use the chain
links and stream stamps to detect gaps and order records.

At graceful shutdown the sink waits up to 10 seconds for those blocking
writes, then flushes its exporters (with a separate 10-second limit). A
timeout is reported as a shutdown error: records from a worker still blocked
at that point may not have reached every exporter. For file output, `fsync:
batch` and `fsync: always` sync the file and, on Unix, its parent directory
after an open or rotation, so the pathname is durable along with the records.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `exporters` | unset | Where records go, as a list. Each record is serialized once and written unchanged to every exporter, so the copies are byte-identical and share a `metadata.uid`. Kinds: `stderr` and `stdout` (one record per line), `file` (`path`, absolute; appended one record per line, created owner-only, never truncated; `fsync`: `never`, `batch` or `always`, default `never`; follows rename-based rotation on Unix by reopening the path, so use logrotate's `create` mode with `delaycompress` rather than `copytruncate`, which drops records written during the copy), and `tracing` (one event per record at target `ocsf.audit`). An exporter that fails is logged and the rest still run. An unwritable file fails startup. |
| `destination` | `stderr` | A single destination, `stderr` or `tracing`, the same as one entry in `exporters`. Set `destination` or `exporters`, not both. With neither, records go to stderr. |
| `product_name`, `vendor_name` | Praxis Policy Engine OCSF Audit / Praxis | `metadata.product`. |
| `chain` | `true` | Attach the attestation and declare `record_integrity`. |
| `chain_uid` | plugin name plus a random per-process suffix | `attestation.chain_uid`. One chain per process; a configured value must be unique per process (see [Chain scope](#chain-scope)). |
| `signing` | `none` | `none` (chained, unsigned) or `dsse`. |
| `signing_key_pem_path` | unset | PKCS#8 P-256 key file for `signing: dsse`; a missing key fails startup rather than emitting unsigned records. The factory requires this form because the engine retains its plugin config. |
| `signing_key_pem` | unset | Only for direct `OcsfAuditEmitter::new` use in tests and demos. The factory rejects inline keys, including when signing is off, because the engine would retain a printable copy in its authoritative config. |
| `signing_key_id` | unset | JWKS `kid`, stamped at `unmapped.signature_key_id`. |
| `authority_uid` | unset | The authority the key belongs to. Inside the hashed bytes; set it whenever signing is on. |
| `include_gap_fields` | `true` | Emit the `cmf.*` fields under `unmapped`. |

## Verifying a record offline

A verifier needs the emitted JSON, the authority's public key, and this
rule, which [`src/sign.rs`](src/sign.rs) implements as `signing_input`:

1. Remove `attestation_list[0].fingerprint` and `.signatures`.
2. Remove `unmapped.signature_b64` and `unmapped.signature_key_id`, and
   `unmapped` itself if that leaves it empty.
3. Serialize per RFC 8785: keys in UTF-16 code-unit order, compact,
   floats in the ES6 `Number::toString` form (`1.0` is `1`, `1e21` is
   `1e+21`). The set-derived arrays are already sorted at build time, so
   the emitted event is canonical. Parse integers exactly rather than
   through a double: `aid.stream.epoch` is a nanosecond value past 2^53,
   which Python's `json` keeps and a plain JavaScript `JSON.parse` does
   not. A float needs a correctly rounding parser for the same reason:
   `0.21000000000000002` and `0.21` are different doubles and canonicalize
   differently, so a parser that lands one ULP off recomputes a fingerprint
   that will not match. Python, JavaScript and Go round correctly; a Rust
   verifier needs `serde_json`'s `float_roundtrip` feature, which this
   workspace enables.
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
reproduces its vector byte for byte. The examples print every record
through `sign::canonical_order`, so the key order matches the vectors under
the `-p` builds below and under a workspace build, where feature
unification turns on `serde_json`'s `preserve_order`.

| Example | Vector | Shows |
|---|---|---|
| `emit_sample` | `SAMPLE-OUTPUT.md` | Two chained, signed post-hook records and the offline verification loop. |
| `decision_sink_demo` | `SAMPLE-OUTPUT-DECISIONS.md` | The five rulings: allow, allow after modification, deny, suppressed deny with an aborted branch, and a delegated mandate draw. |
| `provenance_demo` | `SAMPLE-OUTPUT-PROVENANCE.md` | The `aid.content` digests under the engine's keyed and unkeyed schemes, with the keys and bytes to recompute them. |
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

## Known deviations from OCSF 1.9.0

Checked against the 1.9.0 schema files (`events/application/api_activity`,
`objects/actor`, `objects/user`, `dictionary`). The `ai_agent`, `ai_model`,
`message_context`, `delegation` and `attestation_list` fields the mapping
uses are in the schema; these four are not:

| Emitted | Schema |
|---|---|
| `time` as an RFC 3339 string | `time` is `timestamp_t`, a millisecond epoch integer; the string form belongs in `time_dt`, which the `datetime` profile adds |
| `actor.roles` | `actor` has no `roles` member |
| `actor.user.groups` as strings | `user.groups` is an array of `group` objects |
| top-level `tool` and `resource` | the class carries `resources` (`resource_details[]`); there is no `tool` |

All four are inside the hashed bytes, so correcting them changes every
fingerprint and signature. They move with the deferred change to link chains
across process starts, in the next AID-EMIT-1 revision with regenerated vectors.
Until then a collector that validates against the schema needs to accept
these four, and a query on `time` must parse the string.
