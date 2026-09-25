<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# Auditing

PPE decides who may call which tool and what comes back. Auditing is the record
of those decisions, and of the irreversible acts its plugins perform to carry
them out.

There are two records and they answer different questions. A **decision** says
how the pipeline ruled on one request: which plugins ran, what each did, and
whether the request was allowed or blocked. An **effect** says what a plugin
did to the outside world, such as minting a token at an IdP. Effects outlive
the request and cannot be undone, which is why they are recorded separately and
before the fact rather than after it.

Both are off until configured.

What consumes them is a **sink**: a plugin the engine hands each record to,
which decides what the record looks like and where it goes. The engine builds
the records and owns when they are emitted; a sink only serializes. PPE ships
one, `audit-logger`, and a deployment needing a different format or destination
writes its own.

## What the engine promises

A verdict that was reached is emitted, and the record says what the caller was
told. Emission happens once per invocation, at the engine's return points
rather than in a pipeline phase, so allow, deny and modify all produce one
record and nobody has to reason about which phase runs before which deny.

The engine's return points, specifically, and not the executor's. The pipeline
is not the last thing that can change a verdict: the `assertions:` contract runs
after it and can refuse a request the pipeline allowed. A record emitted before
that would report a request as forwarded that the caller was refused, which is
worse than no record because it reads as evidence. The same holds at the other
end: a request denied before the pipeline starts, because no route resolved for
it, still produces a record. Those are the requests most worth having one for.

When an effect log is configured, a completed act has a durable record of its
intent. The record is `fsync`ed before the act happens, and if it cannot be
written the act does not happen. That is what makes a crash recoverable: an
intent with no outcome means the act may or may not have occurred, which is a
question the **participant** can be asked: the external system the act was
performed against, such as the IdP that would have minted the token.

Durable here means the record was written to the local filesystem and `fsync`ed
before the logging append returns, so it survives the process dying and the machine
losing power. The append that creates the log also syncs the directory
holding it, because a file's own `fsync` does not make the directory entry
naming it durable, and a crash in that window would otherwise leave no file at
all.

It does not mean the record is replicated, and it is only as good as the
storage underneath: a device that acknowledges a flush before the data is on
stable media will lose records a crash should have kept. Nothing above that
layer can detect it.

A plugin behaves the same whether or not auditing is on. There is no capability
a plugin needs and no setting that makes a working deployment stop working.
Turning auditing off costs the record, not the behavior.

A sink observes and does nothing else, and the engine enforces that rather than
trusting it. The extensions a sink is handed are filtered against the
capabilities its own `plugins:` entry declares, exactly as a hook plugin's are:
a sink that declares nothing sees the ungated slots, and one that wants headers
or credential material asks for `read_headers` or `read_inbound_credentials`
like anything else. A sink never receives the host's HTTP transport without
`perform_http`, and the view it gets refuses effects outright, so a sink
watching a plugin mint a token cannot write records under that plugin's name.

What the engine does not promise is that a record reached storage before the
response left. Sinks are awaited, but a sink that buffers internally before
writing to a network destination is past the point the engine can see.

## Turning it on

The reference `audit-logger` runs as a sink when it lists no hooks:

```yaml
plugins:
  - name: audit
    kind: audit/logger
    mode: audit
    capabilities:
      - read_subject           # sub / roles / teams
      - read_client            # client_id / client_name
      - read_labels            # the taint diff
      - read_delegated_tokens  # which audience got which scopes
    config:
      destination: stderr      # or `tracing`
      source: gateway-eu-1     # optional, stamped on every record
```

**A sink declares what it reads, like any other plugin.** The extensions it is
handed are filtered against its own `capabilities:`, so a sink that declares
nothing still runs, still emits a record per invocation, and still chains and
signs — with the gated fields simply absent. Nothing fails, and that is the
problem: a reader of the resulting record cannot tell "no delegation happened"
from "the sink was not permitted to see the delegation." Absence of evidence and
evidence of absence are the same bytes.

So work out which slots a sink reads and grant exactly those. `agent`,
`delegation`, `http`, `raw_credentials` and the `security` sub-fields — subject,
client, workload, labels — each need their grant. A verdict, the ordered plugin
actions, the entity called and the stream position need none, so a sink that
records only those is complete with no capabilities at all.

Any plugin becomes a sink by overriding `Plugin::as_audit_handler`. A sink has
two entry points. `handle` receives every decision. `on_effect` receives every
effect, and has a default that ignores them, so a sink that only cares about
verdicts implements nothing extra.

Effect records need a log:

```yaml
engine_settings:
  effect_log_path: /var/lib/praxis/effects.ndjson
  effect_log_compaction_threshold: 1024   # optional; 0 disables auto-compaction
```

With a path set, intent is durably recorded before a plugin acts. Without one,
effects still reach a sink's `on_effect`, but nothing survives a restart, so an
act interrupted by a crash leaves nothing behind to follow up.

The file holds one JSON record per line and is compacted in place: once an
effect has both an intent and an outcome the pair is dropped, so it tracks what
is in flight rather than growing without bound.

A crash can interrupt an append part-way through its write, leaving a final line
with no newline and possibly cut mid-character. Recovery treats that one line as
the interrupted append it is and discards it: it was never acknowledged, so the
act it guarded never proceeded. A line that will not parse anywhere else is
corruption, and recovery refuses rather than silently dropping a record that
accounts for an irreversible act.

Getting that wrong costs more than an unbounded file. A recovery that cannot
complete never runs reconciliation either, and since reconciliation results are
emitted to the sinks, the stream a consumer is verifying either falls quiet on
those transitions or carries an intent that was in fact settled. So the tolerance
for a torn tail is load-bearing for the evidence, not only for compaction.

The durable record carries no stream position. Positions are stamped when a
record is handed to the sinks, which is the stream they describe; the log is the
write-ahead record of what was attempted, and recovery re-stamps whatever it
resolves into the live stream anyway. Stamping earlier meant a refused write —
fail-closed, so the act correctly did not happen — still spent a sequence number
that nothing was ever emitted under, and a gap has to be read as something far
worse than the disk error it was.

What reconciliation concludes is emitted to the sinks. The resolving record is
appended and compacted away inside the same sweep, so the log is not where
anyone reads it — without the emit, an effect that spent a restart unaccounted
for would vanish with nobody told which way it went.

A host that wires plugins in code calls `PolicyEngine::set_effect_log` before
`initialize`. That install does not survive `load_config`, which rebuilds the
executor from the config it is given, so a log that has to outlive a reload
belongs in config.

A record says which plugins ran and how the pipeline ruled. It does not say
whether any of them changed the request on the way through. A **content hash**
answers that: a digest of the payload taken at entry and again at the end. Equal
digests mean nothing altered the content, different ones mean something did, and
a reader learns which without the audit trail holding either version.

Withholding the content is the point rather than a limitation. A redaction
plugin exists to take content out of a request, and writing that content into an
audit record puts it straight back. A digest says the content changed, or did
not, and nothing else about it.

```yaml
engine_settings:
  capture_content_provenance: true
```

Only payloads that opt in are hashed, which today means the CMF
`MessagePayload`. Anything else records no digest rather than a misleading one.
It is off by default because hashing sits on the request path.

One collector may gather records from several processes. Naming the stream
keeps them countable apart:

```yaml
engine_settings:
  audit_stream_namespace: gw-1
```

Stream ids become `gw-1:decision` and `gw-1:effect`. An empty or whitespace
value is refused at load, since it would compose `:decision`, which is neither
a bare label nor an attributable one.

The epoch has no YAML key on purpose. It defaults to the executor's boot time,
which advances on its own and is correct with no configuration. A host that
needs to set it does so in code, and takes on the invariant: the value has to
be strictly larger on every load, reloads included, because a reload builds a
fresh executor with the counters back at zero. Repeat an epoch and this
generation's records collide with the last one's, and a reader can no longer
tell a restart from records that went missing. A file cannot satisfy that,
which is why the key does not exist. PPE warns when the epoch fails to advance
across a reload, but still loads: the records are worth having even when the
completeness claim is compromised.

## The records

A decision:

```json
{
  "ts": "2026-09-06T10:15:00.123Z",
  "plugin": "audit",
  "verdict": { "deny": {
    "code": "not_permitted",
    "reason": "no grant covers this tool",
    "plugin": "cedar-pdp"
  }},
  "decision_steps": [
    { "plugin": "identity-jwt", "phase": "Sequential", "action": "allowed" },
    { "plugin": "cedar-pdp", "phase": "Sequential", "action": "denied",
      "detail": { "code": "not_permitted", "reason": "no grant covers this tool" } }
  ],
  "span": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id": "3c9f7d21e4075c68",
    "parent_span_id": "71e5093fd0c41822"
  },
  "taint": { "input": ["PII"], "final": ["CONFIDENTIAL", "PII"] }
}
```

`decision_steps` is in execution order. `action` is one of `allowed`, `denied`,
`deny_ignored`, `modified_payload`, `modified_extensions`, `aborted` or
`error`; the ones with something to say also carry `detail`.

`deny_ignored` means a plugin in a phase that cannot block asked to stop and was
overruled. It is not an allow, and a consumer mapping actions onto a disposition
that reads it as one will report the opposite of what the plugin asked for. The
verdict names nothing in that case, so the step is the only place the objection
survives.

`span` is W3C trace context, the same identifiers a tracing system uses to
stitch one end-to-end request back together out of the hops that served it. The
`trace_id` is shared by everything belonging to that request, the `span_id`
names this interception, and the `parent_span_id` names the call that caused it.
A reader with records from several hops can rebuild the order they happened in.
PPE stamps these but does not propagate trace context downstream, so chaining
across hops needs the host to carry it.

`taint` tracks security labels, the markers plugins attach to a request to
record what kind of data it is carrying, such as `PII`. Labels only accumulate,
never disappear, so the difference between the labels at entry and the labels at
the end is exactly what this node added.

`content` appears only with provenance enabled, holding `input_hash` and
`output_hash`.

`epoch`, `stream_id`, `stream_seq` and `emission_seq` place the record in the
audit stream, and they answer two different questions.

`stream_seq` counts records within one stream and never skips, so a reader who
sees 4 then 6 knows record 5 was lost rather than never written. That is the
claim a tamper-evident consumer needs, and it only holds within one `epoch`:
the counters restart with each executor, and `epoch` is the process generation,
so a smaller sequence under a larger epoch is a restart rather than a gap.

`emission_seq` is shared between decisions and effects. It says only what order
things happened in, so that a reader merging both streams can put them back in
sequence. Reading one stream on its own it looks full of holes, and those holes
are the other stream's records, not losses. Use `stream_seq` to check for loss
and `emission_seq` to order, never the reverse.

`stream_id` is the stream a record belongs to, `decision` or `effect`, prefixed
by the namespace when one is configured. The type suffix always survives, so a
consumer recovering it splits on the last colon rather than the first, since a
namespace may contain one.

A transition that recovery settled rides the `effect` stream like any other
effect record, dense with them and stamped from the live process, not the one
that crashed. It is not interleaved onto `decision`, and it does not get a
counter of its own: `stream_seq` is dense per `(epoch, stream_id)`, so a
per-record-kind counter would break exactly the check it exists for.

An effect is its own event:

```json
{
  "event": "effect",
  "effect_kind": "token_mint",
  "effect_state": "confirmed",
  "effect_key": "9f1c...",
  "effect_plugin": "oauth-delegator",
  "effect_details": { "audience": "https://hr.example.com", "scope": "read:compensation" }
}
```

`effect_plugin` is stamped from the plugin the executor was running, not from
anything the plugin supplied, so a record cannot claim to come from somewhere
it did not.

## Effects

An effect moves through four states.

| State | Meaning |
|---|---|
| `prepared` | Intent recorded. Nothing external has happened yet. |
| `confirmed` | The act completed. |
| `rejected` | The act provably did not happen. |
| `unknown` | Nobody can say. Reconcile it. |

`unknown` is the one that matters. A call that timed out may still have landed
at the participant with the answer lost coming back, so recording it as
`rejected` asserts no token was minted when nothing checked. The OAuth
delegator maps precisely: a non-2xx is `rejected`, a timeout or unreachable IdP
is `unknown`, and a 2xx whose body will not parse is `confirmed`, because the
token exists whether or not we managed to read it.

### Which phases may act

Only `sequential` and `transform`. A plugin in any other mode is refused, with
a violation naming the plugin, the mode and the key to change.

This is not about auditing and does not switch off with it. A concurrent branch
is cancelled when another branch short-circuits the phase, `audit` is read-only
by contract, and `fire_and_forget` runs after the verdict is returned. An act in
any of them happens for work the pipeline discarded, and an external act cannot
be discarded. A delegator configured in `concurrent` mode was minting a real
credential and having the result thrown away.

The same refusal applies to a copy of a plugin's extensions. Effects are
performed on the `&Extensions` a handler was given. A clone is detached from
the invocation that authorised it, and without the refusal a plugin could clone
its way around the phase rule.

### Recovery

A restart leaves whatever was in flight when the process stopped: intents whose
outcome was never written. Settling those is **reconciliation**, and it means
asking the participant that would have performed the act whether it did, using
the key the intent recorded. Only the participant knows.

`PolicyEngine::initialize` sweeps the log once, before traffic. Completed
effects are compacted away and the rest are reconciled with an external service
that can answer for the participant, if one is configured.

In practice there is nothing to configure. The question an orphaned intent
raises is "did this mint land at the IdP before we died", and an OAuth IdP has
no endpoint that takes a mint key and reports whether that token was issued, so
the question has nowhere to go. Nor is there a standard place to put the key on
the way out: neither RFC 6749 nor RFC 8693 gives the token endpoint an
idempotency or client-reference parameter. The OAuth delegator's
`idempotency_header:` names one for an IdP that honours a vendor-specific
header, and is unset by default so nothing invented reaches an IdP that never
asked for it.

The reconciler PPE ships by default connects to nothing. It records that the
effect is unresolved, and leaves it `unknown` for an operator to chase.

Whatever a reconciler does settle reaches the audit sinks as its own event. The
resolving record is compacted out of the log in the same sweep that writes it,
so the emit is where that answer surfaces.

A host with an authoritative issuance ledger, one that does know what was
minted, implements `EffectReconciler` and calls
`PolicyEngine::recover_effects_with`. The reconciler reads the self-describing
record and looks up `EffectRecord::key`, so it is specific to the participant at
most, never to the plugin.

`EffectRecord::key` must be unique per attempt. Recovery resolves keys across
the whole file, so a key reused across retries lets an earlier attempt's outcome
mask a later attempt's orphaned intent, and the one act nobody can account for
is the one skipped.

## Writing a sink

```rust
use std::sync::Arc;
use async_trait::async_trait;
use praxis_policy_core::audit::AuditHandler;
use praxis_policy_core::decision::{DecisionLog, Verdict};
use praxis_policy_core::effect::EffectRecord;
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

struct MySink { cfg: PluginConfig }

#[async_trait]
impl AuditHandler for MySink {
    async fn handle(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        let blocked = matches!(decisions.verdict(), Some(Verdict::Deny(_)));
        let _ = (payload, extensions, blocked);
    }

    // Optional. Effects only reach a sink that wants them.
    async fn on_effect(&self, _effect: &EffectRecord, _extensions: &Extensions) {}

    fn name(&self) -> &str { &self.cfg.name }
}

impl Plugin for MySink {
    fn config(&self) -> &PluginConfig { &self.cfg }

    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        Some(self)
    }
}
```

`handle` runs once per pipeline invocation. `on_effect` runs once per lifecycle
transition, so a completed mint calls it twice, once for the intent and once
for the outcome, and a consumer counting mints should count terminal states
rather than calls.

A sink fires for every hook family, so `payload` is not always a CMF
`MessagePayload`. Downcast and handle the case where it is not.

The executor awaits every sink before returning the pipeline result, so a
verdict that was emitted cannot be lost to a crash. The cost is that sink
latency is request latency. A sink writing to a network destination should hand
off to its own queue rather than block. Each call is bounded by the plugin
timeout and its panics are contained; a sink that fails is logged and skipped,
because the verdict is already decided and a lost record does not justify
failing the request.

## Performing an effect

```rust
use praxis_policy_core::effect::EffectRecord;

let intent = EffectRecord::prepared("token_mint", "exchange for hr-api", fresh_key())
    .with_detail("audience", "https://hr.example.com");

let token = ext.perform_effect(&intent, || async {
    idp.mint().await          // the irreversible act
}).await?;
```

`perform_effect` brackets the act so the protocol cannot be skipped or
reordered. If the intent cannot be recorded the act never runs. On success the
effect is `confirmed`, on failure `unknown`. A plugin that can tell a refusal
from a lost answer should call `begin_effect` and `complete_effect` directly and
classify the outcome itself, as the OAuth delegator does.

## What it costs

| Setting | Cost per invocation |
|---|---|
| Nothing configured | A length check. |
| A sink attached | A span, so two UUIDs and two allocations, plus the taint labels, plus the sink's work. |
| `effect_log_path` | One `fsync` per lifecycle transition. Effects are rare. |
| `capture_content_provenance` | One hash of the payload, plus one per sink. |

Provenance is built only when a sink will read it. Decision steps and the
verdict are recorded either way, since the phases record them as they run.

## When something is wrong

A denied request produces no record. Check the logger is in sink mode with no
`hooks:` listed; with hooks listed it is a post-hook observer and never runs on
the deny path.

`delegation.effects_not_permitted`, or an `effect_phase_not_permitted` error.
The plugin is in a mode that cannot perform irreversible acts. Set its `mode:`
to `sequential` or `transform`.

`effect_extensions_detached`. The plugin called `perform_effect` on a copy of
its extensions instead of the `&Extensions` passed to `handle`.

`delegation.effect_log_failed`. The phase is fine but the record could not be
written; check the path is writable. The delegation is denied rather than
minting a credential nothing accounts for.

Recovery reports unresolved effects at startup. Expected with the default
reconciler, which cannot confirm anything and leaves them `unknown`. Each names
its `key` and the plugin that caused it. Resolving them means asking the
participant, or installing a reconciler that can.

## See also

- [`assertions.md`](assertions.md) for what the engine puts on the wire
- `crates/ppe-core/src/audit.rs` for the sink trait
- `crates/ppe-core/src/decision.rs` for the decision log
- `crates/ppe-core/src/effect.rs` for effect records, the log and recovery
