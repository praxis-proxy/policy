# Sample output: `emit_sample`

Real OCSF events produced by the mapping in [`src/ocsf.rs`](src/ocsf.rs) from
the two demo turns in [`examples/emit_sample.rs`](examples/emit_sample.rs).
Deterministic: the timestamps are fixed and the demo signing key is derived
from a fixed scalar, so a re-run reproduces this file byte for byte. AID-EMIT-1
section 12 names this file as a conformance vector; the `// verify` lines at
the end are the example re-deriving every fingerprint and signature from the
emitted JSON and the public key alone.

```sh
cargo run -p praxis-policy-plugin-ocsf-audit --example emit_sample
```

Notes on fidelity:

- **Host class is API Activity (6003)** with its own activity enum: a tool call
  without `readOnlyHint` is the honest `activity_id: 99` with a source-defined
  `activity_name` ("Invoke Tool" / "Completion"); reads (resources, prompts,
  read-only-hinted tools) are `2 (Read)` with the normalized caption.
  `metadata.profiles` declares `ai_operation` and `security_control`, plus
  `record_integrity` when chained. These are post-hook observations, so the
  passive stream carries `action_id: 3 (Observed)` / `disposition_id: 17
  (Logged)`; `SAMPLE-OUTPUT-DECISIONS.md` has the deny and modify records.
- **Attestation shape.** Records carry `attestation_list[]`, each entry holding
  a `fingerprint` object (`algorithm_id` 3 = SHA-256, `encoding_id` 1 = Hex,
  `serialization_id` 2 = JCS, bare-hex `value`), a `chain_uid`, an attestation
  `uid`, and, from the second record on, a `prev_event` naming its predecessor
  by `uid` and `type_uid` and binding it by `fingerprint`.
- **The fingerprint commits to the record's chain position.** It is computed
  over the JCS-style canonical bytes of the whole event with
  `attestation_list[0]` present and carrying `uid` / `chain_uid` /
  `authority_uid` / `prev_event`, and only `fingerprint` / `signatures`
  excluded (plus the two post-hash signature extras under `unmapped`; the rule
  is running code, `sign::signing_input`). So a verifier does not need to know
  anything about this crate: strip those members, canonicalize per RFC 8785,
  recompute.
- **Signed, and independently verifiable.** `signing: dsse` produces
  ECDSA-P256-SHA256 over the DSSE PAE of the same canonical bytes the
  fingerprint covers (deterministic per RFC 6979, which is why this output is
  byte-identical across runs). `signatures[]` carries the `digital_signature`
  descriptor (`algorithm_id` 3 = ECDSA, `serialization_id` 5 = DSSE) and the
  raw bytes and JWKS `kid` ride in `unmapped.signature_b64` /
  `unmapped.signature_key_id` pending
  [ocsf-schema#1709](https://github.com/ocsf/ocsf-schema/pull/1709). The demo
  key is generated at runtime from a fixed scalar (no key material in the
  repo).
- **`attestation.authority_uid` names the party the signing credential belongs
  to** (`org-f3576cf6`, a demo org). It sits inside the hashed bytes, so the
  claimed authority cannot be swapped after the fact without breaking the
  fingerprint; keys rotate, so this is the stable identifier a verifier checks
  the resolved JWKS key against.
- **`metadata.correlation_uid` is the run id**
  (`AgentExtension.conversation_id`): both events of this run carry `"conv-9"`,
  so a SIEM can join them. It sits on `metadata`, which is where OCSF defines
  it. The per-call `tool_call_id` rides at `api.request.uid`. `metadata.uid`
  identifies the record itself, and is what the next record's `prev_event.uid`
  points at.
- **Key ordering is alphabetical** because the canonical form sorts object keys
  (`sign::canonical_bytes`, RFC 8785 order), and that is the only ordering a
  verifier depends on. The printed records happen to match it because
  `serde_json::Map` is backed by a `BTreeMap` without the `preserve_order`
  feature; the hashed bytes do not rely on that.

```jsonc
// ===== OCSF event 1 — Invoke Tool (get_compensation) =====
{
  "action": "Observed",
  "action_id": 3,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [
        "people-ops"
      ],
      "uid": "alice@corp.com"
    }
  },
  "ai_agent": {
    "conversation_uid": "conv-9",
    "instance_uid": "sess-42",
    "parent_uid": "orchestrator-1",
    "turn": 3,
    "uid": "agent-7"
  },
  "api": {
    "request": {
      "uid": "call-001"
    }
  },
  "attestation_list": [
    {
      "authority_uid": "org-f3576cf6",
      "chain_uid": "demo-chain-org-f3576cf6",
      "fingerprint": {
        "algorithm": "SHA-256",
        "algorithm_id": 3,
        "encoding": "Hex",
        "encoding_id": 1,
        "serialization": "JCS",
        "serialization_id": 2,
        "value": "254332470b92c69fc387bbe71f5233a76fd6065631a86c41fb1de335156a8bce"
      },
      "signatures": [
        {
          "algorithm": "ECDSA",
          "algorithm_id": 3,
          "serialization": "DSSE",
          "serialization_id": 5
        }
      ],
      "uid": "demo-chain-org-f3576cf6-att-000000"
    }
  ],
  "category_uid": 6,
  "class_uid": 6003,
  "delegation": {
    "actor_subject_uid": "agent-7",
    "chain": [
      {
        "audience": "workday-api",
        "scopes_granted": [
          "read_compensation"
        ],
        "subject_uid": "agent-7",
        "timestamp": "1970-01-01T00:00:00+00:00",
        "ttl_seconds": 300
      }
    ],
    "depth": 1,
    "origin_subject_uid": "alice@corp.com"
  },
  "disposition": "Logged",
  "disposition_id": 17,
  "metadata": {
    "correlation_uid": "conv-9",
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
    "uid": "demo-chain-org-f3576cf6-000000",
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-06-30T12:00:00.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-001"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.framework": {
      "framework": "langgraph",
      "framework_version": null,
      "graph_id": "graph-hr",
      "node_id": "node-compensation"
    },
    "cmf.mcp": {
      "tool": {
        "annotations": {},
        "name": "get_compensation",
        "namespace": "hr",
        "server_id": "hr-mcp"
      }
    },
    "cmf.security.labels": [
      "PII",
      "secret"
    ],
    "cmf.workload_identity": {
      "attested_at": null,
      "attestor": "gke-workload-identity",
      "spiffe_id": "spiffe://corp/agent/hr-bot",
      "trust_domain": "corp"
    },
    "signature_b64": "MEYCIQCZaHnA2NwS9ohiCxdS/GfMUhZtXSRMFNEohhxgSEcdzAIhANxl7QJlfHm5bVYtorrd0LGKR5iBmgZJsNqgKbih1Yu6",
    "signature_key_id": "demo-key-2026-07"
  }
}

// ===== OCSF event 2 — Completion (chained to event 1) =====
{
  "action": "Observed",
  "action_id": 3,
  "activity_id": 99,
  "activity_name": "Completion",
  "ai_agent": {
    "conversation_uid": "conv-9",
    "instance_uid": "sess-42",
    "parent_uid": null,
    "turn": 4,
    "uid": "agent-7"
  },
  "ai_model": {
    "name": "claude-opus-4-8"
  },
  "attestation_list": [
    {
      "authority_uid": "org-f3576cf6",
      "chain_uid": "demo-chain-org-f3576cf6",
      "fingerprint": {
        "algorithm": "SHA-256",
        "algorithm_id": 3,
        "encoding": "Hex",
        "encoding_id": 1,
        "serialization": "JCS",
        "serialization_id": 2,
        "value": "fed4e10805848335c3e9a5dd053a164094ac5594f0ec776aad83b4c86d239662"
      },
      "prev_event": {
        "fingerprint": {
          "algorithm": "SHA-256",
          "algorithm_id": 3,
          "encoding": "Hex",
          "encoding_id": 1,
          "serialization": "JCS",
          "serialization_id": 2,
          "value": "254332470b92c69fc387bbe71f5233a76fd6065631a86c41fb1de335156a8bce"
        },
        "type_uid": 600399,
        "uid": "demo-chain-org-f3576cf6-000000"
      },
      "signatures": [
        {
          "algorithm": "ECDSA",
          "algorithm_id": 3,
          "serialization": "DSSE",
          "serialization_id": 5
        }
      ],
      "uid": "demo-chain-org-f3576cf6-att-000001"
    }
  ],
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Logged",
  "disposition_id": 17,
  "duration": 842,
  "message_context": {
    "completion_tokens": 28,
    "prompt_tokens": 120,
    "total_tokens": 148
  },
  "metadata": {
    "correlation_uid": "conv-9",
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control",
      "record_integrity"
    ],
    "uid": "demo-chain-org-f3576cf6-000001",
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-06-30T12:00:01.000Z",
  "type_uid": 600399,
  "unmapped": {
    "cmf.completion.stop_reason": "End",
    "signature_b64": "MEQCIBIqfsYhCX7eo8eddXEtfqtSYqsr0GJBry0OQzo0i+FSAiBt8SL7du7Ive2gWVthmcDQ3qGqvtVEuPBm8iRev8QYdQ==",
    "signature_key_id": "demo-key-2026-07"
  }
}

// chain check: event2.prev_event.fingerprint == event1.fingerprint -> true
// chain check: event2.prev_event.uid == event1.metadata.uid   -> true
// verify event1: fingerprint recomputed -> true · DSSE signature -> true
// verify event2: fingerprint recomputed -> true · DSSE signature -> true
```
