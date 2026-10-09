# Sample output: `provenance_demo`

Real OCSF decision records produced by the sink in
[`src/emitter.rs`](src/emitter.rs) (`build_decision`) from the four finalized
`DecisionLog`s in [`examples/provenance_demo.rs`](examples/provenance_demo.rs),
each carrying the two content provenance digests AID-EMIT-1 section 9.2
describes under `unmapped."cpex.content"`. Deterministic: timestamps, span
ids, stream stamps and the demo keys are fixed, so a re-run reproduces this
file byte for byte.

```sh
cargo run -p praxis-policy-plugin-ocsf-audit --example provenance_demo
```

The digests are the engine's. `ContentKey`, the function the executor calls at
pipeline entry and at emission, digests the payload's canonical audit bytes
under keys the demo resolves through the engine's secret store (`file`
backend, the same path `engine_settings.content_provenance_key` takes at
startup). The example feeds it the bytes and places the result on the log the
way the executor does; the emitter copies both values and never holds a key.
Each digest names its scheme and key id, `hmac-sha256:<key_id>:<hex>` or
`sha256:<hex>`; a verifier MUST NOT require either scheme, and two digests are
comparable only when the scheme and key id match.

What each record demonstrates:

1. **Unchanged.** Nothing altered the request between entry and emission: the
   two digests are equal, under one key id.
2. **Redacted.** The request arrived carrying an `ssn` argument and a redactor
   replaced it. The digests differ under the same key id, which is the whole
   claim: something changed the content. Neither value is in the record (the
   OCSF event carries no tool arguments at all), and neither digest reveals it:
   a keyed digest of redacted content cannot be tested against a guess without
   the key.
3. **Rotated key.** Record 1's request after the operator rotated the bytes
   behind `provenance_key`. The key id is different, so a reader knows these
   digests are not comparable with record 1's even though the content is the
   same. Within the record they still agree.
4. **Unkeyed.** Record 1's request under the explicit development setting
   `content_provenance_key: unkeyed`: plain `sha256:<hex>`. This is the form a
   reader must treat as a confirmation oracle for short or templated content,
   and the reason the keyed form exists.

## Recomputing the digests

The `// verify` lines at the end carry everything needed: the two demo keys (as
the engine reads them, the text of the key file, not a decoding of it), the
key-id label, and the canonical audit bytes of each payload. With the Python
standard library only:

```python
import hashlib, hmac

key = b"<provenance_key>"  # the text on the verify line
label = b"praxis-policy/content-provenance/key-id"
data = b"<audit_bytes>"  # one verify line, verbatim
key_id = hmac.new(key, label, hashlib.sha256).digest()[:8].hex()
print(f"hmac-sha256:{key_id}:{hmac.new(key, data, hashlib.sha256).hexdigest()}")
print(f"sha256:{hashlib.sha256(data).hexdigest()}")
```

All eight digests below recompute this way and match. Note
what the verify lines give away on purpose: the pre-redaction bytes of record 2,
so the digests can be checked. In a deployment that content exists nowhere once
the redactor has run; only its digest does, under a key the record does not
carry.

---

```text
// ===== Decision 1 - Unchanged =====
// scheme: keyed (provenance_key)
{
  "action": "Allowed",
  "action_id": 1,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [],
      "uid": "alice@corp.com"
    }
  },
  "api": {
    "request": {
      "uid": "call-051"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Allowed",
  "disposition_id": 1,
  "metadata": {
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control"
    ],
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-10-01T18:00:00.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-051"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.content": {
      "input_hash": "hmac-sha256:c7a7b79c1e0b1704:483b96b8a6742e463cb99fe80e7fd2e416e5a052eb796d3ac27a8fde44b43bdc",
      "output_hash": "hmac-sha256:c7a7b79c1e0b1704:483b96b8a6742e463cb99fe80e7fd2e416e5a052eb796d3ac27a8fde44b43bdc"
    },
    "cpex.decision": {
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        },
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "pii-scan"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90046",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 46,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 46
    }
  }
}

// ===== Decision 2 - Redacted =====
// scheme: keyed (provenance_key)
{
  "action": "Modified",
  "action_id": 4,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [],
      "uid": "alice@corp.com"
    }
  },
  "api": {
    "request": {
      "uid": "call-051"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Allowed",
  "disposition_id": 1,
  "metadata": {
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control"
    ],
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-10-01T18:00:01.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-051"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.content": {
      "input_hash": "hmac-sha256:c7a7b79c1e0b1704:535bd7bec78a7c928582f4e135c7e5468401201fa6aea7c6d51bbce74f7552c8",
      "output_hash": "hmac-sha256:c7a7b79c1e0b1704:1c7d162e97c48b1e908a702b74a868511e9fef36324c715e285e2353ea2e31f6"
    },
    "cpex.decision": {
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        },
        {
          "action": "modified_payload",
          "phase": "transform",
          "plugin": "pii-redactor"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90047",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 47,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 47
    }
  }
}

// ===== Decision 3 - Rotated key =====
// scheme: keyed (provenance_key_rotated)
{
  "action": "Allowed",
  "action_id": 1,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [],
      "uid": "alice@corp.com"
    }
  },
  "api": {
    "request": {
      "uid": "call-051"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Allowed",
  "disposition_id": 1,
  "metadata": {
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control"
    ],
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-10-01T18:00:02.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-051"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.content": {
      "input_hash": "hmac-sha256:14170f79d0136df7:a35cbbed141dacbce73330293a1fd1a52bb3fcb2b7436a810f04e8844bc1d82f",
      "output_hash": "hmac-sha256:14170f79d0136df7:a35cbbed141dacbce73330293a1fd1a52bb3fcb2b7436a810f04e8844bc1d82f"
    },
    "cpex.decision": {
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        },
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "pii-scan"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90048",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 48,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 48
    }
  }
}

// ===== Decision 4 - Unkeyed =====
// scheme: unkeyed
{
  "action": "Allowed",
  "action_id": 1,
  "activity_id": 99,
  "activity_name": "Invoke Tool",
  "actor": {
    "roles": [
      "hr"
    ],
    "user": {
      "groups": [],
      "uid": "alice@corp.com"
    }
  },
  "api": {
    "request": {
      "uid": "call-051"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Allowed",
  "disposition_id": 1,
  "metadata": {
    "product": {
      "name": "AI Identity OCSF Audit",
      "vendor_name": "AI Identity"
    },
    "profiles": [
      "ai_operation",
      "security_control"
    ],
    "version": "1.9.0"
  },
  "severity_id": 1,
  "time": "2026-10-01T18:00:03.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-051"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.content": {
      "input_hash": "sha256:7ceff5a2c40cd7b624d7d9b4446e580be4288fead67611a1ee29255bedcb11a1",
      "output_hash": "sha256:7ceff5a2c40cd7b624d7d9b4446e580be4288fead67611a1ee29255bedcb11a1"
    },
    "cpex.decision": {
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        },
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "pii-scan"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90049",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 49,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 49
    }
  }
}

// verify: provenance_key          = QWlJZGVudGl0eS1kZW1vLXByb3ZlbmFuY2Uta2V5LTIwMjYtMTAtMDEtYQ==
// verify: provenance_key_rotated  = QWlJZGVudGl0eS1kZW1vLXByb3ZlbmFuY2Uta2V5LTIwMjYtMTAtMDEtYg==
// verify: key_id_label            = praxis-policy/content-provenance/key-id
// verify: audit_bytes (entry, records 1/3/4) = {"message":{"content":[{"content":{"arguments":{"employee_id":"EMP-001234"},"name":"get_compensation","namespace":"hr","tool_call_id":"call-051"},"content_type":"tool_call"}],"role":"tool","schema_version":"2.0"}}
// verify: audit_bytes (entry, record 2) = {"message":{"content":[{"content":{"arguments":{"employee_id":"EMP-001234","ssn":"000-00-0000"},"name":"get_compensation","namespace":"hr","tool_call_id":"call-051"},"content_type":"tool_call"}],"role":"tool","schema_version":"2.0"}}
// verify: audit_bytes (emission, record 2) = {"message":{"content":[{"content":{"arguments":{"employee_id":"EMP-001234","ssn":"[REDACTED]"},"name":"get_compensation","namespace":"hr","tool_call_id":"call-051"},"content_type":"tool_call"}],"role":"tool","schema_version":"2.0"}}
```
