# Sample output: `decision_sink_demo`

Real OCSF decision records produced by the sink in
[`src/emitter.rs`](src/emitter.rs) (`AuditHandler` / `build_decision`) from
the five finalized `DecisionLog`s in
[`examples/decision_sink_demo.rs`](examples/decision_sink_demo.rs).
Deterministic: timestamps, span ids and stream stamps are fixed, so a re-run
reproduces this file byte for byte. AID-EMIT-1 section 12 names this file as
a conformance vector.

```sh
cargo run -p praxis-policy-plugin-ocsf-audit --example decision_sink_demo
```

A denying step carries the violation that produced it as `detail`:

```text
# record 3, step cedar-pdp (denied)            # record 4, step injection-guard (deny_ignored)
"detail": {                                     "detail": {
  "code": "missing_permission",                   "code": "policy_deny",
  "reason": "no grant covers this tool"           "reason": "blocked"
},                                              },
```

A verifier MUST NOT require `detail` (AID-EMIT-1 section 9.2); it is
provenance for the step's action, and for a suppressed deny the only place the
objection's code survives, since no verdict names it.

What each record demonstrates:

1. **Allow (clean).** `action: Allowed` / `disposition: Allowed`; the ordered
   per-plugin steps and the terminal verdict under `unmapped."cpex.decision"`.
2. **Allow after modification.** `action: Modified`, never re-coded as a plain
   allow.
3. **Deny.** `action: Denied` / `disposition: Blocked`, with the
   executor-stamped violation at `status_code` / `status_detail`. The record a
   post-hook observer can never produce.
4. **Suppressed deny + aborted branch.** The flat `deny_ignored: true` flag
   plus per-step `deny_ignored` / `aborted` actions, so "every suppressed
   transform deny" is one SIEM query.
5. **Mandate draw (receipt join key).** A delegated-authority allow. The
   subject/actor split reads directly off the record: `actor.user` is the
   subject the work is done *for* (`alice@corp.com`), `ai_agent` is the acting
   agent (`agent-7`), and the `delegation` object is the explicit edge between
   them (`origin_subject_uid` to `actor_subject_uid`, per-hop scopes and TTL;
   a multi-hop chain is the analog of RFC 8693 nested `act` claims). The
   request id at `unmapped."cmf.request.request_id"` equals the correlation id
   a signed draw receipt names, so a receipt-in-hand reconciles against this
   stream.

Every decision record also carries the invocation span (`unmapped."cpex.span"`)
and the seam's completeness and ordering stamps (`unmapped."cpex.stream"`:
`epoch` / `stream_id` / `stream_seq` / `emission_seq`).

---

```text
// ===== Decision 1 — Allow (clean) =====
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
      "uid": "call-042"
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
  "time": "2026-08-21T03:20:00.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-042"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
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
      "span_id": "00f067aa0ba90041",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 41,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 41
    }
  }
}

// ===== Decision 2 — Allow after modification =====
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
      "uid": "call-042"
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
  "time": "2026-08-21T03:20:01.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-042"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
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
      "span_id": "00f067aa0ba90042",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 42,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 42
    }
  }
}

// ===== Decision 3 — Deny (policy violation) =====
{
  "action": "Denied",
  "action_id": 2,
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
      "uid": "call-042"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "disposition": "Blocked",
  "disposition_id": 2,
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
  "status_code": "policy_denied",
  "status_detail": "cedar-pdp: subject lacks permission read_compensation on hr/get_compensation",
  "status_id": 2,
  "time": "2026-08-21T03:20:02.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-042"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.decision": {
      "steps": [
        {
          "action": "denied",
          "detail": {
            "code": "missing_permission",
            "reason": "no grant covers this tool"
          },
          "phase": "sequential",
          "plugin": "cedar-pdp"
        }
      ],
      "verdict": {
        "deny": {
          "code": "policy_denied",
          "reason": "cedar-pdp: subject lacks permission read_compensation on hr/get_compensation"
        }
      }
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90043",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 43,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 43
    }
  }
}

// ===== Decision 4 — Suppressed deny + aborted branch =====
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
      "uid": "call-042"
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
  "time": "2026-08-21T03:20:03.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-042"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.decision": {
      "deny_ignored": true,
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        },
        {
          "action": "deny_ignored",
          "detail": {
            "code": "policy_deny",
            "reason": "blocked"
          },
          "phase": "transform",
          "plugin": "injection-guard"
        },
        {
          "action": "aborted",
          "phase": "transform",
          "plugin": "secondary-scan"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90044",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 44,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 44
    }
  }
}

// ===== Decision 5 — Mandate draw (receipt join key) =====
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
      "uid": "call-042"
    }
  },
  "category_uid": 6,
  "class_uid": 6003,
  "delegation": {
    "actor_subject_uid": "agent-7",
    "chain": [
      {
        "audience": "hr-mcp",
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
  "time": "2026-08-21T03:20:04.000Z",
  "tool": {
    "name": "get_compensation",
    "namespace": "hr",
    "uid": "call-042"
  },
  "type_uid": 600399,
  "unmapped": {
    "cmf.request.request_id": "corr-7f3e2a91",
    "cmf.security.labels": [
      "PII"
    ],
    "cpex.decision": {
      "steps": [
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "mandate-check"
        },
        {
          "action": "allowed",
          "phase": "sequential",
          "plugin": "cedar-pdp"
        }
      ],
      "verdict": "allow"
    },
    "cpex.span": {
      "parent_span_id": "00f067aa0ba90200",
      "span_id": "00f067aa0ba90045",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    },
    "cpex.stream": {
      "emission_seq": 45,
      "epoch": 1755648000000000000,
      "stream_id": "gw-1/boot-7",
      "stream_seq": 45
    }
  }
}

// join: receipt.correlation_id == corr-7f3e2a91 == event 5 unmapped."cmf.request.request_id"
```
