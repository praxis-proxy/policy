# Session Taint and Information Flow

Some controls cannot be decided from a single request. "Do not send anything
externally after reading secret data" depends on what the session did earlier.
PPE tracks that history as Session Taint: labels attached to a session that
later policy can read. This is how PPE enforces information-flow control,
including write-down prevention.

## Information-flow requirement

A caller reads compensation data, then asks the agent to send an email. The
email body is clean: no SSN, no salary, nothing sensitive in the text. It should
still be blocked, because this session has handled secret data and an external
send is a write-down. The LLM cannot be trusted to remember this or to refuse on
its own, and a content scan of the email body would not catch it. The control
must live in state the model cannot see.

## Setting Session Taint

A `taint` effect attaches a label. The scenario marks the session when
compensation is read:

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

`taint(secret, session)` records the label `secret` for the rest of the session.
Labels are monotonic: once set, they persist. The second argument is the scope.

| Scope | Lifetime |
|-------|----------|
| `session` | Persists for the whole session, across requests. |
| `message` | Applies to the current message only. |

## Reading Session Taint in a later policy

A different route, later in the same session, refuses based on the label, even
with a clean payload:

```yaml
routes:
  - tool: send_email
    authorization:
      pre_invocation:
        - "require(perm.email_send)"
        - "security.labels contains \"secret\": deny('session touched secret data', 'session_tainted')"
```

![The taint produce-and-consume flow: get_compensation runs taint(secret, session), writing the secret label into session state; later in the same session, send_email with a clean body is checked against that PPE-owned state and denied with session_tainted when the label is present, allowed otherwise](../../images/apl_tainting_flow.svg)

The email is denied because the session is tainted, not because of anything in
its body. The decision is made from PPE-owned state, so the model cannot route
around it by rewording the email.

## Persistence and isolation

Session Taint labels live in a session store. The default is in-process memory;
the bundled `valkey` store persists them across processes and restarts:

```yaml
global:
  session_store:
    kind: valkey
    endpoint: localhost:6379
```

Labels are scoped per subject. Two callers sharing a session identifier do not
share taint: a label set while acting as one subject does not leak into another
subject's decisions. With the Valkey store, labels survive a gateway restart, so
a long-running session's information-flow history is not lost.

## Pipeline integration

`taint` is an effect; reading labels is an attribute check (`security.labels
contains ...`) like any other predicate. The session store is a registered
capability the runtime writes to after a tainting effect and reads from when
building the attribute bag. Both operations happen inside PPE, so the untrusted
model cannot forge the Session Taint history used for write-down enforcement.

## Next

- [Backend Restriction](restrict.md): apply Session Taint labels to backend
  selection.
- [Configuration](../configuration.md): configure the session store and other
  runtime components.
