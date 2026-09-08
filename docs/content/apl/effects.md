# Effects and Sequencing

An APL rule does something. That something is an effect. Effects are the
building blocks of policy: a `pre_invocation:` block is an ordered list of them,
and they run in sequence until one denies.

## The effects

| Effect | What it does |
|--------|--------------|
| `allow` | No-op. Continue to the next effect. |
| `deny` / `deny('reason')` / `deny('reason', 'code')` | Halt the phase and all later phases with a violation. |
| `run(name)` | Invoke a registered plugin (PII scan, audit log, custom check). `plugin(name)` is refused, naming this as its replacement. |
| `delegate(name, ...)` | Mint a downstream credential via a delegator plugin. See [Delegation](delegation.md). |
| `require_approval(name, ...)` / `confirm(...)` / `require_step_up(...)` / `require_attestation(...)` / `request_info(...)` / `require_review(...)` | Ask a human and suspend the operation until they respond. See [Elicitation](elicitation.md). |
| `taint(label[, scope])` | Attach a label to the session or message. See [Session Taint](tainting.md). |
| `restrict: { ... }` | Narrow the set of backends the router may select from. See [Backend Restriction](restrict.md). |
| field pipelines | Validate or transform `args`/`result` fields. See [APL](index.md). |
| PDP call (`cedar:`, `cel:`, `opa(...)`) | Delegate the decision to a policy engine. See [PDP Integration](pdp.md). |

## Sequencing and halt-on-deny

Effects in a `pre_invocation:` block run top to bottom. The first `deny` halts
the phase and skips every later phase, so order is a tool: put cheap gates first
and expensive effects last.

<!-- validate: route-body -->
```yaml
authorization:
  pre_invocation:
    - "require(role.hr)"                                  # cheap attribute gate
    - cedar:                                              # relationship decision
        action: 'Action::"read"'
        resource:
          type: Repo
          id: ${args.repo_name}
    - "delegate(github-oauth, target: github-api, permissions: [repo:read])"  # expensive, last
```

If `require(role.hr)` denies, the Cedar call and the token exchange never run.
This ordering avoids a PDP call and credential mint for a rejected caller.

## Reactions: on_allow and on_deny

A PDP call can carry reaction blocks that run depending on the decision:

<!-- validate: route-body -->
```yaml
authorization:
  pre_invocation:
    - cedar:
        action: 'Action::"read"'
        resource:
          type: Document
          id: ${args.doc_id}
        on_allow:
          - "taint(cedar_approved, session)"
        on_deny:
          - "deny('not permitted by Cedar policy', 'cedar_denied')"
```

`on_allow` runs its effects when the PDP permits; `on_deny` runs when it denies.
Without an `on_deny`, a PDP denial halts the phase on its own.

## Composition: sequential and parallel

Effects can be grouped. `sequential` runs its members in order and halts
on the first deny. `parallel` runs independent members concurrently; any
deny fails the group, and accumulating effects from the members (taints,
backend restrictions) all take hold.

<!-- validate: route-body -->
```yaml
authorization:
  pre_invocation:
    - "require(perm.read_pii)"
    - parallel:
        - "run(pii-scan)"
        - "run(audit-log)"
```

Both groups take effects, not gates. A member is something the phase
does, so `run(...)`, `taint(...)`, `deny`, and the other effects above
are members; a predicate rule such as `require(...)`, or a PDP call, is
not, and nesting one is a load error. Gate first and group second, as
above, rather than trying to run the gates concurrently.

`parallel` also rejects field operations and delegation, because a
discarded branch would silently lose those effects. Use `sequential`
(the default for a `pre_invocation:` list) whenever one effect depends
on another.

## Phases recap

Effects run within the four route phases: `args`,
`authorization.pre_invocation`, `result`, `authorization.post_invocation` (see
[APL](index.md)). `delegate`, elicitation verbs, and PDP calls belong in
`pre_invocation` or `post_invocation`; field pipelines belong in `args` and
`result`. A deny anywhere halts the rest. An elicitation verb can also *suspend*
a phase — the operation neither allows nor denies, but pauses for a human and
resumes on retry (see [Elicitation](elicitation.md)).

## Next

- [PDP Integration](pdp.md): invoke Cedar, CEL, or OPA as an APL effect.
- [Identity](identity.md): populate the attributes used by predicates and PDPs.
