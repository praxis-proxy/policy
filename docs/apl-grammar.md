# APL: the grammar

APL is the language a policy is written in. This document is normative: where it
and the parser disagree, one of them is a bug, and
`crates/ppe-apl-core/tests/conformance/` is what decides which. Every production
below has an accepted and a rejected case there, and every wart this document
admits to has a case pinning it so nobody quietly "fixes" it.

It replaces a grammar that existed only as comments inside a 5,600-line parser,
and those comments were wrong about quoting, escapes, attribute paths and numbers.
Where a decision here departs from how APL was first sketched, the departure is
named at that decision rather than left for a reader to notice.

## Contents

- [Where policy text appears](#where-policy-text-appears)
- [Lexical rules](#lexical-rules)
- [Predicates](#predicates)
- [Rules](#rules)
- [Steps](#steps)
- [Field pipelines](#field-pipelines)
- [The YAML shape](#the-yaml-shape)
- [Hook dispatch](#hook-dispatch)
- [Surviving warts](#surviving-warts)

---

## Where policy text appears

Three positions, and they accept different things. Most confusion about APL comes
from expecting one position to accept another's forms.

| Position | YAML | Accepts |
|---|---|---|
| **Rule** | an entry in `authorization.pre_invocation:` / `.post_invocation:` | a rule: a predicate, optionally `:` and an action |
| **Step** | the same list | a step: `run(...)`, `taint(...)`, `delegate(...)`, an elicitation verb, a PDP call, `sequential:` / `parallel:`, or a `when:` / `do:` map |
| **Stage** | a value in `args:` / `result:` | a pipe chain of stages |

A rule list and a step list are the same YAML list; an entry is read as a step
when it opens with a step verb and as a rule otherwise.

---

## Lexical rules

### Quoted literals

```ebnf
literal    = "'" { char | escape } "'"
           | '"' { char | escape } '"' ;
escape     = "\\" | "\'" | '\"' ;
```

Both quote styles are accepted. The closing quote must be the same character, so
`"it's"` and `'say "hi"'` each carry the other quote as content.

**The escape set is exactly `\\`, `\'` and `\"`.** It is the minimum that closes
the rule: without it there is no way to write a quote inside a literal delimited by
that quote. An unrecognized escape is an error naming the character.

`\n` and `\t` are deliberately **not** escapes. A deny reason rides in a violation
field a host renders, so a multi-line reason there is a display problem rather than
a missing capability.

A backslash used to pass through untouched, so `regex("\d+")` worked by accident.
Write `regex("\\d+")`.

One reader serves every position, which was not previously true: quoted text was
read in ten places with three different escape rules, and two of them treated an
unterminated quote by silently swallowing the rest of the line.

### Attribute paths

```ebnf
path       = segment { "." segment } [ subscript ] { "." segment [ subscript ] } ;
segment    = ( letter | "_" ) { letter | digit | "_" } ;
subscript  = "[" path "]" ;
```

A path is a production, not a run of permitted characters. Each segment is
non-empty, and a subscript holds a nested path whose *value* is the key to look up:

```
data.tenants[subject.tenant].data_region
```

Rejected, each naming the production it broke: `a..b`, `a.`, `.a`, `data.t[]`,
`data.t[a:b]`, `data.t["a"]`, `data.t["a]"]`, `data.x[a[b]]`.

Every one of those used to lex clean and then resolve to an absent attribute, which
made a predicate silently false and a `require` silently deny: a policy that never
matched and never said why. `data.t["a"]` was the quietest, since it looked up the
four characters `"a"` including the quotes.

An identifier is ASCII. A non-ASCII one is an error naming the character.

### Numbers

```ebnf
number     = [ "-" ] digit { digit } [ "." digit { digit } ] ;
```

No exponent, no digit separators, no radix prefix. Digits are required on both
sides of the dot, so `1.`, `.5` and `-.5` are all errors naming the number; `.5`
was already refused while `-.5` parsed as a float, and that asymmetry is gone.
`1e5` is refused by name rather than producing a trailing-token error that never
mentioned it.

**`007` is the integer 7.** A leading zero does not change a value. Reading it as
octal would alter one silently, which is the failure mode this work exists to
remove.

### Operators and positions

`&` is conjunction, `|` disjunction, `!` negation. There is no `&&` or `||`, and
writing one names the single form. Spacing is not significant: `a&b`, `a & b` and
`a  &  b` are one expression. A lexer comment used to claim a caller enforced
spacing; nothing did.

`not` is reserved. It is legal only in the `not in` phrase; `not authenticated`
names `!`, and a path beginning `not.` is refused.

There is no comment syntax inside policy text. Use YAML comments around it.

Positions in diagnostics are **character** offsets. They were byte offsets, and the
offending character was rendered by casting a single byte, so a message could name
a character that was not in the input.

---

## Predicates

```ebnf
predicate  = or ;
or         = and { "|" and } ;
and        = unary { "&" unary } ;
unary      = "!" unary | atom ;
atom       = "(" predicate ")"
           | "require" "(" require_args ")"
           | "exists" "(" path ")"
           | comparison
           | membership
           | path ;
comparison = path op operand ;
op         = "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" ;
operand    = literal | number | "true" | "false" ;
membership = path [ "not" ] "in" path ;
require_args = predicate { "," predicate } ;
```

Precedence, loosest to tightest:

| Level | Operator |
|---|---|
| 1 | `,` (inside `require(...)` only) |
| 2 | `\|` |
| 3 | `&` |
| 4 | `!` |
| 5 | comparison, `contains`, `in` |

A bare path is true when the attribute is truthy. `exists(path)` is true when the
key is present whatever its value, which is a different question.

**A comparison names its attribute first.** `'x' == a` is rejected naming the
accepted order rather than rewritten, because rewriting would accept text whose
meaning the author only guessed at.

`==` does not take an attribute on the right; the error points at `in` for set
membership. `in` compares a value against an attribute *naming* a set, not against
a literal list.

### `require`

`require(P)` means `!P`. A rule stores the condition under which it denies, so
requiring `P` is denying on `!P`.

```
require(role.hr)                  # deny unless role.hr
require(a, b)                     # deny unless both: !(a & b)
require(a | b)                    # deny unless either: !(a | b)
require(delegation.depth < 3)     # any predicate, not just a name
require(!delegated)
require(a) & b                    # composes: !a & b
```

The comma is conjunction and binds loosest, so `require(a, b | c)` is
`!(a & (b | c))`.

It used to be a rule-level shorthand with its own parser that read only a list of
bare names and refused to mix `,` with `|`. Negation is normalized to the leaves,
so all three previously-legal forms compile to exactly the tree they did before.

A rule whose predicate *is* a `require(...)` call can only carry `deny`. It
states what must hold and refuses when it does not, so `require(a): allow` is a
contradiction and is rejected as one.

The restriction is on that rule shape, not on the operator, and it holds however
the shape is written: string form, `when:` / `do:`, or the multi-effect shorthand.
Nested inside a larger predicate, `require` is the negation it desugars to and
nothing more, so `a & require(b): allow` is legal and allows on `a & !b`. Write it
that way only where the negation is what you mean; `a & !b: allow` says the same
thing without borrowing a word that reads like a requirement.

---

## Rules

```ebnf
rule       = predicate [ ":" action ]
           | action ;
action     = "allow"
           | "deny"
           | "deny" "(" literal [ "," literal ] ")" ;
```

A predicate with no action denies. An action with no predicate is unconditional.
The `:` that separates them is the last one outside quotes, parens and brackets;
bracket-awareness is new, and without it a colon inside a subscript split a
bare-predicate line into a predicate and a nonsense action.

`deny('reason')` and `deny('reason', 'code')` take quoted literals. A paren inside
one is content, so `deny("blocked (see policy)")` is legal — it was refused before,
because paren matching ignored quotes.

A field operation is not a rule. `result.x | redact` in rule position is rejected
naming effect position, where it used to compile as a disjunction.

---

## Steps

```ebnf
step       = "run" "(" name ")"
           | "taint" "(" label [ "," scope ] ")"
           | "delegate" "(" name { "," kwarg } ")"
           | elicit_verb "(" name { "," kwarg } ")"
           | pdp_call
           | step_map ;
kwarg      = key ":" value ;
elicit_verb = "require_approval" | "confirm" | "require_step_up"
            | "require_attestation" | "request_info" | "require_review" ;
```

**`run(name)` is the only form that invokes a plugin**, in a step list and in a
pipe chain alike. `plugin(name)` was a second spelling and is refused naming this
one. The word survives as a noun: `plugin:` is a keyword argument inside
`delegate(...)`.

`taint(label)` and `taint(label, session)` attach a label; the scope is `message`
or `session`.

Six elicitation verbs share one argument parser, so they take the same keyword
arguments (`from:`, `channel:`, `purpose:`, `scope:`, `timeout:`, `on_error:`) and
differ only in the kind they record.

> A `scope:` string is re-parsed as a predicate **at request time**, not at load.
> A lexically invalid scope therefore surfaces as a runtime deny rather than a load
> error. That asymmetry is known and is the one place a policy fault is not found
> at load.

### PDP calls

```ebnf
pdp_call   = dialect ":" | dialect "(" literal ")" ;
dialect    = "cedar" | "cel" | "opa" | "authzen" | "nemo" ;
```

A custom dialect is written `pdp(name):`, which is closest to the existing call
syntax. The name cannot be verified at load, because resolvers register at
runtime.

The parens hold the dialect name, so there is no room left for a call signature.
A custom resolver reads its arguments from the body map, the way `cedar:` does:

```yaml
- pdp(workload):
    path: hr/deny
    on_deny: [deny]
```

### Step maps

A step may be a YAML map instead of a string, for the forms that carry a body:

| Key | Form |
|---|---|
| `when:` / `do:` | conditional step |
| `sequential:` / `parallel:` | ordered and unordered groups |
| `delegate:` | the map form of `delegate(...)` |
| `restrict:` | the backend-candidate constraint |
| `pdp(name):` | a custom PDP dialect |
| a dialect name | `cedar:`, `cel:`, `opa:`, `authzen:`, `nemo:` |

The key set is closed. A misspelling such as `whens:` is an error naming the key,
and the message points at `pdp(whens):` in case a custom dialect was meant.

The closure is on **map-bodied** keys. A key with a sequence body is the
multi-effect shorthand (`- "predicate": [effects]`), so `whens: [deny]` stays a
rule on an attribute named `whens`, and `whens: { on_deny: [...] }` is the error.

A `)` ends a call signature: text after it (`opa(x) y:`) is an error rather than
being dropped. One redundant trailing colon is tolerated, because a key quoted in
YAML keeps the separator the parse already consumed (`- 'opa("p/q"):':`).

---

## Field pipelines

```ebnf
chain      = stage { "|" stage } ;
stage      = type_check | transform | validator | "run" "(" name ")" ;
```

A chain appears as a value under `args:` or `result:`, keyed by field:

```yaml
result:
  ssn: "str | redact(!perm.view_ssn)"
  card: "str | mask(4)"
```

| Stage | Meaning |
|---|---|
| `str`, `int`, `bool`, `float` | type check |
| `redact(P)`, `mask(N)`, `hash`, `omit` | transform |
| `regex(pattern)`, `enum(a, b, …)`, `len(min..max)`, a range literal | validator |
| `run(name)` | dispatch a plugin over the field |

An empty stage is an error: a leading, trailing or doubled `|` leaves a position
with no stage in it, and those used to be skipped, so a chain compiled shorter than
its author wrote.

`parse_pipeline("")` returns an empty pipeline rather than erroring, because a
caller hands it a field value that may be absent, and absent is not malformed.

`validate(name)` is refused. It is in the original design and not in this build,
and the evaluator's stub would let every value through, so accepting it would be a
silent hole. The message names `regex(...)` and `run(...)`.

---

## The YAML shape

```yaml
engine_settings:
  dispatch: policy            # or `hooks`; `policy` is the default

plugins:
  - name: audit-log
    kind: native
    hooks: [cmf.tool_pre_invoke]

global:
  attribute_files: [./data/tenants.yaml]
  pdp: {...}
  session_store: {...}
  authentication: [corp-jwt]
  authorization:
    pre_invocation: ["run(audit-log)"]
  defaults:
    tool:
      authorization: {...}

groups:
  hr-tools:
    authorization: {...}

routes:
  - tool: get_compensation
    authentication: [corp-jwt]
    authorization:
      pre_invocation:
        - "require(role.hr)"
      post_invocation:
        - "taint(audit, session)"
    args:
      employee_id: "str"
    result:
      ssn: "redact(!perm.view_ssn)"
    plugins:
      audit-log: { on_error: ignore }
```

APL terms sit on the section that carries them. There is no `apl:` wrapper.
`authorization:` is the only place a phase list appears, and it must name at least
one phase.

`attribute_files:`, `pdp:` and `session_store:` are `global:` keys and nowhere
else: all three are process-global.

`plugins:` on a route is a **map** of per-plugin overrides. A `plugins:` *list* was
an activation list and is a load error in policy mode; a policy names the plugin it
runs.

An unrecognized key is an error at every scope, naming the key, and naming its
replacement where it had one.

---

## Hook dispatch

`engine_settings.dispatch: hooks` is a supported peer, not a deprecation target,
and it is a different document. Its key set:

| Key | |
|---|---|
| `engine_settings:` | including `dispatch: hooks` |
| `plugins:` | with each plugin's own `hooks:`, `conditions:`, `priority:`, `mode:`, `on_error:` |

`routes:`, `groups:`, `global:` and `global.defaults:` are load errors in hook
mode, and a per-plugin `conditions:` is a load error in policy mode. A document is
legal in one mode only, and the error names the key and the mode that rejects it.

Hook mode has no APL: nothing in this document's grammar appears in such a
document, because no policy step exists to hold it. What it has instead is
per-plugin `conditions:`, which policy mode expresses as a predicate on a step.

---

## Surviving warts

Each of these is a deliberate decision, and each has a case in the corpus so it
cannot be removed by accident.

**A bare stage argument needs no quotes.** `enum(low, medium, high)` and
`regex(^[A-Z]+$)` are legal. Requiring quotes would rewrite working field stages
for no gain in meaning. What a stage argument does not get is the right to open a
literal and not close it.

**`007` is 7.** See [Numbers](#numbers).

**`parse_pipeline("")` is an empty pipeline, while an empty stage inside a chain is
an error.** Two positions, two answers: one takes a possibly-absent field value,
the other is a chain whose author named a stage.

**A custom PDP dialect is unverifiable at load.** `pdp(workload):` is accepted
whether or not a resolver for `workload` will ever register, because resolvers
register at runtime and the load cannot know.

**Static tags only, for `authentication:` inheritance.** Identity resolution walks
a route's static tags while the plugin resolver merges the request's too. The
asymmetry is intended for now and tracked separately.

**An elicitation `scope:` is parsed at request time.** See [Steps](#steps).

---

## See also

- `docs/upgrade-apl.md` — what an existing configuration must rewrite.
- `crates/ppe-apl-core/tests/conformance/` — the cases this document is held to.
- `CHANGELOG.md` — when each of these rules arrived, and what it replaced.
