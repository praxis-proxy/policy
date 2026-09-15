# APL Grammar

This document defines the accepted grammar for APL (Authorization Policy Layer).
The conformance cases in `crates/ppe-apl-core/tests/conformance/` cover accepted
and rejected forms. A disagreement between this document and the parser is a
defect.

## Contents

- [Where APL appears](#where-apl-appears)
- [Lexical rules](#lexical-rules)
- [Predicates](#predicates)
- [Rules](#rules)
- [Steps](#steps)
- [Field pipelines](#field-pipelines)
- [Invalid forms](#invalid-forms)

---

## Where APL appears

APL has three syntactic positions:

| Position | YAML location | Accepted form |
|---|---|---|
| Rule | an entry in `authorization.pre_invocation:` or `authorization.post_invocation:` | a predicate with an optional action, or an action |
| Step | the same phase lists | a rule, plugin call, taint, delegation, elicitation, PDP call, or step map |
| Stage | a field value in `args:` or `result:` | a pipe-separated field pipeline |

A phase list can contain both rules and steps. A string entry that begins with a
step verb is parsed as a step; any other string entry is parsed as a rule.

<!-- validate: fragment -->
```yaml
authorization:
  pre_invocation:
    - "require(role.hr)"
    - "run(audit-log)"
  post_invocation:
    - "taint(audit, session)"
args:
  employee_id: "str"
result:
  ssn: "str | redact(!perm.view_ssn)"
```

There is no `apl:` wrapper. An `authorization:` block must contain at least one
entry in `pre_invocation:` or `post_invocation:`. A declared `args:` or
`result:` field must contain at least one stage.

---

## Lexical rules

The EBNF in this document uses `{ X }` for zero or more repetitions, `[ X ]` for
an optional term, and `|` for alternatives. Terms in angle brackets, such as
`<plugin-name>`, are semantic values described with their containing construct.

### Quoted literals

```ebnf
literal    = "'" { character | escape } "'"
           | '"' { character | escape } '"' ;
escape     = "\\" | "\'" | '\"' ;
```

The closing quote must match the opening quote. The other quote character can
appear unescaped, as in `"it's"` and `'say "hi"'`.

Here, `character` is any Unicode character other than a backslash or the quote
that opened the literal.

The only escapes are `\\`, `\'`, and `\"`. Write `regex("\\d+")` to pass
the pattern `\d+` to the regular-expression stage. Escapes such as `\n` and `\t`
are invalid.

### Attribute paths

```ebnf
path       = segment { "." segment } [ subscript ]
             { "." segment [ subscript ] } ;
segment    = ( letter | "_" ) { letter | digit | "_" } ;
subscript  = "[" path "]" ;
letter     = "A" | ... | "Z" | "a" | ... | "z" ;
digit      = "0" | ... | "9" ;
```

Identifiers are ASCII. Each path segment is non-empty. A subscript contains a
nested path whose resolved value supplies the lookup key:

```text
data.tenants[subject.tenant].data_region
```

String literals are not valid subscripts. For example, `data.t[subject.id]` is
valid and `data.t["id"]` is invalid.

### Numbers

```ebnf
number     = [ "-" ] digit { digit } [ "." digit { digit } ] ;
```

Exponent notation, digit separators, and radix prefixes are not supported.
Digits are required on both sides of a decimal point, so `1.`, `.5`, and `-.5`
are invalid. Leading zeroes are decimal; `007` has the value 7.

### Operators and whitespace

`&` is conjunction, `|` is disjunction, and `!` is negation. `&&` and `||` are
invalid. Whitespace around operators is optional.

`not` is reserved for the `not in` operator. Use `!authenticated`, not
`not authenticated`. An attribute path cannot begin with `not.`.

APL text has no comment syntax. Use YAML comments outside the APL string.

---

## Predicates

```ebnf
predicate     = disjunction ;
disjunction   = conjunction { "|" conjunction } ;
conjunction   = unary { "&" unary } ;
unary         = "!" unary | atom ;
atom          = "(" predicate ")"
              | "require" "(" require_args ")"
              | "exists" "(" path ")"
              | comparison
              | membership
              | path ;
comparison    = path comparison_op operand ;
comparison_op = "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" ;
operand       = literal | number | "true" | "false" ;
membership    = path [ "not" ] "in" path ;
require_args  = predicate { "," predicate } ;
```

Precedence, from loosest to tightest:

| Level | Operator |
|---|---|
| 1 | `,` inside `require(...)` |
| 2 | `\|` |
| 3 | `&` |
| 4 | `!` |
| 5 | comparisons, `contains`, `in`, `not in` |

A bare path is true when its value is truthy. `exists(path)` is true when the
key is present, regardless of its value.

The attribute must be on the left of a comparison. The right operand is a
literal, number, or Boolean. Use `in` or `not in` to test a value against an
attribute containing a set:

```text
subject.department in data.restricted_departments
subject.department not in data.allowed_departments
```

### `require`

`require(P)` is equivalent to `!P`. Because a rule predicate describes the
condition under which the rule applies, a bare requirement denies when its
predicate is false.

```text
require(role.hr)                  # deny unless role.hr
require(a, b)                     # deny unless both: !(a & b)
require(a | b)                    # deny unless either: !(a | b)
require(delegation.depth < 3)
require(!delegated)
require(a) & b                    # equivalent to !a & b
```

Commas inside `require(...)` are conjunctions and have the lowest precedence.
For example, `require(a, b | c)` is equivalent to `!(a & (b | c))`.

A rule whose entire predicate is `require(...)` can only deny. Consequently,
`require(a): allow` is invalid. When nested in a larger predicate, `require(P)`
has only its ordinary `!P` meaning; `a & require(b): allow` is equivalent to
`a & !b: allow`.

---

## Rules

```ebnf
rule       = predicate [ ":" action ]
           | action ;
action     = "allow"
           | "deny"
           | "deny" "(" literal [ "," literal ] ")" ;
```

A predicate without an action denies. An action without a predicate is
unconditional. The predicate/action separator is the last colon outside quoted
literals, parentheses, and brackets.

`deny('reason')` attaches a reason. `deny('reason', 'code')` attaches both a
reason and a code. Both arguments must be quoted literals.

---

## Steps

String steps have the following forms:

```ebnf
step_string  = rule
             | "run" "(" <plugin-name> ")"
             | "taint" "(" <label> [ "," taint_scopes ] ")"
             | "delegate" "(" <plugin-name> { "," kwarg } ")"
             | elicit_verb "(" <plugin-name> { "," kwarg } ")" ;
taint_scopes = taint_scope | "[" taint_scope { "," taint_scope } "]" ;
taint_scope  = "message" | "session" ;
kwarg        = <key> ":" <value> ;
elicit_verb  = "require_approval" | "confirm" | "require_step_up"
             | "require_attestation" | "request_info" | "require_review" ;
```

`run(name)` invokes a plugin. It is valid both as a step and as a field-pipeline
stage. The plugin name must not be empty.

`taint(label)` attaches a session-scoped label. The label must not be empty. The
optional scope is `message`, `session`, or a list containing those values.

`delegate(...)` takes the plugin name as its first positional argument. Remaining
arguments are `key: value` pairs. Values can be quoted or bare scalars, numbers,
Booleans, or flat lists. Use the YAML map form for nested configuration.

Each elicitation verb takes a plugin name followed by keyword arguments. `from:`
is required. Recognized keywords are `from:`, `channel:`, `purpose:` (or
`prompt:`), `scope:`, `timeout:`, and `on_error:`. Additional keywords are passed
to the plugin as configuration. A `scope:` value is parsed as a predicate when
the request is handled, so an invalid scope produces a runtime denial.

### Step maps

The following steps use YAML maps:

| Key | Form |
|---|---|
| `when:` with `do:` | conditional step |
| `sequential:` | ordered group |
| `parallel:` | concurrent group |
| `delegate:` | map form of delegation |
| `restrict:` | backend-candidate constraint |
| `cedar:`, `cel:`, `opa:`, `authzen:`, `nemo:` | built-in PDP call |
| `pdp(name):` | custom PDP call |

The set of map-bodied step keys is closed. A map body is required for delegation,
restriction, and PDP calls. A sequence body under a predicate key is the
multi-effect rule shorthand rather than a step map.

### PDP calls

```ebnf
pdp_key         = builtin_dialect [ "(" <argument> ")" ]
                | "pdp" "(" <custom-dialect-name> ")" ;
builtin_dialect = "cedar" | "cel" | "opa" | "authzen" | "nemo" ;
```

A PDP call is a YAML map whose key is `pdp_key`. A built-in dialect may receive
one quoted or bare argument in parentheses. A custom dialect is named inside
`pdp(...)`; its resolver-specific arguments belong in the body map.

<!-- validate: phase-list -->
```yaml
- opa("hr/deny"):
    on_deny: [deny]
- pdp(workload):
    path: hr/deny
    on_deny: [deny]
```

Custom dialect names are resolved at runtime.

---

## Field pipelines

```ebnf
chain          = stage { "|" stage } ;
stage          = type_check
               | transform
               | validator
               | taint_stage
               | scan_stage
               | "run" "(" <plugin-name> ")" ;
type_check     = "str" | "int" | "bool" | "float" | "email" | "url" | "uuid" ;
transform      = "redact" [ "(" predicate ")" ]
               | "mask" "(" <non-negative-integer> ")"
               | "hash"
               | "omit" ;
validator      = "regex" "(" <pattern> ")"
               | "enum" "(" <value> { "," <value> } ")"
               | "len" "(" range ")"
               | range ;
range          = [ scaled_integer ] ".." [ scaled_integer ] ;
scaled_integer = [ "+" | "-" ] digit { digit } [ "k" | "K" | "m" | "M" ] ;
taint_stage    = "taint" "(" <label> [ "," taint_scopes ] ")" ;
scan_stage     = "pii.redact" | "pii.detect" | "injection.scan" ;
```

At least one bound in a range is required. A `k` suffix multiplies a bound by
1,000 and an `m` suffix multiplies it by 1,000,000; suffixes are
case-insensitive. Length bounds must be non-negative.

A pattern or enumeration value may be a quoted literal or a bare value. Quote a
value when it contains delimiters that would otherwise belong to the surrounding
stage.

Stages execute from left to right:

| Category | Stages |
|---|---|
| Type checks | `str`, `int`, `bool`, `float`, `email`, `url`, `uuid` |
| Transforms | `redact`, `redact(P)`, `mask(N)`, `hash`, `omit` |
| Validators | `regex(pattern)`, `enum(a, b, ...)`, `len(range)`, range literals |
| Effects | `taint(label, scope)` |
| Scans | `pii.redact`, `pii.detect`, `injection.scan` |
| Plugin dispatch | `run(name)` |

An empty stage is invalid, including one created by a leading, trailing, or
doubled `|`.

---

## Invalid forms

| Form | Use instead |
|---|---|
| `a && b` | `a & b` |
| a doubled disjunction operator | `a \| b` |
| `not authenticated` | `!authenticated` |
| `data.t["key"]` | a path-valued subscript such as `data.t[subject.key]` |
| `'x' == attribute` | `attribute == 'x'` |
| `attribute == other_attribute` | `attribute in other_attribute` when the right side is a set |
| `require(a): allow` | an explicit predicate whose meaning permits `allow` |
| `plugin(name)` | `run(name)` |
| `validate(name)` | `regex(pattern)` or `run(name)` |
| `result.x \| redact` in a rule list | `result: { x: "redact" }` |
| an empty field pipeline | remove the field entry or supply a stage |
| a leading, trailing, or doubled pipeline `\|` | a chain with a stage on both sides of every `\|` |

---

## Next

- [Effects and Sequencing](effects.md): apply the grammar in ordered policy
  phases.
- [Upgrading APL](../../upgrade-apl.md): migrate existing configurations.
- [`crates/ppe-apl-core/tests/conformance/`](../../../crates/ppe-apl-core/tests/conformance/):
  accepted and rejected conformance cases.
