# How to add a claim mapper preset in PPE

Adding a preset is data-driven; no new mapper implementation or resolver branch is needed.

## 1. Verify the provider's claim contract

Use provider documentation and representative access tokens to determine:

- Exact claim paths and value types.
- Which claims are optional or require provider configuration.
- Candidate precedence.
- Fields that must remain unmapped because their meaning differs.
- Which roles the preset supports: `subject`, `client`, and optionally `workload`.

Avoid guessing mappings. Presets intentionally leave uncertain fields empty.

## 2. Prototype the mapping inline

Test the intended mapping using `claim_map` first. It uses exactly the same schema as a preset.
Supported destination fields are listed in
[`claim_map_config.rs`](../../builtins/plugins/identity-jwt/src/claim_map_config.rs).

## 3. Add the preset JSON

Create:

```text
builtins/plugins/identity-jwt/src/presets/<name>.json
```

A typical provider preset looks like:

```json
{
  "description": "Describe supported claims, opt-in claims, precedence, and deliberate omissions in detail.",
  "claim_map": {
    "subject": {
      "id": "sub",
      "roles": [
        {
          "path": "vendor.roles",
          "array_only": true
        }
      ],
      "permissions": {
        "paths": [
          {
            "path": "scope",
            "string_only": true
          }
        ],
        "split": "whitespace"
      }
    },
    "client": {
      "client_id": [
        {
          "path": "client_id",
          "stop_if_present": true
        },
        "azp"
      ],
      "authorized_scopes": {
        "paths": [
          {
            "path": "scope",
            "string_only": true
          }
        ],
        "split": "whitespace"
      }
    }
  }
}
```

The three field forms and their options are documented in
[`claim_map_config.rs`](../../builtins/plugins/identity-jwt/src/claim_map_config.rs):

- `"id": "sub"` — one path.
- `"teams": ["teams", "groups"]` — ordered candidates.
- `"roles": {"paths": [...], "merge": "union"}` — candidates plus options.

Important options:

- `array_only`: accept only arrays.
- `string_only`: accept only strings.
- `stop_if_present`: do not fall through if the claim exists with an unusable value; scalar fields only.
- `split: "whitespace"`: split a string such as OAuth `scope`.
- `merge: "union"`: combine collection candidates.
- `on_missing: "deny"`: reject instead of leaving the field empty.

In JSON paths, a literal dot requires `\\.`. Colons do not need escaping.

## 4. Register it alphabetically

Add one entry to `PRESETS` in
[`presets.rs`](../../builtins/plugins/identity-jwt/src/presets.rs):

```rust
("vendor", include_str!("presets/vendor.json")),
```

Keep the table alphabetically sorted. `include_str!` embeds the preset into the binary.

Do not change `DEFAULT_PRESET` unless intentionally making a breaking behavioral change.

## 5. Pin the exact mapping in tests

Extend `every_provider_preset_declares_the_candidates_it_is_documented_to` in
[`presets.rs`](../../builtins/plugins/identity-jwt/src/presets.rs) with every important destination
field and its ordered paths.

Then add tests covering:

- A representative provider token.
- Candidate precedence and fallbacks.
- String-versus-array behavior.
- Every deliberate omission.
- Any provider-specific legacy claim names.
- `on_missing` or anchor behavior where relevant.

Several table-driven tests automatically check every registry entry for parsing, compilation,
unique naming, resolver construction, and factory construction.

## 6. Update hard-coded provider assumptions

Review these tests when adding another provider:

- Provider presets without workload mappings in `presets.rs`.
- The explicit provider-name loop in `presets.rs`.
- Fields intentionally absent from providers in `presets.rs`.
- Resolver workload-role expectations in
  [`resolver.rs`](../../builtins/plugins/identity-jwt/src/resolver.rs).

Current generic tests expect every preset to support both `subject` and `client`. If the new
preset legitimately supports fewer roles, adjust those invariants explicitly instead of adding
speculative mappings.

## 7. Add an end-to-end case

Add a signed-token test to
[`claim_map_e2e.rs`](../../builtins/plugins/identity-jwt/tests/claim_map_e2e.rs) using:

```json
{"claim_mapper": "vendor"}
```

This verifies registry lookup, JWT validation, and identity construction together.

## 8. Update user-facing preset lists

Update:

- Crate documentation in [`lib.rs`](../../builtins/plugins/identity-jwt/src/lib.rs).
- Identity documentation in [`identity-delegation.md`](identity-delegation.md).

Add a new changelog entry if appropriate. Do not rewrite an older release note merely because it
historically says "four presets."

## 9. Validate

```console
cargo nextest run -p praxis-policy-plugin-identity-jwt --lib
cargo nextest run -p praxis-policy-plugin-identity-jwt --test claim_map_e2e
make check
make ci
```

The minimal code change is the JSON file plus registry entry. Tests, documented omissions, and
user-facing lists make it production-ready.
