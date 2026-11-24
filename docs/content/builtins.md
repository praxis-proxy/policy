# Builtins

PPE ships a set of plugins, decision points, and a session store, each
behind a Cargo feature. With a feature enabled,
`praxis_policy::install_builtins` registers its factory and a policy can
name it by `kind`.

## Catalog

| Kind | Type | Feature | Purpose |
|---|---|---|---|
| `identity/jwt` | identity | `jwt` | Resolve a subject from a verified JWT, with configurable claim mapping. See [Identity](apl/identity.md). |
| `identity/api-key` | identity | `api-key` | Resolve an API key against a file or HTTP directory. See [Recipe 7](identity-delegation.md#recipe-7-an-opaque-api-key-resolved-against-a-directory). |
| `delegator/oauth` | delegator | `oauth` | RFC 8693 token exchange, with optional caching. See [Delegation](apl/delegation.md). |
| `delegator/vault` | delegator | `delegator-vault` | Resolve caller-scoped or workload-owned downstream credentials from Vault KV v2. See [Vault delegation recipes](identity-delegation.md#recipe-8-a-users-vault-stored-credential). |
| `elicitation/ciba` | elicitation | `elicitation-ciba` | OIDC CIBA human approval. See [Elicitation](apl/elicitation.md). |
| `cedar-direct` | decision point | `cedar` | Evaluate Cedar policy (dialect `cedar`). |
| `cel` | decision point | `cel` | Evaluate CEL expressions (dialect `cel`). |
| `opa` | decision point | `opa` | Evaluate Rego, embedded (dialect `opa`). |
| `valkey` | session store | `valkey` | Persist Session Taint labels across processes. CIBA can use the same server for approvals. See [Session Taint](apl/tainting.md). |
| `vault` | secret provider | `secrets-vault` | Resolve `secret:` references from Vault KV v2. Not auto-registered: it needs an `HttpTransport` the host supplies. |
| `quota` | policy plugin | `experimental-quota` | Enforce a per-principal token budget through Limitador. Experimental and excluded from `builtins`. |
| `ratelimit/limitador` | rate-limit plugin | `experimental-ratelimit` | Count requests against in-process Limitador limits at `ratelimit.pre_identity` or `ratelimit.post_identity`, listed under `rate_limits:`, and deny with 429. Experimental and excluded from `builtins`. See [Rate Limiting](rate-limiting.md). |

The default session store is in-process memory. It needs no feature and
no `kind`, but labels in it do not survive a reload or reach a second
replica.

CIBA approvals have their own correlation store, chosen by the plugin's
`store:` block: `memory`, or `valkey` to share them across replicas.
Configuring `global.session_store` does not change it unless the block
references that connection. The CIBA `store:` block is required; see
[Elicitation](apl/elicitation.md#correlation-store).

The three decision points are held to each other by a differential test
suite. Given the same attributes and equivalent policy intent, they must
agree across their shared boolean, integer, string, and string-set
subset. Documented semantic differences are allowlisted; a new
disagreement fails the build.

## Not builtins

Two worked examples live in `reference/plugins/` and are not bundled: a PII
scanner (`validator/pii-scan`) and an audit
logger (`audit/logger`). They are linted and tested here, and each
manifest says why it is an example rather than a builtin: the scanner is
plain regexes with no checksum validation, and the logger's sink is
stderr. Register them the way you would any host plugin.

## Cargo features

```toml
# engine only, the default
praxis-policy = "0.7.0"

# every bundled extension
praxis-policy = { version = "0.7.0", features = ["builtins"] }

# a granular subset
praxis-policy = { version = "0.7.0", features = ["jwt", "cedar"] }
```

| Feature | Pulls in |
|---|---|
| `builtins` | all twelve below: `jwt`, `api-key`, `basic`, `kubernetes-token-review`, `oauth`, `delegator-vault`, `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey`, `secrets-vault`. `basic` is unreleased: it is on `main` and not in 0.6.0, so a host pinned to a published version cannot select it yet |
| `jwt` | `identity/jwt`, verified with AWS-LC |
| `jwt-openssl-fips` | `identity/jwt` and DPoP, verified with system OpenSSL under the FIPS provider. Requires `fips`; cannot be combined with `jwt`. HMAC (HS256, HS384, HS512) and EdDSA are refused at config load |
| `api-key` | `identity/api-key` |
| `basic` | `identity/basic`, and the argon2, bcrypt and sha-crypt verifiers it carries. Unreleased; track `main` to use it |
| `kubernetes-token-review` | `identity/kubernetes-token-review` |
| `fips` | OpenSSL FIPS SHA-256 for Policy's shared hashing, used by the engine and API-key. Needs no identity builtin. Keyed content provenance is rejected because it requires HMAC. Select with `default-features = false`; other crypto-using builtins are reported and make the profile unsafe. |
| `oauth` | `delegator/oauth` |
| `delegator-vault` | `delegator/vault` |
| `elicitation-ciba` | `elicitation/ciba` |
| `cedar` | the `cedar-direct` decision point |
| `cel` | the `cel` decision point |
| `opa` | the `opa` decision point |
| `valkey` | the Valkey session store, and the redis and TLS stack it carries |
| `secrets-vault` | the Vault KV v2 secret provider. Not auto-registered: it needs an `HttpTransport` the host supplies |
| `experimental-quota` | the opt-in Limitador-backed token quota plugin; excluded from `builtins` |
| `experimental-ratelimit` | the opt-in in-process Limitador request rate limit plugin for the rate-limit hooks; excluded from `builtins` |
| `http-hyper` | a default outbound HTTP transport, off by default |

The default build is the engine alone, so a host that needs only the
runtime and its own plugins compiles nothing extra.

Default builds use RustCrypto SHA-256. A FIPS build disables defaults and
selects `fips`, optionally with `api-key` and `jwt-openssl-fips`; see
[FIPS](fips.md) for the supported selections, host setup and startup checks.

`basic` is not part of a supported FIPS selection. It is reported whichever
hash scheme the directory holds, so `fips_profile_is_safe()` is false on any
build that enables it, and no choice of scheme changes that. Password
verification runs in RustCrypto for every scheme the plugin accepts: picking
`$5$` or `$6$` records does not move it into OpenSSL, and an empty file still
mints a bcrypt hash for the unknown-user path. A deployment that needs both
Basic and FIPS has to terminate Basic somewhere else.

### What Basic asks of the host

Basic sends a reusable password on every request, and base64 is not
encryption ([RFC 7617 Section 4]). The plugin verifies the credential and
stops there; five duties are the host's, and a deployment that skips them
leaks the password whatever the policy says:

- **Require TLS** on any route carrying a Basic credential.
- **Redact** the configured credential header from access logs, traces and
  error reports. `credential.kind: header` takes a header *name*, so a
  deployment that moved the credential off `Authorization` must redact the
  name it chose; redacting `Authorization` alone leaves the password in the
  logs.
- **Remove** that same header before forwarding the request to an unrelated
  upstream. A successful resolve leaves the inbound header on the request:
  the identity hook has no request-mutation channel. Forwarding it hands a
  service that never authenticated the caller a credential it can replay.
- **Supply the client host** on the `IdentityPayload`, taken from the peer
  address or a trusted proxy, so the failure limit is scoped to the caller.
  Without it, anyone who knows a user-id can lock that user out: see
  [Repeated failures](#repeated-failures).
- **Render `WWW-Authenticate`** from the denial's violation details. Every
  denial this resolver raises carries the challenge under the `http.headers`
  key; nothing in Policy writes it to the wire, so a client gets no prompt
  until the host does.

Basic does not populate `raw_credentials`, so the password reaches no
authorization step, assertion or decision point. That bound stops there: a
later identity handler in the same chain can still read the credential
header through `IdentityPayload::headers()`. Order the chain accordingly, and
treat any handler placed after Basic as holding the password.

A fuller operator recipe is planned; these are the warnings that cannot wait
for it.

[RFC 7617 Section 4]: https://datatracker.ietf.org/doc/html/rfc7617#section-4

### Choosing a Basic directory

Two on-disk providers ship, and they differ in what a record can carry
rather than in how they verify one. Both index by user-id, admit the same
four schemes, enforce one cost profile per file, and share the refresh
window and staleness ceiling described below.

One cost profile means every parameter that changes verification time
matches across records: the bcrypt cost, every argon2 parameter, or the
sha-crypt variant, round count and salt length. A file mixing sha-crypt
salt lengths is refused at load, because a longer salt can add a digest
block to two rounds in three and make those users cheaper or dearer to
verify than an unknown one. Re-hash such a file with one salt length.

Matching salt lengths fix the input length of every round that hashes the
salt, not the exact total work. Sha-crypt setup hashes the salt a number of
times derived from an intermediate digest, so two sha-crypt records with
equal-length salts can still differ by up to a few dozen digest blocks.
That difference is small beside the round count, which the profile does
fix; bcrypt and argon2 records sharing a profile perform the same work.

| | `htpasswd` | `user_file` |
|---|---|---|
| Format | Apache `.htpasswd` lines | YAML under a `users:` key |
| Projectable fields | none: the format carries a user-id and a hash | any field the record names |
| Expiry | none; nothing in the format can express one | `expires_at`, enforced on every request |
| Written by | `htpasswd`, `mkpasswd`, `crypt(3)` | an operator, or whatever projects your directory |

Pick `htpasswd` when an existing file is the source of truth and a policy
needs nothing but the username. Pick `user_file` when a policy is written
against roles, teams or other attributes, or when a credential has to stop
working on a date.

```yaml
plugins:
  - name: ops-basic
    kind: identity/basic
    hooks: [identity.resolve]
    config:
      realm: "ops"
      credential:
        kind: header
        name: Authorization
      provider:
        kind: user_file
        path: /etc/ppe/users.yaml
        refresh_secs: 30
        max_staleness_secs: 300
      record_map:
        subject:
          id: user_id
          roles: roles
          teams: teams
```

<!-- validate: fragment -->

```yaml
# /etc/ppe/users.yaml -- mode 0600, owned by the PPE user.
# Not a PPE config document: this is the directory file the provider reads.
users:
  - username: alice
    password_hash: "<alice's argon2id PHC string>"
    roles: [admin, auditor]
    teams: [platform]
  - username: contractor
    password_hash: "<contractor's argon2id PHC string>"
    roles: [reader]
    expires_at: 2026-12-31T23:59:59Z
```

The two `password_hash` values are placeholders, and the file does not load
until each is a complete PHC string. Mint every record with the same
parameters, since a directory admits one cost profile per file. With the
reference `argon2` CLI, for example:

```console
printf 'Password: ' >&2; IFS= read -rs password; printf '\n' >&2
printf '%s' "$password" | argon2 "$(openssl rand -hex 16)" -id -t 2 -k 19456 -p 1 -e
unset password
```

`read -s` prompts without echoing, so the password never appears in the
command line or the shell history. `printf` is a shell builtin, so it does
not appear in the process list either. Use `printf '%s'` rather than
`echo`, which appends a newline that becomes part of the hashed password.
`IFS=` and `-r` keep leading and trailing spaces and backslashes, which
`read` would otherwise strip from the password before it is hashed.

`username`, `password_hash` and `expires_at` are storage fields: they are
consumed by the backend and never reach the projected claims, so a
`subject.claim.password_hash` assertion cannot render a verifier into an
upstream header. Every other field in a record is yours to name and is
projected through `record_map`. The verified user-id is injected separately
as `user_id`, which is what the default `subject.id` anchor reads.

Six things fail at load rather than at request time, because each one
would otherwise read as an outage or, worse, as silence:

- A duplicate `username`, compared after Unicode normalisation. Two
  spellings of one name are a collision, not a last-wins overwrite that
  hands one caller the other's identity.
- A `username` containing `:`. [RFC 7617 Section 2] splits the credential
  at the first colon, so no client can send that name and the record would
  deny as a wrong password forever.
- A `username` containing a control character, a line or paragraph
  separator, or a bidi control. The decoder refuses those in an inbound
  credential, so the record would be just as unreachable.
- A record field named `user_id`. The resolver injects the verified
  username under that name, so the record's own value would be silently
  replaced.
- An `expires_at` that is not a timestamp. A string-typed field would have
  accepted it and then meant "never expires", which is the one failure an
  expiry must not have.
- A misspelled top-level key. `user:` for `users:` would otherwise load as
  an empty directory that denies every request.

Load and reload errors locate a record by its position in `users:`, such as
`record 3`, and never quote the file: a failed reload is logged at warn on
every refresh interval, so neither a username nor a stored hash belongs in
that line.

[RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2

The file holds hashes, never plaintext, so a copy that leaks hands over no
usable credential. It is still an offline-crackable verifier: it must not be
world-readable, and PPE never writes to it. Re-hashing and rotation belong
to whatever tool owns your directory.

### Advertising `charset="UTF-8"`

`advertise_utf8_charset: true` adds `charset="UTF-8"` to the challenge.
Per [RFC 7617 Section 2.1], that asks the client to send `user-pass` as
UTF-8 in Unicode Normalization Form C. The user-id is NFC-normalised on both
sides either way. The password is not: it is verified as the bytes the
client sent, because normalising it would break every hash minted from the
bytes as typed.

So turning the flag on is a migration step for any record whose hash was
minted from a password that is not already in NFC, such as one typed with a
combining accent (`a` followed by U+0301). A client that honours the
challenge sends the precomposed form, which no longer matches that hash, and
the user is denied as a wrong password. Before enabling the flag, re-hash
such records from the NFC form of the password. Passwords that are plain
ASCII, or already precomposed, are unaffected.

[RFC 7617 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7617#section-2.1

### The password ceiling is tied to the file's scheme

`limits.max_password_bytes` above 72 is refused on a bcrypt directory.
Bcrypt truncates at 72 bytes, so a longer password would be admitted here
and then always rejected by the verifier, locking out every user who chose
one with no denial an operator can read. A ceiling above 72 is a legitimate
setting on an argon2 or sha-crypt file, which consume the whole password.

The check runs on every load of the record file, not only at startup. A
refresh that rewrites an argon2 file as bcrypt under a ceiling above 72 is
refused and the previous index continues to serve, so the file and the
ceiling cannot drift apart between reloads. Lower the ceiling to 72 before
re-hashing a directory to bcrypt.

That retention is bounded. The previous index serves only until it reaches
`provider.max_staleness_secs`, after which every lookup is denied as
`auth.directory_unavailable` rather than answered from an index the backend
no longer stands behind. A refused refresh is therefore a countdown, not a
steady state: a *successful reload* has to land within the staleness
ceiling, or authentication stops for every user in the directory. Restoring
a valid file is not enough on its own. A failed reload delays the next
automatic attempt by `refresh_secs`, so a file restored just after a failure
is not read until that interval passes, and with `refresh_secs` equal to
`max_staleness_secs` that can be after the ceiling. The refusal is logged
once per refresh interval with the path and the parse error.

### Repeated failures

`failure_limit` bounds password guessing. Once a key counted by name has
spent its own budget, further attempts deny as `auth.too_many_failures`
without running the verifier, until the window passes, and a successful
login clears that counter. A key counted in a shared overflow bucket, or
carrying failures inherited from one, is different: a spent bucket still
sends the attempt to verification while the bucket's recovery budget is
open, and a success there clears none of the bucket's failures. A closed
recovery budget stops those recovery attempts, not every attempt on the
bucket. See the overflow buckets below.

| Key | Default | Meaning |
|---|---|---|
| `max_failures` | 100 | failures a key may accumulate before denial |
| `window_secs` | 300 | how long a counter survives its last failure |
| `capacity` | 10,000 | keys tracked by name before overflow buckets |

The key is the user-id scoped to the client host, when the host sets one on
the `IdentityPayload` (`with_client_host`). Without a client host the key is
the user-id alone. That difference decides who a lockout hits:

- **With a client host,** a guesser spends only its own source's budget. The
  user signing in from another source is unaffected. One user-id guessed
  from many sources is not bounded per user-id; put an edge rate limiter in
  front if that matters.
- **Without one,** every client's failures land on the same counter, so
  anyone who knows a user-id can lock that user out for the window by
  sending `max_failures` wrong passwords, and keep it locked out by
  repeating them. The default of 100 is this plugin's local default and
  sets the price of that lockout, not a bound that makes it impossible.

The default is not a NIST consecutive-failure limit. NIST SP 800-63B-4
Section 3.2.2 limits consecutive failed attempts on an account, and once
that limit is reached it has the authenticator disabled until it is
rebound. This limiter does neither: its budget restores itself when the
window passes, even if the account never authenticates, and a source-scoped
key or several replicas give one account several budgets. An account-level
limit that disables and rebinds belongs to whatever owns your directory.

Set the client host only from a value the client cannot choose, such as the
peer address or one a trusted proxy wrote. Taken from a client-supplied
header, it lets a guesser name a fresh source on every request and get a
fresh budget each time. Behind a proxy that hides the client address, every
caller shares one source, and the limiter behaves as if it had none.

The counters live in process memory. A restart clears them, and each replica
keeps its own: with N replicas a guesser gets about N times `max_failures`
per window, and a lockout applies only on the replicas that counted the
failures. A spray of one password across many user-ids never fills a single
counter. Both need a shared or edge limiter.

Past `capacity`, keys are counted in a fixed table of shared overflow
buckets. A spent bucket does not refuse a correct password: the attempt is
verified, because the failures that spent the bucket may belong to another
key. Each bucket's wrong guesses on that path are budgeted too. Once
`max_failures` of them land within a window, the bucket's recovery path
closes until a window has passed since the last failed recovery, so a
guesser who spent a target's bucket gains at most one more budget per
window. While recovery is closed, an attempt on the spent bucket denies as
`auth.too_many_failures` without verifying, and so does one from any key
that shares the bucket. A key promoted to a counter of its own carries the
bucket's failed recoveries with it, so a freed slot does not reopen the
path.

The closure stops recovery attempts only. The bucket's own failures and its
recovery budget expire separately, so once the bucket's failures expire,
ordinary attempts are verified again even while recovery is still closed.
The closure applies again only when those attempts spend the bucket.
Raise `capacity` if the limiter's saturation count keeps rising.

### The HTTP transport

`http-hyper` is the odd one. PPE performs no outbound HTTP of its own: a
host installs an `HttpTransport` and the plugins borrow it, so a process
embedding PPE keeps one connection pool, one TLS trust store, and one
egress path instead of two. A host with its own client injects it with
`PolicyEngine::set_http_transport`. A host with none calls
`install_default_http_transport`, which is what this feature provides.
It is never wired automatically.

Install it before `initialize()`, since that is when a plugin first asks
for it. The install is set-once: a second call is ignored and returns
`false`, so a host that wires twice cannot swap the transport out from
under plugins already holding it.

Two distinct mistakes fail that same `initialize()`, and the message
names which one you made:

- No transport installed. The plugin needs the `http` host service
  "but none is installed; the embedding host must install one before
  initializing the engine". That is a wiring problem in the embedding
  program, not something the policy YAML can fix.
- Transport installed, capability withheld. The plugin does not
  declare `perform_http`, and the error names the capability to add to
  its `capabilities:` list.

The engine keeps the two apart on purpose, so the message points at the
file that needs the edit.

## Referencing a builtin

A registered builtin is named by `kind`. Plugins are declared under
`plugins:` with their hooks and capabilities, decision points under
`global.pdp:`, and the session store under `global.session_store:`.

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      credential:
        kind: header
        name: X-User-Token

global:
  pdp:
    - kind: opa
      policy_text: |
        package ppe
        default allow := false
  session_store:
    kind: valkey
    endpoint: localhost:6379
```

A plugin that fetches JWKS, exchanges a token, or dispatches a CIBA
prompt must declare `perform_http`, or the engine refuses to start and
names the plugin and the missing capability.

### Credential location (`identity/jwt`)

Each `identity/jwt` instance reads its token from one wire location,
named by the `credential:` block in the plugin's `config:`. Three
kinds are supported:

| Kind | Use case | Example |
|---|---|---|
| `header` | Bearer token | `Authorization` |
| `cookie` | Browser app | `__Host-jwt` |
| `query_param` | WebSocket or SSE | `access_token` |

Query parameter credentials require the host to supply the raw query string
in `HttpExtension.query` and grant the resolver `read_query`. Granting
`read_headers` alone does not expose the raw query string to a plugin.

```yaml
# Cookie-based JWT
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      credential:
        kind: cookie
        name: __Host-jwt
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

```yaml
# Query-parameter JWT (WebSocket handshake)
plugins:
  - name: jwt-ws
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http, read_query]
    config:
      role: user
      credential:
        kind: query_param
        name: access_token
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

Omitting both `credential:` and `header:` defaults to
`{ kind: header, name: Authorization }`.
The legacy `header: NAME` setting still works but logs a deprecation
warning when the resolver is built. Migrate it to
`credential: { kind: header, name: NAME }` when updating the policy.
Setting both fields on one resolver is a configuration error.

An issuer with DPoP enabled requires a header credential and the
`read_headers` capability. A cookie or query parameter credential fails
configuration loading when that issuer's DPoP mode is `optional` or
`required`.

Cookie and query-string values are parsed by PPE itself, not by the
host's HTTP framework, so the same request resolves the same credential
regardless of which proxy sits in front of it. Duplicate cookie names or
query-parameter names for the configured credential are rejected as
ambiguous (`auth.ambiguous_credential`) rather than resolved by
first-wins or last-wins.

> **Security note.** A query-parameter token routinely appears in
> access logs, CDN logs, and browser history. PPE logs a one-time
> notice at startup when a resolver uses `query_param` so the operator
> can scrub raw query strings from infrastructure logging.

## Next

- [Testing](testing.md): test policy and plugin behavior through the runtime.
- [Configuration](configuration.md): declare builtins in a policy document.
