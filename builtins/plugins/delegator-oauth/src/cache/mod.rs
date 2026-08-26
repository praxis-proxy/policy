// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Delegated-token cache for `OAuthDelegator`.
//
// Every `delegate` step currently mints a fresh token: the delegator
// computes an expiry from the `IdP`'s `expires_in`, attaches it to the
// `RawDelegatedToken`, and never looks at it again. A token valid for
// five minutes is used once and discarded. At proxy volume that is one
// RFC 8693 exchange per delegated call, which puts a full `IdP` round
// trip on the request path and makes the `IdP` a hard dependency of
// every request rather than of every few minutes.
//
// Reusing a live token is standard for a delegating proxy. The reason it
// is not a small change is the cache key, which is why [`key`] is the
// largest module here and carries the reasoning.
//
// # Layout
//
//   * [`key`] — the security boundary. Derivation, and what may not
//     enter it.
//   * [`config`] — operator knobs, and the serve-window arithmetic.
//   * [`store`] — mechanism. Bounded, coalesced, and careful about the
//     difference between a monotonic clock and a wall clock.
//
// # Off by default
//
// A delegator with no `cache:` block behaves exactly as it did before
// this module existed. Caching a delegated credential widens the
// revocation window and thins the `IdP`'s audit trail; both are
// reasonable trade-offs and neither should arrive with a version bump.
//
// # What this module does not fix
//
// **Revocation.** A cached token outlives an `IdP`-side revocation until
// its entry retires. That is inherent to bearer tokens rather than
// something the cache introduces, but the cache is what makes the window
// non-zero, so `ttl_ceiling_seconds` is the lever and it is documented
// on the field rather than left implicit.
//
// **Mint amplification.** The credential anchor is unvalidated wire data
// (see [`key`]). That is sound for isolation, because only a confirmed
// mint is ever stored, but it means a caller holding *no* valid
// credential can still emit a stream of invented tokens, take a cache
// miss on every one, and drive an `IdP` round trip per request with the
// gateway's client credentials attached. A mint limiter keyed on the
// anchor does not help, because the anchor is the thing being varied.
//
// This is not caused by the cache — today's delegator already performs
// one exchange per request, so the amplification path already exists.
// The cache changes it from the normal cost of a request into the
// abnormal cost of an attacker-shaped one. The fix is a limiter keyed on
// something attested rather than on the anchor, with separate budgets
// for confirmed and failed mints, and it is tracked separately from the
// caching work.
//
// The engine has met this shape before: `RefreshGate` in the JWT
// identity plugin exists because "an unknown `kid` is reachable with an
// unauthenticated request, so a stream of invented `kid`s would
// otherwise be an amplification attack pointed at your own `IdP`". Same
// attacker, same `IdP`, and the mitigation there — claim the attempt
// *before* the fetch so a burst sees the floor immediately — is the one
// that applies here.

pub(crate) mod config;
pub(crate) mod key;
pub(crate) mod store;

pub use config::{CacheConfig, StalenessConfig};
