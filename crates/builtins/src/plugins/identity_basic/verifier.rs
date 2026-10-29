// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Password-hash verification, and the two properties that make it safe here.
//
// CONSTANT TIME. The sibling api-key backend documents at length why it needs
// *no* constant-time comparison: it indexes by digest, so the lookup either
// finds a record or does not, and the credential is never compared byte by
// byte against a stored secret. That reasoning does not transfer. Here a
// presented password is checked against a stored verifier, so the comparison
// is between a caller-controlled value and a secret-derived one, and an early
// return on the first differing byte is a measurable oracle. Both hashing
// crates compare their outputs in constant time internally; this module keeps
// that property by never short-circuiting around them and by folding the final
// verdict through `subtle`.
//
// COST SYMMETRY. The expensive half is not the comparison, it is the KDF. A
// bcrypt verify at cost 12 is milliseconds; a map probe for a user-id that
// does not exist is nanoseconds. So "does this user exist" is trivially
// measurable unless a miss performs the same work a hit would -- which is what
// `dummy_hash` is for, and why the dummy is derived from the worst case
// actually present in the directory rather than from a constant.
//
// Note what is deliberately NOT here: any way to produce a hash for storage.
// PPE verifies; minting belongs to whatever owns the password.

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordVerifier as _};
use subtle::ConstantTimeEq as _;

use super::credential::Password;

/// Which hashing scheme a stored record uses.
///
/// The set is closed by what `.htpasswd` and the YAML backend can hold, and
/// the ordering of the variants is not meaningful -- [`WorkFactor`] carries the
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scheme {
    /// bcrypt, in any of the `$2a$` / `$2b$` / `$2y$` spellings.
    Bcrypt,

    /// argon2, in any of the three variants, as a PHC string.
    Argon2,
}

/// Why a stored hash is not one this plugin will verify.
///
/// Field-free for the same reason [`DecodeError`] is: these are surfaced at
/// config load, where a message naming the offending record is useful, but the
/// hash itself is an offline-crackable verifier and must not travel in an error
/// string that may be logged.
///
/// [`DecodeError`]: super::credential::DecodeError
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HashError {
    /// The scheme prefix is one this plugin refuses outright.
    ///
    /// DES-crypt and plaintext, which are refused even with the weak-scheme
    /// opt-in: a 13-character DES hash has an effective keyspace a laptop
    /// exhausts, and a plaintext "hash" is not a verifier at all.
    #[error("the stored hash uses a scheme this plugin refuses")]
    RefusedScheme,

    /// The scheme is MD5/SHA-1-grade, which this plugin does not verify.
    ///
    /// Distinct from [`RefusedScheme`] so the load error can tell an operator
    /// that re-hashing the file is the fix, rather than implying the record is
    /// corrupt.
    ///
    /// [`RefusedScheme`]: HashError::RefusedScheme
    #[error(
        "the stored hash uses an MD5 or SHA-1 grade scheme (`$apr1$`, `{{SHA}}`) that this \
         plugin does not verify; re-hash the file with bcrypt or argon2"
    )]
    WeakSchemeUnsupported,

    /// The scheme is recognised but the record does not parse.
    #[error("the stored hash is malformed for its scheme")]
    Malformed,

    /// The parameters are above the configured ceiling.
    ///
    /// A well-formed hash with an extreme cost factor is a denial of service
    /// with a valid signature: one login at bcrypt cost 20 is seconds of CPU,
    /// and the caller does not have to authenticate to spend it.
    #[error("the stored hash's parameters exceed the configured ceiling")]
    ParametersTooHigh,
}

/// How much work a verify against a record costs, **within one scheme**.
///
/// Explicitly *not* comparable across schemes, and the type cannot enforce
/// that on its own -- so [`Scheme`] travels with it everywhere it is compared,
/// and the backend refuses a directory that mixes schemes rather than ordering
/// across them.
///
/// An earlier version claimed cross-scheme comparability on the reasoning that
/// the requirement was only "not cheaper than the dearest record" and erring
/// upward was safe. Both halves were wrong. The scales are unrelated: bcrypt
/// cost is a power-of-two CPU exponent, while argon2's dominant term is memory
/// bandwidth. Measured on one machine:
///
/// | record              | this factor | real verify |
/// |---------------------|-------------|-------------|
/// | `argon2 m=4096,t=3` | 15          | 5.8ms       |
/// | `bcrypt cost=12`    | 12          | 160ms       |
///
/// So the ordering inverted the real cost by 28x, and a mixed file would pick
/// the *cheap* argon2 record as its miss-path hash -- making a miss far faster
/// than a bcrypt hit and handing back exactly the user-enumeration oracle KTD9
/// exists to close.
///
/// A calibrated cross-scheme model was considered and rejected: the ratio
/// moves with memory bandwidth and core speed, so any constant baked in here
/// would be a guess that silently degrades on hardware it was not measured
/// on. Refusing to mix is honest and checkable; a fudge factor is neither.
///
/// **This is an ordering key only, never a cost to synthesize from.** An
/// earlier version fed it to `bcrypt::hash` as a cost, which conflated two
/// scales that differ by orders of magnitude: bcrypt cost is a power-of-two
/// exponent, while argon2's memory is already in KiB. An ordinary
/// `m=19456,t=2` record scaled to 16, and minting one bcrypt hash at cost 16
/// takes ~2.6s -- measured, not estimated. The default argon2 ceiling scaled
/// to 28, which is 2^12 times that again. Directory construction took 7.9s for
/// a single argon2 record. The miss path now reuses the heaviest *real* hash
/// in the directory instead; see `Index::dummy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkFactor(u32);

impl WorkFactor {
    /// The floor used when a directory holds no records at all.
    ///
    /// An empty directory still has to pay for a miss, or an empty file is
    /// distinguishable from a populated one by timing alone.
    pub const FLOOR: Self = Self(10);

    /// The work factor as a bcrypt cost, for minting the dummy.
    ///
    /// Clamped to bcrypt's own accepted range. The dummy has to be a *valid*
    /// hash the verifier runs in full: some implementations return early on a
    /// malformed record, which would make the dummy free and defeat its
    /// purpose.
    fn as_bcrypt_cost(self) -> u32 {
        self.0.clamp(4, 31)
    }
}

/// A stored hash that has been checked at load and may be verified against.
///
/// Parsing happens at load so a malformed record fails config rather than a
/// request, and so the per-request path does no validation that could branch
/// on record contents.
#[derive(Debug, Clone)]
pub struct ParsedHash {
    scheme: Scheme,
    work: WorkFactor,
    /// The record as stored. Never logged, never projected.
    encoded: String,
}

impl ParsedHash {
    /// How expensive this record is to verify.
    pub fn work_factor(&self) -> WorkFactor {
        self.work
    }

    /// Which scheme this record uses.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The record as stored.
    ///
    /// A hash, not a password, so this is not a credential leak -- but it *is*
    /// an offline-crackable verifier, so it must never be logged or projected.
    /// Exposed only so a backend can carry it in a `UserRecord`'s verifier
    /// slot, which is the field the projection cannot reach.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

/// Ceilings a stored hash must sit under, and which weak schemes are readable.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The highest bcrypt cost this directory will load.
    pub max_bcrypt_cost: u32,

    /// The highest argon2 memory cost, in KiB.
    pub max_argon2_memory_kib: u32,

    /// The highest argon2 time cost (passes).
    pub max_argon2_time_cost: u32,
}

impl Default for Limits {
    fn default() -> Self {
        // Defaults sit above what a sane deployment configures and below what
        // turns one login into an outage. bcrypt 12 is ~250ms on current
        // hardware and is the common recommendation; 15 is ~2s, which is the
        // ceiling rather than the target.
        Self {
            max_bcrypt_cost: 15,
            max_argon2_memory_kib: 256 * 1024,
            max_argon2_time_cost: 10,
        }
    }
}

/// bcrypt truncates a password at this many bytes.
///
/// Load-bearing for R26 rather than trivia. bcrypt feeds at most 72 bytes to
/// the KDF, so a 92-byte password verifies against a hash minted from its
/// first 72 -- two different passwords, one accepted. The crate does offer a
/// `non_truncating_verify`, but it errors on hashes it did not mint itself, so
/// it cannot be used against a `.htpasswd` file written by Apache. The guard
/// is therefore ours: refuse the credential before it reaches the KDF.
pub const BCRYPT_TRUNCATION_BYTES: usize = 72;

/// Read a stored hash, refusing anything this plugin will not verify.
///
/// There is deliberately no weak-scheme opt-in parameter. An earlier shape had
/// one, but with no MD5 or SHA-1 primitive in this tree it could not actually
/// admit anything -- a flag an operator can set that changes nothing is worse
/// than its absence, so the refusal is unconditional and the error says what
/// to do instead.
///
/// # Errors
///
/// A [`HashError`] for a refused scheme, an MD5/SHA-1-grade scheme, a
/// malformed record, or parameters above `limits`.
pub fn parse_hash(stored: &str, limits: &Limits) -> Result<ParsedHash, HashError> {
    // Order matters: the refused schemes are checked before anything else, so
    // a DES or plaintext record cannot be admitted by the weak-scheme opt-in.
    if is_refused_outright(stored) {
        return Err(HashError::RefusedScheme);
    }
    // apr1 and `{SHA}` are recognised so the failure can say *why*, but are
    // not verifiable here in v1: neither MD5 nor SHA-1 is in this tree, and
    // adding two crypto crates to serve the schemes this plugin exists to move
    // operators off is the wrong trade. An operator hitting this needs to
    // re-hash the file, which is the action they want anyway. There is
    // deliberately no opt-in parameter: one existed in an earlier draft and
    // could not admit anything, so it would have been a setting that changes
    // nothing. The message names the fix instead.
    if weak_scheme(stored) {
        return Err(HashError::WeakSchemeUnsupported);
    }

    if let Some(cost) = bcrypt_cost(stored)? {
        if cost > limits.max_bcrypt_cost {
            return Err(HashError::ParametersTooHigh);
        }
        return Ok(ParsedHash {
            scheme: Scheme::Bcrypt,
            work: WorkFactor(cost),
            encoded: stored.to_owned(),
        });
    }

    if stored.starts_with("$argon2") {
        let parsed = PasswordHash::new(stored).map_err(|_phc_error| HashError::Malformed)?;
        let memory = parsed.params.get_decimal("m").ok_or(HashError::Malformed)?;
        let time = parsed.params.get_decimal("t").ok_or(HashError::Malformed)?;
        if memory > limits.max_argon2_memory_kib || time > limits.max_argon2_time_cost {
            return Err(HashError::ParametersTooHigh);
        }
        // Scaled onto the bcrypt cost axis so one `WorkFactor` orders both
        // schemes. Coarse by design; see `WorkFactor`.
        let work = WorkFactor(memory.max(1).ilog2().saturating_add(time));
        return Ok(ParsedHash {
            scheme: Scheme::Argon2,
            work,
            encoded: stored.to_owned(),
        });
    }

    Err(HashError::Malformed)
}

/// Whether a record uses a scheme refused even with the weak-hash opt-in.
fn is_refused_outright(stored: &str) -> bool {
    // A bare 13-character DES-crypt record carries no `$` marker at all, which
    // is also what a plaintext password looks like. Both are refused, and
    // neither is distinguished: the operator fix is the same.
    !stored.starts_with('$') && !stored.starts_with('{')
}

/// Whether a record uses one of the MD5/SHA-1-grade legacy schemes.
fn weak_scheme(stored: &str) -> bool {
    stored.starts_with("$apr1$") || stored.starts_with("{SHA}")
}

/// bcrypt's cost, read from the fixed-width prefix.
///
/// Hand-parsed because the crate exposes no public hash parser: `split_hash`
/// is private and `HashParts` cannot be built from a string. The format is
/// fixed by the scheme -- `$2y$NN$` then 53 characters of salt and digest --
/// so this reads bytes 4..6 after confirming the shape.
///
/// Returns `Ok(None)` when the record is not bcrypt at all, so the caller can
/// go on to try argon2.
///
/// # Errors
///
/// [`HashError::Malformed`] when the prefix says bcrypt but the rest does not.
fn bcrypt_cost(stored: &str) -> Result<Option<u32>, HashError> {
    let variant = stored.get(..4);
    if !matches!(variant, Some("$2a$" | "$2b$" | "$2y$")) {
        return Ok(None);
    }
    // A valid bcrypt record is exactly 60 ASCII bytes. Checked before slicing
    // so a multi-byte character cannot panic the parse, and non-ASCII is
    // rejected rather than sliced through.
    if stored.len() != 60 || !stored.is_ascii() {
        return Err(HashError::Malformed);
    }
    let cost = stored.get(4..6).ok_or(HashError::Malformed)?;
    if stored.as_bytes().get(6) != Some(&b'$') {
        return Err(HashError::Malformed);
    }
    cost.parse::<u32>()
        .map(Some)
        .map_err(|_not_a_number| HashError::Malformed)
}

/// Mint a floor-cost bcrypt hash, for a directory with no heavier record.
///
/// The fallback for the miss path when the directory is empty, or when every
/// record it holds is cheaper than [`WorkFactor::FLOOR`]. Where a heavier real
/// record exists, the miss path reuses *that* hash instead of minting
/// anything: minting is the expensive operation, and synthesizing a cost from
/// a cross-scheme ordering key is what made it pathological.
///
/// A *valid* bcrypt record, not a placeholder: the verifier has to run it in
/// full, and a malformed record would be rejected early and cost nothing. The
/// password hashed is irrelevant and never matches a real credential, because
/// the miss path discards the verdict.
///
/// # Errors
///
/// Whatever bcrypt says when it cannot mint at this cost, which the caller
/// turns into a load failure -- a directory that cannot build its dummy cannot
/// serve misses safely, so it must not start.
pub fn floor_hash(work: WorkFactor) -> Result<ParsedHash, HashError> {
    let encoded = bcrypt::hash("ppe-basic-dummy-verification-target", work.as_bcrypt_cost())
        .map_err(|_cannot_mint| HashError::Malformed)?;
    Ok(ParsedHash {
        scheme: Scheme::Bcrypt,
        work,
        encoded,
    })
}

/// Check a decoded credential's password against a parsed stored hash.
///
/// The public entry point. [`verify`] takes the plugin-private password type,
/// which only [`decode_basic`] can build, so this is how a caller outside this
/// module tree — the resolver, and the tests — reaches a verification without
/// that type having to become public API.
///
/// [`decode_basic`]: super::credential::decode_basic
pub fn verify_credential(hash: &ParsedHash, credential: &super::BasicCredential) -> bool {
    verify(hash, credential.password())
}

/// Check a password against a parsed stored hash.
///
/// Blocking and CPU-bound by nature; callers run it off the async worker.
///
/// The verdict is folded through a constant-time equality rather than returned
/// as the library's `bool` directly. That is belt-and-braces -- both crates
/// already compare in constant time -- but it keeps the final branch in this
/// function uniform, so a future edit cannot turn the verdict into an early
/// return.
pub fn verify(hash: &ParsedHash, password: &Password) -> bool {
    password.verify_with(|bytes| verify_bytes(hash, bytes))
}

/// Check raw password bytes against a parsed stored hash.
///
/// The bytes-level core. Separate from [`verify`] because a verification has to
/// run off the async worker, and `spawn_blocking` needs an owned value that
/// outlives the `Password`'s closure -- so the closure cannot wrap the whole
/// call. Callers are responsible for keeping the bytes in a zeroizing buffer;
/// within this plugin the only caller does.
pub fn verify_bytes(hash: &ParsedHash, bytes: &[u8]) -> bool {
    let matched = (|| match hash.scheme {
        Scheme::Bcrypt => {
            // R26: bcrypt would otherwise accept any password sharing the
            // stored one's first 72 bytes. Refusing here rather than
            // truncating, because truncating is what creates the collision.
            if bytes.len() > BCRYPT_TRUNCATION_BYTES {
                return 0_u8;
            }
            u8::from(bcrypt::verify(bytes, &hash.encoded).unwrap_or(false))
        },
        Scheme::Argon2 => {
            let Ok(parsed) = PasswordHash::new(&hash.encoded) else {
                return 0_u8;
            };
            u8::from(Argon2::default().verify_password(bytes, &parsed).is_ok())
        },
        // Deliberately exhaustive with no catch-all. `Scheme` is
        // `#[non_exhaustive]` for downstream crates, but within this one the
        // compiler still checks every variant -- so adding a scheme breaks this
        // match at compile time rather than silently falling through to a
        // default. A `_ => 0` arm would be unreachable today and, worse, would
        // hide that breakage behind a verdict of "wrong password" the day a
        // scheme is added.
    })();
    matched.ct_eq(&1_u8).into()
}
