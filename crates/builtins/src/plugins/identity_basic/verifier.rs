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

/// The hashing scheme of a stored record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scheme {
    /// bcrypt, in any of the `$2a$` / `$2b$` / `$2y$` spellings.
    Bcrypt,

    /// argon2, in any of the three variants, as a PHC string.
    Argon2,
}

/// Why a stored hash cannot be admitted for verification.
///
/// Errors contain no stored hash material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HashError {
    /// The record uses a refused scheme, including DES-crypt or plaintext.
    #[error("the stored hash uses a scheme this plugin refuses")]
    RefusedScheme,

    /// The record uses an unsupported MD5 or SHA-1 scheme and must be re-hashed.
    #[error(
        "the stored hash uses an MD5 or SHA-1 grade scheme (`$apr1$`, `{{SHA}}`) that this \
         plugin does not verify; re-hash the file with bcrypt or argon2"
    )]
    WeakSchemeUnsupported,

    /// The scheme is recognised but the record does not parse.
    #[error("the stored hash is malformed for its scheme")]
    Malformed,

    /// The hash parameters exceed the configured ceiling.
    #[error("the stored hash's parameters exceed the configured ceiling")]
    ParametersTooHigh,
}

/// An ordering key for verification work within one hashing scheme.
///
/// Only compare factors belonging to the same [`Scheme`]. Values are not bcrypt
/// cost parameters and must not be used to synthesize hashes.
///
/// [`Scheme`]: Scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkFactor(u32);

impl WorkFactor {
    /// The floor used when a directory holds no records at all.
    pub const FLOOR: Self = Self(10);

    /// A bcrypt cost clamped to the range accepted by the hashing library.
    fn as_bcrypt_cost(self) -> u32 {
        self.0.clamp(4, 31)
    }
}

/// A stored hash admitted for password verification.
///
/// Its `Debug` output redacts the encoded hash.
#[derive(Clone)]
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

    /// The encoded stored hash, for a backend to carry in a verifier slot.
    ///
    /// Do not log or project this offline-crackable verifier.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Compares verification work within a hashing scheme.
    ///
    /// Returns `None` when the records use different schemes, whose work
    /// factors are not comparable.
    pub fn try_cmp_work(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.scheme == other.scheme).then(|| self.work.cmp(&other.work))
    }
}

impl std::fmt::Debug for ParsedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedHash")
            .field("scheme", &self.scheme)
            .field("work", &self.work)
            .field("encoded", &"<redacted>")
            .finish()
    }
}

/// Parameter ceilings for stored password hashes.
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

/// Number of floor-hash mint attempts in this process, exposed for integration tests.
pub static FLOOR_HASH_MINTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The maximum password length accepted by the bcrypt verifier, in bytes.
pub const BCRYPT_TRUNCATION_BYTES: usize = 72;

/// Admit a stored bcrypt or argon2 hash under the configured parameter ceilings.
///
/// DES-crypt, plaintext, MD5, and SHA-1 records are refused.
///
/// # Errors
///
/// Returns a [`HashError`] for a refused or malformed record, or parameters above
/// `limits`.
///
/// [`HashError`]: HashError
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

/// Whether a record uses DES-crypt or plaintext.
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

/// Read a bcrypt cost from its fixed-width prefix.
///
/// Returns `Ok(None)` for a non-bcrypt record.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] when a bcrypt prefix has an invalid shape.
///
/// [`HashError::Malformed`]: HashError::Malformed
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

/// Create a bcrypt hash for dummy verification at the requested work factor.
///
/// Use when a directory has no record at or above its verification floor.
/// Always discard the verification verdict for an unknown user.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] if the hash cannot be created.
///
/// [`HashError::Malformed`]: HashError::Malformed
pub fn floor_hash(work: WorkFactor) -> Result<ParsedHash, HashError> {
    FLOOR_HASH_MINTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let encoded = bcrypt::hash("ppe-basic-dummy-verification-target", work.as_bcrypt_cost())
        .map_err(|_cannot_mint| HashError::Malformed)?;
    Ok(ParsedHash {
        scheme: Scheme::Bcrypt,
        work,
        encoded,
    })
}

/// Verify a decoded credential against an admitted stored hash.
///
/// This call is blocking and CPU-bound; run it off the async worker.
pub fn verify_credential(hash: &ParsedHash, credential: &super::BasicCredential) -> bool {
    verify(hash, credential.password())
}

/// Verify a password against an admitted stored hash.
///
/// This call is blocking and CPU-bound; run it off the async worker.
pub fn verify(hash: &ParsedHash, password: &Password) -> bool {
    password.verify_with(|bytes| verify_bytes(hash, bytes))
}

/// Verify password bytes against an admitted stored hash.
///
/// This call is blocking and CPU-bound; run it off the async worker.
/// Callers should keep the password bytes in a zeroizing buffer.
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
