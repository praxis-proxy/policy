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
// measurable unless a miss performs the same work a hit would -- which is why
// a directory holds one cost profile throughout and reuses one of its own
// records on the miss path, and why admission here rejects any record the
// verifier would refuse before reaching the KDF.
//
// Note what is deliberately NOT here: any way to produce a hash for storage.
// PPE verifies; minting belongs to whatever owns the password.

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordVerifier as _};
use base64::Engine as _;
use subtle::ConstantTimeEq as _;

use super::credential::Password;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The bcrypt cost used for a directory that holds no records at all.
///
/// An empty file still has to answer a lookup, and must cost what a populated
/// one would, or an empty directory is distinguishable by timing alone. This
/// is the only case where a hash is synthesized rather than reused.
pub const EMPTY_DIRECTORY_COST: u32 = 10;

/// The maximum password length accepted by the bcrypt verifier, in bytes.
pub const BCRYPT_TRUNCATION_BYTES: usize = 72;

/// The hashing scheme of a stored record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
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

/// The full cost parameters of a stored hash.
///
/// Compared by **equality**, not by order. Ranking verification cost is not
/// something this type offers, because no ranking is sound: argon2's two
/// dimensions (memory blocks and passes) trade off against each other per
/// RFC 9106, and bcrypt's exponential cost shares no scale with either. A
/// directory must therefore hold one cost profile throughout, and the backend
/// enforces that at load.
///
/// Why uniformity rather than a careful choice of miss-path hash: with bcrypt
/// costs 4 and 12 in one file, a wrong password for the cost-4 user returns in
/// 0.7ms while a miss runs the cost-12 hash in 160ms -- so the cheap user is
/// distinguishable from a non-existent one by a factor of 245, measured. That
/// is a user-enumeration oracle no dummy-selection rule can close, because the
/// *hits* differ from each other. Equal cost for every record is the only
/// shape in which a miss can cost what a hit costs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CostProfile {
    /// A bcrypt cost factor.
    Bcrypt {
        /// The `$2?$NN$` cost exponent.
        cost: u32,
    },

    /// Argon2 parameters, all of which affect the verify cost.
    Argon2 {
        /// Which argon2 variant (`i`, `d`, `id`): they differ in work pattern.
        variant: argon2::Algorithm,
        /// The version field, since v0x10 and v0x13 are different functions.
        version: argon2::Version,
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Passes over memory.
        time_cost: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
}

impl CostProfile {
    /// The scheme this profile belongs to.
    pub fn scheme(self) -> Scheme {
        match self {
            Self::Bcrypt { .. } => Scheme::Bcrypt,
            Self::Argon2 { .. } => Scheme::Argon2,
        }
    }

    /// A short operator-facing description, for a load error.
    ///
    /// Carries parameters only. These are not secret -- they are recoverable
    /// from any hash in the file -- and an operator reconciling two records
    /// needs to see which differ.
    pub fn describe(self) -> String {
        match self {
            Self::Bcrypt { cost } => format!("bcrypt cost {cost}"),
            Self::Argon2 {
                variant,
                version,
                memory_kib,
                time_cost,
                parallelism,
            } => format!(
                "{}(v={:#x}) m={memory_kib},t={time_cost},p={parallelism}",
                variant.as_str(),
                u32::from(version),
            ),
        }
    }
}

/// A stored hash admitted for password verification.
///
/// Its `Debug` output redacts the encoded hash.
#[derive(Clone)]
pub struct ParsedHash {
    profile: CostProfile,
    /// The record as stored. Never logged, never projected.
    encoded: String,
}

impl ParsedHash {
    /// The full cost parameters of this record.
    pub fn profile(&self) -> CostProfile {
        self.profile
    }

    /// Which scheme this record uses.
    pub fn scheme(&self) -> Scheme {
        self.profile.scheme()
    }

    /// The encoded stored hash, for a backend to carry in a verifier slot.
    ///
    /// Do not log or project this offline-crackable verifier.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl std::fmt::Debug for ParsedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedHash")
            .field("profile", &self.profile)
            .field("encoded", &"<redacted>")
            .finish()
    }
}

/// Parameter ceilings for stored password hashes.
#[derive(Clone, Copy, Debug)]
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
            max_argon2_memory_kib: 262_144, // 256 MiB
            max_argon2_time_cost: 10,
        }
    }
}

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
        // The library's own accepted range. A record outside it is rejected
        // before the KDF, which would make that user-id measurably faster to
        // probe than an unknown one.
        if !(4..=31).contains(&cost) {
            return Err(HashError::Malformed);
        }
        if cost > limits.max_bcrypt_cost {
            return Err(HashError::ParametersTooHigh);
        }
        return Ok(ParsedHash {
            profile: CostProfile::Bcrypt { cost },
            encoded: stored.to_owned(),
        });
    }

    if stored.starts_with("$argon2") {
        let parsed = PasswordHash::new(stored).map_err(|_phc_error| HashError::Malformed)?;

        // PHC parsing alone is not admission. It accepts records argon2
        // cannot verify -- an `$argon2x$` variant, or `p=0` -- which then fail
        // before the KDF runs, making that user-id much faster to probe than
        // an unknown one. `Params::try_from` applies the algorithm's own
        // validation, so a record that loads here is one the verifier will
        // run in full.
        let variant = argon2::Algorithm::try_from(parsed.algorithm.as_str())
            .map_err(|_unsupported_variant| HashError::Malformed)?;
        let version = match parsed.version {
            Some(v) => {
                argon2::Version::try_from(v).map_err(|_unsupported_version| HashError::Malformed)?
            },
            None => argon2::Version::default(),
        };
        let params = argon2::Params::try_from(&parsed)
            .map_err(|_invalid_parameters| HashError::Malformed)?;
        // The salt and digest must be present too: argon2 errors out before
        // the KDF without them, which is the same timing signal.
        if parsed.salt.is_none() || parsed.hash.is_none() {
            return Err(HashError::Malformed);
        }

        let memory_kib = params.m_cost();
        let time_cost = params.t_cost();
        let parallelism = params.p_cost();

        if memory_kib > limits.max_argon2_memory_kib || time_cost > limits.max_argon2_time_cost {
            return Err(HashError::ParametersTooHigh);
        }

        return Ok(ParsedHash {
            profile: CostProfile::Argon2 {
                variant,
                version,
                memory_kib,
                time_cost,
                parallelism,
            },
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

/// Read a bcrypt cost from a fully validated record.
///
/// Returns `Ok(None)` for a non-bcrypt record.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] when a bcrypt record has an invalid shape,
/// an out-of-alphabet salt or digest, or a cost outside the library's range.
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

    // The shape is not enough: `bcrypt::verify` decodes both fields and fails
    // *before* running the KDF when either is undecodable, so admitting such
    // a record makes that user-id answer in 25ns against 41ms for a real
    // cost-10 one -- measured -- which is the user-enumeration oracle the
    // dummy-verification path exists to close. A correct alphabet does not
    // imply a decodable field: 22 characters carry 132 bits for a 128-bit
    // salt, so the final character's spare bits must be zero, and `z` in that
    // position is in the alphabet yet still rejected.
    //
    // Decoded with the verifier's own engine and field widths rather than a
    // reimplementation of that rule, so the two cannot disagree about which
    // records are decodable.
    decode_bcrypt_field(stored.get(7..29), &mut [0_u8; 16])?;
    decode_bcrypt_field(stored.get(29..), &mut [0_u8; 23])?;

    cost.parse::<u32>()
        .map(Some)
        .map_err(|_not_a_number| HashError::Malformed)
}

/// Decode one bcrypt field into a buffer sized for its plaintext width.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] when the field is absent or does not decode
/// to exactly the buffer's width.
///
/// [`HashError::Malformed`]: HashError::Malformed
fn decode_bcrypt_field(field: Option<&str>, buffer: &mut [u8]) -> Result<(), HashError> {
    let field = field.ok_or(HashError::Malformed)?;
    let written = bcrypt::BASE_64
        .decode_slice(field.as_bytes(), buffer)
        .map_err(|_undecodable_field| HashError::Malformed)?;
    // `decode_slice` is content with a short field, which would leave the tail
    // of the buffer unwritten; the verifier's fixed-width arrays would then
    // read bytes the record never carried.
    if written != buffer.len() {
        return Err(HashError::Malformed);
    }
    Ok(())
}

/// Create a bcrypt hash for dummy verification at the requested work factor.
///
/// Use only when a directory holds no records at all. A populated directory
/// reuses one of its own records, which costs the same as every other record
/// in it by the uniformity rule. Always discard the verification verdict for
/// an unknown user.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] if the hash cannot be created.
///
/// [`HashError::Malformed`]: HashError::Malformed
pub fn empty_directory_hash() -> Result<ParsedHash, HashError> {
    let encoded = bcrypt::hash("ppe-basic-dummy-verification-target", EMPTY_DIRECTORY_COST)
        .map_err(|_cannot_mint| HashError::Malformed)?;
    Ok(ParsedHash {
        profile: CostProfile::Bcrypt {
            cost: EMPTY_DIRECTORY_COST,
        },
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
    let matched = (|| match hash.scheme() {
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
