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
// Underlying hash. bcrypt is Blowfish-based and argon2 is BLAKE2b-based, so
// neither is built on a SHA-2 primitive, and a deployment restricted to the
// hashes FIPS 180-4 specifies cannot use either however well they resist
// cracking. sha256crypt (`$5$`) and sha512crypt (`$6$`) are SHA-2 iterated per
// Drepper's scheme -- FIPS 180-4 covers those SHA-2 functions, not this
// password scheme built on them, so the distinction here is the primitive and
// not an approval of the scheme. They are the SHA-2-based option `.htpasswd`
// can actually carry -- `crypt(3)` and `mkpasswd` write them, and a shadow
// file already holds them. They are accepted on the
// same terms as the other two: admitted only with parameters the verifier will
// run in full, under a round ceiling, and one cost profile per file.
//
// Note what is deliberately NOT here: any way to produce a hash for storage.
// PPE verifies; minting belongs to whatever owns the password.

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordVerifier as _};
use base64::Engine as _;
use sha_crypt::{PasswordHashRef, ShaCrypt};
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

/// The round count a sha-crypt record without an explicit `rounds=` runs.
pub const SHA_CRYPT_DEFAULT_ROUNDS: u32 = 5_000;

/// The lowest round count the sha-crypt format allows.
pub const SHA_CRYPT_ROUNDS_MIN: u32 = 1_000;

/// The highest round count the sha-crypt format allows.
pub const SHA_CRYPT_ROUNDS_MAX: u32 = 999_999_999;

/// The maximum sha-crypt salt length, in characters.
pub const SHA_CRYPT_MAX_SALT_CHARS: usize = 16;

/// The crypt-base64 width of a sha256crypt digest, in characters.
const SHA256_CRYPT_DIGEST_CHARS: usize = 43;

/// The crypt-base64 width of a sha512crypt digest, in characters.
const SHA512_CRYPT_DIGEST_CHARS: usize = 86;

/// The hashing scheme of a stored record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Scheme {
    /// bcrypt, in any of the `$2a$` / `$2b$` / `$2y$` spellings.
    Bcrypt,

    /// argon2, in any of the three variants, as a PHC string.
    Argon2,

    /// sha256crypt (`$5$`) or sha512crypt (`$6$`), as an MCF string.
    ///
    /// The SHA-2-based option: both iterate SHA-2 ([FIPS 180-4] specifies
    /// those functions, not this password scheme), which neither bcrypt nor
    /// argon2 does.
    ///
    /// [FIPS 180-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    ShaCrypt,
}

/// Which sha-crypt function a record uses.
///
/// `$5$` and `$6$` are different functions, not two parameterisations of one,
/// so the variant is part of a record's [`CostProfile`].
///
/// [`CostProfile`]: CostProfile
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShaCryptVariant {
    /// sha256crypt, spelled `$5$`.
    Sha256,

    /// sha512crypt, spelled `$6$`.
    Sha512,
}

impl ShaCryptVariant {
    /// The MCF identifier an operator sees in the file.
    pub fn ident(self) -> &'static str {
        match self {
            Self::Sha256 => "$5$",
            Self::Sha512 => "$6$",
        }
    }
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
         plugin does not verify; re-hash the file with bcrypt, argon2, or -- where a \
         SHA-2 based hash is required -- sha256crypt (`$5$`) or sha512crypt (`$6$`)"
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

    /// Sha-crypt parameters: the function, and the round count it runs.
    ShaCrypt {
        /// Which function (`$5$` or `$6$`), since the two differ in cost.
        variant: ShaCryptVariant,
        /// Rounds of the digest function.
        rounds: u32,
    },
}

impl CostProfile {
    /// The scheme this profile belongs to.
    pub fn scheme(self) -> Scheme {
        match self {
            Self::Bcrypt { .. } => Scheme::Bcrypt,
            Self::Argon2 { .. } => Scheme::Argon2,
            Self::ShaCrypt { .. } => Scheme::ShaCrypt,
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
            Self::ShaCrypt { variant, rounds } => {
                format!("{} rounds={rounds}", variant.ident())
            },
        }
    }
}

/// A stored hash admitted for password verification.
///
/// Carries its own encoding, which no accessor returns: the record is readable
/// only by the verification call in this module, and `Debug` redacts it. A
/// holder can read the cost parameters and the scheme, nothing more.
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
///
/// Deliberately not `#[non_exhaustive]`, unlike the enums in this module.
/// Every field is a ceiling with a sane default, so the supported way to build
/// one is to name the ceilings being changed and defer the rest:
///
/// ```
/// use praxis_policy_builtins::plugins::identity_basic::Limits;
///
/// let limits = Limits {
///     max_bcrypt_cost: 12,
///     ..Limits::default()
/// };
/// assert_eq!(limits.max_bcrypt_cost, 12);
/// ```
///
/// That pattern already absorbs a new ceiling without a caller change, which
/// is what `#[non_exhaustive]` would be buying -- and it would cost the
/// pattern itself, since the attribute forbids functional update even inside
/// this crate. A caller who instead names all four fields is opting out of
/// that, and a new ceiling will not compile for them. Sealing the type is
/// therefore a change to make when a field is actually added, not before.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The highest bcrypt cost this directory will load.
    pub max_bcrypt_cost: u32,

    /// The highest argon2 memory cost, in KiB.
    pub max_argon2_memory_kib: u32,

    /// The highest argon2 time cost (passes).
    pub max_argon2_time_cost: u32,

    /// The highest sha-crypt round count this directory will load.
    pub max_sha_crypt_rounds: u32,
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
            // Sha-crypt rounds are linear, so the useful range sits far above
            // bcrypt's exponent in raw count: glibc's default is 5_000 and a
            // hardened file uses 100_000-656_000. Measured for `$6$` on
            // current hardware, 5_000 is 0.8ms, 100_000 is 12ms and this
            // ceiling is 82ms -- under bcrypt 12's ~250ms, so it admits every
            // sane deployment. What it refuses is the top of the range the
            // format allows and `Params` accepts: `rounds=999999999` is ~82
            // seconds of CPU for a single login.
            max_sha_crypt_rounds: 1_000_000, // ~82ms for $6$
        }
    }
}

/// Admit a stored bcrypt, argon2, or sha-crypt hash under the configured
/// parameter ceilings.
///
/// DES-crypt, plaintext, MD5, and SHA-1 records are refused.
///
/// Where a deployment is restricted to a SHA-2 underlying hash, use sha256crypt
/// (`$5$`) or sha512crypt (`$6$`); `mkpasswd -m sha512crypt` writes them, and
/// every record in one file must share a single cost profile.
///
/// ```
/// use praxis_policy_builtins::plugins::identity_basic::{
///     Limits, Scheme, ShaCryptVariant,
/// };
/// use praxis_policy_builtins::plugins::identity_basic::verifier::{
///     CostProfile, parse_hash,
/// };
///
/// let stored = "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.\
///               ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
/// let stored: String = stored.split_whitespace().collect();
///
/// let admitted = parse_hash(&stored, &Limits::default())?;
/// assert_eq!(admitted.scheme(), Scheme::ShaCrypt);
/// assert_eq!(
///     admitted.profile(),
///     CostProfile::ShaCrypt {
///         variant: ShaCryptVariant::Sha512,
///         rounds: 100_000,
///     },
/// );
/// # Ok::<(), praxis_policy_builtins::plugins::identity_basic::HashError>(())
/// ```
///
/// A round count above the configured ceiling is refused at load, so an
/// extreme record cannot turn one login into a denial of service:
///
/// ```
/// use praxis_policy_builtins::plugins::identity_basic::{HashError, Limits};
/// use praxis_policy_builtins::plugins::identity_basic::verifier::parse_hash;
///
/// let stored = "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.\
///               ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
/// let stored: String = stored.split_whitespace().collect();
///
/// let limits = Limits {
///     max_sha_crypt_rounds: 50_000,
///     ..Limits::default()
/// };
/// assert_eq!(
///     parse_hash(&stored, &limits).err(),
///     Some(HashError::ParametersTooHigh),
/// );
/// ```
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

    if let Some(variant) = sha_crypt_variant(stored) {
        return admit_sha_crypt(stored, variant, limits);
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

/// Read the sha-crypt variant from a record's MCF identifier.
///
/// Returns `None` for a record that is not sha-crypt.
fn sha_crypt_variant(stored: &str) -> Option<ShaCryptVariant> {
    match stored.get(..3) {
        Some("$5$") => Some(ShaCryptVariant::Sha256),
        Some("$6$") => Some(ShaCryptVariant::Sha512),
        _ => None,
    }
}

/// Admit a sha-crypt record under the configured round ceiling.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] for a record the verifier would reject
/// before running the digest, or [`HashError::ParametersTooHigh`] for a round
/// count above `limits`.
///
/// [`HashError::Malformed`]: HashError::Malformed
/// [`HashError::ParametersTooHigh`]: HashError::ParametersTooHigh
fn admit_sha_crypt(
    stored: &str,
    variant: ShaCryptVariant,
    limits: &Limits,
) -> Result<ParsedHash, HashError> {
    // MCF parsing rejects an empty field, a salt outside the crypt alphabet
    // and an undecodable digest, so a record reaching the checks below is one
    // whose shape the verifier can read. No empty-salt or empty-digest check
    // below for that reason: every spelling of one (`$6$salt$`, `$6$$salt$x`)
    // fails here as `DelimiterInvalid` or `FieldInvalid`, so such a check
    // would be unreachable.
    let parsed = PasswordHashRef::new(stored).map_err(|_mcf_error| HashError::Malformed)?;
    let mut fields = parsed.fields();

    let first = fields.next().ok_or(HashError::Malformed)?;

    // `rounds=` is optional in this format: `$6$salt$hash` means the spec's
    // default of 5_000, which is what glibc and `mkpasswd` write when nobody
    // asks for more. So the first field is the round count or the salt, and
    // which one it is decides how many fields must follow.
    //
    // A field that *looks* like a round count but does not parse -- `rounds=0`,
    // `rounds=abc`, anything outside the 1_000..=999_999_999 the format allows
    // -- is refused here rather than passed on. The verifier does not reject
    // it: it falls through to treating `rounds=abc` as the salt, derives a
    // digest over the wrong input and answers `false` without ever running the
    // record's real parameters. That answer is both wrong and cheap, which
    // makes the user-id measurably faster to probe than an unknown one -- the
    // same oracle the bcrypt field decode above exists to close.
    let (rounds, salt) = match parse_sha_crypt_rounds(first.as_str())? {
        Some(explicit) => (explicit, fields.next().ok_or(HashError::Malformed)?),
        None => (SHA_CRYPT_DEFAULT_ROUNDS, first),
    };

    // The digest must be present. Without it the verifier errors out before
    // the KDF, which is the same timing signal as a refused record.
    let digest = fields.next().ok_or(HashError::Malformed)?;
    // And nothing may follow it: the verifier refuses a trailing field, so a
    // record carrying one would answer cheaply for the same reason.
    if fields.next().is_some() {
        return Err(HashError::Malformed);
    }

    // The full digest width for the variant, so a truncated record cannot be
    // admitted and then compared against fewer bytes than it claims.
    let expected = match variant {
        ShaCryptVariant::Sha256 => SHA256_CRYPT_DIGEST_CHARS,
        ShaCryptVariant::Sha512 => SHA512_CRYPT_DIGEST_CHARS,
    };
    if digest.as_str().len() != expected {
        return Err(HashError::Malformed);
    }

    // The salt is capped by the format at 16 characters. The crate does not
    // enforce that -- it hashes whatever it is given -- so a longer salt would
    // verify here and fail against `crypt(3)`, making this backend disagree
    // with the tool that wrote the file.
    if salt.as_str().len() > SHA_CRYPT_MAX_SALT_CHARS {
        return Err(HashError::Malformed);
    }

    if rounds > limits.max_sha_crypt_rounds {
        return Err(HashError::ParametersTooHigh);
    }

    Ok(ParsedHash {
        profile: CostProfile::ShaCrypt { variant, rounds },
        encoded: stored.to_owned(),
    })
}

/// Read an explicit `rounds=` field, if this field is one.
///
/// Returns `Ok(None)` when the field is a salt rather than a round count.
///
/// # Errors
///
/// Returns [`HashError::Malformed`] for a `rounds=` field outside the range the
/// format allows.
///
/// [`HashError::Malformed`]: HashError::Malformed
fn parse_sha_crypt_rounds(field: &str) -> Result<Option<u32>, HashError> {
    let Some(digits) = field.strip_prefix("rounds=") else {
        return Ok(None);
    };
    let rounds: u32 = digits
        .parse()
        .map_err(|_not_a_number| HashError::Malformed)?;
    if !(SHA_CRYPT_ROUNDS_MIN..=SHA_CRYPT_ROUNDS_MAX).contains(&rounds) {
        return Err(HashError::Malformed);
    }
    Ok(Some(rounds))
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
        Scheme::ShaCrypt => {
            // The variant and rounds come from the record, not from this
            // hasher: `ShaCrypt`'s verify reads both out of the encoding and
            // compares with `ct_eq`, so the value here only supplies defaults
            // it does not use. No length ceiling as bcrypt needs above --
            // sha-crypt consumes the whole password rather than truncating it.
            u8::from(
                ShaCrypt::SHA512
                    .verify_password(bytes, hash.encoded.as_str())
                    .is_ok(),
            )
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
