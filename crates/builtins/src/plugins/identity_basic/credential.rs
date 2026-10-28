// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! RFC 7617 credential decoding: what happens after the shared gate has
//! matched the scheme and before a directory is asked anything.
//!
//! Extraction itself is not reimplemented here. [`CredentialLocation`] with
//! `prefix: Some("Basic ")` already does case-insensitive scheme matching and
//! consumes `1*SP` per [RFC 7235 Section 2.1], returning the `token68` payload
//! verbatim. Re-deriving that would re-open a class of conformance bugs the
//! shared gate has already closed and tested. This module owns only the steps
//! the gate cannot know about: base64, the split, and normalisation.
//!
//! [RFC 7235 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1

use base64::Engine as _;
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

pub use praxis_policy_core::identity::credential::{CredentialLocation, ExtractionError};

/// Why a syntactically extracted credential is not a usable RFC 7617 one.
///
/// Deliberately field-free. Every variant is a shape, never a value: these
/// reach denial reasons and log lines, and a variant carrying the offending
/// byte, its offset, or the buffer it came from would publish the password one
/// `{e}` at a time. The upstream base64 and UTF-8 error types do carry exactly
/// that, which is why neither is wrapped and both are discarded at the call
/// site.
///
/// All of these map onto one external denial code. An attacker learns which
/// *shape* their own header was, which they already know; they must not learn
/// anything that distinguishes a wrong password from an unknown user, and
/// nothing here is reachable once a lookup has happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The payload is not canonical, strictly padded STANDARD base64.
    #[error("the credential is not canonically padded base64")]
    NotBase64,

    /// The decoded octets are not UTF-8.
    #[error("the decoded credential is not UTF-8")]
    NotUtf8,

    /// No colon, so there is no user-id / password boundary.
    #[error("the decoded credential carries no user-id separator")]
    NoSeparator,

    /// One half is empty. RFC 7617 gives no meaning to either.
    #[error("the credential carries an empty user-id or password")]
    EmptyHalf,

    /// A control character, line/paragraph separator, or bidi control.
    #[error("the credential carries a disallowed control character")]
    ControlCharacter,

    /// One half is longer than the configured ceiling.
    #[error("the credential exceeds the configured length ceiling")]
    TooLong,
}

/// A password, held so that it is hard to leak by accident.
///
/// No `Debug`, no `Display`, no `Serialize`, and no accessor returning the
/// bytes: the only reader is [`verify_with`], which hands them to a closure
/// that must consume them in place. A password reaching a log line or a
/// serialized payload is the failure this type exists to make impossible, and
/// unlike an API key a password is also a credential *the user chose*, so a
/// leak compromises every other service they reused it on.
///
/// Scoped to this plugin rather than `pub(crate)`: `pub(crate)` now reaches all
/// ten builtins, and nothing outside this module tree has any business holding
/// one.
///
/// Zeroizing here is partial, and honestly so, exactly as [`PresentedKey`] is.
/// The host hands the engine its headers as `HashMap<String, String>` and the
/// shared gate returns an owned `String`, so unzeroized copies of the
/// credential already exist for the life of the request. Clearing this one
/// shortens the exposure rather than ending it.
///
/// [`PresentedKey`]: crate::plugins::identity_api_key::PresentedKey
/// [`verify_with`]: Password::verify_with
///
/// The absence of those traits is load-bearing, so it is pinned by the
/// compiler rather than by a runtime assertion — a test that merely *looks*
/// for a missing trait impl tends to pass whatever it finds. Formatting a
/// credential does not compile:
///
/// ```compile_fail
/// # use praxis_policy_builtins::plugins::identity_basic::decode_basic;
/// let credential = decode_basic("dXNlcjpwdw==".to_owned(), 255, 255).unwrap();
/// // `BasicCredential` implements no `Debug`, so this is rejected.
/// println!("{credential:?}");
/// ```
///
/// Nor does serializing one:
///
/// ```compile_fail
/// # use praxis_policy_builtins::plugins::identity_basic::decode_basic;
/// let credential = decode_basic("dXNlcjpwdw==".to_owned(), 255, 255).unwrap();
/// let _ = serde_json::to_string(&credential);
/// ```
pub(in crate::plugins::identity_basic) struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// The octets, for a verifier to consume within the calling expression.
    ///
    /// The only reader, and it takes a closure rather than returning a slice so
    /// that a caller cannot bind the bytes to a longer-lived value: copying
    /// them into an owned `Vec` would take the password out from under the
    /// zeroizing buffer, and that copy is not cleared.
    pub(in crate::plugins::identity_basic) fn verify_with<T>(
        &self,
        verify: impl FnOnce(&[u8]) -> T,
    ) -> T {
        verify(&self.0)
    }
}

/// A decoded RFC 7617 credential: an index key and a secret.
///
/// The halves are deliberately different types. The user-id is text because it
/// *is* an index key and must be normalised and compared as text; the password
/// is opaque octets because every text operation on it — case folding,
/// trimming, normalising — would map two different passwords onto one hash
/// lookup, and because `==` on `str` is not constant time.
pub struct BasicCredential {
    user_id: String,
    password: Password,
}

impl BasicCredential {
    /// The NFC-normalised user-id, as the directory indexes it.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Whether the password is exactly these bytes.
    ///
    /// Test-facing: the production path verifies against a stored hash, never
    /// against a known plaintext. Exposed so the decoding cases can pin that
    /// the password survives as the bytes the client sent — without that, no
    /// test could observe the password half at all. Constant-time so this
    /// cannot become a timing oracle if it is ever reached from a request path.
    pub fn password_matches(&self, expected: &[u8]) -> bool {
        self.password.verify_with(|actual| {
            if actual.len() != expected.len() {
                return false;
            }
            // Fold every byte before deciding, so the comparison does not
            // return early on the first difference.
            actual
                .iter()
                .zip(expected)
                .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        })
    }
}

/// Decode what the gate extracted into a user-id and a password.
///
/// The steps, in the order RFC 7617 Section 2 implies and with the reasons the
/// order matters:
///
/// 1. Trim trailing OWS. The shared gate consumes the separator *before* the
///    token but nothing after it, and a legal `Authorization: Basic dG9r `
///    would otherwise fail strict padding.
/// 2. STANDARD base64 with strict padding. Not URL-safe (RFC 7617 says
///    `B64token`), and not lenient: accepting unpadded or non-canonical input
///    means two distinct header values decode to one credential.
/// 3. UTF-8, because the user-id reaches `subject.id` and the logs.
/// 4. Split on the **first** colon. The user-id cannot contain one, so every
///    later colon belongs to the password.
/// 5. Reject an empty half, control characters, and anything past the ceiling —
///    all before NFC, so normalisation never runs on hostile length.
/// 6. NFC the user-id only. The password is hashed as raw bytes, so
///    normalising it would stop a legitimately decomposed password from ever
///    matching its stored hash.
///
/// # Errors
///
/// Returns a [`DecodeError`] for any shape that is not a usable credential.
/// Every variant is a shape rather than a value; see that type.
pub fn decode_basic(
    extracted: String,
    max_user_id: usize,
    max_password: usize,
) -> Result<BasicCredential, DecodeError> {
    // The gate hands back an owned `String`, which is a plaintext copy of the
    // credential. Take ownership of it under a zeroizing buffer immediately so
    // this copy is cleared even on the error paths below.
    let extracted = Zeroizing::new(extracted);
    let payload = extracted.trim_end_matches([' ', '\t']);

    // Pre-sized so the decoded plaintext is written once, into a buffer that is
    // cleared on drop, rather than into a `Vec` that may reallocate and leave
    // the secret in a freed block. The error is discarded rather than wrapped:
    // `base64::DecodeError` names the offending byte and its offset.
    let mut decoded = Zeroizing::new(vec![0_u8; base64::decoded_len_estimate(payload.len())]);
    let written = base64::engine::general_purpose::STANDARD
        .decode_slice(payload.as_bytes(), &mut decoded)
        .map_err(|_carries_offending_byte_and_offset| DecodeError::NotBase64)?;

    // `Utf8Error` carries a valid-prefix length, which is a byte offset into
    // the credential, so it is discarded the same way.
    let text = std::str::from_utf8(decoded.get(..written).ok_or(DecodeError::NotBase64)?)
        .map_err(|_carries_valid_prefix_length| DecodeError::NotUtf8)?;

    let (user_id, password) = text.split_once(':').ok_or(DecodeError::NoSeparator)?;

    if user_id.is_empty() || password.is_empty() {
        return Err(DecodeError::EmptyHalf);
    }
    // Before normalisation, so NFC never runs on an unbounded input. Byte
    // lengths, because that is what a hash function and a header limit see.
    if user_id.len() > max_user_id || password.len() > max_password {
        return Err(DecodeError::TooLong);
    }
    if contains_disallowed(user_id) || contains_disallowed(password) {
        return Err(DecodeError::ControlCharacter);
    }

    Ok(BasicCredential {
        // NFC, not a full PRECIS profile. Enforcing `UsernameCasePreserved`
        // would lock out real users for no gain here, and under-normalising
        // would split one user across two index keys — which NFC is exactly
        // what addresses. Stored user-ids are normalised identically at load.
        user_id: user_id.nfc().collect(),
        password: Password(Zeroizing::new(password.as_bytes().to_vec())),
    })
}

/// Whether a half carries a character that must not reach a log, a header, or
/// `subject.id`.
///
/// Three groups, for three different reasons:
///
/// - **Cc** (C0 and C1). A newline in a user-id is a log-injection primitive,
///   and a CR or LF reaching a `WWW-Authenticate` realm would split the header.
/// - **U+2028 / U+2029**, the line and paragraph separators. Not Cc, but they
///   terminate a line in a JavaScript string literal, so an audit UI rendering
///   a user-id into JSON inherits the same injection.
/// - **The bidi overrides and isolates in Cf**. These re-order rendered text
///   without changing the bytes, so `ad\u{202e}min` can display as another
///   user's name in exactly the audit trail an operator trusts.
///
/// Deliberately not "all of Cf": ZWJ and the variation selectors appear in
/// legitimate names, and refusing them would lock out real users for no
/// security gain. The bidi controls are singled out because their *only*
/// effect is on rendering order.
fn contains_disallowed(half: &str) -> bool {
    half.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{2028}'
                    | '\u{2029}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    })
}
