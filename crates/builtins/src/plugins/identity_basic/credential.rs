// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Decode extracted HTTP Basic credentials per [RFC 7617 Section 2].
//!
//! [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2

use base64::Engine as _;
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

pub use praxis_policy_core::identity::credential::{CredentialLocation, ExtractionError};

/// Why an extracted credential cannot be decoded as Basic authentication.
///
/// Errors contain no credential bytes and are safe to include in diagnostics.
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

    /// The user-id or password is empty.
    #[error("the credential carries an empty user-id or password")]
    EmptyHalf,

    /// A control character, line/paragraph separator, or bidi control.
    #[error("the credential carries a disallowed control character")]
    ControlCharacter,

    /// One half is longer than the configured ceiling.
    #[error("the credential exceeds the configured length ceiling")]
    TooLong,
}

/// A password that cannot be formatted or serialized.
pub(in crate::plugins::identity_basic) struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Pass the password bytes to a verifier.
    pub(in crate::plugins::identity_basic) fn verify_with<T>(
        &self,
        verify: impl FnOnce(&[u8]) -> T,
    ) -> T {
        verify(&self.0)
    }

    /// Copy the password into a zeroizing buffer for a blocking task.
    pub(in crate::plugins::identity_basic) fn to_zeroized_vec(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

/// A decoded Basic credential with an NFC-normalised user-id and unchanged password.
///
/// Credentials cannot be formatted or serialized.
///
/// Formatting a credential does not compile:
///
/// ```compile_fail
/// use praxis_policy_builtins::plugins::identity_basic::decode_basic;
/// let credential = decode_basic("dXNlcjpwdw==".to_owned(), 255, 255).unwrap();
/// println!("{credential:?}");
/// ```
///
/// Nor does serializing one:
///
/// ```compile_fail
/// use praxis_policy_builtins::plugins::identity_basic::decode_basic;
/// let credential = decode_basic("dXNlcjpwdw==".to_owned(), 255, 255).unwrap();
/// let _ = serde_json::to_string(&credential);
/// ```
pub struct BasicCredential {
    user_id: String,
    password: Password,
}

impl BasicCredential {
    /// The NFC-normalised user-id, as the directory indexes it.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The password, for a verifier in this plugin.
    pub(in crate::plugins::identity_basic) fn password(&self) -> &Password {
        &self.password
    }

    /// Copy the password into a zeroizing buffer for a blocking verification.
    ///
    /// The host header map may still retain the original credential.
    pub fn to_zeroized_password(&self) -> Zeroizing<Vec<u8>> {
        self.password.to_zeroized_vec()
    }

    /// Compare the password with expected bytes for decoding tests.
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

/// Decode an extracted Basic payload into an NFC-normalised user-id and a password.
///
/// Accepts canonical STANDARD base64 with trailing HTTP whitespace. The decoded
/// credential must be UTF-8, contain a colon, and have nonempty halves without
/// disallowed control characters. Length ceilings are measured in bytes before
/// normalisation. Password bytes are preserved.
///
/// # Errors
///
/// Returns a [`DecodeError`] for malformed or overlong credentials.
///
/// [`DecodeError`]: DecodeError
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

/// Whether a credential half contains a disallowed control character.
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
