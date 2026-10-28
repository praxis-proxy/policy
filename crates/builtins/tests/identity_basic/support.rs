// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fixtures the cases share: building a credential location gate and driving
//! the RFC 7617 decode step over a header value.

use praxis_policy_builtins::plugins::identity_basic::credential::{
    BasicCredential, CredentialLocation, decode_basic,
};
use praxis_policy_core::extensions::raw_credentials::Credential;

/// The default ceiling the cases use when they are not exercising R26.
pub const CEILING: usize = 255;

/// An `Authorization: Basic` gate, as the plugin configures one.
pub fn gate() -> CredentialLocation {
    CredentialLocation::new(
        Credential::Header {
            name: "Authorization".to_owned(),
        },
        Some("Basic ".to_owned()),
    )
}

/// Run the gate and the decode step over one header value.
///
/// Mirrors the resolver's own order: extract, then decode. Returns the
/// extraction error as a string so a case can assert on which phase failed
/// without this helper needing a third error type.
pub fn extract_and_decode(header: &str) -> Result<BasicCredential, String> {
    extract_and_decode_with(header, CEILING, CEILING)
}

/// As [`extract_and_decode`], with explicit length ceilings for R26.
pub fn extract_and_decode_with(
    header: &str,
    max_user_id: usize,
    max_password: usize,
) -> Result<BasicCredential, String> {
    let location = gate();
    let headers =
        std::collections::HashMap::from([("authorization".to_owned(), header.to_owned())]);
    let raw = location.raw(&headers, None).map_err(|e| format!("{e:?}"))?;
    decode_basic(raw, max_user_id, max_password).map_err(|e| format!("{e:?}"))
}

/// Base64 of a raw credential, for building the malformed cases.
pub fn b64(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Whether a rejection is a decode-phase one rather than an extraction-phase
/// one.
///
/// Every `DecodeError` variant is a malformed-credential rejection that the
/// resolver maps onto one external denial code; the variants exist so an
/// operator reading a debug log can tell the shapes apart, and a case asserts
/// on them only to pin that the *right* shape was detected. The two
/// extraction-phase outcomes a decode case must never produce are a decline
/// (`WrongPrefix`, which belongs to another resolver) and `Empty`.
pub fn is_malformed(err: &str) -> bool {
    // Exact matches: `EmptyHalf` is a decode rejection and must not be confused
    // with the extraction phase's `Empty`.
    !matches!(err, "WrongPrefix" | "Missing" | "Empty" | "Ambiguous")
}

/// The error from decoding a header that must not decode.
///
/// A separate helper rather than `expect_err` on the result, because
/// `BasicCredential` deliberately implements no `Debug` — the type exists to
/// make a credential unprintable, and a test must not be the reason a `Debug`
/// impl gets added. So the Ok case is discarded here and reported as a plain
/// panic message carrying nothing from the credential.
pub fn decode_failure(header: &str) -> String {
    match extract_and_decode(header) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}

/// As [`decode_failure`], with explicit length ceilings for R26.
pub fn decode_failure_with(header: &str, max_user_id: usize, max_password: usize) -> String {
    match extract_and_decode_with(header, max_user_id, max_password) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}
