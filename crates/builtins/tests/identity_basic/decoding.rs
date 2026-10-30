// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! RFC 7617 credential decoding: the gate, the base64 step, the split, and the
//! normalisation — plus every shape that must not reach a directory lookup.
//!
//! The scheme and `1*SP` rules follow [RFC 7235 Section 2.1]; the
//! `user-id:password` construction and its `B64token` encoding are
//! [RFC 7617 Section 2].
//!
//! [RFC 7235 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
//! [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2

use praxis_policy_builtins::plugins::identity_basic::credential::DecodeError;
use praxis_policy_core::identity::credential::ExtractionError;

use crate::support::{
    Failure, b64, decode_failure, decode_failure_with, extract_and_decode, extract_and_decode_with,
    password,
};

/// The RFC 7617 Section 2 worked example, which every other case is a
/// variation on.
const ALADDIN: &str = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// RFC 7617 Section 2
// -----------------------------------------------------------------------------

/// Decode the worked example per [RFC 7617 Section 2].
///
/// [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2
#[test]
fn rfc_7617_example_round_trips() {
    let got = extract_and_decode(ALADDIN).expect("the RFC example decodes");
    assert_eq!(got.user_id(), "Aladdin");
    assert!(
        got.password_matches(b"open sesame"),
        "the RFC 7617 Section 2 example password"
    );
}

// -----------------------------------------------------------------------------
// RFC 7235 Section 2.1
// -----------------------------------------------------------------------------

/// Match authentication schemes case-insensitively per [RFC 7235 Section 2.1].
///
/// [RFC 7235 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
#[test]
fn scheme_matching_ignores_case() {
    for header in [
        "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "bAsIc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
    ] {
        let got = extract_and_decode(header).expect("the scheme matches without case");
        assert_eq!(got.user_id(), "Aladdin");
    }
}

// -----------------------------------------------------------------------------
// RFC 7235 Section 2.1
// -----------------------------------------------------------------------------

/// Accept one or more spaces after the authentication scheme per [RFC 7235 Section 2.1].
///
/// [RFC 7235 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
#[test]
fn multiple_spaces_after_the_scheme_are_consumed() {
    let got = extract_and_decode("Basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        .expect("1*SP allows more than one space");
    assert_eq!(got.user_id(), "Aladdin");
}

#[test]
fn trailing_whitespace_after_the_token_still_decodes() {
    let got = extract_and_decode("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==  ")
        .expect("trailing OWS is trimmed before decoding");
    assert_eq!(got.user_id(), "Aladdin");
}

#[test]
fn another_scheme_declines_rather_than_denying() {
    assert_eq!(
        decode_failure("Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        Failure::Extraction(ExtractionError::WrongPrefix),
        "a Bearer credential must decline so another resolver can serve it, not deny"
    );
}

// -----------------------------------------------------------------------------
// RFC 7617 Section 2
// -----------------------------------------------------------------------------

/// Treat colons after the user-id separator as password bytes per [RFC 7617 Section 2].
///
/// [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2
#[test]
fn the_password_keeps_every_colon_after_the_first() {
    let got = extract_and_decode(&format!("Basic {}", b64(b"user:pa:ss:word")))
        .expect("a colon-bearing password decodes");
    assert_eq!(got.user_id(), "user");
    assert!(
        got.password_matches(b"pa:ss:word"),
        "every colon after the first belongs to the password"
    );
}

#[test]
fn a_credential_with_no_colon_is_malformed() {
    assert_eq!(
        decode_failure(&format!("Basic {}", b64(b"nocolonhere"))),
        Failure::Decode(DecodeError::NoSeparator),
        "a credential with no colon has no user-id/password boundary"
    );
}

#[test]
fn non_base64_input_is_malformed() {
    assert_eq!(
        decode_failure("Basic not!valid!base64!"),
        Failure::Decode(DecodeError::NotBase64),
        "the payload must be base64"
    );
}

#[test]
fn non_canonical_padding_is_malformed() {
    assert_eq!(
        decode_failure("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ"),
        Failure::Decode(DecodeError::NotBase64),
        "padding is strict, so the RFC example without its `==` is refused"
    );
}

#[test]
fn invalid_utf8_is_malformed() {
    assert_eq!(
        decode_failure(&format!("Basic {}", b64(&[0x80, b':', b'p']))),
        Failure::Decode(DecodeError::NotUtf8),
        "a lone continuation byte is not UTF-8"
    );
}

#[test]
fn an_empty_user_id_or_password_is_rejected() {
    for raw in [&b":password"[..], b"user:", b":"] {
        assert_eq!(
            decode_failure(&format!("Basic {}", b64(raw))),
            Failure::Decode(DecodeError::EmptyHalf),
            "neither half may be empty, and this is the decode phase's \
             `EmptyHalf`, not the extraction phase's `Empty`: {raw:?}"
        );
    }
}

// -----------------------------------------------------------------------------
// RFC 7617 Section 2
// -----------------------------------------------------------------------------

/// Reject control characters in credentials per [RFC 7617 Section 2].
///
/// [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2
#[test]
fn control_characters_in_either_half_are_rejected() {
    for raw in [
        &b"us\ner:password"[..],
        b"user:pass\nword",
        b"us\x00er:password",
        b"user:pass\x7fword",
        "us\u{2028}er:password".as_bytes(),
        "user:pass\u{2029}word".as_bytes(),
    ] {
        assert_eq!(
            decode_failure(&format!("Basic {}", b64(raw))),
            Failure::Decode(DecodeError::ControlCharacter),
            "a control character must be rejected as one rather than as some \
             other malformed shape: {raw:?}"
        );
    }
}

#[test]
fn bidi_overrides_and_isolates_in_the_user_id_are_rejected() {
    for marker in [
        "\u{202e}", "\u{202d}", "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
    ] {
        let raw = format!("ad{marker}min:password");
        assert_eq!(
            decode_failure(&format!("Basic {}", b64(raw.as_bytes()))),
            Failure::Decode(DecodeError::ControlCharacter),
            "a bidi control must be rejected as a control character: {marker:?}"
        );
    }
}

#[test]
fn decomposed_and_precomposed_user_ids_normalise_to_one_key() {
    let precomposed = extract_and_decode(&format!("Basic {}", b64("José:pw".as_bytes())))
        .expect("the precomposed form decodes");
    let decomposed = extract_and_decode(&format!("Basic {}", b64("Jose\u{0301}:pw".as_bytes())))
        .expect("the decomposed form decodes");
    assert_eq!(
        precomposed.user_id(),
        decomposed.user_id(),
        "both encodings of one name must normalise to a single index key"
    );
    assert_eq!(precomposed.user_id(), "José");
}

#[test]
fn the_password_is_not_normalised() {
    let decomposed = "pa\u{0301}ssword";
    let got = extract_and_decode(&format!(
        "Basic {}",
        b64(format!("user:{decomposed}").as_bytes())
    ))
    .expect("a decomposed password decodes");
    assert!(
        got.password_matches(decomposed.as_bytes()),
        "the password must survive as the bytes the client sent"
    );
    assert!(
        !got.password_matches(b"password"),
        "normalising the password would break hash matching"
    );
}

#[test]
fn a_user_id_or_password_past_the_ceiling_is_rejected() {
    let long = "u".repeat(40);
    assert_eq!(
        decode_failure_with(
            &format!("Basic {}", b64(format!("{long}:pw").as_bytes())),
            16,
            16
        ),
        Failure::Decode(DecodeError::TooLong),
        "an over-ceiling user-id is rejected before any verification"
    );

    assert_eq!(
        decode_failure_with(
            &format!("Basic {}", b64(format!("user:{long}").as_bytes())),
            16,
            16
        ),
        Failure::Decode(DecodeError::TooLong),
        "an over-ceiling password is rejected before any verification"
    );
}

#[test]
fn a_decode_failure_message_carries_no_credential_bytes() {
    let secret = "s3cr3t-paSSw0rd";
    for raw in [
        format!("nocolon{secret}"),
        format!("user:{secret}\n"),
        format!(":{secret}"),
    ] {
        let rendered = format!(
            "{:?}",
            decode_failure(&format!("Basic {}", b64(raw.as_bytes())))
        );
        assert!(
            !rendered.contains(secret) && !rendered.contains("s3cr3t"),
            "a decode error leaked credential material: {rendered}"
        );
    }
    let rendered = format!("{:?}", decode_failure(&format!("Basic !!{secret}!!")));
    assert!(
        !rendered.contains(secret),
        "a base64 error leaked credential material: {rendered}"
    );
}

#[test]
fn extraction_phase_outcomes_reuse_the_established_errors() {
    assert_eq!(
        crate::support::gate()
            .raw(&std::collections::HashMap::new(), None)
            .expect_err("nothing at the location"),
        ExtractionError::Missing,
        "an absent header is the gate's `Missing`"
    );

    assert_eq!(
        decode_failure("Basic "),
        Failure::Extraction(ExtractionError::Empty),
        "a scheme with no credential is the extraction phase's `Empty`, which must \
         stay distinct from the decode phase's `EmptyHalf`"
    );

    assert_eq!(
        decode_failure(""),
        Failure::Extraction(ExtractionError::Empty),
        "an empty header value is likewise an extraction-phase `Empty`"
    );
}

#[test]
fn an_oversized_header_is_rejected_before_any_buffer_is_allocated() {
    let huge = "A".repeat(1_048_576); // 1 MiB
    assert_eq!(
        decode_failure_with(&format!("Basic {huge}"), 16, 16),
        Failure::Decode(DecodeError::TooLong),
        "a 1 MiB payload under 16-byte ceilings must be refused on length as \
         TooLong; the decode buffer is sized from the header, so a NotBase64 or \
         NotUtf8 verdict here would mean the allocation already happened"
    );

    let fits = b64(b"user:password123");
    extract_and_decode_with(&format!("Basic {fits}"), 16, 16)
        .expect("a credential within both ceilings still decodes, so the bound is not too tight");
}

#[test]
fn a_credential_exactly_at_the_length_ceiling_is_accepted() {
    let at_limit = "u".repeat(16);
    let password = "p".repeat(16);
    let encoded = b64(format!("{at_limit}:{password}").as_bytes());

    let got = extract_and_decode_with(&format!("Basic {encoded}"), 16, 16)
        .expect("a credential exactly at both ceilings is within them, not over");
    assert_eq!(
        got.user_id(),
        at_limit,
        "the boundary is inclusive, so a 16-byte user-id under a 16-byte ceiling decodes"
    );
}

#[test]
fn a_credential_one_byte_over_the_ceiling_is_rejected() {
    let over = "u".repeat(17);
    let encoded_user = b64(format!("{over}:pw").as_bytes());
    assert_eq!(
        decode_failure_with(&format!("Basic {encoded_user}"), 16, 16),
        Failure::Decode(DecodeError::TooLong),
        "17 bytes under a 16-byte user-id ceiling is over the limit"
    );

    let encoded_password = b64(format!("user:{over}").as_bytes());
    assert_eq!(
        decode_failure_with(&format!("Basic {encoded_password}"), 16, 16),
        Failure::Decode(DecodeError::TooLong),
        "and 17 bytes under a 16-byte password ceiling is too"
    );
}

#[test]
fn each_half_is_measured_against_its_own_ceiling() {
    let long = "x".repeat(40);
    let within_user_only = b64(format!("{long}:pw").as_bytes());
    extract_and_decode_with(&format!("Basic {within_user_only}"), 64, 8)
        .expect("a long user-id under a generous user ceiling passes a tight password ceiling");

    let within_password_only = b64(format!("u:{long}").as_bytes());
    extract_and_decode_with(&format!("Basic {within_password_only}"), 8, 64)
        .expect("and the reverse, so the two ceilings are not conflated");

    assert_eq!(
        decode_failure_with(&format!("Basic {within_user_only}"), 8, 64),
        Failure::Decode(DecodeError::TooLong),
        "a user-id over its own ceiling is rejected even when the password ceiling is generous"
    );
}

#[test]
fn an_encoded_payload_exactly_at_the_derived_bound_is_accepted() {
    let user_id = "u".repeat(8);
    let password = "p".repeat(8);
    let encoded = b64(format!("{user_id}:{password}").as_bytes());

    extract_and_decode_with(&format!("Basic {encoded}"), 8, 8).expect(
        "the pre-decode length bound is derived from the ceilings plus the \
         separator, so a credential that fits them must not be refused by it",
    );
}

#[test]
fn password_matching_rejects_a_single_differing_byte() {
    let credential = password("correct horse battery staple");

    assert!(
        credential.password_matches(b"correct horse battery staple"),
        "the exact password matches"
    );
    assert!(
        !credential.password_matches(b"correct horse battery stapleX"),
        "a longer password must not match"
    );
    assert!(
        !credential.password_matches(b"correct horse battery stapl"),
        "nor a shorter one"
    );
    assert!(
        !credential.password_matches(b"Correct horse battery staple"),
        "a difference in the first byte must not match, which an accumulator \
         folded with the wrong operator would miss"
    );
    assert!(
        !credential.password_matches(b"correct horse battery stapla"),
        "nor a difference in the last byte, so every byte reaches the verdict"
    );
    assert!(
        !credential.password_matches(b"correct hcrse battery staple"),
        "nor one in the middle"
    );
}

#[test]
fn password_matching_rejects_differences_that_cancel_pairwise() {
    let credential = password("ab");

    assert!(
        !credential.password_matches(b"ba"),
        "a transposition must not match: the per-byte differences are equal, so \
         an accumulator folded with XOR instead of OR would cancel them to zero \
         and report a match"
    );

    let repeated_delta = password("cc");
    assert!(
        !repeated_delta.password_matches(b"aa"),
        "nor two bytes differing by the same amount, which is the minimal case \
         where an XOR fold disagrees with an OR fold"
    );
}
