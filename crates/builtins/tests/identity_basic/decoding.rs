// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! RFC 7617 credential decoding: the gate, the base64 step, the split, and the
//! normalisation — plus every shape that must not reach a directory lookup.
//!
//! Conformance cases cite the clause they pin, per the repo's RFC-citation
//! convention. The scheme and `1*SP` rules are [RFC 7235 Section 2.1]; the
//! `user-id:password` construction and its `B64token` encoding are
//! [RFC 7617 Section 2].
//!
//! [RFC 7235 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
//! [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2

use praxis_policy_builtins::plugins::identity_basic::credential::DecodeError;
use praxis_policy_core::identity::credential::ExtractionError;

use crate::support::{Failure, b64, decode_failure, decode_failure_with, extract_and_decode};

/// The RFC 7617 Section 2 worked example, which every other case is a
/// variation on.
const ALADDIN: &str = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

#[test]
fn rfc_7617_example_round_trips() {
    let got = extract_and_decode(ALADDIN).expect("the RFC example decodes");
    assert_eq!(got.user_id(), "Aladdin");
    assert!(
        got.password_matches(b"open sesame"),
        "the RFC 7617 Section 2 example password"
    );
}

#[test]
fn scheme_matching_ignores_case() {
    // RFC 7235 Section 2.1: the scheme is case-insensitive.
    for header in [
        "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "bAsIc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
    ] {
        let got = extract_and_decode(header).expect("the scheme matches without case");
        assert_eq!(got.user_id(), "Aladdin");
    }
}

#[test]
fn multiple_spaces_after_the_scheme_are_consumed() {
    // RFC 7235 Section 2.1 separates the scheme from the parameters with
    // `1*SP`, so more than one space is legal.
    let got = extract_and_decode("Basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        .expect("1*SP allows more than one space");
    assert_eq!(got.user_id(), "Aladdin");
}

#[test]
fn trailing_whitespace_after_the_token_still_decodes() {
    // The shared gate strips only the leading separator, so a legal header
    // with trailing OWS would otherwise fail strict base64 padding.
    let got = extract_and_decode("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==  ")
        .expect("trailing OWS is trimmed before decoding");
    assert_eq!(got.user_id(), "Aladdin");
}

#[test]
fn another_scheme_declines_rather_than_denying() {
    // A Bearer credential is not this resolver's. The gate reports
    // `WrongPrefix`, which the resolver turns into a decline so a second
    // resolver on the same header can serve it.
    assert_eq!(
        decode_failure("Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        Failure::Extraction(ExtractionError::WrongPrefix),
        "a Bearer credential must decline so another resolver can serve it, not deny"
    );
}

#[test]
fn the_password_keeps_every_colon_after_the_first() {
    // RFC 7617 Section 2: the user-id cannot contain a colon, so the split is
    // on the *first* one and the rest belong to the password.
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
    // Strict padding: `QWxhZGRpbjpvcGVuIHNlc2FtZQ` is the example without its
    // `==`, which a lenient decoder would accept.
    assert_eq!(
        decode_failure("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ"),
        Failure::Decode(DecodeError::NotBase64),
        "padding is strict, so the RFC example without its `==` is refused"
    );
}

#[test]
fn invalid_utf8_is_malformed() {
    // A lone 0x80 continuation byte is not UTF-8. RFC 7617 Section 2.1 expects
    // UTF-8 where a charset is in play, and a user-id reaches `subject.id`.
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

#[test]
fn control_characters_in_either_half_are_rejected() {
    // Cc, plus the line and paragraph separators. A user-id reaches logs and
    // `subject.id`, so a newline there is a log-injection primitive.
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
    // A user-id is rendered in audit UIs. An RLO turns `admin` into something
    // that reads as another name, so the Cf bidi controls are refused too.
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
    // R4: without NFC the same name in two encodings is two index keys, which
    // splits one user's records and slips past a duplicate check.
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
    // R4: stored hashes are over raw bytes, so normalising the password would
    // stop a legitimately decomposed password from ever matching its hash.
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
    // R26: rejected before any verification, so an oversized credential never
    // reaches a hash function.
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
    // R5: no byte, offset or buffer from the credential may reach a message,
    // because these strings land in denial reasons and log lines.
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
    // And the same for a base64 failure, whose upstream error type is happy to
    // quote the offending byte and its offset.
    let rendered = format!("{:?}", decode_failure(&format!("Basic !!{secret}!!")));
    assert!(
        !rendered.contains(secret),
        "a base64 error leaked credential material: {rendered}"
    );
}

#[test]
fn extraction_phase_outcomes_reuse_the_established_errors() {
    // R19: these are the shared gate's codes, not new ones.
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
