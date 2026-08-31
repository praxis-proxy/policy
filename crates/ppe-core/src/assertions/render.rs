// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Turning an accumulated contract and request state into header values.
//
// Rendering reads the merged contract, never a single level's block, so it
// never sees the layering. What it does see is attacker-influenced data: a
// claim's value is the provider's, so a rendered value carrying CR or LF is
// dropped rather than emitted, since a header that splits is a second header
// nobody configured.

use serde_json::Value;
use tracing::warn;

use super::config::{Encoding, OnMissing};
use super::resolved::{ResolvedContract, ResolvedHeader, ResolvedSource};
use crate::extensions::Extensions;

/// An entry whose source resolved to nothing, where the entry said to deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSource {
    /// The header the entry would have asserted.
    pub header: String,

    /// The source that resolved to nothing.
    pub source: String,
}

/// Render every entry of a contract against request state.
///
/// Returns the name and value pairs to inject, in contract order. An entry
/// whose source resolves to nothing renders nothing, which is the default; one
/// declaring `on_missing: deny` stops the render instead.
///
/// # Errors
///
/// Returns [`MissingSource`] naming the header and the path when an entry
/// declaring `on_missing: deny` resolved nothing.
pub fn render(
    contract: &ResolvedContract,
    ext: &Extensions,
) -> Result<Vec<(String, String)>, MissingSource> {
    let mut rendered = Vec::with_capacity(contract.headers.len());
    for header in &contract.headers {
        match render_one(header, ext) {
            Rendered::Value(value) => rendered.push((header.name.clone(), value)),
            Rendered::Skip => {},
            Rendered::Missing(source) => {
                if header.on_missing == OnMissing::Deny {
                    return Err(MissingSource {
                        header: header.name.clone(),
                        source,
                    });
                }
            },
        }
    }
    Ok(rendered)
}

/// What rendering one entry produced.
enum Rendered {
    /// A value to inject.
    Value(String),

    /// Nothing to inject, and `on_missing` does not apply. A value rejected
    /// for carrying CR or LF lands here rather than in `Missing`: the source
    /// resolved, so calling it absent would be wrong.
    Skip,

    /// The source resolved to nothing, naming the path that did.
    Missing(String),
}

/// Render one entry.
fn render_one(header: &ResolvedHeader, ext: &Extensions) -> Rendered {
    match &header.source {
        ResolvedSource::From(path) => match path.resolve(ext) {
            Some(value) => match encode(&value, header.encode) {
                Some(text) => emit(&header.name, text),
                None => Rendered::Skip,
            },
            None => Rendered::Missing(path.authored()),
        },
        ResolvedSource::Members(members) => {
            // Sorted here rather than relied on from the input. `serde_json::Map`
            // is a `BTreeMap` only while nothing in the dependency graph enables
            // `preserve_order`, and a transitive dependency that does would
            // otherwise make one identity render different header bytes. Sorting
            // makes the order the same either way.
            let mut resolved: Vec<(&String, Value)> = members
                .iter()
                .filter_map(|(member, path)| path.resolve(ext).map(|value| (member, value)))
                .collect();
            resolved.sort_by_key(|(member, _)| *member);
            let mut object = serde_json::Map::new();
            for (member, value) in resolved {
                object.insert(member.clone(), value);
            }
            // Every member absent means the entry itself is absent, so
            // `on_missing` applies to it rather than to one member.
            if object.is_empty() {
                let paths: Vec<String> = members.iter().map(|(_, p)| p.authored()).collect();
                return Rendered::Missing(paths.join(", "));
            }
            match serde_json::to_string(&Value::Object(object)) {
                Ok(text) => emit(&header.name, text),
                Err(cause) => {
                    warn!(
                        header = %header.name,
                        error = %cause,
                        "an asserted header's members did not serialize, so no header is emitted",
                    );
                    Rendered::Skip
                },
            }
        },
        // Cannot happen: validation parses every source at config load.
        ResolvedSource::Unresolvable => {
            warn!(
                header = %header.name,
                "an asserted header's source could not be read, so the header is removed and not \
                 re-asserted",
            );
            Rendered::Skip
        },
    }
}

/// Accept a rendered value, or drop it when it cannot go on the wire.
fn emit(name: &str, value: String) -> Rendered {
    if let Some(defect) = wire_defect(&value) {
        warn!(
            alarm = "assertion_value_rejected",
            header = %name,
            defect,
            "an asserted header's value {defect}, so no header is emitted for it. The value came \
             from provider-minted data, and emitting it would let that data add a header nobody \
             configured",
        );
        return Rendered::Skip;
    }
    Rendered::Value(value)
}

/// Why a rendered value cannot go on the wire, or `None` when it can.
fn wire_defect(value: &str) -> Option<&'static str> {
    if value.contains('\r') || value.contains('\n') {
        return Some("carries a carriage return or line feed");
    }
    if value.contains('\0') {
        return Some("carries a NUL byte");
    }
    None
}

/// Render one resolved value as one header value.
///
/// With no declared encoding a scalar renders bare and a structured value
/// renders as compact JSON, which is what keeps a claim's shape. `json`
/// renders every value as JSON, so a string renders quoted and stays
/// distinguishable from a structured value spelling the same text.
fn encode(value: &Value, encoding: Option<Encoding>) -> Option<String> {
    match encoding {
        None => Some(scalar_text(value)),
        Some(Encoding::Json) => serde_json::to_string(value).ok(),
        Some(Encoding::Csv) => match value {
            Value::Array(items) => Some(
                items
                    .iter()
                    .map(scalar_text)
                    .collect::<Vec<String>>()
                    .join(","),
            ),
            other => Some(scalar_text(other)),
        },
    }
}

/// One value as text: a string bare, a number or boolean as written, and
/// anything structured as compact JSON.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => String::new(),
        structured => serde_json::to_string(structured).unwrap_or_default(),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::assertions::AssertionLevel;
    use crate::assertions::source::SourcePath;
    use crate::extensions::{SecurityExtension, SubjectExtension};

    fn header(name: &str, source: ResolvedSource) -> ResolvedHeader {
        ResolvedHeader {
            name: name.to_owned(),
            lowercase: name.to_lowercase(),
            source,
            on_missing: OnMissing::Omit,
            encode: None,
            declared_in: "global".to_owned(),
            level: AssertionLevel::Global,
            overrode: None,
        }
    }

    fn from(name: &str, path: &str) -> ResolvedHeader {
        header(
            name,
            ResolvedSource::From(SourcePath::parse(path).expect("a source")),
        )
    }

    fn members(name: &str, pairs: &[(&str, &str)]) -> ResolvedHeader {
        header(
            name,
            ResolvedSource::Members(
                pairs
                    .iter()
                    .map(|(member, path)| {
                        (
                            (*member).to_owned(),
                            SourcePath::parse(path).expect("a source"),
                        )
                    })
                    .collect(),
            ),
        )
    }

    fn contract(headers: Vec<ResolvedHeader>) -> ResolvedContract {
        ResolvedContract {
            headers,
            strip: Vec::new(),
        }
    }

    fn subject(subject: SubjectExtension) -> Extensions {
        Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(subject),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn keycloak() -> Extensions {
        subject(SubjectExtension {
            id: Some("alice".to_owned()),
            roles: ["ml-engineer", "viewer"]
                .iter()
                .map(|r| (*r).to_owned())
                .collect(),
            claims: [
                ("tenant".to_owned(), json!("acme")),
                ("teams".to_owned(), json!(["platform"])),
                ("projects".to_owned(), json!(["team-stage", "team-prod"])),
                ("namespace".to_owned(), json!(["team-ml"])),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn a_scalar_source_renders_bare() {
        let rendered = render(
            &contract(vec![from("x-auth-user-id", "subject.id")]),
            &keycloak(),
        )
        .expect("nothing denies");
        assert_eq!(
            rendered,
            vec![("x-auth-user-id".to_owned(), "alice".to_owned())]
        );
    }

    /// The keys are sorted and the array values stay arrays, so an operator's
    /// object renders one way whatever order the members were written in, and
    /// whatever `serde_json::Map` a dependency's feature flags make it.
    #[test]
    fn a_members_entry_renders_one_json_object_with_sorted_keys() {
        let entry = members(
            "x-auth-attributes",
            &[
                ("roles", "subject.roles"),
                ("teams", "claim.teams"),
                ("projects", "claim.projects"),
                ("namespaces", "claim.namespace"),
            ],
        );
        let rendered = render(&contract(vec![entry]), &keycloak()).expect("nothing denies");
        assert_eq!(
            rendered[0].1,
            r#"{"namespaces":["team-ml"],"projects":["team-stage","team-prod"],"roles":["ml-engineer","viewer"],"teams":["platform"]}"#
        );
    }

    /// Two renders of one identity produce the same bytes, object key order
    /// included, so an audit hash and a golden file stay stable.
    #[test]
    fn two_renders_of_one_identity_are_byte_identical() {
        let build = || {
            contract(vec![
                from("x-auth-user-id", "subject.id"),
                members("x-auth-attributes", &[("roles", "subject.roles")]),
            ])
        };
        let ext = keycloak();
        assert_eq!(
            render(&build(), &ext).expect("nothing denies"),
            render(&build(), &ext).expect("nothing denies")
        );
    }

    /// `encode: json` is what keeps a structured claim apart from a string that
    /// spells the same JSON: the string renders quoted, the array does not.
    #[test]
    fn json_encoding_keeps_a_structured_value_apart_from_text_spelling_it() {
        let structured = subject(SubjectExtension {
            claims: [("x".to_owned(), json!(["a"]))].into_iter().collect(),
            ..Default::default()
        });
        let text = subject(SubjectExtension {
            claims: [("x".to_owned(), json!("[\"a\"]"))].into_iter().collect(),
            ..Default::default()
        });
        let mut entry = from("x-shape", "claim.x");
        entry.encode = Some(Encoding::Json);
        let one = render(&contract(vec![entry.clone()]), &structured).expect("nothing denies");
        let two = render(&contract(vec![entry]), &text).expect("nothing denies");
        assert_eq!(one[0].1, r#"["a"]"#);
        assert_eq!(two[0].1, r#""[\"a\"]""#);
        assert_ne!(one, two);
    }

    #[test]
    fn a_structured_claim_with_no_declared_encoding_renders_as_json() {
        let ext = subject(SubjectExtension {
            claims: [("realm_access".to_owned(), json!({"roles": ["admin"]}))]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let rendered = render(&contract(vec![from("x-realm", "claim.realm_access")]), &ext)
            .expect("nothing denies");
        assert_eq!(rendered[0].1, r#"{"roles":["admin"]}"#);
    }

    #[test]
    fn csv_encoding_joins_an_array_and_leaves_a_scalar_alone() {
        let mut collection = from("x-auth-scope", "claim.projects");
        collection.encode = Some(Encoding::Csv);
        let mut scalar = from("x-tenant", "claim.tenant");
        scalar.encode = Some(Encoding::Csv);
        let rendered =
            render(&contract(vec![collection, scalar]), &keycloak()).expect("nothing denies");
        assert_eq!(rendered[0].1, "team-stage,team-prod");
        assert_eq!(rendered[1].1, "acme");
    }

    #[test]
    fn an_empty_collection_renders_empty_rather_than_missing() {
        let ext = subject(SubjectExtension {
            claims: [("projects".to_owned(), json!([]))].into_iter().collect(),
            ..Default::default()
        });
        let mut as_json = from("x-json", "claim.projects");
        as_json.encode = Some(Encoding::Json);
        let mut as_csv = from("x-csv", "claim.projects");
        as_csv.encode = Some(Encoding::Csv);
        let rendered = render(&contract(vec![as_json, as_csv]), &ext).expect("nothing denies");
        assert_eq!(rendered[0].1, "[]");
        assert_eq!(rendered[1].1, "");
    }

    #[test]
    fn a_missing_source_omits_its_header_by_default() {
        let ext = subject(SubjectExtension {
            id: Some("alice".to_owned()),
            ..Default::default()
        });
        let rendered = render(
            &contract(vec![
                from("x-auth-user-id", "subject.id"),
                from("x-auth-tenant-id", "claim.tenant"),
            ]),
            &ext,
        )
        .expect("omit is the default");
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].0, "x-auth-user-id");
    }

    #[test]
    fn a_members_entry_drops_the_members_that_resolved_to_nothing() {
        let ext = subject(SubjectExtension {
            claims: [("tenant".to_owned(), json!("acme"))].into_iter().collect(),
            ..Default::default()
        });
        let rendered = render(
            &contract(vec![members(
                "x-auth-attributes",
                &[("tenant", "claim.tenant"), ("absent", "claim.nothing")],
            )]),
            &ext,
        )
        .expect("nothing denies");
        assert_eq!(rendered[0].1, r#"{"tenant":"acme"}"#);
    }

    /// Every member absent makes the entry itself absent, so `on_missing`
    /// applies to the entry rather than to one member of it.
    #[test]
    fn a_members_entry_whose_members_all_resolve_to_nothing_is_missing() {
        let ext = subject(SubjectExtension::default());
        let mut entry = members("x-auth-attributes", &[("tenant", "claim.tenant")]);
        entry.on_missing = OnMissing::Deny;
        let denied = render(&contract(vec![entry]), &ext).expect_err("the entry is missing");
        assert_eq!(denied.header, "x-auth-attributes");
        assert_eq!(denied.source, "claim.tenant");
    }

    #[test]
    fn on_missing_deny_names_the_header_and_the_path() {
        let ext = subject(SubjectExtension {
            id: Some("alice".to_owned()),
            ..Default::default()
        });
        let mut entry = from("x-auth-tenant-id", "claim.tenant");
        entry.on_missing = OnMissing::Deny;
        let denied = render(&contract(vec![entry]), &ext).expect_err("deny fires");
        assert_eq!(denied.header, "x-auth-tenant-id");
        assert_eq!(denied.source, "claim.tenant");
    }

    /// A claim is provider-minted and so attacker-influenced. A value that
    /// splits would add a header nobody configured, so the entry emits nothing.
    #[test]
    fn a_value_carrying_crlf_emits_no_header_at_all() {
        for hostile in ["acme\r\nx-admin: true", "acme\nx-admin: true", "acme\rx"] {
            let ext = subject(SubjectExtension {
                id: Some(hostile.to_owned()),
                ..Default::default()
            });
            let rendered = render(&contract(vec![from("x-auth-user-id", "subject.id")]), &ext)
                .expect("a rejected value is not a denial");
            assert!(rendered.is_empty(), "{hostile:?} produced {rendered:?}");
        }
    }

    #[test]
    fn a_value_carrying_a_nul_emits_no_header() {
        let ext = subject(SubjectExtension {
            id: Some("alice\0root".to_owned()),
            ..Default::default()
        });
        let rendered = render(&contract(vec![from("x-auth-user-id", "subject.id")]), &ext)
            .expect("a rejected value is not a denial");
        assert!(rendered.is_empty());
    }

    /// A rejected value is not an absent one, so an entry declaring `deny` on
    /// absence does not deny over a value the renderer refused.
    #[test]
    fn a_rejected_value_does_not_trigger_on_missing_deny() {
        let ext = subject(SubjectExtension {
            id: Some("alice\r\n".to_owned()),
            ..Default::default()
        });
        let mut entry = from("x-auth-user-id", "subject.id");
        entry.on_missing = OnMissing::Deny;
        let rendered = render(&contract(vec![entry]), &ext)
            .expect("the source resolved, so nothing is absent");
        assert!(rendered.is_empty());
    }

    /// A source config load accepted and resolution could not parse renders
    /// nothing and denies nothing, so the entry's target is still removed.
    #[test]
    fn an_unresolvable_source_renders_nothing() {
        let mut entry = header("x-auth-user-id", ResolvedSource::Unresolvable);
        entry.on_missing = OnMissing::Deny;
        let rendered = render(&contract(vec![entry]), &keycloak()).expect("no denial");
        assert!(rendered.is_empty());
    }

    #[test]
    fn a_contract_with_no_headers_renders_nothing() {
        let rendered = render(&contract(Vec::new()), &keycloak()).expect("nothing denies");
        assert!(rendered.is_empty());
    }
}
