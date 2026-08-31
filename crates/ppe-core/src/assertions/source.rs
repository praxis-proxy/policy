// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The source grammar: which slots an assertion may read, what reading one
// yields, and which paths are refused.
//
// Parsing is a match over the addressable set rather than a traversal, so a
// path that names nothing is rejected at config load by construction. Two
// refusals are deliberately distinct. Raw credentials and both wire header
// maps are never usable, in either direction, with no config surface to
// widen: rendering a client-supplied header into a header the upstream
// trusts is the laundering this feature exists to prevent, and an upstream
// that controls a response header must not be able to aim it at what the
// client trusts. The request line and the response status are refused for a
// different reason: they are host-populated rather than credential-bearing,
// so they are outside the grammar rather than excluded from it, and
// admitting them later should be a grammar addition.

use std::collections::HashSet;

use serde_json::Value;

use crate::extensions::{Capability, Extensions};

/// Why an authored string is not a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRejection {
    /// The path names no addressable slot.
    Unaddressable,

    /// The path names a slot fixed in code as never usable as a source.
    NeverUsable,

    /// The path names the claim map rather than one claim.
    ClaimRoot,
}

/// A rejected source, carrying the path and why it was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceError {
    /// Which refusal this is.
    pub kind: SourceRejection,

    /// The path as authored.
    pub path: String,
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SourceRejection::Unaddressable => write!(
                f,
                "`{}` names no source; the addressable sources are {}",
                self.path,
                ADDRESSABLE_SOURCES.join(", ")
            ),
            SourceRejection::NeverUsable => write!(
                f,
                "`{}` is never usable as a source, in either direction, and there is no config \
                 surface to change that: raw credentials and both wire header maps are excluded \
                 in code, so a credential cannot be rendered onto the wire and a header one side \
                 controls cannot be re-emitted under a name the other side trusts",
                self.path
            ),
            SourceRejection::ClaimRoot => write!(
                f,
                "`{}` names the whole claim map rather than one claim; write `claim.<name>`, so a \
                 provider's claim set cannot be rendered wholesale",
                self.path
            ),
        }
    }
}

/// The source paths an entry may name, as an operator writes them. Printed by
/// a rejection and by the effective-policy artifact, so the grammar is
/// legible from the error rather than from this file.
pub const ADDRESSABLE_SOURCES: &[&str] = &[
    "subject.id",
    "subject.type",
    "subject.roles",
    "subject.teams",
    "subject.permissions",
    "claim.<name>",
    "client.client_id",
    "client.client_name",
    "client.trust_level",
    "client.roles",
    "client.permissions",
    "client.teams",
    "client.authorized_scopes",
    "client.authorized_audiences",
    "client.claim.<name>",
];

/// The slot prefixes no entry may ever name, with the reason each is refused.
/// Printed by the artifact and matched by [`SourcePath::parse`], so what the
/// engine enforces and what it reports come from one table.
pub const EXCLUDED_SOURCES: &[(&str, &str)] = &[
    (
        "raw_credentials",
        "the inbound bearer tokens captured before validation; rendering one onto a request \
         forwards a credential the upstream did not authenticate",
    ),
    (
        "http.request_headers",
        "the client's own request headers; rendering one into an asserted header is laundering \
         client input as an engine conclusion",
    ),
    (
        "http.response_headers",
        "the upstream's own response headers; rendering one back lets an upstream aim a value at \
         a header the client trusts",
    ),
];

/// One addressable slot an assertion entry reads.
///
/// A claim name is captured whole, so a provider spelling a claim with dots in
/// it needs no escaping here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePath {
    /// `subject.id`.
    SubjectId,
    /// `subject.type`.
    SubjectType,
    /// `subject.roles`.
    SubjectRoles,
    /// `subject.teams`.
    SubjectTeams,
    /// `subject.permissions`.
    SubjectPermissions,
    /// `claim.<name>`, one claim of the authenticated subject.
    Claim(String),
    /// `client.client_id`.
    ClientId,
    /// `client.client_name`.
    ClientName,
    /// `client.trust_level`.
    ClientTrustLevel,
    /// `client.roles`.
    ClientRoles,
    /// `client.permissions`.
    ClientPermissions,
    /// `client.teams`.
    ClientTeams,
    /// `client.authorized_scopes`.
    ClientScopes,
    /// `client.authorized_audiences`.
    ClientAudiences,
    /// `client.claim.<name>`, one claim of the OAuth client.
    ClientClaim(String),
}

impl SourcePath {
    /// Parse an authored source path.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError`] whose `kind` says which refusal applies: a path
    /// outside the grammar, a path fixed in code as never usable, or the claim
    /// root written without a claim name.
    pub fn parse(path: &str) -> Result<Self, SourceError> {
        let rejected = |kind| {
            Err(SourceError {
                kind,
                path: path.to_owned(),
            })
        };
        if EXCLUDED_SOURCES
            .iter()
            .any(|(prefix, _)| path == *prefix || path.starts_with(&format!("{prefix}.")))
        {
            return rejected(SourceRejection::NeverUsable);
        }
        // A claim root names the whole map, which R4's message is about. Read
        // before the table so `claim` and `claim.` share one answer.
        if path == "claim" || path == "claim." || path == "client.claim" || path == "client.claim."
        {
            return rejected(SourceRejection::ClaimRoot);
        }
        if let Some(name) = path.strip_prefix("client.claim.") {
            return Ok(Self::ClientClaim(name.to_owned()));
        }
        if let Some(name) = path.strip_prefix("claim.") {
            return Ok(Self::Claim(name.to_owned()));
        }
        match path {
            "subject.id" => Ok(Self::SubjectId),
            "subject.type" => Ok(Self::SubjectType),
            "subject.roles" => Ok(Self::SubjectRoles),
            "subject.teams" => Ok(Self::SubjectTeams),
            "subject.permissions" => Ok(Self::SubjectPermissions),
            "client.client_id" => Ok(Self::ClientId),
            "client.client_name" => Ok(Self::ClientName),
            "client.trust_level" => Ok(Self::ClientTrustLevel),
            "client.roles" => Ok(Self::ClientRoles),
            "client.permissions" => Ok(Self::ClientPermissions),
            "client.teams" => Ok(Self::ClientTeams),
            "client.authorized_scopes" => Ok(Self::ClientScopes),
            "client.authorized_audiences" => Ok(Self::ClientAudiences),
            // Everything else, the request line and the response status
            // included. They are host-populated, so they are outside the
            // grammar rather than refused as a credential.
            _ => rejected(SourceRejection::Unaddressable),
        }
    }

    /// The path as an operator writes it.
    #[must_use]
    pub fn authored(&self) -> String {
        match self {
            Self::SubjectId => "subject.id".to_owned(),
            Self::SubjectType => "subject.type".to_owned(),
            Self::SubjectRoles => "subject.roles".to_owned(),
            Self::SubjectTeams => "subject.teams".to_owned(),
            Self::SubjectPermissions => "subject.permissions".to_owned(),
            Self::Claim(name) => format!("claim.{name}"),
            Self::ClientId => "client.client_id".to_owned(),
            Self::ClientName => "client.client_name".to_owned(),
            Self::ClientTrustLevel => "client.trust_level".to_owned(),
            Self::ClientRoles => "client.roles".to_owned(),
            Self::ClientPermissions => "client.permissions".to_owned(),
            Self::ClientTeams => "client.teams".to_owned(),
            Self::ClientScopes => "client.authorized_scopes".to_owned(),
            Self::ClientAudiences => "client.authorized_audiences".to_owned(),
            Self::ClientClaim(name) => format!("client.claim.{name}"),
        }
    }

    /// The capability that gates a plugin's read of this slot.
    ///
    /// Nothing is gated here: the engine writes canonical state and is not a
    /// plugin. It is the mapping that keeps the capability model the authority
    /// on what a slot is, and the artifact prints it beside each header.
    #[must_use]
    pub fn capability(&self) -> Capability {
        match self {
            Self::SubjectId | Self::SubjectType => Capability::ReadSubject,
            Self::SubjectRoles => Capability::ReadRoles,
            Self::SubjectTeams => Capability::ReadTeams,
            Self::SubjectPermissions => Capability::ReadPermissions,
            Self::Claim(_) => Capability::ReadClaims,
            Self::ClientId
            | Self::ClientName
            | Self::ClientTrustLevel
            | Self::ClientRoles
            | Self::ClientPermissions
            | Self::ClientTeams
            | Self::ClientScopes
            | Self::ClientAudiences
            | Self::ClientClaim(_) => Capability::ReadClient,
        }
    }

    /// Whether this slot always holds a collection.
    ///
    /// A claim's shape is the provider's, unknown until a request arrives, so
    /// a claim source answers `false` and its encoding is decided at render
    /// time instead.
    #[must_use]
    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            Self::SubjectRoles
                | Self::SubjectTeams
                | Self::SubjectPermissions
                | Self::ClientRoles
                | Self::ClientPermissions
                | Self::ClientTeams
                | Self::ClientScopes
                | Self::ClientAudiences
        )
    }

    /// Read the slot, keeping its JSON shape.
    ///
    /// `None` means the slot is absent, which is what `on_missing` acts on. An
    /// empty collection is present and resolves to an empty array, so a
    /// subject with no roles is distinguishable from no subject at all. A
    /// claim holding JSON null reads as absent: a header rendered from it
    /// would carry the word `null` as if it were a value.
    ///
    /// Collections resolve sorted, so one identity yields identical header
    /// bytes across requests whatever order a set iterated in.
    #[must_use]
    pub fn resolve(&self, ext: &Extensions) -> Option<Value> {
        let security = ext.security.as_deref()?;
        match self {
            Self::SubjectId => security.subject.as_ref()?.id.clone().map(Value::String),
            Self::SubjectType => security
                .subject
                .as_ref()?
                .subject_type
                .and_then(|kind| serde_json::to_value(kind).ok()),
            Self::SubjectRoles => Some(sorted_set(&security.subject.as_ref()?.roles)),
            Self::SubjectTeams => Some(sorted_set(&security.subject.as_ref()?.teams)),
            Self::SubjectPermissions => Some(sorted_set(&security.subject.as_ref()?.permissions)),
            Self::Claim(name) => claim(&security.subject.as_ref()?.claims, name),
            Self::ClientId => Some(Value::String(security.client.as_ref()?.client_id.clone())),
            Self::ClientName => security
                .client
                .as_ref()?
                .client_name
                .clone()
                .map(Value::String),
            Self::ClientTrustLevel => {
                serde_json::to_value(&security.client.as_ref()?.trust_level).ok()
            },
            Self::ClientRoles => Some(sorted_list(&security.client.as_ref()?.roles)),
            Self::ClientPermissions => Some(sorted_list(&security.client.as_ref()?.permissions)),
            Self::ClientTeams => Some(sorted_list(&security.client.as_ref()?.teams)),
            Self::ClientScopes => Some(sorted_list(&security.client.as_ref()?.authorized_scopes)),
            Self::ClientAudiences => {
                Some(sorted_list(&security.client.as_ref()?.authorized_audiences))
            },
            Self::ClientClaim(name) => claim(&security.client.as_ref()?.claims, name),
        }
    }
}

/// One claim, or `None` when it is absent or holds JSON null.
fn claim(claims: &std::collections::HashMap<String, Value>, name: &str) -> Option<Value> {
    match claims.get(name) {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.clone()),
    }
}

/// A set as a sorted JSON array. Sorting happens here rather than at each
/// render site so a new caller cannot forget it.
fn sorted_set(values: &HashSet<String>) -> Value {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    Value::Array(
        sorted
            .into_iter()
            .map(|v| Value::String(v.to_owned()))
            .collect(),
    )
}

/// A list as a sorted JSON array. Sorted rather than kept in authored order,
/// for the same byte-stability reason a set is.
fn sorted_list(values: &[String]) -> Value {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    Value::Array(
        sorted
            .into_iter()
            .map(|v| Value::String(v.to_owned()))
            .collect(),
    )
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
    use crate::extensions::{
        ClientExtension, ClientTrustLevel, SecurityExtension, SubjectExtension, SubjectType,
    };

    fn with_security(security: SecurityExtension) -> Extensions {
        Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        }
    }

    fn subject(subject: SubjectExtension) -> Extensions {
        with_security(SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        })
    }

    fn parse(path: &str) -> SourcePath {
        SourcePath::parse(path).expect("the path is a source")
    }

    fn rejection(path: &str) -> SourceRejection {
        SourcePath::parse(path)
            .expect_err("the path is not a source")
            .kind
    }

    #[test]
    fn a_scalar_slot_resolves_to_its_value() {
        let ext = subject(SubjectExtension {
            id: Some("alice".to_owned()),
            subject_type: Some(SubjectType::User),
            ..Default::default()
        });
        assert_eq!(parse("subject.id").resolve(&ext), Some(json!("alice")));
        assert_eq!(parse("subject.type").resolve(&ext), Some(json!("user")));
    }

    #[test]
    fn a_collection_slot_resolves_sorted() {
        let ext = subject(SubjectExtension {
            roles: ["viewer", "ml-engineer", "admin"]
                .iter()
                .map(|r| (*r).to_owned())
                .collect(),
            teams: ["platform"].iter().map(|t| (*t).to_owned()).collect(),
            permissions: ["write", "read"].iter().map(|p| (*p).to_owned()).collect(),
            ..Default::default()
        });
        assert_eq!(
            parse("subject.roles").resolve(&ext),
            Some(json!(["admin", "ml-engineer", "viewer"]))
        );
        assert_eq!(
            parse("subject.teams").resolve(&ext),
            Some(json!(["platform"]))
        );
        assert_eq!(
            parse("subject.permissions").resolve(&ext),
            Some(json!(["read", "write"]))
        );
    }

    /// One identity yields identical bytes whatever order the set was filled
    /// in, which is what keeps an audit hash and a golden file stable.
    #[test]
    fn a_set_resolves_the_same_whichever_order_it_was_filled_in() {
        let forwards = subject(SubjectExtension {
            roles: ["a", "b", "c"].iter().map(|r| (*r).to_owned()).collect(),
            ..Default::default()
        });
        let backwards = subject(SubjectExtension {
            roles: ["c", "b", "a"].iter().map(|r| (*r).to_owned()).collect(),
            ..Default::default()
        });
        assert_eq!(
            parse("subject.roles").resolve(&forwards),
            parse("subject.roles").resolve(&backwards)
        );
    }

    #[test]
    fn a_nested_claim_keeps_its_shape() {
        let ext = subject(SubjectExtension {
            claims: [(
                "realm_access".to_owned(),
                json!({"roles": ["admin", "viewer"]}),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        assert_eq!(
            parse("claim.realm_access").resolve(&ext),
            Some(json!({"roles": ["admin", "viewer"]}))
        );
    }

    /// A structured claim and a string that happens to spell the same JSON
    /// resolve to different values, so the renderer can keep them apart.
    #[test]
    fn a_structured_claim_and_a_string_spelling_it_are_different_values() {
        let structured = subject(SubjectExtension {
            claims: [("x".to_owned(), json!(["a"]))].into_iter().collect(),
            ..Default::default()
        });
        let text = subject(SubjectExtension {
            claims: [("x".to_owned(), json!("[\"a\"]"))].into_iter().collect(),
            ..Default::default()
        });
        assert_ne!(
            parse("claim.x").resolve(&structured),
            parse("claim.x").resolve(&text)
        );
    }

    #[test]
    fn an_absent_slot_resolves_to_nothing_and_an_empty_collection_does_not() {
        let ext = subject(SubjectExtension::default());
        assert_eq!(parse("subject.id").resolve(&ext), None);
        assert_eq!(parse("claim.tenant").resolve(&ext), None);
        assert_eq!(parse("subject.roles").resolve(&ext), Some(json!([])));
    }

    #[test]
    fn a_claim_holding_json_null_resolves_to_nothing() {
        let ext = subject(SubjectExtension {
            claims: [("tenant".to_owned(), Value::Null)].into_iter().collect(),
            ..Default::default()
        });
        assert_eq!(parse("claim.tenant").resolve(&ext), None);
    }

    #[test]
    fn an_absent_security_slot_resolves_every_path_to_nothing() {
        let ext = Extensions::default();
        for path in [
            "subject.id",
            "subject.roles",
            "claim.tenant",
            "client.client_id",
        ] {
            assert_eq!(parse(path).resolve(&ext), None, "{path}");
        }
    }

    #[test]
    fn the_client_slots_resolve() {
        let ext = with_security(SecurityExtension {
            client: Some(ClientExtension {
                client_id: "agent-app".to_owned(),
                client_name: Some("Agent App".to_owned()),
                trust_level: ClientTrustLevel::FirstParty,
                roles: vec!["partner".to_owned(), "admin".to_owned()],
                permissions: vec!["read".to_owned()],
                teams: vec!["platform".to_owned()],
                authorized_scopes: vec!["b".to_owned(), "a".to_owned()],
                authorized_audiences: vec!["praxis".to_owned()],
                claims: [("region".to_owned(), json!("eu"))].into_iter().collect(),
            }),
            ..Default::default()
        });
        assert_eq!(
            parse("client.client_id").resolve(&ext),
            Some(json!("agent-app"))
        );
        assert_eq!(
            parse("client.client_name").resolve(&ext),
            Some(json!("Agent App"))
        );
        assert_eq!(
            parse("client.trust_level").resolve(&ext),
            Some(json!("first_party"))
        );
        assert_eq!(
            parse("client.roles").resolve(&ext),
            Some(json!(["admin", "partner"]))
        );
        assert_eq!(
            parse("client.permissions").resolve(&ext),
            Some(json!(["read"]))
        );
        assert_eq!(
            parse("client.teams").resolve(&ext),
            Some(json!(["platform"]))
        );
        assert_eq!(
            parse("client.authorized_scopes").resolve(&ext),
            Some(json!(["a", "b"]))
        );
        assert_eq!(
            parse("client.authorized_audiences").resolve(&ext),
            Some(json!(["praxis"]))
        );
        assert_eq!(
            parse("client.claim.region").resolve(&ext),
            Some(json!("eu"))
        );
    }

    /// A claim name is taken whole, so a provider spelling one with dots needs
    /// no escaping and the claim map's own rules are not re-implemented here.
    #[test]
    fn a_claim_name_is_taken_verbatim() {
        assert_eq!(parse("claim.a.b"), SourcePath::Claim("a.b".to_owned()));
        assert_eq!(parse("claim.foo."), SourcePath::Claim("foo.".to_owned()));
        assert_eq!(
            parse("client.claim.a.b"),
            SourcePath::ClientClaim("a.b".to_owned())
        );
    }

    #[test]
    fn every_addressable_path_parses() {
        for path in ADDRESSABLE_SOURCES {
            let authored = path.replace("<name>", "tenant");
            let parsed = SourcePath::parse(&authored).expect(path);
            assert_eq!(parsed.authored(), authored, "{path} must round-trip");
        }
    }

    #[test]
    fn a_path_naming_nothing_is_unaddressable_and_the_message_names_it() {
        for path in ["subject.nonexistent", "nonsense", "", "subject", "client"] {
            assert_eq!(rejection(path), SourceRejection::Unaddressable, "{path}");
            let message = SourcePath::parse(path).expect_err(path).to_string();
            assert!(
                message.contains(path),
                "the message must name the path: {message}"
            );
        }
    }

    /// The claim root gets its own message: it names a real slot, just not one
    /// claim, so telling an operator it names nothing would be wrong.
    #[test]
    fn the_claim_root_is_refused_with_its_own_message() {
        for path in ["claim", "claim.", "client.claim", "client.claim."] {
            assert_eq!(rejection(path), SourceRejection::ClaimRoot, "{path}");
        }
        let message = SourcePath::parse("claim")
            .expect_err("bare claim")
            .to_string();
        assert!(message.contains("claim.<name>"), "{message}");
    }

    /// The excluded set is enumerated rather than sampled, so adding a slot to
    /// it without considering this test fails here.
    #[test]
    fn every_excluded_slot_is_refused_as_never_usable() {
        for path in [
            "raw_credentials",
            "raw_credentials.inbound",
            "raw_credentials.delegated",
            "raw_credentials.inbound_tokens.0.token",
            "http.request_headers",
            "http.request_headers.x-user",
            "http.response_headers",
            "http.response_headers.x-backend",
        ] {
            assert_eq!(rejection(path), SourceRejection::NeverUsable, "{path}");
        }
        for (prefix, _) in EXCLUDED_SOURCES {
            assert_eq!(rejection(prefix), SourceRejection::NeverUsable, "{prefix}");
            assert_eq!(
                rejection(&format!("{prefix}.anything")),
                SourceRejection::NeverUsable,
                "{prefix}.anything"
            );
        }
    }

    /// The request line and the response status are outside the grammar, not
    /// in the excluded set. The `http.` prefix makes it easy to lump them in
    /// with the header maps by accident, so which arm each lands in is pinned.
    #[test]
    fn the_request_line_and_the_status_are_unaddressable_rather_than_excluded() {
        for path in [
            "http",
            "http.method",
            "http.path",
            "http.host",
            "http.scheme",
            "http.status",
        ] {
            assert_eq!(rejection(path), SourceRejection::Unaddressable, "{path}");
        }
    }

    #[test]
    fn the_two_refusals_read_differently() {
        let never = SourcePath::parse("raw_credentials.inbound")
            .expect_err("excluded")
            .to_string();
        let unknown = SourcePath::parse("http.path")
            .expect_err("unaddressable")
            .to_string();
        assert!(never.contains("never usable"), "{never}");
        assert!(!unknown.contains("never usable"), "{unknown}");
        assert!(unknown.contains("names no source"), "{unknown}");
    }

    #[test]
    fn each_slot_maps_to_the_capability_that_gates_it() {
        for (path, expected) in [
            ("subject.id", Capability::ReadSubject),
            ("subject.type", Capability::ReadSubject),
            ("subject.roles", Capability::ReadRoles),
            ("subject.teams", Capability::ReadTeams),
            ("subject.permissions", Capability::ReadPermissions),
            ("claim.tenant", Capability::ReadClaims),
            ("client.client_id", Capability::ReadClient),
            ("client.claim.region", Capability::ReadClient),
        ] {
            assert_eq!(parse(path).capability(), expected, "{path}");
        }
    }

    #[test]
    fn a_collection_slot_says_so_and_a_claim_does_not() {
        for path in [
            "subject.roles",
            "subject.teams",
            "subject.permissions",
            "client.roles",
            "client.permissions",
            "client.teams",
            "client.authorized_scopes",
            "client.authorized_audiences",
        ] {
            assert!(parse(path).is_collection(), "{path}");
        }
        for path in [
            "subject.id",
            "subject.type",
            "claim.teams",
            "client.client_id",
        ] {
            assert!(!parse(path).is_collection(), "{path}");
        }
    }
}
