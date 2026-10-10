// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::borrow::Cow;

use praxis_policy_core::delegation::{DelegationPayload, DelegationSubject};
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::hooks::payload::Extensions;

use super::config::VaultDelegatorConfig;

/// Resolve the identity claim value from the authenticated principal.
///
/// The claim source depends on the delegation subject:
/// - `User` → `security.subject.claims[identity_claim]`
/// - `Client` → `security.client.client_id` or `.claims[identity_claim]`
/// - `CallerWorkload` → `security.caller_workload.{spiffe_id|trust_domain|client_id}`
/// - `ThisWorkload` → `security.this_workload.{spiffe_id|trust_domain|client_id}`
pub(crate) fn resolve_identity(
    subject: &DelegationSubject,
    ext: &Extensions,
    config: &VaultDelegatorConfig,
) -> Result<String, Box<PluginViolation>> {
    let claim = &config.identity_claim;
    let security = ext
        .security
        .as_ref()
        .ok_or_else(|| identity_missing(subject, claim, "no security extension present"))?;

    match subject {
        DelegationSubject::User => {
            let sub = security
                .subject
                .as_ref()
                .ok_or_else(|| identity_missing(subject, claim, "no subject identity resolved"))?;
            if let (true, Some(id)) = (claim == "sub", sub.id.as_deref()) {
                return Ok(id.to_owned());
            }
            sub.claim_str(claim)
                .map(Cow::into_owned)
                .ok_or_else(|| identity_missing(subject, claim, "claim not present on subject"))
        },
        DelegationSubject::Client => {
            let client = security
                .client
                .as_ref()
                .ok_or_else(|| identity_missing(subject, claim, "no client identity resolved"))?;
            if claim == "client_id" {
                return Ok(client.client_id.clone());
            }
            client
                .claims
                .get(claim.as_str())
                .and_then(scalar_to_string)
                .ok_or_else(|| identity_missing(subject, claim, "claim not present on client"))
        },
        DelegationSubject::CallerWorkload => {
            let wl = security.caller_workload.as_ref().ok_or_else(|| {
                identity_missing(subject, claim, "no caller workload identity resolved")
            })?;
            workload_field(wl, claim).ok_or_else(|| {
                identity_missing(
                    subject,
                    claim,
                    "claim not available on WorkloadIdentity \
                     (supported: spiffe_id, trust_domain, client_id)",
                )
            })
        },
        DelegationSubject::ThisWorkload => {
            let wl = security.this_workload.as_ref().ok_or_else(|| {
                identity_missing(subject, claim, "no this_workload identity resolved")
            })?;
            workload_field(wl, claim).ok_or_else(|| {
                identity_missing(
                    subject,
                    claim,
                    "claim not available on WorkloadIdentity \
                     (supported: spiffe_id, trust_domain, client_id)",
                )
            })
        },
        _ => Err(Box::new(PluginViolation::new(
            "delegation.unsupported_subject",
            "unrecognised delegation subject variant",
        ))),
    }
}

/// Resolve the JWT to send to Vault for authentication.
///
/// - `User` / `Client` → `payload.bearer_token()`
/// - `CallerWorkload` → `payload.actor_token()`
/// - `ThisWorkload` → not applicable (uses `AppRole`)
pub(crate) fn resolve_auth_token<'p>(
    subject: &DelegationSubject,
    payload: &'p DelegationPayload,
) -> Result<&'p str, Box<PluginViolation>> {
    match subject {
        DelegationSubject::User | DelegationSubject::Client => {
            let t = payload.bearer_token();
            if t.is_empty() {
                return Err(Box::new(PluginViolation::new(
                    "delegation.bad_request",
                    "empty bearer_token — cannot authenticate to Vault",
                )));
            }
            Ok(t)
        },
        DelegationSubject::CallerWorkload => {
            let t = payload.bearer_token();
            if t.is_empty() {
                return Err(Box::new(PluginViolation::new(
                    "delegation.bad_request",
                    "empty bearer_token — caller workload has no JWT-SVID \
                     to authenticate to Vault",
                )));
            }
            Ok(t)
        },
        DelegationSubject::ThisWorkload => Err(Box::new(PluginViolation::new(
            "delegation.bad_request",
            "this_workload uses AppRole, not a caller token",
        ))),
        _ => Err(Box::new(PluginViolation::new(
            "delegation.unsupported_subject",
            "unrecognised delegation subject variant",
        ))),
    }
}

/// Validate that an identity value is safe for embedding in a Vault path.
///
/// Rejects empty values, null bytes, path traversal sequences (`..`),
/// and percent-encoded forms of `/` and `.` that HTTP clients may decode
/// before sending.
pub(crate) fn validate_identity_value(value: &str) -> Result<(), Box<PluginViolation>> {
    if value.is_empty() {
        return Err(Box::new(PluginViolation::new(
            "delegation.identity_invalid",
            "resolved identity value is empty",
        )));
    }
    if value.contains('\0') {
        return Err(Box::new(PluginViolation::new(
            "delegation.identity_invalid",
            "identity value contains null bytes",
        )));
    }
    if value.contains('?') || value.contains('#') {
        return Err(Box::new(PluginViolation::new(
            "delegation.identity_invalid",
            "identity value contains query-string or fragment separator",
        )));
    }
    let has_traversal = value.split('/').any(|seg| seg == ".." || seg == ".");
    let has_encoded = value.contains("%2e")
        || value.contains("%2E")
        || value.contains("%2f")
        || value.contains("%2F");
    if has_traversal || has_encoded {
        return Err(Box::new(PluginViolation::new(
            "delegation.identity_invalid",
            "identity value contains path traversal or encoded separators",
        )));
    }
    Ok(())
}

/// Whether the template contains the `{{<identity_claim>}}` placeholder.
pub(crate) fn path_has_placeholder(template: &str, identity_claim: &str) -> bool {
    let placeholder = format!("{{{{{identity_claim}}}}}");
    template.contains(&placeholder)
}

/// Replace `{{<identity_claim>}}` in the template with the resolved value.
pub(crate) fn resolve_path(template: &str, identity_claim: &str, identity_value: &str) -> String {
    let placeholder = format!("{{{{{identity_claim}}}}}");
    template.replace(&placeholder, identity_value)
}

fn workload_field(
    wl: &praxis_policy_core::extensions::security::WorkloadIdentity,
    claim: &str,
) -> Option<String> {
    match claim {
        "spiffe_id" => wl.spiffe_id.clone(),
        "trust_domain" => wl.trust_domain.clone(),
        "client_id" => wl.client_id.clone(),
        _ => None,
    }
}

fn scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn identity_missing(
    subject: &DelegationSubject,
    claim: &str,
    detail: &str,
) -> Box<PluginViolation> {
    Box::new(PluginViolation::new(
        "delegation.identity_missing",
        format!(
            "cannot resolve identity claim '{claim}' for {subject}: {detail}",
            subject = subject_label(subject),
        ),
    ))
}

fn subject_label(subject: &DelegationSubject) -> Cow<'static, str> {
    match subject {
        DelegationSubject::User => "user".into(),
        DelegationSubject::Client => "client".into(),
        DelegationSubject::CallerWorkload => "caller_workload".into(),
        DelegationSubject::ThisWorkload => "this_workload".into(),
        _ => "unknown".into(),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::security::{
        ClientExtension, SecurityExtension, SubjectExtension, WorkloadIdentity,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn ext_with_subject(claims: HashMap<String, serde_json::Value>) -> Extensions {
        Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(SubjectExtension {
                    id: Some("user-123".into()),
                    claims,
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn config_with_claim(claim: &str) -> VaultDelegatorConfig {
        serde_json::from_value(serde_json::json!({
            "vault_addr": "https://vault.test",
            "secret_path_template": "x",
            "identity_claim": claim,
            "auth": {}
        }))
        .unwrap()
    }

    #[test]
    fn user_subject_resolves_sub_from_id() {
        let ext = ext_with_subject(HashMap::new());
        let cfg = config_with_claim("sub");

        let id = resolve_identity(&DelegationSubject::User, &ext, &cfg).unwrap();
        assert_eq!(id, "user-123");
    }

    #[test]
    fn user_subject_sub_falls_back_to_claims() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(SubjectExtension {
                    id: None,
                    claims: HashMap::from([("sub".into(), serde_json::json!("from-claims"))]),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("sub");

        let id = resolve_identity(&DelegationSubject::User, &ext, &cfg).unwrap();
        assert_eq!(id, "from-claims");
    }

    #[test]
    fn user_subject_missing_claim_errors() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(SubjectExtension {
                    id: None,
                    claims: HashMap::new(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("sub");

        let err = resolve_identity(&DelegationSubject::User, &ext, &cfg).unwrap_err();
        assert_eq!(err.code, "delegation.identity_missing");
    }

    #[test]
    fn client_subject_resolves_client_id() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                client: Some(ClientExtension {
                    client_id: "my-app".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("client_id");

        let id = resolve_identity(&DelegationSubject::Client, &ext, &cfg).unwrap();
        assert_eq!(id, "my-app");
    }

    #[test]
    fn caller_workload_resolves_spiffe_id() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                caller_workload: Some(WorkloadIdentity {
                    spiffe_id: Some("spiffe://example.com/agent".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("spiffe_id");

        let id = resolve_identity(&DelegationSubject::CallerWorkload, &ext, &cfg).unwrap();
        assert_eq!(id, "spiffe://example.com/agent");
    }

    #[test]
    fn this_workload_resolves_spiffe_id() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                this_workload: Some(WorkloadIdentity {
                    spiffe_id: Some("spiffe://example.com/ppe".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("spiffe_id");

        let id = resolve_identity(&DelegationSubject::ThisWorkload, &ext, &cfg).unwrap();
        assert_eq!(id, "spiffe://example.com/ppe");
    }

    #[test]
    fn workload_unsupported_claim_errors() {
        let ext = Extensions {
            security: Some(Arc::new(SecurityExtension {
                caller_workload: Some(WorkloadIdentity::default()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let cfg = config_with_claim("email");

        let err = resolve_identity(&DelegationSubject::CallerWorkload, &ext, &cfg).unwrap_err();
        assert_eq!(err.code, "delegation.identity_missing");
        assert!(err.reason.contains("spiffe_id"));
    }

    #[test]
    fn path_template_substitution() {
        assert_eq!(
            resolve_path("agents/{{sub}}/github", "sub", "user-42"),
            "agents/user-42/github"
        );
    }

    #[test]
    fn path_template_no_match_unchanged() {
        assert_eq!(
            resolve_path("shared/api-key", "sub", "user-42"),
            "shared/api-key"
        );
    }

    #[test]
    fn path_has_placeholder_true() {
        assert!(path_has_placeholder("agents/{{sub}}/github", "sub"));
    }

    #[test]
    fn path_has_placeholder_false_fixed_path() {
        assert!(!path_has_placeholder("shared/api-key", "sub"));
    }

    #[test]
    fn path_has_placeholder_wrong_claim() {
        assert!(!path_has_placeholder("agents/{{email}}/github", "sub"));
    }

    #[test]
    fn bearer_token_for_user() {
        let payload = DelegationPayload::new("my-jwt", "target");
        let t = resolve_auth_token(&DelegationSubject::User, &payload).unwrap();
        assert_eq!(t, "my-jwt");
    }

    #[test]
    fn empty_bearer_token_errors() {
        let payload = DelegationPayload::new("", "target");
        let err = resolve_auth_token(&DelegationSubject::User, &payload).unwrap_err();
        assert_eq!(err.code, "delegation.bad_request");
    }

    #[test]
    fn bearer_token_for_caller_workload() {
        let payload = DelegationPayload::new("svid-jwt", "target")
            .with_subject(DelegationSubject::CallerWorkload);
        let t = resolve_auth_token(&DelegationSubject::CallerWorkload, &payload).unwrap();
        assert_eq!(t, "svid-jwt");
    }

    #[test]
    fn this_workload_auth_token_errors() {
        let payload = DelegationPayload::new("", "target");
        let err = resolve_auth_token(&DelegationSubject::ThisWorkload, &payload).unwrap_err();
        assert_eq!(err.code, "delegation.bad_request");
    }

    #[test]
    fn rejects_empty_identity() {
        let err = validate_identity_value("").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_null_bytes() {
        let err = validate_identity_value("user\0evil").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_path_traversal() {
        let err = validate_identity_value("../../admin").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_encoded_traversal() {
        let err = validate_identity_value("foo%2e%2e").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_query_string_separator() {
        let err = validate_identity_value("user?admin=true").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_fragment_separator() {
        let err = validate_identity_value("user#fragment").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn rejects_encoded_slash() {
        let err = validate_identity_value("foo%2Fbar").unwrap_err();
        assert_eq!(err.code, "delegation.identity_invalid");
    }

    #[test]
    fn allows_normal_identity() {
        validate_identity_value("user-123").unwrap();
    }

    #[test]
    fn allows_spiffe_id() {
        validate_identity_value("spiffe://example.com/agent").unwrap();
    }
}
