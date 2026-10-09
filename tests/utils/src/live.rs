// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Live mode: the scenarios against a real Keycloak, Valkey and Vault.
//!
//! Each dependency is selected by its own environment variable. An unset
//! variable makes the test print a skip line and return, so a run with
//! `--include-ignored` and nothing provisioned stays green.
//!
//! Traffic to a live base goes over [`HyperTransport`] with private
//! destinations allowed. Everything else still reaches the scripted
//! transport, so a Vault-only or Valkey-only run keeps the scripted
//! identity provider.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use praxis_policy::HyperTransport;
use praxis_policy_core::http::{
    HttpRequest, HttpResponse, HttpTransport, HttpTransportError, form_urlencode,
};
use praxis_policy_core::http_testing::FakeTransport;
use serde_json::Value;
use serde_yaml::{Mapping, Value as Yaml};

use crate::host::Call;
use crate::idp::Persona;

/// Keycloak base URL serving the `policy-demo` realm, such as
/// `http://localhost:8081`. It must match the issuer the realm advertises.
pub const KEYCLOAK_URL: &str = "PPE_KEYCLOAK_URL";

/// Set when the realm's CIBA channel approves on its own, so the approval
/// scenario can complete without a human.
pub const CIBA_AUTO_APPROVE: &str = "PPE_CIBA_AUTO_APPROVE";

/// Valkey endpoint, as the builtin Valkey tests read it.
pub const VALKEY_URL: &str = "VALKEY_TEST_URL";

/// Vault address and `AppRole` credentials, as `vault_live.rs` reads them.
pub const VAULT_VARS: [&str; 3] = ["VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID"];

/// The `hr-copilot` client secret in the demo realm.
const HR_COPILOT_SECRET: &str = "hr-copilot-secret";

/// The scripted hosts a hermetic fixture names, longest first.
const FAKE_IDP_ORIGINS: [&str; 3] = [
    "https://sts.idp.test",
    "https://ciba.idp.test",
    "https://idp.test",
];

/// Keys whose rewritten value needs `insecure_http` beside it on plain HTTP.
const ENDPOINT_KEYS: [&str; 3] = ["url", "token_endpoint", "backchannel_endpoint"];

/// Read `names`, or print a skip line for `test` and return `None`.
fn require<const N: usize>(test: &str, names: [&str; N]) -> Option<[String; N]> {
    let values = names.map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()));
    if values.iter().all(Option::is_some) {
        return Some(values.map(Option::unwrap_or_default));
    }
    #[expect(clippy::print_stderr, reason = "the skip notice is the point")]
    {
        eprintln!("SKIPPED {test}: set {}", names.join(", "));
    }
    None
}

/// The Valkey endpoint, or `None` after a skip line.
#[must_use]
pub fn valkey(test: &str) -> Option<String> {
    require(test, [VALKEY_URL]).map(|[url]| url)
}

/// The live realm, or `None` after a skip line.
#[must_use]
pub fn keycloak(test: &str) -> Option<Realm> {
    require(test, [KEYCLOAK_URL]).map(|[base]| Realm::new(base))
}

/// The live realm when its CIBA channel auto-approves, or `None`.
#[must_use]
pub fn ciba(test: &str) -> Option<Realm> {
    require(test, [KEYCLOAK_URL, CIBA_AUTO_APPROVE]).map(|[base, _]| Realm::new(base))
}

/// The live Vault, or `None` after a skip line.
#[must_use]
pub fn vault(test: &str) -> Option<Vault> {
    require(test, VAULT_VARS).map(|[addr, role_id, secret_id]| Vault {
        addr: addr.trim_end_matches('/').to_owned(),
        role_id,
        secret_id,
    })
}

/// A real socket that may reach loopback and private addresses.
fn socket() -> HyperTransport {
    HyperTransport::new().with_allow_private_destinations()
}

// -----------------------------------------------------------------------------
// Keycloak
// -----------------------------------------------------------------------------

/// The `policy-demo` realm on a live Keycloak.
#[derive(Clone, Debug)]
pub struct Realm {
    base: String,
}

impl Realm {
    fn new(base: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    /// The Keycloak base URL.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// A fresh access token: a password grant for a user (the demo password
    /// is the username), `client_credentials` for the agent.
    ///
    /// # Panics
    ///
    /// When the realm does not issue one. The message names the status,
    /// never the response body.
    pub async fn token(&self, persona: Persona) -> String {
        let user = persona.username();
        let mut form = vec![
            ("client_id", "hr-copilot"),
            ("client_secret", HR_COPILOT_SECRET),
            ("scope", "openid"),
        ];
        if persona == Persona::HrCopilot {
            form.push(("grant_type", "client_credentials"));
        } else {
            form.extend([
                ("grant_type", "password"),
                ("username", user),
                ("password", user),
            ]);
        }
        let url = format!(
            "{}/realms/policy-demo/protocol/openid-connect/token",
            self.base
        );
        let request = HttpRequest::post(url, form_urlencode(&form))
            .header("content-type", "application/x-www-form-urlencoded")
            .expect("form content type");
        let response = socket()
            .execute(request)
            .await
            .unwrap_or_else(|e| panic!("token for {user}: {e}"));
        assert!(
            response.is_success(),
            "token for {user}: status {}",
            response.status
        );
        serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|v| v["access_token"].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("token for {user}: no access_token"))
    }

    /// `user` calling `tool` through `hr-copilot`, with tokens the realm
    /// just issued.
    pub async fn call(&self, user: Persona, tool: &str) -> Call {
        let user_token = self.token(user).await;
        let agent_token = self.token(Persona::HrCopilot).await;
        Call::with_tokens(tool, &user_token, &agent_token)
    }

    /// Point every scripted identity provider endpoint and issuer in `doc` at the realm.
    fn point(&self, doc: &mut Yaml) {
        let insecure = self.base.starts_with("http://");
        walk(doc, &mut |map| {
            let mut endpoint = false;
            for (key, value) in map.iter_mut() {
                let Yaml::String(s) = value else { continue };
                let Some(rest) = FAKE_IDP_ORIGINS.iter().find_map(|o| s.strip_prefix(o)) else {
                    continue;
                };
                *s = format!("{}{rest}", self.base);
                endpoint |= key.as_str().is_some_and(|k| ENDPOINT_KEYS.contains(&k));
            }
            if endpoint && insecure {
                map.insert("insecure_http".into(), true.into());
            }
        });
    }
}

/// Visit every mapping in `value`, depth first.
fn walk(value: &mut Yaml, visit: &mut impl FnMut(&mut Mapping)) {
    match value {
        Yaml::Mapping(map) => {
            visit(map);
            for (_, child) in map.iter_mut() {
                walk(child, visit);
            }
        },
        Yaml::Sequence(items) => items.iter_mut().for_each(|v| walk(v, visit)),
        _ => {},
    }
}

// -----------------------------------------------------------------------------
// Vault
// -----------------------------------------------------------------------------

/// A live Vault and the `AppRole` the tests log in with.
#[derive(Clone)]
pub struct Vault {
    addr: String,
    role_id: String,
    secret_id: String,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The Vault address.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The `AppRole` secret id, for planting.
    #[must_use]
    pub fn secret_id(&self) -> &str {
        &self.secret_id
    }

    /// Point the `vault` provider in `doc` at this Vault and role.
    fn point(&self, doc: &mut Yaml) {
        let provider = &mut doc["secrets"]["providers"]["vault"];
        provider["address"] = self.addr.clone().into();
        provider["insecure_http"] = self.addr.starts_with("http://").into();
        provider["auth"]["role_id"] = self.role_id.clone().into();
        provider["auth"]["secret_id"]["literal"] = self.secret_id.clone().into();
    }
}

// -----------------------------------------------------------------------------
// Documents and transport
// -----------------------------------------------------------------------------

/// What a live document is pointed at. `None` keeps the hermetic part.
#[derive(Clone, Copy, Debug, Default)]
pub struct Targets<'a> {
    /// The realm in place of the scripted identity provider.
    pub realm: Option<&'a Realm>,
    /// A Valkey endpoint for `global.session_store`.
    pub valkey: Option<&'a str>,
    /// A Vault in place of the scripted one.
    pub vault: Option<&'a Vault>,
}

impl Targets<'_> {
    /// `yaml` rewritten for these targets.
    ///
    /// # Panics
    ///
    /// When `yaml` is not a YAML document.
    #[must_use]
    pub fn rewrite(&self, yaml: &str) -> String {
        let mut doc: Yaml = serde_yaml::from_str(yaml).expect("fixture YAML");
        if let Some(realm) = self.realm {
            realm.point(&mut doc);
        }
        if let Some(url) = self.valkey {
            // A fresh prefix per document, so runs sharing a server never
            // see each other's labels.
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let mut store = Mapping::new();
            store.insert("kind".into(), "valkey".into());
            store.insert("endpoint".into(), url.into());
            store.insert(
                "key_prefix".into(),
                format!("ppe-tests:{}:{nanos}", std::process::id()).into(),
            );
            doc["global"]["session_store"] = Yaml::Mapping(store);
        }
        if let Some(vault) = self.vault {
            vault.point(&mut doc);
        }
        serde_yaml::to_string(&doc).expect("serialize fixture")
    }

    /// The live bases a host's transport sends over a real socket.
    #[must_use]
    pub fn bases(&self) -> Vec<String> {
        let realm = self.realm.map(|r| r.base.clone());
        let vault = self.vault.map(|v| v.addr.clone());
        realm.into_iter().chain(vault).collect()
    }
}

/// Sends a request under a live base over a real socket and every other
/// request to the scripted transport.
#[derive(Debug)]
pub(crate) struct Split {
    bases: Vec<String>,
    socket: HyperTransport,
    scripted: Arc<FakeTransport>,
}

impl Split {
    pub(crate) fn new(bases: Vec<String>, scripted: Arc<FakeTransport>) -> Self {
        Self {
            bases,
            socket: socket(),
            scripted,
        }
    }
}

#[async_trait]
impl HttpTransport for Split {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        if self.bases.iter().any(|b| req.url.starts_with(b.as_str())) {
            self.socket.execute(req).await
        } else {
            self.scripted.execute(req).await
        }
    }
}
