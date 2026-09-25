// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Where the key is read from, and the prefix gate.
//
// The prefix does two jobs. It tells a resolver whether a credential is one it
// services at all, so several key populations can share a route without every
// lookup querying every directory. And it is stripped before the lookup,
// because the stored record is keyed by the key and not by the transport
// framing around it.
//
// # Relationship to PR #96
//
// `Credential` here is a local stand-in for the shared type that PR #96 adds to
// `ppe-core` as `praxis_policy_core::identity::Credential`, approved and
// awaiting merge. The tag, the field name, and the variant spellings match it
// exactly, so adopting it is a delete plus an import with no operator-visible
// config change.
//
// Only `Header` is declared here. Cookie and query parameter locations are not
// withheld on principle: a query parameter cannot be read from a plugin today
// at all, because `IdentityPayload` carries no URI, and #96 is what adds
// `raw_query_string` along with a parser that enforces a length limit, rejects
// control characters, and rejects duplicate names. Writing a second cookie
// parser here to bridge the gap would be the worse of the two.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::plugins::identity_api_key::directory::PresentedKey;

/// Where the credential sits on the request.
///
/// `#[non_exhaustive]` for the same reason #96 gives: a location added later
/// must not break an exhaustive `match` downstream.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    /// An HTTP header, e.g. `Authorization: Bearer sk-oai-<key>`.
    Header {
        /// The header name.
        name: String,
    },
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header { name } => write!(f, "header '{name}'"),
        }
    }
}

/// Where the credential sits, and what marks it as this resolver's.
///
/// Built from two sibling config keys rather than deserialized as one block.
/// `credential:` is then exactly #96's `Credential` with nothing wrapped around
/// it, and `prefix:` sits beside it, which is also where it belongs: a prefix
/// says which key population a credential is from, not where it was found.
///
/// Flattening the two into one block was the first shape, and serde refuses it:
/// `deny_unknown_fields` and `flatten` do not compose, so that shape had to
/// give up catching a misspelled key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLocation {
    /// The wire location.
    pub credential: Credential,

    /// What the value must start with to be one this resolver services.
    ///
    /// A space splits it into an auth scheme and a leader, which are treated
    /// differently because they are different things.
    ///
    /// The **scheme** is transport framing, so it is stripped, and RFC 7235
    /// makes it case-insensitive with any run of spaces after it: `Bearer`,
    /// `bearer` and `BEARER` are one scheme, and `bearer   sk-oai-x` is well
    /// formed.
    ///
    /// The **leader** is part of the credential, so it is required and kept.
    /// `sk-oai-` in a `MaaS` key is the key's own first seven characters and the
    /// record is stored under a digest of the whole string, so stripping it
    /// would hash the wrong thing and every credential would be unknown. It
    /// matches exactly, since an API key is opaque and folding its case would
    /// map two different credentials onto one lookup.
    ///
    /// So `Bearer sk-oai-` against `Bearer sk-oai-abc` looks up `sk-oai-abc`.
    /// This is what the reference deployment does: Authorino gates on
    /// `^Bearer sk-oai-.*` and sends `authorization.replace("Bearer ", "")`.
    ///
    /// A prefix with no space is all leader. Absent means every value at that
    /// location is a candidate, which is the single-population case.
    pub prefix: Option<String>,
}

/// What reading the configured location produced.
///
/// The deny codes follow #96's names for the extraction phase, so two identity
/// plugins report the same condition the same way and an operator's runbook
/// holds for both.
#[derive(Debug, PartialEq, Eq)]
pub enum Extraction {
    /// A credential this resolver services.
    Found,

    /// Nothing was supplied at the configured location.
    ///
    /// Denies as `auth.missing_credential`.
    Missing,

    /// The location held a value and it was empty.
    ///
    /// Denies as `auth.empty_credential`.
    Empty,

    /// The location held a value that does not carry this resolver's prefix.
    ///
    /// Not a denial on its own. It is the multi-population case: another
    /// resolver on the chain services this credential, so this one declines and
    /// leaves the payload untouched.
    WrongPrefix,
}

/// `value` without `prefix`, comparing the two without ASCII case.
fn strip_prefix_ignore_case<'v>(value: &'v str, prefix: &str) -> Option<&'v str> {
    let (head, tail) = value.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

impl CredentialLocation {
    /// Pair a location with the prefix that gates it.
    pub fn new(credential: Credential, prefix: Option<String>) -> Self {
        Self { credential, prefix }
    }

    /// The name of the wire location, whatever kind it is.
    pub fn name(&self) -> &str {
        match &self.credential {
            Credential::Header { name } => name,
        }
    }

    /// Read the raw value at the configured location.
    ///
    /// The lookup lowercases the configured name, which is what the JWT
    /// resolver does: HTTP does not promise a casing, and hosts populate the
    /// map in canonical lowercase form.
    fn raw<'h>(&self, headers: &'h HashMap<String, String>) -> Option<&'h str> {
        match &self.credential {
            Credential::Header { name } => headers
                .get(name.to_ascii_lowercase().as_str())
                .map(String::as_str),
        }
    }

    /// Apply the prefix gate to a raw value, yielding the credential itself.
    ///
    /// The scheme and leader rule is on the `prefix` field.
    fn gate<'v>(&self, raw: &'v str) -> Result<&'v str, Extraction> {
        let after = match self.prefix.as_deref() {
            Some(prefix) => Self::strip_gate(raw, prefix)?,
            None => raw,
        };
        if after.is_empty() {
            return Err(Extraction::Empty);
        }
        Ok(after)
    }

    /// Strip the scheme from `raw` and require the leader.
    fn strip_gate<'v>(raw: &'v str, prefix: &str) -> Result<&'v str, Extraction> {
        let Some((scheme, leader)) = prefix.split_once(' ') else {
            // All leader. Required, and kept.
            return raw
                .starts_with(prefix)
                .then_some(raw)
                .ok_or(Extraction::WrongPrefix);
        };

        let after_scheme = strip_prefix_ignore_case(raw, scheme).ok_or(Extraction::WrongPrefix)?;
        // `1*SP` per RFC 7235: the scheme has to be followed by at least one
        // space, so a value merely starting with the scheme's letters is not a
        // match. `bearerish` is not `bearer`.
        let credential = after_scheme.trim_start_matches(' ');
        if credential.len() == after_scheme.len() {
            return Err(Extraction::WrongPrefix);
        }

        credential
            .starts_with(leader.trim_start_matches(' '))
            .then_some(credential)
            .ok_or(Extraction::WrongPrefix)
    }

    /// What reading the configured location produced.
    pub fn extract(&self, headers: &HashMap<String, String>) -> Extraction {
        let Some(raw) = self.raw(headers) else {
            return Extraction::Missing;
        };
        match self.gate(raw) {
            Ok(_) => Extraction::Found,
            Err(outcome) => outcome,
        }
    }

    /// The credential itself, or `None` when [`extract`] would not return
    /// [`Extraction::Found`].
    ///
    /// [`extract`]: CredentialLocation::extract
    pub fn presented(&self, headers: &HashMap<String, String>) -> Option<PresentedKey> {
        let raw = self.raw(headers)?;
        let key = self.gate(raw).ok()?;
        Some(PresentedKey::new(key.as_bytes()))
    }

    /// Reject a location no request can satisfy, at config load.
    ///
    /// # Errors
    ///
    /// An empty or whitespace-only name, or a prefix that is empty. A prefix
    /// present but empty is not the same as no prefix: it reads as a gate and
    /// admits everything, so it is a mistake worth naming rather than
    /// silently treating as absent.
    pub fn validate(&self) -> Result<(), String> {
        if self.name().trim().is_empty() {
            return Err(format!("{} has an empty name", self.credential));
        }
        if self.prefix.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "{}: `prefix` is present and empty, which gates nothing. Remove it to accept \
                 every value at this location",
                self.credential
            ));
        }
        // A leading space would be read as an empty auth scheme, and then no
        // value could satisfy the gate.
        if self.prefix.as_ref().is_some_and(|p| p.starts_with(' ')) {
            return Err(format!(
                "{}: `prefix` starts with a space, which no value can match",
                self.credential
            ));
        }
        Ok(())
    }
}
