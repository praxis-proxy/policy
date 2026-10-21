// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Immutable externally acquired facts and their trusted provenance.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Cache disposition for one metadata acquisition.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataCacheDisposition {
    /// Caching did not apply to this acquisition.
    Disabled,
    /// The acquisition populated or joined a cache miss.
    Miss,
    /// The acquisition used a retained value.
    Hit,
    /// The acquisition revalidated a retained value.
    Revalidated,
    /// The acquisition used an explicitly permitted stale value.
    Stale,
}

impl MetadataCacheDisposition {
    /// Return the stable policy spelling of the disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Miss => "miss",
            Self::Hit => "hit",
            Self::Revalidated => "revalidated",
            Self::Stale => "stale",
        }
    }
}

/// Whether an acquisition produced a value or a normalized error.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataOutcome {
    /// A complete structured value is available.
    Success,
    /// The source returned a normalized error without a partial value.
    Error,
}

impl MetadataOutcome {
    /// Return the stable policy spelling of the outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

/// Trusted identity of the plugin instance that acquired a record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSource {
    /// Configured plugin instance name.
    pub instance: String,
    /// Registered plugin kind.
    pub kind: String,
}

/// One immutable result returned by a policy information source.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquiredFacts {
    cache: MetadataCacheDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetched_at: Option<DateTime<Utc>>,
    outcome: MetadataOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<MetadataSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
}

impl AcquiredFacts {
    /// Create a successful record before framework provenance is stamped.
    #[must_use]
    pub fn success(
        value: Value,
        fetched_at: DateTime<Utc>,
        cache: MetadataCacheDisposition,
    ) -> Self {
        Self {
            cache,
            error_code: None,
            fetched_at: Some(fetched_at),
            outcome: MetadataOutcome::Success,
            source: None,
            stale: false,
            status: None,
            value: Some(value),
        }
    }

    /// Create an error record containing no partial acquired value.
    #[must_use]
    pub fn error(error_code: impl Into<String>, cache: MetadataCacheDisposition) -> Self {
        Self {
            cache,
            error_code: Some(error_code.into()),
            fetched_at: None,
            outcome: MetadataOutcome::Error,
            source: None,
            stale: false,
            status: None,
            value: None,
        }
    }

    /// Attach an upstream status that policy may inspect.
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Mark a successful record as an explicitly permitted stale value.
    #[must_use]
    pub const fn with_stale(mut self) -> Self {
        self.cache = MetadataCacheDisposition::Stale;
        self.stale = true;
        self
    }

    /// Cache disposition for this evaluation.
    #[must_use]
    pub const fn cache(&self) -> MetadataCacheDisposition {
        self.cache
    }

    /// Normalized source error code, if the acquisition failed.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }

    /// Time at which the successful value was fetched.
    #[must_use]
    pub const fn fetched_at(&self) -> Option<&DateTime<Utc>> {
        self.fetched_at.as_ref()
    }

    /// Acquisition outcome.
    #[must_use]
    pub const fn outcome(&self) -> MetadataOutcome {
        self.outcome
    }

    /// Framework-stamped source identity.
    #[must_use]
    pub const fn source(&self) -> Option<&MetadataSource> {
        self.source.as_ref()
    }

    /// Whether this evaluation served a stale value.
    #[must_use]
    pub const fn stale(&self) -> bool {
        self.stale
    }

    /// Exposed upstream status, when configured.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// Original structured value retained by a successful record.
    #[must_use]
    pub const fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }
}

/// Acquired records installed during one policy invocation.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MetadataExtension(BTreeMap<String, AcquiredFacts>);

impl<'de> Deserialize<'de> for MetadataExtension {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let records = BTreeMap::<String, AcquiredFacts>::deserialize(deserializer)?;
        for (instance, facts) in &records {
            validate_instance_name(instance).map_err(D::Error::custom)?;
            validate_record(facts).map_err(D::Error::custom)?;
            let source = facts
                .source()
                .ok_or_else(|| D::Error::custom("installed metadata has no source"))?;
            if source.instance != *instance || source.kind.is_empty() {
                return Err(D::Error::custom(
                    "installed metadata source does not match its key",
                ));
            }
        }
        Ok(Self(records))
    }
}

impl MetadataExtension {
    /// Return the installed record for an instance.
    #[must_use]
    pub fn get(&self, instance: &str) -> Option<&AcquiredFacts> {
        self.0.get(instance)
    }

    /// Iterate over installed records in deterministic instance-name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &AcquiredFacts)> {
        self.0.iter().map(|(name, facts)| (name.as_str(), facts))
    }

    pub(crate) fn install(
        &mut self,
        instance: &str,
        kind: &str,
        mut facts: AcquiredFacts,
    ) -> Result<(), MetadataInstallError> {
        validate_instance_name(instance)?;
        if kind.is_empty() {
            return Err(MetadataInstallError::InvalidSourceKind);
        }
        validate_record(&facts)?;
        if self.0.contains_key(instance) {
            return Err(MetadataInstallError::DuplicateInstance(instance.to_owned()));
        }

        facts.source = Some(MetadataSource {
            instance: instance.to_owned(),
            kind: kind.to_owned(),
        });
        self.0.insert(instance.to_owned(), facts);
        Ok(())
    }
}

/// Failure to install an acquired-facts record.
#[non_exhaustive]
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MetadataInstallError {
    /// An instance already owns its one record for this invocation.
    #[error("metadata instance `{0}` already installed a record")]
    DuplicateInstance(String),
    /// A JSON object key would make the dotted projection ambiguous.
    #[error("metadata response key `{0}` is reserved or ambiguous")]
    InvalidResponseKey(String),
    /// The plugin instance name cannot safely form a namespace segment.
    #[error("invalid metadata instance name `{0}`")]
    InvalidInstanceName(String),
    /// The trusted plugin registration did not supply a source kind.
    #[error("metadata source kind must not be empty")]
    InvalidSourceKind,
    /// Outcome-specific fields do not form a complete atomic record.
    #[error("invalid metadata record shape")]
    InvalidRecordShape,
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Serde predicate for omitting a false stale marker.
fn is_false(value: &bool) -> bool {
    !value
}

/// Enforce a single unambiguous dotted-namespace segment.
fn validate_instance_name(instance: &str) -> Result<(), MetadataInstallError> {
    let mut chars = instance.chars();
    let Some(first) = chars.next() else {
        return Err(MetadataInstallError::InvalidInstanceName(
            instance.to_owned(),
        ));
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(MetadataInstallError::InvalidInstanceName(
            instance.to_owned(),
        ));
    }
    Ok(())
}

/// Enforce the mutually exclusive success and error record shapes.
fn validate_record(facts: &AcquiredFacts) -> Result<(), MetadataInstallError> {
    match (facts.outcome, facts.value.as_ref()) {
        (MetadataOutcome::Success, Some(value))
            if facts.fetched_at.is_some()
                && facts.error_code.is_none()
                && facts.stale == (facts.cache == MetadataCacheDisposition::Stale) =>
        {
            validate_keys(value, true)
        },
        (MetadataOutcome::Error, _)
            if facts.value.is_none()
                && facts.fetched_at.is_none()
                && facts
                    .error_code
                    .as_ref()
                    .is_some_and(|code| !code.is_empty())
                && !facts.stale
                && facts.cache != MetadataCacheDisposition::Stale =>
        {
            Ok(())
        },
        _ => Err(MetadataInstallError::InvalidRecordShape),
    }
}

/// Reject response keys that collide in the derived dotted projection.
fn validate_keys(value: &Value, root: bool) -> Result<(), MetadataInstallError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.is_empty()
                    || key.contains('.')
                    || key.starts_with('$')
                    || (root && key == "value")
                {
                    return Err(MetadataInstallError::InvalidResponseKey(key.clone()));
                }
                validate_keys(child, false)?;
            }
            Ok(())
        },
        Value::Array(items) => {
            for item in items {
                validate_keys(item, false)?;
            }
            Ok(())
        },
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::extensions::{Capability, Extensions, MutabilityTier, SlotName, filter_extensions};
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn framework_install_stamps_source_and_keeps_instances_separate() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!({"active": true})))
            .expect("the first instance installs");
        let allocation = Arc::as_ptr(
            extensions
                .metadata
                .as_ref()
                .expect("metadata allocation exists"),
        );
        extensions
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("a second instance installs");

        let metadata = extensions.metadata.as_deref().expect("metadata is present");
        assert_eq!(
            Arc::as_ptr(
                extensions
                    .metadata
                    .as_ref()
                    .expect("metadata allocation remains")
            ),
            allocation,
            "a uniquely owned metadata map should grow in place"
        );
        let account = metadata.get("account").expect("account record exists");
        assert_eq!(
            account.source().expect("source is stamped").kind,
            "metadata/http"
        );
        assert_eq!(
            account.source().expect("source is stamped").instance,
            "account"
        );
        assert_eq!(metadata.iter().count(), 2);
    }

    #[test]
    fn duplicate_install_is_atomic() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!({"active": true})))
            .expect("the first record installs");
        let before = Arc::clone(extensions.metadata.as_ref().expect("metadata is present"));

        let result = extensions.install_metadata(
            "account",
            "metadata/other",
            success(json!({"active": false})),
        );

        assert_eq!(
            result,
            Err(MetadataInstallError::DuplicateInstance(
                "account".to_owned()
            ))
        );
        assert!(Arc::ptr_eq(
            extensions
                .metadata
                .as_ref()
                .expect("metadata allocation remains"),
            &before
        ));
        assert_eq!(extensions.metadata.as_deref(), Some(before.as_ref()));
    }

    #[test]
    fn shared_metadata_clones_only_after_a_successful_install() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("first record installs");
        let shared = Arc::clone(extensions.metadata.as_ref().expect("metadata exists"));

        extensions
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("second record installs into a detached map");

        let current = extensions.metadata.as_ref().expect("metadata remains");
        assert!(!Arc::ptr_eq(current, &shared));
        assert!(shared.get("account").is_some());
        assert!(shared.get("region").is_none());
        assert!(current.get("region").is_some());
    }

    #[test]
    fn instance_names_follow_the_namespace_contract() {
        for valid in ["account", "_account", "account_status", "a1"] {
            let mut extensions = Extensions::default();
            extensions
                .install_metadata(valid, "metadata/http", success(json!(true)))
                .expect("valid instance should install");
        }
        for invalid in [
            "",
            "1account",
            "account-status",
            "account.status",
            "account/status",
            "é",
        ] {
            let mut extensions = Extensions::default();
            let result =
                extensions.install_metadata(invalid, "metadata/http", success(json!(true)));
            assert_eq!(
                result,
                Err(MetadataInstallError::InvalidInstanceName(
                    invalid.to_owned()
                ))
            );
            assert!(
                extensions.metadata.is_none(),
                "invalid install must be atomic"
            );
        }
    }

    #[test]
    fn ambiguous_response_keys_are_rejected_at_every_depth() {
        for (value, key) in [
            (json!({"a.b": true}), "a.b"),
            (json!({"$status": 200}), "$status"),
            (json!({"value": true}), "value"),
            (json!({"nested": {"a.b": true}}), "a.b"),
            (json!([{"$source": "forged"}]), "$source"),
        ] {
            let mut extensions = Extensions::default();
            let result = extensions.install_metadata("account", "metadata/http", success(value));
            assert_eq!(
                result,
                Err(MetadataInstallError::InvalidResponseKey(key.to_owned()))
            );
            assert!(
                extensions.metadata.is_none(),
                "invalid install must be atomic"
            );
        }
    }

    #[test]
    fn nested_value_key_is_unambiguous() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata(
                "account",
                "metadata/http",
                success(json!({"nested": {"value": true}})),
            )
            .expect("nested `value` should install");
    }

    #[test]
    fn malformed_error_record_is_rejected_without_partial_value() {
        let mut facts = AcquiredFacts::error(
            "metadata.upstream_error",
            MetadataCacheDisposition::Disabled,
        );
        facts.value = Some(json!({"partial": true}));
        let mut extensions = Extensions::default();

        let result = extensions.install_metadata("account", "metadata/http", facts);

        assert_eq!(result, Err(MetadataInstallError::InvalidRecordShape));
        assert!(extensions.metadata.is_none());
    }

    #[test]
    fn installed_extension_round_trips_without_losing_provenance() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!({"active": true})))
            .expect("metadata installs");
        let metadata = extensions.metadata.as_deref().expect("metadata exists");

        let encoded = serde_json::to_value(metadata).expect("metadata serializes");
        let decoded: MetadataExtension =
            serde_json::from_value(encoded).expect("installed metadata deserializes");

        assert_eq!(&decoded, metadata);
    }

    #[test]
    fn empty_source_kind_is_rejected_atomically() {
        let mut extensions = Extensions::default();

        let result = extensions.install_metadata("account", "", success(json!(true)));

        assert_eq!(result, Err(MetadataInstallError::InvalidSourceKind));
        assert!(extensions.metadata.is_none());
    }

    #[test]
    fn framework_overwrites_plugin_supplied_source_identity() {
        let facts: AcquiredFacts = serde_json::from_value(json!({
            "cache": "disabled",
            "fetched_at": "2026-10-19T12:00:00Z",
            "outcome": "success",
            "source": {
                "instance": "forged",
                "kind": "metadata/forged"
            },
            "value": true
        }))
        .expect("source result deserializes before trusted stamping");
        let mut extensions = Extensions::default();

        extensions
            .install_metadata("account", "metadata/http", facts)
            .expect("framework stamps the resolved registration");

        let source = extensions
            .metadata
            .as_deref()
            .and_then(|metadata| metadata.get("account"))
            .and_then(AcquiredFacts::source)
            .expect("installed metadata has trusted provenance");
        assert_eq!(source.instance, "account");
        assert_eq!(source.kind, "metadata/http");
    }

    #[test]
    fn serialized_extension_rejects_unstamped_or_mismatched_sources() {
        let unstamped = serde_json::to_value(MetadataExtension(BTreeMap::from([(
            "account".to_owned(),
            success(json!(true)),
        )])))
        .expect("unstamped metadata serializes");
        serde_json::from_value::<MetadataExtension>(unstamped)
            .expect_err("unstamped metadata must not deserialize");

        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("metadata installs");
        let mut encoded =
            serde_json::to_value(extensions.metadata.as_deref().expect("metadata exists"))
                .expect("metadata serializes");
        encoded["account"]["source"]["instance"] = json!("other");
        serde_json::from_value::<MetadataExtension>(encoded)
            .expect_err("mismatched source must not deserialize");
    }

    #[test]
    fn child_request_drops_parent_metadata() {
        let mut parent = Extensions::default();
        parent
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("parent metadata installs");

        let mut child = parent.for_child_request();
        assert!(
            child.metadata.is_none(),
            "child must not inherit parent records"
        );
        child
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("child may install its own record");

        let parent_metadata = parent.metadata.as_deref().expect("parent metadata remains");
        assert!(parent_metadata.get("region").is_none());
        assert!(parent_metadata.get("account").is_some());
    }

    #[test]
    fn read_metadata_is_the_only_way_a_plugin_sees_the_slot() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("metadata installs");

        let hidden = filter_extensions(&extensions, &HashSet::new());
        assert!(hidden.metadata.is_none());

        let caps = HashSet::from(["read_metadata".to_owned()]);
        let visible = filter_extensions(&extensions, &caps);
        assert!(Arc::ptr_eq(
            extensions
                .metadata
                .as_ref()
                .expect("canonical metadata exists"),
            visible
                .metadata
                .as_ref()
                .expect("capability reveals metadata")
        ));
        let policy = crate::extensions::filter::slot_policy(SlotName::Metadata);
        assert_eq!(policy.tier, MutabilityTier::Immutable);
        assert_eq!(policy.read_cap, Some(Capability::ReadMetadata));
        assert_eq!(policy.write_cap, None);
    }

    #[test]
    fn plugin_owned_copy_cannot_replace_or_remove_metadata() {
        let mut canonical = Extensions::default();
        canonical
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("canonical metadata installs");
        let original = Arc::clone(canonical.metadata.as_ref().expect("metadata exists"));

        let mut replacement_source = Extensions::default();
        replacement_source
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("replacement metadata installs");
        let mut replaced = canonical.cow_copy();
        replaced.metadata = replacement_source.metadata;
        assert!(!canonical.validate_immutable(&replaced));
        canonical.merge_owned(replaced);
        assert!(Arc::ptr_eq(
            canonical.metadata.as_ref().expect("metadata remains"),
            &original
        ));

        let mut removed = canonical.cow_copy();
        removed.metadata = None;
        canonical.merge_owned(removed);
        assert!(Arc::ptr_eq(
            canonical.metadata.as_ref().expect("metadata remains"),
            &original
        ));
    }

    #[test]
    fn plugin_owned_copy_cannot_create_metadata() {
        let canonical = Extensions::default();
        let mut forged_source = Extensions::default();
        forged_source
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("forged fixture installs in its separate container");
        let mut forged = canonical.cow_copy();
        forged.metadata = forged_source.metadata;

        assert!(
            !canonical.validate_immutable(&forged),
            "a plugin must not fabricate an immutable metadata slot"
        );
    }

    #[test]
    fn merge_back_keeps_parent_metadata_over_plugin_view() {
        let mut parent = Extensions::default();
        parent
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("parent record installs");
        let parent_record = Arc::clone(parent.metadata.as_ref().expect("parent metadata"));

        for plugin_metadata in [None, Some(forged_record())] {
            let mut returned = parent.clone();
            returned.metadata = plugin_metadata;
            returned.retain_metadata_from(&parent);
            assert!(
                Arc::ptr_eq(
                    returned.metadata.as_ref().expect("parent metadata is kept"),
                    &parent_record
                ),
                "merge-back must not drop or replace installed records"
            );
        }
    }

    #[test]
    fn extensions_serde_never_carries_metadata() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("record installs");
        let encoded = serde_json::to_value(&extensions).expect("extensions serialize");
        assert!(
            encoded.get("metadata").is_none(),
            "serializing extensions must omit metadata: {encoded}"
        );

        let stamped = serde_json::to_value(extensions.metadata.as_deref().expect("metadata"))
            .expect("metadata serializes");
        let decoded: Extensions =
            serde_json::from_value(json!({ "metadata": stamped })).expect("extensions deserialize");
        assert!(
            decoded.metadata.is_none(),
            "deserialized extensions must not adopt self-stamped metadata"
        );
    }

    #[test]
    fn records_reject_unknown_fields() {
        let mut record = json!({
            "cache": "disabled",
            "fetched_at": "2026-10-19T12:00:00Z",
            "outcome": "success",
            "value": true,
            "statuss": 200
        });
        serde_json::from_value::<AcquiredFacts>(record.clone())
            .expect_err("a misspelled record field must not be ignored");

        record
            .as_object_mut()
            .expect("record is an object")
            .remove("statuss");
        record["source"] = json!({"instance": "account", "kind": "metadata/http", "extra": 1});
        serde_json::from_value::<AcquiredFacts>(record)
            .expect_err("an unknown source field must not be ignored");
    }

    #[test]
    fn every_invalid_record_shape_is_rejected_atomically() {
        let stale_cache_without_marker =
            AcquiredFacts::success(json!(true), instant(), MetadataCacheDisposition::Stale);
        let mut success_with_error_code = success(json!(true));
        success_with_error_code.error_code = Some("metadata.oops".to_owned());
        let mut success_without_fetched_at = success(json!(true));
        success_without_fetched_at.fetched_at = None;
        let mut success_without_value = success(json!(true));
        success_without_value.value = None;
        let mut error_with_fetched_at = error("metadata.oops", MetadataCacheDisposition::Disabled);
        error_with_fetched_at.fetched_at = Some(instant());
        let mut error_with_value = error("metadata.oops", MetadataCacheDisposition::Disabled);
        error_with_value.value = Some(json!(true));

        for (name, facts) in [
            ("stale cache without marker", stale_cache_without_marker),
            ("success with error code", success_with_error_code),
            ("success without fetched_at", success_without_fetched_at),
            ("success without value", success_without_value),
            (
                "stale error",
                error("metadata.oops", MetadataCacheDisposition::Disabled).with_stale(),
            ),
            (
                "error with stale cache",
                error("metadata.oops", MetadataCacheDisposition::Stale),
            ),
            (
                "error without code",
                error("", MetadataCacheDisposition::Disabled),
            ),
            ("error with fetched_at", error_with_fetched_at),
            ("error with value", error_with_value),
        ] {
            let mut extensions = Extensions::default();
            assert_eq!(
                extensions.install_metadata("account", "metadata/http", facts),
                Err(MetadataInstallError::InvalidRecordShape),
                "{name}"
            );
            assert!(extensions.metadata.is_none(), "{name} must install nothing");
        }
    }

    #[test]
    fn response_keys_that_break_the_projection_are_rejected() {
        for (key, value) in [
            ("", json!({"": 1})),
            ("a.b", json!({"a.b": 1})),
            ("$source", json!({"$source": "forged"})),
            ("value", json!({"value": 1})),
            ("$x", json!({"nested": {"$x": 1}})),
            ("", json!({"list": [{"": 1}]})),
        ] {
            let mut extensions = Extensions::default();
            assert_eq!(
                extensions.install_metadata("account", "metadata/http", success(value)),
                Err(MetadataInstallError::InvalidResponseKey(key.to_owned()))
            );
            assert!(extensions.metadata.is_none());
        }
    }

    #[test]
    fn tampered_installed_metadata_fails_to_deserialize() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!({"active": true})))
            .expect("record installs");
        let stamped = serde_json::to_value(extensions.metadata.as_deref().expect("metadata"))
            .expect("metadata serializes");

        let renamed = |key: &str| {
            let mut tampered = stamped.clone();
            let record = tampered
                .as_object_mut()
                .expect("map")
                .remove("account")
                .expect("record");
            tampered[key] = record;
            tampered
        };
        let edited = |pointer: &str, replacement: Value| {
            let mut tampered = stamped.clone();
            *tampered.pointer_mut(pointer).expect("field exists") = replacement;
            tampered
        };
        let mut error_with_value = stamped.clone();
        error_with_value["account"]["outcome"] = json!("error");
        error_with_value["account"]["error_code"] = json!("metadata.oops");

        for (name, tampered) in [
            ("dotted key", renamed("a.b")),
            ("numeric key", renamed("1x")),
            ("key not matching source", renamed("billing")),
            ("error with value", error_with_value),
            (
                "reserved key in value",
                edited("/account/value", json!({"$source": "forged"})),
            ),
            (
                "empty source kind",
                edited("/account/source/kind", json!("")),
            ),
        ] {
            serde_json::from_value::<MetadataExtension>(tampered).expect_err(name);
        }
    }

    #[test]
    fn failed_install_into_a_uniquely_owned_map_changes_nothing() {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("first record installs");
        let before = extensions.metadata.as_deref().cloned();

        let result =
            extensions.install_metadata("account", "metadata/other", success(json!(false)));

        assert_eq!(
            result,
            Err(MetadataInstallError::DuplicateInstance(
                "account".to_owned()
            ))
        );
        assert_eq!(extensions.metadata.as_deref().cloned(), before);
    }

    #[test]
    fn policy_spellings_match_serde_names() {
        for (disposition, spelling) in [
            (MetadataCacheDisposition::Disabled, "disabled"),
            (MetadataCacheDisposition::Miss, "miss"),
            (MetadataCacheDisposition::Hit, "hit"),
            (MetadataCacheDisposition::Revalidated, "revalidated"),
            (MetadataCacheDisposition::Stale, "stale"),
        ] {
            assert_eq!(disposition.as_str(), spelling);
            assert_eq!(
                serde_json::to_value(disposition).expect("serialize"),
                spelling
            );
        }
        for (outcome, spelling) in [
            (MetadataOutcome::Success, "success"),
            (MetadataOutcome::Error, "error"),
        ] {
            assert_eq!(outcome.as_str(), spelling);
            assert_eq!(serde_json::to_value(outcome).expect("serialize"), spelling);
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn instant() -> DateTime<Utc> {
        "2026-10-19T12:00:00Z"
            .parse()
            .expect("a literal RFC3339 instant")
    }

    fn success(value: Value) -> AcquiredFacts {
        AcquiredFacts::success(value, instant(), MetadataCacheDisposition::Disabled)
    }

    fn error(code: &str, cache: MetadataCacheDisposition) -> AcquiredFacts {
        AcquiredFacts::error(code, cache)
    }

    fn forged_record() -> Arc<MetadataExtension> {
        let mut forged = Extensions::default();
        forged
            .install_metadata("account", "metadata/forged", success(json!(false)))
            .expect("forged fixture installs");
        forged.metadata.expect("forged metadata")
    }
}
