// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Immutable externally acquired facts and their trusted provenance.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

/// Internal framework authority to publish validated acquired facts.
///
/// Source plugins return an [`AcquiredFacts`] value; a trusted route
/// orchestrator registered through `PolicyEngine::annotate_route` may hold
/// this capability while validating, stamping, and installing it. Hosts must
/// not grant it to handlers that forward source-controlled extension values.
#[doc(hidden)]
pub const CAP_FRAMEWORK_PUBLISH_METADATA: &str = "__framework_publish_metadata";

/// Namespace reserved for normalized metadata-source failures.
pub const METADATA_ERROR_CODE_PREFIX: &str = "metadata.";

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
#[derive(Clone, Debug)]
pub struct AcquiredFacts {
    cache: MetadataCacheDisposition,
    error_code: Option<String>,
    fetched_at: Option<DateTime<Utc>>,
    numbers_validated: bool,
    outcome: MetadataOutcome,
    source: Option<MetadataSource>,
    stale: bool,
    status: Option<u16>,
    value: Option<Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(
    bound(deserialize = "E: Deserialize<'de>, S: Deserialize<'de>, V: Deserialize<'de>"),
    deny_unknown_fields
)]
struct AcquiredFactsWire<V = Value, E = String, S = MetadataSource> {
    cache: MetadataCacheDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<E>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetched_at: Option<DateTime<Utc>>,
    outcome: MetadataOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<S>,
    #[serde(default, skip_serializing_if = "is_false")]
    stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    value: Option<V>,
}

fn deserialize_present_value<'de, D, V>(deserializer: D) -> Result<Option<V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    V::deserialize(deserializer).map(Some)
}

impl PartialEq for AcquiredFacts {
    fn eq(&self, other: &Self) -> bool {
        self.cache == other.cache
            && self.error_code == other.error_code
            && self.fetched_at == other.fetched_at
            && self.outcome == other.outcome
            && self.source == other.source
            && self.stale == other.stale
            && self.status == other.status
            && self.value == other.value
    }
}

impl Serialize for AcquiredFacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        AcquiredFactsWire {
            cache: self.cache,
            error_code: self.error_code.as_deref(),
            fetched_at: self.fetched_at,
            outcome: self.outcome,
            source: self.source.as_ref(),
            stale: self.stale,
            status: self.status,
            value: self.value.as_ref().map(|value| SerializedMetadataValue {
                value,
                numbers_validated: self.numbers_validated,
            }),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AcquiredFacts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire: AcquiredFactsWire = AcquiredFactsWire::deserialize(deserializer)?;
        let value = wire
            .value
            .map(decode_and_validate_numbers)
            .transpose()
            .map_err(D::Error::custom)?;
        Ok(Self {
            cache: wire.cache,
            error_code: wire.error_code,
            fetched_at: wire.fetched_at,
            numbers_validated: value.is_some(),
            outcome: wire.outcome,
            source: wire.source,
            stale: wire.stale,
            status: wire.status,
            value,
        })
    }
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
            numbers_validated: false,
            outcome: MetadataOutcome::Success,
            source: None,
            stale: false,
            status: None,
            value: Some(value),
        }
    }

    /// Parse a successful record while validating original JSON number tokens.
    ///
    /// Metadata sources parsing an HTTP response should use this constructor
    /// instead of parsing into [`Value`] first. Once a decimal has rounded to
    /// binary64, later validation cannot recover its original token.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataInstallError::InvalidNumber`] when any number is
    /// outside the common lossless evaluator domain, or
    /// [`MetadataInstallError::InvalidJson`] when `json` is malformed.
    pub fn success_json(
        json: &str,
        fetched_at: DateTime<Utc>,
        cache: MetadataCacheDisposition,
    ) -> Result<Self, MetadataInstallError> {
        let _syntax: &serde_json::value::RawValue = serde_json::from_str(json)
            .map_err(|error| MetadataInstallError::InvalidJson(error.to_string()))?;
        validate_json_number_tokens(json)?;
        let value = serde_json::from_str(json)
            .map_err(|error| MetadataInstallError::InvalidJson(error.to_string()))?;
        let mut facts = Self::success(value, fetched_at, cache);
        facts.numbers_validated = true;
        Ok(facts)
    }

    /// Create an error record containing no partial acquired value.
    #[must_use]
    pub fn error(error_code: impl Into<String>, cache: MetadataCacheDisposition) -> Self {
        Self {
            cache,
            error_code: Some(error_code.into()),
            fetched_at: None,
            numbers_validated: false,
            outcome: MetadataOutcome::Error,
            source: None,
            stale: false,
            status: None,
            value: None,
        }
    }

    /// Validate the source-owned record before provenance is stamped.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataInstallError`] when outcome-specific fields or value
    /// keys cannot form one atomic metadata record.
    pub fn validate(&self) -> Result<(), MetadataInstallError> {
        validate_record(self)
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

        facts.numbers_validated = true;
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
    /// A source response is not valid JSON.
    #[error("metadata response is not valid JSON: {0}")]
    InvalidJson(String),
    /// The plugin instance name cannot safely form a namespace segment.
    #[error("invalid metadata instance name `{0}`")]
    InvalidInstanceName(String),
    /// The trusted plugin registration did not supply a source kind.
    #[error("metadata source kind must not be empty")]
    InvalidSourceKind,
    /// Outcome-specific fields do not form a complete atomic record.
    #[error("invalid metadata record shape")]
    InvalidRecordShape,
    /// A source error code is outside the reserved metadata namespace.
    #[error("metadata error code `{0}` must start with `metadata.` and include a name")]
    InvalidErrorCode(String),
    /// A JSON number is outside the common lossless evaluator domain.
    #[error("metadata number is not a signed i64 or exactly representable finite binary64")]
    InvalidNumber(String),
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Serde predicate for omitting a false stale marker.
fn is_false(value: &bool) -> bool {
    !value
}

const EXACT_BINARY64_TAG: &str = "$praxis_exact_binary64";

/// Preserve an already validated floating-point value across serde formats.
/// Response keys beginning with `$` are rejected, so this representation
/// cannot collide with source-owned metadata.
struct SerializedMetadataValue<'a> {
    value: &'a Value,
    numbers_validated: bool,
}

impl Serialize for SerializedMetadataValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.numbers_validated {
            return self.value.serialize(serializer);
        }
        match self.value {
            Value::Number(number) if number.as_i64().is_none() => {
                let Some(candidate) = number.as_f64() else {
                    return number.serialize(serializer);
                };
                let token = if candidate == 0.0 {
                    if candidate.is_sign_negative() {
                        "-0.0".to_owned()
                    } else {
                        "0.0".to_owned()
                    }
                } else {
                    let (digits, exponent) = exact_binary64_decimal(candidate);
                    let sign = if candidate.is_sign_negative() {
                        "-"
                    } else {
                        ""
                    };
                    format!("{sign}{digits}e{exponent}")
                };
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(EXACT_BINARY64_TAG, &token)?;
                map.end()
            },
            Value::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for value in items {
                    sequence.serialize_element(&Self {
                        value,
                        numbers_validated: true,
                    })?;
                }
                sequence.end()
            },
            Value::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(
                        key,
                        &Self {
                            value,
                            numbers_validated: true,
                        },
                    )?;
                }
                map.end()
            },
            value => value.serialize(serializer),
        }
    }
}

/// Decode the reserved exact-number representation and validate every plain
/// JSON number before marking the record as validated.
fn decode_and_validate_numbers(value: Value) -> Result<Value, MetadataInstallError> {
    match value {
        Value::Number(number) => {
            validate_number(&number)?;
            Ok(Value::Number(number))
        },
        Value::Array(items) => items
            .into_iter()
            .map(decode_and_validate_numbers)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(mut fields)
            if fields.len() == 1 && fields.contains_key(EXACT_BINARY64_TAG) =>
        {
            let token = fields
                .remove(EXACT_BINARY64_TAG)
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| {
                    MetadataInstallError::InvalidNumber(EXACT_BINARY64_TAG.to_owned())
                })?;
            let candidate = token
                .parse::<f64>()
                .map_err(|_error| MetadataInstallError::InvalidNumber(token.clone()))?;
            if !decimal_is_exact_binary64(&token, candidate) {
                return Err(MetadataInstallError::InvalidNumber(token));
            }
            serde_json::Number::from_f64(candidate)
                .map(Value::Number)
                .ok_or(MetadataInstallError::InvalidNumber(token))
        },
        Value::Object(fields) => fields
            .into_iter()
            .map(|(key, value)| decode_and_validate_numbers(value).map(|value| (key, value)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(Value::Object),
        other => Ok(other),
    }
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
            validate_keys(value, true, facts.numbers_validated)
        },
        (MetadataOutcome::Error, _)
            if facts.value.is_none()
                && facts.fetched_at.is_none()
                && !facts.stale
                && facts.cache != MetadataCacheDisposition::Stale =>
        {
            let code = facts
                .error_code
                .as_deref()
                .ok_or(MetadataInstallError::InvalidRecordShape)?;
            if code
                .strip_prefix(METADATA_ERROR_CODE_PREFIX)
                .is_none_or(str::is_empty)
            {
                return Err(MetadataInstallError::InvalidErrorCode(code.to_owned()));
            }
            Ok(())
        },
        _ => Err(MetadataInstallError::InvalidRecordShape),
    }
}

/// Reject response keys that collide in the derived dotted projection.
fn validate_keys(
    value: &Value,
    root: bool,
    numbers_validated: bool,
) -> Result<(), MetadataInstallError> {
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
                validate_keys(child, false, numbers_validated)?;
            }
            Ok(())
        },
        Value::Array(items) => {
            for item in items {
                validate_keys(item, false, numbers_validated)?;
            }
            Ok(())
        },
        Value::Number(number) if !numbers_validated => validate_number(number),
        _ => Ok(()),
    }
}

/// Enforce the numeric intersection CEL and OPA can project without rounding.
fn validate_number(number: &serde_json::Number) -> Result<(), MetadataInstallError> {
    if number.as_i64().is_some() {
        return Ok(());
    }
    if number.as_u64().is_some() {
        return Err(MetadataInstallError::InvalidNumber(number.to_string()));
    }
    let text = number.to_string();
    let candidate = number.as_f64();
    if candidate.is_some_and(|candidate| decimal_is_exact_binary64(&text, candidate)) {
        Ok(())
    } else {
        Err(MetadataInstallError::InvalidNumber(text))
    }
}

/// Validate every raw numeric lexeme instead of its parser-rounded value.
fn validate_json_number_tokens(json: &str) -> Result<(), MetadataInstallError> {
    let bytes = json.as_bytes();
    let mut index = 0;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'"' => {
                index += 1;
                while let Some(string_byte) = bytes.get(index).copied() {
                    index += 1;
                    match string_byte {
                        b'\\' => index = index.saturating_add(1),
                        b'"' => break,
                        _ => {},
                    }
                }
            },
            b'-' | b'0'..=b'9' => {
                let start = index;
                index = number_token_end(bytes, index);
                let Some(token) = json.get(start..index) else {
                    return Err(MetadataInstallError::InvalidJson(
                        "number token is not on a character boundary".to_owned(),
                    ));
                };
                validate_number_token(token)?;
            },
            _ => index += 1,
        }
    }
    Ok(())
}

/// Return the end of one JSON number-shaped token.
fn number_token_end(bytes: &[u8], mut index: usize) -> usize {
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            index += 1;
        }
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    index
}

/// Enforce the numeric domain against one unmodified JSON lexeme.
fn validate_number_token(token: &str) -> Result<(), MetadataInstallError> {
    if !token.contains(['.', 'e', 'E']) {
        return token
            .parse::<i64>()
            .map(|_| ())
            .map_err(|_error| MetadataInstallError::InvalidNumber(token.to_owned()));
    }
    let candidate = token.parse::<f64>();
    if candidate.is_ok_and(|candidate| decimal_is_exact_binary64(token, candidate)) {
        Ok(())
    } else {
        Err(MetadataInstallError::InvalidNumber(token.to_owned()))
    }
}

/// Whether a decimal token is the exact value of its binary64 candidate.
fn decimal_is_exact_binary64(text: &str, candidate: f64) -> bool {
    if !candidate.is_finite() {
        return false;
    }
    let Some((token_digits, token_exponent)) = normalized_decimal_token(text) else {
        return false;
    };
    let candidate_is_zero = matches!(candidate.classify(), std::num::FpCategory::Zero);
    if token_digits == "0" {
        return candidate_is_zero;
    }
    if candidate_is_zero {
        return false;
    }

    let (candidate_digits, candidate_exponent) = exact_binary64_decimal(candidate);
    token_digits == candidate_digits && token_exponent == candidate_exponent
}

/// Normalize a decimal as integer digits multiplied by a power of ten.
fn normalized_decimal_token(text: &str) -> Option<(String, i32)> {
    let (mantissa, exponent) = text
        .split_once(['e', 'E'])
        .map_or((text, None), |(mantissa, exponent)| {
            (mantissa, Some(exponent))
        });
    let unsigned = mantissa.strip_prefix(['-', '+']).unwrap_or(mantissa);
    let fractional = unsigned
        .split_once('.')
        .map_or(Some(0_i32), |(_whole, fraction)| {
            i32::try_from(fraction.len()).ok()
        })?;
    let mut digits: String = unsigned
        .chars()
        .filter(|character| *character != '.')
        .collect::<String>()
        .trim_start_matches('0')
        .to_owned();
    if digits.is_empty() {
        return Some(("0".to_owned(), 0));
    }
    let exponent = exponent.map_or(Some(0_i32), |value| value.parse::<i32>().ok())?;
    let mut decimal_exponent = exponent.checked_sub(fractional)?;
    while digits.ends_with('0') {
        digits.pop();
        decimal_exponent = decimal_exponent.checked_add(1)?;
    }
    Some((digits, decimal_exponent))
}

/// Render one finite nonzero binary64 as exact normalized decimal digits.
fn exact_binary64_decimal(candidate: f64) -> (String, i32) {
    const FRACTION_BITS: u32 = 52;
    const FRACTION_EXPONENT: i32 = 52;
    const FRACTION_MASK: u64 = (1_u64 << FRACTION_BITS) - 1;
    const EXPONENT_BIAS: i32 = 1023;
    const SUBNORMAL_EXPONENT: i32 = -1074;

    let bits = candidate.abs().to_bits();
    let stored_exponent = i32::try_from((bits >> FRACTION_BITS) & 0x7ff).unwrap_or_default();
    let fraction = bits & FRACTION_MASK;
    let (mut significand, mut binary_exponent) = if stored_exponent == 0 {
        (fraction, SUBNORMAL_EXPONENT)
    } else {
        (
            (1_u64 << FRACTION_BITS) | fraction,
            stored_exponent - EXPONENT_BIAS - FRACTION_EXPONENT,
        )
    };
    if binary_exponent < 0 {
        while significand % 2 == 0 {
            significand /= 2;
            binary_exponent += 1;
        }
    }
    let mut digits: Vec<u8> = significand
        .to_string()
        .bytes()
        .rev()
        .map(|byte| byte - b'0')
        .collect();
    let mut decimal_exponent = 0_i32;
    if binary_exponent < 0 {
        for _ in 0..binary_exponent.unsigned_abs() {
            multiply_decimal_digits(&mut digits, 5);
        }
        decimal_exponent = binary_exponent;
    } else {
        for _ in 0..binary_exponent.unsigned_abs() {
            multiply_decimal_digits(&mut digits, 2);
        }
    }
    let mut text: String = digits
        .into_iter()
        .rev()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    while text.ends_with('0') {
        text.pop();
        decimal_exponent += 1;
    }
    (text, decimal_exponent)
}

/// Multiply little-endian base-ten digits by one small factor.
fn multiply_decimal_digits(digits: &mut Vec<u8>, factor: u8) {
    let mut carry = 0_u16;
    for digit in &mut *digits {
        let product = u16::from(*digit) * u16::from(factor) + carry;
        *digit = u8::try_from(product % 10).unwrap_or_default();
        carry = product / 10;
    }
    if carry != 0 {
        digits.push(u8::try_from(carry).unwrap_or_default());
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

    const EXACT_BINARY64_ONE_TENTH: &str =
        "0.1000000000000000055511151231257827021181583404541015625";
    const SENSITIVE_NUMBER: &str = "9007199254740993.0";

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
    fn numeric_domain_accepts_i64_and_exact_binary64_values() {
        for value in [json!(i64::MIN), json!(i64::MAX), json!(0.5), json!(1.25)] {
            let mut extensions = Extensions::default();
            extensions
                .install_metadata("account", "metadata/http", success(value))
                .expect("the numeric value is lossless in CEL and OPA");
        }
    }

    #[test]
    fn numeric_domain_rejects_unsigned_and_rounding_values_atomically() {
        for value in [json!(u64::MAX), json!(0.1)] {
            let mut extensions = Extensions::default();
            let result = extensions.install_metadata("account", "metadata/http", success(value));
            assert!(matches!(
                result,
                Err(MetadataInstallError::InvalidNumber(_))
            ));
            assert!(extensions.metadata.is_none(), "a rejected record is atomic");
        }
    }

    #[test]
    fn numeric_domain_validates_the_original_json_token_before_rounding() {
        for token in [
            "9007199254740993.0",
            "1.0000000000000001",
            "0.50000000000000001",
        ] {
            let result =
                AcquiredFacts::success_json(token, instant(), MetadataCacheDisposition::Disabled);
            assert!(
                matches!(result, Err(MetadataInstallError::InvalidNumber(_))),
                "{token} requires binary64 rounding"
            );
        }
    }

    #[test]
    fn numeric_rejection_messages_do_not_disclose_the_rejected_value() {
        let error = AcquiredFacts::success_json(
            SENSITIVE_NUMBER,
            instant(),
            MetadataCacheDisposition::Disabled,
        )
        .expect_err("the rounded account identifier is rejected");
        let rendered = error.to_string();

        assert!(rendered.contains("metadata number"), "{rendered}");
        assert!(
            !rendered.contains(SENSITIVE_NUMBER),
            "the rejection category must not disclose the metadata value: {rendered}"
        );
    }

    #[test]
    fn raw_json_number_validation_is_recursive_and_atomic() {
        let result = AcquiredFacts::success_json(
            r#"{"safe": 0.5, "nested": [1, {"unsafe": 1.0000000000000001}]}"#,
            instant(),
            MetadataCacheDisposition::Disabled,
        );

        assert!(matches!(
            result,
            Err(MetadataInstallError::InvalidNumber(token))
                if token == "1.0000000000000001"
        ));
    }

    #[test]
    fn raw_json_constructor_accepts_exact_numbers_and_reports_malformed_json() {
        let facts = AcquiredFacts::success_json(
            &format!(
                r#"{{
                "minimum": -9223372036854775808,
                "ratio": 5e-1,
                "exact_one_tenth": {EXACT_BINARY64_ONE_TENTH},
                "numeric_text": "9007199254740993.0",
                "escaped": "quoted: \"1.0000000000000001\""
            }}"#
            ),
            instant(),
            MetadataCacheDisposition::Disabled,
        )
        .expect("exact numbers are accepted");
        let value = facts.value().expect("a successful value");
        assert_eq!(value["minimum"], json!(i64::MIN));
        assert_eq!(value["ratio"], json!(0.5));
        assert_eq!(value["exact_one_tenth"], json!(0.1));
        assert_eq!(value["numeric_text"], json!("9007199254740993.0"));
        assert_eq!(value["escaped"], json!("quoted: \"1.0000000000000001\""));
        facts
            .validate()
            .expect("the validated raw numeric representation remains trusted");
        let mut extensions = Extensions::default();
        extensions
            .install_metadata("account", "metadata/http", facts)
            .expect("raw-number validation survives framework installation");

        let malformed = AcquiredFacts::success_json(
            r#"{"ratio": 0.5"#,
            instant(),
            MetadataCacheDisposition::Disabled,
        );
        assert!(matches!(
            malformed,
            Err(MetadataInstallError::InvalidJson(_))
        ));

        for malformed_number in ["-", "1.", "1e"] {
            let result = AcquiredFacts::success_json(
                malformed_number,
                instant(),
                MetadataCacheDisposition::Disabled,
            );
            assert!(
                matches!(result, Err(MetadataInstallError::InvalidJson(_))),
                "malformed number `{malformed_number}` is invalid JSON"
            );
        }
    }

    #[test]
    fn syntactically_valid_out_of_range_numbers_report_the_numeric_domain() {
        let result = AcquiredFacts::success_json(
            r#"{"ratio":1e400}"#,
            instant(),
            MetadataCacheDisposition::Disabled,
        );

        assert!(matches!(
            result,
            Err(MetadataInstallError::InvalidNumber(token)) if token == "1e400"
        ));
    }

    #[test]
    fn zero_accepts_an_exponent_outside_the_nonzero_normalization_range() {
        let facts = AcquiredFacts::success_json(
            r#"{"ratio":0e2147483648}"#,
            instant(),
            MetadataCacheDisposition::Disabled,
        )
        .expect("every exponent spelling of exact zero is lossless");

        assert_eq!(
            facts.value().and_then(|value| value.get("ratio")),
            Some(&json!(0.0))
        );
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
    fn error_codes_must_use_the_metadata_namespace() {
        for code in [
            "",
            "metadata.",
            "policy.deny",
            "elicitation.store_unavailable",
        ] {
            let facts = AcquiredFacts::error(code, MetadataCacheDisposition::Disabled);
            let mut extensions = Extensions::default();

            let result = extensions.install_metadata("account", "metadata/http", facts);

            assert_eq!(
                result,
                Err(MetadataInstallError::InvalidErrorCode(code.to_owned()))
            );
            assert!(extensions.metadata.is_none());
        }
    }

    #[test]
    fn installed_extension_round_trips_without_losing_provenance() {
        let mut extensions = Extensions::default();
        let facts = AcquiredFacts::success_json(
            &format!(r#"{{"active": true, "ratio": {EXACT_BINARY64_ONE_TENTH}}}"#),
            instant(),
            MetadataCacheDisposition::Disabled,
        )
        .expect("the exact decimal is accepted");
        extensions
            .install_metadata("account", "metadata/http", facts)
            .expect("metadata installs");
        let metadata = extensions.metadata.as_deref().expect("metadata exists");

        let encoded = serde_json::to_value(metadata).expect("metadata serializes");
        let decoded: MetadataExtension =
            serde_json::from_value(encoded).expect("installed metadata deserializes");

        assert_eq!(&decoded, metadata);
        decoded
            .get("account")
            .expect("account survives")
            .validate()
            .expect("exact-number validation survives serialization");
    }

    #[test]
    fn plain_success_round_trips_with_semantic_equality() {
        let facts = success(json!({
            "active": true,
            "profile": {"name": "alice", "roles": ["reader", "admin"], "missing": null},
            "scores": [1, 0.5]
        }));
        let encoded = serde_json::to_string(&facts).expect("plain success serializes");
        let decoded: AcquiredFacts = serde_json::from_str(&encoded).expect("plain success decodes");
        assert_eq!(
            decoded, facts,
            "validation state must not change record equality"
        );
        decoded.validate().expect("decoded facts remain valid");

        let encoded = serde_yaml::to_string(&facts).expect("plain success serializes to YAML");
        let decoded: AcquiredFacts =
            serde_yaml::from_str(&encoded).expect("plain success decodes from YAML");
        assert_eq!(
            decoded, facts,
            "record equality must survive either serde format"
        );
    }

    #[test]
    fn typed_success_round_trips_without_changing_validation_state() {
        let mut extensions = Extensions::default();
        let facts =
            AcquiredFacts::success(json!(true), instant(), MetadataCacheDisposition::Disabled);
        extensions
            .install_metadata("account", "metadata/http", facts)
            .expect("metadata installs");
        let metadata = extensions.metadata.as_deref().expect("metadata exists");

        let encoded = serde_json::to_value(metadata).expect("metadata serializes");
        let decoded: MetadataExtension =
            serde_json::from_value(encoded).expect("installed metadata deserializes");

        assert_eq!(&decoded, metadata);
    }

    #[test]
    fn successful_null_round_trips_as_a_present_value() {
        let mut extensions = Extensions::default();
        let facts =
            AcquiredFacts::success_json("null", instant(), MetadataCacheDisposition::Disabled)
                .expect("null is a valid successful JSON value");
        extensions
            .install_metadata("account", "metadata/http", facts)
            .expect("metadata installs");
        let metadata = extensions.metadata.as_deref().expect("metadata exists");

        let encoded = serde_json::to_value(metadata).expect("metadata serializes");
        let decoded: MetadataExtension =
            serde_json::from_value(encoded).expect("installed null metadata deserializes");

        assert_eq!(&decoded, metadata);
        assert_eq!(
            decoded.get("account").and_then(AcquiredFacts::value),
            Some(&Value::Null)
        );
    }

    #[test]
    fn serialized_exact_number_tag_cannot_bypass_validation() {
        let raw_decimal = json!({
            "cache": "disabled",
            "fetched_at": "2026-10-19T12:00:00Z",
            "outcome": "success",
            "value": {"ratio": 0.1}
        });
        serde_json::from_value::<AcquiredFacts>(raw_decimal)
            .expect_err("an ordinary rounded decimal remains invalid");

        let forged_tag = json!({
            "cache": "disabled",
            "fetched_at": "2026-10-19T12:00:00Z",
            "outcome": "success",
            "value": {"ratio": {EXACT_BINARY64_TAG: "9007199254740993"}}
        });
        serde_json::from_value::<AcquiredFacts>(forged_tag)
            .expect_err("the reserved tag accepts only exact binary64 decimals");
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
    fn framework_publication_can_only_append_metadata_instances() {
        let mut canonical = Extensions::default();
        canonical
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("canonical metadata installs");

        let mut appended = canonical.clone();
        appended
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("a second instance installs");
        assert!(canonical.validate_immutable_with_metadata(&appended.cow_copy(), true));

        let mut removed = Extensions::default();
        removed
            .install_metadata("region", "metadata/http", success(json!("eu")))
            .expect("replacement fixture installs");
        assert!(!canonical.validate_immutable_with_metadata(&removed.cow_copy(), true));

        let mut replaced = Extensions::default();
        replaced
            .install_metadata("account", "metadata/http", success(json!(false)))
            .expect("replacement fixture installs");
        assert!(!canonical.validate_immutable_with_metadata(&replaced.cow_copy(), true));

        let dropped = Extensions::default();
        assert!(!canonical.validate_immutable_with_metadata(&dropped.cow_copy(), true));
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
