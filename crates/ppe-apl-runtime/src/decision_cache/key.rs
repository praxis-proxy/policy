// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Cache key for a PDP decision.
//
// The stored key is a SHA-256 digest. The preimage is the dialect, the
// call arguments, every attribute in the bag, and the structured request
// input. Nothing readable from the request is retained in the map, and
// mapping iteration order cannot change the digest: YAML maps, JSON
// objects, and the bag are hashed in sorted-key order.

use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{PdpCall, PdpDialect};
use praxis_policy_core::crypto::{CryptoError, Sha256};

/// 32-byte digest used as the map key. Copyable, comparable, and opaque.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct CacheKey(pub(crate) [u8; 32]);

impl CacheKey {
    /// Digest of one evaluate inputs. Independent of HashMap/YAML map order.
    ///
    /// Structured input is the empty default, matching `evaluate` when the
    /// caller has no request JSON. Test-only: production code goes through
    /// [`Self::for_evaluation`].
    #[cfg(test)]
    #[allow(
        clippy::expect_used,
        reason = "test-only helper uses the selected backend in unit tests"
    )]
    pub(crate) fn for_call(call: &PdpCall, bag: &AttributeBag) -> Self {
        Self::for_evaluation(call, bag, &StructuredInput::default())
            .expect("selected SHA-256 backend is available")
    }

    /// Digest of one `evaluate_structured` inputs. Request JSON is part of
    /// the preimage, so two calls that differ only there cannot share an entry.
    ///
    /// # Errors
    /// Returns an error if the selected SHA-256 provider cannot hash the key.
    pub(crate) fn for_evaluation(
        call: &PdpCall,
        bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<Self, CryptoError> {
        let mut hasher = Sha256::new()?;
        hash_dialect(&mut hasher, &call.dialect)?;
        hash_yaml(&mut hasher, &call.args)?;
        hash_bag(&mut hasher, bag)?;
        hash_structured(&mut hasher, structured)?;
        Ok(Self(hasher.finalize()?))
    }
}

trait HashSink {
    fn update(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), CryptoError>;
}

impl HashSink for Sha256 {
    fn update(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), CryptoError> {
        Sha256::update(self, bytes)
    }
}

impl HashSink for Vec<u8> {
    fn update(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), CryptoError> {
        self.extend_from_slice(bytes.as_ref());
        Ok(())
    }
}

fn hash_dialect(hasher: &mut impl HashSink, dialect: &PdpDialect) -> Result<(), CryptoError> {
    match dialect {
        PdpDialect::Cedar => hasher.update([0_u8])?,
        PdpDialect::Opa => hasher.update([1_u8])?,
        PdpDialect::AuthZen => hasher.update([2_u8])?,
        PdpDialect::NeMo => hasher.update([3_u8])?,
        PdpDialect::Cel => hasher.update([4_u8])?,
        PdpDialect::Custom(name) => {
            hasher.update([5_u8])?;
            hash_bytes(hasher, name.as_bytes())?;
        },
        // `PdpDialect` is `#[non_exhaustive]` in another crate, so this
        // match needs a catch-all. Tag 255 alone would collide if two
        // new variants landed together; `Debug` of a fieldless variant
        // is the variant name, so each unknown dialect gets its own
        // digest. `Custom` is already handled above.
        other => {
            hasher.update([255_u8])?;
            hash_bytes(hasher, format!("{other:?}").as_bytes())?;
        },
    }
    Ok(())
}

fn hash_bag(hasher: &mut impl HashSink, bag: &AttributeBag) -> Result<(), CryptoError> {
    let mut entries: Vec<(&str, &AttributeValue)> = bag.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    hash_len(hasher, entries.len())?;
    for (key, value) in entries {
        hash_bytes(hasher, key.as_bytes())?;
        hash_attr(hasher, value)?;
    }
    Ok(())
}

fn hash_attr(hasher: &mut impl HashSink, value: &AttributeValue) -> Result<(), CryptoError> {
    match value {
        AttributeValue::Bool(v) => {
            hasher.update([0_u8])?;
            hasher.update([u8::from(*v)])?;
        },
        AttributeValue::Int(v) => {
            hasher.update([1_u8])?;
            hasher.update(v.to_be_bytes())?;
        },
        AttributeValue::Float(v) => {
            hasher.update([2_u8])?;
            hasher.update(v.to_bits().to_be_bytes())?;
        },
        AttributeValue::String(v) => {
            hasher.update([3_u8])?;
            hash_bytes(hasher, v.as_bytes())?;
        },
        AttributeValue::StringSet(set) => {
            hasher.update([4_u8])?;
            let mut members: Vec<&str> = set.iter().map(String::as_str).collect();
            members.sort_unstable();
            hash_len(hasher, members.len())?;
            for member in members {
                hash_bytes(hasher, member.as_bytes())?;
            }
        },
        AttributeValue::NonScalar => hasher.update([5_u8])?,
    }
    Ok(())
}

fn hash_yaml(hasher: &mut impl HashSink, value: &serde_yaml::Value) -> Result<(), CryptoError> {
    match value {
        serde_yaml::Value::Null => hasher.update([0_u8])?,
        serde_yaml::Value::Bool(v) => {
            hasher.update([1_u8])?;
            hasher.update([u8::from(*v)])?;
        },
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                hasher.update([2_u8])?;
                hasher.update(i.to_be_bytes())?;
            } else if let Some(u) = n.as_u64() {
                hasher.update([3_u8])?;
                hasher.update(u.to_be_bytes())?;
            } else if let Some(f) = n.as_f64() {
                hasher.update([4_u8])?;
                hasher.update(f.to_bits().to_be_bytes())?;
            } else {
                hasher.update([5_u8])?;
            }
        },
        serde_yaml::Value::String(s) => {
            hasher.update([6_u8])?;
            hash_bytes(hasher, s.as_bytes())?;
        },
        serde_yaml::Value::Sequence(seq) => {
            hasher.update([7_u8])?;
            hash_len(hasher, seq.len())?;
            for item in seq {
                hash_yaml(hasher, item)?;
            }
        },
        serde_yaml::Value::Mapping(map) => {
            hasher.update([8_u8])?;
            let mut pairs: Vec<(Vec<u8>, &serde_yaml::Value)> = map
                .iter()
                .map(|(k, v)| canonical_yaml_bytes(k).map(|bytes| (bytes, v)))
                .collect::<Result<_, _>>()?;
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            hash_len(hasher, pairs.len())?;
            for (key_bytes, val) in pairs {
                hash_bytes(hasher, &key_bytes)?;
                hash_yaml(hasher, val)?;
            }
        },
        serde_yaml::Value::Tagged(tagged) => {
            hasher.update([9_u8])?;
            hash_bytes(hasher, tagged.tag.to_string().as_bytes())?;
            hash_yaml(hasher, &tagged.value)?;
        },
    }
    Ok(())
}

fn canonical_yaml_bytes(value: &serde_yaml::Value) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    hash_yaml(&mut bytes, value)?;
    Ok(bytes)
}

fn hash_structured(
    hasher: &mut impl HashSink,
    structured: &StructuredInput,
) -> Result<(), CryptoError> {
    hasher.update([u8::from(structured.too_deep())])?;
    hash_optional_json(
        hasher,
        structured.llm_request().map(std::convert::AsRef::as_ref),
    )?;
    hash_optional_json(hasher, structured.args().map(std::convert::AsRef::as_ref))
}

fn hash_optional_json(
    hasher: &mut impl HashSink,
    value: Option<&serde_json::Value>,
) -> Result<(), CryptoError> {
    match value {
        None => hasher.update([0_u8])?,
        Some(value) => {
            hasher.update([1_u8])?;
            hash_json(hasher, value)?;
        },
    }
    Ok(())
}

fn hash_json(hasher: &mut impl HashSink, value: &serde_json::Value) -> Result<(), CryptoError> {
    match value {
        serde_json::Value::Null => hasher.update([0_u8])?,
        serde_json::Value::Bool(v) => {
            hasher.update([1_u8])?;
            hasher.update([u8::from(*v)])?;
        },
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                hasher.update([2_u8])?;
                hasher.update(i.to_be_bytes())?;
            } else if let Some(u) = n.as_u64() {
                hasher.update([3_u8])?;
                hasher.update(u.to_be_bytes())?;
            } else if let Some(f) = n.as_f64() {
                hasher.update([4_u8])?;
                hasher.update(f.to_bits().to_be_bytes())?;
            } else {
                hasher.update([5_u8])?;
            }
        },
        serde_json::Value::String(s) => {
            hasher.update([6_u8])?;
            hash_bytes(hasher, s.as_bytes())?;
        },
        serde_json::Value::Array(items) => {
            hasher.update([7_u8])?;
            hash_len(hasher, items.len())?;
            for item in items {
                hash_json(hasher, item)?;
            }
        },
        serde_json::Value::Object(map) => {
            hasher.update([8_u8])?;
            let mut pairs: Vec<(&str, &serde_json::Value)> =
                map.iter().map(|(key, val)| (key.as_str(), val)).collect();
            pairs.sort_by(|left, right| left.0.cmp(right.0));
            hash_len(hasher, pairs.len())?;
            for (key, val) in pairs {
                hash_bytes(hasher, key.as_bytes())?;
                hash_json(hasher, val)?;
            }
        },
    }
    Ok(())
}

fn hash_bytes(hasher: &mut impl HashSink, bytes: &[u8]) -> Result<(), CryptoError> {
    hash_len(hasher, bytes.len())?;
    hasher.update(bytes)
}

fn hash_len(hasher: &mut impl HashSink, len: usize) -> Result<(), CryptoError> {
    hasher.update(u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use super::*;

    #[test]
    fn map_iteration_order_does_not_change_the_digest() {
        let bag = AttributeBag::new();
        let a = CacheKey::for_call(&call_with_map(true), &bag);
        let b = CacheKey::for_call(&call_with_map(false), &bag);
        assert_eq!(a, b);
    }

    #[test]
    fn bag_key_order_does_not_change_the_digest() {
        let call = PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::Value::Null,
        };
        let mut left = AttributeBag::new();
        left.set("z", "1");
        left.set("a", "2");
        let mut right = AttributeBag::new();
        right.set("a", "2");
        right.set("z", "1");
        assert_eq!(
            CacheKey::for_call(&call, &left),
            CacheKey::for_call(&call, &right)
        );
    }

    #[test]
    fn string_set_member_order_does_not_change_the_digest() {
        let call = PdpCall {
            dialect: PdpDialect::Opa,
            args: serde_yaml::Value::Null,
        };
        let mut left = AttributeBag::new();
        left.set(
            "session.labels",
            HashSet::from(["pii".to_owned(), "hr".to_owned()]),
        );
        let mut right = AttributeBag::new();
        right.set(
            "session.labels",
            HashSet::from(["hr".to_owned(), "pii".to_owned()]),
        );
        assert_eq!(
            CacheKey::for_call(&call, &left),
            CacheKey::for_call(&call, &right)
        );
    }

    #[test]
    fn dialect_and_bag_changes_change_the_digest() {
        let args = serde_yaml::Value::Null;
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        let cel = PdpCall {
            dialect: PdpDialect::Cel,
            args: args.clone(),
        };
        let opa = PdpCall {
            dialect: PdpDialect::Opa,
            args,
        };
        assert_ne!(
            CacheKey::for_call(&cel, &bag),
            CacheKey::for_call(&opa, &bag)
        );
        let mut other = bag.clone();
        other.set("subject.id", "bob");
        assert_ne!(
            CacheKey::for_call(&cel, &bag),
            CacheKey::for_call(&cel, &other)
        );
    }

    #[test]
    fn custom_dialect_names_change_the_digest() {
        let bag = AttributeBag::new();
        let args = serde_yaml::Value::Null;
        let a = PdpCall {
            dialect: PdpDialect::Custom("workload".into()),
            args: args.clone(),
        };
        let b = PdpCall {
            dialect: PdpDialect::Custom("guard".into()),
            args,
        };
        assert_ne!(CacheKey::for_call(&a, &bag), CacheKey::for_call(&b, &bag));
    }

    #[test]
    fn tagged_yaml_is_part_of_the_digest() {
        let bag = AttributeBag::new();
        let tagged: serde_yaml::Value = serde_yaml::from_str("!note alice\n").unwrap();
        let plain: serde_yaml::Value = serde_yaml::from_str("alice\n").unwrap();
        let a = PdpCall {
            dialect: PdpDialect::Cel,
            args: tagged,
        };
        let b = PdpCall {
            dialect: PdpDialect::Cel,
            args: plain,
        };
        assert_ne!(CacheKey::for_call(&a, &bag), CacheKey::for_call(&b, &bag));
    }

    #[test]
    fn structured_json_changes_the_digest_and_object_key_order_does_not() {
        let call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let bag = AttributeBag::new();
        let empty = CacheKey::for_call(&call, &bag);
        let with_args = CacheKey::for_evaluation(
            &call,
            &bag,
            &StructuredInput::new(None, Some(Arc::new(serde_json::json!({"z": 1, "a": 2})))),
        )
        .unwrap();
        let reordered = CacheKey::for_evaluation(
            &call,
            &bag,
            &StructuredInput::new(None, Some(Arc::new(serde_json::json!({"a": 2, "z": 1})))),
        )
        .unwrap();
        assert_ne!(empty, with_args);
        assert_eq!(with_args, reordered);
    }

    #[test]
    fn every_supported_dialect_has_a_distinct_cache_key() {
        let keys: Vec<CacheKey> = [
            PdpDialect::Cedar,
            PdpDialect::Opa,
            PdpDialect::AuthZen,
            PdpDialect::NeMo,
            PdpDialect::Cel,
            PdpDialect::Custom("custom-a".to_owned()),
            PdpDialect::Custom("custom-b".to_owned()),
        ]
        .into_iter()
        .map(|dialect| {
            CacheKey::for_call(
                &PdpCall {
                    dialect,
                    args: serde_yaml::Value::Null,
                },
                &AttributeBag::new(),
            )
        })
        .collect();
        assert_distinct(&keys);
    }

    #[test]
    fn bag_value_types_and_values_have_distinct_cache_keys() {
        let keys: Vec<CacheKey> = [
            AttributeValue::Bool(false),
            AttributeValue::Bool(true),
            AttributeValue::Int(0),
            AttributeValue::Int(1),
            AttributeValue::Float(0.0),
            AttributeValue::Float(1.0),
            AttributeValue::String("0".to_owned()),
            AttributeValue::String("1".to_owned()),
            AttributeValue::StringSet(HashSet::new()),
            AttributeValue::StringSet(HashSet::from(["1".to_owned()])),
            AttributeValue::NonScalar,
        ]
        .into_iter()
        .map(|value| {
            let mut bag = AttributeBag::new();
            bag.set("value", value);
            CacheKey::for_call(&call_with_map(true), &bag)
        })
        .collect();
        assert_distinct(&keys);
    }

    #[test]
    fn yaml_value_types_and_values_have_distinct_cache_keys() {
        let keys: Vec<CacheKey> = [
            "null",
            "false",
            "true",
            "0",
            "1",
            "18446744073709551615",
            "1.0",
            "1.5",
            "'1'",
            "[]",
            "[1]",
            "{}",
            "{x: 1}",
            "!note 1",
        ]
        .into_iter()
        .map(yaml_key)
        .collect();
        assert_distinct(&keys);
    }

    #[test]
    fn json_value_types_and_values_have_distinct_cache_keys() {
        let keys: Vec<CacheKey> = [
            serde_json::json!(null),
            serde_json::json!(false),
            serde_json::json!(true),
            serde_json::json!(0),
            serde_json::json!(1),
            serde_json::json!(u64::MAX),
            serde_json::json!(1.0),
            serde_json::json!(1.5),
            serde_json::json!("1"),
            serde_json::json!([]),
            serde_json::json!([1]),
            serde_json::json!({}),
            serde_json::json!({"x": 1}),
        ]
        .into_iter()
        .map(json_key)
        .collect();
        assert_distinct(&keys);
    }

    #[test]
    fn structured_input_presence_and_slot_have_distinct_cache_keys() {
        let call = call_with_map(true);
        let bag = AttributeBag::new();
        let null = Arc::new(serde_json::Value::Null);
        let keys: Vec<CacheKey> = [
            StructuredInput::default(),
            StructuredInput::new(None, Some(null.clone())),
            StructuredInput::new(Some(null.clone()), None),
            StructuredInput::new(Some(null.clone()), Some(null)),
        ]
        .into_iter()
        .map(|input| CacheKey::for_evaluation(&call, &bag, &input).unwrap())
        .collect();
        assert_distinct(&keys);
    }

    #[test]
    fn nested_yaml_map_order_is_ignored_and_sequence_order_matters() {
        let left = yaml_key(
            "? [1, true]\n: {x: [false, 2.5], y: 18446744073709551615}\n? {a: 1, b: 2}\n: other\n",
        );
        let reordered = yaml_key(
            "? {b: 2, a: 1}\n: other\n? [1, true]\n: {y: 18446744073709551615, x: [false, 2.5]}\n",
        );
        let reversed = yaml_key(
            "? [true, 1]\n: {x: [false, 2.5], y: 18446744073709551615}\n? {a: 1, b: 2}\n: other\n",
        );
        assert_eq!(
            left, reordered,
            "mapping order must not affect nested keys or values"
        );
        assert_ne!(left, reversed, "sequence order is part of a mapping key");
        assert_ne!(yaml_key("[1, 2]"), yaml_key("[2, 1]"));
    }

    #[test]
    fn nested_json_object_order_is_ignored_and_array_order_matters() {
        let left =
            json_key(serde_json::json!({"a": {"x": [null, false, 2.5, "one"], "y": 1}, "b": true}));
        let reordered =
            json_key(serde_json::json!({"b": true, "a": {"y": 1, "x": [null, false, 2.5, "one"]}}));
        let reversed =
            json_key(serde_json::json!({"a": {"x": ["one", 2.5, false, null], "y": 1}, "b": true}));
        assert_eq!(left, reordered, "object order must not change nested keys");
        assert_ne!(left, reversed, "array order must change the key");
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn assert_distinct(keys: &[CacheKey]) {
        for (index, key) in keys.iter().enumerate() {
            for other in keys.iter().skip(index + 1) {
                assert_ne!(
                    key, other,
                    "distinct input types or values must not share a cache key"
                );
            }
        }
    }

    fn call_with_map(alpha_first: bool) -> PdpCall {
        let yaml = if alpha_first {
            "alpha: 1\nbeta: 2\n"
        } else {
            "beta: 2\nalpha: 1\n"
        };
        PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::from_str(yaml).unwrap(),
        }
    }

    fn json_key(value: serde_json::Value) -> CacheKey {
        CacheKey::for_evaluation(
            &call_with_map(true),
            &AttributeBag::new(),
            &StructuredInput::new(None, Some(Arc::new(value))),
        )
        .unwrap()
    }

    fn yaml_key(yaml: &str) -> CacheKey {
        CacheKey::for_call(
            &PdpCall {
                dialect: PdpDialect::Cel,
                args: serde_yaml::from_str(yaml).unwrap(),
            },
            &AttributeBag::new(),
        )
    }
}
