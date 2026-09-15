// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Cache key for a PDP decision.
//
// The stored key is a SHA-256 digest. The preimage is the dialect, the
// call arguments, and every attribute in the bag. Nothing readable from
// the request is retained in the map, and mapping iteration order cannot
// change the digest: YAML maps and the bag are hashed in sorted-key order.

use sha2::{Digest as _, Sha256};

use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};
use praxis_policy_apl_core::step::{PdpCall, PdpDialect};

/// 32-byte digest used as the map key. Copyable, comparable, and opaque.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct CacheKey(pub(crate) [u8; 32]);

impl CacheKey {
    /// Digest of one evaluate inputs. Independent of HashMap/YAML map order.
    pub(crate) fn for_call(call: &PdpCall, bag: &AttributeBag) -> Self {
        let mut hasher = Sha256::new();
        hash_dialect(&mut hasher, &call.dialect);
        hash_yaml(&mut hasher, &call.args);
        hash_bag(&mut hasher, bag);
        Self(hasher.finalize().into())
    }
}

fn hash_dialect(hasher: &mut Sha256, dialect: &PdpDialect) {
    match dialect {
        PdpDialect::Cedar => hasher.update([0_u8]),
        PdpDialect::Opa => hasher.update([1_u8]),
        PdpDialect::AuthZen => hasher.update([2_u8]),
        PdpDialect::NeMo => hasher.update([3_u8]),
        PdpDialect::Cel => hasher.update([4_u8]),
        PdpDialect::Custom(name) => {
            hasher.update([5_u8]);
            hash_bytes(hasher, name.as_bytes());
        },
        _ => hasher.update([255_u8]),
    }
}

fn hash_bag(hasher: &mut Sha256, bag: &AttributeBag) {
    let mut entries: Vec<(&str, &AttributeValue)> = bag.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    hash_len(hasher, entries.len());
    for (key, value) in entries {
        hash_bytes(hasher, key.as_bytes());
        hash_attr(hasher, value);
    }
}

fn hash_attr(hasher: &mut Sha256, value: &AttributeValue) {
    match value {
        AttributeValue::Bool(v) => {
            hasher.update([0_u8]);
            hasher.update([u8::from(*v)]);
        },
        AttributeValue::Int(v) => {
            hasher.update([1_u8]);
            hasher.update(v.to_be_bytes());
        },
        AttributeValue::Float(v) => {
            hasher.update([2_u8]);
            hasher.update(v.to_bits().to_be_bytes());
        },
        AttributeValue::String(v) => {
            hasher.update([3_u8]);
            hash_bytes(hasher, v.as_bytes());
        },
        AttributeValue::StringSet(set) => {
            hasher.update([4_u8]);
            let mut members: Vec<&str> = set.iter().map(String::as_str).collect();
            members.sort_unstable();
            hash_len(hasher, members.len());
            for member in members {
                hash_bytes(hasher, member.as_bytes());
            }
        },
    }
}

fn hash_yaml(hasher: &mut Sha256, value: &serde_yaml::Value) {
    match value {
        serde_yaml::Value::Null => hasher.update([0_u8]),
        serde_yaml::Value::Bool(v) => {
            hasher.update([1_u8]);
            hasher.update([u8::from(*v)]);
        },
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                hasher.update([2_u8]);
                hasher.update(i.to_be_bytes());
            } else if let Some(u) = n.as_u64() {
                hasher.update([3_u8]);
                hasher.update(u.to_be_bytes());
            } else if let Some(f) = n.as_f64() {
                hasher.update([4_u8]);
                hasher.update(f.to_bits().to_be_bytes());
            } else {
                hasher.update([5_u8]);
            }
        },
        serde_yaml::Value::String(s) => {
            hasher.update([6_u8]);
            hash_bytes(hasher, s.as_bytes());
        },
        serde_yaml::Value::Sequence(seq) => {
            hasher.update([7_u8]);
            hash_len(hasher, seq.len());
            for item in seq {
                hash_yaml(hasher, item);
            }
        },
        serde_yaml::Value::Mapping(map) => {
            hasher.update([8_u8]);
            let mut pairs: Vec<(Vec<u8>, &serde_yaml::Value)> = map
                .iter()
                .map(|(k, v)| (canonical_yaml_bytes(k), v))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            hash_len(hasher, pairs.len());
            for (key_bytes, val) in pairs {
                hash_bytes(hasher, &key_bytes);
                hash_yaml(hasher, val);
            }
        },
        serde_yaml::Value::Tagged(tagged) => {
            hasher.update([9_u8]);
            hash_bytes(hasher, tagged.tag.to_string().as_bytes());
            hash_yaml(hasher, &tagged.value);
        },
    }
}

fn canonical_yaml_bytes(value: &serde_yaml::Value) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hash_yaml(&mut hasher, value);
    hasher.finalize().to_vec()
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut Sha256, len: usize) {
    hasher.update(u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes());
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn call_with_map(alpha_first: bool) -> PdpCall {
        let yaml = if alpha_first {
            "alpha: 1\nbeta: 2\n"
        } else {
            "beta: 2\nalpha: 1\n"
        };
        let args: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        PdpCall {
            dialect: PdpDialect::Cel,
            args,
        }
    }

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
}
