// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Pipe-chain IR for APL `args:` and `result:` phases.
//
// A field-level pipeline is a sequence of `Stage`s separated by `|` in the
// DSL. Validators (str/int/range/...) check the field's value and can fail
// the request; transforms (mask/redact/omit/hash) modify the value; effects
// (taint) record side information.
//
// Stages whose evaluator behavior is deferred (taint dispatch,
// plugin invocation, regex/named validators, scan placeholders) are still
// represented in the IR so the parser can produce them — the evaluator
// recognizes them and returns a clear "deferred" signal rather than crashing.

use serde::{Deserialize, Serialize};

use crate::rules::Expression;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The type a `str`, `int`, or similar stage asserts a field holds.
pub enum TypeCheck {
    /// A string.
    Str,
    /// An integer.
    Int,
    /// A boolean.
    Bool,
    /// A floating-point number.
    Float,
    /// A syntactically valid email address.
    Email,
    /// A syntactically valid URL.
    Url,
    /// A syntactically valid UUID.
    Uuid,
}

/// Scope at which a taint applies. Marked `#[non_exhaustive]` so new
/// variants (e.g. `Request`, `Pipeline`, conversation-level) can be
/// added without breaking downstream exhaustive matches. v0 emits only
/// `Session` and `Message`; plugin-extracted taints (from
/// `extensions.security.labels` diffs in `CmfPluginInvoker`) default to
/// `Session` because praxis-policy-core's label monotonicity is session-semantic.
/// Config-side `Step::Taint`/`Stage::Taint` declares scopes explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TaintScope {
    /// Persists for the session, so later requests see it.
    Session,
    /// Applies to this message only.
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Which scan a `scan` stage runs.
pub enum ScanKind {
    /// Find PII and replace it.
    PiiRedact,
    /// Find PII and report it without changing the value.
    PiiDetect,
    /// Look for prompt injection.
    InjectionScan,
}

/// One stage in a pipe chain.
///
/// Stages execute left-to-right against a single field value. Validators
/// halt the pipeline on failure; transforms produce a new value; effects
/// (taint) annotate without changing the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Assert the field holds the given type.
    Type(TypeCheck),
    /// `regex("pattern")` — parser captures the pattern; evaluator stubbed
    /// until we add the `regex` crate dependency.
    Regex {
        /// The pattern the value must match.
        pattern: String,
    },
    /// `validate(name)` — named validator dispatch; evaluator stubbed.
    Validate {
        /// The registered validator to run.
        name: String,
    },
    /// `len(..N)`, `len(N..M)`, `len(N..)` — string length bounds.
    Length {
        /// Inclusive lower bound, if any.
        min: Option<usize>,
        /// Inclusive upper bound, if any.
        max: Option<usize>,
    },
    /// Bare range literal `N..M`, `..M`, `N..`, with optional `k`/`K`/`m`/`M`
    /// numeric suffixes. Integer-only.
    Range {
        /// Inclusive lower bound, if any.
        min: Option<i64>,
        /// Inclusive upper bound, if any.
        max: Option<i64>,
    },
    /// `enum(a, b, c)` — value must equal one of the listed strings.
    Enum {
        /// The permitted values.
        values: Vec<String>,
    },

    /// `mask(N)` — replace all but last N chars with `*`.
    Mask {
        /// How many trailing characters survive unmasked.
        keep_last: usize,
    },
    /// `redact` (unconditional) or `redact(!condition)` (conditional).
    /// Replaces value with `[REDACTED]` when condition is true (or always,
    /// if no condition).
    Redact {
        /// Redact only when this holds. `None` redacts unconditionally.
        condition: Option<Expression>,
    },
    /// `omit` — drop the field from output entirely. No conditional form
    /// — use a policy rule for conditional omit.
    Omit,
    /// `hash` — replace value with a hash digest.
    Hash,

    /// Attach a label without changing the value.
    Taint {
        /// The label to attach.
        label: String,
        /// How far the label propagates.
        scopes: Vec<TaintScope>,
    },
    /// Hand the value to a named plugin.
    Plugin {
        /// The plugin to invoke.
        name: String,
    },
    /// Scan the value for PII or injection.
    Scan {
        /// Which scan to run.
        kind: ScanKind,
    },
}

/// Sequence of stages applied to one field's value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pipeline {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The stages, applied left to right.
    pub stages: Vec<Stage>,
}

impl Pipeline {
    /// An empty pipeline, which leaves the value untouched.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a stage.
    pub fn push(&mut self, stage: Stage) {
        self.stages.push(stage);
    }
    /// Whether the pipeline has no stages.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }
}

/// Attaches a pipeline to a specific field name in the args or result phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Dotted path to the field this applies to.
    pub field: String,
    /// The stages to apply.
    pub pipeline: Pipeline,
    /// Source location (e.g., `"get_compensation.result.ssn"`) for audit.
    pub source: String,
}

/// A taint label produced as a side effect of running a pipeline.
///
/// The evaluator accumulates these in `PipelineEvaluation.taints`; the host
/// (praxis-policy-apl-runtime) drains them and writes to the actual `SessionStore`. Same shape
/// as `Stage::Taint`'s fields, but lives at the evaluator boundary because
/// it also carries taints emitted by plugin invocations and scan stages
/// — not just literal `taint(...)` stages.
#[derive(Debug, Clone, PartialEq)]
pub struct TaintEvent {
    /// The label attached.
    pub label: String,
    /// How far it propagates.
    pub scopes: Vec<TaintScope>,
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn pipeline_new_is_empty() {
        let pipeline = Pipeline::new();
        assert!(pipeline.is_empty());
        assert!(pipeline.stages.is_empty());
    }

    #[test]
    fn pipeline_push_adds_stage() {
        let mut pipeline = Pipeline::new();
        assert!(pipeline.is_empty());

        pipeline.push(Stage::Type(TypeCheck::Str));
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.stages.len(), 1);
    }

    #[test]
    fn pipeline_push_multiple_stages() {
        let mut pipeline = Pipeline::new();
        pipeline.push(Stage::Type(TypeCheck::Str));
        pipeline.push(Stage::Type(TypeCheck::Int));
        pipeline.push(Stage::Omit);

        assert_eq!(pipeline.stages.len(), 3);
        assert!(!pipeline.is_empty());
    }

    #[test]
    fn type_check_variants_equality() {
        assert_eq!(TypeCheck::Str, TypeCheck::Str);
        assert_ne!(TypeCheck::Str, TypeCheck::Int);
        assert_ne!(TypeCheck::Email, TypeCheck::Url);
        assert_ne!(TypeCheck::Uuid, TypeCheck::Bool);
        assert_ne!(TypeCheck::Float, TypeCheck::Int);
    }

    #[test]
    fn taint_scope_variants_equality() {
        assert_eq!(TaintScope::Session, TaintScope::Session);
        assert_ne!(TaintScope::Session, TaintScope::Message);
    }

    #[test]
    fn scan_kind_variants_equality() {
        assert_eq!(ScanKind::PiiRedact, ScanKind::PiiRedact);
        assert_ne!(ScanKind::PiiRedact, ScanKind::PiiDetect);
        assert_ne!(ScanKind::InjectionScan, ScanKind::PiiDetect);
        assert_ne!(ScanKind::PiiRedact, ScanKind::InjectionScan);
    }

    #[test]
    fn stage_type_check_variant() {
        let stage = Stage::Type(TypeCheck::Email);
        match stage {
            Stage::Type(check) => assert_eq!(check, TypeCheck::Email),
            _ => panic!("expected Type variant"),
        }
    }

    #[test]
    fn stage_length_bounds_variant() {
        let stage = Stage::Length {
            min: Some(1),
            max: Some(10),
        };
        match stage {
            Stage::Length { min, max } => {
                assert_eq!(min, Some(1));
                assert_eq!(max, Some(10));
            },
            _ => panic!("expected Length variant"),
        }
    }

    #[test]
    fn stage_range_bounds_variant() {
        let stage = Stage::Range {
            min: Some(0),
            max: Some(100),
        };
        match stage {
            Stage::Range { min, max } => {
                assert_eq!(min, Some(0));
                assert_eq!(max, Some(100));
            },
            _ => panic!("expected Range variant"),
        }
    }

    #[test]
    fn stage_enum_variants_all() {
        let regex = Stage::Regex {
            pattern: "^test".to_owned(),
        };
        match regex {
            Stage::Regex { pattern } => assert_eq!(pattern, "^test"),
            _ => panic!("expected Regex variant"),
        }

        let validate = Stage::Validate {
            name: "custom".to_owned(),
        };
        match validate {
            Stage::Validate { name } => assert_eq!(name, "custom"),
            _ => panic!("expected Validate variant"),
        }

        let enum_stage = Stage::Enum {
            values: vec!["a".to_owned(), "b".to_owned()],
        };
        match enum_stage {
            Stage::Enum { values } => assert_eq!(values.len(), 2),
            _ => panic!("expected Enum variant"),
        }
    }

    #[test]
    fn stage_mask_variant() {
        let stage = Stage::Mask { keep_last: 4 };
        match stage {
            Stage::Mask { keep_last } => assert_eq!(keep_last, 4),
            _ => panic!("expected Mask variant"),
        }
    }

    #[test]
    fn stage_redact_unconditional_variant() {
        let stage = Stage::Redact { condition: None };
        match stage {
            Stage::Redact { condition } => assert!(condition.is_none()),
            _ => panic!("expected Redact variant"),
        }
    }

    #[test]
    fn stage_omit_variant() {
        let stage = Stage::Omit;
        match stage {
            Stage::Omit => {},
            _ => panic!("expected Omit variant"),
        }
    }

    #[test]
    fn stage_hash_variant() {
        let stage = Stage::Hash;
        match stage {
            Stage::Hash => {},
            _ => panic!("expected Hash variant"),
        }
    }

    #[test]
    fn stage_taint_variant() {
        let stage = Stage::Taint {
            label: "sensitive".to_owned(),
            scopes: vec![TaintScope::Session, TaintScope::Message],
        };
        match stage {
            Stage::Taint { label, scopes } => {
                assert_eq!(label, "sensitive");
                assert_eq!(scopes.len(), 2);
            },
            _ => panic!("expected Taint variant"),
        }
    }

    #[test]
    fn stage_plugin_variant() {
        let stage = Stage::Plugin {
            name: "redactor".to_owned(),
        };
        match stage {
            Stage::Plugin { name } => assert_eq!(name, "redactor"),
            _ => panic!("expected Plugin variant"),
        }
    }

    #[test]
    fn stage_scan_variant() {
        let stage = Stage::Scan {
            kind: ScanKind::PiiRedact,
        };
        match stage {
            Stage::Scan { kind } => assert_eq!(kind, ScanKind::PiiRedact),
            _ => panic!("expected Scan variant"),
        }
    }

    #[test]
    fn field_rule_construction() {
        let rule = FieldRule {
            field: "request.body.email".to_owned(),
            pipeline: Pipeline::new(),
            source: "policy.apl:42".to_owned(),
        };
        assert_eq!(rule.field, "request.body.email");
        assert!(rule.pipeline.is_empty());
        assert_eq!(rule.source, "policy.apl:42");
    }

    #[test]
    fn field_rule_with_pipeline() {
        let mut pipeline = Pipeline::new();
        pipeline.push(Stage::Type(TypeCheck::Str));
        pipeline.push(Stage::Mask { keep_last: 4 });

        let rule = FieldRule {
            field: "ssn".to_owned(),
            pipeline,
            source: "audit.apl:10".to_owned(),
        };

        assert_eq!(rule.field, "ssn");
        assert!(!rule.pipeline.is_empty());
        assert_eq!(rule.pipeline.stages.len(), 2);
    }

    #[test]
    fn taint_event_construction() {
        let event = TaintEvent {
            label: "pii_found".to_owned(),
            scopes: vec![TaintScope::Message],
        };
        assert_eq!(event.label, "pii_found");
        assert_eq!(event.scopes.len(), 1);
    }

    #[test]
    fn taint_event_multiple_scopes() {
        let event = TaintEvent {
            label: "injection_detected".to_owned(),
            scopes: vec![TaintScope::Session, TaintScope::Message],
        };
        assert_eq!(event.label, "injection_detected");
        assert_eq!(event.scopes.len(), 2);
        assert!(event.scopes.contains(&TaintScope::Session));
        assert!(event.scopes.contains(&TaintScope::Message));
    }

    #[test]
    fn pipeline_serialization_empty() {
        let pipeline = Pipeline::new();
        let json = serde_json::to_string(&pipeline).expect("serialize");
        let deserialized: Pipeline = serde_json::from_str(&json).expect("deserialize");
        assert!(deserialized.is_empty());
    }

    #[test]
    fn pipeline_serialization_with_stages() {
        let mut pipeline = Pipeline::new();
        pipeline.push(Stage::Type(TypeCheck::Str));
        pipeline.push(Stage::Mask { keep_last: 4 });

        let json = serde_json::to_string(&pipeline).expect("serialize");
        let deserialized: Pipeline = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.stages.len(), 2);
    }

    #[test]
    fn stage_serialization_roundtrip_length() {
        let stage = Stage::Length {
            min: Some(5),
            max: Some(50),
        };

        let json = serde_json::to_string(&stage).expect("serialize");
        let deserialized: Stage = serde_json::from_str(&json).expect("deserialize");

        match deserialized {
            Stage::Length { min, max } => {
                assert_eq!(min, Some(5));
                assert_eq!(max, Some(50));
            },
            _ => panic!("deserialization failed"),
        }
    }

    #[test]
    fn stage_serialization_roundtrip_range() {
        let stage = Stage::Range {
            min: Some(-10),
            max: Some(100),
        };

        let json = serde_json::to_string(&stage).expect("serialize");
        let deserialized: Stage = serde_json::from_str(&json).expect("deserialize");

        match deserialized {
            Stage::Range { min, max } => {
                assert_eq!(min, Some(-10));
                assert_eq!(max, Some(100));
            },
            _ => panic!("deserialization failed"),
        }
    }

    #[test]
    fn type_check_serialization() {
        let checks = vec![
            TypeCheck::Str,
            TypeCheck::Int,
            TypeCheck::Bool,
            TypeCheck::Float,
            TypeCheck::Email,
            TypeCheck::Url,
            TypeCheck::Uuid,
        ];

        for check in checks {
            let json = serde_json::to_string(&check).expect("serialize");
            let deserialized: TypeCheck = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(deserialized, check);
        }
    }
}
