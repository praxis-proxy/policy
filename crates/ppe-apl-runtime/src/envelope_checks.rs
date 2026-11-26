// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Missing fields and read-only rewrites would otherwise load successfully
// and silently leave policy intent unenforced on fixed envelopes.

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_PROMPT, ENTITY_RESOURCE};
use praxis_policy_core::visitor::VisitorError;

use praxis_policy_apl_core::pipeline::{FieldRule, ScanKind, Stage};
use praxis_policy_apl_core::rules::{CompiledRoute, Condition, Effect, Expression};

use crate::dispatch_plan::walk_effects;
use crate::message_projection::{
    OPEN_MAP_FIELDS, PROMPT_RESULT_FIELDS, PROMPT_RESULT_READ_ONLY, RESOURCE_FIELDS,
    RESOURCE_READ_ONLY, RESOURCE_REF_FIELDS, RESOURCE_REF_READ_ONLY,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The field-path segment that matches at any depth (`**.ssn`).
const RECURSIVE_SEGMENT: &str = "**";

const ICON_FIELD_PATHS: &[&[&str]] = &[
    &["icons"],
    &["icons", "[]"],
    &["icons", "[]", "src"],
    &["icons", "[]", "mime_type"],
    &["icons", "[]", "sizes"],
    &["icons", "[]", "sizes", "[]"],
];

/// Reject field blocks on HTTP routes, whose payload exposes no fields.
///
/// `scope` identifies the configuration declaration in the diagnostic.
///
/// # Errors
///
/// Returns a configuration error for an unsupported field block.
pub(crate) fn reject_field_stages_without_fields(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    if entity_type != ENTITY_HTTP {
        return Ok(());
    }
    let block = if !layer.args.is_empty() {
        "args"
    } else if !layer.result.is_empty() {
        "result"
    } else {
        return Ok(());
    };
    Err(format!(
        "{scope}: an `http:` route cannot declare a `{block}:` block, because a \
         generic HTTP request carries no message for a field path to address. Read the request \
         from the `http.*` attributes under `pre_invocation:` (or `post_invocation:`) instead."
    )
    .into())
}

/// Reject field operations that change fixed envelope identity fields.
///
/// Checks and labels remain permitted. Recursive paths that can address a
/// read-only field or its descendants are also refused.
///
/// # Errors
///
/// Returns a configuration error naming the scope and protected field.
pub(crate) fn reject_writes_to_read_only_fields(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    for envelope in fixed_envelopes(entity_type, layer) {
        for field_use in &envelope.uses {
            if field_use.stages.iter().any(stage_writes)
                && reaches_read_only_descendant(&envelope, field_use)
            {
                return Err(format!(
                    "{scope}: {origin} changes `{field}`, which is read-only on a \
                     `{entity_type}:` route. It identifies what was authorized, so it can be \
                     checked (in a rule, or with a stage such as `str`) but not rewritten.",
                    origin = field_use.origin,
                    field = field_use.field,
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Reject paths that cannot resolve within a fixed resource or prompt envelope.
///
/// Content is opaque; annotation descendants remain addressable. Redaction
/// paths match names without case, while other stages require exact names.
/// Dynamic tool and prompt argument maps are outside this fixed-field check.
///
/// # Errors
///
/// Returns a configuration error for an unknown field or a scalar descendant.
pub(crate) fn reject_unknown_field_paths(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    for envelope in fixed_envelopes(entity_type, layer) {
        let block = envelope.block;
        for field_use in &envelope.uses {
            let ignore_case = matches_without_case(field_use.stages);
            let mut segments = field_use
                .field
                .split(|ch| ch == '.' || (field_use.condition && ch == '['))
                .peekable();
            let recursive = segments
                .peek()
                .is_some_and(|segment| *segment == RECURSIVE_SEGMENT);
            while segments.next_if_eq(&RECURSIVE_SEGMENT).is_some() {}
            let first = segments.next().unwrap_or_default();
            if recursive {
                let has_open_map = envelope
                    .fields
                    .iter()
                    .any(|field| OPEN_MAP_FIELDS.contains(field));
                if has_open_map || first.is_empty() {
                    continue;
                }
            }
            let Some(known) = envelope_field(envelope.fields, first, ignore_case) else {
                return Err(format!(
                    "{scope}: {origin} names `{field}`, but a `{entity_type}:` `{block}` has no \
                     field `{first}`. Its fields are: {fields}.",
                    origin = field_use.origin,
                    field = field_use.field,
                    fields = envelope.fields.join(", "),
                )
                .into());
            };
            if known == "icons" {
                if field_use.condition && segments.any(|segment| segment != RECURSIVE_SEGMENT) {
                    return Err(format!("{scope}: a condition names `{field}`, but icon descendants are available only to field pipelines", field = field_use.field).into());
                }
                let pattern: Vec<&str> = field_use.field.split('.').collect();
                if ICON_FIELD_PATHS
                    .iter()
                    .any(|path| selector_matches(&pattern, path, ignore_case))
                {
                    continue;
                }
                return Err(format!("{scope}: {origin} names `{field}`, but icons have only src, mime_type and sizes fields", origin = field_use.origin, field = field_use.field).into());
            }
            if segments.any(|segment| segment != RECURSIVE_SEGMENT)
                && !OPEN_MAP_FIELDS.contains(&known)
            {
                return Err(format!(
                    "{scope}: {origin} names `{field}`, but `{first}` holds a single value with \
                     no fields inside it. Address `{first}` as a whole.",
                    origin = field_use.origin,
                    field = field_use.field,
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Match a selector against one fixed schema path. `[]` denotes an array index.
fn selector_matches(pattern: &[&str], path: &[&str], ignore_case: bool) -> bool {
    let Some((segment, rest)) = pattern.split_first() else {
        return path.is_empty();
    };
    if *segment == RECURSIVE_SEGMENT {
        return selector_matches(rest, path, ignore_case)
            || path
                .split_first()
                .is_some_and(|(_, tail)| selector_matches(pattern, tail, ignore_case));
    }
    let Some((key, tail)) = path.split_first() else {
        return false;
    };
    let same = if *key == "[]" {
        segment.parse::<usize>().is_ok()
    } else if ignore_case {
        segment.eq_ignore_ascii_case(key)
    } else {
        *segment == *key
    };
    (same && selector_matches(rest, tail, ignore_case))
        || (*key == "[]" && selector_matches(pattern, tail, ignore_case))
}

/// Whether the full selector can reach a protected value.
fn reaches_read_only_descendant(envelope: &FixedEnvelope<'_>, field: &FieldUse<'_>) -> bool {
    let pattern: Vec<&str> = field.field.split('.').collect();
    if pattern.iter().all(|segment| *segment == RECURSIVE_SEGMENT) {
        return false;
    }
    let ignore_case = matches_without_case(field.stages);
    envelope
        .read_only
        .iter()
        .any(|field| selector_matches(&pattern, &[field], ignore_case))
        || (envelope.read_only.contains(&"icons")
            && ICON_FIELD_PATHS
                .iter()
                .any(|path| selector_matches(&pattern, path, ignore_case)))
}

/// Return the fixed envelopes addressed by a route's field operations.
fn fixed_envelopes<'a>(entity_type: &str, layer: &'a CompiledRoute) -> Vec<FixedEnvelope<'a>> {
    let envelope = |block, rules, fields, read_only| FixedEnvelope {
        block,
        fields,
        read_only,
        uses: field_uses(layer, block, rules),
    };
    match entity_type {
        ENTITY_RESOURCE => vec![
            envelope(
                "args",
                &layer.args,
                RESOURCE_REF_FIELDS,
                RESOURCE_REF_READ_ONLY,
            ),
            envelope("result", &layer.result, RESOURCE_FIELDS, RESOURCE_READ_ONLY),
        ],
        ENTITY_PROMPT => vec![envelope(
            "result",
            &layer.result,
            PROMPT_RESULT_FIELDS,
            PROMPT_RESULT_READ_ONLY,
        )],
        _ => Vec::new(),
    }
}

/// Return field paths from a block and its invocation-rule effects.
fn field_uses<'a>(
    layer: &'a CompiledRoute,
    block: &'static str,
    rules: &'a [FieldRule],
) -> Vec<FieldUse<'a>> {
    let mut uses: Vec<FieldUse<'a>> = rules
        .iter()
        .map(|rule| FieldUse {
            condition: false,
            field: &rule.field,
            origin: format!("the `{block}:` block"),
            stages: &rule.pipeline.stages,
        })
        .collect();
    for (phase, effects) in [
        ("pre_invocation", &layer.pre_invocation),
        ("post_invocation", &layer.post_invocation),
    ] {
        walk_effects(effects, &mut |effect| {
            if let Effect::When { condition, .. } = effect {
                condition_fields(condition, block, &mut uses);
            }
            if let Effect::FieldOp { path, stages } = effect {
                stage_condition_fields(stages, block, &mut uses);
                if let Some(field) = path
                    .strip_prefix(block)
                    .and_then(|rest| rest.strip_prefix('.'))
                {
                    uses.push(FieldUse {
                        condition: false,
                        field,
                        origin: format!("a `{phase}:` rule"),
                        stages,
                    });
                }
            }
        });
    }
    for rule in rules {
        stage_condition_fields(&rule.pipeline.stages, block, &mut uses);
    }
    uses
}

fn stage_condition_fields<'a>(
    stages: &'a [Stage],
    block: &'static str,
    uses: &mut Vec<FieldUse<'a>>,
) {
    for stage in stages {
        if let Stage::Redact {
            condition: Some(condition),
        } = stage
        {
            condition_fields(condition, block, uses);
        }
    }
}

fn condition_fields<'a>(
    expression: &'a Expression,
    block: &'static str,
    uses: &mut Vec<FieldUse<'a>>,
) {
    let mut add = |key: &'a str| condition_key_fields(key, block, uses);
    match expression {
        Expression::Condition(condition) => match condition {
            Condition::Comparison { key, .. }
            | Condition::IsTrue { key }
            | Condition::IsFalse { key }
            | Condition::Exists { key } => add(key),
            Condition::InSet {
                value_key, set_key, ..
            } => {
                add(value_key);
                add(set_key);
            },
        },
        Expression::And(expressions) | Expression::Or(expressions) => {
            for expression in expressions {
                condition_fields(expression, block, uses);
            }
        },
        Expression::Not(expression) => condition_fields(expression, block, uses),
        Expression::Always => {},
    }
}

fn condition_key_fields<'a>(key: &'a str, block: &'static str, uses: &mut Vec<FieldUse<'a>>) {
    let mut add = |reference: &'a str| {
        if let Some(field) = reference
            .strip_prefix(block)
            .and_then(|key| key.strip_prefix('.'))
        {
            uses.push(FieldUse {
                condition: true,
                field,
                origin: "a condition".to_owned(),
                stages: &[],
            });
        }
    };
    add(key);
    let mut rest = key;
    while let Some((_, after_open)) = rest.split_once('[') {
        let Some((operand, tail)) = after_open.split_once(']') else {
            break;
        };
        add(operand.trim());
        rest = tail;
    }
}

/// One block's field uses and the fixed envelope they address.
struct FixedEnvelope<'a> {
    block: &'static str,
    fields: &'static [&'static str],
    read_only: &'static [&'static str],
    uses: Vec<FieldUse<'a>>,
}

/// Whether the path contains a stage that matches keys without case.
fn matches_without_case(stages: &[Stage]) -> bool {
    stages
        .iter()
        .any(|stage| matches!(stage, Stage::Redact { .. }))
}

/// Resolve an envelope name using the stage's case-matching contract.
fn envelope_field(
    fields: &'static [&'static str],
    name: &str,
    ignore_case: bool,
) -> Option<&'static str> {
    if ignore_case {
        let name = name.to_lowercase();
        fields.iter().copied().find(|f| f.to_lowercase() == name)
    } else {
        fields.iter().copied().find(|f| *f == name)
    }
}

/// One field path addressed in an envelope, where it was written, and the
/// stages applied to it.
struct FieldUse<'a> {
    condition: bool,
    field: &'a str,
    origin: String,
    stages: &'a [Stage],
}

/// Whether a field-pipeline stage can change the value it is applied to. A
/// plugin counts as changing it, since it may rewrite the value.
fn stage_writes(stage: &Stage) -> bool {
    match stage {
        Stage::Mask { .. }
        | Stage::Redact { .. }
        | Stage::Omit
        | Stage::Hash
        | Stage::Plugin { .. }
        | Stage::Scan {
            kind: ScanKind::PiiRedact,
        } => true,
        Stage::Type(_)
        | Stage::Regex { .. }
        | Stage::Validate { .. }
        | Stage::Length { .. }
        | Stage::Range { .. }
        | Stage::Enum { .. }
        | Stage::Taint { .. }
        | Stage::Scan {
            kind: ScanKind::PiiDetect | ScanKind::InjectionScan,
        } => false,
    }
}
