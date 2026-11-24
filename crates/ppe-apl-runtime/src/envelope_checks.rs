// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Missing fields and read-only rewrites would otherwise load successfully
// and silently leave policy intent unenforced on fixed envelopes.

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_PROMPT, ENTITY_RESOURCE};
use praxis_policy_core::visitor::VisitorError;

use praxis_policy_apl_core::pipeline::{FieldRule, ScanKind, Stage};
use praxis_policy_apl_core::rules::{CompiledRoute, Effect};

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
            let addressed = field_use
                .field
                .split('.')
                .find(|segment| *segment != RECURSIVE_SEGMENT)
                .unwrap_or_default()
                .to_lowercase();
            if (envelope.read_only.contains(&addressed.as_str())
                || reaches_read_only_descendant(&envelope, field_use))
                && field_use.stages.iter().any(stage_writes)
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
            let mut segments = field_use.field.split('.').peekable();
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

/// Whether a path can reach the read-only icon subtree.
fn reaches_read_only_descendant(envelope: &FixedEnvelope<'_>, field: &FieldUse<'_>) -> bool {
    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        let Some((segment, rest)) = pattern.split_first() else {
            return path.is_empty();
        };
        if *segment == RECURSIVE_SEGMENT {
            return matches(rest, path)
                || path
                    .split_first()
                    .is_some_and(|(_, tail)| matches(pattern, tail));
        }
        let Some((key, tail)) = path.split_first() else {
            return false;
        };
        let same = *segment == *key || (*key == "0" && segment.parse::<usize>().is_ok());
        (same && matches(rest, tail)) || (*key == "0" && matches(pattern, tail))
    }
    if !envelope.read_only.contains(&"icons") {
        return false;
    }
    let name = if matches_without_case(field.stages) {
        field.field.to_lowercase()
    } else {
        field.field.to_owned()
    };
    let pattern: Vec<&str> = name.split('.').collect();
    if pattern.iter().all(|segment| *segment == RECURSIVE_SEGMENT) {
        return false;
    }
    [
        &["icons", "0", "src"][..],
        &["icons", "0", "mime_type"][..],
        &["icons", "0", "sizes"][..],
        &["icons", "0", "sizes", "0"][..],
    ]
    .iter()
    .any(|path| matches(&pattern, path))
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
            if let Effect::FieldOp { path, stages } = effect
                && let Some(field) = path
                    .strip_prefix(block)
                    .and_then(|rest| rest.strip_prefix('.'))
            {
                uses.push(FieldUse {
                    field,
                    origin: format!("a `{phase}:` rule"),
                    stages,
                });
            }
        });
    }
    uses
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
