// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Load-time envelope validation for resource and prompt routes.
//
// These functions validate `args:` / `result:` field paths and stages
// against the fixed envelopes a resource or prompt route projects.
// Extracted from `visitor.rs` so the 3k-line visitor stays focused on
// config walking and handler installation.

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_PROMPT, ENTITY_RESOURCE};
use praxis_policy_core::visitor::VisitorError;

use praxis_policy_apl_core::pipeline::{FieldRule, ScanKind, Stage};
use praxis_policy_apl_core::rules::{CompiledRoute, Effect};

use crate::dispatch_plan::walk_effects;
use crate::message_projection::{
    OPEN_MAP_FIELDS, PROMPT_RESULT_FIELDS, PROMPT_RESULT_READ_ONLY, RESOURCE_FIELDS,
    RESOURCE_READ_ONLY, RESOURCE_REF_FIELDS, RESOURCE_REF_READ_ONLY,
};

/// The field-path segment that matches at any depth (`**.ssn`).
const RECURSIVE_SEGMENT: &str = "**";

/// Refuse an `args:` or `result:` block declared at a scope that reaches only
/// a payload with no fields. Today that is the `http:` selector: an HTTP
/// exchange reaches a policy through its extensions, and `HttpPayload` has
/// nothing for a field path to address, so such a stage would read nothing and
/// rewrite nothing.
///
/// `scope` is the label the refusal names, already spelled the way its caller
/// names the declaration. Called for each scope whose reach is one entity type,
/// which is what gives it a payload to check: a route's own block and
/// `global.defaults.<entity>`. A bundle is shared by routes of several entity
/// types, and `global:` accepts neither block at all.
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

/// Refuse an `args:` or `result:` pipeline, or a rule's field operation
/// (`do: result.uri | redact`), that would change a read-only envelope field:
/// `uri` and `resource_type` on a resource route, `icons` on a
/// fetched resource, and `prompt_name` and `is_error` on a rendered prompt.
///
/// These identify what was authorized, so write-back keeps the original
/// whatever a pipeline does; refusing at load keeps that from being a silent
/// no-op. A stage that only checks or labels the value (`str`, `regex(...)`,
/// `taint(...)`, a detecting scan) is accepted, as are rules that read the
/// field. Called for the same scopes as [`reject_field_stages_without_fields`].
///
/// A recursive path (`**.uri`) is judged by its last segment, since it can
/// reach the top-level field of that name. The name is compared without case,
/// because a `redact` stage matches keys without case at runtime, so
/// `**.URI` reaches `uri` too.
pub(crate) fn reject_writes_to_read_only_fields(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    for envelope in fixed_envelopes(entity_type, layer) {
        for field_use in &envelope.uses {
            let mut segments = field_use.field.split('.');
            let first = segments.next().unwrap_or_default();
            let addressed = if first == RECURSIVE_SEGMENT {
                field_use.field.rsplit('.').next().unwrap_or_default()
            } else {
                first
            };
            let addressed = addressed.to_lowercase();
            if envelope.read_only.contains(&addressed.as_str())
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

/// Refuse an `args:` or `result:` path, or a rule's field operation path
/// (`do: result.ssn | redact`), that cannot resolve on a resource or prompt
/// envelope, which has a fixed set of fields: a name the envelope does
/// not have, or a path that continues inside a field holding a single value
/// (`content.ssn`; `content` is an opaque string). A path inside `annotations`
/// is accepted, since it is an open map, and so is a recursive `**` path.
///
/// Tool `args` / `result` and prompt `args` take their keys from the host's
/// arguments map, so they have no fixed set and are not checked. Called for
/// the same scopes as [`reject_field_stages_without_fields`].
pub(crate) fn reject_unknown_field_paths(
    entity_type: &str,
    scope: &str,
    layer: &CompiledRoute,
) -> Result<(), VisitorError> {
    for envelope in fixed_envelopes(entity_type, layer) {
        let block = envelope.block;
        for field_use in &envelope.uses {
            let mut segments = field_use.field.split('.');
            let first = segments.next().unwrap_or_default();
            if first == RECURSIVE_SEGMENT {
                continue;
            }
            if !envelope.fields.contains(&first) {
                return Err(format!(
                    "{scope}: {origin} names `{field}`, but a `{entity_type}:` `{block}` has no \
                     field `{first}`. Its fields are: {fields}.",
                    origin = field_use.origin,
                    field = field_use.field,
                    fields = envelope.fields.join(", "),
                )
                .into());
            }
            if segments.next().is_some() && !OPEN_MAP_FIELDS.contains(&first) {
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

/// The field uses of `layer` that address a fixed envelope on an
/// `entity_type` route, grouped by envelope with that envelope's fields.
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

/// Every field path under `block` in `layer`: the `block:` field rules, and the
/// rule effects (`do: result.ssn | redact`) in `pre_invocation:` and
/// `post_invocation:`, including effects nested in `when`, sequential,
/// parallel and PDP reaction lists. Both forms write the same envelope, so a
/// check that only read the block would let the rule form through.
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
