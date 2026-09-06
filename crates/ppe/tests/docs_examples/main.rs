// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The documentation's examples, run through the parsers that read them for
// real.
//
// The pages under `docs/` were ported from the engine's previous home, where
// most of them were written against a config shape and a language this
// repository has since changed. Reading them against the current parser is
// what caught the stale ones; keeping them read is what stops the next round
// of changes quietly invalidating a page nobody opens until it matters.
//
// Every fenced `yaml` block is a whole config document unless it says
// otherwise, so a new example is checked by the default rather than by
// somebody remembering to opt in. A block that is a fragment, or that is a
// rule, pipeline, or predicate rather than a document, says so in an HTML
// comment on the line above its fence:
//
//     <!-- validate: route-body -->     a route's body, wrapped in a route
//     <!-- validate: phase-list -->     a list of rules, wrapped in a phase
//     <!-- validate: attributes -->     an attribute file, not a config
//     <!-- validate: apl-rule -->
//     <!-- validate: apl-pipeline -->
//     <!-- validate: apl-predicate -->
//     <!-- validate: fragment -->
//
// The wrapping markers exist so that showing part of a document still checks
// that part. `route-body` and `phase-list` splice the block into the smallest
// document that would carry it and load the result, which catches a stale key
// or a removed spelling exactly as the real loader would.
//
// `fragment` is the escape hatch and it is meant to be uncomfortable: it
// asserts nothing. It is correct for a deliberately invalid example, the
// "before" half of a migration note, and for a snippet no document could
// hold.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use praxis_policy_apl_core::{
    compile_policy_block_value, parse_pipeline, parse_predicate, parse_rule,
};
use praxis_policy_apl_runtime::merge_attribute_docs;
use praxis_policy_core::config::parse_config;

/// Indent every non-empty line of a block by `spaces`, so it can be spliced
/// into a document at depth.
fn indent(body: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    body.lines()
        .map(|l| {
            if l.trim().is_empty() {
                String::new()
            } else {
                format!("{pad}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The smallest document carrying one route body.
fn wrap_route_body(body: &str, spaces: usize) -> String {
    format!(
        "routes:\n  - tool: docs_example\n{}\n",
        indent(body, spaces)
    )
}

/// The smallest document carrying one phase's list of rules.
fn wrap_phase_list(body: &str) -> String {
    format!(
        "routes:\n  - tool: docs_example\n    authorization:\n      \
         pre_invocation:\n{}\n",
        indent(body, 8)
    )
}

/// The APL keys a policy block carries. The block shape denies anything else,
/// so a section's structural keys are dropped before it is compiled.
const APL_KEYS: [&str; 4] = ["authorization", "args", "result", "plugins"];

/// Load a document, then compile every policy block in it.
///
/// `parse_config` alone is not enough. It validates the document's own keys
/// and hands the `authorization:` block onward untouched, so a misspelled
/// phase or a removed step spelling loads clean and only fails when the route
/// is compiled. Both halves run here for the same reason the engine runs
/// both: an example that loads but does not compile is not a working example.
fn check_document(body: &str) -> Result<(), String> {
    parse_config(body).map_err(|e| e.to_string())?;

    let doc: serde_yaml::Value = serde_yaml::from_str(body).map_err(|e| e.to_string())?;
    let mut sections: Vec<(String, &serde_yaml::Value)> = Vec::new();

    if let Some(global) = doc.get("global") {
        sections.push(("global".to_owned(), global));
        if let Some(defaults) = global.get("defaults").and_then(|d| d.as_mapping()) {
            for (name, block) in defaults {
                sections.push((format!("global.defaults.{}", render(name)), block));
            }
        }
    }
    if let Some(groups) = doc.get("groups").and_then(|g| g.as_mapping()) {
        for (name, block) in groups {
            sections.push((format!("groups.{}", render(name)), block));
        }
    }
    if let Some(routes) = doc.get("routes").and_then(|r| r.as_sequence()) {
        for (i, route) in routes.iter().enumerate() {
            sections.push((format!("routes[{i}]"), route));
        }
    }

    for (label, section) in sections {
        let Some(map) = section.as_mapping() else {
            continue;
        };
        let mut apl = serde_yaml::Mapping::new();
        for key in APL_KEYS {
            if let Some(value) = map.get(serde_yaml::Value::from(key)) {
                apl.insert(serde_yaml::Value::from(key), value.clone());
            }
        }
        if apl.is_empty() {
            continue;
        }
        compile_policy_block_value(&label, &serde_yaml::Value::Mapping(apl))
            .map(|_| ())
            .map_err(|e| format!("{label}: {e}"))?;
    }
    Ok(())
}

fn render(value: &serde_yaml::Value) -> String {
    value
        .as_str()
        .map_or_else(|| "<key>".to_owned(), str::to_owned)
}

/// Below this, the walk or the marker convention has broken rather than the
/// examples having thinned out. A harness that silently checks nothing passes
/// forever, which is the one failure this file cannot report on itself.
const MINIMUM_CHECKED_BLOCKS: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Validator {
    Config,
    RouteBody,
    PhaseList,
    Attributes,
    Fragment,
    AplRule,
    AplPipeline,
    AplPredicate,
}

impl Validator {
    fn parse_marker(line: &str) -> Option<Self> {
        let body = line.trim().strip_prefix("<!--")?.strip_suffix("-->")?;
        let value = body.trim().strip_prefix("validate:")?.trim();
        match value {
            "config" => Some(Self::Config),
            "route-body" => Some(Self::RouteBody),
            "phase-list" => Some(Self::PhaseList),
            "attributes" => Some(Self::Attributes),
            "fragment" => Some(Self::Fragment),
            "apl-rule" => Some(Self::AplRule),
            "apl-pipeline" => Some(Self::AplPipeline),
            "apl-predicate" => Some(Self::AplPredicate),
            _ => None,
        }
    }

    /// `Ok(())` when the block is valid, `Err(message)` when it is not.
    fn check(self, body: &str) -> Result<(), String> {
        match self {
            Self::Fragment => Ok(()),
            Self::Config => check_document(body),
            Self::RouteBody => check_document(&wrap_route_body(body, 4)),
            Self::PhaseList => check_document(&wrap_phase_list(body)),
            Self::Attributes => {
                // Parsed straight into the JSON value the merge takes; the
                // YAML reader fills either shape.
                let doc: serde_json::Value =
                    serde_yaml::from_str(body).map_err(|e| e.to_string())?;
                merge_attribute_docs([("docs example".to_owned(), doc)])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
            Self::AplRule => body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .try_for_each(|line| {
                    parse_rule(line, "docs example")
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }),
            Self::AplPipeline => parse_pipeline(body.trim())
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Self::AplPredicate => parse_predicate(body.trim())
                .map(|_| ())
                .map_err(|e| e.to_string()),
        }
    }
}

struct Block {
    line: usize,
    validator: Validator,
    body: String,
}

/// Pull the checkable fenced blocks out of one page.
///
/// Only `yaml` and `apl` fences are considered. Everything else on a page,
/// `rust`, `console`, `text`, `mermaid`, is prose this harness has no parser
/// for and no business asserting on.
fn blocks(markdown: &str) -> Vec<Block> {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut found = Vec::new();
    let mut marker: Option<Validator> = None;
    let mut open: Option<(usize, String, Vec<&str>)> = None;

    for (index, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim_start();

        if let Some((line, lang, body)) = open.take() {
            if trimmed.starts_with("```") {
                if matches!(lang.as_str(), "yaml" | "apl") {
                    found.push(Block {
                        line,
                        validator: marker.take().unwrap_or(Validator::Config),
                        body: body.join("\n"),
                    });
                }
                marker = None;
            } else {
                let mut body = body;
                body.push(raw);
                open = Some((line, lang, body));
            }
            continue;
        }

        if let Some(lang) = trimmed.strip_prefix("```") {
            open = Some((index + 1, lang.trim().to_owned(), Vec::new()));
            continue;
        }

        let candidate = raw.trim();
        if candidate.is_empty() {
            continue; // a blank line may separate a marker from its fence
        }
        // Any other content resets: a marker only binds to the next fence.
        marker = Validator::parse_marker(candidate);
    }
    found
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("read dir entry").path();
        if path.is_dir() {
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
    out.sort();
}

fn docs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .canonicalize()
        .expect("docs/ exists")
}

#[test]
fn documented_examples_are_valid() {
    let root = docs_root();
    let mut files = Vec::new();
    markdown_files(&root, &mut files);

    let mut checked = 0_usize;
    let mut failures = String::new();

    for file in &files {
        // Plans and brainstorms record what was proposed at a point in time.
        // Holding them to today's parser would make finished history fail.
        let relative = file.strip_prefix(&root).unwrap_or(file);
        if relative.starts_with("plans") || relative.starts_with("brainstorms") {
            continue;
        }

        let text = fs::read_to_string(file).expect("read markdown");
        for block in blocks(&text) {
            if block.validator == Validator::Fragment {
                continue;
            }
            checked += 1;
            if let Err(message) = block.validator.check(&block.body) {
                let _ = write!(
                    failures,
                    "\n{}:{}\n    {}\n",
                    relative.display(),
                    block.line,
                    message.replace('\n', "\n    ")
                );
            }
        }
    }

    assert!(
        failures.is_empty(),
        "documentation examples rejected by the parser that reads them:\n{failures}"
    );
    assert!(
        checked >= MINIMUM_CHECKED_BLOCKS,
        "only {checked} example blocks were checked, below the floor of \
         {MINIMUM_CHECKED_BLOCKS}; the walk or the marker convention has broken"
    );
}
