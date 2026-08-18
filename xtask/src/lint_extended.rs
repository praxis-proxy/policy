//! Extended lint: diff-scoped heuristic checks for common low-quality-code
//! patterns that automated compiler lints can't catch structurally.
//!
//! Clippy already denies the machine-checkable half of this class of issue
//! (unwrap/expect, panic, todo!()/unimplemented!(), `dead_code`,
//! `missing_docs`, print/dbg macros, and more, depending on the crate's own
//! lint config).
//! What lint tooling structurally cannot check is comment *content* and
//! diff-local *repetition* -- two common low-effort-code tells. This checks
//! only lines added/changed versus the diff base so pre-existing code is
//! never relitigated.
//!
//! Checks (Block = fails; Warn = printed, does not fail):
//!   - Block: leftover TODO/FIXME/XXX/HACK markers in comments
//!   - Block: commented-out code
//!   - Warn: narrating "what the code does" comments
//!   - Warn: the same numeric/string literal repeated 3+ times without a
//!     named constant
//!   - Warn: weak/generic identifier names introduced by a new let/fn binding
//!   - Warn: new clippy lint suppressions added
//!
//! Diff base resolution: CLI arg, else `$EXTENDED_LINT_BASE`, else
//! `origin/$GITHUB_BASE_REF` in a `GitHub` Actions PR, else `origin/main`.

use std::collections::{HashMap, HashSet};
use std::process::Command;

use regex::Regex;

/// Errors from running the check itself, as opposed to findings the check
/// reports about the diff (which are not errors -- see [`run`]'s `Ok(false)`).
#[derive(Debug, thiserror::Error)]
pub(crate) enum LintExtendedError {
    /// A pattern below failed to compile. Every pattern is a fixed string
    /// literal, so this only fires if one was mistyped.
    #[error("failed to compile pattern: {0}")]
    Pattern(#[from] regex::Error),
    /// `git diff` could not be spawned or its output read.
    #[error("failed to run git diff: {0}")]
    GitDiff(#[from] std::io::Error),
}

/// Patterns used across one check run. Compiled once per [`run`] call rather
/// than cached in statics: the check runs once per process invocation, so
/// there is nothing to amortize by keeping them around longer.
struct Patterns {
    todo_marker: Regex,
    commented_code: Regex,
    weak_name: Regex,
    lit: Regex,
    const_line: Regex,
    suppression: Regex,
    test_module: Regex,
    hunk: Regex,
}

impl Patterns {
    fn compile() -> Result<Self, LintExtendedError> {
        Ok(Self {
            todo_marker: Regex::new(r"(?i)//.*\b(TODO|FIXME|XXX|HACK)\b")?,
            commented_code: Regex::new(
                r"^//+\s*(let\s+\w|fn\s+\w|if\s*\(|for\s*\(|match\s+\w|return\b|\w+\s*\([^)]*\)\s*;?\s*$|\w+\.\w+\(.*\)\s*;?\s*$|[\w:<>]+\s*=\s*.+;\s*$)",
            )?,
            weak_name: Regex::new(
                r"^(let(?:\s+mut)?|fn)\s+(temp|tmp|foo|bar|thing|val|obj|stuff)\b",
            )?,
            lit: Regex::new(r#"(?:^|[^\w.])(\d{2,}|"[^"]{4,}")(?:$|[^\w])"#)?,
            const_line: Regex::new(r"\b(const|static)\s+\w+")?,
            suppression: Regex::new(r"#\[(allow|expect)\(clippy::")?,
            test_module: Regex::new(r"^(#\[cfg\(test\)\]|mod tests\b)")?,
            hunk: Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)")?,
        })
    }
}

const NARRATING_OPENERS: &[&str] = &[
    "increment",
    "decrement",
    "loop through",
    "iterate over",
    "iterate through",
    "return the",
    "returns the",
    "create a",
    "creates a",
    "initialize",
    "set the",
    "sets the",
    "get the",
    "gets the",
    "parse the",
    "parses the",
    "convert ",
    "converts ",
    "check if",
    "checks if",
    "validate that",
    "validates that",
    "call ",
    "calls ",
    "define ",
    "defines ",
    "import ",
    "imports ",
    "declare ",
    "declares ",
    "instantiate",
    "loop over",
    "append ",
    "appends ",
    "remove ",
    "removes ",
    "add ",
    "adds ",
];

struct AddedLine {
    file: String,
    lineno: usize,
    content: String,
}

fn resolve_diff_base(cli_arg: Option<&str>) -> String {
    if let Some(base) = cli_arg {
        return base.to_owned();
    }
    if let Ok(base) = std::env::var("EXTENDED_LINT_BASE") {
        return base;
    }
    if let Ok(base_ref) = std::env::var("GITHUB_BASE_REF") {
        return format!("origin/{base_ref}");
    }
    "origin/main".to_owned()
}

/// This module's own doc comment and test fixtures spell out the literal
/// marker words and comment shapes the checks below look for, so a diff that
/// touches this file trips its own heuristics on lines that are examples, not
/// violations. Unlike the rest of the workspace this file cannot be written
/// to dodge that: the words and shapes *are* the spec. Excluded from the scan
/// pathspec for that reason -- everything else under `xtask/` still gets
/// checked normally.
const SELF_EXCLUDED_PATH: &str = "xtask/src/lint_extended.rs";

fn run_diff(diff_base: &str, hunk_re: &Regex) -> Result<Vec<AddedLine>, LintExtendedError> {
    let exclude_self = format!(":(exclude){SELF_EXCLUDED_PATH}");
    let output = Command::new("git")
        .args([
            "diff",
            "--unified=0",
            diff_base,
            "--",
            "*.rs",
            &exclude_self,
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut added = Vec::new();
    let mut current_file = String::new();
    let mut new_lineno: usize = 0;

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            current_file = path.to_owned();
            continue;
        }
        if let Some(caps) = hunk_re.captures(line) {
            new_lineno = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or_default();
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(content) = line.strip_prefix('+') {
            added.push(AddedLine {
                file: current_file.clone(),
                lineno: new_lineno,
                content: content.to_owned(),
            });
            new_lineno += 1;
        } else if !line.starts_with('-') {
            new_lineno += 1;
        }
    }
    Ok(added)
}

fn test_module_start_line(file: &str, test_module_re: &Regex) -> usize {
    let Ok(text) = std::fs::read_to_string(file) else {
        return usize::MAX;
    };
    for (i, line) in text.lines().enumerate() {
        if test_module_re.is_match(line) {
            return i + 1;
        }
    }
    usize::MAX
}

/// Runs the check.
///
/// # Errors
///
/// Returns an error if a pattern fails to compile (it won't -- see
/// [`Patterns::compile`]) or if `git diff` can't be spawned or read.
pub(crate) fn run(cli_arg: Option<&str>) -> Result<bool, LintExtendedError> {
    let patterns = Patterns::compile()?;
    let diff_base = resolve_diff_base(cli_arg);
    let added = run_diff(&diff_base, &patterns.hunk)?;
    if added.is_empty() {
        println!("[extended-lint] no added Rust lines vs {diff_base}; nothing to check.");
        return Ok(true);
    }

    let mut blocking = Vec::new();
    let mut warnings = Vec::new();
    let mut literal_sites: HashMap<(String, String), Vec<(String, usize)>> = HashMap::new();
    let mut const_declared: HashMap<String, HashSet<String>> = HashMap::new();

    for line in &added {
        let stripped = line.content.trim();
        let comment_text = line
            .content
            .find("//")
            .and_then(|i| line.content.get(i..))
            .map(str::trim)
            .unwrap_or_default();

        if !comment_text.is_empty() && patterns.todo_marker.is_match(comment_text) {
            blocking.push(format!(
                "{}:{}: leftover TODO/FIXME/XXX/HACK marker: {stripped:?}",
                line.file, line.lineno
            ));
        }

        if !comment_text.is_empty()
            && !comment_text.starts_with("///")
            && !comment_text.starts_with("//!")
            && patterns.commented_code.is_match(comment_text)
        {
            blocking.push(format!(
                "{}:{}: looks like commented-out code: {stripped:?}",
                line.file, line.lineno
            ));
        }

        if comment_text.starts_with("//")
            && !comment_text.starts_with("///")
            && !comment_text.starts_with("//!")
        {
            let body = comment_text.trim_start_matches('/').trim().to_lowercase();
            if NARRATING_OPENERS
                .iter()
                .any(|opener| body.starts_with(opener))
            {
                warnings.push(format!(
                    "{}:{}: narrating 'what' comment, prefer self-explanatory code or a doc comment on why: {stripped:?}",
                    line.file, line.lineno
                ));
            }
        }

        if let Some(caps) = patterns.weak_name.captures(stripped) {
            let weak_name = caps.get(2).map_or("", |m| m.as_str());
            warnings.push(format!(
                "{}:{}: weak/generic identifier name {weak_name:?}: {stripped:?}",
                line.file, line.lineno
            ));
        }

        if patterns.suppression.is_match(stripped) {
            warnings.push(format!(
                "{}:{}: new clippy suppression added, double-check the reason: {stripped:?}",
                line.file, line.lineno
            ));
        }

        if patterns.const_line.is_match(stripped) {
            for caps in patterns.lit.captures_iter(stripped) {
                if let Some(m) = caps.get(1) {
                    const_declared
                        .entry(line.file.clone())
                        .or_default()
                        .insert(m.as_str().to_owned());
                }
            }
        }

        if line.lineno < test_module_start_line(&line.file, &patterns.test_module)
            && !stripped.starts_with("#[")
        {
            for caps in patterns.lit.captures_iter(stripped) {
                if let Some(m) = caps.get(1) {
                    literal_sites
                        .entry((line.file.clone(), m.as_str().to_owned()))
                        .or_default()
                        .push((stripped.to_owned(), line.lineno));
                }
            }
        }
    }

    for ((file, literal), sites) in &literal_sites {
        let declared = const_declared
            .get(file)
            .is_some_and(|s| s.contains(literal));
        if sites.len() >= 3 && !declared {
            let lines: Vec<String> = sites.iter().map(|(_, l)| l.to_string()).collect();
            warnings.push(format!(
                "{file}: literal {literal} repeated {}x at lines {} without a named constant -- consider hoisting it",
                sites.len(),
                lines.join(", ")
            ));
        }
    }

    if !warnings.is_empty() {
        eprintln!("[extended-lint] warnings (review, does not block):");
        for w in &warnings {
            eprintln!("  - {w}");
        }
        eprintln!();
    }

    if !blocking.is_empty() {
        eprintln!("[extended-lint] BLOCKING findings:");
        for b in &blocking {
            eprintln!("  - {b}");
        }
        eprintln!();
        eprintln!(
            "[extended-lint] fix the above, or if a match is a false positive, note why in the PR description."
        );
        return Ok(false);
    }

    eprintln!("[extended-lint] no blocking findings.");
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn detects_todo_marker() {
        let patterns = Patterns::compile().unwrap();
        assert!(
            patterns.todo_marker.is_match("// TODO: fix this later"),
            "should flag a TODO marker in a comment"
        );
        assert!(
            !patterns.todo_marker.is_match("// this is fine"),
            "should not flag a comment without a marker"
        );
    }

    #[test]
    fn detects_commented_out_code_but_not_doc_comments() {
        let patterns = Patterns::compile().unwrap();
        assert!(
            patterns.commented_code.is_match("// let x = compute();"),
            "should flag a commented-out let binding"
        );
        assert!(
            !patterns
                .commented_code
                .is_match("/// Returns the computed value."),
            "should not flag a doc comment"
        );
    }

    #[test]
    fn detects_weak_names() {
        let patterns = Patterns::compile().unwrap();
        let caps = patterns.weak_name.captures("let temp = 5;").unwrap();
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("temp"));
        assert!(
            patterns.weak_name.captures("let value = 5;").is_none(),
            "should not flag a descriptive identifier"
        );
    }

    #[test]
    fn detects_narrating_comment_openers() {
        assert!(
            NARRATING_OPENERS
                .iter()
                .any(|o| "increment the counter by one".starts_with(o)),
            "should recognize a narrating opener"
        );
        assert!(
            !NARRATING_OPENERS
                .iter()
                .any(|o| "guards against a torn write".starts_with(o)),
            "should not flag a why-focused comment"
        );
    }
}
