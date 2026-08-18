//! xtask — repo-local developer tooling for the Praxis Policy Engine
//! workspace, run via `cargo run -p xtask --`.
//!
//! Subcommands:
//!   `lint-extended [diff-base]` — diff-scoped heuristic lint checks; see
//!   [`lint_extended`] for what it looks for.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "xtask is a CLI tool that prints to the terminal and reports \
              failures through its process exit code"
)]

mod lint_extended;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(subcommand) = args.next() else {
        print_usage();
        std::process::exit(1);
    };

    let passed = match subcommand.as_str() {
        "lint-extended" => run_lint_extended(args.next()),
        other => {
            eprintln!("xtask: unknown subcommand '{other}'");
            print_usage();
            false
        },
    };

    if !passed {
        std::process::exit(1);
    }
}

/// Runs `lint-extended`, folding a run error into the same non-zero-exit
/// outcome as a blocking finding: either way the check didn't pass clean.
fn run_lint_extended(diff_base: Option<String>) -> bool {
    match lint_extended::run(diff_base.as_deref()) {
        Ok(clean) => clean,
        Err(err) => {
            eprintln!("xtask: lint-extended failed: {err}");
            false
        },
    }
}

fn print_usage() {
    eprintln!("usage: cargo run -p xtask -- <subcommand>");
    eprintln!("subcommands:");
    eprintln!("  lint-extended [diff-base]   diff-scoped heuristic lint checks");
}
