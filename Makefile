# Praxis Policy Engine — Rust workspace Makefile
# =============================================================================
# Targets mirror CI (.github/workflows/) so a green `make ci` locally means a
# green pipeline.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo

# `make release LEVEL=patch` or `make release VERSION=0.1.1`. VERSION wins.
RELEASE_ARG = $(if $(VERSION),$(VERSION),$(if $(LEVEL),$(LEVEL),patch))

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo "Praxis Policy Engine — Makefile"
	@echo ""
	@echo "Build:"
	@echo "  build             Build the workspace (debug)"
	@echo "  build-release     Build the workspace (release)"
	@echo "  check             cargo check the workspace"
	@echo "  clean             Remove the target/ directory"
	@echo ""
	@echo "Lint & format:"
	@echo "  fmt               Format Rust code (cargo fmt --all)"
	@echo "  lint              CI lint gate: fmt --check + clippy -D warnings"
	@echo "  lint-extra        Extra lint checks: typos + taplo fmt --check"
	@echo "  clippy            Run clippy on the workspace (-D warnings)"
	@echo "  lint-fix          Auto-fix: cargo fmt + clippy --fix"
	@echo "  machete           Report unused dependencies (advisory)"
	@echo ""
	@echo "Test:"
	@echo "  test              Run all workspace tests"
	@echo ""
	@echo "Supply chain & coverage:"
	@echo "  audit             cargo deny check (advisories, licenses, bans, sources)"
	@echo "  coverage          Coverage summary, gated at COVERAGE_FLOOR percent"
	@echo "  mutants           Run mutation testing (cargo-mutants)"
	@echo "  semver            Check semver compatibility (cargo-semver-checks)"
	@echo ""
	@echo "Docs:"
	@echo "  doc               cargo doc with warnings denied"
	@echo ""
	@echo "Setup:"
	@echo "  setup-hooks       Install git pre-commit hook"
	@echo ""
	@echo "CI:"
	@echo "  ci                What CI runs: lint + test"
	@echo ""
	@echo "Release:"
	@echo "  release-dry       Preview a release (no changes)"
	@echo "  release-version   Rewrite versions only; no commit, no tag"
	@echo "  release           Bump + commit + tag, then stop"
	@echo "  publish-dry       Package every publishable crate without uploading"
	@echo "  tag               Tag VERSION and push it to trigger the CI publish"

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build:
	@$(CARGO) build --workspace

.PHONY: build-release
build-release:
	@$(CARGO) build --release --workspace

.PHONY: check
check:
	@$(CARGO) check --workspace

.PHONY: clean
clean:
	@$(CARGO) clean

# =============================================================================
# Lint & format
# =============================================================================

.PHONY: fmt
fmt:
	@$(CARGO) fmt --all

.PHONY: clippy
clippy:
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

# CI-safe gate: read-only fmt check plus clippy. Lint levels come from
# [workspace.lints] in Cargo.toml.
.PHONY: lint
lint:
	@echo "fmt --check + clippy -D warnings ..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "lint passed"

.PHONY: lint-fix
lint-fix:
	@$(CARGO) fmt --all
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

# Advisory, not part of the blocking gate: machete is wrong in both directions. It
# reports macro- and derive-only crates as unused, and it misses a genuinely
# unused dependency whose name appears in a comment.
# Extra lint checks: spell checker and TOML formatting. Not part of the
# blocking CI gate; run manually or by lint-extra CI.
.PHONY: lint-extra
lint-extra:
	@command -v typos >/dev/null 2>&1 || $(CARGO) install typos-cli --locked
	@typos
	@command -v taplo >/dev/null 2>&1 || $(CARGO) install taplo-cli --locked
	@taplo fmt --check
	@echo "lint-extra passed"

.PHONY: machete
machete:
	@command -v cargo-machete >/dev/null 2>&1 || $(CARGO) install cargo-machete --locked
	@cargo machete || true

# =============================================================================
# Setup
# =============================================================================

.PHONY: setup-hooks
setup-hooks:
	@git config core.hooksPath .hooks
	@echo "pre-commit hook installed"

# =============================================================================
# Test
# =============================================================================

# Two passes. The first is what a host gets naming no features. The second is the
# only way to reach `#[cfg(feature = ...)]` test modules, and the facade's tests
# are gated that way because its `default` is empty: the bare dependency is the
# engine alone. Dropping either pass hides tests without failing.
.PHONY: test
test:
	@$(CARGO) test --workspace
	@$(CARGO) test --workspace --all-features

# =============================================================================
# Supply chain & coverage
# =============================================================================

.PHONY: audit
audit:
	@command -v cargo-deny >/dev/null 2>&1 || $(CARGO) install cargo-deny --locked
	@cargo deny check

# Minimum line coverage. Raise it, never lower it: a drop means coverage
# regressed. There is no headroom above the floor, so if a platform difference of
# a few lines turns the gate red, cover something rather than lowering it.
#
# 100 percent is not the goal. Some production lines are unreachable defensive
# guards, marked as such where they appear, and cargo-llvm-cov cannot exclude
# lines on stable.
#
# The coverage workflow calls this target rather than repeating the threshold, so
# this is the only copy of the number.
COVERAGE_FLOOR ?= 95

# `--include-ignored` reaches the Valkey integration tests, much of which needs no
# Valkey at all. `VALKEY_TESTS_OPTIONAL=1` lets them skip instead of fail, because
# this target measures and `make test` is what asserts. Set `VALKEY_TEST_URL` to
# measure the paths that do need a server.
.PHONY: coverage
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@VALKEY_TESTS_OPTIONAL=1 cargo llvm-cov --workspace --summary-only \
		--fail-under-lines $(COVERAGE_FLOOR) -- --include-ignored

# Mutation testing. Advisory, not part of the blocking CI gate.
.PHONY: mutants
mutants:
	@command -v cargo-mutants >/dev/null 2>&1 || $(CARGO) install cargo-mutants --locked
	@cargo mutants --workspace

# Semver compatibility check against the last published version.
.PHONY: semver
semver:
	@command -v cargo-semver-checks >/dev/null 2>&1 || $(CARGO) install cargo-semver-checks --locked
	@cargo semver-checks

# =============================================================================
# Docs
# =============================================================================

.PHONY: doc
doc:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps

# =============================================================================
# CI
# =============================================================================

.PHONY: ci
ci: lint test

# =============================================================================
# Release
# =============================================================================
#
# CI publishes on tag push. The local mechanics stop at the tag.

.PHONY: release-tool
release-tool:
	@command -v cargo-release >/dev/null 2>&1 || $(CARGO) install cargo-release --locked

# Preview only. cargo-release makes no changes without --execute.
.PHONY: release-dry
release-dry: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace

# Rewrite the version in [workspace.package] and [workspace.dependencies] only;
# no commit, no tag. For a manual, reviewed bump.
.PHONY: release-version
release-version: release-tool
	@$(CARGO) release version $(RELEASE_ARG) --workspace --execute --no-confirm

# Bump, commit, tag, then stop. --no-publish and --no-push enforce the
# "CI publishes on tag push" model at the CLI level as well, so the guarantee
# does not depend on release.toml being parsed as expected. Afterwards run
# `make tag` or push the tag directly.
.PHONY: release
release: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace --no-publish --no-push --execute

# Build and verify a .crate for every publishable member without uploading, the
# same check the release workflow's dry run performs. CI runs this on a clean
# checkout; --allow-dirty lets it run locally with work in progress.
.PHONY: publish-dry
publish-dry:
	@$(CARGO) package --workspace --locked --allow-dirty

# Tag the current commit and push it. The tag is what the release workflow
# triggers on. VERSION must be semver with no leading `v`.
#   make tag VERSION=0.1.0
.PHONY: tag
tag:
	@test -n "$(VERSION)" || { echo "usage: make tag VERSION=X.Y.Z[-prerelease]"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' \
		|| { echo "error: VERSION '$(VERSION)' is not semver (e.g. 0.1.0; no leading 'v')"; exit 1; }
	git tag v$(VERSION)
	git push origin v$(VERSION)
