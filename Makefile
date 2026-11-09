# Praxis Policy Engine — Rust workspace Makefile
# =============================================================================
# Targets mirror CI (.github/workflows/) so a green `make ci` locally means a
# green pipeline.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo
# A literal comma for `$(call ...)` arguments.
, := ,

# Every compatible feature for the second workspace pass, on the RustCrypto
# backend. It stands in for `--all-features`, which would also enable `fips`
# and select both mutually exclusive backends. FIPS has its own targets.
WORKSPACE_TEST_FEATURES := \
	praxis-policy-core/crypto-rustcrypto,praxis-policy-apl-cmf/crypto-rustcrypto,praxis-policy-apl-runtime/crypto-rustcrypto \
	praxis-policy-builtins/crypto-rustcrypto,praxis-policy-builtins/jwt,praxis-policy-builtins/api-key,praxis-policy-builtins/oauth,praxis-policy-builtins/basic,praxis-policy-builtins/delegator-vault,praxis-policy-builtins/elicitation-ciba,praxis-policy-builtins/experimental-quota,praxis-policy-builtins/experimental-ratelimit,praxis-policy-builtins/cedar,praxis-policy-builtins/cel,praxis-policy-builtins/opa,praxis-policy-builtins/valkey,praxis-policy-builtins/secrets-vault \
	praxis-policy/builtins,praxis-policy/http-hyper,praxis-policy/experimental-quota,praxis-policy/experimental-ratelimit \
	ppe-benches/dhat-heap \
	praxis-policy-test-utils/experimental-ratelimit \
	praxis-policy-tests-integration/experimental-ratelimit,praxis-policy-tests-resilience/experimental-ratelimit,praxis-policy-tests-security/experimental-ratelimit

# Nightly is needed only for the optional ThreadSanitizer target below.
NIGHTLY ?= nightly

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
	@echo "  check-fips-graph  Ensure FIPS graphs link OpenSSL and no other crypto"
	@echo "  check-features    cargo check each builtin feature and reference plugin"
	@echo "  check-crypto-consumer  Verify standalone backend composition and reports"
	@echo "  clean             Remove the target/ directory"
	@echo ""
	@echo "Lint & format:"
	@echo "  fmt               Format Rust code (pinned stable rustfmt)"
	@echo "  lint              CI lint gate: fmt --check + clippy -D warnings"
	@echo "  lint-extra        Extra lint checks: typos + taplo fmt --check"
	@echo "  clippy            Run clippy on the workspace (-D warnings)"
	@echo "  lint-fix          Auto-fix: cargo fmt + clippy --fix"
	@echo "  machete           Report unused dependencies (advisory)"
	@echo "  semver-facade     Facade API compatibility vs the last release"
	@echo ""
	@echo "Test:"
	@echo "  test              Run all workspace tests"
	@echo "  test-fips-no-provider  FIPS reports, refusals and fail-closed hashing"
	@echo "  test-fips-provider     FIPS lib suites against a loaded provider"
	@echo "  test-integration  Integration, resilience and security suites"
	@echo "  test-resilience   Resilience suite (dependency failure, concurrency)"
	@echo "  test-security     Security suite (adversarial inputs)"
	@echo "  test-tsan         Engine concurrency stress under ThreadSanitizer (nightly)"
	@echo "  bench-pdp-cache   PDP decision-cache hit vs miss (on demand, not CI)"
	@echo ""
	@echo "Benchmarks (on demand — not part of make ci; see docs/dev/benchmarks.md):"
	@echo "  bench             Criterion suite (ppe-benches / issue #19)"
	@echo "  bench-percentiles p50/p95/p99 from target/criterion samples"
	@echo "  bench-heap        dhat per-decision + policy-size footprint"
	@echo ""
	@echo "Supply chain & coverage:"
	@echo "  audit             cargo deny check (advisories, licenses, bans, sources)"
	@echo "  coverage          Coverage summary, gated at COVERAGE_FLOOR percent"
	@echo "  mutants           Run mutation testing (cargo-mutants)"
	@echo "  semver            Check semver compatibility (cargo-semver-checks)"
	@echo ""
	@echo "Docs:"
	@echo "  doc               cargo doc with warnings denied"
	@echo "  docs-links        Check every link under docs/ (lychee)"
	@echo "  docs-lint         Markdown style check (markdownlint, needs npx)"
	@echo ""
	@echo "Setup:"
	@echo "  setup-hooks       Install git pre-commit hook"
	@echo ""
	@echo "CI:"
	@echo "  ci                What CI runs: lint + test"
	@echo "                    (ppe-benches compiles via clippy --all-targets"
	@echo "                     plus a dhat-heap pass; make bench is on-demand)"
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

# The inner loop. Covers test and example code as well as the libraries, and
# both feature sets, because most compile errors while editing live in tests.
#
# Prefer this over `make test` while iterating. `cargo check` never links an
# executable, and on macOS with an Endpoint Security agent installed, linking and
# first-running a test binary is what costs the wall clock, not compiling it. See
# AGENTS.md, Conventions -> Tests.
.PHONY: check
check:
	@$(CARGO) check --workspace --all-targets
	@$(CARGO) check --workspace --all-targets --features "$(WORKSPACE_TEST_FEATURES)"
	@for features in $(FIPS_SELECTIONS); do \
		$(CARGO) check -p praxis-policy --no-default-features --features "$$features" --lib || exit 1; \
	done
	@$(MAKE) check-fips-graph

NON_FIPS_CRYPTO := sha2|hmac|ring|rustls|aws-lc-rs|aws-lc-sys|bcrypt|argon2|sha-crypt|password-hash
# Crates a FIPS graph may contain although they hold or call non-validated
# randomness. Each is accepted for identifiers only, never keys or secrets;
# secret material goes through `praxis_policy_core::crypto::random_bytes`.
#   uuid       trace, span and registry ids, CIBA poll owners, effect keys
#   getrandom  the OS source behind `uuid::Uuid::new_v4`
#   signature  `jsonwebtoken`'s signer and verifier traits; no algorithms
FIPS_GRAPH_ALLOWED := uuid|getrandom|signature
# Crypto crates that must be classified, as allowed or non-FIPS, before they
# can appear in a FIPS graph.
CRYPTO_PATTERN := rand|rand_core|chacha20|sha1|sha3|md-5|md5|blake2|blake3|aes|aes-gcm|p256|p384|p521|rsa|ed25519-dalek|curve25519-dalek|ecdsa|elliptic-curve|digest|signature|$(NON_FIPS_CRYPTO)|$(FIPS_GRAPH_ALLOWED)
# Every supported FIPS selection: the shared backend, with optional identity
# builtins.
FIPS_SELECTIONS := fips fips,api-key fips,jwt-openssl-fips fips,api-key,jwt-openssl-fips
# Selections a FIPS consumer must not reach for. Basic's bcrypt, argon2 and
# sha-crypt verifiers have no OpenSSL path, so no `fips` graph may carry them,
# whether `basic` is asked for directly or pulled in by another dependency.
BASIC_FIPS_REFUSED := fips,basic fips,api-key,basic

# Fail on a non-FIPS or unclassified crypto crate in the graph on stdin, and
# print the allowed crates found. `$(1)` names the graph in messages; a
# nonempty `$(2)` skips the OpenSSL requirement for a graph with no crypto.
check_fips_tree = tree="$$(cat)"; \
	if grep -Eq "^($(NON_FIPS_CRYPTO)) v" <<< "$$tree"; then \
		echo "FIPS graph for $(1) links non-FIPS crypto:" >&2; \
		grep -E "^($(NON_FIPS_CRYPTO)) v" <<< "$$tree" >&2; exit 1; \
	fi; \
	unclassified="$$(grep -E "^($(CRYPTO_PATTERN)) v" <<< "$$tree" \
		| grep -Ev "^($(NON_FIPS_CRYPTO)|$(FIPS_GRAPH_ALLOWED)) v" | sort -u || true)"; \
	if [ -n "$$unclassified" ]; then \
		echo "FIPS graph for $(1) has unclassified crypto; add it to FIPS_GRAPH_ALLOWED or NON_FIPS_CRYPTO:" >&2; \
		echo "$$unclassified" >&2; exit 1; \
	fi; \
	[ -n "$(2)" ] || grep -q '^openssl v' <<< "$$tree" || { echo "FIPS graph for $(1) is missing OpenSSL" >&2; exit 1; }; \
	echo "$(1): allowed $$(grep -Eo "^($(FIPS_GRAPH_ALLOWED)) v[^ ]*" <<< "$$tree" | sort -u | tr '\n' ' ')"

CRYPTO_CONSUMER_MANIFEST := tests/consumers/crypto/Cargo.toml
CRYPTO_CONSUMER_CARGO = CARGO_TARGET_DIR="$(abspath $(or $(CARGO_TARGET_DIR),target))" $(CARGO)

.PHONY: check-crypto-consumer
check-crypto-consumer:
	@$(CARGO) fmt --manifest-path $(CRYPTO_CONSUMER_MANIFEST) -- --check
	@$(call run_selected,$(CRYPTO_CONSUMER_CARGO) test --manifest-path $(CRYPTO_CONSUMER_MANIFEST) --locked --lib)
	@$(call run_selected,$(CRYPTO_CONSUMER_CARGO) test --manifest-path $(CRYPTO_CONSUMER_MANIFEST) --locked --features api-key --lib)
	@for features in $(FIPS_SELECTIONS); do \
		$(call run_selected,$(CRYPTO_CONSUMER_CARGO) test --manifest-path $(CRYPTO_CONSUMER_MANIFEST) --locked --no-default-features --features $$features --lib); \
	done
	@for features in crypto-rustcrypto crypto-rustcrypto,api-key $(FIPS_SELECTIONS); do \
		$(CRYPTO_CONSUMER_CARGO) clippy --manifest-path $(CRYPTO_CONSUMER_MANIFEST) \
			--locked --no-default-features --features "$$features" --all-targets -- -D warnings; \
	done
	@for features in $(FIPS_SELECTIONS); do \
		$(CRYPTO_CONSUMER_CARGO) tree --manifest-path $(CRYPTO_CONSUMER_MANIFEST) --locked \
			--no-default-features --features "$$features" -e normal,build --prefix none \
			| { $(call check_fips_tree,consumer $$features); } || exit 1; \
	done
	@for features in fips,api-key,plugin-defaults api-key fips,api-key,jwt,jwt-openssl-fips \
		crypto-rustcrypto,jwt-openssl-fips; do \
		if out="$$($(CRYPTO_CONSUMER_CARGO) check --manifest-path $(CRYPTO_CONSUMER_MANIFEST) \
			--locked --no-default-features --features "$$features" --lib 2>&1)"; then \
			echo "consumer unexpectedly built with $$features" >&2; exit 1; \
		fi; \
		echo "$$out"; \
		case "$$features" in \
			api-key) diagnostic="select a Policy crypto backend: crypto-rustcrypto or fips" ;; \
			*,jwt,jwt-openssl-fips) diagnostic="select one JWT backend" ;; \
			*rustcrypto,jwt-openssl-fips) diagnostic="jwt-openssl-fips requires the fips feature" ;; \
			*) diagnostic="select one Policy crypto backend: crypto-rustcrypto or fips" ;; \
		esac; \
		grep -Fq "$$diagnostic" <<< "$$out" || \
			{ echo "consumer failed without the expected backend diagnostic" >&2; exit 1; }; \
	done
	@echo "Standalone consumer reports, dependency graph and backend refusals passed"

.PHONY: check-fips-graph
check-fips-graph:
	@for features in $(FIPS_SELECTIONS); do \
		$(CARGO) tree -p praxis-policy --no-default-features --features "$$features" \
			-e normal,build --prefix none \
			| { $(call check_fips_tree,praxis-policy $$features); } || exit 1; \
	done
	@for features in $(filter-out fips,$(FIPS_SELECTIONS)); do \
		$(CARGO) tree -p praxis-policy-builtins --no-default-features --features "$$features" \
			-e normal,build --prefix none \
			| { $(call check_fips_tree,praxis-policy-builtins $$features); } || exit 1; \
	done
	@# Builtins with only `fips` activates no engine crate, so it has no OpenSSL.
	@$(CARGO) tree -p praxis-policy-builtins --no-default-features --features fips \
		-e normal,build --prefix none \
		| { $(call check_fips_tree,praxis-policy-builtins fips,no-openssl); }
	@# `basic` is not a FIPS selection: its password verifiers are RustCrypto
	@# only. The graph must therefore stay outside FIPS_SELECTIONS *and* be
	@# caught by the same classifier, so a later edit cannot quietly admit it.
	@for features in $(BASIC_FIPS_REFUSED); do \
		if $(CARGO) tree -p praxis-policy-builtins --no-default-features \
			--features "$$features" -e normal,build --prefix none \
			| { $(call check_fips_tree,praxis-policy-builtins $$features); } >/dev/null 2>&1; then \
			echo "praxis-policy-builtins $$features passed the FIPS graph check; basic must not" >&2; \
			exit 1; \
		fi; \
		echo "praxis-policy-builtins $$features: refused, as a non-FIPS selection"; \
	done
	@echo "FIPS graphs contain OpenSSL and no RustCrypto, ring or AWS-LC"

# FIPS tests split by provider availability. `test-fips-no-provider` runs
# where no FIPS provider is loaded: capability reports, HMAC and config
# refusals, and fail-closed hashing. `test-fips-provider` needs
# PRAXIS_REQUIRE_FIPS_PROVIDER and a loaded provider, and runs the full FIPS
# lib suites against it.
FIPS_REPORT_TEST := crypto_capability_tests::report_matches_the_expected_builtins
FIPS_LIBS := -p praxis-policy-core -p praxis-policy-apl-cmf -p praxis-policy-apl-runtime
FIPS_API_KEY_TEST := fips::fips_api_key_allow_and_deny_follow_provider_availability
FIPS_RATELIMIT_TEST := a_crypto_failure_denies_and_logs_once_per_interval
FIPS_ENGINE_TEST := crypto_capability_tests::initialize_checks_the_shared_backend_in_every_fips_selection
FIPS_API_KEY := fips,api-key
FIPS_UNSAFE_BUILTINS := oauth,delegator-vault,valkey
# Basic has no facade feature, so a consumer reaches it only through another
# dependency's edge on the builtins crate. That is the path the report has to
# cover: the builtin name and the feature spelling differ, so it cannot join
# the loop above.
FIPS_BASIC_FEATURE := praxis-policy-builtins/basic
FIPS_JWT := fips,jwt-openssl-fips
FIPS_JWT_NO_PROVIDER_TESTS := refusals::a_missing_provider_fails_with_the_shared_backend_error
FIPS_JWT_PROVIDER_TESTS := \
	verify::every_approved_algorithm_verifies_independently_signed_tokens \
	verify::rfc_jws_examples_verify \
	verify::rfc_7638_thumbprint_uses_the_fips_backend \
	verify::invalid_tokens_and_claims_are_denied \
	verify::unapproved_keys_are_refused_at_load_and_on_jwks_refresh \
	verify::jwks_rotation_picks_up_a_new_key \
	verify::dpop_binding_and_replay_hold_under_fips \
	verify::shared_secrets_and_hmac_algorithms_are_refused \
	refusals::a_non_fips_default_is_refused \
	refusals::a_conflicting_provider_is_refused \
	refusals::random_bytes_draws_from_the_fips_drbg

# Cargo succeeds when filters stop matching. Require a nonempty selection and
# optionally its expected count so a renamed test cannot disappear from a group.
run_selected = out="$$($(1) 2>&1)" || { echo "$$out"; exit 1; }; echo "$$out"; \
	if grep -q '^running 0 tests' <<< "$$out"; then \
		echo "no tests selected by: $(strip $(1))" >&2; exit 1; \
	fi; \
	if [ -n "$(2)" ] && ! grep -Eq '^running $(2) tests?$$' <<< "$$out"; then \
		echo "expected $(2) tests from: $(strip $(1))" >&2; exit 1; \
	fi

.PHONY: test-fips-capabilities
test-fips-capabilities: test-fips-no-provider

.PHONY: test-fips-no-provider
test-fips-no-provider: export OPENSSL_CONF := $(CURDIR)/.github/fips-no-provider.cnf
test-fips-no-provider:
	@if printenv PRAXIS_REQUIRE_FIPS_PROVIDER >/dev/null; then \
		echo "test-fips-no-provider needs PRAXIS_REQUIRE_FIPS_PROVIDER unset" >&2; exit 1; \
	fi
	@$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO= $(CARGO) test -p praxis-policy \
		--lib -- --exact $(FIPS_REPORT_TEST),1)
	@for features in $(FIPS_SELECTIONS); do \
		$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO= $(CARGO) test -p praxis-policy \
			--no-default-features --features $$features --lib -- --exact $(FIPS_REPORT_TEST),1); \
	done
	@$(call run_selected,$(CARGO) test -p praxis-policy --no-default-features --features fips \
		--lib -- --exact $(FIPS_ENGINE_TEST),1)
	@$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO=jwt $(CARGO) test -p praxis-policy \
		--no-default-features --features $(FIPS_API_KEY)$(,)praxis-policy-builtins/jwt --lib \
		-- --exact $(FIPS_REPORT_TEST),1)
	@$(call run_selected,$(CARGO) test -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_JWT) --test jwt_fips -- --exact $(FIPS_JWT_NO_PROVIDER_TESTS),1)
	@for builtin in $(subst $(,), ,$(FIPS_UNSAFE_BUILTINS)); do \
		$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO=$$builtin $(CARGO) test -p praxis-policy \
			--no-default-features --features $(FIPS_API_KEY)$(,)$$builtin --lib \
			-- --exact $(FIPS_REPORT_TEST),1); \
	done
	@$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO=$(FIPS_UNSAFE_BUILTINS) \
		$(CARGO) test -p praxis-policy --no-default-features \
		--features $(FIPS_API_KEY)$(,)$(FIPS_UNSAFE_BUILTINS) --lib \
		-- --exact $(FIPS_REPORT_TEST),1)
	@$(call run_selected,PPE_EXPECT_BUILTIN_CRYPTO=basic $(CARGO) test -p praxis-policy \
		--no-default-features --features $(FIPS_API_KEY)$(,)$(FIPS_BASIC_FEATURE) --lib \
		-- --exact $(FIPS_REPORT_TEST),1)
	@$(call run_selected,$(CARGO) test -p praxis-policy-core --no-default-features \
		--features fips --lib -- --exact \
		crypto::tests::hmac_is_unavailable_under_fips \
		crypto::tests::the_fips_build_reports_its_backend \
		crypto::tests::a_missing_fips_provider_fails_closed \
		engine::tests::a_missing_crypto_backend_stops_initialization \
		hooks::payload::tests::a_keyed_digest_is_omitted_under_fips \
		config::assertions_tests::fips_refuses_a_declared_provenance_key \
		config::assertions_tests::fips_refuses_provenance_without_a_key_and_offers_only_unkeyed,7)
	@$(call run_selected,$(CARGO) test -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_API_KEY) --test api_key -- --exact $(FIPS_API_KEY_TEST) \
		fips::a_hashing_failure_skips_the_api_key_directory_and_cache,2)
	@$(call run_selected,$(CARGO) test -p praxis-policy-apl-runtime --no-default-features \
		--features fips --test crypto_failure)
	@$(call run_selected,$(CARGO) test -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_API_KEY)$(,)experimental-ratelimit --test ratelimit \
		-- --exact $(FIPS_RATELIMIT_TEST),1)

.PHONY: test-fips-provider
test-fips-provider:
	@test -n "$$PRAXIS_REQUIRE_FIPS_PROVIDER" || \
		{ echo "test-fips-provider needs PRAXIS_REQUIRE_FIPS_PROVIDER and a FIPS provider" >&2; exit 1; }
	@$(CARGO) test $(FIPS_LIBS) --no-default-features --features fips --lib \
		-- --skip crypto::tests::a_missing_fips_provider_fails_closed \
		--skip engine::tests::a_missing_crypto_backend_stops_initialization
	@$(call run_selected,$(CARGO) test -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_API_KEY) --test api_key -- --exact $(FIPS_API_KEY_TEST),1)
	@$(CARGO) test -p praxis-policy -p praxis-policy-core -p praxis-policy-apl-cmf --no-default-features \
		--features $(FIPS_API_KEY) --doc
	@$(call run_selected,$(CARGO) test -p praxis-policy --no-default-features --features fips \
		--lib -- --exact $(FIPS_ENGINE_TEST),1)
	@$(call run_selected,$(CARGO) test -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_JWT) --test jwt_fips -- --exact $(FIPS_JWT_PROVIDER_TESTS),11)

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
	@$(CARGO) clippy --workspace --all-targets --features "$(WORKSPACE_TEST_FEATURES)" -- -D warnings
	@$(MAKE) clippy-fips

# The FIPS profile compiles code no RustCrypto pass sees. Linting the facade
# also lints core, CMF, runtime and builtins in that build.
.PHONY: clippy-fips
clippy-fips:
	@$(CARGO) clippy -p praxis-policy --all-targets --no-default-features \
		--features $(FIPS_API_KEY) -- -D warnings
	@$(CARGO) clippy -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_API_KEY),experimental-ratelimit --test ratelimit -- -D warnings
	@$(CARGO) clippy -p praxis-policy-builtins --no-default-features \
		--features $(FIPS_API_KEY) --test api_key -- -D warnings
	@for features in fips $(FIPS_JWT) fips,api-key,jwt-openssl-fips; do \
		$(CARGO) clippy -p praxis-policy --all-targets --no-default-features \
			--features "$$features" -- -D warnings || exit 1; \
	done
	@$(CARGO) clippy -p praxis-policy-builtins --lib --test jwt_fips --no-default-features \
		--features $(FIPS_JWT) -- -D warnings
	@$(CARGO) clippy -p praxis-policy-apl-runtime --all-targets --no-default-features \
		--features fips -- -D warnings
	@$(CARGO) clippy -p praxis-policy-core --all-targets --no-default-features \
		--features fips -- -D warnings

# CI-safe gate: read-only fmt check plus clippy. Lint levels come from
# [workspace.lints] in Cargo.toml.
.PHONY: lint
lint:
	@echo "fmt --check + clippy -D warnings ..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
# The expanded default feature set enables all builtins; a plain workspace run
# reaches only cedar, cel, and opa through `ppe-pdp-diff`.
	@$(CARGO) clippy --workspace --all-targets --features "$(WORKSPACE_TEST_FEATURES)" -- -D warnings
	@$(CARGO) clippy -p ppe-benches --all-targets --features dhat-heap -- -D warnings
	@$(MAKE) clippy-fips
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

# Two passes: Cargo defaults, then the expanded `WORKSPACE_TEST_FEATURES` set. The
# facade enables only the RustCrypto backend by default, not a builtin, so its
# builtin tests are gated on the second pass. Dropping either pass hides tests.
.PHONY: test
test:
	@$(CARGO) test --workspace
	@$(CARGO) test --workspace --features "$(WORKSPACE_TEST_FEATURES)"

# The suites under tests/. They build only with the explicit suite feature, which
# turns on their `suite` feature; `make test` runs them in its second pass. As in
# praxis, test-integration runs all three.
.PHONY: test-integration
test-integration:
	@$(CARGO) test --features experimental-ratelimit \
		-p praxis-policy-tests-integration \
		-p praxis-policy-tests-resilience \
		-p praxis-policy-tests-security

.PHONY: test-resilience
test-resilience:
	@$(CARGO) test --features experimental-ratelimit -p praxis-policy-tests-resilience

.PHONY: test-security
test-security:
	@$(CARGO) test --features experimental-ratelimit -p praxis-policy-tests-security

# ThreadSanitizer on the engine concurrency stress test. Needs nightly, a
# Linux target, and an instrumented libstd (`-Zbuild-std`). The sanitizer
# does not run on the pinned stable toolchain or on macOS. `--test-threads=1`
# keeps TSan's own reports from overlapping.
.PHONY: test-tsan
test-tsan:
	@echo "ThreadSanitizer: praxis-policy-core engine concurrency ..."
	@RUSTFLAGS="-Zsanitizer=thread" CARGO_INCREMENTAL=0 \
		$(CARGO) +$(NIGHTLY) test -Zbuild-std=std,panic_abort \
		-p praxis-policy-core --test engine_concurrency \
		--target x86_64-unknown-linux-gnu -- --test-threads=1
	@echo "test-tsan passed"

# Hit vs miss for the PDP decision cache. On demand; not part of `make ci`.
# Wall-clock numbers are recorded in docs/pdp-decision-cache.md.
.PHONY: bench-pdp-cache
bench-pdp-cache:
	@$(CARGO) bench -p praxis-policy-builtins --bench pdp_decision_cache --features cel

# =============================================================================
# Benchmarks (issue #19) — on demand, never part of `make ci`
# =============================================================================
#
# Wall-clock benches do not gate PRs: CI runners are noisy and a flaky
# p99 gate would train people to ignore failures. Workspace clippy
# --all-targets plus a dhat-heap clippy pass compile every [[bench]]
# (including heap_profile). See docs/dev/benchmarks.md.

.PHONY: bench
bench:
	@echo "Criterion suite (ppe-benches) — on demand, not a CI gate ..."
	@$(CARGO) bench -p ppe-benches
	@echo "HTML reports under target/criterion/; write-up in docs/dev/benchmarks.md"

.PHONY: bench-percentiles
bench-percentiles:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }
	@python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" \
		|| { echo "bench-percentiles requires Python 3.10+"; exit 1; }
	@python3 tools/bench_percentiles.py

.PHONY: bench-heap
bench-heap:
	@echo "dhat heap_profile (per-decision + policy-size) ..."
	@$(CARGO) bench -p ppe-benches --features dhat-heap --bench heap_profile

# =============================================================================
# Supply chain & coverage
# =============================================================================

# `cargo deny check` covers advisories against the same RustSec database that
# cargo-audit reads, and honors the reviewed exceptions in deny.toml. cargo-audit
# reads audit.toml instead, so running both meant a second ignore list that had
# to agree with the first, and without one it re-reported every accepted
# dev-only advisory.
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
COVERAGE_FLOOR ?= 96

# The expanded default feature set reaches the test targets behind `test-util`,
# without which the compiler's test scaffolding and everything it covers fall outside the floor.
#
# `--include-ignored` reaches the Valkey integration tests, much of which needs no
# Valkey at all. `VALKEY_TESTS_OPTIONAL=1` lets them skip instead of fail, because
# this target measures and `make test` is what asserts. Set `VALKEY_TEST_URL` to
# measure the paths that do need a server.
#
# Both coverage targets share these flags. A report built from a narrower run
# understates what the floor asserted.
COVERAGE_FEATURES := $(filter-out ppe-benches/dhat-heap,$(WORKSPACE_TEST_FEATURES))
COVERAGE_ARGS := --workspace --features "$(COVERAGE_FEATURES)" --exclude ppe-benches
COVERAGE_TEST_ARGS := -- --include-ignored

# `clean` first: llvm-cov merges the mappings of every instrumented binary it
# finds, so a stale one from a run with different features (or a cached target
# dir in CI) is counted a second time, inflating both the line count and the
# miss count.
.PHONY: coverage
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@cargo llvm-cov clean --workspace
	@VALKEY_TESTS_OPTIONAL=1 cargo llvm-cov $(COVERAGE_ARGS) --summary-only \
		--fail-under-lines $(COVERAGE_FLOOR) $(COVERAGE_TEST_ARGS)

# The floor plus an LCOV artifact from one test run, for CI. `--no-report`
# measures once and both `report` calls read that data, so the artifact and the
# gated number cannot diverge. LCOV comes first so a red gate still leaves a
# report to diagnose. `report` takes no feature flags; it reads the object files
# the run above built.
.PHONY: coverage-lcov
coverage-lcov:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@cargo llvm-cov clean --workspace
	@VALKEY_TESTS_OPTIONAL=1 cargo llvm-cov $(COVERAGE_ARGS) --no-report $(COVERAGE_TEST_ARGS)
	@cargo llvm-cov report --lcov --output-path lcov.info
	@cargo llvm-cov report --summary-only --fail-under-lines $(COVERAGE_FLOOR)

# Mutation testing. Advisory, not part of the blocking CI gate.
.PHONY: mutants
mutants:
	@command -v cargo-mutants >/dev/null 2>&1 || $(CARGO) install cargo-mutants --locked
	@cargo mutants --workspace

# Semver compatibility check against the last published version.
.PHONY: semver
# Facade-scoped API compatibility against the last release. The expanded default
# feature set is required, not optional: the facade enables no builtin by
# default, so a default-feature run sees no builtin re-export and passes without
# inspecting the surface this guards. Scoped to the facade deliberately — a workspace-wide run is noisy from
# the retired names and from a crate with no published baseline.
.PHONY: semver-facade
semver-facade:
	@command -v cargo-semver-checks >/dev/null 2>&1 || $(CARGO) install cargo-semver-checks --locked
	@cargo semver-checks --package praxis-policy --only-explicit-features \
		--features "crypto-rustcrypto,builtins,http-hyper,experimental-quota,experimental-ratelimit"

semver:
	@command -v cargo-semver-checks >/dev/null 2>&1 || $(CARGO) install cargo-semver-checks --locked
	@cargo semver-checks

# =============================================================================
# Docs
# =============================================================================

.PHONY: doc
doc:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps
# Second pass for the same reason as `lint`: a default-feature workspace run
# documents only the cedar, cel and opa modules, so the other six are covered
# here alone.
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --features "$(WORKSPACE_TEST_FEATURES)"

# Link and style checks for the markdown under docs/. Advisory, like
# lint-extra: neither is part of `make ci`, because both reach for a tool the
# gate does not otherwise need, and docs-links reaches the network.
#
# The examples in those pages are checked by a test, not from here:
# `crates/ppe/tests/docs_examples` loads every fenced yaml block through the
# real config parser and compiles its policy, so it runs with `make test`.
.PHONY: docs-links
docs-links:
	@command -v lychee >/dev/null 2>&1 || $(CARGO) install lychee --locked
	@lychee --config lychee.toml docs/ ./*.md
	@echo "docs-links passed"

# markdownlint is a Node tool and this is a Rust workspace, so it is used
# through npx when npx is present and skipped, loudly, when it is not.
#
# Plans, brainstorms and proposals are excluded, as they are in the examples
# test: they are dated records of what was proposed, and reformatting finished
# history to today's rules would edit the record to no benefit.
.PHONY: docs-lint
docs-lint:
	@if command -v npx >/dev/null 2>&1; then \
		npx --yes markdownlint-cli2 "docs/**/*.md" "*.md" \
			"!docs/plans/**" "!docs/brainstorms/**" "!docs/proposals/**"; \
		echo "docs-lint passed"; \
	else \
		echo "docs-lint skipped: npx not found"; \
	fi

# =============================================================================
# CI
# =============================================================================

# Compile each builtin feature alone on ordinary defaults, then each reference
# plugin as its own package. Workspace builds unify features across members, so
# only per-package checks catch a feature body that omits its own `dep:` edge,
# module-group marker or crypto backend. This is the only gate that builds a
# partial feature set.
BUILTIN_FEATURES := jwt api-key basic oauth delegator-vault elicitation-ciba \
	experimental-quota experimental-ratelimit cedar cel opa valkey secrets-vault
REFERENCE_PLUGINS := praxis-policy-plugin-audit-logger praxis-policy-plugin-ocsf-audit \
	praxis-policy-plugin-pii-scanner praxis-policy-plugin-transcript-scanner

.PHONY: check-features
check-features:
	@echo "per-feature check: praxis-policy-builtins ..."
	@$(CARGO) check -p praxis-policy-builtins --all-targets
	@for f in $(BUILTIN_FEATURES); do \
		echo "  --features $$f"; \
		$(CARGO) check -p praxis-policy-builtins --all-targets --features "$$f" || exit 1; \
	done
	@for p in $(REFERENCE_PLUGINS); do \
		echo "  -p $$p"; \
		$(CARGO) check -p $$p --all-targets || exit 1; \
	done
	@for features in $(FIPS_SELECTIONS); do \
		$(CARGO) check -p praxis-policy-builtins --lib --no-default-features --features "$$features" || exit 1; \
		$(CARGO) check -p praxis-policy --lib --no-default-features --features "$$features" || exit 1; \
	done
	@$(CARGO) check -p praxis-policy --lib --no-default-features --features crypto-rustcrypto,jwt
	@$(CARGO) check -p praxis-policy-test-utils --all-targets
	@$(CARGO) check -p praxis-policy-test-utils --all-targets --features suite
	@for p in praxis-policy-tests-integration praxis-policy-tests-resilience praxis-policy-tests-security; do \
		$(CARGO) check -p $$p --all-targets --features suite || exit 1; \
	done
	@# The one test that only exists without another feature: CIBA naming the
	@# missing `valkey` feature. Every other pass builds with it.
	@$(CARGO) test -p praxis-policy-builtins --features elicitation-ciba --lib \
		-- elicitation_ciba::factory
	@echo "check-features passed"

.PHONY: ci
ci: lint check-features test

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

# Build a .crate for every publishable member without uploading, then check
# the changed workspace together with all features. Cargo's per-package verify
# resolves sibling crate versions from crates.io, where this change is not yet
# published. The test crates are unpublished and have local-only dependencies.
# CI runs this on a clean checkout; --allow-dirty permits local work in progress.
.PHONY: publish-dry
PACKAGE_TEST_EXCLUDES = --exclude praxis-policy-test-utils \
	--exclude praxis-policy-tests-integration \
	--exclude praxis-policy-tests-resilience \
	--exclude praxis-policy-tests-security
publish-dry:
	@$(CARGO) package --workspace $(PACKAGE_TEST_EXCLUDES) --locked --allow-dirty --no-verify
	@$(CARGO) check --workspace --features "$(WORKSPACE_TEST_FEATURES)" --locked

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
