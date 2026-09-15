# Import Provenance

Most of this tree did not originate here. It was imported from the engine's
previous home with its commit history intact, so `git log` and `git blame` reach
back before this repository existed.

## Snapshot

| | |
|---|---|
| Source repository | `contextforge-org/cpex` |
| Source commit | `aed0f15cda34a9b46e087e7ce337f78579146e12` |
| Extraction tool | `git-filter-repo` |
| Directives | [`tools/port-paths.txt`](../tools/port-paths.txt) |
| Commits before filtering | 256 |
| Commits after filtering | 37 |
| Files imported | 192 |

The source commit is the anchor for any later comparison between the two trees.
Recording it is this import's only obligation toward the eventual convergence
work. How the trees stay in step, and in which direction, is a decision for
that later effort, not this one.

## Second import: the Rego decision point

| | |
|---|---|
| Source commit | `fa222c48837d51e1e25799ac80989669fba8e5b1` |
| Selected | `builtins/pdps/opa/` |
| Commits before filtering | 258 |
| Commits after filtering | 1 |
| Files imported | 8 |

The Rego decision point was excluded from the first import because the
bundled-extensions crate listed it in its default feature set, with an optional
dependency on a directory that import did not carry. That stopped the workspace
from resolving at all. It is now brought in by a second pass over the same
source with the same single-pass technique, so its commit and blame survive
rather than arriving as a copy.

Verified the same way as the first import, against the source rather than by
inspection: 8 files both sides, every blob hash and mode identical, and per-file
commit counts identical.

The source commit differs from the first import's. The source repository
advanced in between, so the two imports have separate anchors. Only the decision
point's own paths were selected in the second pass, so nothing else moved with
it.

## How the import was performed

A fresh clone of the source repository was rewritten with `git-filter-repo`
driven by the directive file, with path selection and path renames applied in a
single pass. Doing the rename as a later commit would have terminated blame at
the move, which is the outcome the single pass exists to avoid.

The rewritten history was then merged here with unrelated histories allowed.
Nothing on this side was rewritten: this repository's initial commit is still
reachable.

## What was verified before the merge

The merge was gated on a mechanical comparison against the source rather than a
spot check. A sampled `git log --follow` test would have passed regardless of
correctness, because a single-pass rewrite leaves no trace of the old path
anywhere in the result, so there is no rename left to cross.

- File count identical: 192 in the source's ported paths, 192 here.
- No file missing and none unexpected under the path mapping.
- Every blob hash and file mode identical.
- Per-file commit counts identical for all 192 files.
- No excluded path present at any of the 37 commits, checked by walking every
  commit rather than only the tip.
- Full-history secret scan clean across all 37 commits.

## What is deliberately absent

Excluded from the import, and therefore absent from history rather than merely
deleted at the tip: the FFI crate, the language bindings, the out-of-process
Python plugin host, the Biscuit delegator, and the example crates. The Rego
decision point was excluded from the first import and imported by the second; see
above.

Two exclusions required code changes, not just path filtering. The
bundled-extensions crate listed the Rego decision point in its default feature
set and declared it as an optional dependency, so the feature, the dependency,
the re-export, the registration site, and the factory-count assertion that
derived its expected value from that feature were all removed. Without that the
workspace does not resolve at all.

## Import consequences

Commits do not correspond one-to-one with the source. Commits touching both
ported and excluded paths were rewritten to their ported portion, and commits
touching only excluded paths were pruned, which is why 256 became 37. Comparison
between the trees works by path and content, not by commit identity.

Imported commit messages reference the source repository's pull requests.
GitHub will autolink those numbers to unrelated numbers here. They are preserved
as written, because rewriting them would cost more traceability than the autolink
noise costs.

Package names lag the directory names. The import moved directories. Renaming
the published packages is a separate change, so for one commit the directory
names and the package names disagree.

## Test reconciliation

Reconciled on tests actually executed, not declared, against the same package set
in the source at the snapshot commit:

| | Source | Here |
|---|---|---|
| Passed | 1116 | 1116 |
| Failed | 0 | 0 |
| Ignored | 25 | 25 |

Exact match. No test was dropped, and no assertion was weakened to make the suite
pass.

### The 25 ignored tests

Recorded rather than counted as passing, because an ignored test proves nothing.
They are not one category:

- 19 are documentation examples marked as non-compiling in doc comments. They
  are illustrative, not skipped coverage.
- 6 are the session-store integration tests and are the real gap. They need a
  running service, so they never execute in a normal run:
  `cross_node_concurrent_append_unions`, `live_dispatch_then_pending`,
  `ttl_set_on_append_and_refreshed_on_load`, `unknown_session_returns_empty_ok`,
  `unreachable_endpoint_fails_closed`, `wrongtype_reply_fails_closed`.

That second group covers the session store. It makes Session Taint survive a
reload or span more than one replica. The component carrying the weakest
automated coverage is therefore the one the data-flow control depends on.
Exercise it against a real service in the acceptance demo.

## The lint seed

The gate adopted here denies a good deal that the source tree parks, including
five rustc lints where a deny is a hard compile error rather than a warning.
Shipping the gate bare would have made the imported tree impossible to build.

The bootstrap commit therefore carried a seed allow-list derived by hand from the
difference between the two configurations. That seed was incomplete: building the
imported tree surfaced four further lints Praxis denies and the source never
configured, so the source had never been compiled against them. Those were
added from the measurement rather than from another reading of the configs.

The lesson is recorded here because it will recur when the parked entries are
closed: the delta between two lint configurations is not reliably computed by
reading them. Compile and measure.

## Coverage

Measured at import: 89.98 percent lines, 90.45 regions, 86.20 functions.

The enforced floor is 89, one point below the measurement. The target is 95,
which is a project requirement rather than an inherited number. Closing that gap
means covering roughly 1,400 more lines out of about 27,900, and it is real work
rather than a configuration change.

The gate is not set to the target before the tests exist. A required check that
nobody can make green is a check people learn to ignore, which costs more than the
missing coverage does.

Two constraints apply when that work resumes. The six ignored
session-store integration tests are the largest single block of uncovered
behavior, and they need a running service rather than more test code. The
component they cover is the one Session Taint depends on, so coverage there
buys more than its line count suggests.
