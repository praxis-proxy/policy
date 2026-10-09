// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Concurrent callers on one shared host, as a gateway holds one engine.
//!
//! Each test drives one [`RefHost`] from many tasks on a multi-thread
//! [`CapturingRuntime`]. Every task checks its own outcomes against an
//! oracle built from its own sequence, and every outcome runs the leak
//! check with that caller's secrets. The runtime has one sink, so logs and
//! audit records are checked against every caller's secrets at once and
//! attributed by content: each call carries an args marker (`trace`) that
//! the upstream and the audit record both see.
//!
//! Seeded. Override with `PPE_STRESS_SEED`, `PPE_STRESS_TASKS`,
//! `PPE_STRESS_OPS` and `PPE_STRESS_WORKERS`. A failure prints the seed.
//!
//! JWKS single-flight is covered by
//! `crates/builtins/tests/jwt/jwks_url_e2e.rs`.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::capture::{self, CapturingRuntime};
use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{
    self, CibaPoll, GATEWAY_AUDIENCE, Persona, TOKEN_EXCHANGE_URL,
};
use praxis_policy_test_utils::secrets::Planted;
use serde_json::{Value, json};

const DEFAULT_SEED: u64 = 0x07a1_17ed;
const DEFAULT_TASKS: usize = 48;
const DEFAULT_OPS: usize = 6;
const DEFAULT_WORKERS: usize = 4;

/// Held on every transport call, so concurrent calls overlap.
const OVERLAP: Duration = Duration::from_millis(2);

/// The deny a tainted session's email raises.
const TAINT_DENY: &str = "session_tainted_secret";

/// The `require(role.hr)` deny on `get_compensation`.
const NOT_HR: &str = "routes.tool:get_compensation.pre_invocation[0]";

/// The `require(perm.email_send)` deny on `send_email`.
const NO_EMAIL: &str = "routes.tool:send_email.pre_invocation[0]";

/// The deny a retry raises while its approval is pending.
const PENDING: &str = "elicitation.pending";

// -----------------------------------------------------------------------------
// Knobs
// -----------------------------------------------------------------------------

/// Reject malformed overrides so stress failures remain reproducible.
fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name).ok().map_or(default, |raw| {
        raw.parse()
            .unwrap_or_else(|_| panic!("{name}={raw:?} is not a u64"))
    })
}

/// Checked conversion prevents a configured task count from silently changing.
fn env_usize(name: &str, default: usize) -> usize {
    let default = u64::try_from(default).expect("fits u64");
    usize::try_from(env_u64(name, default)).expect("fits usize")
}

#[derive(Clone, Copy, Debug)]
struct Knobs {
    seed: u64,
    tasks: usize,
    ops: usize,
    workers: usize,
}

#[expect(
    clippy::print_stderr,
    reason = "the seed is printed so a failure can be replayed"
)]
fn knobs(test: &str) -> Knobs {
    let knobs = Knobs {
        seed: env_u64("PPE_STRESS_SEED", DEFAULT_SEED),
        tasks: env_usize("PPE_STRESS_TASKS", DEFAULT_TASKS).max(2),
        ops: env_usize("PPE_STRESS_OPS", DEFAULT_OPS).max(1),
        workers: env_usize("PPE_STRESS_WORKERS", DEFAULT_WORKERS).max(2),
    };
    eprintln!(
        "{test}: seed={} tasks={} ops={} workers={}",
        knobs.seed, knobs.tasks, knobs.ops, knobs.workers
    );
    knobs
}

/// `SplitMix64`, one stream per task, so a schedule is a function of the
/// seed alone.
struct SplitMix64(u64);

impl SplitMix64 {
    /// A separate random stream per task avoids schedule-dependent choices.
    fn new(seed: u64, stream: u64) -> Self {
        Self(seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    /// The deterministic sequence keeps randomized call plans reproducible.
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A task-local choice prevents scheduling from changing planned operations.
    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// -----------------------------------------------------------------------------
// Callers
// -----------------------------------------------------------------------------

/// One principal: a demo persona, or an HR clone of Bob under its own `sub`
/// so that several callers may email.
#[derive(Clone, Debug)]
struct Caller {
    label: String,
    sub: String,
    claims: Value,
    hr: bool,
    email: bool,
}

impl Caller {
    /// Real persona claims anchor the expected authorization outcomes.
    fn persona(p: Persona) -> Self {
        Self {
            label: p.username().to_owned(),
            sub: p.sub().to_owned(),
            claims: p.claims(),
            hr: matches!(p, Persona::Bob | Persona::Eve),
            email: p == Persona::Bob,
        }
    }

    /// Unique subjects expose cross-user leaks in shared sessions.
    fn hr_clone(k: usize) -> Self {
        let label = format!("hr{k}");
        let sub = format!("c1a5e000-0000-4000-8000-{k:012}");
        let mut claims = Persona::Bob.claims();
        claims["sub"] = json!(sub);
        claims["preferred_username"] = json!(label);
        claims["email"] = json!(format!("{label}@corp.com"));
        Self {
            label,
            sub,
            claims,
            hr: true,
            email: true,
        }
    }

    /// `tool` as this caller through `hr-copilot`, under a fresh `jti`.
    fn call(&self, tool: &str) -> Call {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut claims = self.claims.clone();
        claims["jti"] = json!(format!(
            "{}-{}",
            self.label,
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Call::anonymous(tool)
            .header("x-user-token", &idp::sign(&claims))
            .header(
                "authorization",
                &format!("Bearer {}", Persona::HrCopilot.token()),
            )
    }
}

/// Bob, Eve and Alice, then `clones` HR clones.
fn callers(clones: usize) -> Vec<Caller> {
    [Persona::Bob, Persona::Eve, Persona::Alice]
        .into_iter()
        .map(Caller::persona)
        .chain((0..clones).map(Caller::hr_clone))
        .collect()
}

/// The trace marker ties reads to their audit and upstream records.
fn compensation(marker: &str) -> Value {
    json!({ "employee_id": "EMP-001234", "include_ssn": false, "trace": marker })
}

/// The trace marker identifies which caller sent an email under concurrency.
fn email(marker: &str) -> Value {
    json!({
        "to": "partner@example.com",
        "subject": "FYI",
        "body": "Quarterly planning notes, nothing sensitive here.",
        "trace": marker,
    })
}

/// The trace marker exposes cross-call approval or request mix-ups.
fn adjust(amount: i64, marker: &str) -> Value {
    json!({ "employee_id": "EMP-001234", "amount": amount, "trace": marker })
}

// -----------------------------------------------------------------------------
// Driving and checking
// -----------------------------------------------------------------------------

/// What a task's oracle expects of one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Allowed,
    Denied(&'static str),
}

/// One finished call, for the checks over the shared sink and upstream log.
#[derive(Debug)]
struct Done {
    marker: String,
    sub: String,
    allowed: bool,
    planted: Planted,
}

/// A host on the Cedar fixture whose transport holds every call open.
async fn host_with_latency(latency: Duration) -> Arc<RefHost> {
    let host = RefHost::builder()
        .transport(FakeTransport::new().with_latency(latency))
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("the cedar fixture starts");
    Arc::new(host)
}

/// The bearer the upstream received, when the `IdP` minted it.
fn minted(out: &Outcome) -> Option<String> {
    let seen = out.upstream.as_ref()?;
    let claims = seen.jwt_claims("authorization")?;
    (claims["aud"] != GATEWAY_AUDIENCE).then(|| {
        seen.headers["authorization"]
            .trim_start_matches("Bearer ")
            .to_owned()
    })
}

/// Drive `call` for `caller` and check the outcome against `expect`.
async fn drive(
    host: &RefHost,
    caller: &Caller,
    call: Call,
    marker: &str,
    expect: Expect,
    ctx: &str,
) -> (Outcome, Done) {
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    let out = host.call(call).await;
    if let Some(token) = minted(&out) {
        planted.plant("minted token", token);
    }
    match expect {
        Expect::Allowed => {
            assert!(out.allowed(), "{ctx}: {:?} {:?}", out.violation, out.errors);
            let seen = out
                .upstream
                .as_ref()
                .expect("an allowed call reaches the upstream");
            assert_eq!(
                seen.arguments["trace"], marker,
                "{ctx}: another caller's request"
            );
            assert_eq!(
                seen.headers.get("x-auth-user-id"),
                Some(&caller.sub),
                "{ctx}: asserted another caller's subject"
            );
            if let Some(claims) = seen.jwt_claims("authorization")
                && claims["aud"] != GATEWAY_AUDIENCE
            {
                assert_eq!(
                    claims["sub"], caller.sub,
                    "{ctx}: minted for another caller"
                );
            }
        },
        Expect::Denied(code) => {
            assert_eq!(
                out.denied_at,
                Some(Stage::Request),
                "{ctx}: {:?}",
                out.violation
            );
            assert_eq!(out.violation_code(), Some(code), "{ctx}");
            assert!(out.upstream.is_none(), "{ctx}: a deny reached the upstream");
        },
    }
    out.assert_no_leaks(&planted);
    let done = Done {
        marker: marker.to_owned(),
        sub: caller.sub.clone(),
        allowed: out.allowed(),
        planted,
    };
    (out, done)
}

/// Spawn every future and wait for all. A panic is re-raised with the seed
/// and the task index.
async fn join_all<F>(seed: u64, tasks: Vec<F>) -> Vec<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handles: Vec<_> = tasks.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(v) => out.push(v),
            Err(err) => {
                let payload = err.into_panic();
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "non-string panic".to_owned());
                panic!("seed={seed} task={i}: {message}");
            },
        }
    }
    out
}

/// The checks over what every caller shares: the upstream log, the logs
/// and the audit records.
///
/// - Every upstream request traces to one finished, allowed call, once,
///   and carries that caller's subject and minted token.
/// - No caller's secret reached a log or an audit record.
/// - Every audit record naming a marker names that marker's caller.
fn assert_shared_state(host: &RefHost, runtime: &CapturingRuntime, done: &[Done], seed: u64) {
    let by_marker: HashMap<&str, &Done> = done.iter().map(|d| (d.marker.as_str(), d)).collect();
    assert_eq!(
        by_marker.len(),
        done.len(),
        "seed={seed}: markers are unique"
    );

    let mut reached: HashMap<&str, usize> = HashMap::new();
    for req in host.upstream().requests() {
        let marker = req.arguments["trace"].as_str().unwrap_or_default();
        let owner = by_marker
            .get(marker)
            .unwrap_or_else(|| panic!("seed={seed}: upstream request {marker:?} has no caller"));
        assert!(
            owner.allowed,
            "seed={seed}: denied call {marker} reached the upstream"
        );
        assert_eq!(
            req.headers.get("x-auth-user-id"),
            Some(&owner.sub),
            "seed={seed}: {marker} carried another subject"
        );
        if let Some(claims) = req.jwt_claims("authorization")
            && claims["aud"] != GATEWAY_AUDIENCE
        {
            assert_eq!(
                claims["sub"], owner.sub,
                "seed={seed}: {marker} minted for another"
            );
        }
        *reached.entry(owner.marker.as_str()).or_default() += 1;
    }
    for d in done.iter().filter(|d| d.allowed) {
        assert_eq!(
            reached.get(d.marker.as_str()),
            Some(&1),
            "seed={seed}: {} reached the upstream once",
            d.marker
        );
    }

    let mut all = Planted::new();
    for d in done {
        all.extend(&d.planted);
    }
    all.assert_absent_events(runtime.events());

    let mut audited: HashMap<&str, usize> = HashMap::new();
    for record in runtime.events().audit_records() {
        let Some(marker) = record["tool_call"]["args"]["trace"].as_str() else {
            continue;
        };
        let owner = by_marker
            .get(marker)
            .unwrap_or_else(|| panic!("seed={seed}: audit record {marker:?} has no caller"));
        assert_eq!(
            record["subject"]["id"], owner.sub,
            "seed={seed}: audit record for {marker} names another subject"
        );
        *audited.entry(owner.marker.as_str()).or_default() += 1;
    }
    // Every route audits on its allow path, so an empty sink fails here.
    for d in done.iter().filter(|d| d.allowed) {
        assert_eq!(
            audited.get(d.marker.as_str()),
            Some(&1),
            "seed={seed}: {} has one audit record",
            d.marker
        );
    }
}

// -----------------------------------------------------------------------------
// Taint
// -----------------------------------------------------------------------------

/// What `caller`'s email in a session expects, given whether that caller
/// read compensation in it.
fn email_expect(caller: &Caller, tainted: bool) -> Expect {
    if !caller.email {
        Expect::Denied(NO_EMAIL)
    } else if tainted {
        Expect::Denied(TAINT_DENY)
    } else {
        Expect::Allowed
    }
}

/// Expected read access follows claims, independent of engine output.
fn read_expect(caller: &Caller) -> Expect {
    if caller.hr {
        Expect::Allowed
    } else {
        Expect::Denied(NOT_HR)
    }
}

/// AE4. Two principals interleave over the same eight session ids, each
/// reading compensation in half of them. Then both email from every
/// session at once. Each is blocked only where it read.
#[test]
fn only_the_principal_that_read_compensation_is_blocked_from_email() {
    let k = knobs("ae4");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let pair = [Caller::persona(Persona::Bob), Caller::hr_clone(0)];
        let sessions: Vec<String> = (0..8).map(|s| format!("ae4-{s}")).collect();
        let reads = |who: usize, s: usize| s % 2 == who;

        let mut tasks = Vec::new();
        for (who, caller) in pair.iter().enumerate() {
            for (s, session) in sessions.iter().enumerate().filter(|(s, _)| reads(who, *s)) {
                let (host, caller, session) = (Arc::clone(&host), caller.clone(), session.clone());
                tasks.push(async move {
                    let marker = format!("ae4-read-{}-{s}", caller.label);
                    let call = caller
                        .call("get_compensation")
                        .args(compensation(&marker))
                        .session(&session);
                    drive(&host, &caller, call, &marker, Expect::Allowed, &marker)
                        .await
                        .1
                });
            }
        }
        let mut done = join_all(k.seed, tasks).await;

        let mut emails = Vec::new();
        for (who, caller) in pair.iter().enumerate() {
            for (s, session) in sessions.iter().enumerate() {
                let (host, caller, session) = (Arc::clone(&host), caller.clone(), session.clone());
                let expect = email_expect(&caller, reads(who, s));
                emails.push(async move {
                    let marker = format!("ae4-email-{}-{s}", caller.label);
                    let call = caller
                        .call("send_email")
                        .args(email(&marker))
                        .session(&session);
                    drive(&host, &caller, call, &marker, expect, &marker)
                        .await
                        .1
                });
            }
        }
        done.extend(join_all(k.seed, emails).await);

        let blocked: Vec<&str> = done
            .iter()
            .filter(|d| d.marker.contains("-email-") && !d.allowed)
            .map(|d| d.marker.as_str())
            .collect();
        assert_eq!(
            blocked.len(),
            8,
            "each principal is blocked in its four: {blocked:?}"
        );
        assert_shared_state(&host, &runtime, &done, k.seed);
    });
}

/// Every caller under the same session id at once. Each reader taints only
/// its own view of the session; the others still email.
#[test]
fn one_session_id_under_many_subjects_stays_isolated() {
    let k = knobs("shared-session");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let mut rng = SplitMix64::new(k.seed, 0x5e55);
        let tasks: Vec<_> = callers(k.tasks.saturating_sub(3))
            .into_iter()
            // Eve always reads, so her taint is there for Bob not to see.
            .map(|c| {
                let reads = c.label == "eve" || (c.label != "bob" && rng.coin());
                (c, reads)
            })
            .map(|(caller, reads)| {
                let host = Arc::clone(&host);
                async move {
                    let session = "shared-1";
                    let mut done = Vec::new();
                    if reads {
                        let marker = format!("shared-read-{}", caller.label);
                        let call = caller.call("get_compensation").args(compensation(&marker));
                        let call = call.session(session);
                        let expect = read_expect(&caller);
                        let (_, d) = drive(&host, &caller, call, &marker, expect, &marker).await;
                        done.push(d);
                    }
                    let marker = format!("shared-email-{}", caller.label);
                    let call = caller.call("send_email").args(email(&marker)).session(session);
                    let expect = email_expect(&caller, reads && caller.hr);
                    let (_, d) = drive(&host, &caller, call, &marker, expect, &marker).await;
                    done.push(d);
                    done
                }
            })
            .collect();
        let done: Vec<Done> = join_all(k.seed, tasks)
            .await
            .into_iter()
            .flatten()
            .collect();
        let bob = done
            .iter()
            .find(|d| d.marker == "shared-email-bob")
            .expect("bob emailed");
        assert!(bob.allowed, "seed={}: Eve's taint reached Bob", k.seed);
        assert_shared_state(&host, &runtime, &done, k.seed);
    });
}

/// Seeded random sequences of reads and emails. Task `i` owns one
/// (caller, session) pair: callers repeat across sessions and every
/// session id is shared by all callers.
#[test]
fn random_interleaving_matches_each_tasks_own_oracle() {
    let k = knobs("interleaving");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let callers = callers(3);
        let tasks: Vec<_> = (0..k.tasks)
            .map(|i| {
                let host = Arc::clone(&host);
                let caller = callers[i % callers.len()].clone();
                let session = format!("mix-{}", i / callers.len());
                let mut rng = SplitMix64::new(k.seed, i as u64);
                let ops: Vec<bool> = std::iter::repeat_with(|| rng.coin()).take(k.ops).collect();
                async move {
                    let mut tainted = false;
                    let mut done = Vec::new();
                    for (n, read) in ops.into_iter().enumerate() {
                        let marker = format!("mix-{i}-{n}");
                        let ctx = format!("task {i} op {n} ({} in {session})", caller.label);
                        let (call, expect) = if read {
                            let call = caller.call("get_compensation").args(compensation(&marker));
                            (call, read_expect(&caller))
                        } else {
                            let call = caller.call("send_email").args(email(&marker));
                            (call, email_expect(&caller, tainted))
                        };
                        let (_, d) = drive(
                            &host,
                            &caller,
                            call.session(&session),
                            &marker,
                            expect,
                            &ctx,
                        )
                        .await;
                        tainted |= read && d.allowed;
                        done.push(d);
                    }
                    done
                }
            })
            .collect();
        let done: Vec<Done> = join_all(k.seed, tasks)
            .await
            .into_iter()
            .flatten()
            .collect();
        assert_shared_state(&host, &runtime, &done, k.seed);
    });
}

// -----------------------------------------------------------------------------
// Delegation
// -----------------------------------------------------------------------------

/// Many users exchange at once. Each upstream request carries a token
/// minted for its own caller, which `drive` and the shared check both
/// assert, and the token endpoint saw one exchange per read, so no mint was
/// shared.
#[test]
fn concurrent_delegation_mints_for_each_caller() {
    let k = knobs("delegation");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let callers: Vec<Caller> = callers(k.tasks).into_iter().filter(|c| c.hr).collect();
        let tasks: Vec<_> = callers
            .iter()
            .enumerate()
            .map(|(i, caller)| {
                let (host, caller) = (Arc::clone(&host), caller.clone());
                async move {
                    let marker = format!("delegate-{i}");
                    let call = caller
                        .call("get_compensation")
                        .args(compensation(&marker))
                        .session(&format!("delegate-{i}"));
                    let (out, d) =
                        drive(&host, &caller, call, &marker, Expect::Allowed, &marker).await;
                    assert!(
                        minted(&out).is_some(),
                        "{marker}: no minted token reached the upstream"
                    );
                    d
                }
            })
            .collect();
        let done = join_all(k.seed, tasks).await;
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            callers.len(),
            "seed={}: one exchange per read",
            k.seed
        );
        assert_shared_state(&host, &runtime, &done, k.seed);
    });
}

// -----------------------------------------------------------------------------
// CIBA
// -----------------------------------------------------------------------------

/// Several HR callers suspend on an approval at once. Approving one id
/// lets only that caller apply. The rest stay pending and never reach the
/// upstream.
#[test]
fn approving_one_elicitation_leaves_the_others_pending() {
    let k = knobs("ciba");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let callers: Vec<Caller> = (0..8).map(Caller::hr_clone).collect();
        let amount = |i: usize| 11_000 + i64::try_from(i).expect("small") * 1_000;
        let marker = |i: usize| format!("ciba-{i}");

        let suspends: Vec<_> = callers
            .iter()
            .enumerate()
            .map(|(i, caller)| {
                let (host, caller) = (Arc::clone(&host), caller.clone());
                async move {
                    let m = marker(i);
                    let call = caller
                        .call("adjust_compensation")
                        .args(adjust(amount(i), &m));
                    let (out, d) =
                        drive(&host, &caller, call, &m, Expect::Denied(PENDING), &m).await;
                    let id = out
                        .detail("elicitation_id")
                        .and_then(Value::as_str)
                        .expect("an id");
                    (id.to_owned(), d)
                }
            })
            .collect();
        let suspended = join_all(k.seed, suspends).await;
        let ids: Vec<String> = suspended.iter().map(|(id, _)| id.clone()).collect();
        let mut issued = host.ciba().auth_req_ids();
        issued.sort();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted, issued,
            "one distinct auth_req_id per suspended call"
        );

        host.ciba().set_for(
            &ids[0],
            CibaPoll::Approved {
                approver: "alice".to_owned(),
            },
        );

        let retries: Vec<_> = callers
            .iter()
            .enumerate()
            .map(|(i, caller)| {
                let (host, caller, id) = (Arc::clone(&host), caller.clone(), ids[i].clone());
                async move {
                    let (m, ctx) = (marker(i), format!("{}-retry", marker(i)));
                    let call = caller
                        .call("adjust_compensation")
                        .args(adjust(amount(i), &m))
                        .elicitation_id(&id);
                    let expect = if i == 0 {
                        Expect::Allowed
                    } else {
                        Expect::Denied(PENDING)
                    };
                    let (out, d) = drive(&host, &caller, call, &m, expect, &ctx).await;
                    if i > 0 {
                        assert_eq!(out.detail("elicitation_id"), Some(&json!(id)), "{ctx}");
                    }
                    d
                }
            })
            .collect();
        let retried = join_all(k.seed, retries).await;
        for i in 0..callers.len() {
            let seen = host
                .upstream()
                .requests()
                .into_iter()
                .filter(|r| r.arguments["trace"] == marker(i))
                .count();
            assert_eq!(seen, usize::from(i == 0), "ciba-{i}: upstream count");
        }

        // The suspends share the retries' markers, so they join only the
        // leak check.
        let mut all = Planted::new();
        for (_, d) in &suspended {
            all.extend(&d.planted);
        }
        all.assert_absent_events(runtime.events());
        assert_shared_state(&host, &runtime, &retried, k.seed);
    });
}

/// An approved id echoed by another principal with the same manager and
/// exact args remains bound to its original requester.
#[test]
fn an_approval_is_bound_to_its_requester() {
    let k = knobs("ciba-requester");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(OVERLAP).await;
        let (owner, other) = (Caller::hr_clone(0), Caller::hr_clone(1));
        let args = adjust(20_000, "ciba-owner");
        let call = owner.call("adjust_compensation").args(args.clone());
        let (out, _) = drive(
            &host,
            &owner,
            call,
            "ciba-owner",
            Expect::Denied(PENDING),
            "owner",
        )
        .await;
        let id = out
            .detail("elicitation_id")
            .and_then(Value::as_str)
            .expect("an id")
            .to_owned();
        host.ciba().set_for(
            &id,
            CibaPoll::Approved {
                approver: "alice".to_owned(),
            },
        );

        let call = other
            .call("adjust_compensation")
            .args(args)
            .elicitation_id(&id);
        let mut planted = call.planted();
        planted.plant("client secret", CLIENT_SECRET);
        let out = host.call(call).await;
        out.assert_no_leaks(&planted);
        assert_eq!(
            out.violation_code(),
            Some("elicitation.binding_mismatch"),
            "{} applied {}'s approval",
            other.label,
            owner.label
        );
        assert!(out.upstream.is_none(), "the upstream was not called");
        assert!(host.upstream().requests().is_empty());
    });
}

// -----------------------------------------------------------------------------
// Latency
// -----------------------------------------------------------------------------

/// The index of the p-th percentile in `n` sorted samples, nearest rank.
fn percentile_index(n: usize, p: usize) -> usize {
    (n * p).div_ceil(100).saturating_sub(1)
}

/// A regression guard against serialized dependency calls, such as a lock
/// held across a token exchange. With every dependency call held for a fixed
/// latency, concurrent reads must overlap at the transport. Timing against a
/// baseline is printed but not asserted: on a shared CI runner it measures
/// the machine, not the engine.
#[test]
#[expect(clippy::print_stderr, reason = "the measured times explain a failure")]
fn concurrent_reads_overlap_their_dependency_calls() {
    const LATENCY: Duration = Duration::from_millis(100);
    /// Two concurrent dependency calls distinguish overlap from a lock held
    /// across I/O, which yields exactly one even on a busy runner.
    const MIN_OVERLAP: usize = 2;
    const TASKS: usize = 32;
    const CALLS_PER_TASK: usize = 3;
    let k = knobs("latency");
    let runtime = capture::multi_thread(k.workers);
    runtime.block_on(async {
        let host = host_with_latency(LATENCY).await;
        let callers: Vec<Caller> = (0..TASKS).map(Caller::hr_clone).collect();
        let read = |host: Arc<RefHost>, caller: Caller, marker: String| async move {
            let call = caller
                .call("get_compensation")
                .args(compensation(&marker))
                .session(&marker);
            let start = Instant::now();
            let (_, d) = drive(&host, &caller, call, &marker, Expect::Allowed, &marker).await;
            (start.elapsed(), d)
        };

        let mut done = Vec::new();
        let mut alone = Vec::new();
        for n in 0..12 {
            let (took, d) = read(Arc::clone(&host), callers[0].clone(), format!("alone-{n}")).await;
            // The first few warm the JWKS and the session store.
            if n >= 3 {
                alone.push(took);
            }
            done.push(d);
        }
        alone.sort();
        let baseline = alone[alone.len() / 2];

        let tasks: Vec<_> = callers
            .iter()
            .enumerate()
            .map(|(i, caller)| {
                let (host, caller) = (Arc::clone(&host), caller.clone());
                async move {
                    let mut out = Vec::new();
                    for n in 0..CALLS_PER_TASK {
                        out.push(
                            read(Arc::clone(&host), caller.clone(), format!("load-{i}-{n}")).await,
                        );
                    }
                    out
                }
            })
            .collect();
        let mut times = Vec::new();
        for (took, d) in join_all(k.seed, tasks).await.into_iter().flatten() {
            times.push(took);
            done.push(d);
        }
        times.sort();
        let p99 = times[percentile_index(times.len(), 99)];
        eprintln!(
            "latency: baseline={baseline:?} p50={:?} p99={p99:?} over {} calls",
            times[percentile_index(times.len(), 50)],
            times.len()
        );
        let peak = host.transport().peak_in_flight();
        eprintln!("latency: peak in-flight dependency calls={peak}");
        assert!(
            peak >= MIN_OVERLAP,
            "seed={}: at most {peak} dependency calls overlapped; they look serialized",
            k.seed
        );
        assert_shared_state(&host, &runtime, &done, k.seed);
    });
}
