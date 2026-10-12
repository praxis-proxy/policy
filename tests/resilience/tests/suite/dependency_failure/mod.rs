// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Each external dependency fails, and the full engine fails closed.
//!
//! Plugin-level error mapping is pinned in the builtin suites. A row here
//! asserts only what the full engine shows: the deny code in the host
//! outcome, no upstream call, no inbound or minted token forwarded, and an
//! elapsed bound where a fixture sets a low timeout. Each row's doc cites the
//! builtin test it builds on.
//!
//! Failures are scripted as transport errors, not latency. Latency appears
//! only where a low `plugin_timeout` is what the row asserts.

mod ciba;
mod jwks;
mod pdp;
mod session_store;
mod ssrf;
mod token_exchange;
mod vault;

use bytes::Bytes;
use praxis_policy_core::http::{HttpResponse, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::host::{Outcome, RefHost, Stage};
use praxis_policy_test_utils::secrets::Planted;

/// One way a dependency's endpoint misbehaves.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// The connection is refused.
    Connect,
    /// The deadline passes.
    Timeout,
    /// The answer is larger than the caller's ceiling.
    TooLarge,
    /// An HTTP status with a body.
    Status(u16, &'static str),
}

impl Fault {
    /// A 200 whose body is not what the caller expects.
    const fn malformed(body: &'static str) -> Self {
        Self::Status(200, body)
    }

    fn reply(self) -> Result<HttpResponse, HttpTransportError> {
        match self {
            Self::Connect => Err(HttpTransportError::Connect("refused".to_owned())),
            Self::Timeout => Err(HttpTransportError::Timeout),
            Self::TooLarge => Err(HttpTransportError::ResponseTooLarge {
                actual: 1 << 21,
                limit: 1 << 20,
            }),
            Self::Status(status, body) => Ok(HttpResponse::new(status, Bytes::from(body))),
        }
    }

    /// A transport answering every URL containing `fragment` this way. It
    /// is a responder, so it wins over the host's own.
    fn at(self, fragment: &str) -> FakeTransport {
        self.on(FakeTransport::new(), fragment)
    }

    /// Add this fault for `fragment` to `transport`.
    fn on(self, transport: FakeTransport, fragment: &str) -> FakeTransport {
        transport.respond_with(fragment, move |_| self.reply())
    }
}

/// Assert `out` denied at `stage` with `code`, the upstream saw nothing, and
/// no planted secret reached the caller or an operator.
fn assert_fail_closed(
    host: &RefHost,
    out: &Outcome,
    stage: Stage,
    code: &str,
    planted: &Planted,
    row: &str,
) {
    assert_eq!(
        out.denied_at,
        Some(stage),
        "{row}: {:?} {:?}",
        out.violation,
        out.errors
    );
    assert_eq!(
        out.violation_code(),
        Some(code),
        "{row}: {:?}",
        out.violation
    );
    assert!(out.upstream.is_none(), "{row}: the upstream was called");
    assert!(
        host.upstream().requests().is_empty(),
        "{row}: the upstream log is not empty"
    );
    out.assert_no_leaks(planted);
}
