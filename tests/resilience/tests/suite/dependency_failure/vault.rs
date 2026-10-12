// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Vault fails while the engine resolves a declared secret at startup.
//!
//! `docs/content/configuration.md` ("Resolution and refresh"): every
//! declared value is read during `initialize()`, and one that cannot be read
//! stops startup, since a never-resolved credential has no last-good value.
//! A failure on a later `refresh_secrets()` keeps the last-good value; the
//! reference host does not drive refresh, so that path is not a row here.
//!
//! Provider-level mapping: the unit tests in
//! `crates/builtins/src/secrets/vault/provider.rs`, such as
//! `a_login_connect_failure_is_retried`.

use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::{self, SECRET_HEADER, SECRET_NAME};
use praxis_policy_test_utils::host::RefHost;

use super::Fault;

const LOGIN_URL: &str = "https://vault.test/v1/auth/approle/login";
const KV_URL: &str = "https://vault.test/v1/secret/data/hr-mcp";

/// The `AppRole` secret id the fixture logs in with.
const SECRET_ID: &str = "approle-secret-id";

#[tokio::test]
async fn an_unreadable_secret_at_startup_refuses_to_start_and_names_it() {
    let login = |fault: Fault| fault.at(LOGIN_URL);
    let read = |fault: Fault| fixtures::vault(fault.at(KV_URL), "unused");
    let rows: [(&str, FakeTransport); 10] = [
        ("unscripted Vault", FakeTransport::new()),
        ("login connect", login(Fault::Connect)),
        ("login timeout", login(Fault::Timeout)),
        (
            "login 503",
            login(Fault::Status(503, r#"{"errors":["sealed"]}"#)),
        ),
        (
            "login 403",
            login(Fault::Status(403, r#"{"errors":["permission denied"]}"#)),
        ),
        ("login malformed", login(Fault::malformed("<html/>"))),
        ("read 404", read(Fault::Status(404, r#"{"errors":[]}"#))),
        ("read 500", read(Fault::Status(500, ""))),
        ("read oversized", read(Fault::TooLarge)),
        (
            "read without the field",
            read(Fault::malformed(r#"{"data":{"data":{"other":"x"}}}"#)),
        ),
    ];
    for (row, transport) in rows {
        let err = RefHost::builder()
            .transport(transport)
            .start(SECRET_HEADER)
            .await
            .map(|_| ())
            .expect_err(&format!("{row}: an unreadable secret stops startup"));
        let message = err.to_string();
        assert!(
            message.contains(SECRET_NAME),
            "{row}: the error names the value: {message}"
        );
        assert!(
            !message.contains(SECRET_ID),
            "{row}: the error leaks the AppRole secret id"
        );
    }
}
