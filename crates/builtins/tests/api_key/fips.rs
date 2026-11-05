// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! API-key behavior with the OpenSSL FIPS feature selected.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use praxis_policy_builtins::plugins::identity_api_key::directory::{
    DirectoryError, KeyDirectory, KeyRecord, PresentedKey,
};
use praxis_policy_builtins::plugins::identity_api_key::{CacheConfig, CachingDirectory};
use praxis_policy_core::host::{HostServices, InitExtensions};
use praxis_policy_core::{CryptoError, validate_crypto_backend};

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const KEY: &str = "sk-oai-fips-test";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn fips_api_key_allow_and_deny_follow_provider_availability() {
    let (events, _capture) = capturing();
    let provider_required = std::env::var_os("PRAXIS_REQUIRE_FIPS_PROVIDER").is_some();
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash(KEY)
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    match validate_crypto_backend() {
        Ok(()) => {
            let known = resolve_with_header(&resolver, KEY).await;
            assert!(
                denial_code(&known).is_none(),
                "a known API key must resolve with the FIPS provider available"
            );

            let unknown = resolve_with_header(&resolver, "sk-oai-unknown").await;
            assert_eq!(
                denial_code(&unknown).as_deref(),
                Some("auth.key_unknown"),
                "an unknown API key must be denied after successful hashing"
            );
        },
        Err(error) => {
            assert!(
                !provider_required,
                "the FIPS provider is required in this environment: {error}"
            );
            assert!(
                matches!(error, CryptoError::OpenSsl(_)),
                "FIPS provider failures must be returned as OpenSSL errors: {error}"
            );

            let known = resolve_with_header(&resolver, KEY).await;
            assert_eq!(
                denial_code(&known).as_deref(),
                Some("auth.directory_unavailable"),
                "an unavailable FIPS provider must fail closed for a known key"
            );
            let rendered = format!("{:?}", known.violation);
            for private in [KEY, "OpenSSL", "fips=yes"] {
                assert!(
                    !rendered.contains(private),
                    "client denial exposed {private}: {rendered}"
                );
            }
            assert_crypto_alarm(&events, "api_key_index", 1);
        },
    }
}

#[tokio::test]
async fn a_hashing_failure_skips_the_api_key_directory_and_cache() {
    assert!(
        matches!(validate_crypto_backend(), Err(CryptoError::OpenSsl(_))),
        "this test needs the FIPS provider absent; run `make test-fips-no-provider`"
    );
    let inner = Arc::new(CountingDirectory {
        calls: AtomicUsize::new(0),
    });
    let cache = CachingDirectory::new(
        inner.clone(),
        CacheConfig {
            max_entries: 10,
            max_negative_entries: 10,
            negative_ttl_secs: 60,
            ttl_secs: 60,
        },
    )
    .expect("cache fixture");
    let (events, _capture) = capturing();

    for _ in 0..2 {
        let error = cache
            .lookup(&PresentedKey::new(KEY), &InitExtensions::new())
            .await
            .expect_err("hashing must fail before lookup");
        assert!(
            matches!(&error, DirectoryError::Unavailable(message) if message == "API key hashing failed")
        );
        let rendered = error.to_string();
        for private in [KEY, "OpenSSL", "fips=yes"] {
            assert!(
                !rendered.contains(private),
                "client error exposed {private}: {rendered}"
            );
        }
        assert_eq!(cache.len(), 0, "no positive answer is cached");
        assert_eq!(cache.negative_len(), 0, "no negative answer is cached");
    }

    assert_eq!(
        inner.calls.load(Ordering::Acquire),
        0,
        "the directory must not receive the credential"
    );
    assert_crypto_alarm(&events, "api_key_cache", 2);
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn assert_crypto_alarm(events: &Events, op: &str, count: usize) {
    let alarms = events.matching("policy_crypto_failure");
    assert_eq!(alarms.len(), count, "{alarms:?}");
    for alarm in alarms {
        assert!(
            alarm.contains("[ERROR]") && alarm.contains(&format!("op={op}")),
            "{alarm}"
        );
        assert!(
            !alarm.contains(KEY),
            "the alarm must not expose the credential: {alarm}"
        );
    }
}

#[derive(Debug)]
struct CountingDirectory {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl KeyDirectory for CountingDirectory {
    fn kind(&self) -> &'static str {
        "counting"
    }

    async fn lookup(
        &self,
        _presented: &PresentedKey,
        _services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(Some(KeyRecord::default()))
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    fn matching(&self, needle: &str) -> Vec<String> {
        self.recorded()
            .into_iter()
            .filter(|event| event.contains(needle))
            .collect()
    }

    fn recorded(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

thread_local! { static SINK: RefCell<Option<Events>> = const { RefCell::new(None) }; }

struct Capture;
struct Sink;

impl Drop for Sink {
    fn drop(&mut self) {
        SINK.with_borrow_mut(|sink| *sink = None);
    }
}

struct Render(String);

impl tracing::field::Visit for Render {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!(" {}={value}", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        SINK.with_borrow(|sink| {
            if let Some(events) = sink {
                let mut render = Render(format!("[{}]", event.metadata().level()));
                event.record(&mut render);
                events
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(render.0);
            }
        });
    }

    fn exit(&self, _: &tracing::span::Id) {}

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }
}

fn capturing() -> (Events, Sink) {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(Capture).expect("one subscriber per test binary");
    });
    let events = Events::default();
    SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
    (events, Sink)
}
