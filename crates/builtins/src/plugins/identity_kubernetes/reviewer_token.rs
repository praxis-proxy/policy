// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Serialized refreshes prevent an older read from replacing a newer token.
// Keeping the last token after a failed read avoids an auth outage.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::plugins::identity_kubernetes::config::ReviewerTokenSource;

/// Reads a token from its source.
type Reader = Arc<dyn Fn(&ReviewerTokenSource) -> Result<Zeroizing<String>, String> + Send + Sync>;

/// The token, and when the last read of it was attempted.
struct Current {
    last_attempt: Instant,
    token: Zeroizing<String>,
}

/// PPE's bearer token for the API server, re-read as its source allows.
pub(crate) struct ReviewerToken {
    current: RwLock<Current>,
    reader: Reader,
    refreshing: tokio::sync::Mutex<()>,
    source: ReviewerTokenSource,
}

impl std::fmt::Debug for ReviewerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewerToken")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl ReviewerToken {
    /// Read the token once, so a missing one stops the load.
    ///
    /// # Errors
    ///
    /// An unset variable, an unreadable file, or an empty token.
    pub(crate) fn load(source: ReviewerTokenSource) -> Result<Self, String> {
        Self::with_reader(source, Arc::new(read))
    }

    fn with_reader(source: ReviewerTokenSource, reader: Reader) -> Result<Self, String> {
        let token = reader(&source)?;
        Ok(Self {
            current: RwLock::new(Current {
                last_attempt: Instant::now(),
                token,
            }),
            reader,
            refreshing: tokio::sync::Mutex::new(()),
            source,
        })
    }

    /// The token to send now.
    pub(crate) async fn get(&self) -> Zeroizing<String> {
        let (token, last_attempt) = self.snapshot();
        let ReviewerTokenSource::File { refresh_secs, .. } = &self.source else {
            return token;
        };
        let interval = Duration::from_secs(*refresh_secs);
        if last_attempt.elapsed() < interval {
            return token;
        }

        let Ok(_refreshing) = self.refreshing.try_lock() else {
            return token;
        };
        // Another caller may have refreshed between the check and the lock.
        let (token, last_attempt) = self.snapshot();
        if last_attempt.elapsed() < interval {
            return token;
        }

        let source = self.source.clone();
        let reader = Arc::clone(&self.reader);
        let outcome = tokio::task::spawn_blocking(move || reader(&source)).await;

        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A failure counts as an attempt too, so a broken file costs one read
        // per interval rather than one per request.
        current.last_attempt = Instant::now();
        match outcome {
            Ok(Ok(fresh)) => {
                current.token = fresh.clone();
                fresh
            },
            Ok(Err(error)) => {
                tracing::warn!(%error, "reviewer token re-read failed; keeping the last one");
                current.token.clone()
            },
            Err(error) => {
                tracing::warn!(%error, "reviewer token re-read did not run; keeping the last one");
                current.token.clone()
            },
        }
    }

    /// The current token and when its last read was attempted.
    fn snapshot(&self) -> (Zeroizing<String>, Instant) {
        let current = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (current.token.clone(), current.last_attempt)
    }
}

/// Read the token from its source, trimmed of surrounding whitespace.
fn read(source: &ReviewerTokenSource) -> Result<Zeroizing<String>, String> {
    let raw = match source {
        ReviewerTokenSource::Env { name } => Zeroizing::new(
            std::env::var(name).map_err(|_unset| format!("env var '{name}' is not set"))?,
        ),
        ReviewerTokenSource::File { path, .. } => Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read '{}': {e}", path.display()))?,
        ),
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.is_empty() {
        return Err("the reviewer token is empty".to_owned());
    }
    Ok(token)
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_refreshes_never_overlap_so_a_token_cannot_roll_back() {
        let reads = Arc::new(Reads::default());
        let token = ReviewerToken::with_reader(file_source(0), reads.reader())
            .expect("the first read succeeds");

        let burst = futures::future::join_all(std::iter::repeat_with(|| token.get()).take(8)).await;

        assert_eq!(
            reads.peak.load(Ordering::SeqCst),
            1,
            "two reads ran at once, so an older one could land after a newer one"
        );
        let latest = format!("gen{}", reads.calls.load(Ordering::SeqCst) - 1);
        assert_eq!(
            token.snapshot().0.as_str(),
            latest,
            "the published token is the newest read"
        );
        assert!(
            burst.iter().all(|seen| seen.starts_with("gen")),
            "every caller gets a token while a refresh runs"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_waits_an_interval_before_trying_again() {
        let reads = Arc::new(Reads {
            fail_after_first: true,
            ..Reads::default()
        });
        let token = ReviewerToken::with_reader(file_source(3_600), reads.reader())
            .expect("the first read succeeds");
        token
            .current
            .write()
            .expect("the lock is not poisoned")
            .last_attempt = Instant::now()
            .checked_sub(Duration::from_secs(3_601))
            .expect("the clock is past one interval");

        let first = token.get().await;
        let second = token.get().await;

        assert_eq!(first.as_str(), "gen0", "a failed read keeps the last token");
        assert_eq!(second.as_str(), "gen0");
        assert_eq!(
            reads.calls.load(Ordering::SeqCst),
            2,
            "one load and one failed refresh; the next request does not read again"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Counts reads, how many run at once, and answers `gen<n>` slowly.
    #[derive(Default)]
    struct Reads {
        calls: AtomicUsize,
        fail_after_first: bool,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    impl Reads {
        fn reader(self: &Arc<Self>) -> Reader {
            let reads = Arc::clone(self);
            Arc::new(move |_source: &ReviewerTokenSource| {
                let call = reads.calls.fetch_add(1, Ordering::SeqCst);
                let now = reads.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                reads.peak.fetch_max(now, Ordering::SeqCst);
                #[allow(
                    clippy::disallowed_methods,
                    reason = "the reader runs under spawn_blocking, and the delay is what lets \
                              two reads overlap"
                )]
                std::thread::sleep(Duration::from_millis(20));
                reads.in_flight.fetch_sub(1, Ordering::SeqCst);
                if reads.fail_after_first && call > 0 {
                    return Err("unreadable".to_owned());
                }
                Ok(Zeroizing::new(format!("gen{call}")))
            })
        }
    }

    fn file_source(refresh_secs: u64) -> ReviewerTokenSource {
        ReviewerTokenSource::File {
            path: "/unused".into(),
            refresh_secs,
        }
    }
}
