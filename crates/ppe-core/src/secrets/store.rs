// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Resolved values, the handles consumers hold, and refresh.
//
// A store exists only in the resolved state: `resolve` either returns one with
// every declared value read, or it returns the failure. There is no partially
// populated store and no "not yet" a consumer has to handle, which is what
// makes a read on the request path infallible and synchronous.
//
// Consumers hold a `SecretRef`, not a value. Refresh replaces what the ref
// points at, so a consumer that keeps the ref sees rotation and one that copies
// the value out at startup does not. That asymmetry is the single hazard in
// this module: copying compiles, passes every test with a static secret, and
// silently never rotates in production.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::config::SecretsConfig;
use super::error::{SecretError, SecretResolveError};
use super::provider::{SecretProvider, SecretProviderRegistry};

/// One value and the count of times it has changed.
struct CellState {
    value: Zeroizing<String>,
    generation: u64,
}

/// The shared location a [`SecretRef`] points at.
struct SecretCell {
    state: ArcSwap<CellState>,
}

impl SecretCell {
    fn new(value: Zeroizing<String>) -> Self {
        Self {
            state: ArcSwap::from_pointee(CellState {
                value,
                generation: 0,
            }),
        }
    }

    /// Replace the value, reporting whether it differs from what was there.
    ///
    /// The generation moves only on a change, never on a successful read of
    /// the same bytes. A consumer that reconnects on a generation change would
    /// otherwise reconnect once per refresh interval forever.
    fn replace_if_changed(&self, value: Zeroizing<String>) -> bool {
        let current = self.state.load();
        if current.value.as_str() == value.as_str() {
            return false;
        }
        self.state.store(Arc::new(CellState {
            value,
            generation: current.generation + 1,
        }));
        true
    }
}

/// A handle to one declared value.
///
/// Reads go through the handle, so the holder sees whatever the last refresh
/// wrote. Hold the `SecretRef`; do not call [`SecretRef::get`] once at startup
/// and keep what it returned.
#[derive(Clone)]
pub struct SecretRef {
    cell: Arc<SecretCell>,
}

impl SecretRef {
    /// The current value.
    ///
    /// Returns an owned copy rather than a borrow so there is no guard to hold
    /// across an await, and so the call reads as "what is it now" at every use
    /// rather than as a one-time fetch.
    #[must_use]
    pub fn get(&self) -> Zeroizing<String> {
        self.cell.state.load().value.clone()
    }

    /// How many times the value has changed since startup.
    ///
    /// For a consumer that has to act on rotation rather than just read the
    /// new bytes: a connection pool authenticated when it connected, so a new
    /// password reaches it only when it reconnects. Record the generation
    /// alongside whatever was built from the value, and rebuild when it moves.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.cell.state.load().generation
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRef")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

/// One declared value: where it came from and where it lives now.
struct Binding {
    provider_name: String,
    provider: Arc<dyn SecretProvider>,
    reference: String,
    cell: Arc<SecretCell>,
}

/// What one refresh did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    /// Values whose bytes changed, by name.
    pub updated: Vec<String>,
    /// How many values were read successfully and were unchanged.
    pub unchanged: usize,
    /// Values that could not be re-read. Each keeps its last-good value.
    pub failed: Vec<SecretResolveError>,
}

impl RefreshReport {
    /// Whether every value was re-read successfully.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Every declared value, resolved.
pub struct SecretStore {
    values: HashMap<String, Binding>,
    /// When each provider last re-read all of its values without a failure.
    /// `None` for a provider whose most recent refresh failed, which is the
    /// staleness signal an operator alarms on.
    last_success: HashMap<String, ArcSwapOption<DateTime<Utc>>>,
    /// Serializes refreshes so two callers cannot interleave reads against one
    /// backend, and so a slow refresh does not overlap the next one.
    refresh_lock: Mutex<()>,
}

impl SecretStore {
    /// Build every provider and read every declared value.
    ///
    /// Fail-fast: the first value that cannot be read stops the whole thing.
    /// A value that has never resolved once has no last-good to fall back to,
    /// so there is no degraded state to start in, only a missing credential a
    /// consumer would discover on a request.
    ///
    /// Values resolve in name order, so a document with two broken secrets
    /// reports the same one on every run.
    ///
    /// # Errors
    ///
    /// Returns [`SecretResolveError`] naming the value and provider that
    /// failed. A malformed `secrets:` block surfaces here too, as a
    /// [`SecretError::Config`] against the value that exposed it.
    pub async fn resolve(
        config: &SecretsConfig,
        registry: &SecretProviderRegistry,
    ) -> Result<Self, SecretResolveError> {
        config.validate().map_err(|source| SecretResolveError {
            secret: String::new(),
            provider: String::new(),
            source,
        })?;

        let mut providers: HashMap<String, Arc<dyn SecretProvider>> = HashMap::new();
        let mut declared_providers: Vec<_> = config.providers.iter().collect();
        declared_providers.sort_by(|a, b| a.0.cmp(b.0));
        for (name, declared) in declared_providers {
            let provider = registry
                .build(name, declared)
                .map_err(|source| SecretResolveError {
                    secret: String::new(),
                    provider: name.clone(),
                    source,
                })?;
            providers.insert(name.clone(), provider);
        }

        let mut values = HashMap::new();
        let mut declared_values: Vec<_> = config.values.iter().collect();
        declared_values.sort_by(|a, b| a.0.cmp(b.0));
        for (name, declared) in declared_values {
            // `validate` already rejected this, so reaching it means the two
            // checks disagree. Erroring rather than asserting keeps a future
            // edit to either one from turning a config fault into a panic.
            let Some(provider) = providers.get(&declared.provider) else {
                return Err(SecretResolveError {
                    secret: name.clone(),
                    provider: declared.provider.clone(),
                    source: SecretError::config(format!(
                        "secret `{name}` names provider `{}`, which is not declared under \
                         `secrets.providers`",
                        declared.provider
                    )),
                });
            };
            let value = provider
                .get_secret(&declared.reference)
                .await
                .map_err(|source| SecretResolveError {
                    secret: name.clone(),
                    provider: declared.provider.clone(),
                    source,
                })?;
            values.insert(
                name.clone(),
                Binding {
                    provider_name: declared.provider.clone(),
                    provider: Arc::clone(provider),
                    reference: declared.reference.clone(),
                    cell: Arc::new(SecretCell::new(value)),
                },
            );
        }

        let now = Arc::new(Utc::now());
        let last_success = providers
            .keys()
            .map(|name| (name.clone(), ArcSwapOption::new(Some(Arc::clone(&now)))))
            .collect();

        Ok(Self {
            values,
            last_success,
            refresh_lock: Mutex::new(()),
        })
    }

    /// An empty store, for a deployment declaring no secrets.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            values: HashMap::new(),
            last_success: HashMap::new(),
            refresh_lock: Mutex::new(()),
        }
    }

    /// A handle to one declared value, or `None` when nothing declares it.
    #[must_use]
    pub fn secret(&self, name: &str) -> Option<SecretRef> {
        self.values.get(name).map(|binding| SecretRef {
            cell: Arc::clone(&binding.cell),
        })
    }

    /// The current value of one declared secret.
    ///
    /// For a caller that reads at the point of use and keeps nothing, which is
    /// what the header-rendering path does.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<Zeroizing<String>> {
        self.values
            .get(name)
            .map(|binding| binding.cell.state.load().value.clone())
    }

    /// Whether a name is declared. Config validation asks this without
    /// touching the value.
    #[must_use]
    pub fn declares(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Every declared name, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.values.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Whether anything is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// When this provider last re-read all of its values without a failure.
    ///
    /// `None` once a refresh against it has failed, and until one succeeds
    /// again. A host that alarms on the gap between this and now is alarming on
    /// "the credentials in memory may no longer be the ones in the backend",
    /// which is the failure this design trades availability for.
    #[must_use]
    pub fn provider_last_success(&self, provider: &str) -> Option<DateTime<Utc>> {
        self.last_success
            .get(provider)
            .and_then(arc_swap::ArcSwapAny::load_full)
            .map(|stamp| *stamp)
    }

    /// Re-read every declared value.
    ///
    /// Driven by the host rather than by a task this module spawns, because a
    /// spawned ticker binds to whichever runtime started it and a host that
    /// initializes on a short-lived runtime loses it silently. A host that
    /// never calls this keeps its startup values, which is a documented
    /// behaviour rather than a refresh that stopped without saying so.
    ///
    /// A value that fails keeps its last-good bytes: a stale credential still
    /// serves traffic and a missing one does not. The report names what failed
    /// so the host can log, meter, and alarm on it.
    ///
    /// Values are re-read a provider at a time, so one backend's reads stay
    /// together and a host can reason about the load it puts on each.
    pub async fn refresh(&self) -> RefreshReport {
        let _guard = self.refresh_lock.lock().await;

        let mut by_provider: BTreeMap<&str, Vec<(&str, &Binding)>> = BTreeMap::new();
        for (name, binding) in &self.values {
            by_provider
                .entry(binding.provider_name.as_str())
                .or_default()
                .push((name.as_str(), binding));
        }

        let mut report = RefreshReport::default();
        for (provider_name, mut bound) in by_provider {
            bound.sort_unstable_by_key(|(name, _)| *name);
            let mut all_read = true;
            for (name, binding) in bound {
                match binding.provider.get_secret(&binding.reference).await {
                    Ok(value) => {
                        if binding.cell.replace_if_changed(value) {
                            report.updated.push(name.to_owned());
                        } else {
                            report.unchanged += 1;
                        }
                    },
                    Err(source) => {
                        all_read = false;
                        report.failed.push(SecretResolveError {
                            secret: name.to_owned(),
                            provider: provider_name.to_owned(),
                            source,
                        });
                    },
                }
            }
            if let Some(slot) = self.last_success.get(provider_name) {
                if all_read {
                    slot.store(Some(Arc::new(Utc::now())));
                } else {
                    slot.store(None);
                }
            }
        }
        report
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore")
            .field("values", &self.names())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use async_trait::async_trait;

    use super::*;

    /// A provider whose answers the test controls.
    struct Scripted {
        value: std::sync::Mutex<Result<String, SecretError>>,
        reads: AtomicU64,
    }

    impl Scripted {
        fn new(value: &str) -> Arc<Self> {
            Arc::new(Self {
                value: std::sync::Mutex::new(Ok(value.to_owned())),
                reads: AtomicU64::new(0),
            })
        }

        fn set(&self, value: &str) {
            *self.value.lock().expect("not poisoned") = Ok(value.to_owned());
        }

        fn fail(&self) {
            *self.value.lock().expect("not poisoned") =
                Err(SecretError::backend("the backend is unreachable"));
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl SecretProvider for Scripted {
        async fn get_secret(&self, _reference: &str) -> Result<Zeroizing<String>, SecretError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.value
                .lock()
                .expect("not poisoned")
                .clone()
                .map(Zeroizing::new)
        }
    }

    /// A store over one scripted provider, built without going through config.
    fn store_over(provider: Arc<Scripted>) -> SecretStore {
        let provider: Arc<dyn SecretProvider> = provider;
        let mut values = HashMap::new();
        values.insert(
            "api_key".to_owned(),
            Binding {
                provider_name: "scripted".to_owned(),
                provider,
                reference: "ignored".to_owned(),
                cell: Arc::new(SecretCell::new(Zeroizing::new("first".to_owned()))),
            },
        );
        let mut last_success = HashMap::new();
        last_success.insert("scripted".to_owned(), ArcSwapOption::empty());
        SecretStore {
            values,
            last_success,
            refresh_lock: Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn a_held_ref_sees_a_refreshed_value() {
        let provider = Scripted::new("second");
        let store = store_over(Arc::clone(&provider));
        let handle = store.secret("api_key").expect("declared");

        assert_eq!(handle.get().as_str(), "first");
        assert_eq!(handle.generation(), 0);

        let report = store.refresh().await;
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.updated, vec!["api_key".to_owned()]);

        // The same handle, not a new one: this is what a plugin holds.
        assert_eq!(handle.get().as_str(), "second");
        assert_eq!(handle.generation(), 1);
    }

    #[tokio::test]
    async fn an_unchanged_value_does_not_move_the_generation() {
        let provider = Scripted::new("first");
        let store = store_over(Arc::clone(&provider));
        let handle = store.secret("api_key").expect("declared");

        let report = store.refresh().await;
        assert!(report.updated.is_empty(), "{report:?}");
        assert_eq!(report.unchanged, 1);
        assert_eq!(
            handle.generation(),
            0,
            "a consumer reconnecting on a generation change must not reconnect on every tick"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_good_value() {
        let provider = Scripted::new("second");
        let store = store_over(Arc::clone(&provider));
        let handle = store.secret("api_key").expect("declared");

        store.refresh().await;
        assert_eq!(handle.get().as_str(), "second");

        provider.fail();
        let report = store.refresh().await;
        assert!(!report.is_ok(), "the backend failed");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].secret, "api_key");

        assert_eq!(
            handle.get().as_str(),
            "second",
            "a stale credential serves traffic; a cleared one does not"
        );
        assert_eq!(handle.generation(), 1, "a failure is not a change");
        assert!(
            store.provider_last_success("scripted").is_none(),
            "a failed provider reports no successful refresh"
        );

        provider.set("third");
        let report = store.refresh().await;
        assert!(report.is_ok());
        assert_eq!(handle.get().as_str(), "third");
        assert!(store.provider_last_success("scripted").is_some());
    }

    #[tokio::test]
    async fn refreshes_do_not_overlap() {
        let provider = Scripted::new("first");
        let store = Arc::new(store_over(Arc::clone(&provider)));

        let (a, b) = tokio::join!(store.refresh(), store.refresh());
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(provider.reads(), 2, "each refresh reads once, in turn");
    }

    #[test]
    fn a_ref_does_not_print_its_value() {
        let cell = Arc::new(SecretCell::new(Zeroizing::new("hunter2".to_owned())));
        let handle = SecretRef { cell };
        let printed = format!("{handle:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[tokio::test]
    async fn resolve_reports_which_value_failed() {
        let config: SecretsConfig = serde_yaml::from_str(
            "
providers:
  shell: { kind: env }
values:
  absent_key: { provider: shell, ref: PPE_TEST_STORE_ABSENT }
",
        )
        .expect("valid yaml");
        let registry = SecretProviderRegistry::with_builtin_backends();
        let err = SecretStore::resolve(&config, &registry)
            .await
            .expect_err("the variable is not set");
        assert_eq!(err.secret, "absent_key");
        assert_eq!(err.provider, "shell");
        assert!(format!("{err}").contains("absent_key"), "{err}");
    }
}
