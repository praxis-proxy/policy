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

use arc_swap::ArcSwap;
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

/// One value together with the generation it was read at.
///
/// A consumer that has to act on rotation rather than just read the new bytes
/// records the generation beside whatever it built from the value, and rebuilds
/// when the generation moves. That pairing has to come from one load: a value
/// and a generation read separately can straddle a refresh and pair the old
/// bytes with the new generation, and the consumer then holds a resource built
/// from a credential it believes it has already rebuilt against. Nothing moves
/// the generation again until the value changes once more, so that resource is
/// never rebuilt.
pub struct SecretSnapshot {
    value: Zeroizing<String>,
    generation: u64,
}

impl SecretSnapshot {
    /// The value this snapshot was taken at.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The generation that value belongs to.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for SecretSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSnapshot")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
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

    /// A handle to a fixed value, for tests that need a secret without a
    /// provider behind it.
    #[cfg(test)]
    pub(crate) fn fixed(value: &str) -> Self {
        Self {
            cell: Arc::new(SecretCell::new(Zeroizing::new(value.to_owned()))),
        }
    }

    /// The current value and its generation, from one load.
    ///
    /// What a consumer that acts on rotation reads: a connection pool
    /// authenticated when it connected, so a new password reaches it only when
    /// it reconnects. Record [`SecretSnapshot::generation`] beside whatever was
    /// built from [`SecretSnapshot::value`], and rebuild when a later snapshot
    /// reports a higher one.
    ///
    /// Pair them from here rather than from [`Self::get`] and
    /// [`Self::generation`], which are two loads a refresh can land between.
    #[must_use]
    pub fn snapshot(&self) -> SecretSnapshot {
        let state = self.cell.state.load();
        SecretSnapshot {
            value: state.value.clone(),
            generation: state.generation,
        }
    }

    /// How many times the value has changed since startup.
    ///
    /// For reporting the generation on its own. A consumer rebuilding on
    /// rotation needs the value that belongs to it, which is
    /// [`Self::snapshot`].
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

/// One failed refresh of a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFailure {
    /// When it happened.
    pub at: DateTime<Utc>,
    /// What the provider reported. Carries neither the value nor the
    /// credentials the provider used to read it, per [`SecretProvider`].
    pub reason: String,
}

/// How one provider's refreshes have been going.
///
/// A host alarms on the age of `last_success`, which is the gap between "the
/// credentials in memory were confirmed against the backend" and now. That
/// timestamp survives a failure: a provider that has been failing for an hour
/// reports the success from before it started failing, which is what makes the
/// gap computable. `failing` is the separate question of whether the most
/// recent attempt worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    /// When this provider last re-read all of its values without a failure.
    ///
    /// `None` only before any successful read, which [`SecretStore::resolve`]
    /// rules out for a store it builds.
    pub last_success: Option<DateTime<Utc>>,

    /// The most recent failure, kept after recovery so a host can see that a
    /// provider has been flapping.
    pub last_failure: Option<ProviderFailure>,

    /// Whether the most recent refresh failed.
    pub failing: bool,
}

/// What a host can learn about a provider it names.
///
/// Three variants, carrying four conditions between them: [`ProviderHealth`]'s
/// `failing` flag separates a provider whose last refresh failed from one that
/// is healthy. A single `Option` conflates all four, leaving a host unable to
/// tell a failing provider from one nothing declares, or either from a store
/// that was never built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsHealth {
    /// No store has been resolved. The engine has not initialized, or the
    /// document it loaded declares no secrets. Nothing is being refreshed, and
    /// no credential is in memory to go stale.
    Uninitialized,

    /// A store exists and declares no provider by that name. An alarm that
    /// lands here is watching a name the document no longer has, not a healthy
    /// provider.
    Undeclared,

    /// The provider is declared, and this is how its refreshes have gone.
    Resolved(ProviderHealth),
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

/// A store built for a reload, with writes to cells it shares with the
/// previous one held back.
///
/// Applying those writes as each value is read would change a credential the
/// running document still serves if a later value failed. [`Self::publish`]
/// is the point the reload has decided to go out.
pub(crate) struct ReloadedSecrets {
    store: SecretStore,
    /// `(name, cell, new bytes)`. The name is how a content-key check reads
    /// the length it will have after publish, without writing the cell yet.
    updates: Vec<(String, Arc<SecretCell>, Zeroizing<String>)>,
    /// Values whose declaration was unchanged, so the cell an existing
    /// [`SecretRef`] holds is the one in `store`.
    carried: usize,
}

impl fmt::Debug for ReloadedSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadedSecrets")
            .field("values", &self.store.names())
            .field("carried", &self.carried)
            .field("reread", &self.updates.len())
            .finish_non_exhaustive()
    }
}

impl ReloadedSecrets {
    /// How many values kept the cell they had before this reload.
    #[must_use]
    pub(crate) fn carried(&self) -> usize {
        self.carried
    }

    /// How many values the new block declares.
    #[must_use]
    pub(crate) fn value_count(&self) -> usize {
        self.store.names().len()
    }

    /// How many carried cells have new bytes waiting for [`Self::publish`].
    ///
    /// A carried cell is re-read only when its provider was rebuilt. The
    /// declaration was unchanged, but the backend behind it was not.
    #[must_use]
    pub(crate) fn reread(&self) -> usize {
        self.updates.len()
    }

    /// The length `name` will have once this reload is published.
    ///
    /// `None` when the new block does not declare it. A pending write wins
    /// over the bytes the cell still holds, because those bytes are what a
    /// check has to accept or refuse.
    #[must_use]
    pub(crate) fn len_after_publish(&self, name: &str) -> Option<usize> {
        if let Some((_, _, value)) = self.updates.iter().find(|(n, _, _)| n == name) {
            return Some(value.len());
        }
        self.store.value(name).map(|value| value.len())
    }

    /// Write the pending bytes into the shared cells and return the store.
    ///
    /// After this, a [`SecretRef`] taken before the reload sees the new
    /// bytes. Call it only when every value resolved and the reload is about
    /// to be published.
    pub(crate) fn publish(mut self) -> SecretStore {
        for (_, cell, value) in self.updates.drain(..) {
            cell.replace_if_changed(value);
        }
        self.store
    }
}

/// Every declared value, resolved.
pub struct SecretStore {
    /// The block these bindings were resolved from.
    ///
    /// Held here rather than beside the store so the two cannot drift: a
    /// reload compares against the declaration that produced the values in
    /// memory, not against whatever config was installed last.
    declared: SecretsConfig,
    values: HashMap<String, Binding>,
    /// How each declared provider's refreshes have been going. Keyed by every
    /// provider the document declared, including one no value is bound to, so
    /// a host alarming on a name can tell "declared and idle" from "not
    /// declared".
    health: HashMap<String, ArcSwap<ProviderHealth>>,
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
        Ok(Self::resolve_replacing(config, registry, None)
            .await?
            .publish())
    }

    /// Resolve `config`, keeping the cell of every value whose provider and
    /// reference are unchanged from `previous`.
    ///
    /// A [`SecretRef`] a plugin already holds points at that cell, so it keeps
    /// working and keeps its generation. A value that is new, or whose
    /// provider or reference changed, is read into a new cell. A provider
    /// whose settings changed is built again, and each value still bound to
    /// it is re-read into the cell it already has; those bytes stay pending
    /// until [`ReloadedSecrets::publish`], so one failed read leaves every
    /// cell the running store shares untouched.
    ///
    /// An identical provider declaration reuses the provider itself. A Vault
    /// session, or any other state the provider holds, survives the reload
    /// instead of being logged in for again.
    ///
    /// # Errors
    ///
    /// Returns [`SecretResolveError`] naming the value and provider that
    /// failed, as [`Self::resolve`] does. Nothing on `previous` is modified.
    pub(crate) async fn resolve_replacing(
        config: &SecretsConfig,
        registry: &SecretProviderRegistry,
        previous: Option<&Self>,
    ) -> Result<ReloadedSecrets, SecretResolveError> {
        config.validate().map_err(|source| SecretResolveError {
            secret: String::new(),
            provider: String::new(),
            source,
        })?;

        let mut providers: HashMap<String, Arc<dyn SecretProvider>> = HashMap::new();
        let mut reused_provider: HashMap<String, bool> = HashMap::new();
        let mut declared_providers: Vec<_> = config.providers.iter().collect();
        declared_providers.sort_by(|a, b| a.0.cmp(b.0));
        for (name, declared) in declared_providers {
            let reused = previous.and_then(|previous| {
                if previous.declared.providers.get(name) != Some(declared) {
                    return None;
                }
                // The provider lives on the bindings that use it. One with no
                // values was never built into something that can be reused.
                previous
                    .values
                    .values()
                    .find(|binding| binding.provider_name == *name)
                    .map(|binding| Arc::clone(&binding.provider))
            });
            let was_reused = reused.is_some();
            let provider = match reused {
                Some(provider) => provider,
                None => registry
                    .build(name, declared)
                    .map_err(|source| SecretResolveError {
                        secret: String::new(),
                        provider: name.clone(),
                        source,
                    })?,
            };
            reused_provider.insert(name.clone(), was_reused);
            providers.insert(name.clone(), provider);
        }

        let mut values = HashMap::new();
        let mut updates = Vec::new();
        let mut carried = 0;
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
            let carried_cell = previous.and_then(|previous| {
                let binding = previous.values.get(name)?;
                (binding.provider_name == declared.provider
                    && binding.reference == declared.reference)
                    .then(|| Arc::clone(&binding.cell))
            });
            let cell = if let Some(cell) = carried_cell {
                carried += 1;
                // The declaration is the same, but the provider behind it was
                // rebuilt. Read the new backend now so a failure refuses the
                // reload, and hold the bytes until publish so the shared cell
                // stays on the previous value if a later read fails.
                if !reused_provider
                    .get(&declared.provider)
                    .copied()
                    .unwrap_or(false)
                {
                    let value =
                        provider
                            .get_secret(&declared.reference)
                            .await
                            .map_err(|source| SecretResolveError {
                                secret: name.clone(),
                                provider: declared.provider.clone(),
                                source,
                            })?;
                    updates.push((name.clone(), Arc::clone(&cell), value));
                }
                cell
            } else {
                let value = provider
                    .get_secret(&declared.reference)
                    .await
                    .map_err(|source| SecretResolveError {
                        secret: name.clone(),
                        provider: declared.provider.clone(),
                        source,
                    })?;
                Arc::new(SecretCell::new(value))
            };
            values.insert(
                name.clone(),
                Binding {
                    provider_name: declared.provider.clone(),
                    provider: Arc::clone(provider),
                    reference: declared.reference.clone(),
                    cell,
                },
            );
        }

        // A reused provider was not necessarily re-read, so its health is the
        // one the previous store already had. Copying the snapshot rather than
        // sharing the slot keeps a refresh of the store being replaced from
        // writing health into the one about to be published. A rebuilt
        // provider has just confirmed its credentials, which is a fresh
        // success.
        let resolved_at = Utc::now();
        let mut health = HashMap::new();
        for name in providers.keys() {
            let reused = reused_provider.get(name).copied().unwrap_or(false);
            let snapshot = if reused {
                previous
                    .and_then(|previous| previous.health.get(name))
                    .map(|slot| ProviderHealth::clone(&slot.load()))
            } else {
                None
            };
            health.insert(
                name.clone(),
                ArcSwap::from_pointee(snapshot.unwrap_or(ProviderHealth {
                    last_success: Some(resolved_at),
                    last_failure: None,
                    failing: false,
                })),
            );
        }

        Ok(ReloadedSecrets {
            store: Self {
                declared: config.clone(),
                values,
                health,
                refresh_lock: Mutex::new(()),
            },
            updates,
            carried,
        })
    }

    /// An empty store, for a deployment declaring no secrets.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            declared: SecretsConfig::default(),
            values: HashMap::new(),
            health: HashMap::new(),
            refresh_lock: Mutex::new(()),
        }
    }

    /// The `secrets:` block these values were resolved from.
    ///
    /// What a synchronous reload compares against. A reload that re-resolves
    /// publishes another store; this one still describes the values it holds.
    #[must_use]
    pub fn declared(&self) -> &SecretsConfig {
        &self.declared
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
    /// Kept across a failure, so the gap between this and now is how long the
    /// credentials in memory have gone unconfirmed against the backend. That
    /// gap is what a host alarms on, and it is the exposure this design accepts
    /// in exchange for serving through a backend outage.
    ///
    /// `None` only for a provider nothing declares. Whether the most recent
    /// refresh failed is [`Self::provider_health`].
    #[must_use]
    pub fn provider_last_success(&self, provider: &str) -> Option<DateTime<Utc>> {
        self.health
            .get(provider)
            .and_then(|health| health.load().last_success)
    }

    /// How this provider's refreshes have been going, or `None` when nothing
    /// declares it.
    #[must_use]
    pub fn provider_health(&self, provider: &str) -> Option<ProviderHealth> {
        self.health
            .get(provider)
            .map(|health| ProviderHealth::clone(&health.load()))
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
            // The first failure, since one is enough to make the provider's
            // values unconfirmed and the report carries them all anyway.
            let mut failure: Option<String> = None;
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
                        if failure.is_none() {
                            failure = Some(format!("{source}"));
                        }
                        report.failed.push(SecretResolveError {
                            secret: name.to_owned(),
                            provider: provider_name.to_owned(),
                            source,
                        });
                    },
                }
            }
            self.record_refresh(provider_name, failure);
        }
        report
    }

    /// Fold one provider's result into its health, keeping what the other
    /// outcome established.
    ///
    /// A success keeps the last failure, so a flapping provider stays visible
    /// as one. A failure keeps the last success, which is the timestamp a
    /// staleness alarm subtracts from now; clearing it would leave the host
    /// unable to tell a provider that failed a moment ago from one that has
    /// been failing since startup.
    fn record_refresh(&self, provider: &str, failure: Option<String>) {
        let Some(slot) = self.health.get(provider) else {
            return;
        };
        let current = slot.load();
        let now = Utc::now();
        let updated = match failure {
            None => ProviderHealth {
                last_success: Some(now),
                last_failure: current.last_failure.clone(),
                failing: false,
            },
            Some(reason) => ProviderHealth {
                last_success: current.last_success,
                last_failure: Some(ProviderFailure { at: now, reason }),
                failing: true,
            },
        };
        slot.store(Arc::new(updated));
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore")
            .field("values", &self.names())
            .finish_non_exhaustive()
    }
}

/// A store holding one value under one name, for tests elsewhere in the crate
/// that need something to read a `secret.<name>` source against.
///
/// Assembled directly rather than through [`SecretStore::resolve`], so a caller
/// needs no backend, no temp file, and no runtime. The provider it carries
/// answers with the same bytes forever, which makes [`SecretStore::refresh`] a
/// no-op here; rotation is exercised against a real backend in the engine's own
/// tests, where it is the file being rewritten that makes the test mean
/// something.
#[cfg(test)]
pub(crate) fn fixed(name: &str, value: &str) -> SecretStore {
    struct Fixed(String);

    #[async_trait::async_trait]
    impl SecretProvider for Fixed {
        async fn get_secret(&self, _reference: &str) -> Result<Zeroizing<String>, SecretError> {
            Ok(Zeroizing::new(self.0.clone()))
        }
    }

    let mut values = HashMap::new();
    values.insert(
        name.to_owned(),
        Binding {
            provider_name: "fixed".to_owned(),
            provider: Arc::new(Fixed(value.to_owned())),
            reference: name.to_owned(),
            cell: Arc::new(SecretCell::new(Zeroizing::new(value.to_owned()))),
        },
    );
    SecretStore {
        declared: SecretsConfig::default(),
        values,
        health: HashMap::new(),
        refresh_lock: Mutex::new(()),
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

    use super::super::config::SecretProviderConfig;
    use super::super::provider::SecretProviderFactory;
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
        store_over_value(provider, "first")
    }

    /// The same, for a test that needs the cell to start at a known value.
    fn store_over_value(provider: Arc<Scripted>, initial: &str) -> SecretStore {
        let provider: Arc<dyn SecretProvider> = provider;
        let mut values = HashMap::new();
        values.insert(
            "api_key".to_owned(),
            Binding {
                provider_name: "scripted".to_owned(),
                provider,
                reference: "ignored".to_owned(),
                cell: Arc::new(SecretCell::new(Zeroizing::new(initial.to_owned()))),
            },
        );
        // Never refreshed, so no success and no failure yet. `resolve` seeds a
        // success instead, which is why these tests assert on movement rather
        // than on an absolute stamp.
        let mut health = HashMap::new();
        health.insert(
            "scripted".to_owned(),
            ArcSwap::from_pointee(ProviderHealth {
                last_success: None,
                last_failure: None,
                failing: false,
            }),
        );
        SecretStore {
            declared: SecretsConfig::default(),
            values,
            health,
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

        provider.set("third");
        let report = store.refresh().await;
        assert!(report.is_ok());
        assert_eq!(handle.get().as_str(), "third");
    }

    /// A staleness alarm subtracts the last success from now, so the failure
    /// that makes the credential stale must not be what erases the timestamp.
    #[tokio::test]
    async fn a_failure_keeps_the_last_success_and_reports_itself() {
        let provider = Scripted::new("second");
        let store = store_over(Arc::clone(&provider));

        store.refresh().await;
        let confirmed = store
            .provider_last_success("scripted")
            .expect("a successful refresh records when it happened");

        provider.fail();
        store.refresh().await;

        let health = store.provider_health("scripted").expect("declared");
        assert_eq!(
            health.last_success,
            Some(confirmed),
            "the age of the last success is what a staleness alarm reads"
        );
        assert!(health.failing, "the most recent refresh failed");
        let failure = health.last_failure.expect("the failure is reported");
        assert!(failure.reason.contains("unreachable"), "{}", failure.reason);
        assert!(failure.at >= confirmed);

        provider.set("third");
        store.refresh().await;
        let health = store.provider_health("scripted").expect("declared");
        assert!(!health.failing, "a success clears the current failure");
        assert!(
            health.last_success > Some(confirmed),
            "a success advances the timestamp"
        );
        assert!(
            health.last_failure.is_some(),
            "the earlier failure stays visible, so flapping is not invisible"
        );
    }

    #[tokio::test]
    async fn an_undeclared_provider_has_no_health() {
        let store = store_over(Scripted::new("first"));
        assert!(store.provider_health("scripted").is_some());
        assert!(
            store.provider_health("no-such-provider").is_none(),
            "a name nothing declares is not a healthy provider"
        );
    }

    #[tokio::test]
    async fn refreshes_do_not_overlap() {
        let provider = Scripted::new("first");
        let store = Arc::new(store_over(Arc::clone(&provider)));

        let (a, b) = tokio::join!(store.refresh(), store.refresh());
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(provider.reads(), 2, "each refresh reads once, in turn");
    }

    /// Refresh while a consumer reads. Every value the scripted provider
    /// returns names the generation it produces, so a snapshot pairing bytes
    /// with a generation from either side of a refresh fails the invariant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_snapshot_pairs_a_value_with_its_own_generation() {
        const ROTATIONS: u64 = 200;

        let provider = Scripted::new("v0");
        let store = Arc::new(store_over_value(Arc::clone(&provider), "v0"));
        let handle = store.secret("api_key").expect("declared");

        let rotating = {
            let store = Arc::clone(&store);
            let provider = Arc::clone(&provider);
            tokio::spawn(async move {
                for n in 1..=ROTATIONS {
                    provider.set(&format!("v{n}"));
                    store.refresh().await;
                }
            })
        };

        while !rotating.is_finished() {
            let snapshot = handle.snapshot();
            assert_eq!(
                snapshot.value(),
                format!("v{}", snapshot.generation()),
                "the value and the generation came from different refreshes"
            );
            tokio::task::yield_now().await;
        }
        rotating.await.expect("the rotating task does not panic");

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.generation(),
            ROTATIONS,
            "every rotation changed the bytes, so every one moved the generation"
        );
        assert_eq!(snapshot.value(), format!("v{ROTATIONS}"));
    }

    #[test]
    fn a_snapshot_does_not_print_its_value() {
        let handle = SecretRef::fixed("hunter2");
        let printed = format!("{:?}", handle.snapshot());
        assert!(!printed.contains("hunter2"), "{printed}");
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

    /// Hands back one scripted provider, ignoring the declared settings.
    struct ScriptedFactory {
        provider: Arc<Scripted>,
    }

    impl SecretProviderFactory for ScriptedFactory {
        fn kind(&self) -> &str {
            "scripted"
        }

        fn build(
            &self,
            _config: &SecretProviderConfig,
        ) -> Result<Arc<dyn SecretProvider>, SecretError> {
            let provider = Arc::clone(&self.provider);
            Ok(provider)
        }
    }

    fn scripted_registry(provider: Arc<Scripted>) -> SecretProviderRegistry {
        let mut registry = SecretProviderRegistry::new();
        registry.register(Box::new(ScriptedFactory { provider }));
        registry
    }

    fn scripted_config(values: &str) -> SecretsConfig {
        serde_yaml::from_str(&format!(
            "
providers:
  scripted: {{ kind: scripted }}
values:
{values}
"
        ))
        .expect("valid yaml")
    }

    #[tokio::test]
    async fn an_unchanged_value_keeps_its_cell_when_another_is_added() {
        let provider = Scripted::new("hunter2");
        let registry = scripted_registry(Arc::clone(&provider));
        let first = SecretStore::resolve(
            &scripted_config("  api_key: { provider: scripted, ref: first }\n"),
            &registry,
        )
        .await
        .expect("resolves");
        let handle = first.secret("api_key").expect("declared");

        let replaced = SecretStore::resolve_replacing(
            &scripted_config(
                "  api_key: { provider: scripted, ref: first }\n  \
                 second_key: { provider: scripted, ref: second }\n",
            ),
            &registry,
            Some(&first),
        )
        .await
        .expect("the added value resolves")
        .publish();

        provider.set("rotated");
        let report = replaced.refresh().await;
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(
            handle.get().as_str(),
            "rotated",
            "the handle from before the reload reads the cell the new store refreshes"
        );
    }

    #[tokio::test]
    async fn a_changed_reference_gets_a_new_cell() {
        let provider = Scripted::new("hunter2");
        let registry = scripted_registry(Arc::clone(&provider));
        let first = SecretStore::resolve(
            &scripted_config("  api_key: { provider: scripted, ref: first }\n"),
            &registry,
        )
        .await
        .expect("resolves");
        let handle = first.secret("api_key").expect("declared");

        provider.set("other");
        let replaced = SecretStore::resolve_replacing(
            &scripted_config("  api_key: { provider: scripted, ref: second }\n"),
            &registry,
            Some(&first),
        )
        .await
        .expect("the new reference resolves")
        .publish();

        assert_eq!(
            handle.get().as_str(),
            "hunter2",
            "a changed reference does not write the cell the old handle holds"
        );
        assert_eq!(
            replaced.value("api_key").expect("declared").as_str(),
            "other"
        );

        provider.set("third");
        replaced.refresh().await;
        assert_eq!(handle.get().as_str(), "hunter2");
        assert_eq!(
            replaced.value("api_key").expect("declared").as_str(),
            "third"
        );
    }

    #[tokio::test]
    async fn a_failed_replacement_does_not_touch_the_previous_cell() {
        let provider = Scripted::new("hunter2");
        let registry = scripted_registry(Arc::clone(&provider));
        let first = SecretStore::resolve(
            &scripted_config("  api_key: { provider: scripted, ref: first }\n"),
            &registry,
        )
        .await
        .expect("resolves");
        let handle = first.secret("api_key").expect("declared");

        provider.fail();
        let err = SecretStore::resolve_replacing(
            &scripted_config(
                "  api_key: { provider: scripted, ref: first }\n  \
                 second_key: { provider: scripted, ref: missing }\n",
            ),
            &registry,
            Some(&first),
        )
        .await
        .expect_err("the added value cannot be read");
        assert_eq!(err.secret, "second_key");
        assert_eq!(handle.get().as_str(), "hunter2");
    }
}
