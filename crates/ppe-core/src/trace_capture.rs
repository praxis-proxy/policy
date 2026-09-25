// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Capturing what the crate emits, for tests that assert on diagnostics.
//
// A subscriber installed once for the whole binary, always interested, with a
// thread-local sink. The install is process-wide because callsite interest is
// cached process-wide: a thread-local subscriber does not own whether an event
// fires, so a test running in parallel can have its callsite recached as
// disabled between the `debug!` and the assertion. One always-interested
// subscriber takes the cache out of the race, and the sink keeps each test
// reading only its own events.
//
// One helper rather than one per test module: the global default is a single
// slot, so a second module installing its own would leave whichever lost the
// race capturing nothing.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// The events one test captured.
#[derive(Clone, Default)]
pub(crate) struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    /// Every event captured, in order.
    pub(crate) fn recorded(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The captured events containing `needle`.
    pub(crate) fn matching(&self, needle: &str) -> Vec<String> {
        self.recorded()
            .into_iter()
            .filter(|event| event.contains(needle))
            .collect()
    }
}

thread_local! {
    static SINK: RefCell<Option<Events>> = const { RefCell::new(None) };
}

struct Capture;

/// Clears the sink even if the body panics, so a failing test cannot leak its
/// events into whichever test the runner puts on this thread next.
pub(crate) struct Sink;

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
    fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        SINK.with_borrow(|sink| {
            let Some(events) = sink.as_ref() else {
                return;
            };
            let mut render = Render(format!("[{}]", event.metadata().level()));
            event.record(&mut render);
            events
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(render.0);
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Capture what this thread emits until the returned guard is dropped.
///
/// A second subscriber in this binary would silently take the events this one
/// is asserting on, so the install fails loudly rather than capturing nothing.
#[allow(clippy::expect_used, reason = "test-only helper")]
pub(crate) fn capturing() -> (Events, Sink) {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(Capture)
            .expect("no other subscriber is installed in this test binary");
    });

    let events = Events::default();
    SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
    (events, Sink)
}

/// Capture what `body` emits.
pub(crate) fn capturing_body<T>(body: impl FnOnce() -> T) -> (T, Events) {
    let (events, _guard) = capturing();
    (body(), events)
}
