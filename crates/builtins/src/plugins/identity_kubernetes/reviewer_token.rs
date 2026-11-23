// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// PPE's own token for the API server. A file is re-read once `refresh_secs` has
// passed, as client-go does, so a projected token rotates. A failed re-read
// keeps the last token: denying every request on a read error turns a blip
// into an outage.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::plugins::identity_kubernetes::config::ReviewerTokenSource;

/// The token, and when it was read.
struct Current {
    read_at: Instant,
    token: Zeroizing<String>,
}

/// PPE's bearer token for the API server, re-read as its source allows.
pub(crate) struct ReviewerToken {
    current: RwLock<Current>,
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
        let token = read(&source)?;
        Ok(Self {
            current: RwLock::new(Current {
                read_at: Instant::now(),
                token,
            }),
            source,
        })
    }

    /// The token to send now.
    pub(crate) async fn get(&self) -> Zeroizing<String> {
        let (token, read_at) = {
            let current = self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (current.token.clone(), current.read_at)
        };
        let ReviewerTokenSource::File { refresh_secs, .. } = &self.source else {
            return token;
        };
        if read_at.elapsed() < Duration::from_secs(*refresh_secs) {
            return token;
        }

        let source = self.source.clone();
        match tokio::task::spawn_blocking(move || read(&source)).await {
            Ok(Ok(fresh)) => {
                let mut current = self
                    .current
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *current = Current {
                    read_at: Instant::now(),
                    token: fresh.clone(),
                };
                fresh
            },
            Ok(Err(error)) => {
                tracing::warn!(%error, "reviewer token re-read failed; keeping the last one");
                token
            },
            Err(error) => {
                tracing::warn!(%error, "reviewer token re-read did not run; keeping the last one");
                token
            },
        }
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
