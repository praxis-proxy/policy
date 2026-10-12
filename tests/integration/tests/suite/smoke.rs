// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The harness builds and initializes an engine through the facade.

use praxis_policy_test_utils::host;

#[tokio::test]
async fn engine_initializes_an_empty_config() {
    let engine = host::engine(Vec::new());
    engine
        .load_config_yaml("plugins: []\n")
        .expect("load an empty config");
    engine.initialize().await.expect("initialize");
    assert!(engine.is_initialized(), "engine reports initialized");
    assert_eq!(engine.plugin_count(), 0, "an empty config loads no plugins");
}
