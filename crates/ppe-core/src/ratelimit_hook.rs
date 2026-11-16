// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Entity-less and unphased like `identity.resolve`: the host calls these
// around identity resolution, not at an APL phase boundary.

use crate::http_hook::HttpHook;

crate::define_hooks! {
    /// The rate-limit family's rows in the built-in hook metadata table.
    RATELIMIT_HOOK_METADATA;

    /// Rate-limit hook a host calls once per request, before the first
    /// `identity.resolve`, so a limit can protect credential verification.
    HOOK_RATELIMIT_PRE_IDENTITY: "ratelimit.pre_identity" =>
        family: HttpHook, entity: None, phase: Unphased;
    /// Rate-limit hook a host calls once per request, after the last
    /// `identity.resolve`, so a limit can key on the resolved subject.
    HOOK_RATELIMIT_POST_IDENTITY: "ratelimit.post_identity" =>
        family: HttpHook, entity: None, phase: Unphased;
}
