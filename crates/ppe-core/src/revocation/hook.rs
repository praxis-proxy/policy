// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `RevocationHook`: the `HookTypeDef` marker for the revocation family.
// The engine, not the host, invokes it at each check point on a route whose
// `revocation:` stack is non-empty. Each checker is invoked on its own with
// a fresh payload, so no checker sees or overwrites another's `vouched`.

use crate::hooks::trait_def::PluginResult;

use super::payload::RevocationCheck;

crate::define_hooks! {
    /// The revocation family's row in the built-in hook metadata table.
    REVOCATION_HOOK_METADATA;

    /// Hook name for revocation checkers. Unphased: the engine calls it at
    /// several check points, which the payload names.
    HOOK_REVOCATION_CHECK: "revocation.check" =>
        family: RevocationHook, entity: None, phase: Unphased;
}

crate::define_hook! {
    /// Revocation check: does each resolved identity still hold authority?
    ///
    /// **Payload** ([`RevocationCheck`]): the populated identity slots, the
    /// check point and the route, set by the engine and read through
    /// accessors, plus the `vouched` set the checker fills on a clone. The
    /// identities and raw tokens themselves are read from `Extensions`,
    /// filtered by the checker's capabilities.
    ///
    /// **Deny** through the ordinary violation path, with
    /// [`REVOKED_CODE`] for a revoked identity or credential and
    /// [`REVOCATION_UNAVAILABLE_CODE`] when the status could not be
    /// established. Keep issuer detail (endpoints, realms, clients, upstream
    /// errors) out of the violation's reason and details: hosts render both
    /// to the caller. Log it instead.
    ///
    /// **Allow** with [`RevocationCheck::vouch`] for each slot whose
    /// credential the checker verified with its issuer. Leave out a slot the
    /// checker does not cover. A list-style checker, such as a kill list,
    /// never vouches: it knows an identity is not blocked, not that its
    /// credential is still valid, and a vouch from it would cover a
    /// credential no issuer checked. After every checker allows, the engine
    /// denies any populated slot no checker vouched for.
    ///
    /// **Handler signature:**
    ///
    /// ```rust,ignore
    /// impl HookHandler<RevocationHook> for Introspection {
    ///     async fn handle(
    ///         &self,
    ///         check: &RevocationCheck,
    ///         ext: &Extensions,
    ///         _ctx: &mut PluginContext,
    ///     ) -> PluginResult<RevocationCheck> {
    ///         let mut out = check.clone();
    ///         for &slot in check.slots() {
    ///             let Some(token) = self.token_from_my_issuer(ext, slot) else {
    ///                 continue;
    ///             };
    ///             match self.introspect(token).await {
    ///                 Status::Active => out = out.vouch(slot),
    ///                 Status::Inactive => return deny(REVOKED_CODE, REVOKED_REASON),
    ///                 Status::Failed => {
    ///                     return deny(REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON);
    ///                 },
    ///             }
    ///         }
    ///         PluginResult::modify_payload(out)
    ///     }
    /// }
    /// ```
    ///
    /// [`REVOKED_CODE`]: super::REVOKED_CODE
    /// [`REVOCATION_UNAVAILABLE_CODE`]: super::REVOCATION_UNAVAILABLE_CODE
    /// [`RevocationCheck`]: super::payload::RevocationCheck
    /// [`RevocationCheck::vouch`]: super::payload::RevocationCheck::vouch
    RevocationHook, "revocation.check" => {
        payload: RevocationCheck,
        result: PluginResult<RevocationCheck>,
    }
}
