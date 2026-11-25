// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The revocation hook's payload: what the engine asks a checker, and the
// slots the checker vouched for. Identities and tokens are not copied in;
// a checker reads them from `Extensions` under its own capabilities.

use std::collections::BTreeSet;

use crate::executor::PipelineResult;
use crate::extensions::raw_credentials::TokenRole;
use crate::extensions::security::SecurityExtension;
use crate::hooks::payload::PluginPayload;

/// An identity that authentication resolved into [`SecurityExtension`].
///
/// Revocation coverage is per slot rather than per raw token: an API key or
/// an mTLS workload identity fills a slot without leaving a token in
/// `RawCredentialsExtension.inbound_tokens`, and must still be checked.
///
/// [`SecurityExtension`]: crate::extensions::security::SecurityExtension
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentitySlot {
    /// The user or subject (`security.subject`).
    Subject,

    /// The OAuth client, typically the agent (`security.client`).
    Client,

    /// The calling workload (`security.caller_workload`).
    CallerWorkload,
}

impl IdentitySlot {
    /// The slots `security` has populated, in declaration order.
    ///
    /// ```
    /// use praxis_policy_core::extensions::security::{ClientExtension, SecurityExtension};
    /// use praxis_policy_core::revocation::IdentitySlot;
    ///
    /// let security = SecurityExtension {
    ///     client: Some(ClientExtension::default()),
    ///     ..SecurityExtension::default()
    /// };
    ///
    /// assert_eq!(
    ///     IdentitySlot::populated(Some(&security)).into_iter().collect::<Vec<_>>(),
    ///     vec![IdentitySlot::Client],
    /// );
    /// assert!(IdentitySlot::populated(None).is_empty());
    /// ```
    #[must_use]
    pub fn populated(security: Option<&SecurityExtension>) -> BTreeSet<Self> {
        let Some(security) = security else {
            return BTreeSet::new();
        };
        [
            (Self::Subject, security.subject.is_some()),
            (Self::Client, security.client.is_some()),
            (Self::CallerWorkload, security.caller_workload.is_some()),
        ]
        .into_iter()
        .filter_map(|(slot, present)| present.then_some(slot))
        .collect()
    }

    /// The key under which an identity resolver stores this slot's raw
    /// token in `RawCredentialsExtension.inbound_tokens`, when it stores
    /// one.
    #[must_use]
    pub const fn token_role(self) -> TokenRole {
        match self {
            Self::Subject => TokenRole::User,
            Self::Client => TokenRole::Client,
            Self::CallerWorkload => TokenRole::CallerWorkload,
        }
    }
}

/// Where in a request the engine is checking revocation.
///
/// The engine checks at the hooks whose registered phase is `Pre` or `Post`:
/// the request on its way to the upstream and the response on its way back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckPoint {
    /// Before a request-phase hook runs its pipeline. Authentication has
    /// resolved the identities; no policy has run on them yet.
    AfterAuthentication,

    /// After a request-phase pipeline allowed the call, before it goes to the
    /// upstream. Catches a revocation that landed while a policy step ran.
    BeforeDispatch,

    /// After a response-phase pipeline allowed the result, before it is
    /// released to the caller.
    BeforeRelease,
}

/// The question the engine puts to one revocation checker, and its answer.
///
/// The engine sets the slots and check point. A checker returns a clone with
/// [`Self::vouch`] applied to each slot whose credential it verified with its
/// issuer, through `PluginResult::modify_payload`, or denies with a
/// violation. The checker is resolved per route and reads its route's
/// `config:`, so the route is not repeated here.
///
/// ```
/// use praxis_policy_core::revocation::{CheckPoint, IdentitySlot, RevocationCheck};
///
/// let check = RevocationCheck::new(
///     CheckPoint::AfterAuthentication,
///     [IdentitySlot::Subject, IdentitySlot::Client],
/// );
///
/// let answered = check.clone().vouch(IdentitySlot::Client);
///
/// assert!(answered.vouched().contains(&IdentitySlot::Client));
/// assert!(!answered.vouched().contains(&IdentitySlot::Subject));
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct RevocationCheck {
    check_point: CheckPoint,
    slots: BTreeSet<IdentitySlot>,
    vouched: BTreeSet<IdentitySlot>,
}

impl RevocationCheck {
    /// A check of `slots` at `check_point`, with nothing vouched for yet.
    #[must_use]
    pub fn new(check_point: CheckPoint, slots: impl IntoIterator<Item = IdentitySlot>) -> Self {
        Self {
            check_point,
            slots: slots.into_iter().collect(),
            vouched: BTreeSet::new(),
        }
    }

    /// Where in the request this check runs.
    #[must_use]
    pub const fn check_point(&self) -> CheckPoint {
        self.check_point
    }

    /// Borrow the answer still held by a revocation dispatch.
    ///
    /// Returns `None` when the checker denied or the payload is not a
    /// [`RevocationCheck`].
    #[must_use]
    pub fn from_pipeline_result(result: &PipelineResult) -> Option<&Self> {
        result
            .modified_payload
            .as_ref()
            .and_then(|payload| payload.as_any().downcast_ref::<Self>())
    }

    /// The populated slots the checker is asked about.
    #[must_use]
    pub const fn slots(&self) -> &BTreeSet<IdentitySlot> {
        &self.slots
    }

    /// Record that the checker verified `slot`'s credential with its issuer
    /// and found it valid. A slot the engine did not ask about is ignored.
    #[must_use]
    pub fn vouch(mut self, slot: IdentitySlot) -> Self {
        if self.slots.contains(&slot) {
            self.vouched.insert(slot);
        }
        self
    }

    /// The slots the checker vouched for.
    #[must_use]
    pub const fn vouched(&self) -> &BTreeSet<IdentitySlot> {
        &self.vouched
    }
}

impl PluginPayload for RevocationCheck {
    fn clone_boxed(&self) -> Box<dyn PluginPayload> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PluginContextTable;
    use crate::error::PluginViolation;
    use crate::extensions::Extensions;
    use crate::extensions::security::{ClientExtension, SubjectExtension, WorkloadIdentity};
    use crate::revocation::{REVOKED_CODE, REVOKED_REASON};

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn populated_lists_every_filled_slot_in_order() {
        let security = SecurityExtension {
            caller_workload: Some(WorkloadIdentity::default()),
            client: Some(ClientExtension::default()),
            subject: Some(SubjectExtension::default()),
            ..SecurityExtension::default()
        };

        assert_eq!(
            IdentitySlot::populated(Some(&security))
                .into_iter()
                .collect::<Vec<_>>(),
            vec![
                IdentitySlot::Subject,
                IdentitySlot::Client,
                IdentitySlot::CallerWorkload
            ],
            "all three slots are filled"
        );
    }

    #[test]
    fn populated_is_empty_without_any_identity() {
        assert!(
            IdentitySlot::populated(Some(&SecurityExtension::default())).is_empty(),
            "an unauthenticated request has no slot to check"
        );
        assert!(
            IdentitySlot::populated(None).is_empty(),
            "no security extension means no slot to check"
        );
    }

    #[test]
    fn each_slot_maps_to_its_inbound_token_role() {
        assert_eq!(
            IdentitySlot::Subject.token_role(),
            TokenRole::User,
            "subject"
        );
        assert_eq!(
            IdentitySlot::Client.token_role(),
            TokenRole::Client,
            "client"
        );
        assert_eq!(
            IdentitySlot::CallerWorkload.token_role(),
            TokenRole::CallerWorkload,
            "caller workload"
        );
    }

    #[test]
    fn a_new_check_has_nothing_vouched() {
        let check = RevocationCheck::new(CheckPoint::BeforeDispatch, [IdentitySlot::Subject]);

        assert!(
            check.vouched().is_empty(),
            "nothing is vouched until a checker says so"
        );
        assert_eq!(
            check.check_point(),
            CheckPoint::BeforeDispatch,
            "check point"
        );
        assert_eq!(
            check.slots().iter().copied().collect::<Vec<_>>(),
            vec![IdentitySlot::Subject],
            "slots"
        );
    }

    #[test]
    fn vouching_an_unrequested_slot_is_ignored() {
        let check = RevocationCheck::new(CheckPoint::AfterAuthentication, [IdentitySlot::Client])
            .vouch(IdentitySlot::Subject);

        assert!(
            check.vouched().is_empty(),
            "a checker cannot vouch for a slot the engine did not ask about"
        );
    }

    #[test]
    fn the_answer_is_read_back_from_a_pipeline_result() {
        let answered = RevocationCheck::new(CheckPoint::BeforeRelease, [IdentitySlot::Client])
            .vouch(IdentitySlot::Client);
        let allowed = PipelineResult::allowed_with(
            Box::new(answered.clone()),
            Extensions::default(),
            PluginContextTable::new(),
        );
        let denied = PipelineResult::denied(
            PluginViolation::new(REVOKED_CODE, REVOKED_REASON),
            Extensions::default(),
            PluginContextTable::new(),
        );

        assert_eq!(
            RevocationCheck::from_pipeline_result(&allowed),
            Some(&answered),
            "the checker's answer survives the pipeline"
        );
        assert_eq!(
            RevocationCheck::from_pipeline_result(&denied),
            None,
            "a denied pipeline carries no answer"
        );
    }
}
