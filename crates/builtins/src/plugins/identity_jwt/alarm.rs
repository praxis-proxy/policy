// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Throttled request-path crypto alarms.
//!
//! A failing backend fails every request, so each operation logs at most once
//! per interval with the count it held back.

use praxis_policy_core::crypto::IntervalLog;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

pub(crate) const INTERVAL_SECS: u64 = 60; // 1 minute

/// The request-path operations that can raise a crypto alarm.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Op {
    DpopAth,
    #[cfg(feature = "jwt-openssl-fips")]
    DpopProvider,
    DpopThumbprint,
    DpopVerify,
    JwtVerify,
}

impl Op {
    const fn name(self) -> &'static str {
        match self {
            Self::DpopAth => "dpop_ath",
            #[cfg(feature = "jwt-openssl-fips")]
            Self::DpopProvider => "dpop_provider",
            Self::DpopThumbprint => "dpop_thumbprint",
            Self::DpopVerify => "dpop_verify",
            Self::JwtVerify => "jwt_verify",
        }
    }

    fn log(self) -> &'static IntervalLog {
        static DPOP_ATH: IntervalLog = IntervalLog::new(INTERVAL_SECS);
        #[cfg(feature = "jwt-openssl-fips")]
        static DPOP_PROVIDER: IntervalLog = IntervalLog::new(INTERVAL_SECS);
        static DPOP_THUMBPRINT: IntervalLog = IntervalLog::new(INTERVAL_SECS);
        static DPOP_VERIFY: IntervalLog = IntervalLog::new(INTERVAL_SECS);
        static JWT_VERIFY: IntervalLog = IntervalLog::new(INTERVAL_SECS);
        match self {
            Self::DpopAth => &DPOP_ATH,
            #[cfg(feature = "jwt-openssl-fips")]
            Self::DpopProvider => &DPOP_PROVIDER,
            Self::DpopThumbprint => &DPOP_THUMBPRINT,
            Self::DpopVerify => &DPOP_VERIFY,
            Self::JwtVerify => &JWT_VERIFY,
        }
    }
}

/// Log `policy_crypto_failure` for `op`, at most once per interval.
pub(crate) fn crypto_failure(op: Op, error: &dyn std::fmt::Display) {
    if let Some(suppressed) = op.log().admit() {
        tracing::error!(
            alarm = "policy_crypto_failure",
            op = op.name(),
            %error,
            suppressed,
            interval_seconds = INTERVAL_SECS,
            "JWT crypto backend failed; repeats are counted in `suppressed`"
        );
    }
}
