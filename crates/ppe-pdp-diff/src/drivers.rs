// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Evaluate one catalog case on one shipped dialect.

use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver as _};

use crate::cases::Case;

/// Factory `kind:` strings this harness drives.
///
/// Keep in lockstep with `praxis_policy::builtin_pdp_factories` (see the
/// facade crate test `every_builtin_pdp_kind_is_in_the_differential_harness`).
/// Public so that test imports this constant instead of duplicating the list.
pub const HARNESS_PDP_KINDS: &[&str] = &["cedar-direct", "cel", "opa"];

/// A shipped dialect the catalog evaluates. Adding a variant requires a
/// corresponding arm in [`evaluate`] — that is the harness side of
/// "not just the router."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    Cedar,
    Cel,
    Opa,
}

impl Dialect {
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::Cedar => "cedar-direct",
            Self::Cel => "cel",
            Self::Opa => "opa",
        }
    }

    pub(crate) const fn all() -> [Self; 3] {
        [Self::Cedar, Self::Cel, Self::Opa]
    }
}

/// Run the case's equivalent policy for `dialect` against the case bag.
pub(crate) async fn evaluate(dialect: Dialect, case: &Case) -> Result<PdpDecision, PdpError> {
    match dialect {
        Dialect::Cedar => evaluate_cedar(case).await,
        Dialect::Cel => evaluate_cel(case).await,
        Dialect::Opa => evaluate_opa(case).await,
    }
}

async fn evaluate_cedar(case: &Case) -> Result<PdpDecision, PdpError> {
    let resolver =
        praxis_policy_pdp_cedar_direct::CedarDirectResolver::from_policy_text(&case.cedar_policy)
            .map_err(|e| PdpError::Dispatch(e.to_string()))?;
    resolver.evaluate(&cedar_call(case), &case.bag).await
}

async fn evaluate_cel(case: &Case) -> Result<PdpDecision, PdpError> {
    let resolver = praxis_policy_pdp_cel::CelResolver::new();
    resolver.evaluate(&cel_call(case), &case.bag).await
}

async fn evaluate_opa(case: &Case) -> Result<PdpDecision, PdpError> {
    let resolver = praxis_policy_pdp_opa::OpaResolver::from_config(&serde_yaml::Value::Mapping(
        serde_yaml::Mapping::new(),
    ))
    .map_err(|e| PdpError::Dispatch(e.to_string()))?;
    resolver.evaluate(&opa_call(case), &case.bag).await
}

fn yaml_str(s: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(s.to_owned())
}

fn cedar_call(case: &Case) -> PdpCall {
    let mut resource = serde_yaml::Mapping::new();
    resource.insert(yaml_str("type"), yaml_str("Document"));
    resource.insert(yaml_str("id"), yaml_str("doc-1"));
    if let Some(attrs) = &case.cedar_resource_attrs {
        resource.insert(
            yaml_str("attributes"),
            serde_yaml::Value::Mapping(attrs.clone()),
        );
    }
    let mut args = serde_yaml::Mapping::new();
    args.insert(yaml_str("action"), yaml_str("Action::\"read\""));
    args.insert(yaml_str("resource"), serde_yaml::Value::Mapping(resource));
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::Value::Mapping(args),
    }
}

fn cel_call(case: &Case) -> PdpCall {
    let mut args = serde_yaml::Mapping::new();
    args.insert(yaml_str("expr"), yaml_str(&case.cel_expr));
    PdpCall {
        dialect: PdpDialect::Cel,
        args: serde_yaml::Value::Mapping(args),
    }
}

fn opa_call(case: &Case) -> PdpCall {
    let mut args = serde_yaml::Mapping::new();
    args.insert(yaml_str("query"), yaml_str(&case.opa_query));
    args.insert(yaml_str("module"), yaml_str(&case.opa_module));
    PdpCall {
        dialect: PdpDialect::Opa,
        args: serde_yaml::Value::Mapping(args),
    }
}
