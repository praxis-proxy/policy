// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A step's expressions compile once and are cached by the step's arguments.
// Steps come from config, so the cache holds the policy's static set; the cap
// only trips on a templating bug, and past it a step compiles per request.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use cel::objects::Key;
use cel::{Context, ExecutionError, Program, Value};
use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
use praxis_policy_core::http::{HttpRequest, HttpTransport};
use praxis_policy_core::http_retry::{RetryPolicy, execute_with_retry};

use crate::kubernetes::reviewer_token::ReviewerToken;
use crate::pdps::cel::activation::bag_to_context;
use crate::pdps::cel::resolver::eval_error_category;
use crate::pdps::kubernetes_sar::config::{
    Attributes, DEFAULT_GROUPS, DEFAULT_USER, OnError, StepArgs, SubjectAccessReviewConfig,
    SubjectExprs,
};
use crate::pdps::kubernetes_sar::review::{
    REVIEW_PATH, ReviewRequest, ReviewSpec, Verdict, read_verdict,
};
use crate::pdps::stack;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The dialect a `pdp(kubernetes-sar):` step routes to.
pub const DIALECT: &str = "kubernetes-sar";

/// Distinct step argument sets kept compiled.
const MAX_COMPILED_STEPS: usize = 1_024;

/// A ceiling on the buffered review answer.
const RESPONSE_MAX_BYTES: usize = 65_536; // 64 KiB

/// The error for an `extra` expression of the wrong shape.
const EXTRA_SHAPE: &str = "`subject.extra` must evaluate to a map of string to list of strings";

/// The group the API server lets skip authorization entirely. The review
/// takes PPE's groups on trust, so sending this one would allow anything, and
/// no binding in the cluster would show why. No `ServiceAccount` token
/// carries it, so a review naming it has groups from somewhere else.
const SUPERUSER_GROUP: &str = "system:masters";

// -----------------------------------------------------------------------------
// SubjectAccessReviewResolver
// -----------------------------------------------------------------------------

/// Decides a `pdp(kubernetes-sar):` step by asking the Kubernetes API server.
pub struct SubjectAccessReviewResolver {
    compiled: RwLock<HashMap<String, Arc<CompiledStep>>>,
    connect_timeout: Option<Duration>,
    defaults: SubjectExprs,
    endpoint: String,
    on_error: OnError,
    reviewer: ReviewerToken,
    timeout: Duration,
    transport: Arc<dyn HttpTransport>,
}

impl SubjectAccessReviewResolver {
    /// Build the resolver, reading the reviewer token once.
    ///
    /// # Errors
    ///
    /// Invalid connection settings, an unreadable reviewer token, or a
    /// `subject` default that is not valid CEL.
    pub fn new(
        config: SubjectAccessReviewConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, String> {
        config.api_server.validate()?;
        CompiledSubject::compile(&SubjectExprs::default(), &config.subject)?;
        let reviewer = ReviewerToken::load(config.api_server.reviewer_token.clone())
            .map_err(|e| format!("`api_server.reviewer_token`: {e}"))?;
        Ok(Self {
            compiled: RwLock::new(HashMap::new()),
            connect_timeout: config
                .api_server
                .connect_timeout_secs
                .map(Duration::from_secs),
            defaults: config.subject,
            endpoint: config.api_server.endpoint(REVIEW_PATH),
            on_error: config.on_error,
            reviewer,
            timeout: Duration::from_secs(config.api_server.timeout_secs),
            transport,
        })
    }

    /// The compiled form of a step's arguments.
    fn step(&self, args: &serde_yaml::Value) -> Result<Arc<CompiledStep>, String> {
        let key = serde_yaml::to_string(args).map_err(|e| e.to_string())?;
        if let Some(hit) = self
            .compiled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(hit));
        }

        let step = Arc::new(CompiledStep::compile(args, &self.defaults)?);
        let mut compiled = self
            .compiled
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if compiled.len() < MAX_COMPILED_STEPS {
            compiled.insert(key, Arc::clone(&step));
        } else {
            tracing::warn!("kubernetes-sar: compiled-step cache is full; compiling per request");
        }
        Ok(step)
    }

    /// Send the review and read the verdict.
    async fn review(&self, spec: ReviewSpec) -> Result<Verdict, String> {
        let body = serde_json::to_vec(&ReviewRequest::new(spec))
            .map_err(|e| format!("could not encode the review: {e}"))?;
        let reviewer = self.reviewer.get().await;
        let mut request = HttpRequest::post(&self.endpoint, body.into())
            .timeout(self.timeout)
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/json")
            .and_then(|r| r.header("accept", "application/json"))
            .and_then(|r| r.header("authorization", format!("Bearer {}", reviewer.as_str())))
            .map_err(|e| format!("could not build the review request: {e}"))?;
        if let Some(connect_timeout) = self.connect_timeout {
            request = request.connect_timeout(connect_timeout);
        }

        // A review changes nothing on the server, so retrying is safe. The
        // budget keeps every attempt and backoff inside one `timeout_secs`:
        // a PDP gets no invocation deadline to cap the loop otherwise.
        let retry = RetryPolicy::idempotent().with_total_budget(self.timeout);
        let response = execute_with_retry(self.transport.as_ref(), request, retry)
            .await
            .map_err(|e| format!("the API server could not be reached: {e}"))?;

        match response.status {
            200 | 201 => read_verdict(&response.body),
            status @ (401 | 403) => Err(format!(
                "the API server refused the reviewer credential ({status}): check the reviewer \
                 token and that its identity may `create` `subjectaccessreviews`"
            )),
            status => Err(format!("the API server answered {status}")),
        }
    }

    /// The outcome when the API server gave no answer.
    ///
    /// A deny is returned as an error, which the evaluator turns into a
    /// denial and a decision cache never stores, so an outage's deny does not
    /// outlive the outage. The error text becomes the denial's reason, which
    /// can reach the client, so the cause goes only to the log.
    fn on_error_outcome(&self, cause: &str) -> Result<PdpDecision, PdpError> {
        match self.on_error {
            OnError::Deny => {
                tracing::warn!(
                    cause,
                    "kubernetes-sar: no answer from the API server; denying"
                );
                Err(PdpError::Dispatch(
                    "kubernetes-sar: the API server gave no answer".to_owned(),
                ))
            },
            OnError::Allow => {
                tracing::error!(
                    cause,
                    "kubernetes-sar: no answer from the API server; allowing under \
                     `on_error: allow`"
                );
                Ok(PdpDecision {
                    decision: Decision::Allow,
                    diagnostics: vec![format!("kubernetes-sar: {cause}")],
                })
            },
        }
    }
}

#[async_trait]
impl PdpResolver for SubjectAccessReviewResolver {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Custom(DIALECT.to_owned())
    }

    fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
        self.step(&call.args).map(|_compiled| ())
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        self.evaluate_structured(call, bag, &StructuredInput::default())
            .await
    }

    async fn evaluate_structured(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<PdpDecision, PdpError> {
        let spec = self.step(&call.args).and_then(|step| {
            stack::guarded(|| step.spec(&bag_to_context(bag, &serde_yaml::Value::Null, structured)))
        });
        let spec = match spec {
            Ok(spec) => spec,
            Err(cause) => {
                tracing::debug!(cause, "kubernetes-sar: could not build the review; denying");
                return Ok(deny(vec![format!("kubernetes-sar: {cause}")]));
            },
        };

        match self.review(spec).await {
            Ok(Verdict::Allowed(diagnostics)) => Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics,
            }),
            Ok(Verdict::NotAllowed(diagnostics)) => Ok(deny(diagnostics)),
            Err(cause) => self.on_error_outcome(&cause),
        }
    }
}

// -----------------------------------------------------------------------------
// Compiled Steps
// -----------------------------------------------------------------------------

/// A step with every expression compiled and its subject defaults applied.
struct CompiledStep {
    attributes: Attributes<Program>,
    subject: CompiledSubject,
}

struct CompiledSubject {
    extra: Option<Program>,
    groups: Program,
    uid: Option<Program>,
    user: Program,
}

impl CompiledStep {
    fn compile(args: &serde_yaml::Value, defaults: &SubjectExprs) -> Result<Self, String> {
        let args: StepArgs = serde_yaml::from_value(args.clone())
            .map_err(|e| format!("`pdp({DIALECT})` step: {e}"))?;
        Ok(Self {
            attributes: args
                .attributes
                .try_map(|field, expr| compile(field, expr))?,
            subject: CompiledSubject::compile(&args.subject, defaults)?,
        })
    }

    /// Evaluate every expression into the review's `spec`.
    fn spec(&self, ctx: &Context<'_, '_>) -> Result<ReviewSpec, String> {
        let user = string(&self.subject.user, ctx, "subject.user")?;
        if user.is_empty() {
            return Err("`subject.user` is empty, so there is no one to review".to_owned());
        }
        let groups = strings(&self.subject.groups, ctx, "subject.groups")?;
        if groups.iter().any(|group| group == SUPERUSER_GROUP) {
            return Err(format!(
                "`subject.groups` names `{SUPERUSER_GROUP}`, which skips authorization; refusing \
                 to send it"
            ));
        }
        Ok(ReviewSpec {
            attributes: self
                .attributes
                .try_map(|field, program| string(program, ctx, field))?,
            extra: match &self.subject.extra {
                Some(extra) => string_map(extra, ctx)?,
                None => BTreeMap::new(),
            },
            groups,
            uid: optional(self.subject.uid.as_ref(), ctx, "subject.uid")?,
            user,
        })
    }
}

impl CompiledSubject {
    /// Compile the step's subject, falling back field by field to the block's.
    fn compile(step: &SubjectExprs, block: &SubjectExprs) -> Result<Self, String> {
        let pick = |step: &Option<String>, block: &Option<String>| {
            step.as_ref().or(block.as_ref()).cloned()
        };
        let user = pick(&step.user, &block.user).unwrap_or_else(|| DEFAULT_USER.to_owned());
        let groups = pick(&step.groups, &block.groups).unwrap_or_else(|| DEFAULT_GROUPS.to_owned());
        Ok(Self {
            extra: pick(&step.extra, &block.extra)
                .map(|expr| compile("subject.extra", &expr))
                .transpose()?,
            groups: compile("subject.groups", &groups)?,
            uid: pick(&step.uid, &block.uid)
                .map(|expr| compile("subject.uid", &expr))
                .transpose()?,
            user: compile("subject.user", &user)?,
        })
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// A denial carrying the API server's or the policy's own explanation.
fn deny(diagnostics: Vec<String>) -> PdpDecision {
    PdpDecision {
        decision: Decision::Deny {
            reason: Some("not allowed by Kubernetes authorization".to_owned()),
            rule_source: DIALECT.to_owned(),
        },
        diagnostics,
    }
}

fn compile(field: &str, expr: &str) -> Result<Program, String> {
    Program::compile(expr).map_err(|e| format!("`{field}` is not valid CEL: {e}"))
}

/// Why an expression failed, without any value from the request, since the
/// text reaches logs and audit diagnostics.
fn eval_failed(field: &str, program: &Program, error: &ExecutionError) -> String {
    let category = eval_error_category(error, &program.references());
    format!("`{field}` could not be evaluated: {category}")
}

fn string(program: &Program, ctx: &Context<'_, '_>, field: &str) -> Result<String, String> {
    match program.execute(ctx) {
        Ok(Value::String(text)) => Ok(Arc::unwrap_or_clone(text)),
        Ok(_other) => Err(format!("`{field}` must evaluate to a string")),
        Err(e) => Err(eval_failed(field, program, &e)),
    }
}

fn optional(
    program: Option<&Program>,
    ctx: &Context<'_, '_>,
    field: &str,
) -> Result<Option<String>, String> {
    program
        .map(|program| string(program, ctx, field))
        .transpose()
}

fn strings(program: &Program, ctx: &Context<'_, '_>, field: &str) -> Result<Vec<String>, String> {
    match program.execute(ctx) {
        Ok(Value::List(items)) => string_list(&items, field),
        Ok(_other) => Err(format!("`{field}` must evaluate to a list of strings")),
        Err(e) => Err(eval_failed(field, program, &e)),
    }
}

fn string_list(items: &[Value], field: &str) -> Result<Vec<String>, String> {
    items
        .iter()
        .map(|item| match item {
            Value::String(text) => Ok(text.as_str().to_owned()),
            _ => Err(format!("`{field}` must evaluate to a list of strings")),
        })
        .collect()
}

fn string_map(
    program: &Program,
    ctx: &Context<'_, '_>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let Value::Map(map) = program
        .execute(ctx)
        .map_err(|e| eval_failed("subject.extra", program, &e))?
    else {
        return Err(EXTRA_SHAPE.to_owned());
    };
    map.map
        .iter()
        .map(|(key, value)| match (key, value) {
            (Key::String(key), Value::List(items)) => Ok((
                key.as_str().to_owned(),
                string_list(items, "subject.extra")?,
            )),
            _ => Err(EXTRA_SHAPE.to_owned()),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn an_evaluation_error_names_the_field_and_not_the_request_value() {
        let program =
            compile("resource_attributes.name", "{'known': 'x'}[args.tenant]").expect("valid CEL");
        let mut ctx = Context::default();
        ctx.add_variable_from_value(
            "args",
            HashMap::from([("tenant".to_owned(), "acme-private-tenant".to_owned())]),
        );

        let error = string(&program, &ctx, "resource_attributes.name")
            .expect_err("the key is not in the map");

        assert!(
            error.contains("`resource_attributes.name`"),
            "the field is named: {error}"
        );
        assert!(
            !error.contains("acme-private-tenant"),
            "a key computed from the request must not reach logs or audit: {error}"
        );
    }
}
