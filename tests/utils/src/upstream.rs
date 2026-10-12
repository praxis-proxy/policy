// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! An in-process stand-in for the demo's `hr-mcp-server/server.py`.
//!
//! It answers MCP `tools/call` bodies with the same fixtures and logic and
//! records every request it saw, so a test asserts what reached the
//! upstream rather than what the engine said it would forward.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};

use serde_json::{Value, json};

use crate::idp::claims_of;

/// One request as the upstream received it.
#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    /// `params.name` of the call.
    pub tool: String,
    /// `params.arguments` of the call.
    pub arguments: Value,
    /// Request headers, names lowercased.
    pub headers: BTreeMap<String, String>,
}

impl UpstreamRequest {
    /// The claims of the JWT in `header`, decoded without verification, as
    /// the demo recorder reports them.
    #[must_use]
    pub fn jwt_claims(&self, header: &str) -> Option<Value> {
        self.headers.get(header).and_then(|v| claims_of(v))
    }
}

struct State {
    employees: BTreeMap<&'static str, Value>,
    sent_emails: usize,
    overrides: HashMap<String, Value>,
    seen: Vec<UpstreamRequest>,
}

/// The HR MCP server, minus the network.
pub struct Upstream {
    state: Mutex<State>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("calls", &self.requests().len())
            .finish()
    }
}

/// Return a fresh copy of the demo employee records.
fn employees() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "EMP-001234",
            json!({
                "employee_id": "EMP-001234", "name": "Jane Smith", "salary": 125_000,
                "bonus": 15_000, "ssn": "123-45-6789", "department": "Engineering",
                "internal_notes": "Performance review pending, do not disclose",
                "email": "jane.smith@corp.com", "title": "Senior Software Engineer",
            }),
        ),
        (
            "EMP-005678",
            json!({
                "employee_id": "EMP-005678", "name": "Bob Johnson", "salary": 145_000,
                "bonus": 25_000, "ssn": "234-56-7890", "department": "Marketing",
                "internal_notes": "Promotion candidate Q2",
                "email": "bob.johnson@corp.com", "title": "Marketing Manager",
            }),
        ),
        (
            "EMP-009012",
            json!({
                "employee_id": "EMP-009012", "name": "Alice Chen", "salary": 145_000,
                "bonus": 20_000, "ssn": "456-78-9012", "department": "Engineering",
                "internal_notes": "Team lead, retention risk",
                "email": "alice.chen@corp.com", "title": "Principal Engineer",
            }),
        ),
    ])
}

/// Return the demo repository records used by `search_repos`.
fn repos() -> Value {
    json!([
        {"name": "internal/web-app", "visibility": "internal", "stars": 24, "language": "TypeScript"},
        {"name": "internal/api-gateway", "visibility": "internal", "stars": 18, "language": "Rust"},
        {"name": "internal/data-pipeline", "visibility": "internal", "stars": 11, "language": "Python"},
        {"name": "public/showcase-site", "visibility": "public", "stars": 2840, "language": "Astro"},
        {"name": "external/partner-sdk", "visibility": "external", "stars": 47, "language": "Go"},
    ])
}

/// Read a string argument, using the demo server default when absent.
fn arg_str<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Python truthiness for the JSON values accepted by the demo server.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(v) => v.as_f64().is_some_and(|n| n != 0.0),
        Value::String(v) => !v.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
    }
}

/// The JSON inputs accepted by Python's `int(args.get("amount", 0))`.
fn python_int(value: Option<&Value>) -> Result<i64, String> {
    let Some(value) = value else { return Ok(0) };
    match value {
        Value::Bool(v) => Ok(i64::from(*v)),
        Value::Number(v) => {
            if let Some(n) = v.as_i64() {
                Ok(n)
            } else if let Some(n) = v.as_u64() {
                i64::try_from(n)
                    .map_err(|_error| "amount exceeds the test server's integer range".to_owned())
            } else {
                let n = v.as_f64().ok_or_else(|| "invalid amount".to_owned())?;
                // Exact 2^63 as an f64; decimal spelling trips the lossy-literal lint.
                let limit = f64::from_bits(0x43e0_0000_0000_0000);
                if !n.is_finite() || !(-limit..limit).contains(&n) {
                    return Err("amount exceeds the test server's integer range".to_owned());
                }
                #[expect(clippy::cast_possible_truncation, reason = "mirrors Python int()")]
                Ok(n as i64)
            }
        },
        Value::String(v) => v
            .trim()
            .parse::<i64>()
            .map_err(|_error| format!("invalid literal for int() with base 10: {v:?}")),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            let kind = match value {
                Value::Null => "NoneType",
                Value::Array(_) => "list",
                Value::Object(_) => "dict",
                Value::Bool(_) | Value::Number(_) | Value::String(_) => "unknown",
            };
            Err(format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{kind}'"
            ))
        },
    }
}

/// Project a record onto the keys requested by a tool.
fn pick(record: &Value, keys: &[&str]) -> Value {
    Value::Object(
        keys.iter()
            .filter_map(|k| record.get(*k).map(|v| ((*k).to_owned(), v.clone())))
            .collect(),
    )
}

impl State {
    /// `server.py`'s tool logic. `None` for an unknown tool.
    fn run(&mut self, tool: &str, args: &Value) -> Result<Option<Value>, String> {
        let not_found = |id: &str| json!({ "error": format!("Employee {id} not found") });
        let id = arg_str(args, "employee_id");
        Ok(Some(match tool {
            "get_compensation" => match self.employees.get(id) {
                None => not_found(id),
                Some(e) => {
                    let mut keys = vec![
                        "employee_id",
                        "name",
                        "salary",
                        "bonus",
                        "department",
                        "title",
                        "internal_notes",
                    ];
                    if args.get("include_ssn").is_some_and(truthy) {
                        keys.push("ssn");
                    }
                    pick(e, &keys)
                },
            },
            "send_email" => {
                self.sent_emails += 1;
                json!({
                    "status": "sent",
                    "message_id": format!("msg-{:04}", self.sent_emails),
                    "to": arg_str(args, "to"),
                    "subject": arg_str(args, "subject"),
                })
            },
            "display_compensation" => match self.employees.get(id) {
                None => not_found(id),
                Some(e) => {
                    let salary = e.get("salary").and_then(Value::as_i64).unwrap_or(0);
                    let band = match salary {
                        s if s >= 120_000 => "senior",
                        s if s >= 80_000 => "mid",
                        _ => "junior",
                    };
                    let mut out = pick(e, &["employee_id", "name", "department", "title"]);
                    out["salary_band"] = json!(band);
                    out["has_bonus"] = json!(e.get("bonus").and_then(Value::as_i64) > Some(0));
                    out
                },
            },
            "get_directory" => {
                let dept = arg_str(args, "department").to_lowercase();
                Value::Array(
                    self.employees
                        .values()
                        .filter(|e| {
                            dept.is_empty() || arg_str(e, "department").to_lowercase() == dept
                        })
                        .map(|e| pick(e, &["name", "department", "title", "email"]))
                        .collect(),
                )
            },
            "search_repos" => {
                let name = arg_str(args, "repo_name").to_lowercase();
                let vis = arg_str(args, "visibility").to_lowercase();
                let matches: Vec<Value> = repos()
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|r| {
                        name.is_empty() || arg_str(r, "name").to_lowercase().contains(&name)
                    })
                    .filter(|r| vis.is_empty() || arg_str(r, "visibility") == vis)
                    .cloned()
                    .collect();
                json!({
                    "matches": matches,
                    "query": { "repo_name": arg_str(args, "repo_name"), "visibility": arg_str(args, "visibility") },
                })
            },
            "adjust_compensation" => {
                let amount = python_int(args.get("amount"))?;
                match self.employees.get_mut(id) {
                    None => not_found(id),
                    Some(e) => {
                        let salary = e.get("salary").and_then(Value::as_i64).unwrap_or(0) + amount;
                        e["salary"] = json!(salary);
                        json!({
                            "status": "applied",
                            "employee_id": e["employee_id"],
                            "name": e["name"],
                            "adjustment": amount,
                            "new_salary": salary,
                        })
                    },
                }
            },
            _ => return Ok(None),
        }))
    }
}

impl Upstream {
    /// A fresh server with the demo fixtures and an empty request log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                employees: employees(),
                sent_emails: 0,
                overrides: HashMap::new(),
                seen: Vec::new(),
            }),
        }
    }

    /// Answer `tool` with `result` as the JSON-RPC `result` member, in place
    /// of the server's own. For response-side redaction cases that need a
    /// record shaped differently.
    #[must_use]
    pub fn with_result(self, tool: &str, result: Value) -> Self {
        self.lock().overrides.insert(tool.to_owned(), result);
        self
    }

    /// As [`Upstream::with_result`], on a server a host already owns.
    pub fn set_result(&self, tool: &str, result: Value) {
        self.lock().overrides.insert(tool.to_owned(), result);
    }

    /// Recover the upstream state lock even after a failed test.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Handle one JSON-RPC request body and return the response body.
    ///
    /// Only `tools/call` bodies are recorded, as in `server.py`.
    pub fn call(&self, body: &Value, headers: &HashMap<String, String>) -> Value {
        self.exchange(body, headers).0
    }

    /// As [`Upstream::call`], also returning the request as recorded, so a
    /// concurrent caller gets its own rather than the latest.
    pub fn exchange(
        &self,
        body: &Value,
        headers: &HashMap<String, String>,
    ) -> (Value, Option<UpstreamRequest>) {
        let rpc_id = body.get("id").cloned().unwrap_or(Value::Null);
        if body.get("method").and_then(Value::as_str) != Some("tools/call") {
            let reply = json!({ "jsonrpc": "2.0", "id": rpc_id, "result": { "tools": [] } });
            return (reply, None);
        }
        let params = body.get("params").cloned().unwrap_or(Value::Null);
        let tool = arg_str(&params, "name").to_owned();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let seen = UpstreamRequest {
            tool: tool.clone(),
            arguments: arguments.clone(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v.clone()))
                .collect(),
        };
        let mut state = self.lock();
        state.seen.push(seen.clone());

        if let Some(result) = state.overrides.get(&tool) {
            let reply = json!({ "jsonrpc": "2.0", "id": rpc_id, "result": result });
            return (reply, Some(seen));
        }
        let reply = match state.run(&tool, &arguments) {
            Ok(Some(out)) => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&out).unwrap_or_default() }],
                },
            }),
            Ok(None) => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": { "code": -32601, "message": format!("Unknown tool: {tool}") },
            }),
            Err(message) => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": { "code": -32000, "message": message },
            }),
        };
        (reply, Some(seen))
    }

    /// Every recorded request, in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<UpstreamRequest> {
        self.lock().seen.clone()
    }
}
