// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashSet;

use regorus::Engine;
use regorus::unstable::{Expr, Literal, Module, Query, Rule, RuleHead};

/// Return whether the most recently loaded Rego module reads
/// `input.metadata`, including through a variable bound to `input`.
pub(super) fn last_module_references_metadata(engine: &mut Engine) -> bool {
    engine
        .get_modules()
        .last()
        .is_some_and(|module| module_references_metadata(module))
}

/// Return whether a valid Rego module reads `input.metadata`.
pub(super) fn source_references_metadata(source: &str) -> bool {
    let mut engine = Engine::new();
    engine
        .add_policy("metadata-analysis.rego".to_owned(), source.to_owned())
        .is_ok()
        && last_module_references_metadata(&mut engine)
}

fn module_references_metadata(module: &Module) -> bool {
    let aliases = module_input_aliases(module);
    if module
        .imports
        .iter()
        .any(|import| expression_references_metadata(&import.refr, &aliases))
    {
        return true;
    }

    module.policy.iter().any(|rule| match rule.as_ref() {
        Rule::Spec { head, bodies, .. } => {
            let head_expressions = rule_head_expressions(head);
            head_expressions
                .iter()
                .any(|expression| expression_references_metadata(expression, &aliases))
                || bodies.iter().any(|body| {
                    let mut associated = rule_head_expressions(head);
                    if let Some(assign) = &body.assign {
                        associated.push(assign.value.as_ref());
                    }
                    query_references_metadata(&body.query, &associated, &aliases)
                })
        },
        Rule::Default {
            refr, args, value, ..
        } => {
            let mut expressions = Vec::with_capacity(args.len().saturating_add(2));
            expressions.push(refr.as_ref());
            expressions.extend(args.iter().map(AsRef::as_ref));
            expressions.push(value.as_ref());
            expressions
                .iter()
                .any(|expression| expression_references_metadata(expression, &aliases))
        },
    })
}

fn query_references_metadata(
    query: &Query,
    associated: &[&Expr],
    inherited_aliases: &HashSet<String>,
) -> bool {
    let mut aliases = inherited_aliases.clone();
    let mut alias_pairs = Vec::new();

    for expression in associated {
        collect_alias_pairs(expression, &mut alias_pairs);
    }
    for statement in &query.stmts {
        collect_statement_alias_pairs(statement, &mut alias_pairs);
    }
    close_aliases(&mut aliases, &alias_pairs);

    associated
        .iter()
        .any(|expression| expression_references_metadata(expression, &aliases))
        || query
            .stmts
            .iter()
            .any(|statement| statement_references_metadata(statement, &aliases))
}

fn collect_statement_alias_pairs(
    statement: &regorus::unstable::LiteralStmt,
    pairs: &mut Vec<(String, String)>,
) {
    match &statement.literal {
        Literal::SomeVars { .. } => {},
        Literal::SomeIn {
            key,
            value,
            collection,
            ..
        } => {
            if let Some(key) = key {
                collect_alias_pairs(key, pairs);
            }
            collect_alias_pairs(value, pairs);
            collect_alias_pairs(collection, pairs);
        },
        Literal::Expr { expr, .. } | Literal::NotExpr { expr, .. } => {
            collect_alias_pairs(expr, pairs);
        },
        Literal::Every { domain, .. } => collect_alias_pairs(domain, pairs),
    }
    for modifier in &statement.with_mods {
        collect_alias_pairs(&modifier.refr, pairs);
        collect_alias_pairs(&modifier.r#as, pairs);
    }
}

fn collect_alias_pairs(expression: &Expr, pairs: &mut Vec<(String, String)>) {
    match expression {
        Expr::ArrayCompr { .. } | Expr::SetCompr { .. } | Expr::ObjectCompr { .. } => {},
        Expr::AssignExpr { lhs, rhs, .. } => {
            if let (Some(lhs), Some(rhs)) = (variable_name(lhs), variable_name(rhs)) {
                pairs.push((lhs.to_owned(), rhs.to_owned()));
            }
            collect_alias_pairs(lhs, pairs);
            collect_alias_pairs(rhs, pairs);
        },
        Expr::Array { items, .. } | Expr::Set { items, .. } => {
            for item in items {
                collect_alias_pairs(item, pairs);
            }
        },
        Expr::Object { fields, .. } => {
            for (_, key, value) in fields {
                collect_alias_pairs(key, pairs);
                collect_alias_pairs(value, pairs);
            }
        },
        Expr::Call { fcn, params, .. } => {
            collect_alias_pairs(fcn, pairs);
            for parameter in params {
                collect_alias_pairs(parameter, pairs);
            }
        },
        Expr::UnaryExpr { expr, .. } => collect_alias_pairs(expr, pairs),
        Expr::RefDot { refr, .. } => collect_alias_pairs(refr, pairs),
        Expr::RefBrack { refr, index, .. } => {
            collect_alias_pairs(refr, pairs);
            collect_alias_pairs(index, pairs);
        },
        Expr::BinExpr { lhs, rhs, .. }
        | Expr::BoolExpr { lhs, rhs, .. }
        | Expr::ArithExpr { lhs, rhs, .. } => {
            collect_alias_pairs(lhs, pairs);
            collect_alias_pairs(rhs, pairs);
        },
        Expr::Membership {
            key,
            value,
            collection,
            ..
        } => {
            if let Some(key) = key {
                collect_alias_pairs(key, pairs);
            }
            collect_alias_pairs(value, pairs);
            collect_alias_pairs(collection, pairs);
        },
        Expr::String { .. }
        | Expr::RawString { .. }
        | Expr::Number { .. }
        | Expr::Bool { .. }
        | Expr::Null { .. }
        | Expr::Var { .. } => {},
    }
}

fn statement_references_metadata(
    statement: &regorus::unstable::LiteralStmt,
    aliases: &HashSet<String>,
) -> bool {
    let literal_references = match &statement.literal {
        Literal::SomeVars { .. } => false,
        Literal::SomeIn {
            key,
            value,
            collection,
            ..
        } => {
            key.as_ref()
                .is_some_and(|key| expression_references_metadata(key, aliases))
                || expression_references_metadata(value, aliases)
                || expression_references_metadata(collection, aliases)
        },
        Literal::Expr { expr, .. } | Literal::NotExpr { expr, .. } => {
            expression_references_metadata(expr, aliases)
        },
        Literal::Every { domain, query, .. } => {
            expression_references_metadata(domain, aliases)
                || query_references_metadata(query, &[], aliases)
        },
    };

    literal_references
        || statement.with_mods.iter().any(|modifier| {
            expression_references_metadata(&modifier.refr, aliases)
                || expression_references_metadata(&modifier.r#as, aliases)
        })
}

fn expression_references_metadata(expression: &Expr, aliases: &HashSet<String>) -> bool {
    // Keep this match exhaustive so new Regorus expression forms require an
    // explicit metadata-dependency decision instead of silently failing open.
    match expression {
        Expr::RefDot { refr, field, .. } => {
            if is_alias(refr, aliases) {
                value_is_metadata(&field.1)
            } else {
                expression_references_metadata(refr, aliases)
            }
        },
        Expr::RefBrack { refr, index, .. } => {
            if is_alias(refr, aliases) {
                index_may_select_metadata(index)
            } else {
                expression_references_metadata(refr, aliases)
                    || expression_references_metadata(index, aliases)
            }
        },
        Expr::ArrayCompr { term, query, .. } | Expr::SetCompr { term, query, .. } => {
            query_references_metadata(query, &[term.as_ref()], aliases)
        },
        Expr::ObjectCompr {
            key, value, query, ..
        } => query_references_metadata(query, &[key.as_ref(), value.as_ref()], aliases),
        Expr::Array { items, .. } | Expr::Set { items, .. } => items
            .iter()
            .any(|item| expression_references_metadata(item, aliases)),
        Expr::Object { fields, .. } => fields.iter().any(|(_, key, value)| {
            expression_references_metadata(key, aliases)
                || expression_references_metadata(value, aliases)
        }),
        Expr::Call { fcn, params, .. } => {
            expression_references_metadata(fcn, aliases)
                || params.iter().any(|parameter| {
                    is_alias(parameter, aliases)
                        || expression_references_metadata(parameter, aliases)
                })
        },
        Expr::UnaryExpr { expr, .. } => expression_references_metadata(expr, aliases),
        Expr::BinExpr { lhs, rhs, .. }
        | Expr::BoolExpr { lhs, rhs, .. }
        | Expr::ArithExpr { lhs, rhs, .. }
        | Expr::AssignExpr { lhs, rhs, .. } => {
            expression_references_metadata(lhs, aliases)
                || expression_references_metadata(rhs, aliases)
        },
        Expr::Membership {
            key,
            value,
            collection,
            ..
        } => {
            key.as_ref()
                .is_some_and(|key| expression_references_metadata(key, aliases))
                || expression_references_metadata(value, aliases)
                || expression_references_metadata(collection, aliases)
        },
        Expr::String { .. }
        | Expr::RawString { .. }
        | Expr::Number { .. }
        | Expr::Bool { .. }
        | Expr::Null { .. } => false,
        Expr::Var { .. } => is_alias(expression, aliases),
    }
}

fn rule_head_expressions(head: &RuleHead) -> Vec<&Expr> {
    match head {
        RuleHead::Compr { refr, assign, .. } => {
            let mut expressions = vec![refr.as_ref()];
            if let Some(assign) = assign {
                expressions.push(assign.value.as_ref());
            }
            expressions
        },
        RuleHead::Set { refr, key, .. } => {
            let mut expressions = vec![refr.as_ref()];
            if let Some(key) = key {
                expressions.push(key.as_ref());
            }
            expressions
        },
        RuleHead::Func {
            refr, args, assign, ..
        } => {
            let mut expressions = Vec::with_capacity(args.len().saturating_add(2));
            expressions.push(refr.as_ref());
            expressions.extend(args.iter().map(AsRef::as_ref));
            if let Some(assign) = assign {
                expressions.push(assign.value.as_ref());
            }
            expressions
        },
    }
}

fn close_aliases(aliases: &mut HashSet<String>, pairs: &[(String, String)]) {
    loop {
        let mut changed = false;
        for (left, right) in pairs {
            if aliases.contains(left) {
                changed |= aliases.insert(right.clone());
            }
            if aliases.contains(right) {
                changed |= aliases.insert(left.clone());
            }
        }
        if !changed {
            break;
        }
    }
}

fn input_aliases() -> HashSet<String> {
    HashSet::from(["input".to_owned()])
}

fn module_input_aliases(module: &Module) -> HashSet<String> {
    let mut aliases = input_aliases();
    for import in &module.imports {
        if is_alias(&import.refr, &aliases)
            && let Some(alias) = &import.r#as
        {
            aliases.insert(alias.text().to_owned());
        }
    }
    aliases
}

fn is_alias(expression: &Expr, aliases: &HashSet<String>) -> bool {
    variable_name(expression).is_some_and(|name| aliases.contains(name))
}

fn variable_name(expression: &Expr) -> Option<&str> {
    match expression {
        Expr::Var { value, .. } => value.as_string().ok().map(AsRef::as_ref),
        _ => None,
    }
}

fn index_may_select_metadata(expression: &Expr) -> bool {
    match expression {
        Expr::String { value, .. } | Expr::RawString { value, .. } => value_is_metadata(value),
        Expr::Number { .. } | Expr::Bool { .. } | Expr::Null { .. } => false,
        _ => true,
    }
}

fn value_is_metadata(value: &regorus::Value) -> bool {
    value
        .as_string()
        .is_ok_and(|value| value.as_ref() == "metadata")
}
