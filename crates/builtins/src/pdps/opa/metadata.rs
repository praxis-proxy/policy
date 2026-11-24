// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::{HashMap, HashSet};

use regorus::Engine;
use regorus::unstable::{Expr, Literal, Module, Query, Rule, RuleHead};

type RulePath = Vec<String>;

#[derive(Clone, Debug, Default)]
pub(super) struct MetadataDependencies {
    direct: HashSet<RulePath>,
    edges: HashMap<RulePath, HashSet<RulePath>>,
}

impl MetadataDependencies {
    pub(super) fn from_engine(engine: &mut Engine) -> Self {
        let modules = engine.get_modules();
        let mut analysis = Self::default();
        let mut known = HashSet::new();
        for module in modules {
            let package = expression_path(&module.package.refr).unwrap_or_default();
            for rule in &module.policy {
                if let Some(name) = rule_name(rule, &package) {
                    known.insert(name);
                }
            }
        }
        for module in modules {
            analysis.add_module(module, &known);
        }
        analysis
    }

    pub(super) fn query_requires_metadata(&self, query: &str) -> bool {
        let Some(root) = normalize_query_path(query) else {
            return true;
        };
        let mut pending = self
            .edges
            .keys()
            .filter(|rule| rule.starts_with(&root))
            .cloned()
            .collect::<Vec<_>>();
        let mut seen = HashSet::new();
        while let Some(rule) = pending.pop() {
            if !seen.insert(rule.clone()) {
                continue;
            }
            if self.direct.contains(&rule) {
                return true;
            }
            if let Some(dependencies) = self.edges.get(&rule) {
                pending.extend(dependencies.iter().cloned());
            }
        }
        false
    }

    fn add_module(&mut self, module: &Module, known: &HashSet<RulePath>) {
        let package = expression_path(&module.package.refr).unwrap_or_default();
        let input_aliases = module_input_aliases(module);
        let import_aliases = module_import_aliases(module);
        for rule in &module.policy {
            let Some(name) = rule_name(rule, &package) else {
                continue;
            };
            if rule_references_metadata(rule, &input_aliases) {
                self.direct.insert(name.clone());
            }
            let mut references = HashSet::new();
            collect_rule_references(rule, &package, &import_aliases, &mut references);
            if references.iter().any(|reference| {
                matches!(reference.as_slice(), [input, metadata, ..] if input == "input" && metadata == "metadata")
            }) {
                self.direct.insert(name.clone());
            }
            let dependencies = references.into_iter().flat_map(|candidate| {
                known
                    .iter()
                    .filter(move |rule| rule.starts_with(&candidate))
                    .cloned()
            });
            self.edges.entry(name).or_default().extend(dependencies);
        }
    }
}

fn normalize_query_path(query: &str) -> Option<RulePath> {
    let query = query.trim();
    (query.starts_with("data.")
        && query.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }))
    .then(|| query.split('.').map(str::to_owned).collect())
}

fn rule_name(rule: &Rule, package: &[String]) -> Option<RulePath> {
    let head = match rule {
        Rule::Spec { head, .. } => match head {
            RuleHead::Compr { refr, .. }
            | RuleHead::Set { refr, .. }
            | RuleHead::Func { refr, .. } => refr.as_ref(),
        },
        Rule::Default { refr, .. } => refr.as_ref(),
    };
    let mut path = vec!["data".to_owned()];
    path.extend(package.iter().cloned());
    path.extend(expression_path(head)?);
    Some(path)
}

fn rule_references_metadata(rule: &Rule, aliases: &HashSet<String>) -> bool {
    match rule {
        Rule::Spec { head, bodies, .. } => {
            let head_expressions = rule_head_expressions(head);
            head_expressions
                .iter()
                .any(|expression| expression_references_metadata(expression, aliases))
                || bodies.iter().any(|body| {
                    let mut associated = rule_head_expressions(head);
                    if let Some(assign) = &body.assign {
                        associated.push(assign.value.as_ref());
                    }
                    query_references_metadata(&body.query, &associated, aliases)
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
                .any(|expression| expression_references_metadata(expression, aliases))
        },
    }
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

fn expression_path(expression: &Expr) -> Option<Vec<String>> {
    match expression {
        Expr::Var { value, .. } => value.as_string().ok().map(|name| vec![name.to_string()]),
        Expr::RefDot { refr, field, .. } => {
            let mut path = expression_path(refr)?;
            path.push(field.1.as_string().ok()?.to_string());
            Some(path)
        },
        Expr::RefBrack { refr, index, .. } => {
            let mut path = expression_path(refr)?;
            let part = match index.as_ref() {
                Expr::String { value, .. } | Expr::RawString { value, .. } => {
                    value.as_string().ok()?.to_string()
                },
                _ => return Some(path),
            };
            path.push(part);
            Some(path)
        },
        _ => None,
    }
}

fn expression_path_info(expression: &Expr) -> Option<(Vec<String>, bool)> {
    match expression {
        Expr::RefBrack { refr, index, .. } => {
            let (path, expands) = expression_path_info(refr)?;
            match index.as_ref() {
                Expr::String { value, .. } | Expr::RawString { value, .. } => {
                    let mut path = path;
                    path.push(value.as_string().ok()?.to_string());
                    Some((path, expands))
                },
                _ => Some((path, true)),
            }
        },
        Expr::RefDot { refr, field, .. } => {
            let (mut path, expands) = expression_path_info(refr)?;
            path.push(field.1.as_string().ok()?.to_string());
            Some((path, expands))
        },
        Expr::Var { value, .. } => value
            .as_string()
            .ok()
            .map(|name| (vec![name.to_string()], false)),
        _ => None,
    }
}

fn module_import_aliases(module: &Module) -> HashMap<String, Vec<String>> {
    module
        .imports
        .iter()
        .filter_map(|import| {
            let path = expression_path(&import.refr)?;
            let alias = import
                .r#as
                .as_ref()
                .map_or_else(|| path.last().cloned(), |span| Some(span.text().to_owned()))?;
            Some((alias, path))
        })
        .collect()
}

fn collect_rule_references(
    rule: &Rule,
    package: &[String],
    imports: &HashMap<String, Vec<String>>,
    out: &mut HashSet<RulePath>,
) {
    match rule {
        Rule::Spec { head, bodies, .. } => {
            match head {
                RuleHead::Compr { refr, assign, .. } => {
                    collect_head_index_references(refr, package, imports, out);
                    if let Some(assign) = assign {
                        collect_expression_references(&assign.value, package, imports, out);
                    }
                },
                RuleHead::Func {
                    refr, args, assign, ..
                } => {
                    collect_head_index_references(refr, package, imports, out);
                    for arg in args {
                        collect_expression_references(arg, package, imports, out);
                    }
                    if let Some(assign) = assign {
                        collect_expression_references(&assign.value, package, imports, out);
                    }
                },
                RuleHead::Set { key, .. } => {
                    if let Some(key) = key {
                        collect_expression_references(key, package, imports, out);
                    }
                },
            }
            for body in bodies {
                if let Some(assign) = &body.assign {
                    collect_expression_references(&assign.value, package, imports, out);
                }
                collect_query_references(&body.query, package, imports, out);
            }
        },
        Rule::Default { value, .. } => {
            collect_expression_references(value, package, imports, out);
        },
    }
}

fn collect_head_index_references(
    expression: &Expr,
    package: &[String],
    imports: &HashMap<String, Vec<String>>,
    out: &mut HashSet<RulePath>,
) {
    match expression {
        Expr::RefBrack { refr, index, .. } => {
            collect_head_index_references(refr, package, imports, out);
            collect_expression_references(index, package, imports, out);
        },
        Expr::RefDot { refr, .. } => collect_head_index_references(refr, package, imports, out),
        _ => {},
    }
}

fn collect_query_references(
    query: &Query,
    package: &[String],
    imports: &HashMap<String, Vec<String>>,
    out: &mut HashSet<RulePath>,
) {
    for statement in &query.stmts {
        match &statement.literal {
            Literal::SomeVars { .. } => {},
            Literal::SomeIn {
                key,
                value,
                collection,
                ..
            } => {
                if let Some(key) = key {
                    collect_expression_references(key, package, imports, out);
                }
                collect_expression_references(value, package, imports, out);
                collect_expression_references(collection, package, imports, out);
            },
            Literal::Expr { expr, .. } | Literal::NotExpr { expr, .. } => {
                collect_expression_references(expr, package, imports, out);
            },
            Literal::Every { domain, query, .. } => {
                collect_expression_references(domain, package, imports, out);
                collect_query_references(query, package, imports, out);
            },
        }
        for modifier in &statement.with_mods {
            collect_expression_references(&modifier.refr, package, imports, out);
            collect_expression_references(&modifier.r#as, package, imports, out);
        }
    }
}

fn collect_expression_references(
    expression: &Expr,
    package: &[String],
    imports: &HashMap<String, Vec<String>>,
    out: &mut HashSet<RulePath>,
) {
    if let Some((path, expands)) = expression_path_info(expression) {
        let resolved = if path.first().is_some_and(|part| part == "data") {
            Some(path)
        } else if let Some(imported) = path.first().and_then(|head| imports.get(head)) {
            let mut resolved = imported.clone();
            resolved.extend(path.into_iter().skip(1));
            Some(resolved)
        } else if path
            .first()
            .is_some_and(|head| !matches!(head.as_str(), "input" | "data"))
        {
            let mut resolved = vec!["data".to_owned()];
            resolved.extend(package.iter().cloned());
            resolved.extend(path);
            Some(resolved)
        } else {
            None
        };
        if let Some(mut resolved) = resolved {
            if expands {
                while resolved.len() > 1 {
                    out.insert(resolved.clone());
                    resolved.pop();
                }
            } else {
                out.insert(resolved);
            }
        }
    }

    match expression {
        Expr::ArrayCompr { term, query, .. } | Expr::SetCompr { term, query, .. } => {
            collect_expression_references(term, package, imports, out);
            collect_query_references(query, package, imports, out);
        },
        Expr::ObjectCompr {
            key, value, query, ..
        } => {
            collect_expression_references(key, package, imports, out);
            collect_expression_references(value, package, imports, out);
            collect_query_references(query, package, imports, out);
        },
        Expr::Array { items, .. } | Expr::Set { items, .. } => {
            for item in items {
                collect_expression_references(item, package, imports, out);
            }
        },
        Expr::Object { fields, .. } => {
            for (_, key, value) in fields {
                collect_expression_references(key, package, imports, out);
                collect_expression_references(value, package, imports, out);
            }
        },
        Expr::Call { fcn, params, .. } => {
            collect_expression_references(fcn, package, imports, out);
            for parameter in params {
                collect_expression_references(parameter, package, imports, out);
            }
        },
        Expr::UnaryExpr { expr, .. } | Expr::RefDot { refr: expr, .. } => {
            collect_expression_references(expr, package, imports, out);
        },
        Expr::RefBrack { refr, index, .. } => {
            collect_expression_references(refr, package, imports, out);
            collect_expression_references(index, package, imports, out);
        },
        Expr::BinExpr { lhs, rhs, .. }
        | Expr::BoolExpr { lhs, rhs, .. }
        | Expr::ArithExpr { lhs, rhs, .. }
        | Expr::AssignExpr { lhs, rhs, .. } => {
            collect_expression_references(lhs, package, imports, out);
            collect_expression_references(rhs, package, imports, out);
        },
        Expr::Membership {
            key,
            value,
            collection,
            ..
        } => {
            if let Some(key) = key {
                collect_expression_references(key, package, imports, out);
            }
            collect_expression_references(value, package, imports, out);
            collect_expression_references(collection, package, imports, out);
        },
        Expr::String { .. }
        | Expr::RawString { .. }
        | Expr::Number { .. }
        | Expr::Bool { .. }
        | Expr::Null { .. }
        | Expr::Var { .. } => {},
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
