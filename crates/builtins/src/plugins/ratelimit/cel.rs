// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeSet;

use limitador_cel::common::ast::{EntryExpr, Expr, IdedEntryExpr, IdedExpr};

pub(super) struct Variables {
    pub free: BTreeSet<String>,
    pub local: BTreeSet<String>,
}

impl Variables {
    pub(super) fn parse(source: &str) -> Result<Self, limitador_cel::ParseErrors> {
        let expression = limitador_cel::parser::Parser::new().parse(source)?;
        let mut free = BTreeSet::new();
        collect_free(&expression, &mut Vec::new(), &mut free);
        let local = expression
            .references()
            .variables()
            .into_iter()
            .filter(|name| !free.contains(*name))
            .map(str::to_owned)
            .collect();
        Ok(Self { free, local })
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

fn collect_free<'a>(
    expression: &'a IdedExpr,
    scope: &mut Vec<&'a str>,
    free: &mut BTreeSet<String>,
) {
    match &expression.expr {
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                collect_free(target, scope, free);
            }
            for argument in &call.args {
                collect_free(argument, scope, free);
            }
        },
        Expr::Comprehension(comp) => {
            collect_free(&comp.iter_range, scope, free);
            collect_free(&comp.accu_init, scope, free);
            let outer = scope.len();
            scope.push(&comp.accu_var);
            collect_free(&comp.loop_cond, scope, free);
            collect_free(&comp.result, scope, free);
            scope.push(&comp.iter_var);
            if let Some(variable) = &comp.iter_var2 {
                scope.push(variable);
            }
            collect_free(&comp.loop_step, scope, free);
            scope.truncate(outer);
        },
        Expr::Ident(name) => {
            if !scope.contains(&name.as_str()) {
                free.insert(name.clone());
            }
        },
        Expr::List(list) => {
            for element in &list.elements {
                collect_free(element, scope, free);
            }
        },
        Expr::Map(map) => collect_entries(&map.entries, scope, free),
        Expr::Select(select) => collect_free(&select.operand, scope, free),
        Expr::Struct(structure) => collect_entries(&structure.entries, scope, free),
        Expr::Literal(_) | Expr::Unspecified => {},
    }
}

fn collect_entries<'a>(
    entries: &'a [IdedEntryExpr],
    scope: &mut Vec<&'a str>,
    free: &mut BTreeSet<String>,
) {
    for entry in entries {
        match &entry.expr {
            EntryExpr::StructField(field) => collect_free(&field.value, scope, free),
            EntryExpr::MapEntry(entry) => {
                collect_free(&entry.key, scope, free);
                collect_free(&entry.value, scope, free);
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::Variables;

    #[test]
    fn macros_bind_only_their_local_variables() -> Result<(), limitador_cel::ParseErrors> {
        for source in [
            "['/api/'].exists(prefix, path.startsWith(prefix))",
            "['/api/'].all(prefix, path.startsWith(prefix))",
            "['/api/'].exists_one(prefix, path.startsWith(prefix))",
            "['/api/'].filter(prefix, path.startsWith(prefix))",
            "['/api/'].map(prefix, path.startsWith(prefix))",
            "['/api/'].map(prefix, path.startsWith(prefix), prefix)",
            "['/api/'].exists(prefix, [prefix].all(prefix, path.startsWith(prefix)))",
        ] {
            let variables = Variables::parse(source)?;
            assert_eq!(variables.free, ["path".to_owned()].into(), "{source}");
            assert_eq!(variables.local, ["prefix".to_owned()].into(), "{source}");
        }
        Ok(())
    }

    #[test]
    fn macro_locals_do_not_hide_free_names_in_other_scopes()
    -> Result<(), limitador_cel::ParseErrors> {
        for source in [
            "['/api/'].exists(prefix, path.startsWith(prefix)) && prefix == '/api/'",
            "[prefix].exists(prefix, path.startsWith(prefix))",
            "['/api/'].exists(prefix, path.startsWith(prefix) && missing == '')",
            "{'value': ['a'].map(item, item), path: missing}",
        ] {
            let variables = Variables::parse(source)?;
            let expected: std::collections::BTreeSet<String> = if source.contains("missing") {
                ["missing".to_owned(), "path".to_owned()].into()
            } else {
                ["path".to_owned(), "prefix".to_owned()].into()
            };
            assert_eq!(variables.free, expected, "{source}");
        }
        Ok(())
    }

    #[test]
    fn limit_can_be_a_macro_local_without_being_a_free_reference()
    -> Result<(), limitador_cel::ParseErrors> {
        let variables = Variables::parse("['alice'].exists(limit, limit == subject_id)")?;
        assert_eq!(variables.free, ["subject_id".to_owned()].into());
        assert_eq!(variables.local, ["limit".to_owned()].into());
        Ok(())
    }
}
