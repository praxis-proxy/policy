// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// APL parser: policy text to IR.
//
// The grammar this accepts is written down in docs/apl-grammar.md, and that
// document is normative. This file used to carry the description instead, in a
// comment block that had gone wrong on four counts: it claimed steps, pipe chains,
// `in` / `not in` / `exists()` and `sequential:` / `parallel:` were all rejected,
// long after each was implemented. A grammar kept in a comment beside its parser
// is a grammar nobody can hold the parser to, which is why it moved out.
//
// crates/ppe-apl-core/tests/conformance/ is what holds the two in agreement.
//
// What lives here:
//
//   * `Lexer` — tokens. Quoted literals go through `crate::lexical`, which is the
//     one reader for one, shared with every splitter below.
//   * `PredParser` — the predicate grammar, by precedence climbing.
//   * `parse_rule` — a predicate and an action.
//   * `parse_step` / `parse_step_map` — the step forms, string and map.
//   * `parse_pipeline` / `parse_stage` — field chains.
//   * `compile_policy_block_value` — a section's policy block to a CompiledRoute.
//     This is the entry point an orchestrator uses.
//
// Runs once at config load. The IR it produces is what the evaluator walks at
// request time; the parser is never on the hot path, so clarity wins over speed
// throughout.

use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use crate::pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintScope, TypeCheck};
use crate::plugin_decl::PluginOverride;
use crate::rules::{CompareOp, CompiledRoute, Condition, Effect, Expression, Literal, Rule};
use crate::step::{DelegateStep, ElicitKind, ElicitStep, PdpCall, PdpDialect, Step};

#[derive(Debug, Error)]
/// Why a policy document could not be compiled.
pub enum ParseError {
    /// The document is not valid YAML, or does not match the expected shape.
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// A rule line does not match any accepted form.
    #[error("rule '{rule}': {msg}")]
    Rule {
        /// The rule text as written.
        rule: String,
        /// What is wrong with it.
        msg: String,
    },

    /// The step name is not one this build recognizes.
    #[error("unsupported step `{kind}` in rule '{rule}'")]
    UnsupportedStep {
        /// The rule text as written.
        rule: String,
        /// The step name that is not recognized.
        kind: String,
    },

    /// A predicate does not lex or parse.
    #[error("predicate '{predicate}': {msg}")]
    Predicate {
        /// The predicate text as written.
        predicate: String,
        /// What is wrong with it.
        msg: String,
    },

    /// An `authorization:` block contributes no step, so it authorizes
    /// nothing. Either it names neither phase, or every phase it names is an
    /// empty list.
    #[error(
        "in `{location}`: `authorization:` contributes no step; it declares neither \
         `pre_invocation:` nor `post_invocation:`, or declares them empty. Name at least one \
         step, or remove the block"
    )]
    EmptyAuthorization {
        /// Where in the document the empty block appears.
        location: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String), // dotted: subject.id, role.hr, authenticated
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    Eq,    // ==
    NotEq, // !=
    Gt,    // >
    GtEq,  // >=
    Lt,    // <
    LtEq,  // <=
    And,   // & — spacing around it is not significant
    Or,    // |
    Not,   // !
    /// The word `not`, legal only in the `not in` phrase. Reserved so that
    /// `not authenticated` names `!` rather than reading as an attribute.
    NotWord,
    LParen,
    RParen,
    Comma,
    Contains, // keyword
    Require,  // keyword
    Exists,   // keyword
    In,       // keyword — set membership operator
}

/// What replaced `run(name)`, named wherever the old spelling is refused.
const PLUGIN_IS_RUN: &str = "`plugin(name)` is not a step; `run(name)` is the one form that \
                             invokes a plugin, in a step list and in a pipe chain alike";

/// What an empty path segment breaks, named wherever one is found.
const EMPTY_SEGMENT: &str = "empty segment in an attribute path; a path is dot-separated names, \
                             so `a..b`, `a.` and `.a` name nothing";

/// What the word `not` is for, named wherever it is refused.
const NOT_IS_RESERVED: &str = "`not` is reserved for the `not in` phrase; APL spells predicate \
                               negation `!`, as in `!authenticated`";

/// What a number may look like, named by every rejection of one.
const NUMBER_SHAPE: &str = "a number is an optional `-`, then digits, then optionally `.` and \
                            more digits; there is no exponent form, and digits are required on \
                            both sides of the dot";

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn tokenize_all(&mut self) -> Result<Vec<Tok>, ParseError> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let Some(b) = self.peek() else {
                return Ok(out);
            };

            let tok = match b {
                b'(' => {
                    self.pos += 1;
                    Tok::LParen
                },
                b')' => {
                    self.pos += 1;
                    Tok::RParen
                },
                b',' => {
                    self.pos += 1;
                    Tok::Comma
                },
                b'&' => {
                    self.pos += 1;
                    if self.peek() == Some(b'&') {
                        return Err(self.err_at(
                            self.pos - 1,
                            "`&&` is not an operator; APL spells conjunction `&`",
                        ));
                    }
                    Tok::And
                },
                b'|' => {
                    self.pos += 1;
                    if self.peek() == Some(b'|') {
                        return Err(self.err_at(
                            self.pos - 1,
                            "`||` is not an operator; APL spells disjunction `|`",
                        ));
                    }
                    Tok::Or
                },
                b'=' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::Eq
                    } else {
                        return Err(self.err("expected `==`, saw `=`"));
                    }
                },
                b'!' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::NotEq
                    } else {
                        Tok::Not
                    }
                },
                b'>' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::GtEq
                    } else {
                        Tok::Gt
                    }
                },
                b'<' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::LtEq
                    } else {
                        Tok::Lt
                    }
                },
                b if crate::lexical::is_quote(b) => self.lex_string()?,
                b'-' | b'0'..=b'9' => self.lex_number()?,
                b'.' if self.bytes.get(self.pos + 1).is_some_and(u8::is_ascii_digit) => {
                    return Err(self.err(NUMBER_SHAPE));
                },
                b'.' => return Err(self.err(EMPTY_SEGMENT)),
                b if is_ident_start(b) => self.lex_ident_or_keyword()?,
                _ => {
                    let ch = self.char_at_cursor();
                    return Err(self.err(&format!("unexpected character `{ch}`")));
                },
            };
            out.push(tok);
        }
    }

    fn lex_string(&mut self) -> Result<Tok, ParseError> {
        let lit = crate::lexical::read_literal(self.src, self.pos).map_err(|e| self.at(&e))?;
        self.pos = lit.end;
        Ok(Tok::StringLit(lit.value))
    }

    /// A number is an optional `-`, then one or more digits, then optionally a
    /// `.` and one or more digits. No exponent, no separators, no radix prefix.
    ///
    /// Digits are required on both sides of the dot, which `1.`, `.5` and `-.5`
    /// each broke. `.5` was already refused, by falling off the end of the
    /// dispatch table with a message about an unexpected character, while `-.5`
    /// parsed as a float: one rule now, and it names the number either way.
    ///
    /// A leading zero is accepted and does not change the value: `007` is the
    /// integer 7. Reading it as octal would alter a value silently, which is the
    /// failure mode this work exists to remove.
    fn lex_number(&mut self) -> Result<Tok, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        self.eat_digits();
        if self.pos == int_start {
            return Err(self.err_at(start, NUMBER_SHAPE));
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            let frac_start = self.pos;
            self.eat_digits();
            if self.pos == frac_start {
                return Err(self.err_at(start, NUMBER_SHAPE));
            }
        }
        // An exponent is not part of the grammar, and letting it fall through
        // produced a trailing-token error that never mentioned the number.
        if matches!(self.peek(), Some(b'e' | b'E')) {
            return Err(self.err_at(start, NUMBER_SHAPE));
        }
        let text = self
            .src
            .get(start..self.pos)
            .ok_or_else(|| self.err("bad numeric literal bounds"))?;
        if is_float {
            text.parse::<f64>()
                .map(Tok::FloatLit)
                .map_err(|e| self.err(&format!("bad float `{text}`: {e}")))
        } else {
            text.parse::<i64>()
                .map(Tok::IntLit)
                .map_err(|e| self.err(&format!("bad int `{text}`: {e}")))
        }
    }

    fn eat_digits(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn lex_ident_or_keyword(&mut self) -> Result<Tok, ParseError> {
        let start = self.pos;
        // An attribute path is a production, not a run of permitted characters.
        // It is dot-separated segments, each non-empty, optionally each followed
        // by one `[...]` interpolation group holding a nested path.
        //
        // Every rejection below used to lex clean and then resolve to an absent
        // attribute, which made a predicate silently false and a `require`
        // silently deny: a policy that never matched and never said why.
        let mut has_bracket = false;
        loop {
            let seg_start = self.pos;
            while let Some(b) = self.peek() {
                if is_segment_char(b) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == seg_start {
                return Err(self.err_at(seg_start, EMPTY_SEGMENT));
            }
            if self.peek() == Some(b'[') {
                has_bracket = true;
                self.lex_subscript()?;
            }
            if self.peek() == Some(b'.') {
                self.pos += 1;
                continue;
            }
            break;
        }
        let s = self
            .src
            .get(start..self.pos)
            .ok_or_else(|| self.err("bad identifier bounds"))?;
        if s.starts_with("not.") {
            return Err(self.err_at(start, NOT_IS_RESERVED));
        }
        // A path with an interpolation group is never a keyword.
        if has_bracket {
            return Ok(Tok::Ident(s.to_owned()));
        }
        Ok(match s {
            "true" => Tok::BoolLit(true),
            "false" => Tok::BoolLit(false),
            "contains" => Tok::Contains,
            "require" => Tok::Require,
            "exists" => Tok::Exists,
            "in" => Tok::In,
            // Reserved. It reaches the parser rather than failing here, because
            // `not in` is the one phrase it is legal in and only the parser sees
            // whether `in` follows. Everywhere else the parser names `!`.
            "not" => Tok::NotWord,
            _ => Tok::Ident(s.to_owned()),
        })
    }

    /// The character at the cursor, decoded rather than cast.
    ///
    /// A byte at or above 128 is one of several in a UTF-8 sequence, so casting it
    /// names a character that is not in the input. Diagnostics only.
    fn char_at_cursor(&self) -> char {
        self.src
            .get(self.pos..)
            .and_then(|rest| rest.chars().next())
            .unwrap_or(char::REPLACEMENT_CHARACTER)
    }

    /// Consume one `[...]` interpolation group, whose content is a nested
    /// attribute path the evaluator resolves per request.
    ///
    /// The content is a path, not raw text. It used to be raw, so an empty
    /// subscript, a colon, and a quoted key all lexed clean and then looked up a
    /// key nothing had. A quoted key was the quiet one: `data.t["a"]` looked up
    /// the four characters `"a"`, quotes included, so it never matched.
    fn lex_subscript(&mut self) -> Result<(), ParseError> {
        let open = self.pos;
        self.pos += 1; // `[`
        let inner_start = self.pos;
        loop {
            match self.peek() {
                Some(b']') => break,
                Some(b'[') => {
                    return Err(self.err("nested `[` in an attribute path subscript"));
                },
                Some(b) if is_segment_char(b) || b == b'.' => self.pos += 1,
                Some(_) => {
                    let ch = self.char_at_cursor();
                    return Err(self.err(&format!(
                        "`{ch}` in an attribute path subscript; a subscript holds a nested path, \
                         so it takes names and dots and nothing else"
                    )));
                },
                None => {
                    return Err(self.err_at(open, "unterminated `[` in an attribute path"));
                },
            }
        }
        if self.pos == inner_start {
            return Err(self.err_at(
                open,
                "empty subscript in an attribute path; a subscript holds the nested path whose \
                 value is the key to look up",
            ));
        }
        // Reject `a..b` and a trailing dot inside the group for the same reason
        // as outside it.
        let inner = self
            .src
            .get(inner_start..self.pos)
            .ok_or_else(|| self.err("bad subscript bounds"))?;
        if inner.starts_with('.') || inner.ends_with('.') || inner.contains("..") {
            return Err(self.err_at(
                inner_start,
                "empty segment in an attribute path subscript; a subscript holds dot-separated \
                 names",
            ));
        }
        self.pos += 1; // `]`
        Ok(())
    }

    fn err(&self, msg: &str) -> ParseError {
        self.err_at(self.pos, msg)
    }

    /// The same, for a fault whose position is not where the cursor stopped.
    fn err_at(&self, at: usize, msg: &str) -> ParseError {
        ParseError::Predicate {
            predicate: self.src.to_owned(),
            msg: format!(
                "at character {}: {}",
                crate::lexical::char_offset(self.src, at),
                msg
            ),
        }
    }

    /// Carry a literal reader's fault out, keeping its position. The reader
    /// reports a character offset already, so this must not run it through
    /// `char_offset` a second time.
    fn at(&self, e: &crate::lexical::LiteralError) -> ParseError {
        ParseError::Predicate {
            predicate: self.src.to_owned(),
            msg: format!("at character {}: {}", e.at, e.msg),
        }
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_segment_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

struct PredParser<'a> {
    src: &'a str,
    toks: Vec<Tok>,
    pos: usize,
}

impl<'a> PredParser<'a> {
    fn parse(src: &'a str) -> Result<Expression, ParseError> {
        let toks = Lexer::new(src).tokenize_all()?;
        let mut p = Self { src, toks, pos: 0 };
        let expr = p.parse_or()?;
        if p.pos < p.toks.len() {
            return Err(p.err(&format!(
                "trailing tokens after expression: {:?}",
                p.toks.get(p.pos..).unwrap_or(&[])
            )));
        }
        Ok(expr)
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned()?;
        self.pos += 1;
        Some(t)
    }
    fn err(&self, msg: &str) -> ParseError {
        ParseError::Predicate {
            predicate: self.src.to_owned(),
            msg: msg.to_owned(),
        }
    }

    fn parse_or(&mut self) -> Result<Expression, ParseError> {
        let first = self.parse_and()?;
        let mut rest = Vec::new();
        while matches!(self.peek(), Some(Tok::Or)) {
            self.bump();
            rest.push(self.parse_and()?);
        }
        if rest.is_empty() {
            return Ok(first);
        }
        let mut parts = Vec::with_capacity(rest.len() + 1);
        parts.push(first);
        parts.append(&mut rest);
        Ok(Expression::Or(parts))
    }

    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let first = self.parse_unary()?;
        let mut rest = Vec::new();
        while matches!(self.peek(), Some(Tok::And)) {
            self.bump();
            rest.push(self.parse_unary()?);
        }
        if rest.is_empty() {
            return Ok(first);
        }
        let mut parts = Vec::with_capacity(rest.len() + 1);
        parts.push(first);
        parts.append(&mut rest);
        Ok(Expression::And(parts))
    }

    fn parse_unary(&mut self) -> Result<Expression, ParseError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.bump();
            let inner = self.parse_unary()?;
            return Ok(Expression::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Expression, ParseError> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err(self.err("expected `)`")),
                }
            },
            Some(Tok::Require) => self.parse_require(),
            Some(Tok::Exists) => self.parse_exists(),
            Some(Tok::Ident(_)) => self.parse_identifier_predicate(),
            // `not authenticated` used to read as an attribute called `not`
            // followed by a stray token, so the error named neither `not` nor the
            // operator the author wanted.
            Some(Tok::NotWord) => Err(self.err(NOT_IS_RESERVED)),
            // A comparison is written attribute-first. Rejected rather than
            // rewritten: reading `'x' == a` as `a == 'x'` would accept text whose
            // meaning the author only guessed at.
            Some(Tok::StringLit(_) | Tok::IntLit(_) | Tok::FloatLit(_) | Tok::BoolLit(_)) => {
                Err(self.err(
                    "a comparison names the attribute first, as in `subject.tenant == 'acme'`; a \
                 literal cannot open one",
                ))
            },
            other => Err(self.err(&format!("expected atom, got {other:?}"))),
        }
    }

    /// `require(P)`, which means `!P`.
    ///
    /// A rule stores the condition under which it denies, so requiring `P` is
    /// denying on `!P`. Inside the parens the comma is conjunction and binds
    /// lower than `&` and `|`, so `require(a, b | c)` is `!(a & (b | c))`.
    ///
    /// This replaces a hand-written parser that accepted only a comma-or-pipe
    /// list of bare identifiers, refused to mix the two, and could not be nested.
    /// A comparison, a negation and a parenthesized group were all unwritable
    /// here, not because any is ambiguous but because there was no code path.
    ///
    /// [`normalize_not`] is what makes this a refactor rather than a
    /// reinterpretation: it folds the negation down to the same tree the old
    /// desugaring produced for each of the three forms that were legal.
    fn parse_require(&mut self) -> Result<Expression, ParseError> {
        self.bump(); // `require`
        if !matches!(self.peek(), Some(Tok::LParen)) {
            return Err(self.err("expected `(` after `require`"));
        }
        self.bump();
        let mut parts = Vec::new();
        loop {
            parts.push(self.parse_or()?);
            match self.peek() {
                Some(Tok::Comma) => {
                    self.bump();
                },
                Some(Tok::RParen) => {
                    self.bump();
                    break;
                },
                other => {
                    return Err(self.err(&format!(
                        "expected `,` or `)` in `require(...)`, got {other:?}"
                    )));
                },
            }
        }
        let inner = if parts.len() == 1 {
            parts.pop().unwrap_or(Expression::Always)
        } else {
            Expression::And(parts)
        };
        Ok(normalize_not(inner))
    }

    /// `exists(<identifier>)`. Returns true if the key is present
    /// in the `AttributeBag`, regardless of value (distinct from truthiness).
    fn parse_exists(&mut self) -> Result<Expression, ParseError> {
        self.bump(); // exists
        match self.bump() {
            Some(Tok::LParen) => {},
            _ => return Err(self.err("expected `(` after `exists`")),
        }
        let key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => {
                return Err(self.err(&format!(
                    "exists(...) expects an attribute key, got {other:?}",
                )));
            },
        };
        match self.bump() {
            Some(Tok::RParen) => {},
            other => {
                return Err(self.err(&format!(
                    "expected `)` after exists() argument, got {other:?}",
                )));
            },
        }
        Ok(Expression::Condition(Condition::Exists { key }))
    }

    /// Parse a predicate that begins with an identifier:
    ///   - bare identifier:    `authenticated`  → `IsTrue`
    ///   - comparison:         `delegation.depth > 2`
    ///   - contains:           `session.labels contains "PII"`
    ///   - set membership:     `subject.type in allowed_types`
    ///   - set non-membership: `subject.type not in blocked_types`
    fn parse_identifier_predicate(&mut self) -> Result<Expression, ParseError> {
        let key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            // Unreachable: parse_atom only dispatches here on a leading Ident.
            _ => return Err(self.err("expected an identifier at the start of a predicate")),
        };

        // `in` and `not in` — two-key set membership.
        if matches!(self.peek(), Some(Tok::In)) {
            self.bump();
            return self.finish_in_set(key, false);
        }
        // `not in` is the one place the word `not` is legal. Anywhere else it
        // names `!`, which is what `parse_atom` reports.
        if matches!(self.peek(), Some(Tok::NotWord)) {
            self.bump();
            if matches!(self.peek(), Some(Tok::In)) {
                self.bump();
                return self.finish_in_set(key, true);
            }
            return Err(self.err(NOT_IS_RESERVED));
        }

        let op = match self.peek() {
            Some(Tok::Eq) => Some(CompareOp::Eq),
            Some(Tok::NotEq) => Some(CompareOp::NotEq),
            Some(Tok::Gt) => Some(CompareOp::Gt),
            Some(Tok::GtEq) => Some(CompareOp::GtEq),
            Some(Tok::Lt) => Some(CompareOp::Lt),
            Some(Tok::LtEq) => Some(CompareOp::LtEq),
            Some(Tok::Contains) => Some(CompareOp::Contains),
            _ => None,
        };

        let Some(op) = op else {
            // Bare identifier.
            return Ok(Expression::Condition(Condition::IsTrue { key }));
        };
        self.bump();

        let value = match self.bump() {
            Some(Tok::StringLit(s)) => Literal::String(s),
            Some(Tok::IntLit(i)) => Literal::Int(i),
            Some(Tok::FloatLit(f)) => Literal::Float(f),
            Some(Tok::BoolLit(b)) => Literal::Bool(b),
            Some(Tok::Ident(_)) => {
                return Err(self.err(
                    "RHS-as-identifier on comparison operators not supported — \
                     for set membership use `value_key in set_key`",
                ));
            },
            other => return Err(self.err(&format!("expected literal RHS, got {other:?}"))),
        };

        Ok(Expression::Condition(Condition::Comparison {
            key,
            op,
            value,
        }))
    }

    fn finish_in_set(&mut self, value_key: String, negate: bool) -> Result<Expression, ParseError> {
        let set_key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => {
                return Err(self.err(&format!(
                    "expected set-attribute identifier after `{}in`, got {:?}",
                    if negate { "not " } else { "" },
                    other,
                )));
            },
        };
        Ok(Expression::Condition(Condition::InSet {
            value_key,
            set_key,
            negate,
        }))
    }
}

/// Parse a predicate string into the IR. Public for tests.
/// # Errors
///
/// Returns `ParseError::Predicate` when the expression does not lex, when an
/// operator or operand is missing, or when tokens remain after a complete
/// expression.
pub fn parse_predicate(src: &str) -> Result<Expression, ParseError> {
    PredParser::parse(src.trim())
}

/// Parse a single rule line into a `Rule`.
///
/// Accepted forms:
/// 1. `"require(...)"` is rule-level shorthand, desugaring to
///    `when: <negated condition> do: deny`
/// 2. `"<predicate>: <action>"` becomes `Rule { condition, action }`
/// 3. `"<predicate>"` becomes `Rule { condition, action: Deny }`
/// 4. `"<action>"` alone is form 3 with an always-true predicate
///
/// **Step kinds** (`run(...)`, `taint(...)`, `cedar:`, `opa(...)` etc.)
/// are handled by `parse_step`, not here. This function specifically parses
/// predicate-and-action rules; callers that don't know which they have
/// should use `parse_step` instead.
/// # Errors
///
/// Returns `ParseError::Rule` when the line matches none of the accepted forms,
/// or `ParseError::Predicate` when its predicate half does not parse.
pub fn parse_rule(line: &str, source: &str) -> Result<Rule, ParseError> {
    let trimmed = line.trim();

    // The removed invoke spelling, named before anything else reads the line. It
    // is not a step kind any more, so without this it reaches the predicate
    // parser, which lexes a hyphenated plugin name as a number and reports that.
    if trimmed.trim_start().starts_with("plugin(") {
        return Err(ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: PLUGIN_IS_RUN.to_owned(),
        });
    }

    // Step kinds shouldn't end up here. If they do, the caller used the
    // wrong entry point — point them at parse_step.
    if let Some(kind) = detect_step_kind(trimmed) {
        return Err(ParseError::UnsupportedStep {
            rule: trimmed.to_owned(),
            kind: format!("{kind} (use parse_step for step kinds)"),
        });
    }

    let (predicate_str, effects) = if let Some((p, a)) = split_predicate_action(trimmed) {
        (p, parse_action(a, trimmed)?)
    } else {
        // No `:` — bare action (unconditional) or bare predicate (default deny).
        if let Some(effects) = try_bare_action(trimmed) {
            return Ok(Rule {
                condition: Expression::Always,
                effects,
                source: source.to_owned(),
            });
        }
        // Unconditional `deny('reason')` / `deny('reason', 'code')` —
        // the call form of a bare deny. Lets reaction lists
        // (`on_deny: [...]` / `on_allow: [...]`) and standalone rule
        // lines attach a reason/code without a guard predicate. A
        // malformed `deny(...)` surfaces its own error here rather
        // than being misread as a predicate downstream.
        if let Some(deny) = try_parse_deny_call(trimmed, trimmed)? {
            return Ok(Rule {
                condition: Expression::Always,
                effects: vec![deny],
                source: source.to_owned(),
            });
        }
        // Default: bare predicate denies.
        (
            trimmed,
            vec![Effect::Deny {
                reason: None,
                code: None,
            }],
        )
    };

    reject_field_operation_in_rule_position(predicate_str, trimmed)?;
    reject_require_with_allow(predicate_str, &effects, trimmed)?;

    let condition = parse_predicate(predicate_str).map_err(|e| ParseError::Rule {
        rule: trimmed.to_owned(),
        msg: format!("{e}"),
    })?;

    Ok(Rule {
        condition,
        effects,
        source: source.to_owned(),
    })
}

// The two guards below are shared by all three rule spellings: the string form,
// `when:` / `do:`, and the multi-effect shorthand. Only the string form goes
// through `parse_rule`, so a guard written there alone held for one spelling out
// of three. That is how `when: "require(a)"` with `do: allow` compiled to an
// allow on `!a`. `rule` is the text to quote back, which differs per spelling.

/// A field operation is not a rule. `result.x | redact` used to compile as a
/// disjunction of two truthy attributes and take the default deny, so a chain one
/// position too high enforced something its author never asked for.
///
/// Call before the predicate parse, so the message names the position rather than
/// a predicate that happened to lex.
fn reject_field_operation_in_rule_position(predicate: &str, rule: &str) -> Result<(), ParseError> {
    if let Some(field) = field_operation_in_rule_position(predicate) {
        return Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: format!(
                "`{field}` is a field operation, and this is effect position: a rule here is a \
                 predicate with an optional `allow`/`deny`. Move the chain under `args:` or \
                 `result:`, keyed by the field it names"
            ),
        });
    }
    Ok(())
}

/// `require(...)` denies when its condition does not hold, so a rule whose
/// predicate *is* a `require` call cannot carry `allow`.
///
/// Needs the effects, so it runs after they parse. In two spellings that is also
/// after the predicate parse, which costs nothing: a `require` whose inner
/// predicate does not lex is better reported as the lex error.
fn reject_require_with_allow(
    predicate: &str,
    effects: &[Effect],
    rule: &str,
) -> Result<(), ParseError> {
    if is_require_form(predicate) && effects.iter().any(|e| matches!(e, Effect::Allow)) {
        return Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: "`require(...)` states what must hold and denies when it does not, so its \
                  action can only be `deny`; write the predicate without `require` to allow on it"
                .to_owned(),
        });
    }
    Ok(())
}

/// The negation of `e`, pushed down to the leaves.
///
/// Folding rather than wrapping is what makes `require(P)` a refactor of the old
/// hand-written desugaring instead of a new interpretation of it:
///
/// * `require(a)` gives `IsFalse(a)`, as it did.
/// * `require(a, b)` gives `Or([IsFalse(a), IsFalse(b)])`, as it did.
/// * `require(a | b)` gives `And([IsFalse(a), IsFalse(b)])`, as it did.
///
/// Those three were the whole of what the old parser accepted, so no deployed
/// policy changes shape. A comparison has no negated condition variant, so it
/// keeps an explicit `Not` around it.
fn normalize_not(e: Expression) -> Expression {
    match e {
        Expression::Condition(Condition::IsTrue { key }) => {
            Expression::Condition(Condition::IsFalse { key })
        },
        Expression::Condition(Condition::IsFalse { key }) => {
            Expression::Condition(Condition::IsTrue { key })
        },
        // De Morgan, so the negation reaches the leaves rather than sitting on a
        // group the evaluator would have to invert at request time.
        Expression::And(parts) => Expression::Or(parts.into_iter().map(normalize_not).collect()),
        Expression::Or(parts) => Expression::And(parts.into_iter().map(normalize_not).collect()),
        // A double negation folds, which is what lets `require(!delegated)` mean
        // `delegated` rather than nesting two inversions.
        Expression::Not(inner) => *inner,
        other => Expression::Not(Box::new(other)),
    }
}

/// Whether a rule's predicate half *is* a `require(...)` call, as opposed to
/// containing one.
///
/// Textual because the rule grammar is textual at this level: a rule is a
/// predicate, a colon and an action, and this asks which of the two shapes the
/// predicate is so the action can be checked against it. The predicate itself is
/// parsed by `parse_predicate` like any other.
///
/// The call has to consume the whole predicate. A prefix test made the guard
/// asymmetric: `require(a) & b: allow` was refused while `a & require(b): allow`
/// was accepted, though the grammar documents both as legal composition and
/// restricts only a rule whose *whole* predicate is the call. Do not simplify
/// this back to `starts_with`.
fn is_require_form(s: &str) -> bool {
    let Some(rest) = s.trim().strip_prefix("require") else {
        return false;
    };
    // The predicate lexer skips whitespace between the name and its `(`, so
    // `require (a)` is the same shape and has to be caught with it.
    let normalized = format!("require{}", rest.trim_start());
    // `extract_call_args` reads the outermost matching parens and already refuses
    // anything after the `)` it closed on, so asking it is the exact-form test.
    extract_call_args(&normalized, "require").is_some()
}

/// The field path a rule line names, when the line is really a field operation.
///
/// Deliberately narrow. `result.x | result.y: deny` is a **legal** disjunction of
/// two truthy attributes and has to keep compiling, so an `args.`/`result.` head
/// is not enough on its own. What separates the two is whether any later segment
/// is a stage rather than another attribute path, which [`parse_stage`] is the
/// authority on: widen this by hand and the two answers drift.
fn field_operation_in_rule_position(predicate: &str) -> Option<&str> {
    let segments = split_top_level(predicate.trim(), b'|');
    let (head, rest) = segments.split_first()?;
    let head = head.trim();
    if rest.is_empty() {
        return None;
    }
    if !(head.starts_with("args.") || head.starts_with("result.")) {
        return None;
    }
    rest.iter()
        .any(|seg| parse_stage(seg.trim()).is_ok())
        .then_some(head)
}

fn detect_step_kind(s: &str) -> Option<&'static str> {
    let s = s.trim_start();
    for prefix in [
        "taint(",
        "run(",
        "cedar:",
        "opa(",
        "authzen(",
        "nemo(",
        "cel:",
        "sequential:",
        "parallel:",
    ] {
        if s.starts_with(prefix) {
            return Some(prefix.trim_end_matches('(').trim_end_matches(':'));
        }
    }
    None
}

/// Split on the *last* unescaped `:` that's outside quotes and parens — this
/// is the predicate/action separator. The DSL doesn't escape colons, and `:`
/// doesn't appear in our predicate grammar, but quotes and parens can contain
/// arbitrary text.
fn split_predicate_action(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut parens: i32 = 0;
    let mut brackets: i32 = 0;
    let mut last_colon: Option<usize> = None;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if crate::lexical::is_quote(b) {
            // One reader for a literal, so a colon inside quoted text is skipped
            // by the same rule the lexer reads it with. An unterminated literal
            // stops the scan rather than swallowing the rest of the line: the
            // caller finds no action and the lexer then names the literal, which
            // is the fault the author can act on.
            match crate::lexical::skip_literal(s, i) {
                Ok(end) => i = end,
                Err(_) => break,
            }
            continue;
        }
        match b {
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            // Brackets count too. They did not, while both sibling splitters
            // counted them, so a colon inside a subscript on a bare-predicate
            // line split the rule into a predicate and a nonsense action.
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b':' if parens == 0 && brackets == 0 => last_colon = Some(i),
            _ => {},
        }
        i += 1;
    }
    last_colon.and_then(|i| Some((s.get(..i)?.trim(), s.get(i + 1..)?.trim())))
}

/// Parse the *right* side of a shorthand `predicate: action` rule into a
/// single-element effects vec. Recognized forms (the `code`
/// extension we added):
///
///   * `deny`                    → `vec![Effect::Deny { reason: None, code: None }]`
///   * `deny('reason')`          → `vec![Effect::Deny { reason: Some, code: None }]`
///   * `deny('reason', 'code')`  → `vec![Effect::Deny { reason: Some, code: Some }]`
///   * `allow`                   → `vec![Effect::Allow]`
///
/// Anything else (plugin/delegate/taint) goes through `parse_step`, not
/// here — those are sibling Steps in v0. Multi-effect `do:` lists use a
/// separate parsing path that produces `Vec<Effect>` directly.
fn parse_action(s: &str, rule: &str) -> Result<Vec<Effect>, ParseError> {
    if let Some(effect) = try_bare_action(s) {
        return Ok(effect);
    }
    if let Some(deny) = try_parse_deny_call(s.trim(), rule)? {
        return Ok(vec![deny]);
    }
    Err(ParseError::Rule {
        rule: rule.to_owned(),
        msg: format!(
            "unsupported action `{}` — recognized: `deny`, `deny('reason')`, `deny('reason', 'code')`, `allow`",
            s.trim()
        ),
    })
}

fn try_bare_action(s: &str) -> Option<Vec<Effect>> {
    match s.trim() {
        "deny" => Some(vec![Effect::Deny {
            reason: None,
            code: None,
        }]),
        "allow" => Some(vec![Effect::Allow]),
        _ => None,
    }
}

/// Parse `deny('reason')` or `deny('reason', 'code')`. Returns
/// `Ok(None)` when `s` doesn't start with `deny(` so the caller can
/// fall through to other action handlers.
fn try_parse_deny_call(s: &str, rule: &str) -> Result<Option<Effect>, ParseError> {
    if !s.starts_with("deny(") {
        return Ok(None);
    }
    let inside = extract_call_args(s, "deny").ok_or_else(|| ParseError::Rule {
        rule: rule.to_owned(),
        msg: "malformed `deny(...)`".into(),
    })?;
    // Two positional args max. Spec precedent: `deny('reason')` (1 arg);
    // Extension: `deny('reason', 'code')` (2 args). Both quoted.
    let parts = split_top_level_commas(&inside).map_err(|e| ParseError::Rule {
        rule: rule.to_owned(),
        msg: format!("deny(...): {e}"),
    })?;
    let mut iter = parts.into_iter();
    let reason = match iter.next() {
        Some(p) => Some(strip_string_literal(p.trim(), rule)?),
        None => None,
    };
    let code = match iter.next() {
        Some(p) => Some(strip_string_literal(p.trim(), rule)?),
        None => None,
    };
    if iter.next().is_some() {
        return Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: "deny(...) takes at most two args: deny('reason', 'code')".into(),
        });
    }
    Ok(Some(Effect::Deny { reason, code }))
}

/// Strip surrounding single or double quotes from a literal. The DSL
/// uses single quotes (`'reason'`) per the spec examples, but accept
/// double quotes too so YAML escaping is forgiving.
fn strip_string_literal(s: &str, rule: &str) -> Result<String, ParseError> {
    let s = s.trim();
    match literal_or_bare(s) {
        Ok(Some(inner)) => Ok(inner),
        Ok(None) => Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: format!("expected a quoted string, got `{s}`"),
        }),
        Err(e) => Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: e.msg,
        }),
    }
}

/// Parse a single YAML entry from a `pre_invocation` / `post_invocation` list.
///
/// Two YAML shapes:
/// - **String entry** — a rule line, taint effect, or plugin call.
///   - `"require(authenticated)"` → `Step::Rule`
///   - `"delegation.depth > 2: deny"` → `Step::Rule`
///   - `"run(rate_limiter)"` → `Step::Plugin`
///   - `"taint(PII, session)"` → `Step::Taint`
/// - **Map entry** (single-key map) — PDP call with optional reactions.
///   - `cedar: { action: read, resource: e, on_deny: [...] }` → `Step::Pdp`
///   - `opa("path"): { on_deny: [...] }` → `Step::Pdp`
/// # Errors
///
/// Returns `ParseError::Rule` when the value is neither a string nor a
/// single-key map, when the step name is unknown, or when its arguments are
/// malformed.
pub fn parse_step(value: &serde_yaml::Value, source: &str) -> Result<Step, ParseError> {
    match value {
        serde_yaml::Value::String(s) => parse_step_string(s, source),
        serde_yaml::Value::Mapping(m) => parse_step_map(m, source),
        other => Err(ParseError::Rule {
            rule: format!("{other:?}"),
            msg: "step must be a string or a single-key map".into(),
        }),
    }
}

fn parse_step_string(line: &str, source: &str) -> Result<Step, ParseError> {
    let trimmed = line.trim();

    // taint(...) — emit as Step::Taint, reusing the pipeline parser's logic
    // so the shape stays consistent with field-level taint.
    if trimmed.starts_with("taint(") {
        let inside = extract_call_args(trimmed, "taint").ok_or_else(|| ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: "malformed `taint(...)`".into(),
        })?;
        let taint_stage = parse_taint(&inside, trimmed)?;
        // parse_taint produces Stage::Taint; lift to Step::Taint.
        if let Stage::Taint { label, scopes } = taint_stage {
            return Ok(Step::Taint { label, scopes });
        }
        return Err(ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: "internal: `taint(...)` did not produce a taint stage".into(),
        });
    }

    // `run(name)` invokes a named plugin. `plugin(name)` was a second spelling
    // for the same thing; it is refused below, naming this one.
    if trimmed.starts_with("plugin(") {
        return Err(ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: PLUGIN_IS_RUN.to_owned(),
        });
    }
    if trimmed.starts_with("run(") {
        let verb = "run";
        let inside = extract_call_args(trimmed, verb).ok_or_else(|| ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: format!("malformed `{verb}(...)`"),
        })?;
        let name = inside.trim();
        if name.is_empty() {
            return Err(ParseError::Rule {
                rule: trimmed.to_owned(),
                msg: format!("`{verb}(...)`: plugin name must not be empty"),
            });
        }
        return Ok(Step::Plugin {
            name: name.to_owned(),
        });
    }

    // delegate(name, key: value, key: [a, b], ...) — emit as Step::Delegate.
    // Compact alternative to the map form (`- delegate: { plugin: ..., ... }`).
    // First positional arg is the plugin name; subsequent `key: value`
    // pairs become per-call config overrides (or `on_error` if the key
    // is reserved). Use the map form for nested configs the kwarg
    // parser doesn't handle.
    if trimmed.starts_with("delegate(") {
        let inside = extract_call_args(trimmed, "delegate").ok_or_else(|| ParseError::Rule {
            rule: trimmed.to_owned(),
            msg: "malformed `delegate(...)`".into(),
        })?;
        let parsed = parse_delegate_call_args(&inside, source)?;
        return Ok(Step::Delegate(DelegateStep {
            plugin_name: parsed.plugin_name,
            config_override: parsed.config_override,
            on_error: parsed.on_error,
            source: source.to_owned(),
        }));
    }

    // Elicitation sugar verbs — each desugars to `Step::Elicit` with a
    // fixed `ElicitKind`. All-kwarg form (`from:`, `channel:`, …), same
    // `key: value` shape as `delegate(...)`. Verbs are matched with the
    // trailing `(` so `require_approval` / `require_attestation` /
    // `require_review` / `require_step_up` don't collide on the
    // `require_` prefix.
    for (verb, kind) in ELICIT_VERBS {
        if trimmed.starts_with(&format!("{verb}(")) {
            let inside = extract_call_args(trimmed, verb).ok_or_else(|| ParseError::Rule {
                rule: trimmed.to_owned(),
                msg: format!("malformed `{verb}(...)`"),
            })?;
            let parsed = parse_elicit_call_args(verb, &inside, source)?;
            return Ok(Step::Elicit(ElicitStep {
                kind: *kind,
                plugin_name: parsed.plugin_name,
                channel: parsed.channel,
                from: parsed.from,
                purpose: parsed.purpose,
                scope: parsed.scope,
                timeout: parsed.timeout,
                config_override: parsed.config_override,
                on_error: parsed.on_error,
                source: source.to_owned(),
            }));
        }
    }

    // Otherwise fall through to the rule parser — predicate-and-action.
    let rule = parse_rule(trimmed, source)?;
    Ok(Step::Rule(rule))
}

/// Intermediate shape produced by [`parse_delegate_call_args`]. The
/// string-form parser fills this; the caller wraps into `Step::Delegate`
/// with the source path it has in scope.
struct ParsedDelegateCall {
    plugin_name: String,
    config_override: Option<serde_yaml::Value>,
    on_error: Option<String>,
}

/// Parse the inside-parens of `delegate(name, key: value, key: [a, b], ...)`.
///
/// Grammar (informal):
/// ```text
/// delegate_args := plugin_name [, kwarg [, kwarg]*]
/// plugin_name   := bare_ident_or_string
/// kwarg         := key ":" value
/// value         := scalar | "[" value (, value)* "]"
/// scalar        := bare_word | number | "true" | "false" | quoted_string
/// ```
///
/// Reserved keys consumed before going into `config_override`:
///   - `on_error` — pulled out as `DelegateStep.on_error`
///
/// Everything else lands in `config_override` as a yaml mapping. Use
/// the map form (`- delegate: { plugin: ..., config: { ... }, ... }`)
/// for nested config shapes the flat kwarg parser doesn't handle.
fn parse_delegate_call_args(inside: &str, source: &str) -> Result<ParsedDelegateCall, ParseError> {
    let parts = split_top_level_commas(inside).map_err(|msg| ParseError::Rule {
        rule: format!("delegate({inside})"),
        msg: format!("{source}: {msg}"),
    })?;
    let mut parts_iter = parts.into_iter();

    let plugin_name = parts_iter
        .next()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ParseError::Rule {
            rule: format!("delegate({inside})"),
            msg: format!(
                "{source}: `delegate(...)` requires a plugin name as the first \
                 positional argument"
            ),
        })?;
    // Read the name whether it was written bare or as a literal.
    let plugin_name = literal_value(&plugin_name).map_err(|msg| ParseError::Rule {
        rule: format!("delegate({inside})"),
        msg: format!("{source}: {msg}"),
    })?;
    if plugin_name.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("delegate({inside})"),
            msg: format!("{source}: `delegate(...)` plugin name cannot be empty"),
        });
    }

    let mut on_error: Option<String> = None;
    let mut config_map = serde_yaml::Mapping::new();

    for raw_kwarg in parts_iter {
        let kwarg = raw_kwarg.trim();
        if kwarg.is_empty() {
            continue;
        }
        let (key, value_str) = kwarg.split_once(':').ok_or_else(|| ParseError::Rule {
            rule: kwarg.to_owned(),
            msg: format!(
                "{source}: `delegate(...)` kwarg `{kwarg}` must be `key: value` \
                     (use the map form for richer config)"
            ),
        })?;
        let key = key.trim();
        let value_str = value_str.trim();
        if key.is_empty() {
            return Err(ParseError::Rule {
                rule: kwarg.to_owned(),
                msg: format!("{source}: `delegate(...)` kwarg has empty key"),
            });
        }
        if key == "on_error" {
            let val = parse_delegate_value(value_str).map_err(|msg| ParseError::Rule {
                rule: kwarg.to_owned(),
                msg: format!("{source}: on_error: {msg}"),
            })?;
            on_error = Some(
                val.as_str()
                    .ok_or_else(|| ParseError::Rule {
                        rule: kwarg.to_owned(),
                        msg: format!("{source}: `on_error` must be a string"),
                    })?
                    .to_owned(),
            );
            continue;
        }
        // Reject `plugin:` as a kwarg — the plugin name is the positional
        // first argument; allowing both would be ambiguous.
        if key == "plugin" {
            return Err(ParseError::Rule {
                rule: kwarg.to_owned(),
                msg: format!(
                    "{source}: `plugin` is set as the first positional argument \
                     of `delegate(...)`; don't pass it as a kwarg too"
                ),
            });
        }
        let value = parse_delegate_value(value_str).map_err(|msg| ParseError::Rule {
            rule: kwarg.to_owned(),
            msg: format!("{source}: `{key}`: {msg}"),
        })?;
        config_map.insert(serde_yaml::Value::String(key.to_owned()), value);
    }

    let config_override = if config_map.is_empty() {
        None
    } else {
        Some(serde_yaml::Value::Mapping(config_map))
    };

    Ok(ParsedDelegateCall {
        plugin_name,
        config_override,
        on_error,
    })
}

/// Sugar verb → [`ElicitKind`] table. Each verb desugars to the same
/// `Step::Elicit` node with the kind fixed.
const ELICIT_VERBS: &[(&str, ElicitKind)] = &[
    ("require_approval", ElicitKind::Approval),
    ("confirm", ElicitKind::Confirm),
    ("require_step_up", ElicitKind::StepUp),
    ("require_attestation", ElicitKind::Attestation),
    ("request_info", ElicitKind::Info),
    ("require_review", ElicitKind::Review),
];

/// Intermediate shape produced by [`parse_elicit_call_args`]. The
/// caller fixes `kind` (from the verb) and `source`, then wraps into
/// `Step::Elicit`.
struct ParsedElicitCall {
    plugin_name: String,
    from: String,
    channel: Option<String>,
    purpose: Option<String>,
    scope: Option<String>,
    timeout: Option<String>,
    on_error: Option<String>,
    config_override: Option<serde_yaml::Value>,
}

/// Parse the inside-parens of an elicitation verb,
/// `verb(plugin_name, from: ..., scope: ..., purpose: ..., timeout: ...)`.
///
/// Shape mirrors `delegate(...)`: the **first positional argument is the
/// `ElicitationHandler` plugin name** (the routing key, resolved
/// `name → entry`). `from` is a required kwarg (the approver, CIBA
/// `login_hint`). `channel` is an OPTIONAL audit label — not a routing
/// key. Recognized keys map to `ElicitStep` fields; `prompt` is an alias
/// for `purpose` (the elicitation-hook doc uses `prompt` for
/// `confirm`/`require_attestation`, `purpose` for `require_approval` —
/// both are the human-readable message). Everything else lands in
/// `config_override` (e.g. `details_link`) for the plugin.
fn parse_elicit_call_args(
    verb: &str,
    inside: &str,
    source: &str,
) -> Result<ParsedElicitCall, ParseError> {
    let parts = split_top_level_commas(inside).map_err(|msg| ParseError::Rule {
        rule: format!("{verb}({inside})"),
        msg: format!("{source}: {msg}"),
    })?;
    let mut parts_iter = parts.into_iter();

    // First positional argument: the plugin name (same as delegate()).
    let plugin_name = parts_iter
        .next()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ParseError::Rule {
            rule: format!("{verb}({inside})"),
            msg: format!(
                "{source}: `{verb}(...)` requires an ElicitationHandler plugin name \
                 as the first positional argument"
            ),
        })?;
    // Read the name whether it was written bare or as a literal, the same way
    // `delegate(...)` reads its own.
    let plugin_name = literal_value(&plugin_name).map_err(|msg| ParseError::Rule {
        rule: format!("{verb}({inside})"),
        msg: format!("{source}: {msg}"),
    })?;

    let mut from: Option<String> = None;
    let mut channel: Option<String> = None;
    let mut purpose: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut timeout: Option<String> = None;
    let mut on_error: Option<String> = None;
    let mut config_map = serde_yaml::Mapping::new();

    // Coerce a parsed value to a string, erroring if it isn't one.
    let as_string = |value: serde_yaml::Value, key: &str| -> Result<String, ParseError> {
        match value {
            serde_yaml::Value::String(s) => Ok(s),
            other => Err(ParseError::Rule {
                rule: format!("{verb}(...)"),
                msg: format!("{source}: `{key}` must be a string, got {other:?}"),
            }),
        }
    };

    for raw_kwarg in parts_iter {
        let kwarg = raw_kwarg.trim();
        if kwarg.is_empty() {
            continue;
        }
        let (key, value_str) = kwarg.split_once(':').ok_or_else(|| ParseError::Rule {
            rule: kwarg.to_owned(),
            msg: format!(
                "{source}: `{verb}(...)` argument `{kwarg}` must be `key: value` \
                 (the plugin name is the first positional argument)"
            ),
        })?;
        let key = key.trim();
        let value_str = value_str.trim();
        if key.is_empty() {
            return Err(ParseError::Rule {
                rule: kwarg.to_owned(),
                msg: format!("{source}: `{verb}(...)` argument has empty key"),
            });
        }
        let value = parse_delegate_value(value_str).map_err(|msg| ParseError::Rule {
            rule: kwarg.to_owned(),
            msg: format!("{source}: `{key}`: {msg}"),
        })?;
        match key {
            "from" => from = Some(as_string(value, "from")?),
            "channel" => channel = Some(as_string(value, "channel")?),
            "scope" => scope = Some(as_string(value, "scope")?),
            "purpose" | "prompt" => purpose = Some(as_string(value, key)?),
            "timeout" => timeout = Some(as_string(value, "timeout")?),
            "on_error" => on_error = Some(as_string(value, "on_error")?),
            // Reject `plugin:` as a kwarg — it's the positional arg.
            "plugin" => {
                return Err(ParseError::Rule {
                    rule: kwarg.to_owned(),
                    msg: format!(
                        "{source}: the plugin name is the first positional argument \
                         of `{verb}(...)`; don't pass it as a kwarg too"
                    ),
                });
            },
            _ => {
                config_map.insert(serde_yaml::Value::String(key.to_owned()), value);
            },
        }
    }

    let from = from.ok_or_else(|| ParseError::Rule {
        rule: format!("{verb}({inside})"),
        msg: format!("{source}: `{verb}(...)` requires `from` (the approver)"),
    })?;

    let config_override = if config_map.is_empty() {
        None
    } else {
        Some(serde_yaml::Value::Mapping(config_map))
    };

    Ok(ParsedElicitCall {
        plugin_name,
        from,
        channel,
        purpose,
        scope,
        timeout,
        on_error,
        config_override,
    })
}

/// Split a `key: value, key: value` string on TOP-LEVEL commas only —
/// commas inside `[...]` or quoted strings are preserved as part of
/// the surrounding value. Returns the comma-separated pieces (trimmed
/// at boundaries; whitespace inside values preserved).
///
/// Errors on unmatched brackets / unterminated quotes — those produce
/// confusing downstream errors otherwise.
fn split_top_level_commas(input: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth: usize = 0;
    let bytes = input.as_bytes();
    let mut i = 0;

    while let Some(&b) = bytes.get(i) {
        if crate::lexical::is_quote(b) {
            // Step over the literal with the shared reader, keeping its text
            // verbatim: each part is handed on to `literal_value`, which is what
            // resolves the escapes, so resolving them here too would do it twice.
            // What changes is that the escape rule is the lexer's now, where this
            // site used to carry one of its own.
            let end = crate::lexical::skip_literal(input, i).map_err(|e| e.msg)?;
            current.push_str(input.get(i..end).unwrap_or_default());
            i = end;
            continue;
        }
        // Take one whole character, so a multi-byte one outside a literal survives
        // rather than being rebuilt from a single byte.
        let ch = input
            .get(i..)
            .and_then(|rest| rest.chars().next())
            .ok_or_else(|| "delegate(...) args are cut mid-character".to_owned())?;
        match ch {
            '[' | '(' | '{' => {
                bracket_depth += 1;
                current.push(ch);
            },
            ']' | ')' | '}' => {
                bracket_depth = bracket_depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unmatched `{ch}` in delegate(...) args"))?;
                current.push(ch);
            },
            ',' if bracket_depth == 0 => {
                parts.push(std::mem::take(&mut current));
            },
            _ => current.push(ch),
        }
        i += ch.len_utf8();
    }
    if bracket_depth != 0 {
        return Err("unbalanced brackets in delegate(...) args".to_owned());
    }
    parts.push(current);
    Ok(parts)
}

/// Parse a single value from the function-call form: a scalar
/// (string / number / bool) or a list literal `[a, b, c]`. Use the
/// map form for anything more complex.
fn parse_delegate_value(s: &str) -> Result<serde_yaml::Value, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty value".to_owned());
    }
    // List literal — recursive scalar parse on each element.
    if let Some(stripped) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let items = split_top_level_commas(stripped)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            out.push(parse_delegate_value(item)?);
        }
        return Ok(serde_yaml::Value::Sequence(out));
    }
    // A quoted literal, read by the same rule the lexer reads one with.
    if let Some(inner) = literal_or_bare(trimmed).map_err(|e| e.msg)? {
        return Ok(serde_yaml::Value::String(inner));
    }
    // Bool literals.
    if trimmed == "true" {
        return Ok(serde_yaml::Value::Bool(true));
    }
    if trimmed == "false" {
        return Ok(serde_yaml::Value::Bool(false));
    }
    // Numeric literals — integer first, then float.
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(serde_yaml::Value::Number(serde_yaml::Number::from(n)));
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        return Ok(serde_yaml::Value::Number(serde_yaml::Number::from(f)));
    }
    // Fallback: treat as bare string (e.g. `target: workday-api` →
    // value is `workday-api`). Same convention as YAML scalars.
    Ok(serde_yaml::Value::String(trimmed.to_owned()))
}

/// The inner text of a value wrapped in one matching pair of `"` or `'`.
///
/// `None` when the input is not wrapped that way, which deliberately includes a
/// lone quote character. `"` both starts and ends with the same byte, so the
/// hand-rolled `starts_with(q) && ends_with(q)` test accepts it and the
/// follow-up `s[1..s.len() - 1]` slices from 1 to 0. Two callers were missing
/// the length guard that made that safe, and `regex(")` or `enum(")` in a policy
/// aborted the parser. Expressing the check as a strip pair cannot have that
/// shape: a lone quote leaves nothing for the suffix strip to remove.
/// Read `s` as one quoted literal, or as a bare word.
///
/// `Ok(Some(v))` for a literal with its escapes resolved, `Ok(None)` for text
/// that opens no literal. A literal that is unterminated, carries an unrecognized
/// escape, or is followed by anything is an error.
///
/// This replaces a `strip_prefix` / `strip_suffix` pair that stripped the
/// outermost matching quotes without reading a literal, so `"a" == "b"` came back
/// as `a" == "b`: two literals spliced through their inner quotes. It is also
/// what makes `regex(")` an unterminated literal instead of a pattern matching
/// one quote character.
fn literal_or_bare(s: &str) -> Result<Option<String>, crate::lexical::LiteralError> {
    crate::lexical::read_whole_literal(s)
}

/// Strip a single pair of wrapping `"`/`'` if present. No-op on
/// unquoted input. Used for the positional plugin name where the
/// operator may have quoted to escape a hyphen or similar (`delegate("workday-oauth")`).
/// The value of `s`, whether it was written as a literal or bare.
///
/// # Errors
///
/// Returns the message of a malformed literal, for a caller whose own error is a
/// `String`.
fn literal_value(s: &str) -> Result<String, String> {
    match literal_or_bare(s) {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Ok(s.trim().to_owned()),
        Err(e) => Err(e.msg),
    }
}

fn parse_step_map(m: &serde_yaml::Mapping, source: &str) -> Result<Step, ParseError> {
    // Canonical structured rule: `- when: X\n  do: Y`.
    // Detected by the presence of *both* `when` and `do` keys — order
    // doesn't matter, and the map can carry extra keys for future
    // extensions (e.g. `id:` for rule identifiers).
    if has_key(m, "when") && has_key(m, "do") {
        return parse_when_do_rule(m, source);
    }

    let mut entries = m.iter();
    let (Some((key_val, body_val)), None) = (entries.next(), entries.next()) else {
        return Err(ParseError::Rule {
            rule: format!("{m:?}"),
            msg: "step map must have exactly one key (PDP call signature, \
                   `when:`/`do:`, or a `predicate: [effects...]` shorthand)"
                .into(),
        });
    };
    let key = key_val.as_str().ok_or_else(|| ParseError::Rule {
        rule: format!("{key_val:?}"),
        msg: "PDP step key must be a string".into(),
    })?;

    // Shorthand multi-effect map: `- "predicate": [list]` (multi-effect
    // from one predicate). Detected by a single-key map
    // whose value is a YAML sequence. Single-effect map shorthand
    // (`- "predicate": deny`) still goes through `parse_step_string`
    // via the colon-split, NOT here — by the time we land in this
    // function, single-string values have already been resolved by
    // the caller's `parse_step` dispatch.
    if let serde_yaml::Value::Sequence(items) = body_val {
        // Skip PDP keys — `cedar:` / `opa:` etc. have list bodies for
        // `on_deny:` / `on_allow:` and need the existing handling.
        // Also skip `sequential:` / `parallel:` orchestration keys
        // since they take a list body and would otherwise be parsed
        // as predicates. The shorthand recognises only predicate-
        // shaped keys.
        let trimmed = key.trim();
        if trimmed != "delegate"
            && trimmed != "sequential"
            && trimmed != "parallel"
            && !is_known_pdp_dialect(trimmed)
        {
            return parse_shorthand_multi_effect(trimmed, items, source);
        }
    }

    // `delegate:` is a special non-PDP step shape — branch before the
    // dialect logic. See `parse_delegate_step` for the expected body.
    if key.trim() == "delegate" {
        return parse_delegate_step(body_val, source);
    }

    // `restrict:` — the backend candidate constraint (accumulating
    // effect, `Taint` family). Body is a map of typed fields + a
    // `custom` label map; branch before the PDP-dialect logic since
    // `restrict` is not a PDP call.
    if key.trim() == "restrict" {
        let spec = parse_restrict_spec(body_val, source)?;
        return Ok(Step::Restrict { spec });
    }

    // Top-level `sequential:` / `parallel:` orchestration —
    // wrap the resulting Effect into an unconditional Rule so the
    // top-level Vec<Step> stays uniform.
    match key.trim() {
        "sequential" => {
            let effect = parse_sequential_effect(body_val, source)?;
            return Ok(Step::Rule(Rule {
                condition: Expression::Always,
                effects: vec![effect],
                source: source.to_owned(),
            }));
        },
        "parallel" => {
            let effect = parse_parallel_effect(body_val, source)?;
            return Ok(Step::Rule(Rule {
                condition: Expression::Always,
                effects: vec![effect],
                source: source.to_owned(),
            }));
        },
        _ => {},
    }

    // Everything left is a PDP call, and the key set is closed. This used to
    // split at `(` and resolve the prefix through an open mapping, which made
    // every unhandled key a custom dialect: `whens:` compiled to a PDP lookup
    // instead of failing, and `pdp(workload):` resolved `pdp` rather than
    // `workload`, so the resolver registered for `workload` could never be
    // reached.
    let (dialect, paren_args) = parse_pdp_key(key)?;

    // Extract args + on_deny/on_allow.
    // Cedar: body map carries args fields directly + on_deny/on_allow.
    // Others: paren_args carries the call signature; body map is reactions only.
    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: format!("{body_val:?}"),
        msg: format!("`{key}:` body must be a map (with on_deny / on_allow / args)"),
    })?;

    let (args, on_deny, on_allow) = extract_pdp_body(body, paren_args.as_deref(), source)?;

    Ok(Step::Pdp {
        call: PdpCall { dialect, args },
        on_deny,
        on_allow,
    })
}

/// Lookup helper — `serde_yaml::Mapping::contains_key` only matches when
/// the search key is a `Value`, so we wrap the string conversion.
fn has_key(m: &serde_yaml::Mapping, key: &str) -> bool {
    m.contains_key(serde_yaml::Value::String(key.to_owned()))
}

/// Whether a top-level map key is a recognized PDP dialect. Used by
/// the shorthand-list detector to avoid mis-parsing a `cedar: [...]`
/// reaction list as a predicate-with-effects map.
fn is_known_pdp_dialect(key: &str) -> bool {
    let base = key.find('(').and_then(|i| key.get(..i)).unwrap_or(key);
    let base = base.trim();
    // `pdp` counts. A sequence body is not a valid PDP shape either way, but
    // routing `pdp(x): [deny]` through the PDP path reports "body must be a map"
    // rather than trying to read `pdp(x)` as a predicate.
    base == PDP_CUSTOM_KEY || PdpDialect::from_builtin_key(base).is_some()
}

/// The key that names a custom dialect: `pdp(name):`.
const PDP_CUSTOM_KEY: &str = "pdp";

/// What a step map may be keyed on, for the error that names the closed set.
const STEP_MAP_KEYS: &str = "`when:` with `do:`, `sequential:`, `parallel:`, \
                            `delegate:`, `restrict:`, a built-in PDP dialect \
                            (`cedar:`, `cel:`, `opa:`, `authzen:`, `nemo:`), or \
                            `pdp(name):` for a custom dialect";

/// The dialect a step-map key names, and the call signature it carries.
///
/// Three productions, and nothing else: `pdp(name)` names a custom dialect, a
/// built-in dialect names itself either bare or with a call signature, and any
/// other key is a misspelling.
///
/// `pdp(name)` carries no call signature, because the parens hold the dialect
/// name. A custom resolver reads its arguments from the body map, the way
/// `cedar:` does.
fn parse_pdp_key(key: &str) -> Result<(PdpDialect, Option<String>), ParseError> {
    let trimmed = key.trim();
    // A key quoted in YAML keeps the separator the parse already consumed
    // (`- 'opa("p/q"):':`), so one trailing colon is redundant rather than
    // content. Tolerated here so the check below is about dropped text.
    let trimmed = trimmed.strip_suffix(':').map_or(trimmed, str::trim_end);
    let Some((name, inside)) = split_call_key(trimmed)? else {
        return PdpDialect::from_builtin_key(trimmed)
            .map(|d| (d, None))
            .ok_or_else(|| unknown_step_map_key(trimmed));
    };
    if name == PDP_CUSTOM_KEY {
        if inside.is_empty() {
            return Err(ParseError::Rule {
                rule: trimmed.to_owned(),
                msg: "`pdp(name):` names the custom dialect to route to, so the name must not \
                      be empty"
                    .to_owned(),
            });
        }
        return Ok((PdpDialect::Custom(inside), None));
    }
    PdpDialect::from_builtin_key(name)
        .map(|d| (d, Some(inside)))
        .ok_or_else(|| unknown_step_map_key(trimmed))
}

/// Split `name(literal)` into its two halves, or `None` when the key carries no
/// call signature.
///
/// The closing paren has to terminate the key. Without that, trailing text after
/// the `)` was read as part of neither half and silently dropped.
fn split_call_key(key: &str) -> Result<Option<(&str, String)>, ParseError> {
    let Some(open) = key.find('(') else {
        return Ok(None);
    };
    let close = key.rfind(')').ok_or_else(|| ParseError::Rule {
        rule: key.to_owned(),
        msg: "missing `)` in PDP call signature".into(),
    })?;
    let after = key.get(close + 1..).unwrap_or("");
    if close < open || !after.trim().is_empty() {
        return Err(ParseError::Rule {
            rule: key.to_owned(),
            msg: "the `)` must end a PDP call signature, with nothing after it".into(),
        });
    }
    // The argument is read as a literal, so a resolver receives the path the
    // author wrote. This site stripped nothing, so `opa("hr/deny")` handed the
    // resolver `"hr/deny"` with the quotes still on it.
    let raw = key.get(open + 1..close).ok_or_else(|| ParseError::Rule {
        rule: key.to_owned(),
        msg: "malformed `()` in PDP call signature".into(),
    })?;
    let inside = literal_value(raw).map_err(|msg| ParseError::Rule {
        rule: key.to_owned(),
        msg,
    })?;
    Ok(Some((key.get(..open).unwrap_or(key).trim(), inside)))
}

/// A step-map key outside the closed set, named beside what is accepted.
fn unknown_step_map_key(key: &str) -> ParseError {
    ParseError::Rule {
        rule: key.to_owned(),
        msg: format!(
            "`{key}:` is not a step-map key. Accepted: {STEP_MAP_KEYS}. A custom PDP dialect is \
             written `pdp({key}):`, not `{key}:`"
        ),
    }
}

/// Parse the canonical `- when: X` `do: Y` rule form. `Y`
/// may be a single effect string (`do: deny`) or a list of effect
/// entries (`do: [run(audit), taint(X), deny('msg')]`). Map-form
/// effects (like a nested `delegate:` block) are allowed inside `do:`
/// via the same dispatch as top-level steps.
fn parse_when_do_rule(m: &serde_yaml::Mapping, source: &str) -> Result<Step, ParseError> {
    // Validate keys — surface a useful error if there's stray content
    // beyond `when:` / `do:` (e.g. typo'd `whens:`). `id:` is reserved
    // for a future rule-identifier extension; tolerate it as a
    // pass-through for now.
    for (k, _) in m {
        let key = k.as_str().unwrap_or("");
        if !matches!(key, "when" | "do" | "id") {
            return Err(ParseError::Rule {
                rule: format!("{m:?}"),
                msg: format!(
                    "unexpected key `{key}` in when/do rule (allowed: `when`, `do`, `id`)"
                ),
            });
        }
    }

    let when_val = m
        .get(serde_yaml::Value::String("when".into()))
        .ok_or_else(|| ParseError::Rule {
            rule: format!("{m:?}"),
            msg: "`when:` key missing from when/do rule".into(),
        })?;
    let predicate = when_val.as_str().ok_or_else(|| ParseError::Rule {
        rule: format!("{when_val:?}"),
        msg: "`when:` must be a predicate string".into(),
    })?;
    // `when:` is rule position, so it passes the same guards the string form does.
    let quoted = format!("when: {predicate}");
    reject_field_operation_in_rule_position(predicate, &quoted)?;
    let condition = parse_predicate(predicate).map_err(|e| ParseError::Rule {
        rule: quoted.clone(),
        msg: format!("{e}"),
    })?;

    let do_val = m
        .get(serde_yaml::Value::String("do".into()))
        .ok_or_else(|| ParseError::Rule {
            rule: format!("{m:?}"),
            msg: "`do:` key missing from when/do rule".into(),
        })?;
    let effects = parse_do_body(do_val, source)?;
    if effects.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{m:?}"),
            msg: "`do:` produced no effects".into(),
        });
    }
    reject_require_with_allow(predicate, &effects, &quoted)?;

    Ok(Step::Rule(Rule {
        condition,
        effects,
        source: source.to_owned(),
    }))
}

/// Parse the shorthand multi-effect map form: `- "predicate": [list]`.
/// Equivalent to the canonical
/// `when: predicate` `do: [list]` shape, just terser.
fn parse_shorthand_multi_effect(
    predicate: &str,
    effect_list: &[serde_yaml::Value],
    source: &str,
) -> Result<Step, ParseError> {
    // The map key is rule position, so it passes the same guards the string form
    // does.
    reject_field_operation_in_rule_position(predicate, predicate)?;
    let condition = parse_predicate(predicate).map_err(|e| ParseError::Rule {
        rule: predicate.to_owned(),
        msg: format!("{e}"),
    })?;

    let mut effects = Vec::with_capacity(effect_list.len());
    for item in effect_list {
        effects.push(parse_effect_value(item, source)?);
    }
    if effects.is_empty() {
        return Err(ParseError::Rule {
            rule: predicate.to_owned(),
            msg: "shorthand multi-effect map produced no effects".into(),
        });
    }
    reject_require_with_allow(predicate, &effects, predicate)?;
    Ok(Step::Rule(Rule {
        condition,
        effects,
        source: source.to_owned(),
    }))
}

/// Parse a `do:` body — single effect string, list of effects, or a
/// single map-shaped effect (`do: { parallel: [...] }`,
/// `do: { delegate: {...} }`, etc.).
fn parse_do_body(val: &serde_yaml::Value, source: &str) -> Result<Vec<Effect>, ParseError> {
    match val {
        serde_yaml::Value::String(s) => Ok(vec![parse_effect_string(s, source)?]),
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .map(|item| parse_effect_value(item, source))
            .collect(),
        serde_yaml::Value::Mapping(_) => {
            // Single map-form effect — delegate, sequential, parallel.
            // Route through parse_effect_value which dispatches by key.
            Ok(vec![parse_effect_value(val, source)?])
        },
        other => Err(ParseError::Rule {
            rule: format!("{other:?}"),
            msg: "`do:` value must be a string, a list of effects, or an effect map".into(),
        }),
    }
}

/// Parse one effect entry from a YAML value — string form or map form
/// (the latter for `delegate:` configs nested inside `do:`,
/// `sequential:`, and `parallel:`).
fn parse_effect_value(val: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    match val {
        serde_yaml::Value::String(s) => parse_effect_string(s, source),
        serde_yaml::Value::Mapping(m) => {
            // `sequential:` / `parallel:` map forms — a single-key
            // map whose key is `sequential` / `parallel` and whose
            // value is a list of effects.
            let mut entries = m.iter();
            if let (Some((k, v)), None) = (entries.next(), entries.next())
                && let Some(key_str) = k.as_str()
            {
                match key_str.trim() {
                    "sequential" => return parse_sequential_effect(v, source),
                    "parallel" => return parse_parallel_effect(v, source),
                    "restrict" => return parse_restrict_effect(v, source),
                    _ => {},
                }
            }
            // Otherwise reuse the existing step-map parser for
            // `delegate:`, `cedar:` etc. and collapse the Step.
            let step = parse_step(val, source)?;
            step_to_effect(step, source)
        },
        other => Err(ParseError::Rule {
            rule: format!("{other:?}"),
            msg: "effect entry must be a string or a map".into(),
        }),
    }
}

/// Parse a `sequential: [list]` effect value. The body MUST be a list
/// (a single effect would defeat the purpose of explicit grouping).
fn parse_sequential_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let items = body.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{body:?}"),
        msg: "`sequential:` body must be a list of effects".into(),
    })?;
    if items.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{body:?}"),
            msg: "`sequential:` body is empty".into(),
        });
    }
    let mut effects = Vec::with_capacity(items.len());
    for item in items {
        effects.push(parse_effect_value(item, source)?);
    }
    Ok(Effect::Sequential(effects))
}

/// Parse a `parallel: [list]` effect value. The body MUST be a list,
/// and the parsed Effect is validated for parallel-purity (rejects
/// `FieldOp` / `Delegate` nested anywhere underneath).
fn parse_parallel_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let items = body.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{body:?}"),
        msg: "`parallel:` body must be a list of effects".into(),
    })?;
    if items.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{body:?}"),
            msg: "`parallel:` body is empty".into(),
        });
    }
    let mut effects = Vec::with_capacity(items.len());
    for item in items {
        effects.push(parse_effect_value(item, source)?);
    }
    let parallel = Effect::Parallel(effects);
    parallel
        .validate_parallel_purity()
        .map_err(|msg| ParseError::Rule {
            rule: source.to_owned(),
            msg,
        })?;
    Ok(parallel)
}

/// Parse a `restrict: { ... }` map into an `Effect::Restrict`. Thin
/// wrapper over [`parse_restrict_spec`] — the effect form (inside `do:` /
/// `sequential:` / `parallel:` / a PDP reaction) and the top-level step
/// form share the same body shape.
fn parse_restrict_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let spec = parse_restrict_spec(body, source)?;
    Ok(Effect::Restrict { spec })
}

/// Parse a `restrict:` body map into a [`RestrictSpec`]. Every field is
/// optional, but an entirely empty `restrict:` is rejected — it would
/// constrain nothing, so it's an author error. Unknown keys are a hard
/// error: the constraint is a fixed contract we ask the host's router to
/// honor, and a typo'd field must never silently widen the eligible set.
///
/// The string-set fields (`allow_models` / `deny_models` / `allow_regions`
/// / `allow_sites`) accept either a literal YAML list **or** a bare
/// scalar `data.*` reference resolved per request.
fn parse_restrict_spec(
    body_val: &serde_yaml::Value,
    source: &str,
) -> Result<crate::constraint::RestrictSpec, ParseError> {
    use crate::constraint::{OnEmpty, RestrictSpec};

    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: source.to_owned(),
        msg: "`restrict:` body must be a map of constraint fields (allow_models / \
              deny_models / allow_regions / allow_sites / max_cost_tier / custom / \
              on_empty)"
            .to_owned(),
    })?;

    let mut spec = RestrictSpec::default();

    for (k, v) in body {
        let key = k.as_str().ok_or_else(|| ParseError::Rule {
            rule: source.to_owned(),
            msg: "`restrict:` field keys must be strings".to_owned(),
        })?;
        // Field-scoped error so authors see e.g. `restrict.allow_models: ...`.
        let field_err = |msg: String| ParseError::Rule {
            rule: source.to_owned(),
            msg: format!("`restrict.{}`: {}", key.trim(), msg),
        };
        match key.trim() {
            "allow_models" => {
                spec.allow_models = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "deny_models" => {
                spec.deny_models = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "allow_regions" => {
                spec.allow_regions = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "allow_sites" => {
                spec.allow_sites = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "max_cost_tier" => {
                let tier = v
                    .as_str()
                    .ok_or_else(|| field_err("must be a string tier".to_owned()))?;
                if tier.trim().is_empty() {
                    return Err(field_err("tier must not be empty".to_owned()));
                }
                spec.max_cost_tier = Some(tier.trim().to_owned());
            },
            "custom" => {
                spec.custom = parse_label_map(v).map_err(&field_err)?;
            },
            "on_empty" => {
                let s = v
                    .as_str()
                    .ok_or_else(|| field_err("must be `deny` or `fallback`".to_owned()))?;
                spec.on_empty = match s.trim() {
                    "deny" => OnEmpty::Deny,
                    "fallback" => OnEmpty::Fallback,
                    other => {
                        return Err(field_err(format!(
                            "unknown value `{other}` (expected `deny` or `fallback`)"
                        )));
                    },
                };
            },
            other => {
                return Err(ParseError::Rule {
                    rule: source.to_owned(),
                    msg: format!(
                        "unknown `restrict:` field `{other}` (allowed: allow_models, \
                         deny_models, allow_regions, allow_sites, max_cost_tier, \
                         custom, on_empty)"
                    ),
                });
            },
        }
    }

    // `is_empty()` ignores `on_empty` (a bare `on_empty:` constrains
    // nothing), so this also rejects `restrict: { on_empty: deny }`.
    if spec.is_empty() {
        return Err(ParseError::Rule {
            rule: source.to_owned(),
            msg: "`restrict:` declares no constraint fields — it would restrict nothing; \
                  remove it or add at least one of allow_models / deny_models / \
                  allow_regions / allow_sites / max_cost_tier / custom"
                .to_owned(),
        });
    }

    Ok(spec)
}

/// Parse a `restrict` string-set field. A YAML **sequence** is a literal
/// set of strings; a bare **scalar string** is a `data.*` reference
/// resolved per request — e.g.
/// `allow_models: data.agents[subject.id].allowed_models`.
fn parse_string_set_spec(
    v: &serde_yaml::Value,
) -> Result<crate::constraint::StringSetSpec, String> {
    use crate::constraint::StringSetSpec;
    match v {
        serde_yaml::Value::Sequence(_) => Ok(StringSetSpec::Literal(parse_string_list(v)?)),
        serde_yaml::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Err("reference path must not be empty".to_owned());
            }
            Ok(StringSetSpec::Ref(s.to_owned()))
        },
        _ => Err("must be a list of strings or a `data.*` reference string".to_owned()),
    }
}

/// Parse a YAML value expected to be a non-empty list of non-empty
/// strings (the `allow_*` / `deny_*` constraint fields). Surrounding
/// whitespace is trimmed; interior characters (e.g. a `*` glob or a `/`
/// in a model id) are preserved.
fn parse_string_list(v: &serde_yaml::Value) -> Result<Vec<String>, String> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| "must be a list of strings".to_owned())?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item
            .as_str()
            .ok_or_else(|| "list entries must be strings".to_owned())?;
        if s.trim().is_empty() {
            return Err("list entries must not be empty".to_owned());
        }
        out.push(s.trim().to_owned());
    }
    if out.is_empty() {
        return Err("list must not be empty".to_owned());
    }
    Ok(out)
}

/// Parse a YAML value expected to be a flat map of `label: value`
/// pairs (the `custom` field). Scalar values (string / bool / number)
/// are coerced to their string form: `custom` is equality-matched
/// labels, not typed values.
fn parse_label_map(
    v: &serde_yaml::Value,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let map = v
        .as_mapping()
        .ok_or_else(|| "must be a map of `label: value` pairs".to_owned())?;
    let mut out = std::collections::BTreeMap::new();
    for (k, val) in map {
        let key = k
            .as_str()
            .ok_or_else(|| "label keys must be strings".to_owned())?;
        if key.trim().is_empty() {
            return Err("label keys must not be empty".to_owned());
        }
        let value = scalar_to_string(val).ok_or_else(|| {
            format!(
                "label `{}` must be a scalar (string / bool / number)",
                key.trim()
            )
        })?;
        out.insert(key.trim().to_owned(), value);
    }
    if out.is_empty() {
        return Err("`custom` map must not be empty".to_owned());
    }
    Ok(out)
}

/// Coerce a scalar YAML value to its string form for a `custom` label.
/// Non-scalars (sequences, maps, null) return `None` — a label value
/// must be a single comparable token.
fn scalar_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse one effect string. Reuses [`parse_step_string`] for forms
/// shared with top-level steps (`run(...)`, `taint(...)`,
/// `delegate(...)`, predicate-action rules), then collapses the
/// resulting Step into an Effect.
fn parse_effect_string(s: &str, source: &str) -> Result<Effect, ParseError> {
    // Bare `allow` / `deny` / `deny('reason')` / `deny('reason', 'code')`
    // are accepted directly — they map to control effects with no
    // associated condition. Same parsing as the right-hand side of a
    // shorthand `predicate: action` rule.
    let trimmed = s.trim();
    if let Some(mut effects) = try_bare_action(trimmed)
        && effects.len() == 1
        && let Some(only) = effects.pop()
    {
        return Ok(only);
    }
    if let Some(effect) = try_parse_deny_call(trimmed, s)? {
        return Ok(effect);
    }
    // Content effect — `result.salary | redact`, `args.ssn | mask(4)`,
    // etc. Detected by a top-level `|` that splits a dotted path from
    // a pipe chain. The pipe is at top level (depth 0); commas /
    // parens inside the chain don't get confused.
    if let Some(field_op) = try_parse_field_op(trimmed, s)? {
        return Ok(field_op);
    }
    // Everything else (plugin/delegate/taint/rule) routes through the
    // step parser; collapse the result.
    let step = parse_step_string(s, source)?;
    step_to_effect(step, source)
}

/// Parse `<path> | <stage> [| <stage>...]` into an `Effect::FieldOp`.
/// Returns `Ok(None)` when no top-level `|` is found so the caller can
/// fall through to other effect handlers.
fn try_parse_field_op(s: &str, rule: &str) -> Result<Option<Effect>, ParseError> {
    let Some(pipe_idx) = find_top_level_pipe(s) else {
        return Ok(None);
    };
    let (Some(path), Some(chain)) = (s.get(..pipe_idx), s.get(pipe_idx + 1..)) else {
        return Ok(None);
    };
    let (path, chain) = (path.trim(), chain.trim());
    if path.is_empty() || chain.is_empty() {
        return Ok(None);
    }
    // The path must look like a dotted field reference. Anything else
    // (e.g. `role.hr | role.security` — though that wouldn't get here
    // because predicates don't appear in effect position) is a sign
    // the author meant something other than a field op.
    if !is_valid_field_path(path) {
        return Ok(None);
    }
    let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
        rule: rule.to_owned(),
        msg: format!("field op `{path}`: {e}"),
    })?;
    if pipeline.stages.is_empty() {
        return Err(ParseError::Rule {
            rule: rule.to_owned(),
            msg: format!("field op `{path}` has no stages"),
        });
    }
    Ok(Some(Effect::FieldOp {
        path: path.to_owned(),
        stages: pipeline.stages,
    }))
}

/// Find the byte index of the first top-level `|` that isn't part of
/// `||` (logical-or inside a predicate). Depth-aware: skips `|` inside
/// `(...)` / `[...]` and inside single- or double-quoted strings.
fn find_top_level_pipe(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if crate::lexical::is_quote(b) {
            // This site skipped two bytes after a backslash, which is one of the
            // three escape rules that used to coexist and the only one that could
            // land mid-character on multi-byte content. The shared reader cannot.
            match crate::lexical::skip_literal(s, i) {
                Ok(end) => i = end,
                Err(_) => return None,
            }
            continue;
        }
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'|' if depth == 0 => {
                // `||` is not an operator, and the lexer says so. Stepping over it
                // here keeps this from reading the first `|` as a chain separator
                // and reporting a stage fault for an operator mistake.
                if bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                    continue;
                }
                return Some(i);
            },
            _ => {},
        }
        i += 1;
    }
    None
}

/// A field path is a dotted identifier sequence rooted at `args.` or
/// `result.`. Reject anything else early so a stray `role.hr | …` in
/// effect position fails fast.
fn is_valid_field_path(s: &str) -> bool {
    let Some(rest) = s
        .strip_prefix("args.")
        .or_else(|| s.strip_prefix("result."))
    else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

/// Collapse a `Step` produced by the legacy step parser into an
/// `Effect`. The legitimate inputs are `Plugin`, `Delegate`, `Taint`,
/// and `Rule` (when a control action like `deny`/`allow` was parsed).
/// Anything else (`Pdp`) is rejected — nested PDP calls inside `do:`
/// are out of scope.
/// Recursively map a top-level `Step` (as produced by `parse_step`) into
/// an `Effect`. Used at `compile_apl_blocks` — keeps `parse_step`'s
/// internal shape for the moment while the public IR collapses to Effect.
/// All five Step variants map cleanly: Rule → When, Pdp → Pdp (recursive
/// on reactions), Plugin/Delegate/Taint pass-through.
pub(crate) fn step_to_top_level_effect(step: Step) -> Result<Effect, ParseError> {
    match step {
        Step::Rule(rule) => Ok(Effect::When {
            condition: rule.condition,
            body: rule.effects,
            source: rule.source,
        }),
        Step::Pdp {
            call,
            on_allow,
            on_deny,
        } => {
            let on_allow = on_allow
                .into_iter()
                .map(step_to_top_level_effect)
                .collect::<Result<Vec<_>, _>>()?;
            let on_deny = on_deny
                .into_iter()
                .map(step_to_top_level_effect)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Effect::Pdp {
                call,
                on_allow,
                on_deny,
            })
        },
        Step::Plugin { name } => Ok(Effect::Plugin { name }),
        Step::Delegate(d) => Ok(Effect::Delegate(d)),
        Step::Elicit(e) => Ok(Effect::Elicit(e)),
        Step::Taint { label, scopes } => Ok(Effect::Taint { label, scopes }),
        Step::Restrict { spec } => Ok(Effect::Restrict { spec }),
    }
}

fn step_to_effect(step: Step, source: &str) -> Result<Effect, ParseError> {
    match step {
        Step::Plugin { name } => Ok(Effect::Plugin { name }),
        Step::Delegate(d) => Ok(Effect::Delegate(d)),
        Step::Elicit(e) => Ok(Effect::Elicit(e)),
        Step::Taint { label, scopes } => Ok(Effect::Taint { label, scopes }),
        Step::Restrict { spec } => Ok(Effect::Restrict { spec }),
        Step::Rule(rule) => {
            // Nested when/do inside a do: list isn't supported
            // — only control effects (allow/deny) flatten cleanly.
            if !matches!(rule.condition, Expression::Always) {
                return Err(ParseError::Rule {
                    rule: source.to_owned(),
                    msg: "conditional rules nested inside `do:` are not supported \
                          (use a sibling `when:`/`do:` rule instead)"
                        .into(),
                });
            }
            if rule.effects.len() != 1 {
                return Err(ParseError::Rule {
                    rule: source.to_owned(),
                    msg: format!(
                        "unconditional rule inside `do:` must produce exactly one \
                         effect, got {}",
                        rule.effects.len()
                    ),
                });
            }
            rule.effects
                .into_iter()
                .next()
                .ok_or_else(|| ParseError::Rule {
                    rule: source.to_owned(),
                    msg: "unconditional rule inside `do:` produced no effect".into(),
                })
        },
        Step::Pdp { .. } => Err(ParseError::Rule {
            rule: source.to_owned(),
            msg: "PDP calls inside `do:` are not supported (use a sibling \
                  step instead)"
                .into(),
        }),
    }
}

/// Parse a `delegate:` step body into a `Step::Delegate`. Accepted
/// YAML shape:
///
/// ```yaml
/// - delegate:
///     plugin: workday-oauth          # required — TokenDelegateHook plugin name
///     config:                         # optional — per-call config override
///       target: workday-api
///       permissions: [read_compensation]
///     on_error: deny                  # optional — deny | continue (default deny)
/// ```
///
/// `config:` is opaque — the framework hands it to the named plugin
/// via the existing per-call config-override pathway. The plugin
/// owns the typed schema (target / audience / permissions / mode /
/// attenuation are conventions, not parser-enforced).
fn parse_delegate_step(body_val: &serde_yaml::Value, source: &str) -> Result<Step, ParseError> {
    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: source.to_owned(),
        msg: "`delegate:` body must be a map with `plugin:` and optional \
              `config:` / `on_error:`"
            .to_owned(),
    })?;

    let plugin = body
        .get(serde_yaml::Value::String("plugin".to_owned()))
        .ok_or_else(|| ParseError::Rule {
            rule: source.to_owned(),
            msg: "`delegate:` requires `plugin: <name>` referencing a \
                  top-level plugin registered under `token.delegate`"
                .to_owned(),
        })?;
    let plugin_name = plugin
        .as_str()
        .ok_or_else(|| ParseError::Rule {
            rule: source.to_owned(),
            msg: "`delegate.plugin` must be a string".to_owned(),
        })?
        .to_owned();
    if plugin_name.is_empty() {
        return Err(ParseError::Rule {
            rule: source.to_owned(),
            msg: "`delegate.plugin` cannot be empty".to_owned(),
        });
    }

    let config_override = body
        .get(serde_yaml::Value::String("config".to_owned()))
        .cloned();

    let on_error = match body.get(serde_yaml::Value::String("on_error".to_owned())) {
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| ParseError::Rule {
                    rule: source.to_owned(),
                    msg: "`delegate.on_error` must be a string (e.g. `deny`, \
                          `continue`)"
                        .to_owned(),
                })?
                .to_owned(),
        ),
        None => None,
    };

    Ok(Step::Delegate(DelegateStep {
        plugin_name,
        config_override,
        on_error,
        source: source.to_owned(),
    }))
}

/// Split a PDP body into (args, `on_deny`, `on_allow`).
///
/// If `paren_args` is `Some`, the call's args are the string inside the
/// parens (OPA-style) and the body map only carries reactions. If `None`,
/// the body map carries both args and reactions (Cedar-style); we strip
/// the reaction keys and treat what's left as args.
fn extract_pdp_body(
    body: &serde_yaml::Mapping,
    paren_args: Option<&str>,
    source: &str,
) -> Result<(serde_yaml::Value, Vec<Step>, Vec<Step>), ParseError> {
    let mut on_deny = Vec::new();
    let mut on_allow = Vec::new();
    let mut args_map = serde_yaml::Mapping::new();

    for (k, v) in body {
        match k.as_str() {
            Some("on_deny") => {
                on_deny = parse_reaction_list(v, source, "on_deny")?;
            },
            Some("on_allow") => {
                on_allow = parse_reaction_list(v, source, "on_allow")?;
            },
            _ => {
                // Non-reaction key — part of args (Cedar-style).
                args_map.insert(k.clone(), v.clone());
            },
        }
    }

    let args = match paren_args {
        Some(s) => serde_yaml::Value::String(s.to_owned()),
        None => serde_yaml::Value::Mapping(args_map),
    };

    Ok((args, on_deny, on_allow))
}

fn parse_reaction_list(
    v: &serde_yaml::Value,
    source: &str,
    which: &str,
) -> Result<Vec<Step>, ParseError> {
    let list = v.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{v:?}"),
        msg: format!("`{which}:` must be a list of steps"),
    })?;
    list.iter()
        .enumerate()
        .map(|(i, entry)| parse_step(entry, &format!("{source}.{which}[{i}]")))
        .collect()
}

/// Extract the args inside a call like `taint(X, Y)` or `run(foo)`.
/// Returns the substring between the outermost matching parens.
fn extract_call_args(line: &str, name: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with(name) {
        return None;
    }
    let after = line.get(name.len()..)?;
    if !after.starts_with('(') {
        return None;
    }
    // Find the matching close paren, stepping over quoted text rather than
    // counting parens inside it. Counting them is why `deny("blocked (see
    // policy)")` was refused as malformed: the paren in the reason closed the
    // call early, and `deny("a)b")` closed it earlier still.
    let bytes = after.as_bytes();
    let mut depth = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if crate::lexical::is_quote(b) {
            if let Ok(end) = crate::lexical::skip_literal(after, i) {
                i = end;
                continue;
            }
            // Unterminated: treat the quote as an ordinary character so the close
            // paren is still found, and let whoever reads the argument name the
            // literal. Returning None here would report the call malformed for a
            // quoting mistake.
            i += 1;
            continue;
        }
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // Anything after the close paren is invalid.
                    if after.get(i + 1..)?.trim().is_empty() {
                        return Some(after.get(1..i)?.to_owned());
                    }
                    return None;
                }
            },
            _ => {},
        }
        i += 1;
    }
    None
}

/// Parse a pipe-chain string into a `Pipeline`.
///
/// Splits on `|` (outside parens/quotes), trims each stage, parses each.
/// Empty pipelines (empty string or whitespace) are valid — they produce
/// `Pipeline { stages: vec![] }`.
/// # Errors
///
/// Returns `ParseError::Predicate` when a stage name is unknown or its
/// arguments do not parse. A `validate` stage is rejected here because it is
/// only meaningful on a field rule.
pub fn parse_pipeline(src: &str) -> Result<Pipeline, ParseError> {
    let trimmed = src.trim();
    let mut pipeline = Pipeline::new();
    if trimmed.is_empty() {
        // An absent field value, not a malformed chain. Kept because callers hand
        // this an optional value directly.
        return Ok(pipeline);
    }
    let segments = split_top_level(trimmed, b'|');
    for seg in segments {
        let seg = seg.trim();
        if seg.is_empty() {
            return Err(ParseError::Predicate {
                predicate: src.to_owned(),
                msg: "empty stage in a pipe chain; a leading, trailing or doubled `|` leaves a \
                      position with no stage in it"
                    .to_owned(),
            });
        }
        pipeline.push(parse_stage(seg)?);
    }
    Ok(pipeline)
}

/// Split `s` on `delim` at depth 0 — respects parens and quotes.
fn split_top_level(s: &str, delim: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if crate::lexical::is_quote(b) {
            // The shared reader steps over the literal, so an escaped quote
            // inside one does not end it. This site tracked quotes with no escape
            // rule at all, which is one of the three rules that used to coexist.
            match crate::lexical::skip_literal(s, i) {
                Ok(end) => i = end,
                // Unterminated: stop splitting and let the stage reader name the
                // literal. Swallowing the rest silently is what it used to do.
                Err(_) => break,
            }
            continue;
        }
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            c if c == delim && depth == 0 => {
                if let Some(segment) = s.get(start..i) {
                    out.push(segment);
                }
                start = i + 1;
            },
            _ => {},
        }
        i += 1;
    }
    out.push(s.get(start..).unwrap_or(""));
    out
}

fn parse_stage(src: &str) -> Result<Stage, ParseError> {
    let s = src.trim();
    let bad = |msg: &str| ParseError::Predicate {
        predicate: src.to_owned(),
        msg: msg.to_owned(),
    };

    // Bare range literal: starts with `-`, digit, or `..`.
    if let Some(stage) = try_parse_range(s) {
        return Ok(stage);
    }

    // Otherwise the stage starts with an identifier (keyword) optionally
    // followed by `(args)`.
    let (head, args) = split_head_args(s).ok_or_else(|| bad("expected stage identifier"))?;

    match (head, args.as_deref()) {
        ("str", None) => Ok(Stage::Type(TypeCheck::Str)),
        ("int", None) => Ok(Stage::Type(TypeCheck::Int)),
        ("bool", None) => Ok(Stage::Type(TypeCheck::Bool)),
        ("float", None) => Ok(Stage::Type(TypeCheck::Float)),
        ("email", None) => Ok(Stage::Type(TypeCheck::Email)),
        ("url", None) => Ok(Stage::Type(TypeCheck::Url)),
        ("uuid", None) => Ok(Stage::Type(TypeCheck::Uuid)),
        ("redact", None) => Ok(Stage::Redact { condition: None }),
        ("omit", None) => Ok(Stage::Omit),
        ("hash", None) => Ok(Stage::Hash),
        ("mask", Some(a)) => parse_stage_mask(a, &bad),
        ("redact", Some(a)) => parse_stage_redact_cond(a, src),
        ("hash", Some(_)) => Err(bad("hash takes no arguments")),
        ("omit", Some(_)) => Err(bad(
            "omit takes no arguments — for conditional omit, use a policy rule predicate",
        )),
        ("len", Some(a)) => parse_stage_len(a, &bad),
        ("enum", Some(a)) => parse_stage_enum(a, &bad),
        ("regex", Some(a)) => parse_stage_regex(a, &bad),
        ("validate", Some(a)) => Err(parse_stage_validate_rejected(a, &bad)),
        ("plugin", Some(_)) => Err(bad(PLUGIN_IS_RUN)),
        ("run", Some(a)) => parse_stage_plugin(head, a, &bad),
        ("taint", Some(a)) => parse_taint(a, src),

        // Scan placeholders parse as bare identifiers.
        ("pii.redact", None) => Ok(Stage::Scan {
            kind: ScanKind::PiiRedact,
        }),
        ("pii.detect", None) => Ok(Stage::Scan {
            kind: ScanKind::PiiDetect,
        }),
        ("injection.scan", None) => Ok(Stage::Scan {
            kind: ScanKind::InjectionScan,
        }),

        (other, _) => Err(bad(&format!("unknown stage `{other}`"))),
    }
}

fn parse_stage_mask(a: &str, bad: &impl Fn(&str) -> ParseError) -> Result<Stage, ParseError> {
    let n: usize = a.trim().parse().map_err(|e| {
        bad(&format!(
            "mask(N) expects a non-negative integer, got `{a}`: {e}"
        ))
    })?;
    Ok(Stage::Mask { keep_last: n })
}

fn parse_stage_redact_cond(a: &str, src: &str) -> Result<Stage, ParseError> {
    // redact(!perm.view_ssn) — argument is a predicate expression.
    let cond = parse_predicate(a).map_err(|e| ParseError::Predicate {
        predicate: src.to_owned(),
        msg: format!("invalid redact() condition: {e}"),
    })?;
    Ok(Stage::Redact {
        condition: Some(cond),
    })
}

fn parse_stage_len(a: &str, bad: &impl Fn(&str) -> ParseError) -> Result<Stage, ParseError> {
    let (min, max) = parse_range_inner(a)
        .ok_or_else(|| bad(&format!("len(...) expects N..M range, got `{a}`")))?;
    // `try_from` carries both halves of what the manual check plus cast did:
    // negatives are rejected, and the conversion is exact on every target width
    // rather than only on 64-bit.
    let to_usize = |v: i64| -> Result<usize, ParseError> {
        usize::try_from(v).map_err(|e| bad(&format!("len bound `{v}` is not a valid length: {e}")))
    };
    Ok(Stage::Length {
        min: min.map(to_usize).transpose()?,
        max: max.map(to_usize).transpose()?,
    })
}

fn parse_stage_enum(a: &str, bad: &impl Fn(&str) -> ParseError) -> Result<Stage, ParseError> {
    let values = split_top_level(a, b',')
        .into_iter()
        .map(|v| literal_value(v.trim()).map_err(|m| bad(&m)))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(bad("enum() requires at least one value"));
    }
    Ok(Stage::Enum { values })
}

fn parse_stage_regex(a: &str, bad: &impl Fn(&str) -> ParseError) -> Result<Stage, ParseError> {
    Ok(Stage::Regex {
        pattern: literal_value(a.trim()).map_err(|m| bad(&m))?,
    })
}

// Named-validator dispatch (`validate(name)`) is in the spec
// but not implemented in this build — the evaluator's no-op stub would
// silently let invalid values through. Reject at compile time so
// operators notice immediately and reach for one of the working
// alternatives:
//
//   * `regex("pattern")` — inline named-regex equivalent
//   * `run(name)` — full plugin dispatch for rich validation (Luhn,
//     format-with-context, etc.)
//
// When the ValidatorRegistry slice lands, this rejection flips back to
// returning `Stage::Validate { name }`.
fn parse_stage_validate_rejected(a: &str, bad: &impl Fn(&str) -> ParseError) -> ParseError {
    bad(&format!(
        "`validate({})` — named-validator dispatch is not implemented \
         in this build. Use `regex(\"pattern\")` for a named-regex \
         equivalent, or `run({})` for richer validation logic.",
        a.trim(),
        a.trim(),
    ))
}

fn parse_stage_plugin(
    head: &str,
    a: &str,
    bad: &impl Fn(&str) -> ParseError,
) -> Result<Stage, ParseError> {
    let name = a.trim();
    if name.is_empty() {
        // Mirror the empty-name guard in `parse_step_string` so both the
        // policy-step and field-stage paths reject a nameless `plugin()`
        // / `run()` with the same diagnostic.
        return Err(bad(&format!(
            "`{head}(...)`: plugin name must not be empty"
        )));
    }
    Ok(Stage::Plugin {
        name: name.to_owned(),
    })
}

/// Try to parse `s` as a bare range literal: `0..100`, `..500`, `0..`, `0..1M`.
fn try_parse_range(s: &str) -> Option<Stage> {
    if !s.contains("..") {
        return None;
    }
    // Quick reject: must not start with a letter (would be a keyword).
    let first = s.as_bytes().first().copied()?;
    if first.is_ascii_alphabetic() || first == b'_' {
        return None;
    }
    let (min, max) = parse_range_inner(s)?;
    Some(Stage::Range { min, max })
}

/// Parse the inside of a range expression: `N..M`, `..M`, `N..`.
/// Returns `Some((min, max))` if shape is valid; `None` if it's not a range.
fn parse_range_inner(s: &str) -> Option<(Option<i64>, Option<i64>)> {
    let dotdot = s.find("..")?;
    let left = s.get(..dotdot)?.trim();
    let right = s.get(dotdot + 2..)?.trim();
    let min = if left.is_empty() {
        None
    } else {
        Some(parse_numeric_with_suffix(left)?)
    };
    let max = if right.is_empty() {
        None
    } else {
        Some(parse_numeric_with_suffix(right)?)
    };
    if min.is_none() && max.is_none() {
        return None; // `..` alone isn't a useful range
    }
    Some((min, max))
}

/// Parse a number with optional `k/K` (×1000) or `m/M` (×`1_000_000`) suffix.
fn parse_numeric_with_suffix(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, mult) = if let Some(rest) = s.strip_suffix(['k', 'K']) {
        (rest, 1_000_i64)
    } else if let Some(rest) = s.strip_suffix(['m', 'M']) {
        (rest, 1_000_000_i64)
    } else {
        (s, 1_i64)
    };
    let n: i64 = num_part.parse().ok()?;
    n.checked_mul(mult)
}

/// Split `s` (a stage form like `mask(4)`) into `(head, Some(args_inside_parens))`
/// or `(head, None)` if there are no parens.
fn split_head_args(s: &str) -> Option<(&str, Option<String>)> {
    if let Some(open) = s.find('(') {
        // Match the corresponding closing paren at depth 0, stepping over quoted
        // text. Counting parens inside a literal is why `regex("(")` was refused
        // as having no stage identifier: the paren in the pattern closed the call
        // before the real one did.
        let bytes = s.as_bytes();
        let mut depth = 0;
        let mut close = None;
        let mut i = open;
        while let Some(&b) = bytes.get(i) {
            if crate::lexical::is_quote(b) {
                if let Ok(end) = crate::lexical::skip_literal(s, i) {
                    i = end;
                    continue;
                }
                // Unterminated: fall through and treat the quote as an ordinary
                // character, so the close paren is still found and the argument
                // reader is what names the literal. Stopping here would report a
                // missing stage identifier for a quoting mistake.
                i += 1;
                continue;
            }
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                },
                _ => {},
            }
            i += 1;
        }
        let close = close?;
        let head = s.get(..open)?.trim();
        if head.is_empty() {
            return None;
        }
        let args = s.get(open + 1..close)?.to_owned();
        // Reject trailing garbage after the closing paren.
        s.get(close + 1..)?
            .trim()
            .is_empty()
            .then_some((head, Some(args)))
    } else {
        let head = s.trim();
        if head.is_empty() {
            None
        } else {
            Some((head, None))
        }
    }
}

fn parse_taint(args: &str, src: &str) -> Result<Stage, ParseError> {
    // taint(label) | taint(label, session) | taint(label, [session, message])
    let parts = split_top_level(args, b',');
    let Some(label) = parts.first().map(|p| p.trim().to_owned()) else {
        return Err(ParseError::Predicate {
            predicate: src.to_owned(),
            msg: "taint() requires at least a label".into(),
        });
    };
    if label.is_empty() {
        return Err(ParseError::Predicate {
            predicate: src.to_owned(),
            msg: "taint label must not be empty".into(),
        });
    }

    let scopes = if parts.len() == 1 {
        vec![TaintScope::Session] // default
    } else {
        let scope_arg = parts.get(1..).unwrap_or(&[]).join(",");
        let scope_arg = scope_arg.trim();
        if let Some(inner) = scope_arg
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            split_top_level(inner, b',')
                .into_iter()
                .map(|s| parse_taint_scope(s.trim(), src))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![parse_taint_scope(scope_arg, src)?]
        }
    };

    Ok(Stage::Taint { label, scopes })
}

fn parse_taint_scope(s: &str, src: &str) -> Result<TaintScope, ParseError> {
    match s {
        "session" => Ok(TaintScope::Session),
        "message" => Ok(TaintScope::Message),
        other => Err(ParseError::Predicate {
            predicate: src.to_owned(),
            msg: format!("unknown taint scope `{other}` (expected `session` or `message`)"),
        }),
    }
}

#[derive(Debug, Default, Deserialize)]
/// One route's raw blocks, before compilation.
///
/// `deny_unknown_fields` is what keeps a policy from being dropped: the four
/// fields below are the whole APL body, and a catch-all here would swallow a
/// removed spelling into a route that compiles empty. Safe because the struct
/// has no `#[serde(flatten)]`. A section's structural keys never reach this
/// shape: the APL runtime copies only the policy terms into the block it
/// compiles.
#[serde(deny_unknown_fields)]
pub struct RouteYaml {
    /// `authorization:` block — `{ pre_invocation, post_invocation }`. The
    /// only place the two phase lists appear. `None` means the section wrote no
    /// block at all.
    #[serde(default, deserialize_with = "authorization_block")]
    pub authorization: Option<AuthorizationYaml>,

    /// `args:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// `result:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub result: HashMap<String, String>,

    /// Per-route plugin overrides — only the spec-overridable keys
    /// (config / capabilities / `on_error`). Merged on top of the root
    /// `plugins:` declaration at dispatch time.
    #[serde(default)]
    pub plugins: HashMap<String, PluginOverride>,
}

/// Read the `authorization:` value, treating an explicit null as a block that
/// names neither phase rather than as no block at all. Serde would map a null
/// onto `None`, which is how `authorization:` written with nothing under it used
/// to load clean and enforce nothing. `reject_empty_authorization` refuses the
/// result. `serde(default)` still supplies `None` when the key is absent, since
/// this runs only for a key that is present.
fn authorization_block<'de, D>(de: D) -> Result<Option<AuthorizationYaml>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(de)?;
    if value.is_null() {
        return Ok(Some(AuthorizationYaml::default()));
    }
    AuthorizationYaml::deserialize(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

/// The `authorization:` block, which carries at least one of the two phase
/// lists. Each phase is `Option` so a block naming neither is a load error
/// rather than an empty block that authorizes nothing; `compile_route` and
/// `compile_apl_blocks` both refuse one.
///
/// `deny_unknown_fields` is load-bearing: without it a removed key nested under
/// the wrapper (`authorization: { policy: [...] }`) would be silently dropped by
/// serde — both phases absent, no error, no authorization enforced (a
/// fail-open). Denying unknown fields turns that into a load error and also
/// catches typos like `pre_invocaton:`. Safe here because the struct has no
/// `#[serde(flatten)]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationYaml {
    /// Effects run before the call. Each entry is either a string (rule /
    /// plugin / taint) or a single-key map (PDP call with reactions). See
    /// `parse_step`.
    #[serde(default)]
    pub pre_invocation: Option<Vec<serde_yaml::Value>>,

    /// Effects run after it.
    #[serde(default)]
    pub post_invocation: Option<Vec<serde_yaml::Value>>,
}

/// Refuse an `authorization:` block that contributes no step. Such a block
/// authorizes nothing, and the has-APL gate would drop the route as if it
/// carried no policy at all, so it is rejected before that gate rather than
/// read as an empty one.
///
/// A phase written as an empty list counts as absent. It reaches the same end
/// state by a different spelling: layers append, so an empty list overrides
/// nothing and cannot be the way a section opts out of an inherited one.
fn reject_empty_authorization(
    location: &str,
    authorization: Option<&AuthorizationYaml>,
) -> Result<(), ParseError> {
    let contributes_nothing = authorization.is_some_and(|a| {
        let empty =
            |phase: &Option<Vec<serde_yaml::Value>>| phase.as_ref().is_none_or(Vec::is_empty);
        empty(&a.pre_invocation) && empty(&a.post_invocation)
    });
    if contributes_nothing {
        return Err(ParseError::EmptyAuthorization {
            location: location.to_owned(),
        });
    }
    Ok(())
}

/// Compile the APL bodies (authorization/args/result/plugins) of a
/// single block into a `CompiledRoute`. Doesn't gate on "has any APL
/// fields": a block that declares no APL term compiles to an empty route.
/// `source` is the path prefix baked into rule/pipeline diagnostics
/// (e.g. `"global.policy.all"`, `"route.get_compensation"`).
///
/// `authorization:` is the only place the two phase lists appear, and a block
/// naming neither is refused rather than read as empty.
/// Compile one declared `args:` / `result:` entry into its pipeline.
///
/// A declared entry with no stages is a load error, while the public
/// [`parse_pipeline`] keeps answering an empty input with an empty pipeline. Two
/// positions, two answers: that entry point takes a field value that may be
/// absent, and absent is not malformed. Here the author named a field and then
/// left its chain empty, which used to compile to a no-op `FieldRule`.
fn compile_declared_pipeline(half: &str, field: &str, chain: &str) -> Result<Pipeline, ParseError> {
    let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
        rule: format!("{half}.{field}: {chain:?}"),
        msg: format!("{e}"),
    })?;
    if pipeline.stages.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{half}.{field}: {chain:?}"),
            msg: format!(
                "`{half}.{field}:` declares no stages. A field entry names an operation to run on \
                 the field, so an empty chain is a no-op the author did not mean; remove the \
                 entry or give it a stage"
            ),
        });
    }
    Ok(pipeline)
}

fn compile_apl_blocks(source: &str, raw: RouteYaml) -> Result<CompiledRoute, ParseError> {
    reject_empty_authorization(source, raw.authorization.as_ref())?;
    let mut route = CompiledRoute::new(source);
    let (auth_pre, auth_post) = raw
        .authorization
        .map(|a| {
            (
                a.pre_invocation.unwrap_or_default(),
                a.post_invocation.unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    for (i, entry) in auth_pre.iter().enumerate() {
        let step = parse_step(entry, &format!("{source}.pre_invocation[{i}]"))?;
        route.pre_invocation.push(step_to_top_level_effect(step)?);
    }
    for (i, entry) in auth_post.iter().enumerate() {
        let step = parse_step(entry, &format!("{source}.post_invocation[{i}]"))?;
        route.post_invocation.push(step_to_top_level_effect(step)?);
    }
    for (half, entries, out) in [
        ("args", &raw.args, &mut route.args),
        ("result", &raw.result, &mut route.result),
    ] {
        for (field, chain) in entries {
            let pipeline = compile_declared_pipeline(half, field, chain)?;
            out.push(FieldRule {
                field: field.clone(),
                pipeline,
                source: format!("{source}.{half}.{field}"),
            });
        }
    }
    route.plugin_overrides = raw.plugins;
    Ok(route)
}

/// Compile a single APL policy block from a `serde_yaml::Value` whose
/// shape is the body of a section's policy block:
///
/// ```yaml
/// args:
///   employee_id: "str"
/// authorization:
///   pre_invocation:
///     - "require(authenticated)"
///   post_invocation:
///     - "taint(forward)"
/// result:
///   ssn: "redact(!perm.view_ssn)"
/// ```
///
/// Used by external orchestrators (praxis-policy-apl-runtime's `AplConfigVisitor`) that
/// have already located an APL block inside a larger unified-config
/// YAML. `source` is woven into per-rule / per-pipeline diagnostic paths.
/// Returns an empty `CompiledRoute` when the value is null or contains
/// no APL fields — callers that want a "is this empty?" gate can check
/// `declared_phases().is_empty()` on the result.
/// # Errors
///
/// Returns `ParseError::Yaml` when the block does not deserialize into the route
/// shape, or the per-rule error from a rule or pipeline that fails to compile.
pub fn compile_policy_block_value(
    source: &str,
    block: &serde_yaml::Value,
) -> Result<CompiledRoute, ParseError> {
    if block.is_null() {
        return Ok(CompiledRoute::new(source));
    }
    let raw: RouteYaml = serde_yaml::from_value(block.clone())?;
    compile_apl_blocks(source, raw)
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::deref_by_slicing,
    clippy::needless_raw_strings,
    clippy::unnecessary_wraps,
    clippy::expect_used,
    clippy::get_unwrap,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::attributes::AttributeBag;
    use crate::evaluator::Decision;
    use crate::test_util::{compile_test_policy, compile_test_route};

    /// Unwrap a parsed step as a rule, or fail naming what came back instead.
    ///
    /// Sixteen tests needed this and each wrote its own `let ... else { panic!() }`,
    /// which is three lines that a passing run never executes. One helper reports
    /// the same failure with the offending variant included.
    fn expect_rule(step: Step) -> Rule {
        match step {
            Step::Rule(rule) => rule,
            other => panic!("expected Step::Rule, got {other:?}"),
        }
    }

    /// Unwrap a parsed step as a delegate step. Same reasoning as [`expect_rule`],
    /// for the eight tests that needed it.
    fn expect_delegate(step: Step) -> crate::step::DelegateStep {
        match step {
            Step::Delegate(ds) => ds,
            other => panic!("expected Step::Delegate, got {other:?}"),
        }
    }

    #[test]
    fn lex_basic() {
        let toks = Lexer::new("delegation.depth > 2").tokenize_all().unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Ident("delegation.depth".into()),
                Tok::Gt,
                Tok::IntLit(2),
            ]
        );
    }

    #[test]
    fn lex_strings_both_quotes() {
        let a = Lexer::new(r#""double""#).tokenize_all().unwrap();
        let b = Lexer::new(r#"'single'"#).tokenize_all().unwrap();
        assert_eq!(a, vec![Tok::StringLit("double".into())]);
        assert_eq!(b, vec![Tok::StringLit("single".into())]);
    }

    #[test]
    fn lex_keywords_vs_idents() {
        let toks = Lexer::new("require(role.hr) & authenticated")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Require,
                Tok::LParen,
                Tok::Ident("role.hr".into()),
                Tok::RParen,
                Tok::And,
                Tok::Ident("authenticated".into()),
            ]
        );
    }

    #[test]
    fn lex_rejects_single_equals() {
        let err = Lexer::new("a = 1").tokenize_all().unwrap_err();
        assert!(format!("{err}").contains("expected `==`"));
    }

    // ----- interpolated attribute paths -----

    #[test]
    fn lex_interpolated_path_is_one_ident() {
        let toks = Lexer::new("data.tenants[subject.tenant].data_region")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![Tok::Ident(
                "data.tenants[subject.tenant].data_region".into()
            )]
        );
    }

    #[test]
    fn lex_interpolated_path_in_comparison() {
        let toks = Lexer::new("data.tenants[subject.tenant].data_region == 'eu'")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Ident("data.tenants[subject.tenant].data_region".into()),
                Tok::Eq,
                Tok::StringLit("eu".into()),
            ]
        );
    }

    #[test]
    fn lex_rejects_unterminated_bracket() {
        let err = Lexer::new("data.tenants[subject.tenant")
            .tokenize_all()
            .unwrap_err();
        assert!(format!("{err}").contains("unterminated"), "got: {err}");
    }

    #[test]
    fn lex_rejects_nested_bracket() {
        let err = Lexer::new("data.x[a[b]]").tokenize_all().unwrap_err();
        assert!(format!("{err}").contains("nested"), "got: {err}");
    }

    #[test]
    fn interpolated_predicate_parses_to_comparison() {
        let e = parse_predicate("data.tenants[subject.tenant].data_region == 'eu'").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "data.tenants[subject.tenant].data_region".into(),
                op: CompareOp::Eq,
                value: Literal::String("eu".into()),
            })
        );
    }

    // ----- Predicate parser -----

    #[test]
    fn pred_bare_identifier() {
        let e = parse_predicate("authenticated").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::IsTrue {
                key: "authenticated".into()
            })
        );
    }

    #[test]
    fn pred_comparison() {
        let e = parse_predicate("delegation.depth > 2").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "delegation.depth".into(),
                op: CompareOp::Gt,
                value: Literal::Int(2),
            })
        );
    }

    #[test]
    fn pred_contains() {
        let e = parse_predicate(r#"session.labels contains "PII""#).unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "session.labels".into(),
                op: CompareOp::Contains,
                value: Literal::String("PII".into()),
            })
        );
    }

    #[test]
    fn pred_precedence_or_lowest_and_middle_not_highest() {
        // `!a & b | c` should parse as `(!a & b) | c`.
        let e = parse_predicate("!a & b | c").unwrap();
        match e {
            Expression::Or(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Expression::And(_) => {},
                    other => panic!("first OR branch should be AND, got {other:?}"),
                }
            },
            other => panic!("top-level should be OR, got {other:?}"),
        }
    }

    #[test]
    fn pred_parens_override_precedence() {
        // `(role.finance | role.admin) & !delegated`.
        let e = parse_predicate("(role.finance | role.admin) & !delegated").unwrap();
        match e {
            Expression::And(parts) => {
                assert_eq!(parts.len(), 2);
                matches!(parts[0], Expression::Or(_));
                matches!(parts[1], Expression::Not(_));
            },
            other => panic!("expected top-level AND, got {other:?}"),
        }
    }

    /// `require(...)` is a predicate now, so it nests.
    ///
    /// It used to be refused here as a rule-level shorthand. That was not a
    /// grammar constraint so much as the absence of a code path: the hand-written
    /// parser read a list of bare identifiers and had nowhere to put a
    /// sub-expression.
    #[test]
    fn pred_require_parses_as_a_predicate() {
        let e = parse_predicate("require(authenticated)").expect("`require` is a predicate");
        assert_eq!(
            e,
            Expression::Condition(Condition::IsFalse {
                key: "authenticated".into()
            }),
            "and it means the negation of what it requires"
        );
        parse_predicate("require(a) | require(b)").expect("so it composes");
    }

    #[test]
    fn rule_require_single_arg_desugars_to_isfalse_and_deny() {
        // require(X)  →  Rule { condition: IsFalse(X), action: Deny }
        let r = parse_rule("require(authenticated)", "test").unwrap();
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny {
                reason: None,
                code: None
            }]
        ));
        assert_eq!(
            r.condition,
            Expression::Condition(Condition::IsFalse {
                key: "authenticated".into()
            }),
        );
    }

    #[test]
    fn rule_require_comma_is_and_desugars_to_or_of_isfalse() {
        // require(X, Y)  →  Or([IsFalse(X), IsFalse(Y)]) + Deny
        // i.e., "deny if any are falsy" = "any are falsy → deny"
        let r = parse_rule("require(role.hr, perm.view_ssn)", "test").unwrap();
        assert_eq!(
            r.condition,
            Expression::Or(vec![
                Expression::Condition(Condition::IsFalse {
                    key: "role.hr".into()
                }),
                Expression::Condition(Condition::IsFalse {
                    key: "perm.view_ssn".into()
                }),
            ]),
        );
    }

    #[test]
    fn rule_require_pipe_is_or_desugars_to_and_of_isfalse() {
        // require(X | Y)  →  And([IsFalse(X), IsFalse(Y)]) + Deny
        // i.e., "deny only if all are falsy" = "all are falsy → deny"
        let r = parse_rule("require(role.finance | role.admin)", "test").unwrap();
        assert_eq!(
            r.condition,
            Expression::And(vec![
                Expression::Condition(Condition::IsFalse {
                    key: "role.finance".into()
                }),
                Expression::Condition(Condition::IsFalse {
                    key: "role.admin".into()
                }),
            ]),
        );
    }

    /// Mixing `,` and `|` inside `require(...)` means something now.
    ///
    /// The old parser refused it, because it tracked a single separator and had
    /// no precedence to appeal to. The comma binds lower than `&` and `|`, so
    /// `require(a, b | c)` is `!(a & (b | c))`, which distributes to
    /// `!a | (!b & !c)`.
    #[test]
    fn rule_require_may_mix_separators_and_the_comma_binds_lower() {
        let r = parse_rule("require(a, b | c)", "test").expect("mixing is meaningful now");
        assert_eq!(
            r.condition,
            Expression::Or(vec![
                Expression::Condition(Condition::IsFalse { key: "a".into() }),
                Expression::And(vec![
                    Expression::Condition(Condition::IsFalse { key: "b".into() }),
                    Expression::Condition(Condition::IsFalse { key: "c".into() }),
                ]),
            ])
        );
    }

    #[test]
    fn pred_eq_with_ident_rhs_rejected_with_in_hint() {
        // `subject.type == allowed_types` — `==` doesn't take an ident RHS,
        // and the error should hint at `in` for set membership.
        let err = parse_predicate("subject.type == allowed_types").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("RHS-as-identifier"));
        assert!(msg.contains("set membership use"));
    }

    #[test]
    fn pred_in_set_basic() {
        let e = parse_predicate("subject.type in allowed_types").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "allowed_types".into(),
                negate: false,
            }),
        );
    }

    #[test]
    fn pred_not_in_set() {
        let e = parse_predicate("subject.type not in blocked_types").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "blocked_types".into(),
                negate: true,
            }),
        );
    }

    #[test]
    fn pred_exists_basic() {
        let e = parse_predicate("exists(args.amount)").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Exists {
                key: "args.amount".into()
            }),
        );
    }

    #[test]
    fn pred_exists_inside_compound() {
        // exists() is a sub-predicate (unlike require) — can nest in & / |.
        let e = parse_predicate("exists(args.amount) & args.amount > 0").unwrap();
        match e {
            Expression::And(parts) => {
                assert_eq!(parts.len(), 2);
                assert_eq!(
                    parts[0],
                    Expression::Condition(Condition::Exists {
                        key: "args.amount".into()
                    }),
                );
            },
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn pred_exists_requires_paren_and_ident() {
        parse_predicate("exists").unwrap_err();
        parse_predicate("exists()").unwrap_err();
        parse_predicate("exists(authenticated").unwrap_err();
    }

    #[test]
    fn pred_trailing_tokens_rejected() {
        let err = parse_predicate("a b").unwrap_err();
        assert!(format!("{err}").contains("trailing"));
    }

    #[test]
    fn rule_predicate_action_form() {
        let r = parse_rule("delegation.depth > 2: deny", "test").unwrap();
        match r.effects.as_slice() {
            [Effect::Deny { .. }] => {},
            other => panic!("expected [Deny], got {other:?}"),
        }
        match r.condition {
            Expression::Condition(Condition::Comparison { .. }) => {},
            other => panic!("expected Comparison, got {other:?}"),
        }
    }

    #[test]
    fn rule_predicate_only_defaults_to_deny() {
        // Missing action defaults to deny.
        let r = parse_rule("!authenticated", "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Deny { .. }]));
    }

    #[test]
    fn rule_explicit_allow() {
        let r = parse_rule("role.admin: allow", "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Allow]));
    }

    #[test]
    fn rule_bare_action_unconditional() {
        // Bare `- deny` and `- allow` are unconditional rules with
        // Expression::Always as the predicate.
        let r = parse_rule("deny", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny {
                reason: None,
                code: None
            }]
        ));

        let r = parse_rule("allow", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(r.effects.as_slice(), [Effect::Allow]));
    }

    #[test]
    fn rule_bare_deny_call_carries_reason_and_code() {
        // Unconditional `deny('reason')` / `deny('reason', 'code')` parse
        // to an Always-guarded Deny, so they're usable as bare rule lines
        // and as `on_deny:` / `on_allow:` reactions.
        let r = parse_rule("deny('nope')", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        match r.effects.as_slice() {
            [
                Effect::Deny {
                    reason: Some(reason),
                    code: None,
                },
            ] => assert_eq!(reason, "nope"),
            other => panic!("expected [Deny{{reason: Some, code: None}}], got {other:?}"),
        }

        let r = parse_rule("deny('nope', 'cel.policy')", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        match r.effects.as_slice() {
            [
                Effect::Deny {
                    reason: Some(reason),
                    code: Some(code),
                },
            ] => {
                assert_eq!(reason, "nope");
                assert_eq!(code, "cel.policy");
            },
            other => panic!("expected [Deny{{reason, code}}], got {other:?}"),
        }
    }

    #[test]
    fn rule_malformed_bare_deny_call_errors() {
        // A malformed `deny(...)` must surface its own error rather than
        // falling through to the predicate parser.
        let err = parse_rule("deny(unquoted)", "test").unwrap_err();
        assert!(
            matches!(err, ParseError::Rule { .. }),
            "expected ParseError::Rule, got {err:?}"
        );
    }

    #[test]
    fn rule_step_kinds_rejected_clearly() {
        for s in [
            "run(rate_limiter)",
            "cedar:(action: read)",
            "opa(path)",
            "taint(audit)",
        ] {
            let err = parse_rule(s, "test").unwrap_err();
            assert!(
                matches!(err, ParseError::UnsupportedStep { .. }),
                "expected UnsupportedStep for `{s}`, got {err:?}"
            );
        }
    }

    #[test]
    fn rule_deny_with_unquoted_arg_rejected() {
        // `deny "reason"` (space-separated, no parens) is not a valid
        // form. The supported reason-carrying shape is
        // `deny('reason')` / `deny('reason', 'code')` and
        // the `code` extension.
        let err = parse_rule(r#"authenticated: deny "go away""#, "test").unwrap_err();
        assert!(format!("{err}").contains("unsupported action"));
    }

    #[test]
    fn rule_deny_with_quoted_reason_accepted() {
        // `deny('reason')` — single-arg form. Reason landing on the
        // effect; code defaulting to None.
        let r = parse_rule(r#"delegation.depth > 2: deny('too deep')"#, "test").unwrap();
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny { reason: Some(s), code: None }] if s == "too deep"
        ));
    }

    #[test]
    fn rule_deny_with_reason_and_code_accepted() {
        // `deny('reason', 'code')` — extension. Both reason and
        // author-supplied code surface in the violation.
        let r = parse_rule(
            r#"delegation.depth > 2: deny('too deep', 'delegation.depth_exceeded')"#,
            "test",
        )
        .unwrap();
        match r.effects.as_slice() {
            [
                Effect::Deny {
                    reason: Some(reason),
                    code: Some(code),
                },
            ] => {
                assert_eq!(reason, "too deep");
                assert_eq!(code, "delegation.depth_exceeded");
            },
            other => panic!("expected Deny with reason+code, got {other:?}"),
        }
    }

    #[test]
    fn rule_deny_with_too_many_args_rejected() {
        // Cap on positional args — `deny(reason, code)` is the limit.
        let err = parse_rule(r#"x: deny('a', 'b', 'c')"#, "test").unwrap_err();
        assert!(format!("{err}").contains("at most two args"));
    }

    #[test]
    fn rule_deny_with_unquoted_args_in_call_rejected() {
        // The args MUST be quoted; bare identifiers aren't legal.
        let err = parse_rule(r#"x: deny(bare, identifier)"#, "test").unwrap_err();
        assert!(format!("{err}").contains("expected a quoted string"));
    }

    fn parse_step_yaml(yaml: &str) -> Result<Step, ParseError> {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        parse_step(&v, "test")
    }

    #[test]
    fn when_do_single_effect_deny() {
        // do: deny  — single string value, no list.
        let step = parse_step_yaml("when: delegation.depth > 2\ndo: deny").unwrap();
        match step {
            Step::Rule(rule) => {
                assert!(matches!(
                    rule.condition,
                    Expression::Condition(Condition::Comparison { .. })
                ));
                assert!(matches!(
                    rule.effects.as_slice(),
                    [Effect::Deny {
                        reason: None,
                        code: None
                    }]
                ));
            },
            other => panic!("expected Step::Rule, got {other:?}"),
        }
    }

    #[test]
    fn when_do_single_effect_deny_with_reason_and_code() {
        // The `deny('reason', 'code')` extension works inside `do:` too.
        let step = parse_step_yaml(
            "when: delegation.depth > 2\ndo: deny('too deep', 'delegation.depth_exceeded')",
        )
        .unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [
                Effect::Deny {
                    reason: Some(r),
                    code: Some(c),
                },
            ] => {
                assert_eq!(r, "too deep");
                assert_eq!(c, "delegation.depth_exceeded");
            },
            other => panic!("expected Deny+reason+code, got {other:?}"),
        }
    }

    #[test]
    fn when_do_multi_effect_list() {
        // The headline demo case: fan-out from one predicate.
        // do: [run(audit_logger), taint(unauth), deny('refused')]
        let yaml = r#"
when: "!role.hr"
do:
  - "run(audit_logger)"
  - "taint(unauth, session)"
  - "deny('refused', 'role.hr_required')"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert_eq!(rule.effects.len(), 3);
        assert!(matches!(rule.effects[0], Effect::Plugin { ref name } if name == "audit_logger"));
        assert!(matches!(
            rule.effects[1],
            Effect::Taint { ref label, .. } if label == "unauth"
        ));
        match &rule.effects[2] {
            Effect::Deny {
                reason: Some(r),
                code: Some(c),
            } => {
                assert_eq!(r, "refused");
                assert_eq!(c, "role.hr_required");
            },
            other => panic!("expected Deny+reason+code, got {other:?}"),
        }
    }

    #[test]
    fn when_do_key_order_does_not_matter() {
        // YAML maps are unordered; `do:` first should parse the same.
        let step = parse_step_yaml("do: deny\nwhen: delegation.depth > 2").unwrap();
        assert!(matches!(step, Step::Rule(_)));
    }

    #[test]
    fn when_do_with_unknown_key_rejected() {
        // Typo guard — surface unknown keys instead of silently dropping.
        let err = parse_step_yaml("when: x\ndo: deny\nwhne: typo").unwrap_err();
        assert!(format!("{err}").contains("unexpected key"));
    }

    #[test]
    fn when_do_empty_do_list_rejected() {
        // An empty `do:` is almost certainly an author mistake;
        // require at least one effect.
        let err = parse_step_yaml("when: x\ndo: []").unwrap_err();
        assert!(format!("{err}").contains("no effects"));
    }

    #[test]
    fn shorthand_multi_effect_map() {
        // Shorthand for the canonical when/do form. The predicate is
        // the map's only key, the value is a list of effects.
        let yaml = r#"
"!role.hr":
  - "run(audit_logger)"
  - "deny('unauthorized')"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Plugin { ref name } if name == "audit_logger"));
        assert!(matches!(
            rule.effects[1],
            Effect::Deny { reason: Some(ref r), code: None } if r == "unauthorized"
        ));
    }

    #[test]
    fn shorthand_multi_effect_map_with_nested_delegate() {
        // Map-form effects (like `delegate:`) work inside a shorthand
        // list, exercising the parse_effect_value path.
        let yaml = r#"
"role.hr":
  - delegate:
      plugin: workday-oauth
      config:
        audience: workday-api
  - "run(audit_logger)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Delegate(_)));
        assert!(matches!(rule.effects[1], Effect::Plugin { .. }));
    }

    #[test]
    fn cedar_with_list_body_still_parses_as_pdp() {
        // Regression guard — `cedar:` and other PDP keys whose body
        // happens to be list-shaped (e.g. when the author embeds a
        // bare reaction list) must NOT be reinterpreted as a
        // shorthand multi-effect map.
        //
        // Cedar bodies in production are maps with `action`/`resource`
        // keys — we don't actually accept a Sequence body, but the
        // shorthand-list detector explicitly excludes known PDP
        // dialect keys so the failure mode here is the existing PDP
        // body error, not a shorthand misparse.
        let err = parse_step_yaml("cedar: [oh no]").unwrap_err();
        // Existing PDP body validator complains about the shape —
        // proves we didn't try to read `cedar` as a predicate.
        assert!(format!("{err}").contains("body must be a map"));
    }

    #[test]
    fn shorthand_multi_effect_empty_list_rejected() {
        let err = parse_step_yaml(r#""x": []"#).unwrap_err();
        assert!(format!("{err}").contains("no effects"));
    }

    #[test]
    fn when_do_with_field_op_result_redact() {
        // The headline case: `result.salary | redact` as an effect
        // inside a do: list, alongside other effect kinds.
        let yaml = r#"
when: "!perm.view_ssn"
do:
  - "run(audit_logger)"
  - "result.salary | redact"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Plugin { .. }));
        match &rule.effects[1] {
            Effect::FieldOp { path, stages } => {
                assert_eq!(path, "result.salary");
                assert_eq!(stages.len(), 1, "single `redact` stage");
            },
            other => panic!("expected FieldOp, got {other:?}"),
        }
    }

    #[test]
    fn when_do_with_field_op_args_mask() {
        // `args.card_number | mask(4)` — args side + parametrised stage.
        let yaml = r#"
when: role.support
do: "args.card_number | mask(4)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                assert_eq!(stages.len(), 1);
            },
            other => panic!("expected single FieldOp, got {other:?}"),
        }
    }

    #[test]
    fn when_do_with_chained_field_op() {
        // Chained stages — type check + content effect. Uses stages
        // the pipeline parser actually knows about (`str` and `mask`).
        let yaml = r#"
when: role.support
do: "args.card_number | str | mask(4)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                assert_eq!(stages.len(), 2, "two-stage chain");
            },
            other => panic!("expected single FieldOp, got {other:?}"),
        }
    }

    #[test]
    fn field_stage_run_dispatches_a_plugin() {
        // `run(name)` is a plugin-transform stage in a field pipeline, the same
        // verb a step list uses. `plugin(name)` was a second spelling for it and
        // is refused; the test below pins that.
        let yaml = r#"
when: role.support
do: "args.card_number | run(luhn)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                match &stages[..] {
                    [Stage::Plugin { name }] => assert_eq!(name, "luhn"),
                    other => panic!("expected [Stage::Plugin], got {other:?}"),
                }
            },
            other => panic!("expected single FieldOp, got {other:?}"),
        }
    }

    #[test]
    fn field_stage_run_empty_name_is_rejected() {
        // `run()` with no name in a field pipeline must be rejected, mirroring the
        // policy-step path (`parse_step_string`).
        let err = parse_stage("run()").expect_err("empty name must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("run") && msg.contains("must not be empty"),
            "expected a verb-named empty-name error, got: {msg}"
        );

        // The removed spelling names its replacement rather than reporting an
        // empty name, since the verb is the fault.
        let removed = parse_stage("plugin()").expect_err("the old spelling is refused");
        assert!(format!("{removed}").contains("run(name)"), "{removed}");
    }

    /// A pipeline whose path is neither `args.` nor `result.` must not be taken
    /// as a field op. Accepting it would apply a redaction to a path that does
    /// not exist, which reads as enforcement while doing nothing.
    ///
    /// The control below is what makes this meaningful: an identical step
    /// differing only in the path prefix does parse as a field op, so the
    /// rejection is attributable to the path rather than to anything else in
    /// the step.
    #[test]
    fn a_pipeline_path_outside_args_or_result_is_not_a_field_op() {
        let bad = parse_step_yaml("when: \"role.hr\"\ndo: \"role.hr | redact\"");
        match bad {
            Ok(Step::Rule(rule)) => assert!(
                !matches!(rule.effects.as_slice(), [Effect::FieldOp { .. }]),
                "bare `role.hr` must not parse as a field-op path"
            ),
            Err(_) => {},
            other => panic!("unexpected: {other:?}"),
        }

        let good = parse_step_yaml("when: \"role.hr\"\ndo: \"args.x | redact\"")
            .expect("the same step with an args. path must parse");
        let rule = expect_rule(good);
        assert!(
            matches!(
                rule.effects.as_slice(),
                [Effect::FieldOp { path, .. }] if path == "args.x"
            ),
            "control: an args. path is a field op, got {:?}",
            rule.effects
        );
    }

    /// `args.x |` with nothing after the pipe is an author typo. It has to be
    /// refused rather than treated as a no-op chain, and the message has to quote
    /// the offending expression so the author can find it.
    #[test]
    fn a_trailing_pipe_with_no_stage_is_rejected() {
        let err = parse_step_yaml("when: \"role.hr\"\ndo: \"args.x | \"")
            .expect_err("a trailing pipe must not parse");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("args.x |"),
            "the error must quote the offending expression: {msg}"
        );
    }

    #[test]
    fn shorthand_multi_effect_with_field_op() {
        // Shorthand `predicate: [list]` with a content effect.
        let yaml = r#"
"!perm.view_ssn":
  - "run(audit_logger)"
  - "result.ssn | redact"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[1], Effect::FieldOp { .. }));
    }

    #[test]
    fn find_top_level_pipe_skips_inside_parens() {
        // Top-level `|` between path and chain → returns its index.
        // Inner `|` inside `(...)` or quotes is ignored.
        assert_eq!(find_top_level_pipe("args.x | mask(4)"), Some(7));
        assert_eq!(find_top_level_pipe("validate(luhn)"), None);
        assert_eq!(find_top_level_pipe(r#"args.x | mask("a|b")"#), Some(7));
        // No top-level pipe even with a `|` inside the parameter set.
        assert_eq!(find_top_level_pipe("mask(a|b)"), None);
    }

    #[test]
    fn top_level_sequential() {
        // `- sequential: [list]` as a top-level policy step.
        let yaml = r#"
sequential:
  - "run(rate_limiter)"
  - "run(audit_logger)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        assert!(matches!(rule.condition, Expression::Always));
        match rule.effects.as_slice() {
            [Effect::Sequential(inner)] => {
                assert_eq!(inner.len(), 2);
                assert!(matches!(inner[0], Effect::Plugin { .. }));
                assert!(matches!(inner[1], Effect::Plugin { .. }));
            },
            other => panic!("expected single Sequential effect, got {other:?}"),
        }
    }

    #[test]
    fn top_level_parallel() {
        let yaml = r#"
parallel:
  - "run(pii_scanner)"
  - "run(nemo_guardrails)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => {
                assert_eq!(inner.len(), 2);
            },
            other => panic!("expected single Parallel effect, got {other:?}"),
        }
    }

    #[test]
    fn parallel_inside_do_body() {
        // The DSL spec's "Conditional parallel" example: a `when:`
        // rule whose `do:` is a single parallel block.
        let yaml = r#"
when: args.include_ssn == true
do:
  parallel:
    - "run(pii_scanner)"
    - "run(nemo_guardrails)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => assert_eq!(inner.len(), 2),
            other => panic!("expected Parallel in do:, got {other:?}"),
        }
    }

    #[test]
    fn parallel_rejects_field_op_at_parse_time() {
        // FieldOp inside Parallel should fail at parse, not at runtime.
        let yaml = r#"
parallel:
  - "run(audit)"
  - "args.ssn | redact"
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{err}").contains("mutation"), "got: {err}");
    }

    #[test]
    fn parallel_rejects_delegate_at_parse_time() {
        let yaml = r#"
parallel:
  - "run(audit)"
  - "delegate(workday)"
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{err}").contains("mutation"));
    }

    #[test]
    fn sequential_allows_mutations() {
        // The escape valve — Sequential lets mutations through.
        let yaml = r#"
sequential:
  - "args.ssn | redact"
  - "run(audit)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [Effect::Sequential(inner)] => {
                assert!(matches!(inner[0], Effect::FieldOp { .. }));
                assert!(matches!(inner[1], Effect::Plugin { .. }));
            },
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parallel_empty_list_rejected() {
        let err = parse_step_yaml("parallel: []").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn sequential_empty_list_rejected() {
        let err = parse_step_yaml("sequential: []").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    // ----- restrict effect -----

    /// A literal `StringSetSpec` for terse assertions.
    fn lit(items: &[&str]) -> Option<crate::constraint::StringSetSpec> {
        Some(crate::constraint::StringSetSpec::Literal(
            items.iter().map(std::string::ToString::to_string).collect(),
        ))
    }

    #[test]
    fn top_level_restrict_full_shape() {
        // Every field exercised at once, including `custom` scalar
        // coercion and an explicit `on_empty`.
        let yaml = r#"
restrict:
  allow_models: ["vllm/*", "anthropic/claude-sonnet-*"]
  deny_models:  ["openai/*"]
  allow_regions: [eu]
  allow_sites: [site-a]
  max_cost_tier: cheap
  custom: { gpu: h100, dedicated: true }
  on_empty: fallback
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict, got {step:?}");
        };
        use crate::constraint::OnEmpty;
        assert_eq!(
            spec.allow_models,
            lit(&["vllm/*", "anthropic/claude-sonnet-*"])
        );
        assert_eq!(spec.deny_models, lit(&["openai/*"]));
        assert_eq!(spec.allow_regions, lit(&["eu"]));
        assert_eq!(spec.allow_sites, lit(&["site-a"]));
        assert_eq!(spec.max_cost_tier.as_deref(), Some("cheap"));
        // `custom` coerces the bool `true` to the string "true".
        assert_eq!(spec.custom.get("gpu"), Some(&"h100".to_owned()));
        assert_eq!(spec.custom.get("dedicated"), Some(&"true".to_owned()));
        assert_eq!(spec.on_empty, OnEmpty::Fallback);
    }

    #[test]
    fn restrict_on_empty_defaults_to_deny() {
        let step = parse_step_yaml("restrict: { deny_models: [\"openai/*\"] }").unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(spec.on_empty, crate::constraint::OnEmpty::Deny);
    }

    #[test]
    fn restrict_field_reference_parses_as_ref() {
        // A scalar `data.*` path is a reference, not a literal. A path
        // containing `[...]` must be quoted so YAML doesn't read the
        // brackets as a flow sequence (block form works unquoted too).
        let yaml = r#"
restrict:
  allow_models: "data.agents[subject.id].allowed_models"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(
            spec.allow_models,
            Some(crate::constraint::StringSetSpec::Ref(
                "data.agents[subject.id].allowed_models".to_owned()
            ))
        );
    }

    #[test]
    fn restrict_bracketless_reference_parses_unquoted() {
        // A reference with no `[...]` is a clean plain scalar — no quoting
        // needed even in flow form.
        let step = parse_step_yaml("restrict: { allow_regions: data.tenant_regions }").unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(
            spec.allow_regions,
            Some(crate::constraint::StringSetSpec::Ref(
                "data.tenant_regions".to_owned()
            ))
        );
    }

    #[test]
    fn restrict_inside_when_do_body() {
        // The EU-sovereignty shape: gate at the composition layer,
        // restrict in the `do:` body.
        let yaml = r#"
when: session.labels contains 'eu_resident'
do:
  - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [Effect::Restrict { spec }] => {
                assert_eq!(spec.allow_regions, lit(&["eu"]));
            },
            other => panic!("expected single Restrict effect, got {other:?}"),
        }
    }

    #[test]
    fn restrict_inside_pdp_on_allow() {
        // `restrict` composes in a PDP reaction — authz says yes, then
        // pin routing.
        let yaml = r#"
cedar:
  action: read
  resource: eu_data
  on_allow:
    - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Pdp { on_allow, .. } = step else {
            panic!("expected Step::Pdp, got {step:?}");
        };
        match on_allow.as_slice() {
            [Step::Restrict { spec }] => {
                assert_eq!(spec.allow_regions, lit(&["eu"]));
            },
            other => panic!("expected Restrict in on_allow, got {other:?}"),
        }
    }

    #[test]
    fn restrict_empty_body_rejected() {
        // A `restrict:` with no constraint fields restricts nothing —
        // author error.
        let err = parse_step_yaml("restrict: {}").unwrap_err();
        assert!(
            format!("{err}").contains("no constraint fields"),
            "got: {err}"
        );
    }

    #[test]
    fn restrict_only_on_empty_rejected() {
        // `on_empty` alone still constrains nothing.
        let err = parse_step_yaml("restrict: { on_empty: deny }").unwrap_err();
        assert!(
            format!("{err}").contains("no constraint fields"),
            "got: {err}"
        );
    }

    #[test]
    fn restrict_unknown_field_rejected() {
        let err = parse_step_yaml("restrict: { allow_zones: [eu] }").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown"), "got: {msg}");
        assert!(msg.contains("allow_zones"), "got: {msg}");
    }

    #[test]
    fn restrict_bad_on_empty_value_rejected() {
        let err = parse_step_yaml("restrict: { deny_models: [\"openai/*\"], on_empty: maybe }")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("on_empty"), "got: {msg}");
        assert!(msg.contains("maybe"), "got: {msg}");
    }

    #[test]
    fn restrict_non_scalar_custom_value_rejected() {
        let yaml = r#"
restrict:
  custom:
    gpu: [h100, a100]
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{err}").contains("scalar"), "got: {err}");
    }

    #[test]
    fn restrict_allowed_inside_parallel() {
        // `restrict` is non-mutating, so it is *allowed* in parallel —
        // this guards that we didn't accidentally class it as a mutation.
        let yaml = r#"
parallel:
  - "run(audit)"
  - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => {
                assert_eq!(inner.len(), 2);
                assert!(matches!(inner[1], Effect::Restrict { .. }));
            },
            other => panic!("expected Parallel with Restrict, got {other:?}"),
        }
    }

    #[test]
    fn nested_orchestration() {
        // `sequential: [plugin, parallel: [plugin, plugin]]` — the
        // parser handles arbitrary nesting through parse_effect_value.
        let yaml = r#"
sequential:
  - "run(rate_limiter)"
  - parallel:
      - "run(pii_scanner)"
      - "run(nemo)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let rule = expect_rule(step);
        let Effect::Sequential(outer) = &rule.effects[0] else {
            panic!("expected Sequential");
        };
        assert_eq!(outer.len(), 2);
        assert!(matches!(outer[0], Effect::Plugin { .. }));
        match &outer[1] {
            Effect::Parallel(inner) => assert_eq!(inner.len(), 2),
            other => panic!("expected nested Parallel, got {other:?}"),
        }
    }

    #[test]
    fn split_respects_quotes_and_parens() {
        // The `:` inside parens / quotes shouldn't be the separator.
        let r = parse_rule(r#"session.labels contains "a:b": deny"#, "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Deny { .. }]));
        if let Expression::Condition(Condition::Comparison { value, .. }) = r.condition {
            assert_eq!(value, Literal::String("a:b".into()));
        } else {
            panic!("expected Comparison");
        }
    }

    #[test]
    fn compile_simple_route() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2 & include_ssn: deny"
"#;
        let route = compile_test_route("get_compensation", yaml).unwrap();
        assert_eq!(route.pre_invocation.len(), 3);
        assert!(
            route
                .declared_phases()
                .contains(crate::rules::Phase::PreInvocation)
        );
    }

    #[test]
    fn authorization_carries_both_phases() {
        // `authorization:` is the only place the two phase lists appear, and
        // one block may name both.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
    post_invocation:
      - "taint(audit, session)"
"#;
        let route = compile_test_route("r", yaml).unwrap();
        assert_eq!(route.pre_invocation.len(), 1);
        assert_eq!(route.post_invocation.len(), 1);
    }

    #[test]
    fn authorization_naming_only_the_post_phase_loads() {
        // One phase is enough: a block that authorizes only after the call
        // is a complete declaration.
        let yaml = r#"
route:
  authorization:
    post_invocation:
      - "taint(audit, session)"
"#;
        let route = compile_test_route("r", yaml).unwrap();
        assert!(
            route.pre_invocation.is_empty(),
            "no pre-invocation steps declared"
        );
        assert_eq!(route.post_invocation.len(), 1);
    }

    #[test]
    fn removed_key_nested_under_authorization_is_rejected() {
        // Fail-closed: a removed key nested inside the `authorization:` wrapper
        // must error, not be silently dropped (which would load a route with no
        // authorization enforced). Guarded by `deny_unknown_fields` on
        // `AuthorizationYaml`.
        let yaml = r#"
route:
  authorization:
    policy:
      - "require(authenticated)"
"#;
        let err = compile_test_policy("r", yaml).expect_err("nested `policy:` must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy") || msg.contains("unknown field"),
            "error should flag the unknown nested key: {msg}"
        );
    }

    #[test]
    fn authorization_typo_under_wrapper_is_rejected() {
        // `deny_unknown_fields` also catches typos so they don't silently
        // no-op the phase.
        let yaml = r#"
route:
  authorization:
    pre_invocaton:
      - "require(authenticated)"
"#;
        assert!(
            compile_test_policy("r", yaml).is_err(),
            "a typo'd sub-key under `authorization:` must be rejected, not ignored"
        );
    }

    #[test]
    fn authorization_naming_neither_phase_is_rejected() {
        // An empty block authorizes nothing, and the has-APL gate would drop
        // the route as if it carried no policy, so it fails the load instead.
        let yaml = r#"
route:
  authorization: {}
"#;
        let err =
            compile_test_policy("r", yaml).expect_err("an empty `authorization:` must be rejected");
        assert!(
            matches!(err, ParseError::EmptyAuthorization { ref location } if location == "r"),
            "expected the empty-authorization error for route `r`, got {err:?}"
        );
        let msg = format!("{err}");
        for phase in ["pre_invocation", "post_invocation"] {
            assert!(msg.contains(phase), "the error must name `{phase}`: {msg}");
        }
    }

    #[test]
    fn authorization_declaring_only_empty_phases_is_rejected() {
        // An empty list reaches the same end state as an absent one by a
        // different spelling: layers append, so an empty list overrides
        // nothing. Refusing only the absent form left the loud check with a
        // quiet way around it.
        for block in [
            "pre_invocation: []",
            "post_invocation: []",
            "pre_invocation: []\n    post_invocation: []",
        ] {
            let yaml = format!(
                r#"
route:
  authorization:
    {block}
"#
            );
            let err = compile_test_policy("r", &yaml)
                .expect_err("an `authorization:` contributing no step must be rejected");
            assert!(
                matches!(err, ParseError::EmptyAuthorization { ref location } if location == "r"),
                "expected the empty-authorization error for `{block}`, got {err:?}"
            );
        }
    }

    #[test]
    fn authorization_with_one_empty_phase_beside_a_real_one_loads() {
        // Only a block contributing nothing at all is refused. A phase written
        // empty beside one that carries steps is a shape an author may well
        // reach for while editing, and it authorizes exactly what it says.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
    post_invocation: []
"#;
        let route = compile_test_route("r", yaml).expect("one real phase is enough");
        assert_eq!(route.pre_invocation.len(), 1);
        assert!(route.post_invocation.is_empty());
    }

    #[test]
    fn a_field_stage_nested_under_authorization_is_rejected() {
        // `args:` and `result:` are phases, not authorization steps, so they sit
        // beside `authorization:` rather than inside it. The symmetry with
        // `pre_invocation:` is a guess `deny_unknown_fields` refuses.
        for field_stage in ["args", "result"] {
            let yaml = format!(
                r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
    {field_stage}:
      ssn: "redact(!perm.view_ssn)"
"#
            );
            let err = compile_test_policy("r", &yaml)
                .expect_err("a field stage under `authorization:` must be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains(field_stage),
                "the error must name `{field_stage}`: {msg}"
            );
        }
    }

    #[test]
    fn an_authorization_key_with_nothing_under_it_is_rejected() {
        // A null value is a block that names neither phase, not the absence of
        // a block: serde maps null onto `None`, which used to load clean and
        // enforce nothing.
        let yaml = r#"
route:
  authorization:
"#;
        let err =
            compile_test_policy("r", yaml).expect_err("a null `authorization:` must be rejected");
        assert!(
            matches!(err, ParseError::EmptyAuthorization { ref location } if location == "r"),
            "expected the empty-authorization error for route `r`, got {err:?}"
        );
    }

    #[test]
    fn a_policy_block_naming_neither_phase_is_rejected() {
        // The same refusal on the block path an orchestrator's visitor takes,
        // which has no has-APL gate of its own to hide behind.
        let block: serde_yaml::Value =
            serde_yaml::from_str("authorization: {}\n").expect("fixture parses");
        let err = compile_policy_block_value("global", &block)
            .expect_err("an empty `authorization:` must be rejected at section scope");
        assert!(
            matches!(err, ParseError::EmptyAuthorization { ref location } if location == "global"),
            "expected the empty-authorization error for `global`, got {err:?}"
        );
    }

    #[test]
    fn field_pipeline_error_names_field_path() {
        // A malformed pipeline under `result:` names `result.<field>` in
        // the diagnostic so the operator can locate the offending field.
        let yaml = r#"
route:
  result:
    x: "nonsense"
"#;
        let err = compile_test_policy("r", yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("result.x"), "expected result.x in: {msg}");
    }

    #[test]
    fn removed_policy_field_names_are_rejected() {
        // The removed authorization-phase keys must fail loudly, never be
        // silently dropped (which would fail open). `RouteYaml` has no
        // catch-all, so serde reports them as unknown fields.
        for removed in ["policy", "post_policy"] {
            let yaml = format!("route:\n  {removed}:\n    - \"require(authenticated)\"\n");
            let err = compile_test_policy("r", &yaml)
                .expect_err(&format!("`{removed}` must be rejected"));
            let msg = format!("{err}");
            assert!(
                msg.contains(removed),
                "`{removed}` rejection should name the key: {msg}"
            );
        }
    }

    #[test]
    fn a_block_whose_only_key_was_removed_is_rejected_not_read_as_empty() {
        // A block whose *only* key is a removed name must not read as one that
        // declared no policy, which would be a fail-open. `RouteYaml` has no
        // catch-all, so serde refuses the key rather than compiling an empty
        // route around it.
        let yaml = r#"
route:
  policy:
    - "require(authenticated)"
"#;
        assert!(
            matches!(compile_test_policy("ghost", yaml), Err(ParseError::Yaml(_))),
            "a route whose only key was removed must be rejected, not omitted"
        );
    }

    #[test]
    fn a_flat_phase_key_on_a_policy_block_is_rejected() {
        // `RouteYaml` has no catch-all, so the standalone entry point refuses a
        // flat phase list the same way the config loader's key table does. It
        // used to land in the catch-all and compile the route empty.
        let yaml = r#"
route:
  pre_invocation:
    - "require(authenticated)"
"#;
        let err = compile_test_policy("r", yaml).expect_err("a flat phase key must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("pre_invocation"),
            "the rejection should name the key: {msg}"
        );
    }

    #[test]
    fn a_block_with_only_plugin_overrides_declares_no_phase() {
        // An override block alone is not a policy: an override only means
        // something where a step dispatches the plugin. The compiled route is
        // empty rather than absent, which is the one shape a caller has to read
        // now that nothing drops a route from a map.
        let yaml = r#"
route:
  plugins:
    audit-log:
      on_error: fail_open
"#;
        let route = compile_test_route("legacy", yaml).unwrap();
        assert!(
            route.declared_phases().is_empty(),
            "an override-only block declares no phase"
        );
        assert!(route.plugin_overrides.contains_key("audit-log"));
    }

    #[test]
    fn compile_propagates_rule_errors_with_source() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "subject.id == garbage_ident"
"#;
        let err = compile_test_policy("bad", yaml).unwrap_err();
        // RHS-as-identifier is rejected; the error mentions the offending input.
        let msg = format!("{err}");
        assert!(
            msg.contains("RHS-as-identifier") || msg.contains("garbage_ident"),
            "error message should reference the failure: {msg}",
        );
    }

    #[test]
    fn compile_plugin_step_string_form() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "run(rate_limiter)"
"#;
        let route = compile_test_route("rate_limited", yaml).unwrap();
        assert_eq!(route.pre_invocation.len(), 1);
        match &route.pre_invocation[0] {
            Effect::Plugin { name } => assert_eq!(name, "rate_limiter"),
            other => panic!("expected Effect::Plugin, got {other:?}"),
        }
    }

    #[test]
    fn compile_run_step_string_form_invokes_a_plugin() {
        // `run(name)` compiles to Effect::Plugin. It was one of two spellings for
        // that; `plugin(name)` is refused now, pinned below.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "run(rate_limiter)"
"#;
        let route = compile_test_route("rate_limited", yaml).unwrap();
        assert_eq!(route.pre_invocation.len(), 1);
        match &route.pre_invocation[0] {
            Effect::Plugin { name } => assert_eq!(name, "rate_limiter"),
            other => panic!("expected Effect::Plugin, got {other:?}"),
        }
    }

    #[test]
    fn parse_step_run_is_plugin_alias() {
        for s in ["run(audit-log)", "run(audit-log)"] {
            let step = parse_step(&serde_yaml::Value::String(s.to_owned()), "test").unwrap();
            match step {
                crate::step::Step::Plugin { name } => assert_eq!(name, "audit-log", "{s}"),
                other => panic!("expected Step::Plugin for `{s}`, got {other:?}"),
            }
        }
        // Empty / malformed `run(...)` surfaces a clear, verb-named error.
        let err = parse_step(&serde_yaml::Value::String("run()".to_owned()), "test").unwrap_err();
        assert!(
            format!("{err}").contains("run("),
            "error should name `run(...)`: {err}"
        );
    }

    #[test]
    fn compile_taint_step_string_form() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "taint(audit, session)"
"#;
        let route = compile_test_route("audit_marked", yaml).unwrap();
        match &route.pre_invocation[0] {
            Effect::Taint { label, scopes } => {
                assert_eq!(label, "audit");
                assert_eq!(scopes, &vec![TaintScope::Session]);
            },
            other => panic!("expected Effect::Taint, got {other:?}"),
        }
    }

    #[test]
    fn compile_pdp_call_cedar_map_form() {
        // Cedar uses the `cedar:` key with args inline + on_deny/on_allow.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - cedar:
          action: read
          resource: employee
          on_deny:
            - deny
          on_allow:
            - "run(audit_logger)"
"#;
        let route = compile_test_route("authz_check", yaml).unwrap();
        match &route.pre_invocation[0] {
            Effect::Pdp {
                call,
                on_deny,
                on_allow,
            } => {
                assert_eq!(call.dialect, PdpDialect::Cedar);
                // Cedar args are a map: action + resource (with reaction
                // keys stripped out).
                let args_map = call.args.as_mapping().expect("cedar args should be a map");
                assert!(args_map.contains_key(serde_yaml::Value::String("action".into())));
                assert!(args_map.contains_key(serde_yaml::Value::String("resource".into())));
                assert!(!args_map.contains_key(serde_yaml::Value::String("on_deny".into())));
                assert_eq!(on_deny.len(), 1);
                assert_eq!(on_allow.len(), 1);
            },
            other => panic!("expected Effect::Pdp, got {other:?}"),
        }
    }

    #[test]
    fn compile_pdp_call_cel_map_form() {
        // `cel:` carries an `expr:` string + optional on_deny/on_allow
        // reactions. Routes to the CEL-backed resolver via PdpDialect::Cel.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - cel:
          expr: "subject.id == 'alice' && delegation.depth <= 2"
          on_deny:
            - deny
"#;
        let route = compile_test_route("authz_check", yaml).unwrap();
        match &route.pre_invocation[0] {
            Effect::Pdp {
                call,
                on_deny,
                on_allow,
            } => {
                assert_eq!(call.dialect, PdpDialect::Cel);
                let args_map = call.args.as_mapping().expect("cel args should be a map");
                assert!(args_map.contains_key(serde_yaml::Value::String("expr".into())));
                // Reaction keys are stripped from the opaque call args.
                assert!(!args_map.contains_key(serde_yaml::Value::String("on_deny".into())));
                assert_eq!(on_deny.len(), 1);
                assert_eq!(on_allow.len(), 0);
            },
            other => panic!("expected Effect::Pdp, got {other:?}"),
        }
    }

    #[test]
    fn compile_pdp_call_opa_paren_form() {
        // OPA uses `opa("path"):` with the path inside parens + body is reactions.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - 'opa("hr/compensation/deny"):':
          on_deny:
            - deny
"#;
        let route = compile_test_route("opa_check", yaml).unwrap();
        match &route.pre_invocation[0] {
            Effect::Pdp { call, on_deny, .. } => {
                assert_eq!(call.dialect, PdpDialect::Opa);
                // OPA args are a string (the path).
                assert!(call.args.as_str().unwrap().contains("hr/compensation/deny"));
                assert_eq!(on_deny.len(), 1);
            },
            other => panic!("expected Effect::Pdp, got {other:?}"),
        }
    }

    /// A custom dialect is `pdp(name):`, and a bare unknown key is a misspelling.
    ///
    /// This asserted the opposite: a bare `my_engine:` became
    /// `Custom("my_engine")`, which made every typo a PDP lookup and left
    /// `pdp(my_engine):` resolving a dialect called `pdp`.
    #[test]
    fn compile_pdp_custom_dialect_is_named_in_the_parens() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - pdp(my_engine):
          on_deny: [deny]
"#;
        let route = compile_test_route("custom_pdp", yaml).unwrap();
        match &route.pre_invocation[0] {
            Effect::Pdp { call, .. } => {
                assert_eq!(call.dialect, PdpDialect::Custom("my_engine".into()));
            },
            other => panic!("expected Pdp, got {other:?}"),
        }

        let bare = r#"
route:
  authorization:
    pre_invocation:
      - my_engine:
          on_deny: [deny]
"#;
        let err = compile_test_route("custom_pdp", bare)
            .expect_err("a bare unknown key is not a custom dialect")
            .to_string();
        assert!(err.contains("pdp(my_engine)"), "{err}");
    }

    #[tokio::test]
    async fn end_to_end_hr_compensation() {
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2: deny"
"#;
        let route = compile_test_route("get_compensation", yaml).unwrap();

        let pdp: std::sync::Arc<dyn crate::PdpResolver> = std::sync::Arc::new(NullPdpResolver);
        let plugins: std::sync::Arc<dyn crate::PluginInvoker> =
            std::sync::Arc::new(NullPluginInvoker);
        let delegations: std::sync::Arc<dyn crate::DelegationInvoker> =
            std::sync::Arc::new(crate::NoopDelegationInvoker);
        let elicitations: std::sync::Arc<dyn crate::ElicitationInvoker> =
            std::sync::Arc::new(crate::NoopElicitationInvoker);

        // Alice: authenticated, hr role, depth=1 → allow.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("role.hr", true);
        bag.set("delegation.depth", 1_i64);
        assert_eq!(
            crate::evaluate_effects(
                &route.pre_invocation,
                &mut bag,
                &pdp,
                &plugins,
                &delegations,
                &elicitations,
                crate::DispatchPhase::Pre,
                &mut crate::route::RoutePayload::new(serde_json::Value::Null)
            )
            .await
            .decision,
            Decision::Allow,
        );

        // Same Alice but depth=3 → deny (third rule fires).
        bag.set("delegation.depth", 3_i64);
        match crate::evaluate_effects(
            &route.pre_invocation,
            &mut bag,
            &pdp,
            &plugins,
            &delegations,
            &elicitations,
            crate::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("pre_invocation[2]"),
                    "expected pre_invocation[2], got {rule_source}"
                );
            },
            d => panic!("expected Deny, got {d:?}"),
        }

        // Bob: authenticated but neither hr nor finance → deny on rule 1.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("delegation.depth", 1_i64);
        match crate::evaluate_effects(
            &route.pre_invocation,
            &mut bag,
            &pdp,
            &plugins,
            &delegations,
            &elicitations,
            crate::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("pre_invocation[1]"),
                    "expected pre_invocation[1], got {rule_source}"
                );
            },
            d => panic!("expected Deny, got {d:?}"),
        }
    }

    // Test fixtures for async evaluator — null resolvers that nothing in
    // a pure-rule route should ever invoke.
    struct NullPdpResolver;
    #[async_trait::async_trait]
    impl crate::PdpResolver for NullPdpResolver {
        fn dialect(&self) -> crate::PdpDialect {
            crate::PdpDialect::Cedar
        }
        async fn evaluate(
            &self,
            _call: &crate::PdpCall,
            _bag: &crate::AttributeBag,
        ) -> Result<crate::PdpDecision, crate::PdpError> {
            panic!("NullPdpResolver should not be invoked in pure-rule tests");
        }
    }

    struct NullPluginInvoker;
    #[async_trait::async_trait]
    impl crate::PluginInvoker for NullPluginInvoker {
        async fn invoke(
            &self,
            _name: &str,
            _bag: &crate::AttributeBag,
            _invocation: crate::PluginInvocation<'_>,
        ) -> Result<crate::PluginOutcome, crate::PluginError> {
            panic!("NullPluginInvoker should not be invoked in pure-rule tests");
        }
    }

    #[test]
    fn pipeline_simple_bare_stages() {
        let p = parse_pipeline("str").unwrap();
        assert_eq!(p.stages, vec![Stage::Type(TypeCheck::Str)]);

        let p = parse_pipeline("omit").unwrap();
        assert_eq!(p.stages, vec![Stage::Omit]);

        let p = parse_pipeline("hash").unwrap();
        assert_eq!(p.stages, vec![Stage::Hash]);
    }

    #[test]
    fn pipeline_chains_split_on_pipe() {
        let p = parse_pipeline("str | mask(4)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Type(TypeCheck::Str), Stage::Mask { keep_last: 4 },]
        );

        let p = parse_pipeline("int | 0..1M").unwrap();
        assert_eq!(
            p.stages,
            vec![
                Stage::Type(TypeCheck::Int),
                Stage::Range {
                    min: Some(0),
                    max: Some(1_000_000)
                },
            ]
        );
    }

    #[test]
    fn pipeline_pipe_inside_parens_does_not_split() {
        // `redact(!a | b)` is one stage; the inner `|` is OR inside a
        // predicate condition, not a chain separator.
        let p = parse_pipeline("str | redact(!perm.view_ssn | role.admin)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact { condition: Some(_) } => {},
            other => panic!("expected Redact with condition, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_length_constraints() {
        let p = parse_pipeline("len(..500)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: None,
                max: Some(500)
            }]
        );
        let p = parse_pipeline("len(10..50)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: Some(10),
                max: Some(50)
            }]
        );
        let p = parse_pipeline("len(8..)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: Some(8),
                max: None
            }]
        );
    }

    #[test]
    fn pipeline_range_with_suffixes() {
        let p = parse_pipeline("0..10k").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: Some(0),
                max: Some(10_000)
            }]
        );
        let p = parse_pipeline("0..1M").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: Some(0),
                max: Some(1_000_000)
            }]
        );
        let p = parse_pipeline("..500").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: None,
                max: Some(500)
            }]
        );
    }

    #[test]
    fn pipeline_enum_unquoted_and_quoted() {
        let p = parse_pipeline("enum(low, medium, high)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Enum {
                values: vec!["low".into(), "medium".into(), "high".into()],
            }]
        );
        let p = parse_pipeline(r#"enum("a", "b")"#).unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Enum {
                values: vec!["a".into(), "b".into()],
            }]
        );
    }

    #[test]
    fn pipeline_redact_with_predicate_condition() {
        let p = parse_pipeline("str | redact(!perm.view_ssn)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact {
                condition: Some(Expression::Not(inner)),
            } => match inner.as_ref() {
                Expression::Condition(Condition::IsTrue { key }) => {
                    assert_eq!(key, "perm.view_ssn");
                },
                other => panic!("expected IsTrue(perm.view_ssn), got {other:?}"),
            },
            other => panic!("expected Redact with Not condition, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_taint_scopes() {
        let p = parse_pipeline("taint(PII)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
        let p = parse_pipeline("taint(PII, message)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Message],
            }]
        );
        let p = parse_pipeline("taint(PII, [session, message])").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Session, TaintScope::Message],
            }]
        );
    }

    #[test]
    fn pipeline_unknown_stage_rejected() {
        let err = parse_pipeline("nonsense").unwrap_err();
        assert!(format!("{err}").contains("unknown stage"));
    }

    #[test]
    fn pipeline_omit_with_args_rejected() {
        // omit has no conditional form.
        let err = parse_pipeline("omit(!perm.x)").unwrap_err();
        assert!(format!("{err}").contains("omit takes no arguments"));
    }

    #[test]
    fn compile_route_with_args_and_result() {
        let yaml = r#"
route:
  args:
    employee_id: "uuid"
    amount: "int | 0..1M"
  result:
    ssn: "str | redact(!perm.view_ssn)"
    employee_id: "str | mask(4)"
    internal_notes: "omit"
"#;
        let route = compile_test_route("get_compensation", yaml).unwrap();
        assert_eq!(route.args.len(), 2);
        assert_eq!(route.result.len(), 3);

        // Pull out the ssn pipeline and confirm shape.
        let ssn = route.result.iter().find(|f| f.field == "ssn").unwrap();
        assert_eq!(ssn.pipeline.stages.len(), 2);
        assert!(matches!(
            ssn.pipeline.stages[0],
            Stage::Type(TypeCheck::Str)
        ));
        assert!(matches!(
            ssn.pipeline.stages[1],
            Stage::Redact { condition: Some(_) }
        ));

        // declared_phases should include Result and Args now.
        let phases = route.declared_phases();
        assert!(phases.contains(crate::rules::Phase::Args));
        assert!(phases.contains(crate::rules::Phase::Result));
    }

    #[test]
    fn compile_route_with_only_args_still_compiles() {
        // A route with no authorization block but with `args:`
        // validators is still an APL route (declared_phases non-empty).
        let yaml = r#"
route:
  args:
    employee_id: "uuid"
"#;
        let route = compile_test_route("validate_only", yaml).unwrap();
        assert!(
            !route.declared_phases().is_empty(),
            "`args:` alone is a policy"
        );
    }

    #[test]
    fn compile_propagates_pipeline_parse_errors() {
        let yaml = r#"
route:
  result:
    x: "nonsense"
"#;
        let err = compile_test_policy("bad", yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown stage"));
    }

    #[test]
    fn compile_captures_root_plugins_block_into_registry() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: native
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_subject]
    config:
      max_requests: 100
  - name: audit
    kind: native
    hooks: [cmf.tool_post_invoke]
route:
  authorization:
    pre_invocation:
      - "run(rate_limiter)"
"#;
        let cfg = compile_test_policy("get_compensation", yaml).unwrap();
        assert_eq!(cfg.plugins.len(), 2);
        let rl = cfg.plugins.get("rate_limiter").unwrap();
        assert_eq!(rl.kind, "native");
        assert_eq!(rl.hooks, vec!["cmf.tool_pre_invoke".to_owned()]);
        assert_eq!(rl.capabilities, vec!["read_subject".to_owned()]);
        // The route still compiles (it names run(rate_limiter)).
        assert!(!cfg.route.declared_phases().is_empty());
    }

    #[test]
    fn compile_captures_route_level_plugin_overrides() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: native
    hooks: [cmf.tool_pre_invoke]
    config:
      max_requests: 100
route:
  authorization:
    pre_invocation:
      - "run(rate_limiter)"
  plugins:
    rate_limiter:
      config:
        max_requests: 10
      on_error: ignore
"#;
        let cfg = compile_test_policy("hot_path", yaml).unwrap();
        let route = &cfg.route;
        let ovr = route.plugin_overrides.get("rate_limiter").unwrap();
        assert_eq!(ovr.on_error.as_deref(), Some("ignore"));
        let cfg_yaml = ovr.config.as_ref().unwrap();
        assert_eq!(
            cfg_yaml["max_requests"],
            serde_yaml::from_str::<serde_yaml::Value>("10").unwrap()
        );

        // Verify EffectivePlugin::resolve sees the override.
        let eff = crate::plugin_decl::EffectivePlugin::resolve(
            "rate_limiter",
            &cfg.plugins,
            &route.plugin_overrides,
        )
        .unwrap();
        assert_eq!(eff.on_error, Some("ignore"));
        // Hooks NOT overridable — still from the global declaration.
        assert_eq!(eff.hooks, &["cmf.tool_pre_invoke".to_owned()]);
    }

    #[test]
    fn compile_policy_block_value_parses_apl_body() {
        let yaml = r#"
authorization:
  pre_invocation:
    - "require(authenticated)"
result:
  ssn: "redact(!perm.view_ssn)"
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let compiled =
            compile_policy_block_value("global.policy.all", &value).expect("compile block");
        assert_eq!(compiled.route_key, "global.policy.all");
        assert_eq!(compiled.pre_invocation.len(), 1);
        assert_eq!(compiled.result.len(), 1);
        assert_eq!(compiled.result[0].field, "ssn");
    }

    #[test]
    fn compile_policy_block_value_null_is_empty_route() {
        let value = serde_yaml::Value::Null;
        let compiled =
            compile_policy_block_value("global.defaults.tool", &value).expect("compile null");
        assert!(compiled.declared_phases().is_empty());
        assert_eq!(compiled.route_key, "global.defaults.tool");
    }

    #[test]
    fn compile_policy_block_value_threads_source_into_rule_paths() {
        let yaml = r#"
authorization:
  pre_invocation:
    - "require(authenticated)"
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_policy_block_value("groups.hr", &value).expect("compile");
        match &compiled.pre_invocation[0] {
            crate::rules::Effect::When { source, .. } => {
                assert_eq!(source, "groups.hr.pre_invocation[0]");
            },
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_delegate_step_with_only_plugin() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert!(ds.config_override.is_none());
        assert!(ds.on_error.is_none());
        assert_eq!(ds.source, "test.policy[0]");
    }

    #[test]
    fn parse_delegate_step_with_config_and_on_error() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
    config:
      target: workday-api
      permissions: [read_compensation]
    on_error: deny
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[1]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert_eq!(ds.on_error.as_deref(), Some("deny"));
        let cfg = ds.config_override.as_ref().expect("config_override set");
        let target = cfg
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("target".into())))
            .and_then(|v| v.as_str());
        assert_eq!(target, Some("workday-api"));
    }

    #[test]
    fn parse_delegate_step_missing_plugin_errors() {
        let yaml = r#"
- delegate:
    config: { target: workday-api }
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("missing plugin");
        let msg = format!("{err}");
        assert!(msg.contains("requires `plugin:"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_empty_plugin_errors() {
        let yaml = r#"
- delegate:
    plugin: ""
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("empty plugin");
        let msg = format!("{err}");
        assert!(msg.contains("cannot be empty"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_non_string_on_error_errors() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
    on_error: 42
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("non-string on_error");
        let msg = format!("{err}");
        assert!(msg.contains("on_error"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_non_map_body_errors() {
        let yaml = r#"
- delegate: workday-oauth
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("non-map delegate body");
        let msg = format!("{err}");
        assert!(msg.contains("must be a map"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_bare_plugin_name() {
        let yaml = r#"- "delegate(workday-oauth)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert!(ds.config_override.is_none());
        assert!(ds.on_error.is_none());
        assert_eq!(ds.source, "test.policy[0]");
    }

    #[test]
    fn parse_delegate_string_with_string_kwargs() {
        let yaml =
            r#"- "delegate(workday-oauth, target: workday-api, audience: https://workday.com)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.plugin_name, "workday-oauth");
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert_eq!(
            cfg.get(serde_yaml::Value::String("target".into()))
                .and_then(|v| v.as_str()),
            Some("workday-api"),
        );
        assert_eq!(
            cfg.get(serde_yaml::Value::String("audience".into()))
                .and_then(|v| v.as_str()),
            Some("https://workday.com"),
        );
    }

    #[test]
    fn parse_delegate_string_with_list_kwarg() {
        let yaml = r#"- "delegate(workday-oauth, permissions: [read_compensation, write_notes])""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        let perms = cfg
            .get(serde_yaml::Value::String("permissions".into()))
            .and_then(|v| v.as_sequence())
            .expect("permissions sequence");
        let names: Vec<&str> = perms.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(names, vec!["read_compensation", "write_notes"]);
    }

    #[test]
    fn parse_delegate_string_on_error_pulled_out() {
        let yaml = r#"- "delegate(workday-oauth, target: workday-api, on_error: continue)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.on_error.as_deref(), Some("continue"));
        // on_error must NOT also leak into config_override.
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert!(
            cfg.get(serde_yaml::Value::String("on_error".into()))
                .is_none(),
            "on_error must not appear in config_override"
        );
    }

    #[test]
    fn parse_delegate_string_quoted_plugin_name() {
        // Quoting the plugin name is harmless — the parser strips
        // the wrapping quotes. Useful when the name contains
        // characters the bare-ident reader doesn't like.
        let yaml = r#"- 'delegate("workday-oauth")'"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        assert_eq!(ds.plugin_name, "workday-oauth");
    }

    #[test]
    fn parse_delegate_string_quoted_value_preserves_internal_commas() {
        let yaml =
            r#"- 'delegate(workday-oauth, audience: "https://workday.com,backup.workday.com")'"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let ds = expect_delegate(step);
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert_eq!(
            cfg.get(serde_yaml::Value::String("audience".into()))
                .and_then(|v| v.as_str()),
            Some("https://workday.com,backup.workday.com"),
        );
    }

    #[test]
    fn parse_delegate_string_empty_args_errors() {
        let yaml = r#"- "delegate()""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("empty args");
        let msg = format!("{err}");
        assert!(msg.contains("plugin name"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_plugin_kwarg_rejected() {
        // `plugin:` as a kwarg is ambiguous when the plugin name is
        // also the positional first arg — reject loudly.
        let yaml = r#"- "delegate(workday-oauth, plugin: other-thing)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("plugin kwarg");
        let msg = format!("{err}");
        assert!(msg.contains("positional"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_kwarg_missing_colon_errors() {
        let yaml = r#"- "delegate(workday-oauth, target workday-api)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("missing colon");
        let msg = format!("{err}");
        assert!(msg.contains("key: value"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_unbalanced_brackets_errors() {
        let yaml = r#"- "delegate(workday-oauth, permissions: [read_compensation)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("unbalanced");
        let msg = format!("{err}");
        assert!(
            msg.contains("unmatched") || msg.contains("unbalanced"),
            "got: {msg}"
        );
    }

    #[test]
    fn compile_route_mixed_string_and_map_delegate_forms() {
        // Both forms coexist in the same policy block — string form
        // for the compact case, map form for richer config.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(role.hr)"
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - delegate:
          plugin: audit-receipt
          on_error: continue
          config:
            mode: trace
"#;
        let cfg = compile_test_policy("get_compensation", yaml).expect("compile");
        let route = &cfg.route;
        assert_eq!(route.pre_invocation.len(), 3);

        // Step [1] is the string-form delegate.
        let crate::rules::Effect::Delegate(s1) = &route.pre_invocation[1] else {
            panic!("expected Delegate at policy[1]");
        };
        assert_eq!(s1.plugin_name, "workday-oauth");
        assert!(s1.on_error.is_none());

        // Step [2] is the map-form delegate.
        let crate::rules::Effect::Delegate(s2) = &route.pre_invocation[2] else {
            panic!("expected Delegate at policy[2]");
        };
        assert_eq!(s2.plugin_name, "audit-receipt");
        assert_eq!(s2.on_error.as_deref(), Some("continue"));
    }

    #[test]
    fn compile_route_with_delegate_in_both_step_lists() {
        // End-to-end: delegate() lands in the right phase with the
        // right source path for diagnostics. Mixed with normal rules
        // to prove it doesn't perturb existing step parsing.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(role.hr)"
      - delegate:
          plugin: workday-oauth
          config:
            target: workday-api
            permissions: [read_compensation]
      - "require(authenticated)"
    post_invocation:
      - delegate:
          plugin: audit-biscuit
          on_error: continue
"#;
        let cfg = compile_test_policy("get_compensation", yaml).expect("compile");
        let route = &cfg.route;
        assert_eq!(route.pre_invocation.len(), 3);

        // Policy step [1] is the delegate.
        let crate::rules::Effect::Delegate(ds) = &route.pre_invocation[1] else {
            panic!(
                "expected Delegate at policy[1], got {:?}",
                route.pre_invocation[1]
            );
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert_eq!(ds.source, "get_compensation.pre_invocation[1]");

        // post_invocation[0] is the audit-biscuit delegate.
        let crate::rules::Effect::Delegate(post_ds) = &route.post_invocation[0] else {
            panic!("expected Delegate at post_invocation[0]");
        };
        assert_eq!(post_ds.plugin_name, "audit-biscuit");
        assert_eq!(post_ds.on_error.as_deref(), Some("continue"));
        assert_eq!(post_ds.source, "get_compensation.post_invocation[0]");
    }

    fn parse_elicit_str(s: &str) -> crate::step::ElicitStep {
        let value = serde_yaml::Value::String(s.to_owned());
        let step = parse_step(&value, "test.policy[0]").expect("parse");
        match step {
            crate::step::Step::Elicit(e) => e,
            other => panic!("expected Elicit, got {other:?}"),
        }
    }

    #[test]
    fn parse_require_approval_full_kwargs() {
        let e = parse_elicit_str(
            "require_approval(manager-approver, from: user.manager, channel: \"ciba\", \
             scope: \"args.amount <= 25000\", \
             purpose: \"Approve salary change\", timeout: 24h)",
        );
        assert_eq!(e.kind, ElicitKind::Approval);
        assert_eq!(e.plugin_name, "manager-approver");
        assert_eq!(e.from, "user.manager");
        assert_eq!(e.channel.as_deref(), Some("ciba"));
        assert_eq!(e.scope.as_deref(), Some("args.amount <= 25000"));
        assert_eq!(e.purpose.as_deref(), Some("Approve salary change"));
        assert_eq!(e.timeout.as_deref(), Some("24h"));
        assert!(e.on_error.is_none());
        assert!(e.config_override.is_none());
        assert_eq!(e.source, "test.policy[0]");
    }

    #[test]
    fn parse_channel_is_optional() {
        // No `channel:` — it's an audit label, not required for routing.
        let e = parse_elicit_str("require_approval(manager-approver, from: user.manager)");
        assert_eq!(e.plugin_name, "manager-approver");
        assert!(e.channel.is_none());
    }

    #[test]
    fn parse_each_verb_maps_to_its_kind() {
        for (verb, want) in [
            ("require_approval", ElicitKind::Approval),
            ("confirm", ElicitKind::Confirm),
            ("require_step_up", ElicitKind::StepUp),
            ("require_attestation", ElicitKind::Attestation),
            ("request_info", ElicitKind::Info),
            ("require_review", ElicitKind::Review),
        ] {
            let e = parse_elicit_str(&format!("{verb}(inband-asker, from: user.sub)"));
            assert_eq!(e.kind, want, "verb `{verb}`");
            assert_eq!(e.plugin_name, "inband-asker");
            assert_eq!(e.from, "user.sub");
        }
    }

    #[test]
    fn parse_confirm_prompt_aliases_purpose() {
        // The elicitation-hook doc uses `prompt` for confirm; it maps to
        // the same `purpose` field as `require_approval`.
        let e =
            parse_elicit_str("confirm(inband-asker, from: user.sub, prompt: \"Drop the table?\")");
        assert_eq!(e.kind, ElicitKind::Confirm);
        assert_eq!(e.purpose.as_deref(), Some("Drop the table?"));
    }

    #[test]
    fn parse_unknown_kwarg_goes_to_config_override() {
        let e = parse_elicit_str(
            "require_approval(slack-approver, from: user.manager, \
             details_link: https://approvals.example.com/req)",
        );
        let cfg = e.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert_eq!(
            cfg.get(serde_yaml::Value::String("details_link".into()))
                .and_then(|v| v.as_str()),
            Some("https://approvals.example.com/req"),
        );
        // Recognized keys must NOT leak into config_override.
        assert!(cfg.get(serde_yaml::Value::String("from".into())).is_none());
    }

    #[test]
    fn parse_on_error_pulled_out() {
        let e = parse_elicit_str(
            "require_approval(manager-approver, from: user.manager, on_error: continue)",
        );
        assert_eq!(e.on_error.as_deref(), Some("continue"));
        assert!(e.config_override.is_none());
    }

    #[test]
    fn parse_missing_plugin_name_errors() {
        let value = serde_yaml::Value::String("require_approval(from: user.manager)".into());
        let err = parse_step(&value, "test.policy[0]").expect_err("missing plugin name");
        // `from: user.manager` parses as the positional first arg, so the
        // missing piece surfaces as the required `from` kwarg.
        assert!(format!("{err}").contains("requires `from`"), "got: {err}");
    }

    #[test]
    fn parse_empty_args_errors() {
        let value = serde_yaml::Value::String("require_approval()".into());
        let err = parse_step(&value, "test.policy[0]").expect_err("empty args");
        assert!(format!("{err}").contains("plugin name"), "got: {err}");
    }

    #[test]
    fn parse_plugin_kwarg_rejected() {
        // Passing `plugin:` as a kwarg is ambiguous with the positional.
        let value = serde_yaml::Value::String(
            "require_approval(manager-approver, plugin: other, from: user.manager)".into(),
        );
        let err = parse_step(&value, "test.policy[0]").expect_err("plugin kwarg");
        assert!(format!("{err}").contains("first positional"), "got: {err}");
    }

    #[test]
    fn parse_missing_from_errors() {
        let value = serde_yaml::Value::String("require_approval(manager-approver)".into());
        let err = parse_step(&value, "test.policy[0]").expect_err("missing from");
        assert!(format!("{err}").contains("requires `from`"));
    }

    #[test]
    fn parse_require_prefixed_verbs_do_not_collide() {
        // `require_attestation` must not be swallowed by a `require_a*`
        // partial match — each verb is matched with its trailing `(`.
        let e = parse_elicit_str("require_attestation(inband-asker, from: user.sub)");
        assert_eq!(e.kind, ElicitKind::Attestation);
    }

    #[test]
    fn compile_route_with_require_approval_in_policy() {
        // End-to-end: the sugar verb survives compilation and lands as
        // an Effect::Elicit at the right phase/source. The `when`-gated
        // form mirrors the manager-approval design doc.
        let yaml = r#"
route:
  authorization:
    pre_invocation:
      - "require(authenticated)"
      - when: "args.amount > 10000"
        do:
          - "require_approval(manager-approver, from: user.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve salary change\", timeout: 24h)"
"#;
        let cfg = compile_test_policy("payroll_adjust", yaml).expect("compile");
        let route = &cfg.route;
        assert_eq!(route.pre_invocation.len(), 2);

        // policy[1] is the `when` wrapper; its body[0] is the elicitation.
        let crate::rules::Effect::When { body, .. } = &route.pre_invocation[1] else {
            panic!(
                "expected When at policy[1], got {:?}",
                route.pre_invocation[1]
            );
        };
        let crate::rules::Effect::Elicit(e) = &body[0] else {
            panic!("expected Elicit in when-body, got {:?}", body[0]);
        };
        assert_eq!(e.kind, ElicitKind::Approval);
        assert_eq!(e.plugin_name, "manager-approver");
        assert_eq!(e.from, "user.manager");
        assert_eq!(e.channel.as_deref(), Some("ciba"));
        assert_eq!(e.scope.as_deref(), Some("args.amount <= 25000"));
    }

    #[test]
    fn parse_pipeline_rejects_validate_stage_at_compile_time() {
        // Named-validator dispatch isn't implemented; the parser
        // rejects `validate(...)` rather than letting it through to
        // a runtime stub that silently passes. Diagnostic points the
        // operator at the working alternatives.
        let err = parse_pipeline("str | validate(ssn_format) | mask(4)")
            .expect_err("validate(name) should fail to parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented"),
            "diagnostic should explain that validate is unimplemented: {msg}",
        );
        assert!(
            msg.contains("regex") && msg.contains("run"),
            "diagnostic should suggest regex(...) and run(...): {msg}",
        );
        assert!(
            msg.contains("ssn_format"),
            "diagnostic should echo the rejected validator name: {msg}",
        );
    }

    /// A lone quote in a stage argument is an unterminated literal.
    ///
    /// It used to be content, so `regex(")` compiled to a pattern matching one
    /// double-quote character and `enum(")` to a set holding one. That was the
    /// visible half of a wider problem: quoted text was read in ten places with
    /// three different escape rules, and this site had none, so a quote was a
    /// delimiter only when it happened to appear at both ends.
    ///
    /// One reader serves every site now. What a stage argument keeps is the right
    /// to carry no quotes at all, which the sibling test below pins: requiring
    /// them would rewrite working field stages for no gain in meaning. What it
    /// loses is the right to open a literal and not close it.
    ///
    /// The reason this test was first written still holds and is still checked: a
    /// lone quote satisfied both `starts_with` and `ends_with`, and the follow-up
    /// slice ran from 1 to 0, so `parse_pipeline` panicked on operator input. It
    /// returns an error here, not a panic.
    #[test]
    fn lone_quote_in_stage_argument_is_an_unterminated_literal() {
        for src in ["str | regex(\")", "str | enum(\")", "str | regex(')"] {
            let msg = parse_pipeline(src)
                .expect_err("a lone quote does not read as content")
                .to_string();
            assert!(msg.contains("unterminated"), "{src}: {msg}");
        }

        // Two quotes are a closed literal, so an empty pattern still parses.
        parse_pipeline("str | regex(\"\")").expect("an empty quoted pattern is a closed literal");
    }

    #[test]
    fn quoted_and_bare_stage_arguments_agree_with_prior_behavior() {
        // Guards the shared quote stripper against changing what it accepts.
        let p = parse_pipeline("str | regex(\"^[A-Z]+$\")").expect("quoted pattern");
        assert!(
            format!("{:?}", p.stages).contains("^[A-Z]+$"),
            "quotes must be stripped from the pattern: {:?}",
            p.stages
        );
        let bare = parse_pipeline("str | regex(^[A-Z]+$)").expect("bare pattern");
        assert!(
            format!("{:?}", bare.stages).contains("^[A-Z]+$"),
            "an unquoted pattern must survive unchanged: {:?}",
            bare.stages
        );
    }

    #[test]
    fn parse_pipeline_does_not_reject_other_stages() {
        // Sanity: the validate rejection doesn't catch unrelated
        // stages. A pipeline with no validate stage parses cleanly.
        let p = parse_pipeline("str | len(..100) | regex(\"^[A-Z]+$\") | mask(4)")
            .expect("non-validate pipeline parses");
        assert_eq!(p.stages.len(), 4);
    }
}
