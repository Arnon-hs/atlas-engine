use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Node, ParseOptions, Parser};

use crate::{
    CallSite, CoverageStatus, DataFlowFact, DataFlowKind, DependencyFact, DependencySyntax,
    ImportBinding, Language, LiteralBooleanOption, ParseDiagnostic, ParsedFile, ParserProfile,
    SourceRange, StructuralMetrics, Symbol, SymbolKind, redact_secrets,
};

const MAX_PARSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_AST_NODES: usize = 250_000;
const MAX_AST_RECORDS: usize = 16_384;
const MAX_NAME_BYTES: usize = 512;
const MAX_METADATA_CHILDREN: usize = 256;
const MAX_DATAFLOW_NODES: usize = 100_000;
const MAX_DATAFLOW_FACTS: usize = 4_096;

/// Grammar selection with per-call parser ownership, suitable for a bounded
/// Rayon pool. Trees and native parser internals never cross the domain API.
#[derive(Default)]
pub struct ParserRegistry {
    _private: (),
}

impl ParserRegistry {
    pub fn parse(
        &self,
        language: Language,
        relative_path: &str,
        source: &str,
        max_parse_millis: u64,
    ) -> ParsedFile {
        self.parse_with_profile(
            ParserProfile::Legacy,
            language,
            relative_path,
            source,
            max_parse_millis,
        )
    }

    pub fn parse_extended(
        &self,
        language: Language,
        relative_path: &str,
        source: &str,
        max_parse_millis: u64,
    ) -> ParsedFile {
        self.parse_with_profile(
            ParserProfile::Extended,
            language,
            relative_path,
            source,
            max_parse_millis,
        )
    }

    fn parse_with_profile(
        &self,
        profile: ParserProfile,
        language: Language,
        relative_path: &str,
        source: &str,
        max_parse_millis: u64,
    ) -> ParsedFile {
        let mut result = ParsedFile::default();
        let supported = match profile {
            ParserProfile::Legacy => language.has_ast(),
            ParserProfile::Extended => language.has_extended_ast(),
        };
        if !supported {
            result.status = CoverageStatus::Unsupported;
            result.dataflow_status = if profile == ParserProfile::Extended {
                CoverageStatus::Unsupported
            } else {
                CoverageStatus::NotReported
            };
            return result;
        }
        result.status = CoverageStatus::Partial;
        result.dataflow_status =
            if profile == ParserProfile::Extended && language == Language::Python {
                CoverageStatus::Partial
            } else if profile == ParserProfile::Extended {
                CoverageStatus::Unsupported
            } else {
                CoverageStatus::NotReported
            };
        if source.len() > MAX_PARSE_BYTES || max_parse_millis == 0 {
            result.diagnostics.push(diagnostic(
                "parse_budget",
                "Input exceeds the parser budget",
            ));
            return result;
        }
        let grammar = match language {
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript if relative_path.ends_with(".tsx") => {
                tree_sitter_typescript::LANGUAGE_TSX.into()
            }
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Rust if profile == ParserProfile::Extended => {
                tree_sitter_rust::LANGUAGE.into()
            }
            Language::Shell if profile == ParserProfile::Extended => {
                tree_sitter_bash::LANGUAGE.into()
            }
            _ => return result,
        };
        let mut parser = Parser::new();
        if parser.set_language(&grammar).is_err() {
            result.diagnostics.push(diagnostic(
                "parser_unavailable",
                "The selected parser grammar could not be loaded",
            ));
            return result;
        }
        let started = Instant::now();
        let budget = Duration::from_millis(max_parse_millis.min(10_000));
        let mut progress = |_: &tree_sitter::ParseState| {
            if started.elapsed() >= budget {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let bytes = source.as_bytes();
        let tree = parser.parse_with_options(
            &mut |offset: usize, _| {
                &bytes[offset.min(bytes.len())..offset.saturating_add(16 * 1024).min(bytes.len())]
            },
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        );
        let Some(tree) = tree else {
            result.diagnostics.push(diagnostic(
                "parse_budget",
                "Parsing stopped at its cooperative time budget",
            ));
            return result;
        };
        if tree.root_node().has_error() {
            result.diagnostics.push(diagnostic(
                "parse_error",
                "Source contains syntax errors; extracted structure may be partial",
            ));
        }
        // Parse original syntax; use the identical byte coordinates from a masked
        // copy for every metadata name. Redaction does not alter the AST itself.
        let redacted = redact_secrets(source);
        if !redacted.redaction_complete {
            result.diagnostics.push(diagnostic(
                "redaction_budget",
                "Secret redaction reached its bounded scan limit; extracted semantics are partial",
            ));
        }
        let mut cursor = tree.walk();
        let mut scopes: Vec<(usize, SymbolKind, String)> = Vec::new();
        let mut nodes = 0;
        let mut records = 0;
        let mut depth = 0;
        let mut semicolon_namespace = String::new();
        let mut depth_reported = false;
        let mut metrics = StructuralMetrics::default();
        let mut control_scopes = Vec::new();
        'walk: loop {
            let node = cursor.node();
            nodes += 1;
            if nodes > MAX_AST_NODES
                || records >= MAX_AST_RECORDS
                || (nodes.is_multiple_of(64) && started.elapsed() >= budget)
            {
                result.diagnostics.push(diagnostic(
                    "parse_budget",
                    "AST extraction reached its time or record budget; structure is partial",
                ));
                break;
            }
            if node.is_named() {
                if is_control_flow_node(language, node.kind()) {
                    metrics.branch_points += 1;
                    control_scopes.push(node.id());
                    metrics.max_control_nesting =
                        metrics.max_control_nesting.max(control_scopes.len() as u64);
                }
                if let Some((kind, name, range_node)) = symbol_for(
                    language,
                    node,
                    &redacted.content,
                    scopes.last().map(|s| s.1),
                ) {
                    if language == Language::Php && node.kind() == "namespace_definition" {
                        semicolon_namespace = if node.child_by_field_name("body").is_none() {
                            name.clone()
                        } else {
                            String::new()
                        };
                    }
                    let mut names: Vec<&str> =
                        scopes.iter().map(|scope| scope.2.as_str()).collect();
                    if !semicolon_namespace.is_empty() && node.kind() != "namespace_definition" {
                        names.insert(0, &semicolon_namespace);
                    }
                    names.push(&name);
                    let qualified_name = names.join(".");
                    if qualified_name.len() <= 4096 {
                        if matches!(
                            kind,
                            SymbolKind::Function | SymbolKind::Method | SymbolKind::Constructor
                        ) {
                            metrics.functions += 1;
                        }
                        result.symbols.push(Symbol {
                            kind,
                            name: name.clone(),
                            qualified_name,
                            range: range(range_node),
                        });
                        records += 1;
                        if kind != SymbolKind::Constant {
                            scopes.push((node.id(), kind, name));
                        }
                    }
                }
                let Ok(imports) = imports_for(language, node, &redacted.content) else {
                    result.diagnostics.push(metadata_budget_diagnostic());
                    break;
                };
                if records + imports.len() > MAX_AST_RECORDS {
                    result.diagnostics.push(metadata_budget_diagnostic());
                    break;
                }
                let Ok(dependencies) =
                    dependencies_for(language, node, &redacted.content, &imports)
                else {
                    result.diagnostics.push(metadata_budget_diagnostic());
                    break;
                };
                if records + imports.len() + dependencies.len() > MAX_AST_RECORDS {
                    result.diagnostics.push(metadata_budget_diagnostic());
                    break;
                }
                records += imports.len() + dependencies.len();
                result.imports.extend(imports);
                result.dependencies.extend(dependencies);
                if let Some(callee) = call_for(language, node, &redacted.content) {
                    let Ok(options) = boolean_options(language, node, &redacted.content) else {
                        result.diagnostics.push(metadata_budget_diagnostic());
                        break;
                    };
                    if records + 1 + options.len() > MAX_AST_RECORDS {
                        result.diagnostics.push(metadata_budget_diagnostic());
                        break;
                    }
                    records += 1 + options.len();
                    result.calls.push(CallSite {
                        callee,
                        range: range(node),
                        literal_boolean_options: options,
                    });
                }
            }
            if depth < 256 && cursor.goto_first_child() {
                depth += 1;
                continue;
            }
            if depth >= 256 && node.child_count() > 0 && !depth_reported {
                result.diagnostics.push(diagnostic(
                    "parse_depth",
                    "AST nesting exceeds the extraction depth budget",
                ));
                depth_reported = true;
            }
            loop {
                if scopes
                    .last()
                    .is_some_and(|scope| scope.0 == cursor.node().id())
                {
                    scopes.pop();
                }
                if control_scopes
                    .last()
                    .is_some_and(|node_id| *node_id == cursor.node().id())
                {
                    control_scopes.pop();
                }
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    break 'walk;
                }
                depth -= 1;
            }
        }
        result.symbols.sort_by(|a, b| {
            a.range
                .start_byte
                .cmp(&b.range.start_byte)
                .then(b.range.end_byte.cmp(&a.range.end_byte))
                .then(a.qualified_name.cmp(&b.qualified_name))
        });
        result.calls.sort_by(|a, b| {
            a.range
                .start_byte
                .cmp(&b.range.start_byte)
                .then(a.callee.cmp(&b.callee))
        });
        result.dependencies.sort_by(|left, right| {
            left.range
                .start_byte
                .cmp(&right.range.start_byte)
                .then(left.syntax.cmp(&right.syntax))
                .then(left.module.cmp(&right.module))
        });
        result.dependencies.dedup();
        if result.diagnostics.is_empty() {
            result.status = CoverageStatus::Complete;
            result.structural_metrics = Some(metrics);
        }
        if profile == ParserProfile::Extended && language == Language::Python {
            let (dataflows, status) =
                python_dataflows(tree.root_node(), &redacted.content, started, budget);
            result.dataflows = dataflows;
            result.dataflow_status = if result.status == CoverageStatus::Complete {
                status
            } else {
                CoverageStatus::Partial
            };
        }
        result
    }
}

fn is_control_flow_node(language: Language, kind: &str) -> bool {
    match language {
        Language::Php => matches!(
            kind,
            "if_statement"
                | "else_if_clause"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "foreach_statement"
                | "case_statement"
                | "catch_clause"
                | "conditional_expression"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            kind,
            "if_statement"
                | "switch_case"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
                | "catch_clause"
                | "ternary_expression"
        ),
        Language::Python => matches!(
            kind,
            "if_statement"
                | "elif_clause"
                | "for_statement"
                | "while_statement"
                | "case_clause"
                | "except_clause"
                | "conditional_expression"
        ),
        Language::Rust => matches!(
            kind,
            "if_expression"
                | "match_arm"
                | "for_expression"
                | "while_expression"
                | "loop_expression"
        ),
        Language::Shell => matches!(
            kind,
            "if_statement"
                | "elif_clause"
                | "for_statement"
                | "c_style_for_statement"
                | "while_statement"
                | "case_item"
        ),
        _ => false,
    }
}

#[derive(Clone)]
struct PythonTaint {
    source_range: SourceRange,
    hops: u64,
}

fn python_dataflows(
    root: Node<'_>,
    redacted: &str,
    started: Instant,
    budget: Duration,
) -> (Vec<DataFlowFact>, CoverageStatus) {
    let mut cursor = root.walk();
    let mut facts = Vec::new();
    let mut nodes = 0usize;
    let mut complete = true;
    'walk: loop {
        let node = cursor.node();
        nodes += 1;
        if nodes > MAX_DATAFLOW_NODES
            || facts.len() >= MAX_DATAFLOW_FACTS
            || (nodes.is_multiple_of(64) && started.elapsed() >= budget)
        {
            complete = false;
            break;
        }
        if node.kind() == "function_definition" {
            complete &= analyze_python_function(node, redacted, &mut facts);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                break 'walk;
            }
        }
    }
    facts.sort_by(|left, right| {
        left.sink_range
            .start_byte
            .cmp(&right.sink_range.start_byte)
            .then(
                left.source_range
                    .start_byte
                    .cmp(&right.source_range.start_byte),
            )
            .then(left.assignment_hops.cmp(&right.assignment_hops))
    });
    facts.dedup();
    (
        facts,
        if complete {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        },
    )
}

fn analyze_python_function(
    function: Node<'_>,
    redacted: &str,
    facts: &mut Vec<DataFlowFact>,
) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let Ok(parameters) = metadata_children(parameters) else {
        return false;
    };
    let mut tainted = BTreeMap::<String, PythonTaint>::new();
    let mut complete = true;
    for parameter in parameters {
        match python_parameter_identifier(parameter) {
            Some(identifier) => {
                let Some(name) = name_text(identifier, redacted) else {
                    complete = false;
                    continue;
                };
                if tainted.len() >= 128 {
                    return false;
                }
                tainted.insert(
                    name,
                    PythonTaint {
                        source_range: range(identifier),
                        hops: 0,
                    },
                );
            }
            None if !matches!(
                parameter.kind(),
                "keyword_separator" | "positional_separator"
            ) =>
            {
                complete = false;
            }
            None => {}
        }
    }
    let Ok(statements) = metadata_children(body) else {
        return false;
    };
    for statement in statements {
        if facts.len() >= MAX_DATAFLOW_FACTS {
            return false;
        }
        match statement.kind() {
            "expression_statement" => {
                let Some(expression) = statement.named_child(0) else {
                    complete = false;
                    continue;
                };
                match expression.kind() {
                    "assignment" => {
                        let Some(left) = expression.child_by_field_name("left") else {
                            complete = false;
                            continue;
                        };
                        let Some(right) = expression.child_by_field_name("right") else {
                            complete = false;
                            continue;
                        };
                        complete &=
                            record_python_sinks_in_expression(right, redacted, &tainted, facts);
                        if left.kind() != "identifier" {
                            complete = false;
                            continue;
                        }
                        let Some(name) = name_text(left, redacted) else {
                            complete = false;
                            continue;
                        };
                        if let Some(mut value) =
                            python_taint_expression(right, redacted, &tainted, 0)
                        {
                            value.hops = value.hops.saturating_add(1);
                            if value.hops > 8
                                || (tainted.len() >= 128 && !tainted.contains_key(&name))
                            {
                                complete = false;
                            } else {
                                tainted.insert(name, value);
                            }
                        } else {
                            if python_expression_mentions_taint(right, redacted, &tainted) {
                                complete = false;
                            }
                            tainted.remove(&name);
                        }
                    }
                    "call" => {
                        complete &= record_python_sinks_in_expression(
                            expression, redacted, &tainted, facts,
                        );
                    }
                    "identifier" | "string" | "integer" | "float" | "none" | "true" | "false" => {}
                    _ => complete = false,
                }
            }
            "return_statement" => {
                if let Some(expression) = statement.named_child(0) {
                    complete &=
                        record_python_sinks_in_expression(expression, redacted, &tainted, facts);
                }
            }
            "pass_statement"
            | "import_statement"
            | "import_from_statement"
            | "global_statement"
            | "nonlocal_statement"
            | "future_import_statement" => {}
            // Nested definitions are evaluated separately and do not share the
            // outer function's local taint model.
            "function_definition" | "class_definition" | "decorated_definition" => {}
            _ => complete = false,
        }
    }
    complete
}

/// Inspect every call evaluated by a supported expression. This deliberately
/// walks nested calls: treating only the outer call as modeled would let
/// `wrapper(eval(parameter))` become a false complete zero. An uninspectable
/// call or traversal limit fails the enclosing function to partial coverage.
fn record_python_sinks_in_expression(
    root: Node<'_>,
    redacted: &str,
    tainted: &BTreeMap<String, PythonTaint>,
    facts: &mut Vec<DataFlowFact>,
) -> bool {
    let mut cursor = root.walk();
    let mut visited = 0usize;
    loop {
        let node = cursor.node();
        visited += 1;
        if visited > 1_024 || facts.len() >= MAX_DATAFLOW_FACTS {
            return false;
        }
        if node.kind() == "call" && !record_python_sink(node, redacted, tainted, facts) {
            return false;
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return true;
            }
        }
    }
}

fn python_parameter_identifier(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "default_parameter" | "typed_default_parameter" => node.child_by_field_name("name"),
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "identifier")
        }
        _ => None,
    }
}

fn python_taint_expression(
    node: Node<'_>,
    redacted: &str,
    tainted: &BTreeMap<String, PythonTaint>,
    depth: usize,
) -> Option<PythonTaint> {
    if depth > 16 {
        return None;
    }
    match node.kind() {
        "identifier" => tainted.get(&name_text(node, redacted)?).cloned(),
        "parenthesized_expression" => {
            python_taint_expression(node.named_child(0)?, redacted, tainted, depth + 1)
        }
        "binary_operator" => {
            let left = node
                .child_by_field_name("left")
                .and_then(|child| python_taint_expression(child, redacted, tainted, depth + 1));
            let right = node
                .child_by_field_name("right")
                .and_then(|child| python_taint_expression(child, redacted, tainted, depth + 1));
            merge_python_taint(left, right)
        }
        // Unknown transforms are not treated as sanitizers. Propagate taint from
        // any explicit argument and count the transform as one additional hop.
        "call" => {
            let arguments = node.child_by_field_name("arguments")?;
            let children = metadata_children(arguments).ok()?;
            let mut value = None;
            for child in children {
                let argument = if child.kind() == "keyword_argument" {
                    child.child_by_field_name("value")?
                } else {
                    child
                };
                value = merge_python_taint(
                    value,
                    python_taint_expression(argument, redacted, tainted, depth + 1),
                );
            }
            value.map(|mut value| {
                value.hops = value.hops.saturating_add(1);
                value
            })
        }
        _ => None,
    }
}

fn merge_python_taint(
    left: Option<PythonTaint>,
    right: Option<PythonTaint>,
) -> Option<PythonTaint> {
    match (left, right) {
        (Some(left), Some(right)) => Some(
            if (left.hops, left.source_range.start_byte)
                <= (right.hops, right.source_range.start_byte)
            {
                left
            } else {
                right
            },
        ),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn record_python_sink(
    call: Node<'_>,
    redacted: &str,
    tainted: &BTreeMap<String, PythonTaint>,
    facts: &mut Vec<DataFlowFact>,
) -> bool {
    let Some(callee_name) = call
        .child_by_field_name("function")
        .and_then(|node| callee(node, redacted, 0))
    else {
        return false;
    };
    let kind = if matches!(
        callee_name.as_str(),
        "eval" | "exec" | "builtins.eval" | "builtins.exec"
    ) {
        DataFlowKind::PythonParameterToDynamicEvaluation
    } else if matches!(
        callee_name.as_str(),
        "subprocess.run"
            | "subprocess.call"
            | "subprocess.Popen"
            | "subprocess.check_call"
            | "subprocess.check_output"
    ) && python_shell_true(call, redacted)
    {
        DataFlowKind::PythonParameterToShellExecution
    } else {
        return true;
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let Ok(arguments) = metadata_children(arguments) else {
        return false;
    };
    let Some(argument) = arguments.into_iter().find(|argument| {
        !matches!(
            argument.kind(),
            "keyword_argument" | "list_splat" | "dictionary_splat"
        )
    }) else {
        return true;
    };
    if let Some(value) = python_taint_expression(argument, redacted, tainted, 0) {
        facts.push(DataFlowFact {
            kind,
            source_range: value.source_range,
            sink_range: range(call),
            assignment_hops: value.hops,
        });
    } else if python_expression_mentions_taint(argument, redacted, tainted) {
        return false;
    }
    true
}

fn python_expression_mentions_taint(
    root: Node<'_>,
    redacted: &str,
    tainted: &BTreeMap<String, PythonTaint>,
) -> bool {
    let mut cursor = root.walk();
    let mut visited = 0usize;
    loop {
        let node = cursor.node();
        visited += 1;
        if visited > 1_024 {
            return true;
        }
        if node.kind() == "identifier"
            && name_text(node, redacted).is_some_and(|name| tainted.contains_key(&name))
        {
            return true;
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return false;
            }
        }
    }
}

fn python_shell_true(call: Node<'_>, redacted: &str) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let Ok(arguments) = metadata_children(arguments) else {
        return false;
    };
    arguments.into_iter().any(|argument| {
        argument.kind() == "keyword_argument"
            && argument
                .child_by_field_name("name")
                .and_then(|name| name_text(name, redacted))
                .is_some_and(|name| name == "shell")
            && argument.child_by_field_name("value").and_then(literal_bool) == Some(true)
    })
}

fn metadata_budget_diagnostic() -> ParseDiagnostic {
    diagnostic(
        "parse_budget",
        "AST import or argument metadata reached its record budget; structure is partial",
    )
}

fn metadata_children(node: Node<'_>) -> Result<Vec<Node<'_>>, ()> {
    if node.named_child_count() > MAX_METADATA_CHILDREN {
        return Err(());
    }
    let mut cursor = node.walk();
    Ok(node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect())
}

fn plain_string(node: Node<'_>, redacted: &str) -> Option<String> {
    if node.kind() != "string" || redacted.get(node.byte_range())?.contains('\\') {
        return None;
    }
    name_text(node, redacted)
}

fn static_property_name(node: Node<'_>, redacted: &str) -> Option<String> {
    match node.kind() {
        "string" => plain_string(node, redacted),
        "property_identifier" | "identifier" | "number" => name_text(node, redacted),
        _ => None,
    }
}

fn literal_bool(mut node: Node<'_>) -> Option<bool> {
    for _ in 0..8 {
        match node.kind() {
            "true" => return Some(true),
            "false" => return Some(false),
            "parenthesized_expression" if node.named_child_count() == 1 => {
                node = node.named_child(0)?;
            }
            _ => return None,
        }
    }
    None
}

fn boolean_options(
    language: Language,
    node: Node<'_>,
    redacted: &str,
) -> Result<Vec<LiteralBooleanOption>, ()> {
    if !matches!(
        language,
        Language::JavaScript | Language::TypeScript | Language::Python
    ) || node.has_error()
    {
        return Ok(Vec::new());
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Ok(Vec::new());
    };
    let arguments = metadata_children(arguments)?;
    let mut options = Vec::new();
    if language == Language::Python {
        let mut values = BTreeMap::new();
        for argument in arguments {
            if argument.kind() == "keyword_argument"
                && let Some(name) = argument
                    .child_by_field_name("name")
                    .and_then(|name| name_text(name, redacted))
            {
                let value = argument.child_by_field_name("value").and_then(literal_bool);
                // Duplicate Python keywords are invalid, not an override.
                values
                    .entry(name)
                    .and_modify(|old| *old = None)
                    .or_insert(value);
            }
        }
        options.extend(values.into_iter().filter_map(|(name, value)| {
            value.map(|value| LiteralBooleanOption {
                name,
                value,
                argument_index: None,
            })
        }));
    } else if !arguments
        .iter()
        .any(|argument| argument.kind() == "spread_element")
    {
        let mut inspected = arguments.len();
        for (index, argument) in arguments.into_iter().enumerate() {
            if argument.kind() != "object" {
                continue;
            }
            inspected += argument.named_child_count();
            if inspected > MAX_METADATA_CHILDREN {
                return Err(());
            }
            let Some(values) = object_boolean_values(argument, redacted)? else {
                continue;
            };
            options.extend(values.into_iter().filter_map(|(name, value)| {
                value.map(|value| LiteralBooleanOption {
                    name,
                    value,
                    argument_index: Some(index),
                })
            }));
            if options.len() > MAX_METADATA_CHILDREN {
                return Err(());
            }
        }
    }
    Ok(options)
}

// Only direct properties count. A spread or unknown/computed key could replace
// any earlier value, so that object's metadata is withheld. Known duplicate
// keys keep their final value, including nonliteral, shorthand and method forms.
fn object_boolean_values(
    node: Node<'_>,
    redacted: &str,
) -> Result<Option<BTreeMap<String, Option<bool>>>, ()> {
    let mut values = BTreeMap::new();
    for property in metadata_children(node)? {
        let (name, value) = match property.kind() {
            "pair" => {
                let Some(name) = property
                    .child_by_field_name("key")
                    .and_then(|key| static_property_name(key, redacted))
                else {
                    return Ok(None);
                };
                (
                    name,
                    property.child_by_field_name("value").and_then(literal_bool),
                )
            }
            "method_definition" => {
                let Some(name) = property
                    .child_by_field_name("name")
                    .and_then(|name| static_property_name(name, redacted))
                else {
                    return Ok(None);
                };
                (name, None)
            }
            "shorthand_property_identifier" => {
                let Some(name) = name_text(property, redacted) else {
                    return Ok(None);
                };
                (name, None)
            }
            _ => return Ok(None),
        };
        values.insert(name, value);
    }
    Ok(Some(values))
}

fn type_only_import(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .take(MAX_METADATA_CHILDREN * 4)
        .any(|child| !child.is_named() && child.kind() == "type")
}

fn require_module(node: Node<'_>, redacted: &str) -> Result<Option<String>, ()> {
    if node.kind() != "call_expression"
        || !node
            .child_by_field_name("function")
            .is_some_and(|function| {
                function.kind() == "identifier"
                    && name_text(function, redacted).as_deref() == Some("require")
            })
    {
        return Ok(None);
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Ok(None);
    };
    let arguments = metadata_children(arguments)?;
    Ok(if arguments.len() == 1 {
        plain_string(arguments[0], redacted)
    } else {
        None
    })
}

fn dependencies_for(
    language: Language,
    node: Node<'_>,
    redacted: &str,
    imports: &[ImportBinding],
) -> Result<Vec<DependencyFact>, ()> {
    if node.has_error() {
        return Ok(Vec::new());
    }
    let mut dependencies = Vec::new();
    match (language, node.kind()) {
        (Language::Python, "import_statement" | "import_from_statement") => {
            let mut modules = imports
                .iter()
                .map(|binding| {
                    if binding.module.bytes().all(|byte| byte == b'.') {
                        binding.imported_name.as_ref().map_or_else(
                            || binding.module.clone(),
                            |name| format!("{}{name}", binding.module),
                        )
                    } else {
                        binding.module.clone()
                    }
                })
                .collect::<Vec<_>>();
            modules.sort();
            modules.dedup();
            dependencies.extend(modules.into_iter().map(|module| DependencyFact {
                syntax: DependencySyntax::StaticImport,
                module: Some(module),
                range: range(node),
            }));
        }
        (Language::JavaScript | Language::TypeScript, "import_statement") => {
            let mut module = node
                .child_by_field_name("source")
                .and_then(|source| plain_string(source, redacted));
            if module.is_none() {
                module = metadata_children(node)?
                    .into_iter()
                    .find(|child| child.kind() == "import_require_clause")
                    .and_then(|clause| clause.child_by_field_name("source"))
                    .and_then(|source| plain_string(source, redacted));
            }
            if let Some(module) = module {
                dependencies.push(DependencyFact {
                    syntax: DependencySyntax::StaticImport,
                    module: Some(module),
                    range: range(node),
                });
            }
        }
        (Language::JavaScript | Language::TypeScript, "call_expression") => {
            let Some(function) = node.child_by_field_name("function") else {
                return Ok(dependencies);
            };
            if function.kind() == "import" {
                dependencies.push(DependencyFact {
                    syntax: DependencySyntax::DynamicImport,
                    module: None,
                    range: range(node),
                });
            } else if function.kind() == "identifier"
                && name_text(function, redacted).as_deref() == Some("require")
            {
                let module = require_module(node, redacted)?;
                dependencies.push(DependencyFact {
                    syntax: if module.is_some() {
                        DependencySyntax::StaticImport
                    } else {
                        DependencySyntax::DynamicImport
                    },
                    module,
                    range: range(node),
                });
            }
        }
        _ => {}
    }
    Ok(dependencies)
}

fn imports_for(
    language: Language,
    node: Node<'_>,
    redacted: &str,
) -> Result<Vec<ImportBinding>, ()> {
    if node.has_error()
        || !matches!(
            node.kind(),
            "import_statement" | "import_from_statement" | "variable_declarator"
        )
    {
        return Ok(Vec::new());
    }
    let mut imports = Vec::new();
    match (language, node.kind()) {
        (Language::Python, "import_statement" | "import_from_statement") => {
            let from = node.child_by_field_name("module_name");
            let module = from.and_then(|module| name_text(module, redacted));
            for child in metadata_children(node)? {
                if from.is_some_and(|from| from.id() == child.id()) {
                    continue;
                }
                let (name, alias) = if child.kind() == "aliased_import" {
                    (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("alias"),
                    )
                } else if child.kind() == "dotted_name" {
                    (Some(child), None)
                } else {
                    continue;
                };
                let Some(name) = name.and_then(|name| name_text(name, redacted)) else {
                    continue;
                };
                let local_name = if let Some(alias) = alias {
                    let Some(alias) = name_text(alias, redacted) else {
                        continue;
                    };
                    alias
                } else if from.is_none() {
                    name.split('.').next().unwrap_or(&name).to_owned()
                } else {
                    name.clone()
                };
                if let Some(module) = module.as_ref() {
                    imports.push(ImportBinding {
                        module: module.clone(),
                        imported_name: Some(name),
                        local_name,
                    });
                } else if from.is_none() {
                    imports.push(ImportBinding {
                        module: name,
                        imported_name: None,
                        local_name,
                    });
                }
            }
        }
        (Language::JavaScript | Language::TypeScript, "import_statement") => {
            if type_only_import(node) {
                return Ok(imports);
            }
            let children = metadata_children(node)?;
            if let Some(module) = node
                .child_by_field_name("source")
                .and_then(|source| plain_string(source, redacted))
            {
                for clause in children
                    .into_iter()
                    .filter(|child| child.kind() == "import_clause")
                {
                    for binding in metadata_children(clause)? {
                        match binding.kind() {
                            "identifier" => {
                                if let Some(local_name) = name_text(binding, redacted) {
                                    imports.push(ImportBinding {
                                        module: module.clone(),
                                        imported_name: Some("default".into()),
                                        local_name,
                                    });
                                }
                            }
                            "namespace_import" => {
                                if let Some(local_name) = metadata_children(binding)?
                                    .into_iter()
                                    .find(|name| name.kind() == "identifier")
                                    .and_then(|name| name_text(name, redacted))
                                {
                                    imports.push(ImportBinding {
                                        module: module.clone(),
                                        imported_name: None,
                                        local_name,
                                    });
                                }
                            }
                            "named_imports" => {
                                for specifier in metadata_children(binding)? {
                                    if specifier.kind() != "import_specifier"
                                        || type_only_import(specifier)
                                    {
                                        continue;
                                    }
                                    let Some(original) = specifier.child_by_field_name("name")
                                    else {
                                        continue;
                                    };
                                    if let (Some(imported_name), Some(local_name)) = (
                                        name_text(original, redacted),
                                        name_text(
                                            specifier
                                                .child_by_field_name("alias")
                                                .unwrap_or(original),
                                            redacted,
                                        ),
                                    ) {
                                        imports.push(ImportBinding {
                                            module: module.clone(),
                                            imported_name: Some(imported_name),
                                            local_name,
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                for clause in children
                    .into_iter()
                    .filter(|child| child.kind() == "import_require_clause")
                {
                    if let (Some(module), Some(local_name)) = (
                        clause
                            .child_by_field_name("source")
                            .and_then(|source| plain_string(source, redacted)),
                        metadata_children(clause)?
                            .into_iter()
                            .find(|name| name.kind() == "identifier")
                            .and_then(|name| name_text(name, redacted)),
                    ) {
                        imports.push(ImportBinding {
                            module,
                            imported_name: None,
                            local_name,
                        });
                    }
                }
            }
        }
        (Language::JavaScript | Language::TypeScript, "variable_declarator") => {
            let Some(value) = node.child_by_field_name("value") else {
                return Ok(imports);
            };
            let Some(module) = require_module(value, redacted)? else {
                return Ok(imports);
            };
            let Some(name) = node.child_by_field_name("name") else {
                return Ok(imports);
            };
            if name.kind() == "identifier" {
                if let Some(local_name) = name_text(name, redacted) {
                    imports.push(ImportBinding {
                        module,
                        imported_name: None,
                        local_name,
                    });
                }
            } else if name.kind() == "object_pattern" {
                for binding in metadata_children(name)? {
                    let pair = match binding.kind() {
                        "shorthand_property_identifier_pattern" => {
                            name_text(binding, redacted).map(|name| (name.clone(), name))
                        }
                        "pair_pattern" => binding
                            .child_by_field_name("key")
                            .and_then(|key| static_property_name(key, redacted))
                            .zip(
                                binding
                                    .child_by_field_name("value")
                                    .filter(|value| value.kind() == "identifier")
                                    .and_then(|value| name_text(value, redacted)),
                            ),
                        _ => None,
                    };
                    if let Some((imported_name, local_name)) = pair {
                        imports.push(ImportBinding {
                            module: module.clone(),
                            imported_name: Some(imported_name),
                            local_name,
                        });
                    }
                }
            }
        }
        _ => {}
    }
    if imports.len() > MAX_METADATA_CHILDREN {
        Err(())
    } else {
        Ok(imports)
    }
}

fn diagnostic(code: &str, message: &str) -> ParseDiagnostic {
    ParseDiagnostic {
        code: code.into(),
        message: message.into(),
        range: None,
    }
}

fn range(node: Node<'_>) -> SourceRange {
    let start = node.start_position();
    let end = node.end_position();
    SourceRange {
        start_line: start.row + 1,
        end_line: end.row + 1,
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_column: start.column + 1,
        end_column: end.column + 1,
    }
}

fn name_text(node: Node<'_>, redacted: &str) -> Option<String> {
    let text = redacted.get(node.byte_range())?;
    if text.len() > MAX_NAME_BYTES {
        return None;
    }
    let text = text.trim_matches(['\'', '"', '`']);
    if text.is_empty() || text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_owned())
}

fn symbol_for<'a>(
    language: Language,
    node: Node<'a>,
    redacted: &str,
    enclosing: Option<SymbolKind>,
) -> Option<(SymbolKind, String, Node<'a>)> {
    let node_kind = node.kind();
    let mut kind = match (language, node_kind) {
        (_, "class_declaration" | "class_definition") => SymbolKind::Class,
        (_, "interface_declaration") => SymbolKind::Interface,
        (Language::Php, "trait_declaration") => SymbolKind::Trait,
        (_, "namespace_definition" | "internal_module" | "module_declaration") => {
            SymbolKind::Module
        }
        (_, "function_declaration" | "generator_function_declaration" | "function_signature") => {
            SymbolKind::Function
        }
        (Language::Rust, "function_item") => {
            let mut ancestor = node.parent();
            let mut in_impl = false;
            for _ in 0..3 {
                let Some(parent) = ancestor else { break };
                if parent.kind() == "impl_item" {
                    in_impl = true;
                    break;
                }
                ancestor = parent.parent();
            }
            if in_impl {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            }
        }
        (Language::Shell, "function_definition") => SymbolKind::Function,
        (Language::Php | Language::Python, "function_definition") => {
            if language == Language::Python && enclosing == Some(SymbolKind::Class) {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            }
        }
        (
            _,
            "method_declaration"
            | "method_definition"
            | "method_signature"
            | "abstract_method_signature",
        ) => SymbolKind::Method,
        (Language::Php, "const_element") => SymbolKind::Constant,
        (Language::JavaScript | Language::TypeScript, "variable_declarator") => {
            let value = node.child_by_field_name("value")?;
            match value.kind() {
                "arrow_function" | "function_expression" | "generator_function" => {
                    SymbolKind::Function
                }
                "class" => SymbolKind::Class,
                _ => {
                    if node.parent()?.child(0)?.kind() == "const" {
                        SymbolKind::Constant
                    } else {
                        return None;
                    }
                }
            }
        }
        (Language::Python, "assignment") => {
            let name = node.child_by_field_name("left")?;
            if name.kind() != "identifier" {
                return None;
            }
            let value = name_text(name, redacted)?;
            if !value.bytes().any(|b| b.is_ascii_uppercase())
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return None;
            }
            return Some((SymbolKind::Constant, value, expanded_range(node)));
        }
        _ => return None,
    };
    let named = node.child_by_field_name("name").or_else(|| {
        if node_kind == "const_element" {
            node.named_child(0)
        } else {
            None
        }
    })?;
    if matches!(named.kind(), "object_pattern" | "array_pattern") {
        return None;
    }
    let name = name_text(named, redacted)?;
    if kind == SymbolKind::Method
        && matches!(name.as_str(), "constructor" | "__construct" | "__init__")
    {
        kind = SymbolKind::Constructor;
    }
    Some((kind, name, expanded_range(node)))
}

fn expanded_range(mut node: Node<'_>) -> Node<'_> {
    for _ in 0..3 {
        let Some(parent) = node.parent() else { break };
        if matches!(parent.kind(), "export_statement" | "decorated_definition")
            || (matches!(
                parent.kind(),
                "lexical_declaration" | "variable_declaration"
            ) && parent.named_child_count() == 1)
        {
            node = parent;
        } else {
            break;
        }
    }
    node
}

fn call_for(language: Language, node: Node<'_>, redacted: &str) -> Option<String> {
    match (language, node.kind()) {
        (Language::Php, "function_call_expression")
        | (Language::JavaScript | Language::TypeScript, "call_expression")
        | (Language::Python, "call") => callee(node.child_by_field_name("function")?, redacted, 0),
        (Language::Php, "member_call_expression" | "nullsafe_member_call_expression") => {
            let object = node
                .child_by_field_name("object")
                .and_then(|n| callee(n, redacted, 0))
                .unwrap_or_else(|| "<dynamic>".into());
            let method = name_text(node.child_by_field_name("name")?, redacted)?;
            Some(format!("{object}.{method}"))
        }
        (Language::Php, "scoped_call_expression") => {
            let scope = node
                .child_by_field_name("scope")
                .and_then(|n| callee(n, redacted, 0))
                .unwrap_or_else(|| "<dynamic>".into());
            Some(format!(
                "{scope}::{}",
                name_text(node.child_by_field_name("name")?, redacted)?
            ))
        }
        (Language::Php, "eval_expression") => Some("eval".into()),
        (Language::JavaScript | Language::TypeScript, "new_expression") => {
            callee(node.child_by_field_name("constructor")?, redacted, 0)
        }
        (Language::Php, "shell_command_expression") => Some("shell_exec".into()),
        (Language::Rust, "call_expression") => {
            callee(node.child_by_field_name("function")?, redacted, 0)
        }
        (Language::Shell, "command") => callee(node.child_by_field_name("name")?, redacted, 0),
        _ => None,
    }
}

/// Canonicalize only callee structure; arguments are never copied into metadata.
fn callee(node: Node<'_>, redacted: &str, depth: usize) -> Option<String> {
    if depth > 8 {
        return None;
    }
    match node.kind() {
        "member_expression" | "attribute" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|n| callee(n, redacted, depth + 1))
                .unwrap_or_else(|| "<dynamic>".into());
            let property = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("attribute"))?;
            Some(format!("{object}.{}", name_text(property, redacted)?))
        }
        "subscript_expression" => {
            let object = callee(node.child_by_field_name("object")?, redacted, depth + 1)?;
            let index = node.child_by_field_name("index")?;
            if index.kind() != "string" {
                return None;
            }
            Some(format!("{object}.{}", name_text(index, redacted)?))
        }
        "call_expression" => {
            if name_text(node.child_by_field_name("function")?, redacted)?.as_str() != "require" {
                return None;
            }
            let argument = node.child_by_field_name("arguments")?.named_child(0)?;
            if argument.kind() != "string" {
                return None;
            }
            match name_text(argument, redacted)?.as_str() {
                "child_process" | "node:child_process" => Some("child_process".into()),
                _ => None,
            }
        }
        _ => {
            let text = name_text(node, redacted)?;
            if text
                .chars()
                .all(|ch| ch.is_alphanumeric() || "_$.\\:*".contains(ch))
            {
                Some(text)
            } else {
                None
            }
        }
    }
}
