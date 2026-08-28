use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Node, ParseOptions, Parser};

use crate::{
    CallSite, ImportBinding, Language, LiteralBooleanOption, ParseDiagnostic, ParsedFile,
    SourceRange, Symbol, SymbolKind, redact_secrets,
};

const MAX_PARSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_AST_NODES: usize = 250_000;
const MAX_AST_RECORDS: usize = 16_384;
const MAX_NAME_BYTES: usize = 512;
const MAX_METADATA_CHILDREN: usize = 256;

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
        let mut result = ParsedFile::default();
        if !language.has_ast() {
            return result;
        }
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
        let mut cursor = tree.walk();
        let mut scopes: Vec<(usize, SymbolKind, String)> = Vec::new();
        let mut nodes = 0;
        let mut records = 0;
        let mut depth = 0;
        let mut semicolon_namespace = String::new();
        let mut depth_reported = false;
        'walk: loop {
            let node = cursor.node();
            nodes += 1;
            if nodes > MAX_AST_NODES
                || records >= MAX_AST_RECORDS
                || (nodes % 64 == 0 && started.elapsed() >= budget)
            {
                result.diagnostics.push(diagnostic(
                    "parse_budget",
                    "AST extraction reached its time or record budget; structure is partial",
                ));
                break;
            }
            if node.is_named() {
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
                records += imports.len();
                result.imports.extend(imports);
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
        result
    }
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
