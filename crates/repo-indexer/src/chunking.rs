use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use repo_core::{
    Diagnostic, ENGINE_VERSION, Language, ParserRegistry, SCHEMA_VERSION, Symbol, detect_secrets,
    is_unsafe_display_char, normalize_relative_path, redact_secrets,
};

use crate::{ChunkKind, FileIndex, IndexError, IndexOptions, IndexRecord, MAX_RECORDS_PER_FILE};

const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STRUCTURAL_SEGMENTS: usize = 8_192;

#[derive(Clone, Copy, Debug)]
struct Segment {
    start: usize,
    end: usize,
    owner: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct Plan {
    segment: Segment,
    part: usize,
}

fn diagnostic(path: &str, code: &str, message: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        relative_path: Some(path.to_owned()),
        message: message.to_owned(),
    }
}

fn add_segment(segments: &mut Vec<Segment>, segment: Segment) {
    if let Some(last) = segments.last_mut()
        && last.owner == segment.owner
        && last.end == segment.start
    {
        last.end = segment.end;
        return;
    }
    segments.push(segment);
}

/// Sweep nested syntax ranges into a partition, giving each byte to the
/// innermost symbol. This also tolerates partially recovered crossing ranges.
fn structural_segments(symbols: &[Symbol], length: usize) -> Option<Vec<Segment>> {
    let mut events = Vec::with_capacity(symbols.len().saturating_mul(2));
    for (index, symbol) in symbols.iter().enumerate() {
        events.push((symbol.range.start_byte, true, index));
        events.push((symbol.range.end_byte, false, index));
    }
    events.sort_unstable();
    let mut active = BTreeSet::new();
    let mut result = Vec::new();
    let mut previous = 0;
    let mut event_index = 0;
    while event_index < events.len() {
        let position = events[event_index].0;
        if previous < position {
            add_segment(
                &mut result,
                Segment {
                    start: previous,
                    end: position,
                    owner: active.last().map(|&(_, _, index)| index),
                },
            );
        }
        while event_index < events.len() && events[event_index].0 == position {
            let (_, starts, index) = events[event_index];
            let range = &symbols[index].range;
            let key = (range.start_byte, Reverse(range.end_byte), index);
            if starts {
                active.insert(key);
            } else {
                active.remove(&key);
            }
            event_index += 1;
        }
        if result.len() > MAX_STRUCTURAL_SEGMENTS {
            return None;
        }
        previous = position;
    }
    if previous < length {
        add_segment(
            &mut result,
            Segment {
                start: previous,
                end: length,
                owner: None,
            },
        );
    }
    Some(result)
}

fn split_end(source: &str, start: usize, end: usize, max_bytes: usize) -> usize {
    let mut limit = end.min(start.saturating_add(max_bytes));
    if limit == end {
        return end;
    }
    while !source.is_char_boundary(limit) {
        limit -= 1;
    }
    // max_bytes >= 4 guarantees at least one UTF-8 scalar can be consumed.
    if let Some(newline) = source.as_bytes()[start..limit]
        .iter()
        .rposition(|&byte| byte == b'\n')
    {
        start + newline + 1
    } else {
        limit
    }
}

fn plan_chunks(
    source: &str,
    segments: &[Segment],
    symbol_count: usize,
    max_bytes: usize,
) -> Option<Vec<Plan>> {
    let mut parts = vec![0usize; symbol_count + 1];
    let mut plans = Vec::new();
    for segment in segments {
        let mut start = segment.start;
        while start < segment.end {
            if plans.len() == MAX_RECORDS_PER_FILE {
                return None;
            }
            let end = split_end(source, start, segment.end, max_bytes);
            let counter = &mut parts[segment.owner.unwrap_or(symbol_count)];
            plans.push(Plan {
                segment: Segment {
                    start,
                    end,
                    owner: segment.owner,
                },
                part: *counter,
            });
            *counter += 1;
            start = end;
        }
    }
    Some(plans)
}

fn safe_label(value: &str) -> String {
    // ParserRegistry already extracts labels from the fully redacted source.
    // This second check protects the standalone metadata serialization boundary.
    redact_secrets(value).content
}

fn identity(
    repository_id: Option<&str>,
    path: &str,
    kind: ChunkKind,
    qualified_name: Option<&str>,
    occurrence: usize,
    part: usize,
) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("atlas-engine chunk identity v1");
    // Explicit length prefixes avoid ambiguity from separators in hostile names.
    for value in [
        repository_id.unwrap_or(""),
        path,
        kind.as_str(),
        qualified_name.unwrap_or(""),
    ] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(&(occurrence as u64).to_le_bytes());
    hasher.update(&(part as u64).to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Index one UTF-8 file without filesystem access. Secret detection always runs
/// over the complete file before slicing, including multiline credentials. Raw
/// source is never stored in output records. Inputs above 64 MiB are skipped.
///
/// Identity is based on repository ID, path, kind, qualified name, occurrence and
/// part, not content or line offsets. Inserting unrelated code before a named
/// symbol preserves its identity. Renames, moves, duplicate-name insertions, and
/// changes to how oversized/enclosing symbols are partitioned can change IDs.
pub fn chunk_source(
    language: Language,
    relative_path: &str,
    source: &str,
    repository_id: Option<&str>,
    commit_sha: Option<&str>,
    max_parse_millis: u64,
    options: &IndexOptions,
) -> Result<FileIndex, IndexError> {
    options.validate()?;
    let normalized = normalize_relative_path(Path::new(relative_path)).map_err(|_| {
        IndexError::Configuration("relative_path must be a safe portable relative path".to_owned())
    })?;
    let relative_path = normalized.as_str();
    if repository_id.is_some_and(|value| {
        value.len() > 1024
            || value.chars().any(is_unsafe_display_char)
            || !detect_secrets(value).is_empty()
    }) {
        return Err(IndexError::Configuration(
            "repository_id must be bounded metadata without control characters or secrets"
                .to_owned(),
        ));
    }
    if commit_sha.is_some_and(|value| {
        !matches!(value.len(), 40 | 64)
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().all(|byte| byte == b'0')
    }) {
        return Err(IndexError::Configuration(
            "commit_sha must be a Git object identifier".to_owned(),
        ));
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Ok(FileIndex::skipped(Some(diagnostic(
            relative_path,
            "index_input_limit",
            "File exceeds the indexer input byte limit.",
        ))));
    }
    let sensitive = detect_secrets(source);
    let redacted = redact_secrets(source);
    if redacted.content.len() != source.len() {
        return Err(IndexError::RedactionInvariant);
    }
    let parsed = ParserRegistry::default().parse(language, relative_path, source, max_parse_millis);
    let mut diagnostics: Vec<_> = parsed
        .diagnostics
        .into_iter()
        .map(|entry| Diagnostic {
            code: entry.code,
            relative_path: Some(relative_path.to_owned()),
            message: entry.message,
        })
        .collect();
    let mut invalid_range = false;
    let mut symbols: Vec<_> = parsed
        .symbols
        .into_iter()
        .filter(|symbol| {
            let range = &symbol.range;
            let valid = range.start_byte < range.end_byte
                && range.end_byte <= source.len()
                && source.is_char_boundary(range.start_byte)
                && source.is_char_boundary(range.end_byte);
            invalid_range |= !valid;
            valid
        })
        .collect();
    if invalid_range {
        diagnostics.push(diagnostic(
            relative_path,
            "index_invalid_range",
            "An invalid parser range was omitted.",
        ));
    }
    symbols.sort_by(|left, right| {
        left.range
            .start_byte
            .cmp(&right.range.start_byte)
            .then_with(|| right.range.end_byte.cmp(&left.range.end_byte))
            .then_with(|| left.qualified_name.cmp(&right.qualified_name))
            .then_with(|| {
                ChunkKind::from(left.kind)
                    .as_str()
                    .cmp(ChunkKind::from(right.kind).as_str())
            })
    });
    let fallback = [Segment {
        start: 0,
        end: source.len(),
        owner: None,
    }];
    let segments = structural_segments(&symbols, source.len());
    let mut plans = segments
        .as_deref()
        .and_then(|segments| plan_chunks(source, segments, symbols.len(), options.max_chunk_bytes));
    if plans.is_none() {
        diagnostics.push(diagnostic(
            relative_path,
            "index_structure_budget",
            "Structural record budget exceeded; using bounded file chunks.",
        ));
        plans = plan_chunks(source, &fallback, symbols.len(), options.max_chunk_bytes);
    }
    let Some(plans) = plans else {
        diagnostics.push(diagnostic(
            relative_path,
            "index_record_budget",
            "File skipped because bounded file chunks exceed the per-file record limit.",
        ));
        return Ok(FileIndex {
            records: Vec::new(),
            diagnostics,
            indexed: false,
        });
    };
    let mut seen = BTreeMap::new();
    let symbol_data: Vec<_> = symbols
        .iter()
        .map(|symbol| {
            let kind = ChunkKind::from(symbol.kind);
            let name = safe_label(&symbol.name);
            let qualified = safe_label(&symbol.qualified_name);
            let counter = seen
                .entry((kind.as_str(), qualified.clone()))
                .or_insert(0usize);
            let occurrence = *counter;
            *counter += 1;
            (kind, name, qualified, occurrence)
        })
        .collect();
    let mut sensitive_starts: Vec<_> = sensitive.iter().map(|found| found.start_byte).collect();
    let mut sensitive_ends: Vec<_> = sensitive.iter().map(|found| found.end_byte).collect();
    sensitive_starts.sort_unstable();
    sensitive_ends.sort_unstable();
    let mut current_line = 1;
    let mut records = Vec::with_capacity(plans.len());
    for plan in plans {
        let Segment { start, end, owner } = plan.segment;
        let (kind, name, qualified, occurrence) = match owner {
            Some(index) => {
                let (kind, name, qualified, occurrence) = &symbol_data[index];
                (
                    *kind,
                    Some(name.clone()),
                    Some(qualified.clone()),
                    *occurrence,
                )
            }
            None => (ChunkKind::File, None, None, 0),
        };
        let content = redacted
            .content
            .get(start..end)
            .ok_or(IndexError::RedactionInvariant)?
            .to_owned();
        let redaction_count = sensitive_starts.partition_point(|&position| position < end)
            - sensitive_ends.partition_point(|&position| position <= start);
        let start_line = current_line;
        current_line += source.as_bytes()[start..end]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        records.push(IndexRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            engine_version: ENGINE_VERSION.to_owned(),
            repository_id: repository_id.map(str::to_owned),
            commit_sha: commit_sha.map(str::to_ascii_lowercase),
            relative_path: relative_path.to_owned(),
            language,
            chunk_id: identity(
                repository_id,
                relative_path,
                kind,
                qualified.as_deref(),
                occurrence,
                plan.part,
            ),
            content_hash: blake3::hash(content.as_bytes()).to_hex().to_string(),
            symbol_kind: kind,
            symbol_name: name,
            qualified_name: qualified,
            start_line,
            end_line: current_line,
            start_byte: start,
            end_byte: end,
            content,
            redacted: redaction_count > 0,
            redaction_count,
            part_index: plan.part,
        });
    }
    Ok(FileIndex {
        records,
        diagnostics,
        indexed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn chunks(language: Language, source: &str, bytes: usize) -> FileIndex {
        chunk_source(
            language,
            "source",
            source,
            Some("example/project"),
            None,
            100,
            &IndexOptions {
                max_chunk_bytes: bytes,
            },
        )
        .unwrap()
    }

    fn assert_partition(source: &str, result: &FileIndex, bytes: usize) {
        let expected = redact_secrets(source).content;
        let mut offset = 0;
        let mut reconstructed = String::new();
        for record in &result.records {
            assert_eq!(record.start_byte, offset);
            assert!(record.end_byte > record.start_byte);
            assert!(record.content.len() <= bytes);
            assert!(source.is_char_boundary(record.start_byte));
            assert!(source.is_char_boundary(record.end_byte));
            assert_eq!(record.content.len(), record.end_byte - record.start_byte);
            assert_eq!(
                record.content_hash,
                blake3::hash(record.content.as_bytes()).to_hex().as_str()
            );
            reconstructed.push_str(&record.content);
            offset = record.end_byte;
        }
        assert_eq!(offset, source.len());
        assert_eq!(reconstructed, expected);
    }

    #[test]
    fn nested_symbols_and_gaps_form_exact_partition() {
        let source = "# header\nclass Greeter:\n    def hello(self):\n        return 'привет'\n\n    def bye(self):\n        return 'bye'\n\n# footer\n";
        let result = chunks(Language::Python, source, 256);
        assert_partition(source, &result, 256);
        assert!(
            result
                .records
                .iter()
                .any(|record| record.symbol_kind == ChunkKind::Class)
        );
        assert!(
            result
                .records
                .iter()
                .any(|record| record.symbol_kind == ChunkKind::Method)
        );
        assert!(
            result
                .records
                .iter()
                .any(|record| record.symbol_kind == ChunkKind::File)
        );
    }

    #[test]
    fn symbol_identity_survives_offset_and_content_changes() {
        let before = chunks(Language::Python, "def target():\n    return 1\n", 256);
        let after = chunks(
            Language::Python,
            "# inserted header\ndef unrelated():\n    pass\n\ndef target():\n    return 2\n",
            256,
        );
        let first = before
            .records
            .iter()
            .find(|record| record.symbol_name.as_deref() == Some("target"))
            .unwrap();
        let second = after
            .records
            .iter()
            .find(|record| record.symbol_name.as_deref() == Some("target"))
            .unwrap();
        assert_eq!(first.chunk_id, second.chunk_id);
        assert_ne!(first.content_hash, second.content_hash);
        assert_ne!(first.start_byte, second.start_byte);
    }

    #[test]
    fn credentials_are_redacted_before_tiny_chunk_boundaries() {
        let token = format!("ghp_{}", "A7b9".repeat(9));
        let source = format!("# generated test-only credential\nTOKEN = '{token}'\n");
        let result = chunks(Language::Python, &source, 7);
        assert_partition(&source, &result, 7);
        let joined: String = result
            .records
            .iter()
            .map(|record| record.content.as_str())
            .collect();
        assert!(!joined.contains(&token));
        assert!(!joined.contains("A7b9"));
        assert!(
            result
                .records
                .iter()
                .filter(|record| record.redacted)
                .count()
                > 1
        );
        assert!(
            !serde_json::to_string(&result.records)
                .unwrap()
                .contains(&token)
        );
    }

    #[test]
    fn multiline_private_key_and_metadata_never_reveal_secret() {
        let source = "# FAKE test key, not valid cryptographic material\nKEY = '''-----BEGIN PRIVATE KEY-----\nVEhJU19JU19OT1RfQV9SRUFMX0tFWQ==\n-----END PRIVATE KEY-----'''\n";
        let result = chunks(Language::Python, source, 16);
        assert_partition(source, &result, 16);
        let output = serde_json::to_string(&result.records).unwrap();
        assert!(!output.contains("VEhJU19JU19OT1RfQV9SRUFMX0tFWQ"));
        let token_name = format!("ghp_{}", "A7b9".repeat(9));
        let function = format!("def {token_name}():\n    pass\n");
        let result = chunks(Language::Python, &function, 256);
        assert!(
            !serde_json::to_string(&result.records)
                .unwrap()
                .contains(&token_name)
        );
    }

    #[test]
    fn fallback_prefers_line_boundaries_and_handles_unbroken_unicode() {
        let source = "first\nsecond\nthird\n";
        let result = chunks(Language::Markdown, source, 10);
        assert_eq!(result.records[0].content, "first\n");
        assert_partition(source, &result, 10);
        let source = "🚀語é".repeat(50);
        assert_partition(&source, &chunks(Language::Unknown, &source, 7), 7);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn arbitrary_utf8_has_bounded_gapless_chunks(source in ".{0,1024}", max_bytes in 4usize..256) {
            let result = chunks(Language::Unknown, &source, max_bytes);
            assert_partition(&source, &result, max_bytes);
        }

        #[test]
        fn unrelated_prefix_preserves_named_symbol_identity(lines in 0usize..80, result_value in 0u32..1_000_000) {
            let baseline = chunks(Language::JavaScript, "function stableName() { return 0; }\n", 256);
            let prefix = "// preceding line\n".repeat(lines);
            let edited = chunks(Language::JavaScript, &format!("{prefix}function stableName() {{ return {result_value}; }}\n"), 256);
            let before = baseline.records.iter().find(|record| record.symbol_name.as_deref() == Some("stableName")).unwrap();
            let after = edited.records.iter().find(|record| record.symbol_name.as_deref() == Some("stableName")).unwrap();
            prop_assert_eq!(&before.chunk_id, &after.chunk_id);
        }
    }
}
