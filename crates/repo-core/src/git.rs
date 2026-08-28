//! A deliberately small, inert Git reader. It never reads config, includes,
//! hooks, object filters, linked-worktree targets, alternates, or global files.
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;

use crate::traversal::{ReadFailure, read_regular, read_relative};
use crate::{Diagnostic, GitMetadata, normalize_relative_path};

pub(crate) struct GitState {
    pub metadata: GitMetadata,
    pub tracked: Option<BTreeSet<String>>,
    pub exclude: Option<String>,
}

impl GitState {
    pub fn tracked_or_parent(&self, path: &str, is_dir: bool) -> bool {
        self.tracked.as_ref().is_some_and(|tracked| {
            if !is_dir {
                return tracked.contains(path);
            }
            let prefix = format!("{path}/");
            tracked
                .range(prefix.clone()..)
                .next()
                .is_some_and(|first| first.starts_with(&prefix))
        })
    }
}

pub(crate) fn inspect(root: &Dir, diagnostics: &mut Vec<Diagnostic>) -> GitState {
    let mut result = GitState {
        metadata: GitMetadata::default(),
        tracked: None,
        exclude: None,
    };
    let git_meta = match root.symlink_metadata(".git") {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return result,
        Err(_) => {
            diagnostics.push(Diagnostic::new(
                "git_metadata_unavailable",
                None,
                "Git metadata could not be inspected",
            ));
            return result;
        }
    };
    if !git_meta.is_dir() || git_meta.is_symlink() {
        diagnostics.push(Diagnostic::new(
            "git_worktree_unsupported",
            None,
            "Git files, symbolic links and linked worktree pointers are not followed",
        ));
        return result;
    }
    let git = match root.open_dir_nofollow(".git") {
        Ok(dir) => dir,
        Err(_) => {
            diagnostics.push(Diagnostic::new(
                "git_metadata_unavailable",
                None,
                "Git directory could not be safely opened",
            ));
            return result;
        }
    };
    let head = read_regular(&git, OsStr::new("HEAD"), 1024)
        .ok()
        .and_then(|v| String::from_utf8(v).ok());
    match head.as_deref().map(str::trim) {
        Some(head) if is_oid(head) => {
            result.metadata.is_repository = true;
            result.metadata.commit_sha = Some(head.to_ascii_lowercase());
        }
        Some(head) if head.starts_with("ref: ") && valid_ref(&head[5..]) => {
            result.metadata.is_repository = true;
            let reference = &head[5..];
            result.metadata.branch = reference.strip_prefix("refs/heads/").map(str::to_owned);
            match read_relative(&git, reference, 1024) {
                Ok(bytes) => {
                    if let Ok(value) = std::str::from_utf8(&bytes)
                        && is_oid(value.trim())
                    {
                        result.metadata.commit_sha = Some(value.trim().to_ascii_lowercase());
                    } else {
                        diagnostics.push(Diagnostic::new(
                            "git_ref_invalid",
                            None,
                            "Git reference did not contain a valid object identifier",
                        ));
                    }
                }
                Err(ReadFailure::NotFound) => {
                    if let Ok(packed) = read_regular(&git, OsStr::new("packed-refs"), 1024 * 1024) {
                        result.metadata.commit_sha = packed_reference(&packed, reference);
                    }
                    // An absent branch is valid for an unborn repository. Do not
                    // invent a SHA or report a failed scan for that common case.
                }
                Err(_) => diagnostics.push(Diagnostic::new(
                    "git_ref_unavailable",
                    None,
                    "Git reference could not be read without following links",
                )),
            }
        }
        _ => {
            diagnostics.push(Diagnostic::new(
                "git_head_invalid",
                None,
                "Git HEAD is missing, unsupported or invalid",
            ));
            return result;
        }
    }
    match read_regular(&git, OsStr::new("index"), 16 * 1024 * 1024) {
        Ok(bytes) => match parse_index(&bytes) {
            Some(tracked) => result.tracked = Some(tracked),
            None => diagnostics.push(Diagnostic::new(
                "git_index_unsupported",
                None,
                "Git tracking is unknown: index is malformed or uses an unsupported format",
            )),
        },
        Err(ReadFailure::NotFound) => result.tracked = Some(BTreeSet::new()),
        Err(_) => diagnostics.push(Diagnostic::new(
            "git_index_unavailable",
            None,
            "Git tracking is unknown: index exceeds bounds or could not be safely read",
        )),
    }
    match read_relative(&git, "info/exclude", 64 * 1024) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(value) => result.exclude = Some(value),
            Err(_) => diagnostics.push(Diagnostic::new(
                "ignore_invalid",
                Some(".git/info/exclude"),
                "Git exclude rules are not UTF-8",
            )),
        },
        Err(ReadFailure::NotFound) => {}
        Err(_) => diagnostics.push(Diagnostic::new(
            "git_exclude_unavailable",
            Some(".git/info/exclude"),
            "Git exclude rules exceed bounds or could not be safely read",
        )),
    }
    result
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value.bytes().any(|b| b != b'0')
}

fn valid_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() <= 1024
        && normalize_relative_path(Path::new(value)).is_ok_and(|n| n == value)
        && !value.contains("..")
        && !value.contains("@{")
        && !value
            .bytes()
            .any(|b| b <= b' ' || b == 127 || b"~^:?*[\\".contains(&b))
        && value
            .split('/')
            .all(|p| !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock"))
}

fn packed_reference(bytes: &[u8], reference: &str) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines().take(16_384) {
        if line.starts_with(['#', '^']) {
            continue;
        }
        let Some((oid, name)) = line.split_once(' ') else {
            continue;
        };
        if name == reference && is_oid(oid) {
            return Some(oid.to_ascii_lowercase());
        }
    }
    None
}

/// Read ordinary SHA-1 index v2/v3 entries only. The index is untrusted advisory
/// working-tree metadata, not proof of a commit or verified object ownership.
/// Required extensions (split/sparse), v4 and SHA-256 layouts fail closed.
fn parse_index(bytes: &[u8]) -> Option<BTreeSet<String>> {
    if bytes.len() < 32 || bytes.get(..4)? != b"DIRC" {
        return None;
    }
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_be_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let version = u32_at(4)?;
    if !matches!(version, 2 | 3) {
        return None;
    }
    let count = u32_at(8)? as usize;
    if count > 1_000_000 || count > (bytes.len() - 32) / 64 {
        return None;
    }
    let data_end = bytes.len() - 20;
    let mut offset: usize = 12;
    let mut paths = BTreeSet::new();
    for _ in 0..count {
        let start = offset;
        let mode = u32_at(offset + 24)?;
        // Sparse directory entries need expansion against Git objects. This
        // implementation deliberately does not interpret those objects.
        if mode & 0o170000 == 0o040000 {
            return None;
        }
        let flags = u16::from_be_bytes(bytes.get(offset + 60..offset + 62)?.try_into().ok()?);
        offset += 62;
        if flags & 0x4000 != 0 {
            if version < 3 {
                return None;
            }
            let extra = u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
            if extra & !0x6000 != 0 {
                return None;
            }
            offset += 2;
        }
        let max_end = offset.checked_add(4097)?.min(data_end);
        let path_len = bytes.get(offset..max_end)?.iter().position(|&b| b == 0)?;
        if flags & 0x0fff != 0x0fff && usize::from(flags & 0x0fff) != path_len {
            return None;
        }
        let path = std::str::from_utf8(bytes.get(offset..offset + path_len)?).ok()?;
        if path == ".git"
            || path.starts_with(".git/")
            || normalize_relative_path(Path::new(path)).ok()? != path
        {
            return None;
        }
        paths.insert(path.to_owned());
        let unpadded_end = offset + path_len + 1;
        offset = start.checked_add((unpadded_end - start).checked_add(7)? & !7)?;
        if offset > data_end || bytes.get(unpadded_end..offset)?.iter().any(|&b| b != 0) {
            return None;
        }
    }
    while offset < data_end {
        let header = bytes.get(offset..offset + 8)?;
        // Lowercase first-byte extensions are mandatory; unknown semantics must
        // not be misreported as a complete inventory of tracked files.
        if !header[0].is_ascii_uppercase() || !header[..4].iter().all(u8::is_ascii_alphanumeric) {
            return None;
        }
        let length = u32::from_be_bytes(header[4..8].try_into().ok()?) as usize;
        offset = offset.checked_add(8)?.checked_add(length)?;
        if offset > data_end {
            return None;
        }
    }
    (offset == data_end).then_some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(paths: &[&str]) -> Vec<u8> {
        let mut data = b"DIRC".to_vec();
        data.extend_from_slice(&2_u32.to_be_bytes());
        data.extend_from_slice(&(paths.len() as u32).to_be_bytes());
        for path in paths {
            let start = data.len();
            data.extend_from_slice(&[0; 60]);
            data.extend_from_slice(&(path.len() as u16).to_be_bytes());
            data.extend_from_slice(path.as_bytes());
            data.push(0);
            while !(data.len() - start).is_multiple_of(8) {
                data.push(0);
            }
        }
        data.extend_from_slice(&[0; 20]);
        data
    }

    #[test]
    fn recognizes_basic_index_and_rejects_required_extensions() {
        let mut data = index(&[".env", "src/main.py"]);
        assert_eq!(parse_index(&data).unwrap().len(), 2);
        data.truncate(data.len() - 20);
        data.extend_from_slice(b"link\0\0\0\0");
        data.extend_from_slice(&[0; 20]);
        assert!(parse_index(&data).is_none());
        let mut sparse = index(&["directory"]);
        sparse[36..40].copy_from_slice(&0o040000_u32.to_be_bytes());
        assert!(parse_index(&sparse).is_none());
    }

    #[test]
    fn invalid_paths_and_truncation_never_become_tracked() {
        for path in ["../outside", "/absolute", "a\\b", ".git/config", "a/../b"] {
            assert!(parse_index(&index(&[path])).is_none(), "{path}");
        }
        let data = index(&["safe.py"]);
        for end in 0..data.len() {
            assert!(parse_index(&data[..end]).is_none());
        }
    }

    #[test]
    fn ref_validation_blocks_escape_and_controls() {
        assert!(valid_ref("refs/heads/feature/test"));
        for value in [
            "refs/../config",
            "refs/heads/x\n",
            "refs/heads/.hidden",
            "refs/heads/a.lock",
            "refs//heads/x",
            "/etc/passwd",
        ] {
            assert!(!valid_ref(value));
        }
    }
}
