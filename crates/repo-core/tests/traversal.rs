use std::fs;
use std::path::Path;

use repo_core::{
    Language, Repository, ScanOptions, TrackingState, classify, normalize_relative_path,
};
use tempfile::tempdir;

fn put(root: &Path, name: &str, contents: impl AsRef<[u8]>) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn names(repository: &Repository) -> Vec<&str> {
    repository
        .files
        .iter()
        .map(|f| f.relative_path.as_str())
        .collect()
}

fn inert_git(root: &Path) {
    put(root, ".git/HEAD", "ref: refs/heads/main\n");
    put(
        root,
        ".git/refs/heads/main",
        "0123456789abcdef0123456789abcdef01234567\n",
    );
}

fn index(paths: &[&str]) -> Vec<u8> {
    let mut bytes = b"DIRC".to_vec();
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&(paths.len() as u32).to_be_bytes());
    for path in paths {
        let start = bytes.len();
        bytes.extend_from_slice(&[0; 60]);
        bytes.extend_from_slice(&(path.len() as u16).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        while !(bytes.len() - start).is_multiple_of(8) {
            bytes.push(0);
        }
    }
    bytes.extend_from_slice(&[0; 20]);
    bytes
}

#[test]
fn obeys_scoped_ignore_rules_and_distinguishes_policies() {
    let temp = tempdir().unwrap();
    put(temp.path(), ".gitignore", "*.tmp\n!keep.tmp\nignored/\n");
    put(temp.path(), "z.py", "print('last')\n");
    put(temp.path(), "a.py", "print('first')\n");
    put(temp.path(), "skip.tmp", "ignored");
    put(temp.path(), "keep.tmp", "kept");
    put(temp.path(), "ignored/visible.py", "ignored");
    put(temp.path(), "node_modules/module.js", "engine");
    put(temp.path(), "private/credentials.txt", "user");
    put(temp.path(), "nested/.gitignore", "local.py\n!allow.tmp\n");
    put(temp.path(), "nested/local.py", "ignored");
    put(temp.path(), "nested/allow.tmp", "kept");
    let options = ScanOptions {
        excludes: vec!["private/**".into()],
        ..Default::default()
    };
    let repo = Repository::open(temp.path(), options).unwrap();
    assert_eq!(
        names(&repo),
        [
            ".gitignore",
            "a.py",
            "keep.tmp",
            "nested/.gitignore",
            "nested/allow.tmp",
            "z.py"
        ]
    );
    for code in ["ignored_vcs", "ignored_engine", "excluded_user"] {
        assert!(repo.diagnostics.iter().any(|d| d.code == code), "{code}");
    }
    assert!(
        repo.files
            .iter()
            .all(|f| f.tracking == TrackingState::Unknown)
    );
}

#[test]
fn selection_fingerprint_is_portable_and_independent_of_source_and_git_identity() {
    let first = tempdir().unwrap();
    let second = tempdir().unwrap();
    let entries = [
        (".gitignore", "*.tmp\n"),
        ("src/.gitignore", "*.log\n"),
        (".git/info/exclude", "*.local\n"),
        ("src/main.py", "print('fixture')\n"),
    ];
    inert_git(first.path());
    inert_git(second.path());
    for (path, contents) in entries {
        put(first.path(), path, contents);
    }
    for (path, contents) in entries.into_iter().rev() {
        put(second.path(), path, contents);
    }
    let scan = |root: &Path, threads| {
        Repository::open(
            root,
            ScanOptions {
                threads,
                ..Default::default()
            },
        )
        .unwrap()
        .selection_fingerprint
    };
    let expected = scan(first.path(), 1);
    assert!(expected == scan(second.path(), 4));
    assert!(expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()));

    put(second.path(), "src/main.py", "print('changed fixture')\n");
    put(second.path(), "new.py", "pass\n");
    put(
        second.path(),
        ".git/index",
        index(&["src/main.py", "new.py"]),
    );
    put(
        second.path(),
        ".git/refs/heads/main",
        "abcdef0123456789abcdef0123456789abcdef0123\n",
    );
    assert!(expected == scan(second.path(), 2));
}

#[test]
fn selection_fingerprint_tracks_changed_removed_and_empty_ignore_scopes() {
    let temp = tempdir().unwrap();
    inert_git(temp.path());
    let scan = || {
        Repository::open(temp.path(), ScanOptions::default())
            .unwrap()
            .selection_fingerprint
    };
    let absent = scan();
    for path in [".gitignore", "nested/.gitignore", ".git/info/exclude"] {
        put(temp.path(), path, "");
        let empty_scope = scan();
        assert!(
            empty_scope != absent,
            "An empty scope must differ from absence"
        );
        put(temp.path(), path, "*.tmp\n");
        let original = scan();
        assert!(original != empty_scope);
        put(temp.path(), path, "*.log\n");
        assert!(
            scan() != original,
            "Changed ignore bytes require a new identity"
        );
        fs::remove_file(temp.path().join(path)).unwrap();
        assert!(
            scan() == absent,
            "Removed metadata must leave no retained scope"
        );
    }

    put(temp.path(), "nested/.gitignore", "*.tmp\n");
    let nested = scan();
    fs::remove_file(temp.path().join("nested/.gitignore")).unwrap();
    put(temp.path(), "other/.gitignore", "*.tmp\n");
    assert!(
        scan() != nested,
        "Identical rules at different scopes are distinct"
    );
}

#[test]
fn selection_fingerprint_retains_metadata_failures_without_exposing_rules() {
    let temp = tempdir().unwrap();
    inert_git(temp.path());
    let scan = || Repository::open(temp.path(), ScanOptions::default()).unwrap();
    let absent = scan().selection_fingerprint;
    for path in [".gitignore", "nested/.gitignore", ".git/info/exclude"] {
        put(temp.path(), path, [0xff]);
        let invalid = scan();
        assert!(invalid.selection_fingerprint != absent);
        assert!(invalid.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "ignore_invalid" && diagnostic.relative_path.as_deref() == Some(path)
        }));
        put(temp.path(), path, [0xfe]);
        assert!(scan().selection_fingerprint != invalid.selection_fingerprint);

        put(temp.path(), path, "x".repeat(1025));
        let limited = scan();
        assert!(limited.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "ignore_limit" && diagnostic.relative_path.as_deref() == Some(path)
        }));
        assert!(limited.selection_fingerprint != absent);

        put(temp.path(), path, "x".repeat(65 * 1024));
        let unread = scan();
        let expected_code = if path == ".git/info/exclude" {
            "git_exclude_unavailable"
        } else {
            "file_too_large"
        };
        assert!(unread.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == expected_code && diagnostic.relative_path.as_deref() == Some(path)
        }));
        assert!(unread.selection_fingerprint == absent);
        fs::remove_file(temp.path().join(path)).unwrap();
    }
}

#[test]
fn reads_inert_git_tracking_without_interpreting_config() {
    let temp = tempdir().unwrap();
    inert_git(temp.path());
    put(
        temp.path(),
        ".git/config",
        "[include]\npath = /outside/config\n[core]\nfsmonitor = malicious-command\n",
    );
    put(
        temp.path(),
        ".git/index",
        index(&[".env", "src/tracked.py"]),
    );
    put(temp.path(), ".git/info/exclude", "info-excluded.txt\n");
    put(temp.path(), ".gitignore", ".env*\nsrc/\n!src/extra.py\n");
    put(temp.path(), ".env", "NOT_A_SECRET=fixture\n");
    put(temp.path(), ".env.untracked", "not-indexed\n");
    put(temp.path(), "src/tracked.py", "print('tracked')\n");
    put(temp.path(), "src/untracked.py", "print('ignored')\n");
    put(
        temp.path(),
        "src/extra.py",
        "print('parent remains ignored')\n",
    );
    put(temp.path(), "info-excluded.txt", "ignored\n");
    put(temp.path(), "plain.txt", "untracked\n");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert!(repo.metadata.git.is_repository);
    assert_eq!(repo.metadata.git.branch.as_deref(), Some("main"));
    assert_eq!(
        repo.metadata.git.commit_sha.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert_eq!(
        names(&repo),
        [".env", ".gitignore", "plain.txt", "src/tracked.py"]
    );
    assert_eq!(
        repo.files
            .iter()
            .find(|f| f.relative_path == ".env")
            .unwrap()
            .tracking,
        TrackingState::Tracked
    );
    assert_eq!(
        repo.files
            .iter()
            .find(|f| f.relative_path == "plain.txt")
            .unwrap()
            .tracking,
        TrackingState::Untracked
    );
}

#[test]
fn unknown_git_formats_and_worktrees_do_not_invent_tracking() {
    let temp = tempdir().unwrap();
    inert_git(temp.path());
    let mut invalid_index = index(&["a.py"]);
    invalid_index[4..8].copy_from_slice(&4_u32.to_be_bytes());
    put(temp.path(), ".git/index", invalid_index);
    put(temp.path(), "a.py", "pass\n");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert_eq!(repo.files[0].tracking, TrackingState::Unknown);
    assert!(
        repo.diagnostics
            .iter()
            .any(|d| d.code == "git_index_unsupported")
    );
    fs::remove_dir_all(temp.path().join(".git")).unwrap();
    put(temp.path(), ".git", "gitdir: /outside/private-git\n");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert!(!repo.metadata.git.is_repository);
    assert!(repo.metadata.git.commit_sha.is_none());
    assert!(
        repo.diagnostics
            .iter()
            .any(|d| d.code == "git_worktree_unsupported")
    );
    let portable = serde_json::to_string(&repo.metadata).unwrap();
    assert!(!portable.contains("outside"));
}

#[test]
fn bounds_files_size_depth_and_total_reads_without_absolute_paths() {
    let temp = tempdir().unwrap();
    put(temp.path(), "a.txt", "1234");
    put(temp.path(), "b.txt", "5678");
    put(temp.path(), "c.txt", "9012");
    put(temp.path(), "large.bin", [1; 32]);
    put(temp.path(), "nested/deeper/deep.py", "pass");
    let options = ScanOptions {
        max_file_size: 8,
        max_total_bytes: 8,
        max_depth: 1,
        ..Default::default()
    };
    let repo = Repository::open(temp.path(), options).unwrap();
    assert_eq!(names(&repo), ["a.txt", "b.txt"]);
    for code in ["max_total_bytes", "file_too_large", "max_depth"] {
        assert!(repo.diagnostics.iter().any(|d| d.code == code), "{code}");
    }
    assert!(
        !serde_json::to_string(&repo.diagnostics)
            .unwrap()
            .contains(temp.path().to_str().unwrap())
    );
    let options = ScanOptions {
        max_files: 1,
        ..Default::default()
    };
    let repo = Repository::open(temp.path(), options).unwrap();
    assert_eq!(names(&repo), ["a.txt"]);
    assert!(repo.diagnostics.iter().any(|d| d.code == "max_files"));
}

#[test]
fn reread_detects_content_replacement() {
    let temp = tempdir().unwrap();
    put(temp.path(), "source.py", "print('one')\n");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert_eq!(repo.read_text(&repo.files[0]).unwrap(), "print('one')\n");
    put(temp.path(), "source.py", "print('two')\n");
    assert_eq!(
        repo.read_text(&repo.files[0]).unwrap_err().code,
        "file_changed"
    );
}

#[test]
fn reread_rejects_forged_paths_without_echoing_them() {
    let temp = tempdir().unwrap();
    put(temp.path(), "a.py", "pass\n");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    for path in [
        "/outside/private",
        "../escape",
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let mut forged = repo.files[0].clone();
        forged.relative_path = path.into();
        let diagnostic = repo.read_text(&forged).unwrap_err();
        assert_eq!(diagnostic.code, "path_rejected");
        assert!(diagnostic.relative_path.is_none());
        assert!(!diagnostic.message.contains(path));
    }
}

#[test]
fn invalid_utf8_is_inventoried_without_silent_text_skips() {
    let temp = tempdir().unwrap();
    put(temp.path(), "invalid.py", [0xff, 0xfe]);
    put(temp.path(), "binary.dat", [0, 1, 2]);
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert_eq!(repo.files.len(), 2);
    assert!(
        repo.diagnostics
            .iter()
            .any(|d| d.code == "unsupported_encoding")
    );
    assert!(repo.diagnostics.iter().any(|d| d.code == "binary_file"));
    assert!(repo.files.iter().all(|f| repo.read_text(f).is_err()));
}

#[test]
fn ignores_external_parent_rules_and_limits_invalid_ignore_metadata() {
    let temp = tempdir().unwrap();
    put(temp.path(), ".gitignore", "*\n");
    put(temp.path(), "repo/.gitignore", "x".repeat(65 * 1024));
    put(temp.path(), "repo/visible.py", "pass\n");
    let repo = Repository::open(temp.path().join("repo"), ScanOptions::default()).unwrap();
    assert!(names(&repo).contains(&"visible.py"));
    assert!(repo.diagnostics.iter().any(|d| d.code == "file_too_large"));
}

#[test]
fn entry_exhaustion_skips_the_whole_unsorted_directory() {
    let temp = tempdir().unwrap();
    for i in 0..1025 {
        put(temp.path(), &format!("file-{i:04}"), "");
    }
    let options = ScanOptions {
        max_files: 1,
        ..Default::default()
    };
    let repo = Repository::open(temp.path(), options).unwrap();
    assert!(repo.files.is_empty());
    assert!(repo.diagnostics.iter().any(|d| d.code == "max_entries"));
}

#[test]
fn classification_and_path_model_are_portable() {
    assert_eq!(
        normalize_relative_path(Path::new("./a/./b.py")).unwrap(),
        "a/b.py"
    );
    for bad in [
        "",
        ".",
        "..",
        "a/../b",
        "/root/file",
        "a\\b",
        "C:/file",
        "control\u{1b}.py",
        "newline\n.py",
        "bidi\u{202e}.py",
        "isolate\u{2066}.py",
        "line\u{2028}separator.py",
        "paragraph\u{2029}separator.py",
    ] {
        assert!(normalize_relative_path(Path::new(bad)).is_err(), "{bad}");
    }
    assert!(
        normalize_relative_path(Path::new(&format!(
            "{}.py",
            "ghp_".to_owned() + &"A".repeat(36)
        )))
        .is_err()
    );
    let unicode = classify("a.py", "αβ\r\nγ\n".as_bytes());
    assert_eq!(unicode.language, Language::Python);
    assert_eq!(unicode.line_count, Some(2));
    assert_eq!(classify("a.txt", b"").line_count, Some(0));
    assert_eq!(classify("a.txt", b"a\nb").line_count, Some(2));
    assert!(classify("min.min.js", b"x").generated);
    assert!(classify("lock/Cargo.lock", b"x").generated);
    for bytes in [b"a\0b".as_slice(), &[255, 254]] {
        let classification = classify("a.py", bytes);
        assert!(classification.binary);
        assert_eq!(classification.line_count, None);
    }
    assert_eq!(
        serde_json::to_string(&Language::TypeScript).unwrap(),
        "\"typescript\""
    );
}

#[test]
fn invalid_configuration_and_secret_identifiers_are_rejected_safely() {
    let temp = tempdir().unwrap();
    let options = ScanOptions {
        threads: 0,
        ..Default::default()
    };
    assert!(Repository::open(temp.path(), options).is_err());
    let token = format!("ghp_{}", "A".repeat(36));
    let options = ScanOptions {
        repository_id: Some(format!("owner/{token}")),
        ..Default::default()
    };
    let error = Repository::open(temp.path(), options)
        .unwrap_err()
        .to_string();
    assert!(!error.contains(&token));
    put(temp.path(), &token, "secret filename");
    let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    assert!(repo.files.is_empty());
    assert!(
        !serde_json::to_string(&repo.diagnostics)
            .unwrap()
            .contains(&token)
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    #[test]
    fn root_and_descendant_links_never_escape() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("repo");
        fs::create_dir(&root).unwrap();
        put(parent.path(), "outside.py", "outside confidential value\n");
        symlink(parent.path().join("outside.py"), root.join("escape.py")).unwrap();
        symlink(parent.path(), root.join("external-dir")).unwrap();
        symlink(parent.path().join("outside.py"), root.join(".gitignore")).unwrap();
        symlink(&root, parent.path().join("alias")).unwrap();
        let repo = Repository::open(&root, ScanOptions::default()).unwrap();
        assert!(repo.files.is_empty());
        assert!(repo.diagnostics.iter().any(|d| d.code == "symlink_skipped"));
        assert!(Repository::open(parent.path().join("alias"), ScanOptions::default()).is_err());
        assert!(Repository::open(parent.path().join("alias/"), ScanOptions::default()).is_err());
    }

    #[test]
    fn reread_refuses_an_intermediate_directory_symlink_swap() {
        let parent = tempdir().unwrap();
        put(parent.path(), "repo/sub/a.py", "same bytes\n");
        put(parent.path(), "outside/a.py", "same bytes\n");
        let repo = Repository::open(parent.path().join("repo"), ScanOptions::default()).unwrap();
        fs::rename(
            parent.path().join("repo/sub"),
            parent.path().join("repo/old"),
        )
        .unwrap();
        symlink(
            parent.path().join("outside"),
            parent.path().join("repo/sub"),
        )
        .unwrap();
        assert!(repo.read_text(&repo.files[0]).is_err());
    }

    #[test]
    fn special_files_are_skipped_without_reading() {
        let temp = tempdir().unwrap();
        let _socket = UnixListener::bind(temp.path().join("socket")).unwrap();
        let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
        assert!(repo.files.is_empty());
        assert!(
            repo.diagnostics
                .iter()
                .any(|d| d.code == "special_file_skipped"
                    && d.relative_path.as_deref() == Some("socket"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_content_and_ignore_files_are_skipped_without_reading() {
        let temp = tempdir().unwrap();
        for name in ["fifo", ".gitignore"] {
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                temp.path().join(name),
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
        }
        let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
        assert!(repo.files.is_empty());
        for name in ["fifo", ".gitignore"] {
            assert!(
                repo.diagnostics
                    .iter()
                    .any(|d| d.code == "special_file_skipped"
                        && d.relative_path.as_deref() == Some(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn non_utf8_path_validation_never_uses_lossy_conversion() {
        for byte in [254, 255] {
            let path = OsString::from_vec(vec![b'x', byte]);
            assert!(normalize_relative_path(Path::new(&path)).is_err());
        }
    }

    // macOS APFS rejects these filenames at creation; Linux permits them and
    // exercises the actual walker, while the validator test above runs on both.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_are_skipped_without_collision() {
        let temp = tempdir().unwrap();
        for byte in [254, 255] {
            fs::write(
                temp.path().join(OsString::from_vec(vec![b'x', byte])),
                "unread",
            )
            .unwrap();
        }
        let repo = Repository::open(temp.path(), ScanOptions::default()).unwrap();
        assert!(repo.files.is_empty());
        assert_eq!(
            repo.diagnostics
                .iter()
                .filter(|d| d.code == "non_utf8_path")
                .count(),
            2
        );
    }
}
