use std::ffi::OsStr;
use std::io::Read;
use std::path::{Component, Path};
use std::sync::Arc;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::git::{self, GitState};
use crate::{
    CoreError, Diagnostic, FileRecord, MAX_METADATA_BYTES, MIN_METADATA_BYTES, RepositoryMetadata,
    ScanOptions, TrackingState, classify, content_hash, normalize_relative_path,
};

const MAX_DIAGNOSTICS: usize = 1024;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_IGNORE_BYTES: usize = 1024 * 1024;
const MAX_IGNORE_PATTERNS: usize = 8192;
// These deterministic charges are conservative retention estimates, not RSS
// measurements. Variable-width strings are charged separately at their byte length.
const FILE_RECORD_METADATA_OVERHEAD: usize = 256;
const DIAGNOSTIC_METADATA_OVERHEAD: usize = 192;
const CALLER_CONFIGURATION_METADATA_OVERHEAD: usize = 64;
const CALLER_EXCLUDE_METADATA_OVERHEAD: usize = 128;
const CALLER_REPOSITORY_ID_METADATA_OVERHEAD: usize = 64;
const IGNORE_FINGERPRINT_METADATA_OVERHEAD: usize = 96;
const IGNORE_SCOPE_METADATA_OVERHEAD: usize = 256;
const IGNORE_PATTERN_METADATA_OVERHEAD: usize = 128;
const METADATA_BUDGET_CODE: &str = "metadata_budget";
const METADATA_BUDGET_MESSAGE: &str =
    "Inventory metadata byte budget reached; remaining entries were not admitted";
const METADATA_BUDGET_DIAGNOSTIC_BYTES: usize =
    DIAGNOSTIC_METADATA_OVERHEAD + METADATA_BUDGET_CODE.len() + METADATA_BUDGET_MESSAGE.len();

/// A scan inventory plus an open directory capability. No absolute path is kept
/// in its public model, diagnostics, or Debug representation.
pub struct Repository {
    pub files: Vec<FileRecord>,
    pub diagnostics: Vec<Diagnostic>,
    pub metadata: RepositoryMetadata,
    pub options: ScanOptions,
    /// BLAKE3 identity of the relative paths and bytes of ignore metadata read
    /// during this inventory. Incomplete metadata diagnostics must still be
    /// rejected by callers; this is not a completeness or source-content proof.
    pub selection_fingerprint: String,
    root: Arc<Dir>,
}

impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("files", &self.files)
            .field("diagnostics", &self.diagnostics)
            .field("metadata", &self.metadata)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Repository {
    pub fn open(path: impl AsRef<Path>, options: ScanOptions) -> Result<Self, CoreError> {
        validate_options(&options)?;
        let caller_metadata_bytes = caller_configuration_metadata_bytes(&options);
        if caller_metadata_bytes
            > options
                .max_metadata_bytes
                .saturating_sub(METADATA_BUDGET_DIAGNOSTIC_BYTES)
        {
            return Err(CoreError::Configuration(
                "max_metadata_bytes is too small for retained caller configuration".into(),
            ));
        }
        let root = Arc::new(open_root(path.as_ref())?);
        let mut initial_diagnostics = Vec::new();
        let git_metadata_budget = options
            .max_metadata_bytes
            .saturating_sub(METADATA_BUDGET_DIAGNOSTIC_BYTES)
            .saturating_sub(caller_metadata_bytes);
        let mut git = git::inspect(&root, &mut initial_diagnostics, git_metadata_budget);
        let git_metadata_exhausted = git.metadata_exhausted;
        // The raw exclude bytes are needed only to derive the fingerprint and
        // matcher. Move them out so they are dropped before the repository walk.
        let git_exclude = git.exclude.take();
        let excludes = compile_patterns("", options.excludes.iter().map(String::as_str))
            .map_err(|_| CoreError::Configuration("invalid exclusion pattern".into()))?;
        let mut state = WalkState {
            options: &options,
            git: &git,
            files: Vec::new(),
            diagnostics: Vec::new(),
            excludes,
            entries: 0,
            read_bytes: 0,
            ignore_bytes: 0,
            ignore_patterns: 0,
            ignore_metadata: Vec::new(),
            // Reserve the terminal signal up front so the budget cannot hide
            // its own exhaustion and accidentally look like a complete scan.
            metadata_bytes: METADATA_BUDGET_DIAGNOSTIC_BYTES
                .saturating_add(caller_metadata_bytes)
                .saturating_add(git.retained_metadata_bytes),
            metadata_exhausted: false,
            stopped: false,
            suppressed: 0,
        };
        for diagnostic in initial_diagnostics {
            state.diagnostic(diagnostic);
            if state.stopped {
                break;
            }
        }
        if git_metadata_exhausted {
            state.exhaust_metadata();
        }
        let mut scopes = Vec::new();
        if !state.stopped
            && let Some(exclude) = git_exclude.as_deref()
        {
            state.ignore_bytes += exclude.len();
            state.record_ignore_metadata(".git/info/exclude", exclude);
            match std::str::from_utf8(exclude) {
                Ok(source) => state.add_ignore_scope("", ".git/info/exclude", source, &mut scopes),
                Err(_) => state.diagnostic(Diagnostic::new(
                    "ignore_invalid",
                    Some(".git/info/exclude"),
                    "Git exclude rules are not UTF-8",
                )),
            }
        }
        drop(git_exclude);
        state.walk(&root, "", 0, &mut scopes, false);
        state
            .files
            .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        state.diagnostics.sort_by(|a, b| {
            a.relative_path
                .cmp(&b.relative_path)
                .then(a.code.cmp(&b.code))
        });
        let files = std::mem::take(&mut state.files);
        let diagnostics = std::mem::take(&mut state.diagnostics);
        let selection_fingerprint = selection_fingerprint(&mut state.ignore_metadata);
        drop(state);
        Ok(Self {
            files,
            diagnostics,
            metadata: RepositoryMetadata {
                repository_id: options.repository_id.clone(),
                git: git.metadata,
            },
            options,
            selection_fingerprint,
            root,
        })
    }

    /// Reread through the retained capability, with every component opened without
    /// following links. Content drift is an explicit skip, never silent substitution.
    pub fn read_text(&self, file: &FileRecord) -> Result<String, Diagnostic> {
        if !normalize_relative_path(Path::new(&file.relative_path))
            .is_ok_and(|path| path == file.relative_path)
        {
            return Err(Diagnostic::new(
                "path_rejected",
                None,
                "File path is not a safe portable relative path",
            ));
        }
        if file.binary || !file.utf8 {
            return Err(Diagnostic::new(
                "non_text_file",
                Some(&file.relative_path),
                "Binary or non-UTF-8 content cannot be read as text",
            ));
        }
        let bytes = read_relative(
            &self.root,
            &file.relative_path,
            self.options.max_file_size.min(64 * 1024 * 1024),
        )
        .map_err(|err| err.diagnostic(Some(&file.relative_path)))?;
        if bytes.len() as u64 != file.size_bytes || content_hash(&bytes) != file.content_hash {
            return Err(Diagnostic::new(
                "file_changed",
                Some(&file.relative_path),
                "File content changed since inventory; use an immutable snapshot",
            ));
        }
        String::from_utf8(bytes).map_err(|_| {
            Diagnostic::new(
                "file_changed",
                Some(&file.relative_path),
                "File is no longer valid UTF-8",
            )
        })
    }
}

fn caller_configuration_metadata_bytes(options: &ScanOptions) -> usize {
    let excludes = options.excludes.iter().fold(0usize, |total, pattern| {
        total
            .saturating_add(CALLER_EXCLUDE_METADATA_OVERHEAD)
            // The caller String remains in ScanOptions while the compiled
            // matcher retains its own pattern representation during traversal.
            .saturating_add(pattern.len().saturating_mul(2))
    });
    let repository_id = options.repository_id.as_deref().map_or(0, |id| {
        CALLER_REPOSITORY_ID_METADATA_OVERHEAD.saturating_add(id.len().saturating_mul(2))
    });
    CALLER_CONFIGURATION_METADATA_OVERHEAD
        .saturating_add(excludes)
        .saturating_add(repository_id)
}

fn validate_options(options: &ScanOptions) -> Result<(), CoreError> {
    let invalid = |message: &str| CoreError::Configuration(message.into());
    if !(1..=64 * 1024 * 1024).contains(&options.max_file_size) {
        return Err(invalid("max_file_size must be between 1 byte and 64 MiB"));
    }
    if !(1..=1_000_000).contains(&options.max_files) {
        return Err(invalid("max_files must be between 1 and 1000000"));
    }
    if !(1..=64 * 1024 * 1024 * 1024).contains(&options.max_total_bytes) {
        return Err(invalid("max_total_bytes must be between 1 byte and 64 GiB"));
    }
    if !(MIN_METADATA_BYTES..=MAX_METADATA_BYTES).contains(&options.max_metadata_bytes) {
        return Err(invalid(
            "max_metadata_bytes must be between 1 KiB and 1 GiB",
        ));
    }
    if !(1..=256).contains(&options.max_depth) {
        return Err(invalid("max_depth must be between 1 and 256"));
    }
    if !(1..=10_000).contains(&options.max_parse_millis) {
        return Err(invalid("max_parse_millis must be between 1 and 10000"));
    }
    if !(1..=32).contains(&options.threads) {
        return Err(invalid("threads must be between 1 and 32"));
    }
    if options.excludes.len() > 128
        || options
            .excludes
            .iter()
            .any(|p| p.len() > 1024 || p.contains(['\n', '\r', '\0']))
    {
        return Err(invalid(
            "at most 128 single-line exclusion patterns of at most 1024 bytes are allowed",
        ));
    }
    if options.repository_id.as_ref().is_some_and(|id| {
        id.len() > 1024 || id.chars().any(char::is_control) || !crate::detect_secrets(id).is_empty()
    }) {
        return Err(invalid(
            "repository_id must contain at most 1024 bytes without controls or high-confidence secrets",
        ));
    }
    Ok(())
}

fn open_root(path: &Path) -> Result<Dir, CoreError> {
    let invalid = || {
        CoreError::Input(
            "repository root is unavailable, not a directory, or a symbolic link".into(),
        )
    };
    let absolute = std::path::absolute(path).map_err(|_| invalid())?;
    // Trust the user-selected parent as an ambient starting point; the final
    // repository component itself must not be a symlink, including trailing '/'.
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
        let parent = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|_| invalid())?;
        return parent.open_dir_nofollow(name).map_err(|_| invalid());
    }
    if absolute
        .components()
        .all(|p| matches!(p, Component::RootDir | Component::Prefix(_)))
    {
        return Dir::open_ambient_dir(absolute, ambient_authority()).map_err(|_| invalid());
    }
    Err(invalid())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadFailure {
    NotFound,
    Symlink,
    Special,
    TooLarge,
    Changed,
    InvalidPath,
    Io,
}

impl ReadFailure {
    pub(crate) fn diagnostic(self, path: Option<&str>) -> Diagnostic {
        let (code, message) = match self {
            Self::NotFound | Self::Io => ("file_read_failed", "File could not be safely read"),
            Self::Symlink => ("symlink_skipped", "Symbolic links are not followed"),
            Self::Special => ("special_file_skipped", "Only regular files are read"),
            Self::TooLarge => ("file_too_large", "File exceeds its read budget"),
            Self::Changed => (
                "file_changed",
                "File changed during reading; use an immutable snapshot",
            ),
            Self::InvalidPath => ("path_rejected", "File path is not a portable relative path"),
        };
        Diagnostic::new(code, path, message)
    }
}

fn io_failure(error: std::io::Error) -> ReadFailure {
    if error.kind() == std::io::ErrorKind::NotFound {
        ReadFailure::NotFound
    } else {
        ReadFailure::Io
    }
}

/// Only a single file name is accepted here, so no intermediate symlink can be
/// resolved by open_with. Nonblocking opens prevent a FIFO replacement race.
pub(crate) fn read_regular(dir: &Dir, name: &OsStr, limit: u64) -> Result<Vec<u8>, ReadFailure> {
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(ReadFailure::InvalidPath);
    }
    let before = dir.symlink_metadata(name).map_err(io_failure)?;
    if before.is_symlink() {
        return Err(ReadFailure::Symlink);
    }
    if !before.is_file() {
        return Err(ReadFailure::Special);
    }
    if before.len() > limit {
        return Err(ReadFailure::TooLarge);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let mut file = dir.open_with(name, &options).map_err(io_failure)?;
    let opened = file.metadata().map_err(io_failure)?;
    if !opened.is_file() {
        return Err(ReadFailure::Special);
    }
    if opened.len() > limit {
        return Err(ReadFailure::TooLarge);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_failure)?;
    if bytes.len() as u64 > limit {
        return Err(ReadFailure::TooLarge);
    }
    let after = file.metadata().map_err(io_failure)?;
    if opened.len() != bytes.len() as u64
        || after.len() != opened.len()
        || opened.modified().ok() != after.modified().ok()
    {
        return Err(ReadFailure::Changed);
    }
    Ok(bytes)
}

pub(crate) fn read_relative(root: &Dir, path: &str, limit: u64) -> Result<Vec<u8>, ReadFailure> {
    let normalized =
        normalize_relative_path(Path::new(path)).map_err(|_| ReadFailure::InvalidPath)?;
    if normalized != path {
        return Err(ReadFailure::InvalidPath);
    }
    let mut components = normalized.split('/').peekable();
    let mut nested: Option<Dir> = None;
    while let Some(part) = components.next() {
        let current = nested.as_ref().unwrap_or(root);
        if components.peek().is_none() {
            return read_regular(current, OsStr::new(part), limit);
        }
        nested = Some(current.open_dir_nofollow(part).map_err(io_failure)?);
    }
    Err(ReadFailure::InvalidPath)
}

fn compile_patterns<'a>(root: &str, lines: impl Iterator<Item = &'a str>) -> Result<Gitignore, ()> {
    let mut builder = GitignoreBuilder::new(root);
    for line in lines {
        builder.add_line(None, line).map_err(|_| ())?;
    }
    builder.build().map_err(|_| ())
}

fn selection_fingerprint(records: &mut [(String, blake3::Hash)]) -> String {
    records.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hash = blake3::Hasher::new_derive_key("atlas-engine.repository-selection.v1");
    hash.update(&(records.len() as u64).to_le_bytes());
    for (path, digest) in records {
        hash.update(&(path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        // BLAKE3 digests have a fixed 32-byte width. Paths are length-prefixed
        // and the record count is explicit, so field boundaries are unambiguous.
        hash.update(digest.as_bytes());
    }
    hash.finalize().to_hex().to_string()
}

struct WalkState<'a> {
    options: &'a ScanOptions,
    git: &'a GitState,
    files: Vec<FileRecord>,
    diagnostics: Vec<Diagnostic>,
    excludes: Gitignore,
    entries: usize,
    read_bytes: u64,
    ignore_bytes: usize,
    ignore_patterns: usize,
    ignore_metadata: Vec<(String, blake3::Hash)>,
    metadata_bytes: usize,
    metadata_exhausted: bool,
    stopped: bool,
    suppressed: usize,
}

impl WalkState<'_> {
    fn reserve_metadata(&mut self, bytes: usize) -> bool {
        let available = self
            .options
            .max_metadata_bytes
            .saturating_sub(self.metadata_bytes);
        if bytes > available {
            self.exhaust_metadata();
            false
        } else {
            self.metadata_bytes += bytes;
            true
        }
    }

    fn release_metadata(&mut self, bytes: usize) {
        self.metadata_bytes = self
            .metadata_bytes
            .saturating_sub(bytes)
            .max(METADATA_BUDGET_DIAGNOSTIC_BYTES);
    }

    fn exhaust_metadata(&mut self) {
        if self.metadata_exhausted {
            return;
        }
        self.metadata_exhausted = true;
        self.stopped = true;
        let diagnostic = Diagnostic::new(METADATA_BUDGET_CODE, None, METADATA_BUDGET_MESSAGE);
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(diagnostic);
        } else {
            self.diagnostics[MAX_DIAGNOSTICS - 1] = diagnostic;
        }
    }

    fn record_ignore_metadata(&mut self, path: &str, bytes: &[u8]) {
        // Empty files consume no byte/line budget. Bound their fingerprint
        // retention with the existing metadata pattern limit as well.
        if self.ignore_metadata.len() == MAX_IGNORE_PATTERNS {
            self.diagnostic(Diagnostic::new(
                "ignore_limit",
                Some(path),
                "Ignore metadata scope budget reached; selection identity is incomplete",
            ));
            return;
        }
        let retained_bytes = IGNORE_FINGERPRINT_METADATA_OVERHEAD.saturating_add(path.len());
        if !self.reserve_metadata(retained_bytes) {
            return;
        }
        self.ignore_metadata
            .push((path.to_owned(), blake3::hash(bytes)));
    }

    fn diagnostic(&mut self, diagnostic: Diagnostic) {
        if self.metadata_exhausted {
            return;
        }
        if self.diagnostics.len() < MAX_DIAGNOSTICS - 1 {
            let retained_bytes = diagnostic_metadata_bytes(&diagnostic);
            if self.reserve_metadata(retained_bytes) {
                self.diagnostics.push(diagnostic);
            }
        } else {
            self.suppressed += 1;
            let limited = Diagnostic::new(
                "diagnostic_limit",
                None,
                &format!(
                    "{} additional diagnostics omitted by retention budget",
                    self.suppressed
                ),
            );
            if self.diagnostics.len() == MAX_DIAGNOSTICS - 1 {
                let retained_bytes = diagnostic_metadata_bytes(&limited);
                if self.reserve_metadata(retained_bytes) {
                    self.diagnostics.push(limited)
                }
            } else {
                let old_bytes = diagnostic_metadata_bytes(&self.diagnostics[MAX_DIAGNOSTICS - 1]);
                let new_bytes = diagnostic_metadata_bytes(&limited);
                if new_bytes <= old_bytes {
                    self.release_metadata(old_bytes - new_bytes);
                    self.diagnostics[MAX_DIAGNOSTICS - 1] = limited;
                } else if self.reserve_metadata(new_bytes - old_bytes) {
                    self.diagnostics[MAX_DIAGNOSTICS - 1] = limited;
                }
            }
        }
    }

    fn add_ignore_scope(
        &mut self,
        prefix: &str,
        path: &str,
        source: &str,
        scopes: &mut Vec<Gitignore>,
    ) {
        if self.stopped {
            return;
        }
        let count = source.lines().count();
        if source.len() > MAX_IGNORE_BYTES as usize
            || self.ignore_patterns + count > MAX_IGNORE_PATTERNS
            || source.lines().any(|line| line.len() > 1024)
        {
            self.diagnostic(Diagnostic::new(
                "ignore_limit",
                Some(path),
                "Ignore rules exceed metadata budget; rules were not applied",
            ));
            return;
        }
        match compile_patterns(prefix, source.lines()) {
            Ok(matcher) => {
                self.ignore_patterns += count;
                let retained_bytes = IGNORE_SCOPE_METADATA_OVERHEAD
                    .saturating_add(source.len())
                    .saturating_add(count.saturating_mul(IGNORE_PATTERN_METADATA_OVERHEAD));
                if self.reserve_metadata(retained_bytes) {
                    scopes.push(matcher);
                }
            }
            Err(()) => self.diagnostic(Diagnostic::new(
                "ignore_invalid",
                Some(path),
                "Invalid ignore rules were not applied",
            )),
        }
    }

    fn walk(
        &mut self,
        dir: &Dir,
        prefix: &str,
        depth: usize,
        scopes: &mut Vec<Gitignore>,
        ignored_parent: bool,
    ) {
        if self.stopped {
            return;
        }
        let scope_count = scopes.len();
        let ignore_path = if prefix.is_empty() {
            ".gitignore".to_owned()
        } else {
            format!("{prefix}/.gitignore")
        };
        // Charge attempted ignore reads before UTF-8/grammar validation. Metadata
        // that is malformed or concurrently changed still consumes this budget.
        let ignore_read = match dir.symlink_metadata(".gitignore") {
            Ok(meta) if meta.len() > MAX_IGNORE_BYTES => Err(ReadFailure::TooLarge),
            Ok(meta)
                if meta.len() as usize
                    > MAX_TOTAL_IGNORE_BYTES.saturating_sub(self.ignore_bytes) =>
            {
                self.diagnostic(Diagnostic::new(
                    "ignore_limit",
                    Some(&ignore_path),
                    "Total ignore metadata read budget reached; rules were not read",
                ));
                Err(ReadFailure::NotFound)
            }
            Ok(meta) => {
                self.ignore_bytes += meta.len() as usize;
                read_regular(dir, OsStr::new(".gitignore"), meta.len())
            }
            Err(error) => Err(io_failure(error)),
        };
        match ignore_read {
            Ok(bytes) => {
                self.record_ignore_metadata(&ignore_path, &bytes);
                match std::str::from_utf8(&bytes) {
                    Ok(source) => self.add_ignore_scope(prefix, &ignore_path, source, scopes),
                    Err(_) => self.diagnostic(Diagnostic::new(
                        "ignore_invalid",
                        Some(&ignore_path),
                        "Ignore rules are not valid UTF-8",
                    )),
                }
            }
            Err(ReadFailure::NotFound) => {}
            Err(error) => self.diagnostic(error.diagnostic(Some(&ignore_path))),
        }
        if self.stopped {
            scopes.truncate(scope_count);
            return;
        }
        let entries = match dir.entries() {
            Ok(entries) => entries,
            Err(_) => {
                self.diagnostic(Diagnostic::new(
                    "directory_read_failed",
                    (!prefix.is_empty()).then_some(prefix),
                    "Directory could not be safely enumerated",
                ));
                scopes.truncate(scope_count);
                return;
            }
        };
        let entry_limit = self
            .options
            .max_files
            .saturating_mul(16)
            .clamp(1024, 2_000_000);
        let mut names = Vec::new();
        for entry in entries {
            self.entries += 1;
            if self.entries > entry_limit || names.len() >= MAX_DIRECTORY_ENTRIES {
                self.diagnostic(Diagnostic::new(
                    "max_entries",
                    (!prefix.is_empty()).then_some(prefix),
                    "Directory entry budget reached; incomplete directory was not scanned",
                ));
                self.stopped = true;
                scopes.truncate(scope_count);
                return;
            }
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(_) => self.diagnostic(Diagnostic::new(
                    "directory_entry_failed",
                    (!prefix.is_empty()).then_some(prefix),
                    "Directory entry was unavailable",
                )),
            }
        }
        names.sort();
        for name in names {
            if self.stopped {
                break;
            }
            let Some(name_str) = name.to_str() else {
                self.diagnostic(Diagnostic::new(
                    "non_utf8_path",
                    (!prefix.is_empty()).then_some(prefix),
                    "A non-UTF-8 filename was skipped without lossy conversion",
                ));
                continue;
            };
            let candidate = if prefix.is_empty() {
                name_str.to_owned()
            } else {
                format!("{prefix}/{name_str}")
            };
            let relative = match normalize_relative_path(Path::new(&candidate)) {
                Ok(relative) => relative,
                Err(_) => {
                    self.diagnostic(Diagnostic::new(
                        "path_rejected",
                        None,
                        "A filename outside the portable path model was skipped",
                    ));
                    continue;
                }
            };
            let meta = match dir.symlink_metadata(&name) {
                Ok(meta) => meta,
                Err(_) => {
                    self.diagnostic(Diagnostic::new(
                        "file_metadata_failed",
                        Some(&relative),
                        "File metadata was unavailable",
                    ));
                    continue;
                }
            };
            let is_dir = meta.is_dir();
            if name_str.eq_ignore_ascii_case(".git")
                || (is_dir
                    && matches!(
                        name_str,
                        "node_modules"
                            | "vendor"
                            | "target"
                            | "dist"
                            | "build"
                            | "coverage"
                            | ".cache"
                    ))
            {
                self.diagnostic(Diagnostic::new(
                    "ignored_engine",
                    Some(&relative),
                    "Excluded by engine policy",
                ));
                continue;
            }
            if self.excludes.matched(&relative, is_dir).is_ignore() {
                self.diagnostic(Diagnostic::new(
                    "excluded_user",
                    Some(&relative),
                    "Excluded by caller pattern",
                ));
                continue;
            }
            let vcs_match = scopes.iter().rev().find_map(|matcher| {
                let matched = matcher.matched_path_or_any_parents(&relative, is_dir);
                if matched.is_none() {
                    None
                } else {
                    Some(matched.is_ignore())
                }
            });
            // Git ignore rules do not erase already-tracked evidence, including
            // an accidentally staged .env. Engine/user policy still takes precedence.
            if (ignored_parent || vcs_match == Some(true))
                && !self.git.tracked_or_parent(&relative, is_dir)
            {
                self.diagnostic(Diagnostic::new(
                    "ignored_vcs",
                    Some(&relative),
                    "Excluded by repository ignore rules",
                ));
                continue;
            }
            if meta.is_symlink() {
                self.diagnostic(ReadFailure::Symlink.diagnostic(Some(&relative)));
                continue;
            }
            if is_dir {
                if depth >= self.options.max_depth {
                    self.diagnostic(Diagnostic::new(
                        "max_depth",
                        Some(&relative),
                        "Directory depth budget reached",
                    ));
                    continue;
                }
                match dir.open_dir_nofollow(&name) {
                    Ok(child) => self.walk(
                        &child,
                        &relative,
                        depth + 1,
                        scopes,
                        ignored_parent || vcs_match == Some(true),
                    ),
                    Err(_) => self.diagnostic(Diagnostic::new(
                        "directory_open_failed",
                        Some(&relative),
                        "Directory could not be opened without following links",
                    )),
                }
                continue;
            }
            if !meta.is_file() {
                self.diagnostic(ReadFailure::Special.diagnostic(Some(&relative)));
                continue;
            }
            if self.files.len() >= self.options.max_files {
                self.diagnostic(Diagnostic::new(
                    "max_files",
                    None,
                    "File count budget reached",
                ));
                self.stopped = true;
                break;
            }
            if meta.len() > self.options.max_file_size {
                self.diagnostic(ReadFailure::TooLarge.diagnostic(Some(&relative)));
                continue;
            }
            if meta.len() > self.options.max_total_bytes.saturating_sub(self.read_bytes) {
                self.diagnostic(Diagnostic::new(
                    "max_total_bytes",
                    Some(&relative),
                    "File exceeds remaining total read budget",
                ));
                continue;
            }
            let retained_bytes = FILE_RECORD_METADATA_OVERHEAD.saturating_add(relative.len());
            if !self.reserve_metadata(retained_bytes) {
                break;
            }
            // Charge attempted reads, not only successful records, so a mutating
            // input cannot force unlimited repeated failed reads.
            self.read_bytes += meta.len();
            match read_regular(dir, &name, meta.len()) {
                Ok(bytes) => {
                    let class = classify(&relative, &bytes);
                    if !class.utf8 {
                        self.diagnostic(Diagnostic::new(
                            "unsupported_encoding",
                            Some(&relative),
                            "Non-UTF-8 content is retained only in the file inventory",
                        ));
                    } else if class.binary {
                        self.diagnostic(Diagnostic::new(
                            "binary_file",
                            Some(&relative),
                            "Binary content is retained only in the file inventory",
                        ));
                    }
                    if self.stopped {
                        break;
                    }
                    let tracking =
                        self.git
                            .tracked
                            .as_ref()
                            .map_or(TrackingState::Unknown, |tracked| {
                                if tracked.contains(&relative) {
                                    TrackingState::Tracked
                                } else {
                                    TrackingState::Untracked
                                }
                            });
                    self.files.push(FileRecord {
                        relative_path: relative,
                        size_bytes: bytes.len() as u64,
                        language: class.language,
                        binary: class.binary,
                        generated: class.generated,
                        content_hash: content_hash(&bytes),
                        line_count: class.line_count,
                        utf8: class.utf8,
                        tracking,
                    });
                }
                Err(error) => {
                    self.release_metadata(retained_bytes);
                    self.diagnostic(error.diagnostic(Some(&relative)));
                }
            }
        }
        scopes.truncate(scope_count);
    }
}

fn diagnostic_metadata_bytes(diagnostic: &Diagnostic) -> usize {
    DIAGNOSTIC_METADATA_OVERHEAD
        .saturating_add(diagnostic.code.len())
        .saturating_add(diagnostic.message.len())
        .saturating_add(diagnostic.relative_path.as_deref().map_or(0, str::len))
}
