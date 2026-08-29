//! Bounded access to caller-owned artifacts outside the analyzed repository.
//!
//! The repository is hostile input. External manifests and scanner result
//! artifacts therefore use a separate boundary: resolve and pin the parent,
//! reject a final symbolic link or special file, open without following links
//! and without blocking, then enforce the byte budget again while reading.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

const READ_BUFFER_BYTES: usize = 32 * 1024;

/// Fixed, non-sensitive failure categories for external input handling.
///
/// Display strings never include a path, digest, source byte, or operating
/// system error. A CLI may map every non-configuration variant to an input
/// failure without accidentally echoing hostile data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalInputError {
    InvalidConfiguration,
    UnsafeInput,
    NotOrdinaryFile,
    SizeLimitExceeded,
    ReadFailed,
    ChangedDuringRead,
    ArtifactMismatch,
}

impl fmt::Display for ExternalInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid external input configuration",
            Self::UnsafeInput => "external input path is not safe",
            Self::NotOrdinaryFile => "external input is not an ordinary file",
            Self::SizeLimitExceeded => "external input exceeds its byte limit",
            Self::ReadFailed => "external input could not be read safely",
            Self::ChangedDuringRead => "external input changed while it was being read",
            Self::ArtifactMismatch => "external result artifact does not match its evidence",
        })
    }
}

impl std::error::Error for ExternalInputError {}

/// Digest and byte count independently recomputed from a result artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    pub size_bytes: u64,
    pub sha256: String,
}

/// Read at most `max_bytes`, using one additional byte as an overflow sentinel.
///
/// This generic entry point performs no filesystem checks. File callers should
/// use [`read_bounded_external_file`] so the ordinary-file and repository
/// separation boundary is also enforced.
pub fn read_bounded(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, ExternalInputError> {
    let sentinel_limit = max_bytes
        .checked_add(1)
        .ok_or(ExternalInputError::InvalidConfiguration)?;
    let initial_capacity = usize::try_from(max_bytes.min(READ_BUFFER_BYTES as u64))
        .map_err(|_| ExternalInputError::InvalidConfiguration)?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .by_ref()
        .take(sentinel_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ExternalInputError::ReadFailed)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ExternalInputError::SizeLimitExceeded);
    }
    Ok(bytes)
}

/// Safely read a bounded ordinary file whose resolved path is outside `repository_root`.
pub fn read_bounded_external_file(
    path: &Path,
    repository_root: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, ExternalInputError> {
    let mut opened = open_external_ordinary_file(path, repository_root, max_bytes)?;
    let bytes = read_bounded(&mut opened.file, max_bytes)?;
    verify_unchanged(&opened, bytes.len() as u64)?;
    Ok(bytes)
}

/// Recompute and verify a bounded external result artifact's exact size and SHA-256.
///
/// The function does not parse, retain, or return artifact contents. The
/// expected digest must use the evidence contract's lowercase 64-hex format.
pub fn verify_external_result_artifact(
    path: &Path,
    repository_root: &Path,
    max_bytes: u64,
    expected_size_bytes: u64,
    expected_sha256: &str,
) -> Result<VerifiedArtifact, ExternalInputError> {
    if expected_size_bytes == 0 || expected_size_bytes > max_bytes {
        return Err(ExternalInputError::InvalidConfiguration);
    }
    let expected_digest =
        decode_sha256(expected_sha256).ok_or(ExternalInputError::InvalidConfiguration)?;
    let mut opened = open_external_ordinary_file(path, repository_root, max_bytes)?;
    if opened.stamp.len != expected_size_bytes {
        return Err(ExternalInputError::ArtifactMismatch);
    }
    let (size_bytes, digest) = hash_bounded(&mut opened.file, max_bytes)?;
    verify_unchanged(&opened, size_bytes)?;
    if size_bytes != expected_size_bytes || digest != expected_digest {
        return Err(ExternalInputError::ArtifactMismatch);
    }
    Ok(VerifiedArtifact {
        size_bytes,
        sha256: encode_sha256(&digest),
    })
}

struct OpenedExternalFile {
    file: cap_std::fs::File,
    stamp: FileStamp,
}

fn open_external_ordinary_file(
    path: &Path,
    repository_root: &Path,
    max_bytes: u64,
) -> Result<OpenedExternalFile, ExternalInputError> {
    if max_bytes == u64::MAX {
        return Err(ExternalInputError::InvalidConfiguration);
    }
    let root =
        std::fs::canonicalize(repository_root).map_err(|_| ExternalInputError::UnsafeInput)?;
    if !std::fs::metadata(&root)
        .map_err(|_| ExternalInputError::UnsafeInput)?
        .is_dir()
    {
        return Err(ExternalInputError::UnsafeInput);
    }
    let filename = path
        .file_name()
        .filter(|name| is_single_normal_component(name))
        .ok_or(ExternalInputError::UnsafeInput)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| ExternalInputError::UnsafeInput)?;
    let requested = parent.join(filename);
    if requested.starts_with(&root) {
        return Err(ExternalInputError::UnsafeInput);
    }

    let directory = open_external_parent(&parent).map_err(|_| ExternalInputError::UnsafeInput)?;
    let before = directory
        .symlink_metadata(filename)
        .map_err(|_| ExternalInputError::UnsafeInput)?;
    if !before.is_file() {
        return Err(ExternalInputError::NotOrdinaryFile);
    }
    if before.len() > max_bytes {
        return Err(ExternalInputError::SizeLimitExceeded);
    }

    let file =
        open_external_file(&directory, filename).map_err(|_| ExternalInputError::UnsafeInput)?;
    let opened = file
        .metadata()
        .map_err(|_| ExternalInputError::ReadFailed)?;
    if !opened.is_file() {
        return Err(ExternalInputError::NotOrdinaryFile);
    }
    if opened.len() > max_bytes {
        return Err(ExternalInputError::SizeLimitExceeded);
    }
    let before_stamp = FileStamp::from_metadata(&before);
    let opened_stamp = FileStamp::from_metadata(&opened);
    if before_stamp != opened_stamp {
        return Err(ExternalInputError::ChangedDuringRead);
    }
    Ok(OpenedExternalFile {
        file,
        stamp: opened_stamp,
    })
}

fn open_external_parent(path: &Path) -> io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt;

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid parent",
        ));
    }
    let mut directory = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = directory.open_dir_nofollow(name)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported parent component",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_external_file(directory: &cap_std::fs::Dir, name: &OsStr) -> io::Result<cap_std::fs::File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt};

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    directory.open_with(name, &options)
}

#[cfg(not(unix))]
fn open_external_file(
    _directory: &cap_std::fs::Dir,
    _name: &OsStr,
) -> io::Result<cap_std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "external input boundary requires a supported Unix platform",
    ))
}

fn is_single_normal_component(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn hash_bounded(
    reader: &mut impl Read,
    max_bytes: u64,
) -> Result<(u64, [u8; 32]), ExternalInputError> {
    let sentinel_limit = max_bytes
        .checked_add(1)
        .ok_or(ExternalInputError::InvalidConfiguration)?;
    let mut limited = reader.take(sentinel_limit);
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    let mut size_bytes = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = match limited.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ExternalInputError::ReadFailed),
        };
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or(ExternalInputError::SizeLimitExceeded)?;
        if size_bytes > max_bytes {
            return Err(ExternalInputError::SizeLimitExceeded);
        }
        hasher.update(&buffer[..read]);
    }
    Ok((size_bytes, hasher.finalize().into()))
}

fn verify_unchanged(
    opened: &OpenedExternalFile,
    bytes_read: u64,
) -> Result<(), ExternalInputError> {
    let after = opened
        .file
        .metadata()
        .map_err(|_| ExternalInputError::ReadFailed)?;
    if !after.is_file()
        || bytes_read != opened.stamp.len
        || FileStamp::from_metadata(&after) != opened.stamp
    {
        return Err(ExternalInputError::ChangedDuringRead);
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl FileStamp {
    fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        use cap_std::fs::MetadataExt;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<cap_std::time::SystemTime>,
}

#[cfg(not(unix))]
impl FileStamp {
    fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = decode_hex(value.as_bytes()[offset])?.checked_mul(16)?
            + decode_hex(value.as_bytes()[offset + 1])?;
    }
    Some(digest)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_sha256(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::time::{Duration, Instant};

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn generic_reader_enforces_the_exact_byte_limit() {
        assert_eq!(read_bounded(Cursor::new(b"abc"), 3).unwrap(), b"abc");
        assert_eq!(
            read_bounded(Cursor::new(b"abcd"), 3),
            Err(ExternalInputError::SizeLimitExceeded)
        );
        assert_eq!(
            read_bounded(Cursor::new([]), u64::MAX),
            Err(ExternalInputError::InvalidConfiguration)
        );
    }

    #[test]
    fn external_reader_rejects_files_inside_the_repository() {
        let repository = tempfile::tempdir().unwrap();
        let path = repository.path().join("artifact.json");
        fs::write(&path, b"{}").unwrap();
        assert_eq!(
            read_bounded_external_file(&path, repository.path(), 1024),
            Err(ExternalInputError::UnsafeInput)
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_reader_rejects_a_final_symbolic_link() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.json");
        let linked = outside.path().join("linked.json");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        assert_eq!(
            read_bounded_external_file(&linked, repository.path(), 1024),
            Err(ExternalInputError::NotOrdinaryFile)
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_reader_rejects_a_fifo_without_blocking() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fifo = outside.path().join("artifact.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let started = Instant::now();
        assert_eq!(
            read_bounded_external_file(&fifo, repository.path(), 1024),
            Err(ExternalInputError::NotOrdinaryFile)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn external_reader_rechecks_the_file_size() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("artifact.json");
        fs::write(&path, b"12345").unwrap();
        assert_eq!(
            read_bounded_external_file(&path, repository.path(), 4),
            Err(ExternalInputError::SizeLimitExceeded)
        );
    }

    #[test]
    fn result_verifier_checks_digest_and_size_without_returning_contents() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("result.sarif");
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            verify_external_result_artifact(&path, repository.path(), 1024, 3, ABC_SHA256).unwrap(),
            VerifiedArtifact {
                size_bytes: 3,
                sha256: ABC_SHA256.into(),
            }
        );
        assert_eq!(
            verify_external_result_artifact(&path, repository.path(), 1024, 4, ABC_SHA256),
            Err(ExternalInputError::ArtifactMismatch)
        );
        assert_eq!(
            verify_external_result_artifact(&path, repository.path(), 1024, 3, &"0".repeat(64)),
            Err(ExternalInputError::ArtifactMismatch)
        );
    }

    #[test]
    fn result_verifier_rejects_noncanonical_digest_configuration() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("result.sarif");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            verify_external_result_artifact(
                &path,
                repository.path(),
                1024,
                3,
                &ABC_SHA256.to_uppercase(),
            ),
            Err(ExternalInputError::InvalidConfiguration)
        );
    }

    #[test]
    fn errors_do_not_echo_paths_or_digests() {
        let repository = tempfile::tempdir().unwrap();
        let sensitive_name = "secret-absolute-path";
        let path = repository.path().join(sensitive_name);
        fs::write(&path, b"abc").unwrap();
        let error =
            verify_external_result_artifact(&path, repository.path(), 1024, 3, &"0".repeat(64))
                .unwrap_err()
                .to_string();
        assert!(!error.contains(sensitive_name));
        assert!(!error.contains(&"0".repeat(64)));
    }
}
