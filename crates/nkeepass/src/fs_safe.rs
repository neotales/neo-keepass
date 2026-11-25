//! Safe TOCTOU-resistant filesystem primitives (zero `unsafe` code).

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::template::is_safe_display_text;

/// Policy error returned by safe filesystem open/read/normalization helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafeFsError {
    NotFound,
    Io,
    TooLarge,
    UnsafeFile,
    UnsafePermissions,
    UnsafePath,
}

/// Captured vault file metadata fingerprint used to detect on-disk changes
/// across hook ticks without re-opening or decrypting the KDBX file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFingerprint {
    /// Normalized canonical vault path (never containing `\\?\` or controls).
    pub path: String,
    /// Modification timestamp seconds (Unix epoch or Windows 100ns filetime).
    pub mtime_secs: i64,
    /// Modification timestamp sub-second nanoseconds (0 on Windows).
    pub mtime_nanos: i64,
    /// Metadata change / creation timestamp seconds.
    pub ctime_secs: i64,
    /// Metadata change / creation timestamp sub-second nanoseconds.
    pub ctime_nanos: i64,
    /// File length in bytes.
    pub size: u64,
    /// Platform inode number (0 when unavailable on non-Unix).
    pub ino: u64,
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "s390x",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "mips",
            target_arch = "mips64"
        )
    ))]
    {
        0o400_000
    }
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )
    ))]
    {
        0o100_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x0100
    }
    #[cfg(not(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86_64",
                target_arch = "x86",
                target_arch = "s390x",
                target_arch = "riscv64",
                target_arch = "loongarch64",
                target_arch = "sparc",
                target_arch = "sparc64",
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "m68k"
            )
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        0
    }
}

#[cfg(unix)]
const fn unix_o_nonblock() -> i32 {
    #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
    {
        0x0080
    }
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64")
    ))]
    {
        0x4000
    }
    #[cfg(all(
        target_os = "linux",
        not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    {
        0o4_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x0004
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        0
    }
}

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;

/// Checks if a string uses a Windows verbatim or device namespace (`\\?\`, `\\.\`).
#[must_use]
pub(crate) fn has_windows_namespace_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    let is_sep = |b: u8| b == b'\\' || b == b'/';
    bytes.len() >= 4
        && is_sep(bytes[0])
        && is_sep(bytes[1])
        && matches!(bytes[2], b'?' | b'.')
        && is_sep(bytes[3])
}

/// Strips `\\?\` from a Windows `VerbatimDisk` path (`\\?\C:\...` -> `C:\...`).
/// Rejects `\\?\UNC\...`, `\\.\...`, and other verbatim/device namespaces.
pub(crate) fn normalize_path_text_for_platform(
    raw: &str,
    is_windows: bool,
) -> Result<String, SafeFsError> {
    if raw.is_empty() || !is_safe_display_text(raw) {
        return Err(SafeFsError::UnsafePath);
    }

    if !is_windows {
        return Ok(raw.to_owned());
    }

    let bytes = raw.as_bytes();
    let is_sep = |b: u8| b == b'\\' || b == b'/';
    let stripped = if bytes.len() >= 4
        && is_sep(bytes[0])
        && is_sep(bytes[1])
        && bytes[2] == b'?'
        && is_sep(bytes[3])
    {
        let rest = &raw[4..];
        let rest_bytes = rest.as_bytes();
        if rest_bytes.len() >= 3
            && rest_bytes[0].is_ascii_alphabetic()
            && rest_bytes[1] == b':'
            && is_sep(rest_bytes[2])
        {
            rest
        } else {
            return Err(SafeFsError::UnsafePath);
        }
    } else if has_windows_namespace_prefix(raw) {
        return Err(SafeFsError::UnsafePath);
    } else {
        raw
    };

    if stripped.is_empty() || !is_safe_display_text(stripped) {
        return Err(SafeFsError::UnsafePath);
    }

    Ok(stripped.replace('/', "\\"))
}

/// Normalizes a canonical path (stripping Windows `\\?\` on disk paths and
/// rejecting unsafe characters or Windows device/verbatim UNC namespaces).
pub(crate) fn normalize_canonical_path(path: &Path) -> Result<PathBuf, SafeFsError> {
    let raw = path.to_str().ok_or(SafeFsError::UnsafePath)?;
    let normalized = normalize_path_text_for_platform(raw, cfg!(windows))?;
    Ok(PathBuf::from(normalized))
}

/// Computes the platform-appropriate lookup key for a normalized path:
/// on Windows, strips `\\?\`, normalizes `/` to `\`, and folds ASCII case;
/// on Unix, preserves exact case.
pub(crate) fn path_lookup_key_for_platform(
    raw: &str,
    is_windows: bool,
) -> Result<String, SafeFsError> {
    let normalized = normalize_path_text_for_platform(raw, is_windows)?;
    if is_windows {
        Ok(normalized.to_ascii_lowercase())
    } else {
        Ok(normalized)
    }
}

/// Computes the host-platform lookup key for `path`.
pub(crate) fn path_lookup_key(path: &Path) -> Result<String, SafeFsError> {
    let raw = path.to_str().ok_or(SafeFsError::UnsafePath)?;
    path_lookup_key_for_platform(raw, cfg!(windows))
}

/// Validates that `path` is a safe absolute path with no `.` or `..` components,
/// no control/BiDi characters, and no Windows verbatim/device namespaces.
pub(crate) fn is_safe_absolute_path_text(raw: &str) -> bool {
    if raw.is_empty() || !is_safe_display_text(raw) {
        return false;
    }
    if cfg!(windows) && has_windows_namespace_prefix(raw) {
        return false;
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return false;
    }
    !path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

#[cfg(unix)]
pub(crate) fn verify_unix_dir_owner_only(meta: &Metadata) -> Result<(), SafeFsError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(SafeFsError::UnsafeFile);
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(SafeFsError::UnsafePermissions);
    }
    let euid = rustix::process::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(SafeFsError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_windows_dir_no_reparse(dir: &Path) -> Result<(), SafeFsError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let lmeta = fs::symlink_metadata(dir).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            SafeFsError::NotFound
        } else {
            SafeFsError::Io
        }
    })?;
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_dir() {
        return Err(SafeFsError::UnsafeFile);
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                SafeFsError::NotFound
            } else {
                SafeFsError::UnsafeFile
            }
        })?;
    let fmeta = handle.metadata().map_err(|_| SafeFsError::Io)?;
    let attrs = fmeta.file_attributes();
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        return Err(SafeFsError::UnsafeFile);
    }
    Ok(())
}

/// Opens (or creates) `trust.lock` safely without following symlinks or
/// Windows reparse points, verifying regular-file ownership.
pub(crate) fn open_lock_file_safe(path: &Path) -> Result<File, SafeFsError> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || !meta.file_type().is_file())
    {
        return Err(SafeFsError::UnsafeFile);
    }

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(unix_o_nofollow() | unix_o_nonblock());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts.open(path).map_err(|_| SafeFsError::Io)?;
    let fmeta = file.metadata().map_err(|_| SafeFsError::Io)?;
    if !fmeta.file_type().is_file() {
        return Err(SafeFsError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if fmeta.uid() != rustix::process::geteuid().as_raw()
            || (fmeta.permissions().mode() & 0o077) != 0
        {
            return Err(SafeFsError::UnsafePermissions);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attrs = fmeta.file_attributes();
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(SafeFsError::UnsafeFile);
        }
    }
    Ok(file)
}

fn safe_fs_error_to_io(err: SafeFsError) -> io::Error {
    match err {
        SafeFsError::NotFound => io::Error::new(io::ErrorKind::NotFound, "file not found"),
        SafeFsError::UnsafeFile | SafeFsError::UnsafePath => {
            io::Error::new(io::ErrorKind::InvalidInput, "path must be a regular file")
        }
        SafeFsError::UnsafePermissions => {
            io::Error::new(io::ErrorKind::PermissionDenied, "unsafe file permissions")
        }
        SafeFsError::TooLarge => {
            io::Error::new(io::ErrorKind::InvalidData, "file exceeds size limit")
        }
        SafeFsError::Io => io::Error::other("filesystem I/O error"),
    }
}

fn open_regular_file_nofollow_raw(path: &Path) -> Result<(File, Metadata), SafeFsError> {
    let lmeta = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            SafeFsError::NotFound
        } else {
            SafeFsError::Io
        }
    })?;
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_file() {
        return Err(SafeFsError::UnsafeFile);
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_o_nofollow() | unix_o_nonblock());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts.open(path).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound => SafeFsError::NotFound,
        io::ErrorKind::PermissionDenied => SafeFsError::Io,
        _ => SafeFsError::UnsafeFile,
    })?;

    let fmeta = file.metadata().map_err(|_| SafeFsError::Io)?;
    if !fmeta.file_type().is_file() {
        return Err(SafeFsError::UnsafeFile);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
            return Err(SafeFsError::UnsafeFile);
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attrs = fmeta.file_attributes();
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(SafeFsError::UnsafeFile);
        }
    }

    Ok((file, fmeta))
}

/// Opens an existing regular file without following symlinks or Windows reparse
/// points and without blocking on FIFOs or device nodes, verifying post-open
/// descriptor identity (`dev`/`ino` on Unix, no reparse point on Windows) and
/// regular-file type.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] when `path` does not exist,
/// [`io::ErrorKind::InvalidInput`] when `path` is a symlink, reparse point,
/// directory, FIFO, or device, or another [`io::Error`] if opening or stating
/// fails.
pub fn open_regular_file_nofollow(path: &Path) -> io::Result<(File, Metadata)> {
    open_regular_file_nofollow_raw(path).map_err(safe_fs_error_to_io)
}

/// Opens an existing regular file without blocking on FIFOs or device nodes,
/// verifying post-open descriptor metadata confirms a regular file.
///
/// Unlike [`open_regular_file_nofollow`], symlinks resolving to a regular file
/// are permitted (for example, symlink-managed vault files), while symlinks to
/// FIFOs, devices, or directories are rejected before reading.
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] when the opened descriptor is not a
/// regular file, or the underlying [`io::Error`] when opening or stating fails.
pub fn open_regular_file_nonblocking(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_o_nonblock());
    }
    let file = opts.open(path)?;
    let fmeta = file.metadata()?;
    if !fmeta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be a regular file",
        ));
    }
    Ok(file)
}

/// Opens an existing regular file safely without following symlinks/reparse points
/// or blocking on FIFOs/devices.
///
/// When `require_owner_only` is `true`, verifies `mode & 0o077 == 0` on Unix and
/// `windows_private_file::verify` on Windows. Otherwise verifies `!world_writable`
/// (`mode & 0o002 == 0`) on Unix.
pub(crate) fn safe_open_regular_file(
    path: &Path,
    require_owner_only: bool,
) -> Result<(File, Metadata), SafeFsError> {
    let (file, fmeta) = open_regular_file_nofollow_raw(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = fmeta.permissions().mode();
        if require_owner_only {
            if mode & 0o077 != 0 {
                return Err(SafeFsError::UnsafePermissions);
            }
        } else if mode & 0o002 != 0 {
            return Err(SafeFsError::UnsafePermissions);
        }
        let euid = rustix::process::geteuid().as_raw();
        if fmeta.uid() != euid {
            return Err(SafeFsError::UnsafePermissions);
        }
    }

    #[cfg(windows)]
    {
        if require_owner_only && windows_private_file::verify(&file).is_err() {
            return Err(SafeFsError::UnsafePermissions);
        }
    }

    #[cfg(not(any(unix, windows)))]
    let _ = require_owner_only;

    Ok((file, fmeta))
}

/// Opens `path` safely (without following symlinks), verifies it is a safe regular
/// file, reads up to `max_bytes` in a single pass, and returns the normalized
/// canonical path paired with the exact read bytes.
pub(crate) fn safe_read_regular_file_bounded(
    path: &Path,
    max_bytes: usize,
    require_owner_only: bool,
) -> Result<(PathBuf, Vec<u8>), SafeFsError> {
    let (file, fmeta) = safe_open_regular_file(path, require_owner_only)?;
    let canon = fs::canonicalize(path).map_err(|_| SafeFsError::UnsafePath)?;
    let cmeta = fs::symlink_metadata(&canon).map_err(|_| SafeFsError::UnsafeFile)?;
    if cmeta.file_type().is_symlink() || !cmeta.file_type().is_file() {
        return Err(SafeFsError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if cmeta.dev() != fmeta.dev() || cmeta.ino() != fmeta.ino() {
            return Err(SafeFsError::UnsafeFile);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (cmeta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || cmeta.file_size() != fmeta.file_size()
        {
            return Err(SafeFsError::UnsafeFile);
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = &fmeta;

    let normalized = normalize_canonical_path(&canon)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SafeFsError::Io)?;
    if bytes.len() > max_bytes {
        return Err(SafeFsError::TooLarge);
    }
    Ok((normalized, bytes))
}

/// Pre-opens a vault file safely (`O_NOFOLLOW | O_NONBLOCK` /
/// `FILE_FLAG_OPEN_REPARSE_POINT`) to rule out FIFOs/devices/symlinks before
/// passing it to `VaultService::open`, returning its [`VaultFingerprint`].
pub(crate) fn preopen_vault_fingerprint(path: &Path) -> Result<VaultFingerprint, SafeFsError> {
    let (_file, fmeta) = safe_open_regular_file(path, false)?;
    let canon = fs::canonicalize(path).map_err(|_| SafeFsError::UnsafePath)?;
    let normalized = normalize_canonical_path(&canon)?;
    let display = normalized
        .to_str()
        .ok_or(SafeFsError::UnsafePath)?
        .to_owned();

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(VaultFingerprint {
            path: display,
            mtime_secs: fmeta.mtime(),
            mtime_nanos: fmeta.mtime_nsec(),
            ctime_secs: fmeta.ctime(),
            ctime_nanos: fmeta.ctime_nsec(),
            size: fmeta.size(),
            ino: fmeta.ino(),
        })
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(VaultFingerprint {
            path: display,
            mtime_secs: i64::try_from(fmeta.last_write_time()).unwrap_or(i64::MAX),
            mtime_nanos: 0,
            ctime_secs: i64::try_from(fmeta.creation_time()).unwrap_or(i64::MAX),
            ctime_nanos: 0,
            size: fmeta.file_size(),
            ino: 0,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(VaultFingerprint {
            path: display,
            mtime_secs: 0,
            mtime_nanos: 0,
            ctime_secs: 0,
            ctime_nanos: 0,
            size: fmeta.len(),
            ino: 0,
        })
    }
}
