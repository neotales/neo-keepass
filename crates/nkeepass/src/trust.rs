//! Fail-closed persistent trust store (`data_dir()/trust.json`) with
//! exclusive file locking, owner-only permissions, and cross-platform key
//! normalization.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_safe::{
    SafeFsError, has_windows_namespace_prefix, normalize_canonical_path,
    normalize_path_text_for_platform, path_lookup_key, path_lookup_key_for_platform,
    safe_read_regular_file_bounded,
};
use crate::manifest::{LoadedManifest, ManifestSourceKind, load_single_manifest_file};
use crate::private_file;
use crate::sha256::{constant_time_eq, is_lowercase_hex};
use crate::template::is_safe_display_text;

/// Maximum serialized size of `trust.json` (1 MiB).
pub const MAX_TRUST_STORE_BYTES: usize = 1024 * 1024;

/// Maximum number of trusted entries stored in `trust.json`.
pub const MAX_TRUST_ENTRIES: usize = 4096;

const TRUST_FILE_NAME: &str = "trust.json";
const TRUST_LOCK_NAME: &str = "trust.lock";
const TRUST_VERSION: u32 = 1;

/// Failure returned by trust store operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustError {
    /// Store or target path is unavailable, empty, or contains unsafe characters.
    InvalidPath,
    /// Target file does not exist.
    NotFound,
    /// Target path or `trust.json` is a symlink, reparse point, or non-regular file.
    UnsafeFile,
    /// `data_dir()` or `trust.json` permissions/DACL are not owner-only.
    UnsafePermissions,
    /// Supplied SHA-256 digest is not a 64-character lowercase hex string.
    InvalidDigest,
    /// `trust.json` is malformed, uses an unsupported version, or has invalid fields.
    CorruptStore,
    /// `trust.json` exceeds [`MAX_TRUST_STORE_BYTES`] or [`MAX_TRUST_ENTRIES`].
    LimitExceeded,
    /// Underlying filesystem or lock I/O error.
    Io,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("invalid or unsafe trust path"),
            Self::NotFound => f.write_str("trusted file target does not exist"),
            Self::UnsafeFile => {
                f.write_str("trust store or target failed regular-file safety check")
            }
            Self::UnsafePermissions => {
                f.write_str("trust store directory or file lacks owner-only permissions")
            }
            Self::InvalidDigest => f.write_str("invalid SHA-256 digest in trust operation"),
            Self::CorruptStore => f.write_str("trust store is corrupt or unsupported"),
            Self::LimitExceeded => f.write_str("trust store exceeds size or entry limit"),
            Self::Io => f.write_str("trust store I/O error"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<SafeFsError> for TrustError {
    fn from(err: SafeFsError) -> Self {
        match err {
            SafeFsError::NotFound => Self::NotFound,
            SafeFsError::Io => Self::Io,
            SafeFsError::TooLarge => Self::LimitExceeded,
            SafeFsError::UnsafeFile => Self::UnsafeFile,
            SafeFsError::UnsafePermissions => Self::UnsafePermissions,
            SafeFsError::UnsafePath => Self::InvalidPath,
        }
    }
}

/// Kind of trusted file recorded in `trust.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustKind {
    /// `.nkp.toml` manifest.
    Toml,
    /// Standalone `.nkp.env` manifest.
    NkpEnv,
    /// Explicitly trusted `.env` file.
    DotEnv,
}

impl From<ManifestSourceKind> for TrustKind {
    fn from(kind: ManifestSourceKind) -> Self {
        match kind {
            ManifestSourceKind::Toml => Self::Toml,
            ManifestSourceKind::NkpEnv => Self::NkpEnv,
            ManifestSourceKind::DotEnv => Self::DotEnv,
        }
    }
}

/// Single trusted file record in `trust.json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry {
    /// Canonicalized, display-safe file path (Windows `\\?\` stripped).
    pub path: String,
    /// 64-character lowercase SHA-256 hex digest of trusted file contents.
    pub sha256: String,
    /// Manifest kind.
    pub kind: TrustKind,
    /// UNIX timestamp (seconds) when trust was recorded.
    pub trusted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTrustEntry {
    key: String,
    path: String,
    sha256: String,
    kind: TrustKind,
    trusted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreFile {
    version: u32,
    entries: Vec<StoredTrustEntry>,
}

/// In-memory snapshot of `trust.json` entries keyed by platform-normalized path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustStore {
    entries: BTreeMap<String, TrustEntry>,
}

fn validate_data_dir_path(path: PathBuf) -> Result<PathBuf, TrustError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(TrustError::InvalidPath);
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(TrustError::InvalidPath);
    }
    let text = path.to_str().ok_or(TrustError::InvalidPath)?;
    if !is_safe_display_text(text) || (cfg!(windows) && has_windows_namespace_prefix(text)) {
        return Err(TrustError::InvalidPath);
    }
    Ok(path)
}

/// Resolves the application data directory (`data_dir()`) matching `nkp` CLI
/// resolution order (`NEO_KEEPASS_DATA_DIR`, `XDG_DATA_DIR`, `XDG_DATA_HOME`,
/// or platform home fallback).
///
/// # Errors
///
/// Returns [`TrustError::InvalidPath`] when no valid absolute data directory can
/// be resolved.
pub fn default_data_dir() -> Result<PathBuf, TrustError> {
    if let Some(val) = env::var_os("NEO_KEEPASS_DATA_DIR").filter(|v| !v.is_empty()) {
        return validate_data_dir_path(PathBuf::from(val));
    }
    if let Some(val) = env::var_os("XDG_DATA_DIR").filter(|v| !v.is_empty()) {
        return Ok(validate_data_dir_path(PathBuf::from(val))?.join("nkeepass"));
    }
    if let Some(val) = env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(validate_data_dir_path(PathBuf::from(val))?.join("nkeepass"));
    }

    #[cfg(windows)]
    {
        if let Some(profile) =
            known_folders::get_known_folder_path(known_folders::KnownFolder::Profile)
            && let Ok(valid) = validate_data_dir_path(profile)
        {
            return Ok(valid.join(".local").join("share").join("nkeepass"));
        }
        if let Some(val) = env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
            return Ok(validate_data_dir_path(PathBuf::from(val))?
                .join(".local")
                .join("share")
                .join("nkeepass"));
        }
        Err(TrustError::InvalidPath)
    }

    #[cfg(not(windows))]
    {
        let home = env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or(TrustError::InvalidPath)?;
        Ok(validate_data_dir_path(PathBuf::from(home))?
            .join(".local")
            .join("share")
            .join("nkeepass"))
    }
}

/// Normalizes a path string for display and strips Windows `\\?\` from
/// `VerbatimDisk` paths (`\\?\C:\...` -> `C:\...`), rejecting control/BiDi
/// characters and Windows UNC/device namespaces.
///
/// # Errors
///
/// Returns [`TrustError::InvalidPath`] if the path is empty, contains
/// control/BiDi characters, or uses a disallowed Windows namespace.
pub fn normalize_display_path_for_platform(
    raw: &str,
    is_windows: bool,
) -> Result<String, TrustError> {
    normalize_path_text_for_platform(raw, is_windows).map_err(TrustError::from)
}

/// Computes the canonical lookup key for a path string on the target platform
/// (stripping `\\?\` and ASCII-lowercasing on Windows; preserving case on Unix).
///
/// # Errors
///
/// Returns [`TrustError::InvalidPath`] when path normalization fails.
pub fn canonical_key_for_platform(raw: &str, is_windows: bool) -> Result<String, TrustError> {
    path_lookup_key_for_platform(raw, is_windows).map_err(TrustError::from)
}

fn verify_existing_store_dir(dir: &Path) -> Result<(), TrustError> {
    let meta = fs::symlink_metadata(dir).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            TrustError::NotFound
        } else {
            TrustError::Io
        }
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(TrustError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        crate::fs_safe::verify_unix_dir_owner_only(&meta)?;
    }
    #[cfg(windows)]
    {
        // Verify directory has a non-reparse, owner-only protected DACL via secure_directory
        // or open-reparse check. On existing directory, re-securing or checking owner is done
        // before writes; for read, check no reparse point on directory.
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x0400 != 0 {
            return Err(TrustError::UnsafeFile);
        }
    }
    Ok(())
}

fn ensure_private_store_dir(dir: &Path) -> Result<(), TrustError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(TrustError::UnsafeFile);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                        .map_err(|_| TrustError::UnsafePermissions)?;
                }
                let updated = fs::symlink_metadata(dir).map_err(|_| TrustError::Io)?;
                crate::fs_safe::verify_unix_dir_owner_only(&updated)?;
            }
            #[cfg(windows)]
            {
                private_file::set_owner_only(dir, "cannot secure trust directory")
                    .map_err(|_| TrustError::UnsafePermissions)?;
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|_| TrustError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| TrustError::UnsafePermissions)?;
            }
            #[cfg(windows)]
            {
                private_file::set_owner_only(dir, "cannot secure trust directory")
                    .map_err(|_| TrustError::UnsafePermissions)?;
            }
            verify_existing_store_dir(dir)?;
        }
        Err(_) => return Err(TrustError::Io),
    }
    Ok(())
}

fn open_trust_lock(dir: &Path) -> Result<File, TrustError> {
    let lock_path = dir.join(TRUST_LOCK_NAME);
    if let Ok(meta) = fs::symlink_metadata(&lock_path)
        && (meta.file_type().is_symlink() || !meta.file_type().is_file())
    {
        return Err(TrustError::UnsafeFile);
    }

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&lock_path).map_err(|_| TrustError::Io)?;
    let fmeta = file.metadata().map_err(|_| TrustError::Io)?;
    if !fmeta.file_type().is_file() {
        return Err(TrustError::UnsafeFile);
    }
    file.lock().map_err(|_| TrustError::Io)?;
    Ok(file)
}

fn load_store_unlocked(dir: &Path) -> Result<TrustStore, TrustError> {
    match verify_existing_store_dir(dir) {
        Ok(()) => {}
        Err(TrustError::NotFound) => return Ok(TrustStore::default()),
        Err(err) => return Err(err),
    }

    let path = dir.join(TRUST_FILE_NAME);
    let (_canon, bytes) = match safe_read_regular_file_bounded(&path, MAX_TRUST_STORE_BYTES, true) {
        Ok(res) => res,
        Err(SafeFsError::NotFound) => return Ok(TrustStore::default()),
        Err(err) => return Err(TrustError::from(err)),
    };

    let parsed: TrustStoreFile =
        serde_json::from_slice(&bytes).map_err(|_| TrustError::CorruptStore)?;
    if parsed.version != TRUST_VERSION {
        return Err(TrustError::CorruptStore);
    }
    if parsed.entries.len() > MAX_TRUST_ENTRIES {
        return Err(TrustError::LimitExceeded);
    }

    let mut entries = BTreeMap::new();
    for item in parsed.entries {
        if !is_lowercase_hex(&item.sha256, 64) {
            return Err(TrustError::CorruptStore);
        }
        let display_path = normalize_path_text_for_platform(&item.path, cfg!(windows))?;
        let key = path_lookup_key_for_platform(&display_path, cfg!(windows))?;
        if key != item.key && !cfg!(windows) {
            return Err(TrustError::CorruptStore);
        }
        if entries
            .insert(
                key,
                TrustEntry {
                    path: display_path,
                    sha256: item.sha256,
                    kind: item.kind,
                    trusted_at_unix: item.trusted_at_unix,
                },
            )
            .is_some()
        {
            return Err(TrustError::CorruptStore);
        }
    }

    Ok(TrustStore { entries })
}

fn save_store_unlocked(dir: &Path, store: &TrustStore) -> Result<(), TrustError> {
    if store.entries.len() > MAX_TRUST_ENTRIES {
        return Err(TrustError::LimitExceeded);
    }
    let stored_entries: Vec<StoredTrustEntry> = store
        .entries
        .iter()
        .map(|(key, entry)| StoredTrustEntry {
            key: key.clone(),
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            kind: entry.kind,
            trusted_at_unix: entry.trusted_at_unix,
        })
        .collect();

    let payload = TrustStoreFile {
        version: TRUST_VERSION,
        entries: stored_entries,
    };
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|_| TrustError::Io)?;
    if bytes.len() > MAX_TRUST_STORE_BYTES {
        return Err(TrustError::LimitExceeded);
    }

    let mut temp = private_file::new_private_temp(dir).map_err(|err| {
        if err.kind() == io::ErrorKind::PermissionDenied
            || err.kind() == io::ErrorKind::Unsupported
            || private_file::capability_query_failed(&err)
        {
            TrustError::UnsafePermissions
        } else {
            TrustError::Io
        }
    })?;
    temp.write_all(&bytes).map_err(|_| TrustError::Io)?;
    temp.as_file().sync_all().map_err(|_| TrustError::Io)?;
    temp.persist(dir.join(TRUST_FILE_NAME))
        .map_err(|_| TrustError::Io)?;
    #[cfg(unix)]
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| TrustError::Io)?;
    Ok(())
}

fn with_locked_store_mut<R>(
    dir: &Path,
    f: impl FnOnce(&mut TrustStore) -> Result<R, TrustError>,
) -> Result<R, TrustError> {
    ensure_private_store_dir(dir)?;
    let lock = open_trust_lock(dir)?;
    let mut store = load_store_unlocked(dir)?;
    let result = f(&mut store)?;
    save_store_unlocked(dir, &store)?;
    let _ = lock.unlock();
    drop(lock);
    Ok(result)
}

fn canonicalize_existing_regular_target(path: &Path) -> Result<(PathBuf, String), TrustError> {
    let lmeta = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            TrustError::NotFound
        } else {
            TrustError::Io
        }
    })?;
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_file() {
        return Err(TrustError::UnsafeFile);
    }
    let (canon, _bytes) =
        safe_read_regular_file_bounded(path, crate::manifest::MAX_MANIFEST_BYTES, false)?;
    let display = canon.to_str().ok_or(TrustError::InvalidPath)?.to_owned();
    if !is_safe_display_text(&display) {
        return Err(TrustError::InvalidPath);
    }
    Ok((canon, display))
}

fn resolve_untrust_key(path: &Path) -> Result<String, TrustError> {
    if let Ok(canon) = fs::canonicalize(path) {
        let norm = normalize_canonical_path(&canon)?;
        return path_lookup_key(&norm).map_err(TrustError::from);
    }
    if path.is_absolute() {
        let norm = normalize_canonical_path(path)?;
        return path_lookup_key(&norm).map_err(TrustError::from);
    }
    let cwd = env::current_dir().map_err(|_| TrustError::InvalidPath)?;
    let joined = cwd.join(path);
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(TrustError::InvalidPath);
                }
            }
        }
    }
    let norm = normalize_canonical_path(&normalized)?;
    path_lookup_key(&norm).map_err(TrustError::from)
}

impl TrustStore {
    /// Loads `trust.json` from `dir` (read-only). Returns an empty store if
    /// `dir` or `trust.json` does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if `dir` or `trust.json` fails symlink,
    /// permission/DACL, size, or schema validation.
    pub fn load_from_dir(dir: &Path) -> Result<Self, TrustError> {
        load_store_unlocked(dir)
    }

    /// Loads `trust.json` from [`default_data_dir()`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] when `data_dir()` is unavailable or `trust.json`
    /// fails validation.
    pub fn load_default() -> Result<Self, TrustError> {
        let dir = default_data_dir()?;
        Self::load_from_dir(&dir)
    }

    /// Returns `true` iff `path` and `sha256` match an entry in this store.
    /// Fail-closed: returns `false` on any path or digest validation failure.
    #[must_use]
    pub fn is_trusted(&self, path: &Path, sha256: &str) -> bool {
        if !is_lowercase_hex(sha256, 64) {
            return false;
        }
        let Ok(key) = path_lookup_key(path) else {
            return false;
        };
        let Some(entry) = self.entries.get(&key) else {
            return false;
        };
        constant_time_eq(entry.sha256.as_bytes(), sha256.as_bytes())
    }

    /// Returns `true` iff `path`'s normalized key is present in this store
    /// (regardless of digest), used to decide whether an ordinary `.env` is
    /// managed by `nkp`.
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        let Ok(key) = path_lookup_key(path) else {
            return false;
        };
        self.entries.contains_key(&key)
    }

    /// Lists all trusted entries in deterministic key order.
    #[must_use]
    pub fn list_trusted(&self) -> Vec<&TrustEntry> {
        self.entries.values().collect()
    }
}

/// Trusts a single existing regular file `(path, sha256)` in `store_dir/trust.json`.
///
/// # Errors
///
/// Returns [`TrustError`] when `path` is unsafe/missing, `sha256` is not 64
/// lowercase hex chars, `store_dir` fails permission checks, or the store exceeds
/// bounds.
pub fn trust_file(
    store_dir: &Path,
    path: &Path,
    sha256: &str,
    kind: TrustKind,
    now_unix: u64,
) -> Result<TrustEntry, TrustError> {
    if !is_lowercase_hex(sha256, 64) {
        return Err(TrustError::InvalidDigest);
    }
    let (canon, display_path) = canonicalize_existing_regular_target(path)?;
    let key = path_lookup_key(&canon)?;

    with_locked_store_mut(store_dir, |store| {
        if !store.entries.contains_key(&key) && store.entries.len() >= MAX_TRUST_ENTRIES {
            return Err(TrustError::LimitExceeded);
        }
        let entry = TrustEntry {
            path: display_path,
            sha256: sha256.to_owned(),
            kind,
            trusted_at_unix: now_unix,
        };
        store.entries.insert(key, entry.clone());
        Ok(entry)
    })
}

/// Validates and trusts a manifest file (`.nkp.toml`, `.nkp.env`, or `.env`)
/// along with any `env_file`/`env_files` referenced by a `.nkp.toml` atomically
/// under `trust.lock`.
///
/// # Errors
///
/// Returns [`TrustError`] on filesystem/store failures or if manifest parsing
/// fails.
pub fn trust_manifest_file(
    store_dir: &Path,
    manifest_path: &Path,
    now_unix: u64,
) -> Result<(LoadedManifest, Vec<TrustEntry>), TrustError> {
    let loaded = load_single_manifest_file(manifest_path).map_err(|err| match err {
        crate::manifest::ManifestError::UnsafeFile => TrustError::UnsafeFile,
        crate::manifest::ManifestError::UnsafePath => TrustError::InvalidPath,
        crate::manifest::ManifestError::TooLarge => TrustError::LimitExceeded,
        _ => TrustError::Io,
    })?;

    let mut records = Vec::new();
    let main_key = path_lookup_key(&loaded.file.canonical_path)?;
    records.push((
        main_key,
        TrustEntry {
            path: loaded.file.display_path.clone(),
            sha256: loaded.file.sha256.clone(),
            kind: TrustKind::from(loaded.kind),
            trusted_at_unix: now_unix,
        },
    ));
    if loaded.kind == ManifestSourceKind::Toml {
        for env_file in &loaded.env_files {
            let key = path_lookup_key(&env_file.file.canonical_path)?;
            records.push((
                key,
                TrustEntry {
                    path: env_file.file.display_path.clone(),
                    sha256: env_file.file.sha256.clone(),
                    kind: TrustKind::DotEnv,
                    trusted_at_unix: now_unix,
                },
            ));
        }
    }

    let entries = with_locked_store_mut(store_dir, |store| {
        let new_count = records
            .iter()
            .filter(|(k, _)| !store.entries.contains_key(k))
            .count();
        if store.entries.len() + new_count > MAX_TRUST_ENTRIES {
            return Err(TrustError::LimitExceeded);
        }
        let mut out = Vec::with_capacity(records.len());
        for (key, entry) in records {
            store.entries.insert(key, entry.clone());
            out.push(entry);
        }
        Ok(out)
    })?;

    Ok((loaded, entries))
}

/// Revokes trust for `path` in `store_dir/trust.json`. Returns `true` if an
/// entry was removed.
///
/// # Errors
///
/// Returns [`TrustError`] when `path` is invalid or `trust.json` cannot be
/// locked, verified, or updated.
pub fn untrust_file(store_dir: &Path, path: &Path) -> Result<bool, TrustError> {
    let key = resolve_untrust_key(path)?;
    with_locked_store_mut(store_dir, |store| Ok(store.entries.remove(&key).is_some()))
}

/// Revokes all trusted entries in `store_dir/trust.json`, returning how many
/// entries were removed.
///
/// # Errors
///
/// Returns [`TrustError`] when `trust.json` cannot be locked, verified, or
/// updated.
pub fn untrust_all(store_dir: &Path) -> Result<usize, TrustError> {
    with_locked_store_mut(store_dir, |store| {
        let count = store.entries.len();
        store.entries.clear();
        Ok(count)
    })
}

/// Removes entries from `store_dir/trust.json` whose target files no longer
/// exist or are no longer regular files, returning the number removed.
///
/// # Errors
///
/// Returns [`TrustError`] when `trust.json` cannot be locked, verified, or
/// updated.
pub fn prune_missing(store_dir: &Path) -> Result<usize, TrustError> {
    with_locked_store_mut(store_dir, |store| {
        let before = store.entries.len();
        store.entries.retain(|_, entry| {
            fs::symlink_metadata(&entry.path)
                .is_ok_and(|meta| !meta.file_type().is_symlink() && meta.file_type().is_file())
        });
        Ok(before - store.entries.len())
    })
}

/// Lists all entries currently stored in `store_dir/trust.json`.
///
/// # Errors
///
/// Returns [`TrustError`] when `trust.json` fails permission, symlink, or
/// schema checks.
pub fn list_trusted(store_dir: &Path) -> Result<Vec<TrustEntry>, TrustError> {
    let store = TrustStore::load_from_dir(store_dir)?;
    Ok(store.entries.into_values().collect())
}

/// Checks whether `(path, sha256)` is currently trusted in `store_dir/trust.json`.
///
/// # Errors
///
/// Returns [`TrustError`] when `trust.json` exists and fails permission,
/// symlink, or schema checks.
pub fn is_trusted(store_dir: &Path, path: &Path, sha256: &str) -> Result<bool, TrustError> {
    let store = TrustStore::load_from_dir(store_dir)?;
    Ok(store.is_trusted(path, sha256))
}
