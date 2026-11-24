//! Strict zero-dependency `.nkp.toml` v1 parser, TOCTOU-safe ancestor walk,
//! and root-to-leaf binding merger.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::env_file::{EnvLine, EnvValueKind, parse_env_file, validate_env_var_name};
use crate::fs_safe::{
    SafeFsError, is_safe_absolute_path_text, normalize_canonical_path, path_lookup_key,
    safe_read_regular_file_bounded,
};
use crate::sha256::sha256_hex;
use crate::template::{
    MAX_FIELD_NAME_BYTES, TemplateError, is_safe_display_text, is_valid_entry_path,
    is_valid_vault_alias,
};

/// Maximum size in bytes permitted for a `.nkp.toml` or `.env` manifest (64 KiB).
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Maximum number of ancestor directories traversed while searching for manifests.
pub const MAX_WALK_DEPTH: usize = 64;

/// Maximum number of manifests allowed in a merged inheritance chain.
pub const MAX_INHERIT_DEPTH: usize = 8;

/// Maximum number of distinct vaults referenced by a single hook invocation.
pub const MAX_VAULTS_PER_HOOK: usize = 4;

/// Maximum number of effective environment variable bindings after merging.
pub const MAX_MANIFEST_BINDINGS: usize = 256;

/// Maximum number of `env_files` entries permitted in one `.nkp.toml`.
pub const MAX_ENV_FILES_PER_MANIFEST: usize = 16;

/// Failure returned when discovering, reading, parsing, or merging manifests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// Filesystem I/O failed while inspecting directories or reading files.
    Io,
    /// A manifest or `.env` file exceeded [`MAX_MANIFEST_BYTES`].
    TooLarge,
    /// A manifest file did not contain valid UTF-8.
    InvalidUtf8,
    /// A manifest, directory, or referenced `.env` file was a symlink,
    /// non-regular file, world-writable, or failed ownership verification.
    UnsafeFile,
    /// A file or vault path contained control/BiDi characters or an unsupported
    /// Windows namespace.
    UnsafePath,
    /// Invalid TOML syntax in `.nkp.toml`.
    ParseSyntax {
        /// 1-based line number where the syntax error occurred.
        line: usize,
    },
    /// `.nkp.toml` is missing `version = 1` or specifies an unsupported version.
    UnsupportedVersion,
    /// `.nkp.toml` contains an unrecognized key or table.
    UnknownField,
    /// `.nkp.toml` defines a key or table more than once.
    DuplicateField,
    /// `.nkp.toml` `vault` value is empty, CWD-relative, or otherwise invalid.
    InvalidVaultSpec,
    /// `.nkp.toml` `inherit` value is not `"stop"` or `"merge"`.
    InvalidInheritMode,
    /// `.nkp.toml` specifies both `env_file` and `env_files`.
    ConflictingEnvFiles,
    /// An `env_file` / `env_files` path is invalid, empty, duplicate, or escapes
    /// the manifest directory.
    InvalidEnvFilePath,
    /// An `[env]` binding value or `entry`/`field` selector is invalid.
    InvalidEnvBinding,
    /// Effective bindings exceed [`MAX_MANIFEST_BINDINGS`].
    TooManyBindings,
    /// Distinct vaults across the chain exceed [`MAX_VAULTS_PER_HOOK`].
    TooManyVaults,
    /// Discovered manifests in the chain exceed [`MAX_INHERIT_DEPTH`].
    TooManyManifests,
    /// Environment variable name, `.env` syntax, or case-collision error.
    Template(TemplateError),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("cannot read manifest directory or file"),
            Self::TooLarge => f.write_str("manifest file exceeds 64 KiB limit"),
            Self::InvalidUtf8 => f.write_str("manifest file is not valid UTF-8"),
            Self::UnsafeFile => f.write_str("manifest file failed safety or ownership checks"),
            Self::UnsafePath => f.write_str("manifest or vault path failed safety validation"),
            Self::ParseSyntax { line } => write!(f, "invalid .nkp.toml syntax on line {line}"),
            Self::UnsupportedVersion => f.write_str(".nkp.toml must declare integer version = 1"),
            Self::UnknownField => f.write_str(".nkp.toml contains an unknown field or table"),
            Self::DuplicateField => f.write_str(".nkp.toml contains a duplicate field or table"),
            Self::InvalidVaultSpec => {
                f.write_str(".nkp.toml vault must be a valid alias or normalized absolute path")
            }
            Self::InvalidInheritMode => {
                f.write_str(".nkp.toml inherit must be \"stop\" or \"merge\"")
            }
            Self::ConflictingEnvFiles => {
                f.write_str(".nkp.toml cannot specify both env_file and env_files")
            }
            Self::InvalidEnvFilePath => f.write_str(
                ".nkp.toml env_file path must be relative within the manifest directory",
            ),
            Self::InvalidEnvBinding => f.write_str("invalid [env] binding in .nkp.toml"),
            Self::TooManyBindings => f.write_str("manifest chain exceeds maximum binding count"),
            Self::TooManyVaults => {
                f.write_str("manifest chain exceeds maximum distinct vault count")
            }
            Self::TooManyManifests => f.write_str("manifest chain exceeds maximum inherit depth"),
            Self::Template(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<TemplateError> for ManifestError {
    fn from(err: TemplateError) -> Self {
        Self::Template(err)
    }
}

impl From<SafeFsError> for ManifestError {
    fn from(err: SafeFsError) -> Self {
        match err {
            SafeFsError::Io | SafeFsError::NotFound => Self::Io,
            SafeFsError::TooLarge => Self::TooLarge,
            SafeFsError::UnsafeFile | SafeFsError::UnsafePermissions => Self::UnsafeFile,
            SafeFsError::UnsafePath => Self::UnsafePath,
        }
    }
}

/// Inheritance behaviour declared in `.nkp.toml`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InheritMode {
    /// Stop walking ancestor directories at this manifest (default).
    #[default]
    Stop,
    /// Continue walking ancestor directories and merge parent bindings.
    Merge,
}

/// Target vault selector declared in `.nkp.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultSpec {
    /// Configured vault alias (`[A-Za-z0-9_-]{1,128}`).
    Alias(String),
    /// Normalized absolute `.kdbx` path.
    Path(PathBuf),
}

impl VaultSpec {
    /// Returns a stable comparison key for deduplicating vaults across a chain.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        match self {
            Self::Alias(alias) => format!("alias:{alias}"),
            Self::Path(path) => {
                let key =
                    path_lookup_key(path).unwrap_or_else(|_| path.to_string_lossy().into_owned());
                format!("path:{key}")
            }
        }
    }
}

/// Single entry binding declared under `[env]` in `.nkp.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvEntryBinding {
    /// Validated `KeePass` entry path or entry alias.
    pub entry: String,
    /// Optional explicit field selector (`None` uses alias field or `"Password"`).
    pub field: Option<String>,
}

/// Parsed `.nkp.toml` v1 document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestDocument {
    /// Schema version (always `1`).
    pub version: u32,
    /// Optional vault alias or normalized absolute path.
    pub vault: Option<VaultSpec>,
    /// Ancestor inheritance mode (`"stop"` or `"merge"`).
    pub inherit: InheritMode,
    /// Optional relative `.env` files located within the manifest directory.
    pub env_files: Vec<String>,
    /// Ordered `[env]` variable bindings (`VAR = ...`).
    pub env: Vec<(String, EnvEntryBinding)>,
}

/// Kind of manifest file discovered or loaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestSourceKind {
    /// `.nkp.toml` manifest.
    Toml,
    /// Standalone `.nkp.env` manifest.
    NkpEnv,
    /// Explicitly trusted `.env` file.
    DotEnv,
}

/// Normalized path and SHA-256 digest computed from a single bounded read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedFile {
    /// Canonical filesystem path with Windows `\\?\` stripped.
    pub canonical_path: PathBuf,
    /// Display-safe UTF-8 path string.
    pub display_path: String,
    /// Lowercase 64-character SHA-256 hex digest of the exact bytes read.
    pub sha256: String,
}

/// Loaded and parsed `.env` file referenced by a manifest or standalone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedEnvFile {
    /// File path and SHA-256 digest.
    pub file: LoadedFile,
    /// Parsed assignments.
    pub lines: Vec<EnvLine>,
}

/// One loaded manifest layer in a directory chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedManifest {
    /// Manifest file path and SHA-256 digest.
    pub file: LoadedFile,
    /// Manifest kind (`.nkp.toml`, `.nkp.env`, or trusted `.env`).
    pub kind: ManifestSourceKind,
    /// Parsed `.nkp.toml` document when `kind == ManifestSourceKind::Toml`.
    pub doc: Option<ManifestDocument>,
    /// Loaded `.env` files associated with this manifest layer.
    pub env_files: Vec<LoadedEnvFile>,
}

impl LoadedManifest {
    /// Returns a composite SHA-256 hex digest binding this manifest file and all
    /// of its referenced `env_files` in order.
    #[must_use]
    pub fn composite_sha256(&self) -> String {
        if self.env_files.is_empty() || self.kind != ManifestSourceKind::Toml {
            return self.file.sha256.clone();
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(b"nkp-manifest-v1\0");
        buf.extend_from_slice(self.file.sha256.as_bytes());
        for env_file in &self.env_files {
            buf.push(0);
            buf.extend_from_slice(env_file.file.display_path.as_bytes());
            buf.push(0);
            buf.extend_from_slice(env_file.file.sha256.as_bytes());
        }
        sha256_hex(&buf)
    }
}

/// Ordered root-to-leaf chain of discovered manifests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredChain {
    /// Manifest layers ordered root-to-leaf (parent first, nearest dir last).
    pub manifests: Vec<LoadedManifest>,
    /// Every individual file (`.nkp.toml` and referenced `.env` files) that must
    /// be trusted in `trust.json` before activation.
    pub files_to_verify: Vec<LoadedFile>,
    /// Distinct vault selectors referenced across the chain (`<= 4`).
    pub vaults: Vec<VaultSpec>,
}

/// Source of a merged environment variable binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingSource {
    /// Binding from `[env]` in `.nkp.toml`.
    Entry(EnvEntryBinding),
    /// Binding from `.env` / `.nkp.env` (`Literal` or `Template`).
    DotEnv(EnvValueKind),
}

/// Effective post-merge binding for a single environment variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveBinding {
    /// Environment variable name.
    pub name: String,
    /// Optional vault selector inherited from the declaring `.nkp.toml` layer.
    pub vault: Option<VaultSpec>,
    /// Binding source (`Entry` or `DotEnv`).
    pub source: BindingSource,
}

/// Merged environment bindings produced from a [`DiscoveredChain`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedBindings {
    /// Effective variable bindings keyed by exact variable name.
    pub bindings: BTreeMap<String, EffectiveBinding>,
    /// Distinct vaults referenced across the chain.
    pub vaults: Vec<VaultSpec>,
    /// `true` when at least one binding requires resolving from a `KeePass` vault.
    pub requires_vault_unlock: bool,
}

fn validate_vault_spec(raw: &str) -> Result<VaultSpec, ManifestError> {
    if raw.is_empty() || !is_safe_display_text(raw) {
        return Err(ManifestError::InvalidVaultSpec);
    }
    if is_valid_vault_alias(raw) {
        return Ok(VaultSpec::Alias(raw.to_owned()));
    }
    if !is_safe_absolute_path_text(raw) {
        return Err(ManifestError::InvalidVaultSpec);
    }
    Ok(VaultSpec::Path(PathBuf::from(raw)))
}

fn validate_relative_env_file_path(raw: &str) -> Result<String, ManifestError> {
    if raw.is_empty() || !is_safe_display_text(raw) {
        return Err(ManifestError::InvalidEnvFilePath);
    }
    if raw.starts_with('/') || raw.starts_with('\\') || raw.contains(':') {
        return Err(ManifestError::InvalidEnvFilePath);
    }
    let mut parts = Vec::new();
    for segment in raw.split(['/', '\\']) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ManifestError::InvalidEnvFilePath);
        }
        parts.push(segment);
    }
    if parts.is_empty() {
        return Err(ManifestError::InvalidEnvFilePath);
    }
    Ok(parts.join("/"))
}

fn validate_entry_binding(
    entry: &str,
    field: Option<&str>,
) -> Result<EnvEntryBinding, ManifestError> {
    if !is_valid_entry_path(entry) {
        return Err(ManifestError::InvalidEnvBinding);
    }
    let validated_field = match field {
        Some(f) => {
            if f.is_empty()
                || f.len() > MAX_FIELD_NAME_BYTES
                || f.contains('#')
                || !is_safe_display_text(f)
            {
                return Err(ManifestError::InvalidEnvBinding);
            }
            Some(f.to_owned())
        }
        None => None,
    };
    Ok(EnvEntryBinding {
        entry: entry.to_owned(),
        field: validated_field,
    })
}

// --- Minimal strict zero-dependency TOML parser for `.nkp.toml` v1 ---

struct TomlCursor<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> TomlCursor<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn syntax_err(&self) -> ManifestError {
        ManifestError::ParseSyntax { line: self.line }
    }

    fn advance_ascii(&mut self, count: usize) {
        self.pos += count;
    }

    fn skip_inline_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) -> Result<(), ManifestError> {
        if self.peek() == Some(b'#') {
            self.pos += 1;
            while self.pos < self.bytes.len() {
                let ch = self.src[self.pos..]
                    .chars()
                    .next()
                    .ok_or_else(|| self.syntax_err())?;
                if ch == '\n' {
                    break;
                }
                if ch == '\r' && self.bytes.get(self.pos + 1) == Some(&b'\n') {
                    break;
                }
                if (ch.is_control() && ch != '\t') || ch == '\u{7f}' {
                    return Err(self.syntax_err());
                }
                self.pos += ch.len_utf8();
            }
        }
        Ok(())
    }

    fn expect_line_end_or_eof(&mut self) -> Result<(), ManifestError> {
        self.skip_inline_ws();
        self.skip_comment()?;
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.pos += 1;
                self.line += 1;
                Ok(())
            }
            Some(b'\r') if self.bytes.get(self.pos + 1) == Some(&b'\n') => {
                self.pos += 2;
                self.line += 1;
                Ok(())
            }
            _ => Err(self.syntax_err()),
        }
    }

    fn skip_ws_and_comments_multiline(&mut self) -> Result<(), ManifestError> {
        loop {
            self.skip_inline_ws();
            self.skip_comment()?;
            match self.peek() {
                Some(b'\n') => {
                    self.pos += 1;
                    self.line += 1;
                }
                Some(b'\r') if self.bytes.get(self.pos + 1) == Some(&b'\n') => {
                    self.pos += 2;
                    self.line += 1;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn parse_key(&mut self) -> Result<String, ManifestError> {
        match self.peek() {
            Some(b'"') => self.parse_basic_string(),
            Some(b'\'') => self.parse_literal_string(),
            Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' => {
                let start = self.pos;
                while let Some(next) = self.peek() {
                    if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Ok(self.src[start..self.pos].to_owned())
            }
            _ => Err(self.syntax_err()),
        }
    }

    fn parse_unicode_escape(&mut self, digits: usize) -> Result<char, ManifestError> {
        if self.pos + digits > self.bytes.len() {
            return Err(self.syntax_err());
        }
        let hex = &self.src[self.pos..self.pos + digits];
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.syntax_err());
        }
        let code = u32::from_str_radix(hex, 16).map_err(|_| self.syntax_err())?;
        self.pos += digits;
        char::from_u32(code).ok_or_else(|| self.syntax_err())
    }

    fn parse_basic_string(&mut self) -> Result<String, ManifestError> {
        if self.peek() != Some(b'"') {
            return Err(self.syntax_err());
        }
        self.pos += 1;
        // Reject multiline basic strings `"""` explicitly for strictness.
        if self.bytes.get(self.pos..self.pos + 2) == Some(b"\"\"") {
            return Err(self.syntax_err());
        }
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let ch = self.src[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| self.syntax_err())?;
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\n' | '\r' => return Err(self.syntax_err()),
                c if c.is_control() && c != '\t' => return Err(self.syntax_err()),
                '\\' => {
                    let esc = self.peek().ok_or_else(|| self.syntax_err())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape(4)?),
                        b'U' => out.push(self.parse_unicode_escape(8)?),
                        _ => return Err(self.syntax_err()),
                    }
                }
                other => out.push(other),
            }
        }
        Err(self.syntax_err())
    }

    fn parse_literal_string(&mut self) -> Result<String, ManifestError> {
        if self.peek() != Some(b'\'') {
            return Err(self.syntax_err());
        }
        self.pos += 1;
        if self.bytes.get(self.pos..self.pos + 2) == Some(b"''") {
            return Err(self.syntax_err());
        }
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let ch = self.src[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| self.syntax_err())?;
            self.pos += ch.len_utf8();
            match ch {
                '\'' => return Ok(out),
                '\n' | '\r' => return Err(self.syntax_err()),
                c if c.is_control() && c != '\t' => return Err(self.syntax_err()),
                other => out.push(other),
            }
        }
        Err(self.syntax_err())
    }

    fn parse_string(&mut self) -> Result<String, ManifestError> {
        match self.peek() {
            Some(b'"') => self.parse_basic_string(),
            Some(b'\'') => self.parse_literal_string(),
            _ => Err(self.syntax_err()),
        }
    }

    fn parse_u32(&mut self) -> Result<u32, ManifestError> {
        if self.peek() == Some(b'+') {
            self.pos += 1;
        }
        let start = self.pos;
        let mut digits = String::new();
        let mut prev_underscore = true;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                digits.push(char::from(b));
                prev_underscore = false;
                self.pos += 1;
            } else if b == b'_' && !prev_underscore {
                prev_underscore = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start || prev_underscore || digits.is_empty() {
            return Err(self.syntax_err());
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(self.syntax_err());
        }
        // Must terminate on delimiter/whitespace/comment, not e.g. `.0` float or `e5`.
        if let Some(next) = self.peek()
            && !matches!(next, b' ' | b'\t' | b'\r' | b'\n' | b'#')
        {
            return Err(self.syntax_err());
        }
        digits
            .parse::<u32>()
            .map_err(|_| ManifestError::UnsupportedVersion)
    }

    fn parse_string_array(&mut self) -> Result<Vec<String>, ManifestError> {
        if self.peek() != Some(b'[') {
            return Err(self.syntax_err());
        }
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws_and_comments_multiline()?;
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(items);
            }
            if items.len() >= MAX_ENV_FILES_PER_MANIFEST {
                return Err(ManifestError::InvalidEnvFilePath);
            }
            let item = self.parse_string()?;
            items.push(item);
            self.skip_ws_and_comments_multiline()?;
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(self.syntax_err()),
            }
        }
    }

    fn parse_env_inline_table(&mut self) -> Result<EnvEntryBinding, ManifestError> {
        if self.peek() != Some(b'{') {
            return Err(self.syntax_err());
        }
        self.pos += 1;
        let mut entry: Option<String> = None;
        let mut field: Option<String> = None;

        self.skip_inline_ws();
        if self.peek() == Some(b'}') {
            return Err(ManifestError::InvalidEnvBinding);
        }

        loop {
            self.skip_inline_ws();
            let key = self.parse_key()?;
            self.skip_inline_ws();
            if self.peek() != Some(b'=') {
                return Err(self.syntax_err());
            }
            self.pos += 1;
            self.skip_inline_ws();
            let val = self.parse_string()?;
            match key.as_str() {
                "entry" => {
                    if entry.is_some() {
                        return Err(ManifestError::DuplicateField);
                    }
                    entry = Some(val);
                }
                "field" => {
                    if field.is_some() {
                        return Err(ManifestError::DuplicateField);
                    }
                    field = Some(val);
                }
                _ => return Err(ManifestError::UnknownField),
            }
            self.skip_inline_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_inline_ws();
                    if self.peek() == Some(b'}') {
                        // TOML 1.0 forbids trailing commas in inline tables.
                        return Err(self.syntax_err());
                    }
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.syntax_err()),
            }
        }

        let entry = entry.ok_or(ManifestError::InvalidEnvBinding)?;
        validate_entry_binding(&entry, field.as_deref())
    }
}

#[derive(Eq, PartialEq)]
enum Section {
    Root,
    Env,
    EnvEntry(String),
}

struct EnvEntrySubtable {
    name: String,
    entry: Option<String>,
    field: Option<String>,
}

struct TomlParseState {
    section: Section,
    seen_env_section: bool,
    seen_root_keys: BTreeSet<String>,
    seen_env_upper: BTreeSet<String>,
    version: Option<u32>,
    vault: Option<VaultSpec>,
    inherit: InheritMode,
    env_files: Vec<String>,
    used_env_file_singular: bool,
    used_env_files_plural: bool,
    env: Vec<(String, EnvEntryBinding)>,
    active_subtable: Option<EnvEntrySubtable>,
}

impl TomlParseState {
    fn new() -> Self {
        Self {
            section: Section::Root,
            seen_env_section: false,
            seen_root_keys: BTreeSet::new(),
            seen_env_upper: BTreeSet::new(),
            version: None,
            vault: None,
            inherit: InheritMode::Stop,
            env_files: Vec::new(),
            used_env_file_singular: false,
            used_env_files_plural: false,
            env: Vec::new(),
            active_subtable: None,
        }
    }

    fn flush_subtable(&mut self) -> Result<(), ManifestError> {
        if let Some(sub) = self.active_subtable.take() {
            let entry = sub.entry.ok_or(ManifestError::InvalidEnvBinding)?;
            let binding = validate_entry_binding(&entry, sub.field.as_deref())?;
            self.env.push((sub.name, binding));
        }
        Ok(())
    }

    fn parse_section_header(&mut self, cur: &mut TomlCursor<'_>) -> Result<(), ManifestError> {
        self.flush_subtable()?;
        cur.advance_ascii(1);
        if cur.peek() == Some(b'[') {
            return Err(ManifestError::UnknownField);
        }
        cur.skip_inline_ws();
        let first = cur.parse_key()?;
        cur.skip_inline_ws();
        if cur.peek() == Some(b'.') {
            cur.advance_ascii(1);
            cur.skip_inline_ws();
            let var_name = cur.parse_key()?;
            cur.skip_inline_ws();
            if cur.peek() != Some(b']') {
                return Err(cur.syntax_err());
            }
            cur.advance_ascii(1);
            cur.expect_line_end_or_eof()?;
            if first != "env" {
                return Err(ManifestError::UnknownField);
            }
            validate_env_var_name(&var_name)?;
            if !self.seen_env_upper.insert(var_name.to_ascii_uppercase()) {
                return Err(TemplateError::DuplicateEnvVar.into());
            }
            if self.env.len() >= MAX_MANIFEST_BINDINGS {
                return Err(ManifestError::TooManyBindings);
            }
            self.section = Section::EnvEntry(var_name.clone());
            self.active_subtable = Some(EnvEntrySubtable {
                name: var_name,
                entry: None,
                field: None,
            });
        } else {
            if cur.peek() != Some(b']') {
                return Err(cur.syntax_err());
            }
            cur.advance_ascii(1);
            cur.expect_line_end_or_eof()?;
            if first != "env" {
                return Err(ManifestError::UnknownField);
            }
            if self.seen_env_section {
                return Err(ManifestError::DuplicateField);
            }
            self.seen_env_section = true;
            self.section = Section::Env;
        }
        Ok(())
    }

    fn parse_root_key(&mut self, key: &str, cur: &mut TomlCursor<'_>) -> Result<(), ManifestError> {
        if !self.seen_root_keys.insert(key.to_owned()) {
            return Err(ManifestError::DuplicateField);
        }
        match key {
            "version" => {
                let v = cur.parse_u32()?;
                if v != 1 {
                    return Err(ManifestError::UnsupportedVersion);
                }
                self.version = Some(v);
            }
            "vault" => {
                let raw = cur.parse_string()?;
                self.vault = Some(validate_vault_spec(&raw)?);
            }
            "inherit" => {
                let raw = cur.parse_string()?;
                self.inherit = match raw.as_str() {
                    "stop" => InheritMode::Stop,
                    "merge" => InheritMode::Merge,
                    _ => return Err(ManifestError::InvalidInheritMode),
                };
            }
            "env_file" => {
                if self.used_env_files_plural {
                    return Err(ManifestError::ConflictingEnvFiles);
                }
                self.used_env_file_singular = true;
                let raw = cur.parse_string()?;
                self.env_files.push(validate_relative_env_file_path(&raw)?);
            }
            "env_files" => {
                if self.used_env_file_singular {
                    return Err(ManifestError::ConflictingEnvFiles);
                }
                self.used_env_files_plural = true;
                let items = cur.parse_string_array()?;
                if items.is_empty() {
                    return Err(ManifestError::InvalidEnvFilePath);
                }
                let mut seen_paths = BTreeSet::new();
                for raw in items {
                    let norm = validate_relative_env_file_path(&raw)?;
                    if !seen_paths.insert(norm.clone()) {
                        return Err(ManifestError::InvalidEnvFilePath);
                    }
                    self.env_files.push(norm);
                }
            }
            _ => return Err(ManifestError::UnknownField),
        }
        cur.expect_line_end_or_eof()
    }

    fn parse_env_key(
        &mut self,
        key: String,
        cur: &mut TomlCursor<'_>,
    ) -> Result<(), ManifestError> {
        validate_env_var_name(&key)?;
        if !self.seen_env_upper.insert(key.to_ascii_uppercase()) {
            return Err(TemplateError::DuplicateEnvVar.into());
        }
        if self.env.len() >= MAX_MANIFEST_BINDINGS {
            return Err(ManifestError::TooManyBindings);
        }
        let binding = match cur.peek() {
            Some(b'"' | b'\'') => {
                let entry = cur.parse_string()?;
                validate_entry_binding(&entry, None)?
            }
            Some(b'{') => cur.parse_env_inline_table()?,
            _ => return Err(ManifestError::InvalidEnvBinding),
        };
        cur.expect_line_end_or_eof()?;
        self.env.push((key, binding));
        Ok(())
    }

    fn parse_subtable_key(
        &mut self,
        key: &str,
        cur: &mut TomlCursor<'_>,
    ) -> Result<(), ManifestError> {
        let Some(sub) = self.active_subtable.as_mut() else {
            return Err(cur.syntax_err());
        };
        let val = cur.parse_string()?;
        match key {
            "entry" => {
                if sub.entry.is_some() {
                    return Err(ManifestError::DuplicateField);
                }
                sub.entry = Some(val);
            }
            "field" => {
                if sub.field.is_some() {
                    return Err(ManifestError::DuplicateField);
                }
                sub.field = Some(val);
            }
            _ => return Err(ManifestError::UnknownField),
        }
        cur.expect_line_end_or_eof()
    }
}

/// Parses a `.nkp.toml` v1 manifest string with closed-schema enforcement.
///
/// Enforces `<= 64 KiB`, `version = 1` (required), unknown-field rejection,
/// duplicate-key rejection, case-insensitive variable collision rejection, and
/// path/binding safety rules.
///
/// # Errors
///
/// Returns [`ManifestError`] on size limits, syntax errors, unsupported
/// versions, unknown or duplicate keys, invalid paths, or invalid `[env]`
/// bindings.
pub fn parse_manifest_toml(input: &str) -> Result<ManifestDocument, ManifestError> {
    if input.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    if input.contains('\0') {
        return Err(ManifestError::ParseSyntax { line: 1 });
    }

    let mut cur = TomlCursor::new(input);
    let mut state = TomlParseState::new();

    while !cur.is_eof() {
        cur.skip_ws_and_comments_multiline()?;
        if cur.is_eof() {
            break;
        }
        if cur.peek() == Some(b'[') {
            state.parse_section_header(&mut cur)?;
            continue;
        }

        let key = cur.parse_key()?;
        cur.skip_inline_ws();
        if cur.peek() == Some(b'.') {
            return Err(ManifestError::UnknownField);
        }
        if cur.peek() != Some(b'=') {
            return Err(cur.syntax_err());
        }
        cur.advance_ascii(1);
        cur.skip_inline_ws();

        match &state.section {
            Section::Root => state.parse_root_key(&key, &mut cur)?,
            Section::Env => state.parse_env_key(key, &mut cur)?,
            Section::EnvEntry(_) => state.parse_subtable_key(&key, &mut cur)?,
        }
    }

    state.flush_subtable()?;

    let version = state.version.ok_or(ManifestError::UnsupportedVersion)?;
    Ok(ManifestDocument {
        version,
        vault: state.vault,
        inherit: state.inherit,
        env_files: state.env_files,
        env: state.env,
    })
}

fn read_loaded_text_file(path: &Path) -> Result<(LoadedFile, String), ManifestError> {
    let (canonical_path, bytes) = safe_read_regular_file_bounded(path, MAX_MANIFEST_BYTES, false)?;
    let display_path = canonical_path
        .to_str()
        .ok_or(ManifestError::UnsafePath)?
        .to_owned();
    if !is_safe_display_text(&display_path) {
        return Err(ManifestError::UnsafePath);
    }
    let sha256 = sha256_hex(&bytes);
    let text = String::from_utf8(bytes).map_err(|_| ManifestError::InvalidUtf8)?;
    Ok((
        LoadedFile {
            canonical_path,
            display_path,
            sha256,
        },
        text,
    ))
}

fn resolve_safe_relative_child(base_dir: &Path, rel: &str) -> Result<PathBuf, ManifestError> {
    let normalized_rel = validate_relative_env_file_path(rel)?;
    let mut cur = base_dir.to_path_buf();
    let segments: Vec<&str> = normalized_rel.split('/').collect();
    for (idx, seg) in segments.iter().enumerate() {
        cur.push(seg);
        let meta = fs::symlink_metadata(&cur).map_err(|_| ManifestError::Io)?;
        if meta.file_type().is_symlink() {
            return Err(ManifestError::UnsafeFile);
        }
        if idx + 1 < segments.len() {
            if !meta.file_type().is_dir() {
                return Err(ManifestError::UnsafeFile);
            }
        } else if !meta.file_type().is_file() {
            return Err(ManifestError::UnsafeFile);
        }
    }
    Ok(cur)
}

fn load_toml_manifest_from_dir(
    dir: &Path,
    toml_path: &Path,
) -> Result<LoadedManifest, ManifestError> {
    let (file, text) = read_loaded_text_file(toml_path)?;
    let doc = parse_manifest_toml(&text)?;
    let mut env_files = Vec::with_capacity(doc.env_files.len());
    for rel in &doc.env_files {
        let child_path = resolve_safe_relative_child(dir, rel)?;
        let (env_file_meta, env_text) = read_loaded_text_file(&child_path)?;
        let lines = parse_env_file(&env_text)?;
        env_files.push(LoadedEnvFile {
            file: env_file_meta,
            lines,
        });
    }
    Ok(LoadedManifest {
        file,
        kind: ManifestSourceKind::Toml,
        doc: Some(doc),
        env_files,
    })
}

fn load_env_manifest(
    path: &Path,
    kind: ManifestSourceKind,
) -> Result<LoadedManifest, ManifestError> {
    let (file, text) = read_loaded_text_file(path)?;
    let lines = parse_env_file(&text)?;
    Ok(LoadedManifest {
        file: file.clone(),
        kind,
        doc: None,
        env_files: vec![LoadedEnvFile { file, lines }],
    })
}

/// Loads and validates a single manifest file (`.nkp.toml`, `.nkp.env`, or `.env`)
/// using a TOCTOU-safe bounded single read.
///
/// # Errors
///
/// Returns [`ManifestError`] when the path is unsafe, unreadable, oversized,
/// symlinked, or fails schema/`.env` validation.
pub fn load_single_manifest_file(path: &Path) -> Result<LoadedManifest, ManifestError> {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(ManifestError::UnsafePath)?;
    if file_name == ".nkp.toml" {
        let canon = fs::canonicalize(path).map_err(|_| ManifestError::Io)?;
        let norm = normalize_canonical_path(&canon)?;
        let parent = norm.parent().ok_or(ManifestError::UnsafePath)?;
        load_toml_manifest_from_dir(parent, path)
    } else if file_name == ".nkp.env" {
        load_env_manifest(path, ManifestSourceKind::NkpEnv)
    } else {
        load_env_manifest(path, ManifestSourceKind::DotEnv)
    }
}

fn inspect_dir_manifest(
    dir: &Path,
    is_dotenv_path_trusted: &mut impl FnMut(&Path) -> bool,
) -> Result<Option<(LoadedManifest, InheritMode)>, ManifestError> {
    let toml_path = dir.join(".nkp.toml");
    match fs::symlink_metadata(&toml_path) {
        Ok(_) => {
            let loaded = load_toml_manifest_from_dir(dir, &toml_path)?;
            let inherit = loaded
                .doc
                .as_ref()
                .map_or(InheritMode::Stop, |doc| doc.inherit);
            return Ok(Some((loaded, inherit)));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ManifestError::Io),
    }

    let nkp_env_path = dir.join(".nkp.env");
    match fs::symlink_metadata(&nkp_env_path) {
        Ok(_) => {
            let loaded = load_env_manifest(&nkp_env_path, ManifestSourceKind::NkpEnv)?;
            return Ok(Some((loaded, InheritMode::Stop)));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ManifestError::Io),
    }

    let dot_env_path = dir.join(".env");
    if let Ok(dot_meta) = fs::symlink_metadata(&dot_env_path)
        && !dot_meta.file_type().is_symlink()
        && dot_meta.file_type().is_file()
        && let Ok(canon_dot) = fs::canonicalize(&dot_env_path)
        && let Ok(norm_dot) = normalize_canonical_path(&canon_dot)
        && is_dotenv_path_trusted(&norm_dot)
    {
        let loaded = load_env_manifest(&dot_env_path, ManifestSourceKind::DotEnv)?;
        return Ok(Some((loaded, InheritMode::Stop)));
    }

    Ok(None)
}

/// Walks upward from `cwd` (bounded by [`MAX_WALK_DEPTH`], [`MAX_INHERIT_DEPTH`],
/// [`MAX_VAULTS_PER_HOOK`], and filesystem mount boundaries on Unix) to
/// discover an active manifest chain.
///
/// Ordinary `.env` files (without `.nkp.toml` or `.nkp.env`) are only treated as
/// manifests when `is_dotenv_path_trusted(&canonical_env_path)` returns `true`.
///
/// # Errors
///
/// Returns [`ManifestError`] when any discovered candidate fails safety,
/// syntax, inheritance depth, or vault-count validation.
pub fn discover_chain(
    cwd: &Path,
    mut is_dotenv_path_trusted: impl FnMut(&Path) -> bool,
) -> Result<Option<DiscoveredChain>, ManifestError> {
    let canon_cwd = fs::canonicalize(cwd).map_err(|_| ManifestError::Io)?;
    let start_dir = normalize_canonical_path(&canon_cwd)?;
    let start_meta = fs::symlink_metadata(&start_dir).map_err(|_| ManifestError::Io)?;
    if start_meta.file_type().is_symlink() || !start_meta.file_type().is_dir() {
        return Err(ManifestError::UnsafeFile);
    }

    #[cfg(unix)]
    let start_dev = {
        use std::os::unix::fs::MetadataExt;
        start_meta.dev()
    };

    let mut manifests_leaf_to_root = Vec::new();
    let mut current: Option<PathBuf> = Some(start_dir);
    let mut depth = 0_usize;

    while let Some(dir) = current {
        if depth >= MAX_WALK_DEPTH {
            break;
        }
        depth += 1;

        let Ok(dir_meta) = fs::symlink_metadata(&dir) else {
            return Err(ManifestError::Io);
        };
        if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
            return Err(ManifestError::UnsafeFile);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if dir_meta.dev() != start_dev {
                break;
            }
        }

        if let Some((loaded, inherit)) = inspect_dir_manifest(&dir, &mut is_dotenv_path_trusted)? {
            manifests_leaf_to_root.push(loaded);
            if manifests_leaf_to_root.len() > MAX_INHERIT_DEPTH {
                return Err(ManifestError::TooManyManifests);
            }
            if inherit == InheritMode::Stop {
                break;
            }
        }

        current = dir.parent().map(Path::to_path_buf);
    }

    if manifests_leaf_to_root.is_empty() {
        return Ok(None);
    }

    manifests_leaf_to_root.reverse();

    let mut files_to_verify = Vec::new();
    let mut seen_vaults = BTreeSet::new();
    let mut vaults = Vec::new();
    for manifest in &manifests_leaf_to_root {
        files_to_verify.push(manifest.file.clone());
        if manifest.kind == ManifestSourceKind::Toml {
            for env_file in &manifest.env_files {
                files_to_verify.push(env_file.file.clone());
            }
        }
        if let Some(doc) = &manifest.doc
            && let Some(vault_spec) = &doc.vault
        {
            let key = vault_spec.dedup_key();
            if seen_vaults.insert(key) {
                if vaults.len() >= MAX_VAULTS_PER_HOOK {
                    return Err(ManifestError::TooManyVaults);
                }
                vaults.push(vault_spec.clone());
            }
        }
    }

    Ok(Some(DiscoveredChain {
        manifests: manifests_leaf_to_root,
        files_to_verify,
        vaults,
    }))
}

fn insert_merged_binding(
    bindings: &mut BTreeMap<String, EffectiveBinding>,
    case_index: &mut BTreeMap<String, String>,
    name: String,
    binding: EffectiveBinding,
) -> Result<(), ManifestError> {
    let upper = name.to_ascii_uppercase();
    if let Some(existing_name) = case_index.get(&upper) {
        if existing_name != &name {
            return Err(TemplateError::DuplicateEnvVar.into());
        }
        bindings.insert(name, binding);
        return Ok(());
    }
    if bindings.len() >= MAX_MANIFEST_BINDINGS {
        return Err(ManifestError::TooManyBindings);
    }
    case_index.insert(upper, name.clone());
    bindings.insert(name, binding);
    Ok(())
}

/// Merges a root-to-leaf [`DiscoveredChain`] into effective variable bindings.
///
/// Within a manifest layer, `[env]` overrides `env_files`. Across `merge` layers,
/// child layers override parent layers for exact-case variable names while
/// rejecting case-only collisions (`FOO` vs `foo`) on all platforms.
///
/// # Errors
///
/// Returns [`ManifestError`] when a case-only collision occurs or effective
/// bindings exceed [`MAX_MANIFEST_BINDINGS`].
pub fn merge_chain_bindings(chain: &DiscoveredChain) -> Result<MergedBindings, ManifestError> {
    let mut bindings = BTreeMap::new();
    let mut case_index = BTreeMap::new();
    let mut inherited_vault: Option<VaultSpec> = None;

    for manifest in &chain.manifests {
        let layer_vault = manifest
            .doc
            .as_ref()
            .and_then(|d| d.vault.clone())
            .or_else(|| inherited_vault.clone());
        inherited_vault.clone_from(&layer_vault);

        for env_file in &manifest.env_files {
            for line in &env_file.lines {
                insert_merged_binding(
                    &mut bindings,
                    &mut case_index,
                    line.name.clone(),
                    EffectiveBinding {
                        name: line.name.clone(),
                        vault: layer_vault.clone(),
                        source: BindingSource::DotEnv(line.value.clone()),
                    },
                )?;
            }
        }

        if let Some(doc) = &manifest.doc {
            for (name, entry_binding) in &doc.env {
                insert_merged_binding(
                    &mut bindings,
                    &mut case_index,
                    name.clone(),
                    EffectiveBinding {
                        name: name.clone(),
                        vault: layer_vault.clone(),
                        source: BindingSource::Entry(entry_binding.clone()),
                    },
                )?;
            }
        }
    }

    let requires_vault_unlock = bindings.values().any(|b| match &b.source {
        BindingSource::Entry(_) | BindingSource::DotEnv(EnvValueKind::Template(_)) => true,
        BindingSource::DotEnv(EnvValueKind::Literal(_)) => false,
    });

    Ok(MergedBindings {
        bindings,
        vaults: chain.vaults.clone(),
        requires_vault_unlock,
    })
}
