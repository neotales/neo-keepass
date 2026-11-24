//! Canonical `nkp://` URI parser, secret lookup boundary, and single-pass
//! non-recursive text template injector.

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

use crate::service::{SelectorError, ServiceError, SessionId, VaultService};

/// Maximum length in bytes accepted for a `@vault_alias` segment.
pub const MAX_VAULT_ALIAS_BYTES: usize = 128;

/// Maximum length in decoded UTF-8 bytes accepted for an `nkp://` entry path.
pub const MAX_ENTRY_PATH_BYTES: usize = 1024;

/// Maximum length in decoded UTF-8 bytes accepted for an `nkp://` `#field` name.
pub const MAX_FIELD_NAME_BYTES: usize = 256;

/// Hard upper bound on template input size in bytes (16 MiB).
pub const MAX_TEMPLATE_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Hard upper bound on rendered template output size in bytes (64 MiB).
pub const MAX_TEMPLATE_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Hard upper bound on `nkp://` references allowed in a single template.
pub const MAX_TEMPLATE_REFS: usize = 1024;

/// Structured failure returned by `nkp://` URI parsing, template rendering,
/// and `.env` parsing/resolution.
///
/// Error variants and display messages are static or structural (e.g. line
/// numbers) and never embed secret bytes or vault-controlled names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateError {
    /// The `nkp://` URI is malformed or missing the `nkp://` scheme.
    InvalidUri,
    /// The `@vault_alias` prefix is empty, overlong, or uses invalid characters.
    InvalidVaultAlias,
    /// The `entry_path` is empty, overlong, contains `.`/`..`, empty segments, or unsafe characters.
    InvalidEntryPath,
    /// The `#field_name` fragment is empty, overlong, contains `#`, or uses unsafe characters.
    InvalidFieldName,
    /// A `%HH` percent-encoded sequence is malformed or decodes to invalid UTF-8.
    InvalidPercentEncoding,
    /// A braced `{{nkp://...` reference is missing its closing `}}`.
    UnterminatedReference,
    /// Template input exceeds the configured or maximum byte limit.
    InputTooLarge,
    /// Rendered output would exceed the configured or maximum byte limit.
    OutputTooLarge,
    /// Template contains more `nkp://` references than permitted.
    TooManyReferences,
    /// Caller-supplied [`RenderOptions`] violate hard safety bounds.
    InvalidOptions,
    /// The `@vault_alias` in the URI is not registered with the lookup adapter.
    UnknownVaultAlias,
    /// No entry matches the resolved path.
    EntryNotFound,
    /// More than one entry or group matches the resolved path or alias.
    AmbiguousEntry,
    /// The requested field does not exist on the resolved entry.
    FieldNotFound,
    /// Multiple fields share the requested name on the resolved entry.
    AmbiguousField,
    /// The entry's OTP configuration is missing or invalid.
    InvalidOtp,
    /// Stateful HOTP is refused by non-mutating template resolution.
    HotpUnsupported,
    /// The backing vault session is locked.
    VaultLocked,
    /// The backing vault session handle is stale.
    StaleSession,
    /// A resolved secret value is not valid UTF-8.
    NonUtf8Secret,
    /// A resolved secret or `.env` value contains NUL, disallowed control bytes, or bidirectional controls.
    UnsafeSecretCharacters,
    /// The `.env` input exceeds the maximum allowed byte size.
    InvalidEnvFileSize,
    /// The `.env` input contains more assignments than permitted.
    TooManyEnvEntries,
    /// A `.env` line has invalid syntax.
    InvalidEnvSyntax {
        /// 1-based line number where the syntax error occurred.
        line: usize,
    },
    /// An environment variable name fails `[A-Za-z_][A-Za-z0-9_]*` or length `1..=128`.
    InvalidEnvVarName,
    /// An environment variable name is on the reserved execution/app blocklist.
    ReservedEnvVar,
    /// An environment variable name collides (case-insensitively) with an earlier binding.
    DuplicateEnvVar,
    /// A vault service operation failed with a non-secret service error.
    Service(ServiceError),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUri => f.write_str("invalid nkp:// URI"),
            Self::InvalidVaultAlias => f.write_str("invalid vault alias in nkp:// URI"),
            Self::InvalidEntryPath => f.write_str("invalid entry path in nkp:// URI"),
            Self::InvalidFieldName => f.write_str("invalid field name in nkp:// URI"),
            Self::InvalidPercentEncoding => f.write_str("invalid percent-encoding in nkp:// URI"),
            Self::UnterminatedReference => f.write_str("unterminated {{nkp://...}} reference"),
            Self::InputTooLarge => f.write_str("template input exceeds size limit"),
            Self::OutputTooLarge => f.write_str("rendered template output exceeds size limit"),
            Self::TooManyReferences => f.write_str("template exceeds maximum reference count"),
            Self::InvalidOptions => f.write_str("invalid template render options"),
            Self::UnknownVaultAlias => f.write_str("unknown vault alias in nkp:// URI"),
            Self::EntryNotFound => f.write_str("referenced entry not found"),
            Self::AmbiguousEntry => f.write_str("referenced entry or alias is ambiguous"),
            Self::FieldNotFound => f.write_str("referenced field not found"),
            Self::AmbiguousField => f.write_str("referenced field is ambiguous"),
            Self::InvalidOtp => f.write_str("invalid OTP configuration on referenced entry"),
            Self::HotpUnsupported => f.write_str("HOTP is unsupported in template resolution"),
            Self::VaultLocked => f.write_str("vault session is locked"),
            Self::StaleSession => f.write_str("vault session is stale"),
            Self::NonUtf8Secret => f.write_str("resolved secret is not valid UTF-8"),
            Self::UnsafeSecretCharacters => {
                f.write_str("value contains disallowed control or BiDi characters")
            }
            Self::InvalidEnvFileSize => f.write_str(".env file exceeds maximum allowed size"),
            Self::TooManyEnvEntries => f.write_str(".env file exceeds maximum entry count"),
            Self::InvalidEnvSyntax { line } => {
                write!(f, "invalid .env syntax on line {line}")
            }
            Self::InvalidEnvVarName => f.write_str("invalid environment variable name"),
            Self::ReservedEnvVar => f.write_str("reserved environment variable name is forbidden"),
            Self::DuplicateEnvVar => {
                f.write_str("duplicate or case-colliding environment variable name")
            }
            Self::Service(err) => f.write_str(err.message()),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Parsed canonical `nkp://[@vault_alias/]entry_path[#field]` secret reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NkpUri {
    /// Optional configured vault alias from `@vault_alias/`.
    pub vault_alias: Option<String>,
    /// Percent-decoded, slash-separated `KeePass` entry path or entry alias.
    pub entry_path: String,
    /// Optional percent-decoded field selector from `#field_name` (`#otp` for TOTP).
    pub field: Option<String>,
}

/// Returns `true` if `ch` is a Unicode bidirectional formatting character or
/// line/paragraph separator (`U+2028..=U+2029`).
#[must_use]
pub const fn is_bidi_or_line_separator(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Returns `true` when `value` contains no Unicode control characters (C0, DEL,
/// C1) and no bidirectional / line-separator spoofing characters.
#[must_use]
pub fn is_safe_display_text(value: &str) -> bool {
    !value
        .chars()
        .any(|ch| ch.is_control() || is_bidi_or_line_separator(ch))
}

/// Returns `true` when `value` contains no NUL, no bidirectional / line-separator
/// characters, and no control characters other than optional `'\n'`.
#[must_use]
pub fn is_valid_secret_text(value: &str, allow_newlines: bool) -> bool {
    !value.chars().any(|ch| {
        (ch.is_control() && !(allow_newlines && ch == '\n')) || is_bidi_or_line_separator(ch)
    })
}

/// Validates a vault alias name (`1..=128` ASCII `[A-Za-z0-9_-]`).
#[must_use]
pub fn is_valid_vault_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= MAX_VAULT_ALIAS_BYTES
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Validates a decoded `KeePass` entry path (`1..=1024` bytes, non-empty, no
/// leading/trailing `/`, no empty/`.`/`..` segments, and control/BiDi-free).
#[must_use]
pub fn is_valid_entry_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_ENTRY_PATH_BYTES
        && is_safe_display_text(path)
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_utf8(input: &str) -> Result<String, TemplateError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0_usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes
                .get(i + 1)
                .copied()
                .and_then(hex_nibble)
                .ok_or(TemplateError::InvalidPercentEncoding)?;
            let lo = bytes
                .get(i + 2)
                .copied()
                .and_then(hex_nibble)
                .ok_or(TemplateError::InvalidPercentEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| TemplateError::InvalidPercentEncoding)
}

/// Parses a canonical `nkp://[@vault_alias/]entry_path[#field_name]` URI.
///
/// # Errors
///
/// Returns [`TemplateError`] when the URI lacks the `nkp://` scheme, contains
/// an invalid `@vault_alias`, malformed `%HH` percent-encoding, empty/`.`/`..`
/// path segments, an empty/invalid `#field_name`, or control/BiDi characters.
pub fn parse_nkp_uri(input: &str) -> Result<NkpUri, TemplateError> {
    if !is_safe_display_text(input) {
        return Err(TemplateError::InvalidUri);
    }
    let rest = input
        .strip_prefix("nkp://")
        .ok_or(TemplateError::InvalidUri)?;

    let (path_part, field) = match rest.split_once('#') {
        Some((path_part, field_raw)) => {
            if field_raw.is_empty() || field_raw.contains('#') {
                return Err(TemplateError::InvalidFieldName);
            }
            let decoded = percent_decode_utf8(field_raw)?;
            if decoded.is_empty()
                || decoded.len() > MAX_FIELD_NAME_BYTES
                || decoded.contains('#')
                || !is_safe_display_text(&decoded)
            {
                return Err(TemplateError::InvalidFieldName);
            }
            (path_part, Some(decoded))
        }
        None => (rest, None),
    };

    let (vault_alias, entry_raw) = if let Some(after_at) = path_part.strip_prefix('@') {
        let (alias, remainder) = after_at
            .split_once('/')
            .ok_or(TemplateError::InvalidVaultAlias)?;
        if !is_valid_vault_alias(alias) {
            return Err(TemplateError::InvalidVaultAlias);
        }
        (Some(alias.to_owned()), remainder)
    } else {
        (None, path_part)
    };

    let entry_path = percent_decode_utf8(entry_raw)?;
    if !is_valid_entry_path(&entry_path) {
        return Err(TemplateError::InvalidEntryPath);
    }

    Ok(NkpUri {
        vault_alias,
        entry_path,
        field,
    })
}

/// Abstraction for resolving parsed [`NkpUri`] references to zeroizing secret
/// bytes without exposing vault internals to template or `.env` parsers.
pub trait SecretLookup {
    /// Resolves `uri` to its raw secret bytes wrapped in [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError`] when the vault alias, entry, field, or TOTP
    /// cannot be resolved unambiguously.
    fn resolve_secret(&mut self, uri: &NkpUri) -> Result<Zeroizing<Vec<u8>>, TemplateError>;
}

/// Bound entry alias target and optional default field name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryAlias {
    /// Canonical `KeePass` entry path inside the vault.
    pub target: String,
    /// Optional bound field used when the `nkp://` URI omits `#field`.
    pub field: Option<String>,
}

/// [`SecretLookup`] adapter backed by a live [`VaultService`] [`SessionId`],
/// a pinned UNIX timestamp for deterministic `#otp` TOTP evaluation, optional
/// vault alias bindings, and an entry alias map.
pub struct ServiceSecretLookup<'a> {
    service: &'a VaultService,
    session: SessionId,
    timestamp: u64,
    active_vault_alias: Option<String>,
    extra_vaults: BTreeMap<String, (&'a VaultService, SessionId)>,
    entry_aliases: BTreeMap<String, EntryAlias>,
}

impl fmt::Debug for ServiceSecretLookup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceSecretLookup")
            .field("session", &self.session)
            .field("timestamp", &self.timestamp)
            .field("active_vault_alias", &self.active_vault_alias)
            .field("extra_vault_count", &self.extra_vaults.len())
            .field("entry_alias_count", &self.entry_aliases.len())
            .finish()
    }
}

impl<'a> ServiceSecretLookup<'a> {
    /// Creates a new lookup adapter for an unlocked [`VaultService`] session
    /// with a single pinned UNIX `timestamp` (in seconds) for `#otp` TOTP codes.
    #[must_use]
    pub fn new(service: &'a VaultService, session: SessionId, timestamp: u64) -> Self {
        Self {
            service,
            session,
            timestamp,
            active_vault_alias: None,
            extra_vaults: BTreeMap::new(),
            entry_aliases: BTreeMap::new(),
        }
    }

    /// Associates a vault alias name with the primary `(service, session)`.
    ///
    /// If `alias` does not satisfy [`is_valid_vault_alias`], it is ignored so
    /// invalid aliases continue to fail closed.
    #[must_use]
    pub fn with_vault_alias(mut self, alias: impl Into<String>) -> Self {
        let alias = alias.into();
        if is_valid_vault_alias(&alias) {
            self.active_vault_alias = Some(alias);
        }
        self
    }

    /// Registers an additional unlocked vault session under `alias`.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::InvalidVaultAlias`] when `alias` violates
    /// [`is_valid_vault_alias`].
    pub fn add_vault(
        &mut self,
        alias: impl Into<String>,
        service: &'a VaultService,
        session: SessionId,
    ) -> Result<(), TemplateError> {
        let alias = alias.into();
        if !is_valid_vault_alias(&alias) {
            return Err(TemplateError::InvalidVaultAlias);
        }
        self.extra_vaults.insert(alias, (service, session));
        Ok(())
    }

    /// Replaces the entry alias map used to expand aliased entry paths and
    /// bound default fields.
    #[must_use]
    pub fn with_entry_aliases(mut self, aliases: BTreeMap<String, EntryAlias>) -> Self {
        self.entry_aliases = aliases;
        self
    }

    fn select_vault(
        &self,
        vault_alias: Option<&str>,
    ) -> Result<(&'a VaultService, SessionId), TemplateError> {
        match vault_alias {
            None => Ok((self.service, self.session)),
            Some(alias) => {
                if let Some(&(service, session)) = self.extra_vaults.get(alias) {
                    Ok((service, session))
                } else if self.active_vault_alias.as_deref() == Some(alias) {
                    Ok((self.service, self.session))
                } else {
                    Err(TemplateError::UnknownVaultAlias)
                }
            }
        }
    }
}

fn map_entry_service_error(err: ServiceError) -> TemplateError {
    match err {
        ServiceError::Locked => TemplateError::VaultLocked,
        ServiceError::Stale => TemplateError::StaleSession,
        ServiceError::NotFound => TemplateError::EntryNotFound,
        ServiceError::Ambiguous => TemplateError::AmbiguousEntry,
        ServiceError::RootGroup | ServiceError::InvalidInput => TemplateError::InvalidEntryPath,
        other => TemplateError::Service(other),
    }
}

fn map_field_service_error(err: ServiceError) -> TemplateError {
    match err {
        ServiceError::Locked => TemplateError::VaultLocked,
        ServiceError::Stale => TemplateError::StaleSession,
        ServiceError::NotFound => TemplateError::FieldNotFound,
        ServiceError::Ambiguous | ServiceError::AmbiguousField => TemplateError::AmbiguousField,
        ServiceError::InvalidOtp => TemplateError::InvalidOtp,
        ServiceError::HotpUnsupported => TemplateError::HotpUnsupported,
        other => TemplateError::Service(other),
    }
}

fn map_selector_error(err: SelectorError) -> TemplateError {
    match err {
        SelectorError::MalformedPath | SelectorError::RootGroup => TemplateError::InvalidEntryPath,
        SelectorError::AmbiguousGroup { .. } | SelectorError::AmbiguousEntry { .. } => {
            TemplateError::AmbiguousEntry
        }
        SelectorError::MissingGroup { .. } | SelectorError::NotFound => {
            TemplateError::EntryNotFound
        }
        SelectorError::Service(service_err) => map_entry_service_error(service_err),
    }
}

impl SecretLookup for ServiceSecretLookup<'_> {
    fn resolve_secret(&mut self, uri: &NkpUri) -> Result<Zeroizing<Vec<u8>>, TemplateError> {
        let (service, session) = self.select_vault(uri.vault_alias.as_deref())?;

        let (effective_path, bound_field) =
            if let Some(alias) = self.entry_aliases.get(&uri.entry_path) {
                if !is_valid_entry_path(&alias.target) {
                    return Err(TemplateError::InvalidEntryPath);
                }
                if alias.target != uri.entry_path {
                    match service.resolve_entry(session, &uri.entry_path) {
                        Ok(_) => return Err(TemplateError::AmbiguousEntry),
                        Err(ServiceError::NotFound) => {}
                        Err(err) => return Err(map_entry_service_error(err)),
                    }
                }
                (alias.target.as_str(), alias.field.as_deref())
            } else {
                (uri.entry_path.as_str(), None)
            };

        let effective_field = uri.field.as_deref().or(bound_field).unwrap_or("Password");
        if effective_field.is_empty()
            || effective_field.len() > MAX_FIELD_NAME_BYTES
            || !is_safe_display_text(effective_field)
        {
            return Err(TemplateError::InvalidFieldName);
        }

        if effective_field == "otp" {
            let resolved = service
                .resolve_entry_for_otp(session, effective_path)
                .map_err(map_selector_error)?;
            let code = service
                .totp_code_with_period(&resolved.reference(), self.timestamp)
                .map_err(map_field_service_error)?;
            Ok(Zeroizing::new(code.code().as_bytes().to_vec()))
        } else {
            let resolved = service
                .resolve_entry(session, effective_path)
                .map_err(map_entry_service_error)?;
            let bytes = service
                .reveal_field(&resolved.reference(), effective_field)
                .map_err(map_field_service_error)?;
            Ok(Zeroizing::new(bytes.as_slice().to_vec()))
        }
    }
}

/// Output escaping applied to resolved secret values during template rendering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ValueEscape {
    /// Emit validated secret text verbatim without quotes or escaping.
    #[default]
    Raw,
    /// Emit a double-quoted `.env` / JSON string literal (`"..."`), escaping
    /// `\`, `"`, and `\n`.
    DotenvDoubleQuoted,
}

/// Bounded configuration for [`render_text`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderOptions {
    /// Maximum allowed template input length in bytes (`1..=16 MiB`).
    pub max_input_bytes: usize,
    /// Maximum allowed rendered output length in bytes (`1..=64 MiB`).
    pub max_output_bytes: usize,
    /// Maximum allowed `nkp://` references (`1..=1024`).
    pub max_refs: usize,
    /// Whether `'\n'` is allowed in resolved secrets.
    pub allow_newlines: bool,
    /// Escaping strategy applied to each resolved secret.
    pub escape: ValueEscape,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            max_input_bytes: MAX_TEMPLATE_INPUT_BYTES,
            max_output_bytes: MAX_TEMPLATE_OUTPUT_BYTES,
            max_refs: MAX_TEMPLATE_REFS,
            allow_newlines: true,
            escape: ValueEscape::Raw,
        }
    }
}

impl RenderOptions {
    fn validate(&self) -> Result<(), TemplateError> {
        if self.max_input_bytes == 0
            || self.max_input_bytes > MAX_TEMPLATE_INPUT_BYTES
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_TEMPLATE_OUTPUT_BYTES
            || self.max_refs == 0
            || self.max_refs > MAX_TEMPLATE_REFS
        {
            return Err(TemplateError::InvalidOptions);
        }
        Ok(())
    }
}

enum TemplateChunk<'a> {
    Literal(&'a str),
    Reference(NkpUri),
}

const fn is_bare_uri_delimiter(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '\'' | '"' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ';' | ',' | '\\'
        )
}

fn scan_template(
    input: &str,
    max_input_bytes: usize,
    max_refs: usize,
    mut on_chunk: impl FnMut(TemplateChunk<'_>) -> Result<(), TemplateError>,
) -> Result<(), TemplateError> {
    if input.len() > max_input_bytes {
        return Err(TemplateError::InputTooLarge);
    }

    let bytes = input.as_bytes();
    let mut cursor = 0_usize;
    let mut ref_count = 0_usize;

    while let Some(rel_pos) = input[cursor..].find("nkp://") {
        let scheme_pos = cursor + rel_pos;
        let is_braced = scheme_pos >= cursor + 2 && &bytes[scheme_pos - 2..scheme_pos] == b"{{";

        let literal_end = if is_braced {
            scheme_pos - 2
        } else {
            scheme_pos
        };
        if literal_end > cursor {
            on_chunk(TemplateChunk::Literal(&input[cursor..literal_end]))?;
        }

        ref_count += 1;
        if ref_count > max_refs {
            return Err(TemplateError::TooManyReferences);
        }

        if is_braced {
            let after_scheme = scheme_pos + "nkp://".len();
            let rel_close = input[after_scheme..]
                .find("}}")
                .ok_or(TemplateError::UnterminatedReference)?;
            let uri_end = after_scheme + rel_close;
            let uri = parse_nkp_uri(&input[scheme_pos..uri_end])?;
            on_chunk(TemplateChunk::Reference(uri))?;
            cursor = uri_end + 2;
        } else {
            let after_scheme = scheme_pos + "nkp://".len();
            let uri_end = input[after_scheme..]
                .find(is_bare_uri_delimiter)
                .map_or(input.len(), |rel| after_scheme + rel);
            let uri = parse_nkp_uri(&input[scheme_pos..uri_end])?;
            on_chunk(TemplateChunk::Reference(uri))?;
            cursor = uri_end;
        }
    }

    if cursor < input.len() {
        on_chunk(TemplateChunk::Literal(&input[cursor..]))?;
    }

    Ok(())
}

/// Extracts and validates all `nkp://` references from `input` without
/// querying any secret lookup backend.
///
/// Suitable for `--check` / dry-run inspection without disclosing secrets.
///
/// # Errors
///
/// Returns [`TemplateError`] if `input` exceeds [`MAX_TEMPLATE_INPUT_BYTES`],
/// references exceed [`MAX_TEMPLATE_REFS`], any `{{nkp://...` is unclosed, or
/// any `nkp://` URI fails validation.
pub fn extract_references(input: &str) -> Result<Vec<NkpUri>, TemplateError> {
    let mut refs = Vec::new();
    scan_template(
        input,
        MAX_TEMPLATE_INPUT_BYTES,
        MAX_TEMPLATE_REFS,
        |chunk| {
            if let TemplateChunk::Reference(uri) = chunk {
                refs.push(uri);
            }
            Ok(())
        },
    )?;
    Ok(refs)
}

fn push_bounded(
    output: &mut Zeroizing<String>,
    text: &str,
    max_output_bytes: usize,
) -> Result<(), TemplateError> {
    let next_len = output
        .len()
        .checked_add(text.len())
        .ok_or(TemplateError::OutputTooLarge)?;
    if next_len > max_output_bytes {
        return Err(TemplateError::OutputTooLarge);
    }
    output.push_str(text);
    Ok(())
}

fn push_dotenv_double_quoted(
    output: &mut Zeroizing<String>,
    secret: &str,
    max_output_bytes: usize,
) -> Result<(), TemplateError> {
    let mut extra = 2_usize; // opening and closing '"'
    for byte in secret.bytes() {
        extra = extra
            .checked_add(match byte {
                b'\\' | b'"' | b'\n' => 2,
                _ => 1,
            })
            .ok_or(TemplateError::OutputTooLarge)?;
    }
    let next_len = output
        .len()
        .checked_add(extra)
        .ok_or(TemplateError::OutputTooLarge)?;
    if next_len > max_output_bytes {
        return Err(TemplateError::OutputTooLarge);
    }

    output.push('"');
    for ch in secret.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            other => output.push(other),
        }
    }
    output.push('"');
    Ok(())
}

/// Renders `input` in a single left-to-right non-recursive pass, resolving all
/// bare `nkp://...` and braced `{{nkp://...}}` references via `lookup`.
///
/// Resolved secret bytes are validated as UTF-8 with no NUL, disallowed control
/// characters, or bidirectional controls, and are **never** re-scanned for `nkp://`
/// tokens. Fails closed atomically before returning any output.
///
/// # Errors
///
/// Returns [`TemplateError`] when options, bounds, URI syntax, secret lookup,
/// UTF-8 decoding, or control/BiDi character validation fails.
pub fn render_text(
    input: &str,
    lookup: &mut dyn SecretLookup,
    options: &RenderOptions,
) -> Result<Zeroizing<String>, TemplateError> {
    options.validate()?;

    let mut output = Zeroizing::new(String::with_capacity(
        input.len().min(64 * 1024).min(options.max_output_bytes),
    ));

    scan_template(
        input,
        options.max_input_bytes,
        options.max_refs,
        |chunk| match chunk {
            TemplateChunk::Literal(text) => {
                push_bounded(&mut output, text, options.max_output_bytes)
            }
            TemplateChunk::Reference(uri) => {
                let raw_secret = lookup.resolve_secret(&uri)?;
                let secret_str =
                    std::str::from_utf8(&raw_secret).map_err(|_| TemplateError::NonUtf8Secret)?;
                if !is_valid_secret_text(secret_str, options.allow_newlines) {
                    return Err(TemplateError::UnsafeSecretCharacters);
                }
                match options.escape {
                    ValueEscape::Raw => {
                        push_bounded(&mut output, secret_str, options.max_output_bytes)
                    }
                    ValueEscape::DotenvDoubleQuoted => {
                        push_dotenv_double_quoted(&mut output, secret_str, options.max_output_bytes)
                    }
                }
            }
        },
    )?;

    Ok(output)
}
