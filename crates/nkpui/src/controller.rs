//! Pure, GPU-independent state and controller logic for `nkpui`.
//!
//! Keeps vault session ownership, credential zeroization, database creation,
//! group/entry CRUD, entry editing, search/tree navigation, explicit secret
//! reveal, attachment handling, `.env`/template injection, and dirty-vault
//! focus/idle lock transitions cleanly separated from Rune view rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use neotales_keepass::KdbxWriteOptions;
use neotales_keepass::{
    CredentialProvider, KdbxCredentials, OtpAlgorithm, OtpDigits, OtpEncoder, OtpKind, OtpUri,
    read_key_file,
};
use nkeepass::env_file::{EnvLine, EnvValueKind, parse_env_file, resolve_env_file};
use nkeepass::icons::{DEFAULT_GROUP_ICON_ID, is_valid_standard_icon_id};
use nkeepass::password_generator::Policy;
use nkeepass::private_file::write_private_noclobber;
use nkeepass::service::FieldUpdate;
use nkeepass::template::{
    NkpUri, RenderOptions, ServiceSecretLookup, TemplateError, ValueEscape, extract_references,
    is_safe_display_text, render_text,
};
use nkeepass::{
    AttachmentDescriptor, CustomIconId, CustomIconSummary, DatabaseSettings,
    DatabaseSettingsUpdate, EntryRef, GroupRef, GroupTreeNode, KDBX_LIMITS, OtpConfig, OtpMetadata,
    PathCompletion, SearchHit, SelectedEntry, ServiceError, ServiceOtpAlgorithm, ServiceOtpKind,
    SessionId, TreeGroup, VaultService,
};
use zeroize::Zeroizing;

/// Default idle duration in seconds before an unlocked session locks automatically (`5 minutes`).
pub const DEFAULT_AUTO_LOCK_SECS: f64 = 300.0;

/// Selectable auto-lock timeout presets (`1m`, `5m`, `10m`, `15m`, `30m`, `Never`).
pub const AUTO_LOCK_PRESETS: &[(Option<f64>, &str)] = &[
    (Some(60.0), "1m (60s)"),
    (Some(300.0), "5m (300s)"),
    (Some(600.0), "10m (600s)"),
    (Some(900.0), "15m (900s)"),
    (Some(1800.0), "30m (1800s)"),
    (None, "Never"),
];

/// Maximum attachment file size accepted when attaching a binary (`16 MiB`).
pub const MAX_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum template/env file size loaded into the Inject view (`1 MiB`).
pub const MAX_INJECT_FILE_BYTES: u64 = 1024 * 1024;

/// Default generated password length in characters.
pub const GENERATED_PASSWORD_LEN: usize = 20;

/// Standard `KeePass` tag marking a favorite entry.
pub const FAVORITE_TAG: &str = "favorite";

/// Maximum number of recent in-session vault paths shown on the lock screen.
pub const MAX_RECENT_VAULTS: usize = 8;

/// Maximum number of configured vault shortcuts loaded from `config.json`.
pub const MAX_CONFIGURED_VAULTS: usize = 32;

/// Maximum byte length of a configured vault display label.
pub const MAX_CONFIGURED_LABEL_BYTES: usize = 64;

/// Maximum byte length of a configured vault path.
pub const MAX_CONFIGURED_PATH_BYTES: usize = 4096;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Current lock lifecycle phase of the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPhase {
    /// No active vault session or credentials are held in memory.
    Locked,
    /// A background worker thread is executing KDF + KDBX open or create.
    Unlocking,
    /// A vault session and its owned credentials are active.
    Unlocked,
}

/// Lock screen operation mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LockMode {
    /// Unlock an existing `.kdbx` database.
    #[default]
    Open,
    /// Create a new `.kdbx` database and unlock it.
    Create,
}

/// Active workspace view inside an unlocked vault.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceTab {
    /// Group sidebar, searchable entry list, and entry detail/editor pane.
    #[default]
    Browser,
    /// Template and `.env` `nkp://` reference inspector and renderer.
    Inject,
}

/// Rendering mode for the Inject tool view.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InjectMode {
    /// Arbitrary text template using [`render_text`].
    #[default]
    Template,
    /// Non-executing `.env` document using [`parse_env_file`] and [`resolve_env_file`].
    EnvFile,
}

/// Cause of a vault lock request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockTrigger {
    /// User clicked the Lock button.
    Manual,
    /// Desktop window lost focus.
    FocusLoss,
    /// Inactivity timer ([`DEFAULT_AUTO_LOCK_SECS`] or configured preset) elapsed.
    IdleTimeout,
}

/// Pending user decision when a lock is requested while the vault has unsaved changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLockDecision {
    /// Original trigger that opened the unsaved-changes modal.
    pub trigger: LockTrigger,
    /// Whether `Save & Lock` is waiting on an in-flight save operation.
    pub save_requested: bool,
    /// Non-secret error message from a failed save attempt, if any.
    pub error: Option<String>,
}

/// Current TOTP code and remaining window metadata for the selected entry.
#[derive(Clone, Eq, PartialEq)]
pub struct TotpDisplay {
    /// Generated TOTP digits held in a zeroizing buffer.
    pub code: Zeroizing<String>,
    /// Seconds remaining until the current period expires.
    pub remaining_secs: u64,
    /// TOTP period in seconds.
    pub period: u64,
}

impl fmt::Debug for TotpDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpDisplay")
            .field("code", &"[REDACTED]")
            .field("remaining_secs", &self.remaining_secs)
            .field("period", &self.period)
            .finish()
    }
}

/// Explicitly revealed field secret in Detail view, safely distinguishing empty
/// text and non-UTF-8 binary payloads.
#[derive(Clone, Eq, PartialEq)]
pub enum RevealedSecret {
    /// Valid UTF-8 text (may be empty `""`).
    Text(Zeroizing<String>),
    /// Non-UTF-8 binary payload with a bounded zeroizing hex preview.
    NonUtf8 {
        /// Exact byte length of the underlying protected field.
        byte_len: usize,
        /// Safe read-only preview string stored in zeroizing memory.
        preview: Zeroizing<String>,
    },
}

impl fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f
                .debug_struct("RevealedSecret::Text")
                .field("is_empty", &text.is_empty())
                .finish_non_exhaustive(),
            Self::NonUtf8 { byte_len, .. } => f
                .debug_struct("RevealedSecret::NonUtf8")
                .field("byte_len", byte_len)
                .finish_non_exhaustive(),
        }
    }
}

impl RevealedSecret {
    /// Converts raw revealed bytes into either UTF-8 text or a bounded non-UTF-8 preview.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self::Text(Zeroizing::new(text.to_owned())),
            Err(_) => Self::NonUtf8 {
                byte_len: bytes.len(),
                preview: format_non_utf8_preview(bytes),
            },
        }
    }

    /// Returns the revealed UTF-8 text slice, or `None` for non-UTF-8 binary fields.
    #[cfg(test)]
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text.as_str()),
            Self::NonUtf8 { .. } => None,
        }
    }
}

/// Formats a bounded read-only hex preview for non-UTF-8 protected bytes inside [`Zeroizing`].
#[must_use]
pub fn format_non_utf8_preview(bytes: &[u8]) -> Zeroizing<String> {
    use std::fmt::Write as _;
    const MAX_PREVIEW_BYTES: usize = 24;
    let mut out = Zeroizing::new(format!("[non-UTF-8 binary, {} bytes] ", bytes.len()));
    for (idx, byte) in bytes.iter().take(MAX_PREVIEW_BYTES).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > MAX_PREVIEW_BYTES {
        out.push_str(" ...");
    }
    out
}

/// Validates that `raw` is an `http://` or `https://` URL safe to pass to `Tx::open_url`.
#[must_use]
pub fn validate_http_url(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 4096
        || trimmed.chars().any(char::is_control)
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    Some(trimmed)
}

/// Guided OTP configuration mode in the Entry Editor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OtpEditorMode {
    /// No OTP configured (removes `"otp"` on Apply if previously present).
    #[default]
    None,
    /// Structured time-based OTP (`TOTP`).
    Totp,
    /// Structured counter-based OTP (`HOTP`).
    Hotp,
    /// Raw `otpauth://...` URI editor.
    RawUri,
}

/// Structured OTP draft parameters inside [`EntryEditorState`].
#[derive(Clone, Eq, PartialEq)]
pub struct OtpDraftConfig {
    /// Active OTP editor mode.
    pub mode: OtpEditorMode,
    /// Base32-encoded OTP secret in zeroizing memory.
    pub secret: Zeroizing<String>,
    /// HMAC digest algorithm.
    pub algorithm: ServiceOtpAlgorithm,
    /// Generated code digit count (`6` or `8`; `5` when `steam == true`).
    pub digits: u8,
    /// TOTP step period in seconds.
    pub period: u64,
    /// HOTP counter value.
    pub counter: u64,
    /// Whether Steam Guard 5-character encoding is active.
    pub steam: bool,
}

impl Default for OtpDraftConfig {
    fn default() -> Self {
        Self {
            mode: OtpEditorMode::None,
            secret: Zeroizing::new(String::new()),
            algorithm: ServiceOtpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            steam: false,
        }
    }
}

impl fmt::Debug for OtpDraftConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpDraftConfig")
            .field("mode", &self.mode)
            .field("has_secret", &!self.secret.is_empty())
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .field("steam", &self.steam)
            .finish()
    }
}

/// Flattened visible row for the collapsible `TreeView` group sidebar.
#[derive(Clone, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent recycle-bin, children, expansion, and root display flags"
)]
pub struct VisibleTreeGroup {
    /// Opaque session-bound group handle.
    pub reference: GroupRef,
    /// Safe group display name.
    pub label: String,
    /// Normalized root-prefixed group path (matches `GroupTreeNode::path`).
    pub path: String,
    /// Nesting depth (`0` for root).
    pub depth: usize,
    /// Standard `KeePass` 2.x icon ID.
    pub icon_id: u32,
    /// Optional embedded custom icon UUID.
    pub custom_icon_id: Option<CustomIconId>,
    /// Direct entry count inside this group.
    pub entry_count: usize,
    /// Whether this group is the configured Recycle Bin.
    pub is_recycle_bin: bool,
    /// Whether this group has child subgroups.
    pub has_children: bool,
    /// Whether child subgroups are currently expanded.
    pub expanded: bool,
    /// Whether this row is the root group.
    pub is_root: bool,
}

impl fmt::Debug for VisibleTreeGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VisibleTreeGroup")
            .field("label", &self.label)
            .field("path", &self.path)
            .field("depth", &self.depth)
            .field("entry_count", &self.entry_count)
            .field("is_recycle_bin", &self.is_recycle_bin)
            .field("expanded", &self.expanded)
            .finish_non_exhaustive()
    }
}

/// Non-secret detail projection plus explicit reveal state for one entry.
pub struct EntryDetailState {
    /// Session-scoped reference to the selected entry.
    pub entry_ref: EntryRef,
    /// Canonical path projection shown in the header.
    pub path: String,
    /// Allowlisted entry metadata from [`VaultService::selected_entry`].
    pub metadata: SelectedEntry,
    /// Allowlisted attachment descriptors including `protected` flag and [`nkeepass::AttachmentRef`].
    pub attachments: Vec<AttachmentDescriptor>,
    /// Non-protected username text, if unprotected and present.
    pub username: String,
    /// Non-protected URL text, if unprotected and present.
    pub url: String,
    /// Non-protected notes text, if unprotected and present.
    pub notes: String,
    /// Standard text fields (`UserName`, `URL`, `Notes`) marked `protected` by the vault.
    pub protected_standard_fields: BTreeMap<&'static str, bool>,
    /// Explicitly revealed protected standard field buffers, cleared on switch or lock.
    pub revealed_standard_fields: BTreeMap<&'static str, RevealedSecret>,
    /// Explicitly revealed password buffer, cleared on entry switch or lock.
    pub revealed_password: Option<RevealedSecret>,
    /// Explicitly revealed custom field values keyed by custom-field index.
    pub revealed_custom_fields: BTreeMap<usize, RevealedSecret>,
    /// Non-sensitive OTP configuration metadata when configured.
    pub otp_meta: Option<OtpMetadata>,
    /// Current TOTP code when `otp_meta` is [`ServiceOtpKind::Totp`].
    pub totp: Option<TotpDisplay>,
    /// Most recently generated HOTP code (zeroized on switch or lock).
    pub hotp_code: Option<Zeroizing<String>>,
    /// Whether this entry currently resides inside the Recycle Bin.
    pub is_in_recycle_bin: bool,
}

impl fmt::Debug for EntryDetailState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDetailState")
            .field("path", &self.path)
            .field("title", &self.metadata.title())
            .field("attachment_count", &self.attachments.len())
            .field("has_revealed_password", &self.revealed_password.is_some())
            .field(
                "revealed_custom_field_count",
                &self.revealed_custom_fields.len(),
            )
            .field("has_totp", &self.totp.is_some())
            .finish_non_exhaustive()
    }
}

/// Editable draft for one custom string field in [`EntryEditorState`].
#[derive(Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent draft protection, reveal, origin, and snapshot flags"
)]
pub struct EditableCustomField {
    /// Custom field key name.
    pub name: String,
    /// Field value held in zeroizing memory.
    pub value: Zeroizing<String>,
    /// Safe read-only preview when the underlying KDBX field contains non-UTF-8 bytes.
    pub non_utf8_preview: Option<Zeroizing<String>>,
    /// Whether the field is protected in the KDBX inner stream.
    pub protected: bool,
    /// Whether the field value is currently unmasked in the editor.
    pub revealed: bool,
    /// Whether this custom field was added in the current editor session.
    pub is_new: bool,
    original_value: Zeroizing<String>,
    original_protected: bool,
}

impl fmt::Debug for EditableCustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EditableCustomField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("protected", &self.protected)
            .field("revealed", &self.revealed)
            .field("is_new", &self.is_new)
            .finish_non_exhaustive()
    }
}

/// Non-secret configured vault entry discovered from `nkp`'s `config.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredVault {
    /// Friendly alias or role label (e.g. `"work"`, `"Default"`).
    pub label: String,
    /// Configured filesystem path to the `.kdbx` vault.
    pub path: String,
}

/// Editable draft state for the currently selected entry.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent protection and reveal flags for standard entry fields"
)]
pub struct EntryEditorState {
    /// Session-scoped reference to the entry being edited.
    pub entry_ref: EntryRef,
    /// Canonical entry path when editing began.
    pub path: String,
    /// Draft standard `KeePass` 2.x icon ID (`0..=68`).
    pub icon_id: u32,
    /// Draft custom icon UUID when preserved from the vault.
    pub custom_icon_id: Option<CustomIconId>,
    /// Whether the user explicitly selected a new standard icon in the editor.
    pub icon_changed: bool,
    /// Draft entry title.
    pub title: String,
    /// Draft `UserName` field.
    pub username: Zeroizing<String>,
    /// Safe read-only preview if `UserName` contains non-UTF-8 bytes.
    pub username_non_utf8: Option<Zeroizing<String>>,
    /// Whether `UserName` is protected.
    pub username_protected: bool,
    /// Draft `Password` field.
    pub password: Zeroizing<String>,
    /// Safe read-only preview if `Password` contains non-UTF-8 bytes.
    pub password_non_utf8: Option<Zeroizing<String>>,
    /// Whether `Password` is unmasked in the editor.
    pub password_revealed: bool,
    /// Draft `URL` field.
    pub url: Zeroizing<String>,
    /// Safe read-only preview if `URL` contains non-UTF-8 bytes.
    pub url_non_utf8: Option<Zeroizing<String>>,
    /// Whether `URL` is protected.
    pub url_protected: bool,
    /// Draft `Notes` field.
    pub notes: Zeroizing<String>,
    /// Safe read-only preview if `Notes` contains non-UTF-8 bytes.
    pub notes_non_utf8: Option<Zeroizing<String>>,
    /// Whether `Notes` is protected.
    pub notes_protected: bool,
    /// Draft `otpauth://` URI stored in the protected `"otp"` field.
    pub otp_uri: Zeroizing<String>,
    /// Safe read-only preview if `"otp"` contains non-UTF-8 bytes.
    pub otp_non_utf8: Option<Zeroizing<String>>,
    /// Whether `otp_uri` is currently unmasked in the editor.
    pub otp_revealed: bool,
    /// Guided OTP draft parameters (`None`, `Totp`, `Hotp`, or `RawUri`).
    pub otp_config: OtpDraftConfig,
    /// Draft tag list.
    pub tags: Vec<String>,
    /// Draft custom string fields.
    pub custom_fields: Vec<EditableCustomField>,
    /// Existing custom field names staged for removal on Apply.
    pub removed_custom_fields: Vec<String>,
    original_icon_id: u32,
    original_custom_icon_id: Option<CustomIconId>,
    original_title: String,
    original_username: Zeroizing<String>,
    original_username_protected: bool,
    original_password: Zeroizing<String>,
    original_url: Zeroizing<String>,
    original_url_protected: bool,
    original_notes: Zeroizing<String>,
    original_notes_protected: bool,
    original_otp_uri: Zeroizing<String>,
    original_otp_config: OtpDraftConfig,
    had_otp_field: bool,
    original_tags: Vec<String>,
}

impl fmt::Debug for EntryEditorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryEditorState")
            .field("path", &self.path)
            .field("icon_id", &self.icon_id)
            .field("title", &self.title)
            .field("password", &"[REDACTED]")
            .field("has_otp_uri", &!self.otp_uri.is_empty())
            .field("custom_field_count", &self.custom_fields.len())
            .field("removed_custom_count", &self.removed_custom_fields.len())
            .finish_non_exhaustive()
    }
}

/// Explicit lock screen field attribution for status/error diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LockErrorField {
    /// No error or status active.
    #[default]
    None,
    /// Informational status notice (not an error).
    Info,
    /// Error relates to the `.kdbx` vault path.
    Vault,
    /// Error relates to the master password or confirmation.
    Master,
    /// Error relates to the key file path or contents.
    KeyFile,
    /// Error relates to the combined credentials (password and optional key file).
    Credentials,
}

/// Result returned by a background unlock or create worker task.
pub struct UnlockOutcome {
    /// Opened service instance, active session, and owned credentials (or diagnostic message).
    pub result: Result<(VaultService, SessionId, KdbxCredentials), String>,
    /// Explicit target field attribution when `result` is `Err`.
    pub error_field: LockErrorField,
}

impl fmt::Debug for UnlockOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockOutcome")
            .field("ok", &self.result.is_ok())
            .field("error_field", &self.error_field)
            .finish()
    }
}

/// Result returned by a background save worker task.
pub struct SaveOutcome {
    /// Generation identifier matching [`VaultController::save_generation`].
    pub generation: u64,
    /// Returned service instance (reinstalled if unlocked, dropped if already locked).
    pub service: VaultService,
    /// Returned credentials (reinstalled on unlocked/failure, dropped on lock).
    pub credentials: KdbxCredentials,
    /// Save success or non-secret diagnostic message.
    pub result: Result<(), String>,
}

impl fmt::Debug for SaveOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveOutcome")
            .field("generation", &self.generation)
            .field("credentials", &self.credentials)
            .field("ok", &self.result.is_ok())
            .finish_non_exhaustive()
    }
}

/// Outcome of locking the vault so the UI shell can mirror cleanup into widgets/clipboard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockCleanup {
    /// Whether an active or in-flight session was cleared.
    pub locked_active_session: bool,
    /// Whether any timed secret clipboard lease should also be cleared immediately.
    pub clear_clipboard: bool,
}

/// Pure application state and controller for `nkpui`.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent session dirty, saving, status error, and reveal flags"
)]
pub struct VaultController {
    /// Current lock phase.
    pub phase: VaultPhase,
    /// Current lock screen mode (`Open` vs `Create`).
    pub lock_mode: LockMode,
    /// Path to the `.kdbx` vault file.
    pub vault_path: String,
    /// Optional path to a `KeePass` key file.
    pub key_file_path: String,
    /// Non-secret status or error message for the lock screen.
    pub lock_status: Option<String>,
    /// Explicit field attribution for `lock_status`.
    pub lock_error_field: LockErrorField,
    /// Active workspace tab when unlocked.
    pub active_tab: WorkspaceTab,
    /// Whether the live vault has unsaved in-memory mutations.
    pub dirty: bool,
    /// Whether a background save worker is currently writing the vault to disk.
    pub saving: bool,
    /// Pending dirty-vault lock decision modal state.
    pub pending_lock_decision: Option<PendingLockDecision>,
    /// Search query string inside the browser view.
    pub search_query: String,
    /// Breadcrumb stack of visited groups `(label, GroupRef)` starting from root.
    pub breadcrumbs: Vec<(String, GroupRef)>,
    /// Standard and custom icon metadata matching each entry in `breadcrumbs`.
    pub breadcrumb_icons: Vec<(u32, Option<CustomIconId>)>,
    /// Whether the entry list is filtered to entries tagged `"favorite"`.
    pub favorites_only: bool,
    /// Non-secret vault aliases/paths read-only loaded from `nkp`'s `config.json`.
    pub configured_vaults: Vec<ConfiguredVault>,
    /// In-session recently unlocked or created `.kdbx` paths (MRU).
    pub recent_vaults: Vec<String>,
    /// Selected length for the Entry Editor password generator.
    pub gen_length: usize,
    /// Selected character classes for the Entry Editor password generator.
    pub gen_policy: Policy,
    /// Direct child groups of the currently selected group (empty during search).
    pub child_groups: Vec<TreeGroup>,
    /// Visible entry hits for the current group or search query.
    pub entries: Vec<SearchHit>,
    /// Index of the selected entry in `entries`.
    pub selected_index: Option<usize>,
    /// Detail state for the currently selected entry.
    pub detail: Option<EntryDetailState>,
    /// Active Entry Editor state when editing the selected entry.
    pub editor: Option<EntryEditorState>,
    /// Non-secret status message for browser operations.
    pub browser_status: Option<String>,
    /// Whether `browser_status` represents an error (`true`) vs informational notice (`false`).
    pub browser_status_is_error: bool,
    /// Current inject view mode (`Template` vs `EnvFile`).
    pub inject_mode: InjectMode,
    /// Raw template or `.env` source text.
    pub inject_input: String,
    /// Target private file path for saving rendered output without clobbering.
    pub inject_save_path: String,
    /// Extracted `nkp://` references from `inject_input`.
    pub extracted_refs: Vec<NkpUri>,
    /// Validated `.env` assignments when in [`InjectMode::EnvFile`].
    pub parsed_env_lines: Vec<EnvLine>,
    /// Non-secret parse/validation error for `inject_input`.
    pub inject_preview_error: Option<String>,
    /// Rendered output buffer held in [`Zeroizing`] until cleared or locked.
    pub rendered_output: Option<Zeroizing<String>>,
    /// Whether `rendered_output` is shown unmasked in the UI.
    pub inject_output_revealed: bool,
    /// Non-secret status message for the inject view.
    pub inject_status: Option<String>,
    /// Whether `inject_status` represents an error (`true`) vs informational notice (`false`).
    pub inject_status_is_error: bool,
    /// Last user interaction timestamp (monotonic seconds from runtime clock).
    pub last_activity_secs: f64,
    /// Configurable idle auto-lock timeout in seconds (`None` disables idle lock).
    pub auto_lock_secs: Option<f64>,
    /// Opt-in flag to automatically lock the vault on window focus loss (default `false`).
    pub lock_on_focus_loss: bool,
    /// Full hierarchical group tree loaded from [`VaultService::group_tree`].
    pub group_tree: Option<GroupTreeNode>,
    /// Expanded group paths in the collapsible `TreeView` sidebar.
    pub expanded_groups: BTreeSet<String>,
    /// Full path of the currently active group in [`Self::group_tree`].
    pub current_group_path: String,
    /// Whether the open database has the Recycle Bin enabled.
    pub recycle_bin_enabled: bool,
    service: VaultService,
    session: Option<SessionId>,
    credentials: Option<KdbxCredentials>,
    unlock_generation: u64,
    save_generation: u64,
}

impl fmt::Debug for VaultController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultController")
            .field("phase", &self.phase)
            .field("lock_mode", &self.lock_mode)
            .field("vault_path", &self.vault_path)
            .field("dirty", &self.dirty)
            .field("saving", &self.saving)
            .field("has_pending_lock", &self.pending_lock_decision.is_some())
            .field("has_session", &self.session.is_some())
            .field("has_credentials", &self.credentials.is_some())
            .field("active_tab", &self.active_tab)
            .field("entry_count", &self.entries.len())
            .field("selected_index", &self.selected_index)
            .field("has_detail", &self.detail.is_some())
            .field("has_editor", &self.editor.is_some())
            .field("has_rendered_output", &self.rendered_output.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for VaultController {
    fn default() -> Self {
        Self {
            phase: VaultPhase::Locked,
            lock_mode: LockMode::Open,
            vault_path: String::new(),
            key_file_path: String::new(),
            lock_status: None,
            lock_error_field: LockErrorField::None,
            active_tab: WorkspaceTab::Browser,
            dirty: false,
            saving: false,
            pending_lock_decision: None,
            search_query: String::new(),
            breadcrumbs: Vec::new(),
            breadcrumb_icons: Vec::new(),
            favorites_only: false,
            configured_vaults: Vec::new(),
            recent_vaults: Vec::new(),
            gen_length: GENERATED_PASSWORD_LEN,
            gen_policy: Policy {
                upper: true,
                lower: true,
                digits: true,
                symbols: true,
            },
            child_groups: Vec::new(),
            entries: Vec::new(),
            selected_index: None,
            detail: None,
            editor: None,
            browser_status: None,
            browser_status_is_error: false,
            inject_mode: InjectMode::Template,
            inject_input: String::from("export API_TOKEN=nkp://Example/API#Password\n"),
            inject_save_path: String::new(),
            extracted_refs: Vec::new(),
            parsed_env_lines: Vec::new(),
            inject_preview_error: None,
            rendered_output: None,
            inject_output_revealed: false,
            inject_status: None,
            inject_status_is_error: false,
            last_activity_secs: 0.0,
            auto_lock_secs: Some(DEFAULT_AUTO_LOCK_SECS),
            lock_on_focus_loss: false,
            group_tree: None,
            expanded_groups: BTreeSet::new(),
            current_group_path: String::new(),
            recycle_bin_enabled: true,
            service: VaultService::default(),
            session: None,
            credentials: None,
            unlock_generation: 0,
            save_generation: 0,
        }
    }
}

/// Returns the current UNIX timestamp in whole seconds.
#[must_use]
pub fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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

fn open_regular_file_nofollow(
    path: &Path,
    label: &str,
) -> Result<(File, std::fs::Metadata), String> {
    let lmeta = std::fs::symlink_metadata(path).map_err(|_| format!("cannot access {label}"))?;
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file (symlinks and special files are refused)"
        ));
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_o_nofollow() | unix_o_nonblock());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts
        .open(path)
        .map_err(|_| format!("cannot open {label}"))?;
    let meta = file
        .metadata()
        .map_err(|_| format!("cannot inspect {label}"))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != lmeta.dev() || meta.ino() != lmeta.ino() {
            return Err(format!("{label} changed while opening"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(format!(
                "{label} must be a regular file (reparse points are refused)"
            ));
        }
    }
    Ok((file, meta))
}

fn ensure_vault_regular_file(path: &Path) -> Result<(), String> {
    // Allow valid symlinked vaults (e.g. dotfiles managers), while rejecting
    // FIFOs, directories, and device nodes without blocking on open().
    let meta = std::fs::metadata(path).map_err(|_| String::from("cannot access vault file"))?;
    if !meta.is_file() {
        return Err(String::from("vault file is not a regular file"));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_o_nonblock());
    }
    let file = opts
        .open(path)
        .map_err(|_| String::from("cannot open vault file"))?;
    let fmeta = file
        .metadata()
        .map_err(|_| String::from("cannot inspect vault file"))?;
    if !fmeta.file_type().is_file() {
        return Err(String::from("vault file is not a regular file"));
    }
    Ok(())
}

fn build_credentials(
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
) -> Result<KdbxCredentials, (LockErrorField, String)> {
    let mut providers: Vec<Box<dyn CredentialProvider + Send>> = Vec::new();
    if let Some(key_path) = key_file_path {
        let (file, _meta) = open_regular_file_nofollow(key_path, "key file")
            .map_err(|msg| (LockErrorField::KeyFile, msg))?;
        let Ok(key_file) = read_key_file(file) else {
            return Err((LockErrorField::KeyFile, String::from("invalid key file")));
        };
        providers.push(Box::new(key_file));
    }

    let password_bytes = (!password.is_empty()).then(|| password.as_bytes());
    KdbxCredentials::from_parts(password_bytes, providers).map_err(|_| {
        (
            LockErrorField::Credentials,
            String::from("enter a master password or select a key file"),
        )
    })
}

/// Reads a regular attachment source file bounded to [`MAX_ATTACHMENT_BYTES`] (`16 MiB`),
/// refusing symlinks, Windows reparse points, FIFOs, and special files.
///
/// # Errors
///
/// Returns a fixed diagnostic if the path cannot be opened, is a symlink or
/// non-regular file, or exceeds [`MAX_ATTACHMENT_BYTES`].
pub fn read_attachment_file_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let (file, meta) = open_regular_file_nofollow(path, "attachment source")?;
    if meta.len() > MAX_ATTACHMENT_BYTES {
        return Err(String::from("attachment exceeds 16 MiB size limit"));
    }
    let max_bytes = usize::try_from(MAX_ATTACHMENT_BYTES).unwrap_or(usize::MAX);
    let capacity = usize::try_from(meta.len())
        .unwrap_or(0)
        .min(max_bytes)
        .saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_ATTACHMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| String::from("cannot read attachment file"))?;
    if bytes.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(String::from("attachment exceeds 16 MiB size limit"));
    }
    Ok(bytes)
}

/// Appends `.kdbx` when `path` has no file extension, preserving chosen extensions.
#[must_use]
pub fn ensure_kdbx_extension(path: PathBuf) -> PathBuf {
    if path.as_os_str().is_empty() || path.extension().is_some() {
        path
    } else {
        path.with_extension("kdbx")
    }
}

/// Reads a UTF-8 template or `.env` source file bounded to [`MAX_INJECT_FILE_BYTES`] (`1 MiB`),
/// refusing symlinks, Windows reparse points, FIFOs, and special files.
///
/// # Errors
///
/// Returns a fixed diagnostic if the file cannot be opened, exceeds `1 MiB`,
/// or is not valid UTF-8.
pub fn read_inject_file_bounded(path: &Path) -> Result<String, String> {
    let (file, meta) = open_regular_file_nofollow(path, "template/env file")?;
    if meta.len() > MAX_INJECT_FILE_BYTES {
        return Err(String::from("template/env file exceeds 1 MiB size limit"));
    }
    let max_bytes = usize::try_from(MAX_INJECT_FILE_BYTES).unwrap_or(usize::MAX);
    let capacity = usize::try_from(meta.len())
        .unwrap_or(0)
        .min(max_bytes)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_INJECT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| String::from("cannot read template/env file"))?;
    if bytes.len() as u64 > MAX_INJECT_FILE_BYTES {
        return Err(String::from("template/env file exceeds 1 MiB size limit"));
    }
    String::from_utf8(bytes).map_err(|_| String::from("template/env file must be valid UTF-8"))
}

fn validated_env_base_dir(raw: &std::ffi::OsStr) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if raw.as_bytes().contains(&0) {
            return None;
        }
    }
    let text = raw.to_str()?;
    if text.contains('\0')
        || text.starts_with(r"\\?\")
        || text.starts_with(r"\\.\")
        || text.starts_with("//?/")
        || text.starts_with("//./")
    {
        return None;
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return None;
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(path)
}

fn validated_env_var_dir(name: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(name)?;
    validated_env_base_dir(&raw)
}

fn resolve_nkp_config_path() -> Option<PathBuf> {
    if let Some(dir) = validated_env_var_dir("NKP_CONFIG_HOME") {
        return Some(dir.join("config.json"));
    }
    if let Some(dir) = validated_env_var_dir("NEO_KEEPASS_CONFIG_DIR") {
        return Some(dir.join("config.json"));
    }
    if let Some(dir) = validated_env_var_dir("XDG_CONFIG_DIR") {
        return Some(dir.join("nkeepass").join("config.json"));
    }
    if let Some(dir) = validated_env_var_dir("XDG_CONFIG_HOME") {
        return Some(dir.join("nkeepass").join("config.json"));
    }
    #[cfg(windows)]
    if let Some(dir) = validated_env_var_dir("APPDATA") {
        return Some(dir.join("nkeepass").join("config.json"));
    }
    let home = validated_env_var_dir("HOME")?;
    Some(home.join(".config").join("nkeepass").join("config.json"))
}

fn config_parent_is_safe(config_path: &Path) -> bool {
    let Some(parent) = config_path.parent() else {
        return false;
    };
    let Ok(meta) = std::fs::symlink_metadata(parent) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (meta.mode() & 0o002) != 0 {
            return false;
        }
    }
    true
}

fn config_file_permissions_safe(config_path: &Path, opened: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(lmeta) = std::fs::symlink_metadata(config_path) else {
            return false;
        };
        if (lmeta.mode() & 0o077) != 0 {
            return false;
        }
        let Ok(fmeta) = opened.metadata() else {
            return false;
        };
        if (fmeta.mode() & 0o077) != 0 {
            return false;
        }
    }
    #[cfg(not(unix))]
    let _ = (config_path, opened);
    true
}

fn push_unique_configured_vault(out: &mut Vec<ConfiguredVault>, label: &str, path: &str) {
    if out.len() >= MAX_CONFIGURED_VAULTS {
        return;
    }
    let trimmed_label = label.trim();
    let trimmed = path.trim();
    if trimmed_label.is_empty()
        || trimmed_label.len() > MAX_CONFIGURED_LABEL_BYTES
        || trimmed.is_empty()
        || trimmed.len() > MAX_CONFIGURED_PATH_BYTES
        || !is_safe_display_text(trimmed_label)
        || !is_safe_display_text(trimmed)
        || out.iter().any(|existing| existing.path == trimmed)
    {
        return;
    }
    out.push(ConfiguredVault {
        label: trimmed_label.to_owned(),
        path: trimmed.to_owned(),
    });
}

/// Reads non-secret vault paths and aliases from an explicit `config.json` path,
/// returning an empty list if absent, unsafe, or malformed.
#[must_use]
pub fn load_configured_vaults_from_path(config_path: &Path) -> Vec<ConfiguredVault> {
    if !config_parent_is_safe(config_path) {
        return Vec::new();
    }
    let Ok((file, meta)) = open_regular_file_nofollow(config_path, "config.json") else {
        return Vec::new();
    };
    if !config_file_permissions_safe(config_path, &file) || meta.len() > MAX_CONFIG_BYTES {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_CONFIG_BYTES
    {
        return Vec::new();
    }
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(obj) = doc.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(aliases) = obj.get("aliases").and_then(serde_json::Value::as_object) {
        for (name, entry) in aliases {
            if out.len() >= MAX_CONFIGURED_VAULTS {
                break;
            }
            let Some(entry_obj) = entry.as_object() else {
                continue;
            };
            let is_vault = entry_obj
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|k| k == "vault");
            let Some(target) = entry_obj.get("target").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if is_vault {
                push_unique_configured_vault(&mut out, name, target);
            }
        }
    }
    if let Some(default_vault) = obj.get("default_vault").and_then(serde_json::Value::as_str) {
        push_unique_configured_vault(&mut out, "Default", default_vault);
    }
    if let Some(current) = obj.get("current").and_then(serde_json::Value::as_str) {
        let matches_alias = out.iter().any(|item| item.label == current);
        if !matches_alias
            && (current.contains('/')
                || current.contains('\\')
                || Path::new(current)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("kdbx")))
        {
            push_unique_configured_vault(&mut out, "Current", current);
        }
    }
    out
}

/// Reads non-secret vault paths and aliases from `nkp`'s existing `config.json` if present.
#[must_use]
pub fn load_configured_vaults() -> Vec<ConfiguredVault> {
    resolve_nkp_config_path().map_or_else(Vec::new, |path| load_configured_vaults_from_path(&path))
}

/// Executes blocking KDBX credential parsing + [`VaultService::open`] for a worker thread.
///
/// The master password is taken in a [`Zeroizing`] buffer and cleared once moved
/// into [`KdbxCredentials`].
#[must_use]
pub fn open_vault_blocking(
    vault_path: &Path,
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
) -> UnlockOutcome {
    if let Err(err) = ensure_vault_regular_file(vault_path) {
        return UnlockOutcome {
            result: Err(err),
            error_field: LockErrorField::Vault,
        };
    }

    let mut credentials = match build_credentials(password, key_file_path) {
        Ok(creds) => creds,
        Err((error_field, err)) => {
            return UnlockOutcome {
                result: Err(err),
                error_field,
            };
        }
    };

    let mut service = VaultService::default();
    match service.open(vault_path, &mut credentials, &KDBX_LIMITS) {
        Ok(session) => UnlockOutcome {
            result: Ok((service, session, credentials)),
            error_field: LockErrorField::None,
        },
        Err(err) => {
            let error_field = match err {
                ServiceError::Io => LockErrorField::Vault,
                _ => LockErrorField::Credentials,
            };
            UnlockOutcome {
                result: Err(err.message().to_owned()),
                error_field,
            }
        }
    }
}

/// Executes blocking [`VaultService::create_recommended`] (`Argon2id` + `GZip` + AES-256)
/// followed by [`VaultService::open`].
#[must_use]
pub fn create_and_open_vault_blocking(
    vault_path: &Path,
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
) -> UnlockOutcome {
    let mut create_creds = match build_credentials(password, key_file_path) {
        Ok(creds) => creds,
        Err((error_field, err)) => {
            return UnlockOutcome {
                result: Err(err),
                error_field,
            };
        }
    };

    let service = VaultService::default();
    if let Err(err) = service.create_recommended(vault_path, &mut create_creds, None) {
        return UnlockOutcome {
            result: Err(err.message().to_owned()),
            error_field: LockErrorField::Vault,
        };
    }
    drop(create_creds);
    open_vault_blocking(vault_path, password, key_file_path)
}

/// Executes blocking [`VaultService::create`] with explicit `write_options`
/// followed by [`VaultService::open`].
#[cfg(test)]
#[must_use]
pub fn create_and_open_vault_with_options(
    vault_path: &Path,
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
    write_options: KdbxWriteOptions,
) -> UnlockOutcome {
    let mut create_creds = match build_credentials(password, key_file_path) {
        Ok(creds) => creds,
        Err((error_field, err)) => {
            return UnlockOutcome {
                result: Err(err),
                error_field,
            };
        }
    };

    let service = VaultService::default();
    if let Err(err) = service.create(vault_path, &mut create_creds, write_options, None) {
        return UnlockOutcome {
            result: Err(err.message().to_owned()),
            error_field: LockErrorField::Vault,
        };
    }
    drop(create_creds);
    open_vault_blocking(vault_path, password, key_file_path)
}

/// Executes blocking [`VaultService::save`] on a background worker thread,
/// returning ownership of both [`VaultService`] and [`KdbxCredentials`].
#[must_use]
pub fn save_vault_blocking(
    generation: u64,
    vault_path: &Path,
    mut service: VaultService,
    mut credentials: KdbxCredentials,
) -> SaveOutcome {
    let result = service
        .save(vault_path, &mut credentials)
        .map_err(|err| err.message().to_owned());
    SaveOutcome {
        generation,
        service,
        credentials,
        result,
    }
}

fn is_disallowed_tag_char(ch: char) -> bool {
    ch.is_control() || matches!(ch, ';' | ',' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn validate_and_append_tags(existing: &mut Vec<String>, raw_tags: &str) -> Result<(), String> {
    let parts: Vec<&str> = raw_tags.split(',').collect();
    let mut pending = Vec::new();
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > 256 || trimmed.chars().any(is_disallowed_tag_char) {
            return Err(String::from(
                "tags must be 1..=256 bytes without control characters or ';' / ','",
            ));
        }
        pending.push(trimmed.to_owned());
    }
    if pending.is_empty() {
        return Err(String::from("enter one or more tag names"));
    }
    for tag in pending {
        let lower = tag.to_lowercase();
        if !existing.iter().any(|cur| cur.to_lowercase() == lower) {
            if existing.len() >= 256 {
                return Err(String::from("at most 256 tags are allowed per entry"));
            }
            existing.push(tag);
        }
    }
    Ok(())
}

struct EditorCustomFieldsRead {
    custom_fields: Vec<EditableCustomField>,
    otp_uri: Zeroizing<String>,
    otp_non_utf8: Option<Zeroizing<String>>,
    had_otp_field: bool,
}

impl VaultController {
    /// Creates a controller pre-seeded with the initial `inject_input` preview parsed
    /// and read-only configured vaults loaded from `nkp`'s `config.json`.
    #[must_use]
    pub fn new() -> Self {
        let mut controller = Self {
            configured_vaults: load_configured_vaults(),
            ..Self::default()
        };
        controller.refresh_inject_preview();
        controller
    }

    /// Records a successfully unlocked/created vault path into the MRU `recent_vaults` list.
    pub fn record_recent_vault(&mut self, path: &str) {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return;
        }
        self.recent_vaults.retain(|item| item != trimmed);
        self.recent_vaults.insert(0, trimmed.to_owned());
        self.recent_vaults.truncate(MAX_RECENT_VAULTS);
    }

    /// Fetches bounded (`<= 256 KiB`) custom KDBX icon bytes for `id` in the live session.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when locked, stale, or the vault contains duplicate icon UUIDs.
    pub fn custom_icon_bytes(&self, id: CustomIconId) -> Result<Option<Vec<u8>>, ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        self.service.custom_icon_bytes(session, id)
    }

    /// Returns `(icon_id, custom_icon_id)` for the currently open group.
    #[must_use]
    pub fn current_group_icon(&self) -> (u32, Option<CustomIconId>) {
        self.breadcrumb_icons
            .last()
            .copied()
            .unwrap_or((DEFAULT_GROUP_ICON_ID, None))
    }

    /// Records user interaction time so idle lock counts from the latest event.
    pub fn record_activity(&mut self, now_secs: f64) {
        self.last_activity_secs = now_secs;
    }

    /// Returns whether owned [`KdbxCredentials`] are currently held in memory.
    #[cfg(test)]
    #[must_use]
    pub const fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Returns whether an active [`SessionId`] is currently held in memory.
    #[cfg(test)]
    #[must_use]
    pub const fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Returns whether the currently open group is the vault root group.
    #[must_use]
    pub fn is_at_root(&self) -> bool {
        self.breadcrumbs.len() <= 1
    }

    /// Returns the opaque handle for the currently viewed group, if unlocked.
    #[must_use]
    pub fn current_group_ref(&self) -> Option<&GroupRef> {
        self.breadcrumbs.last().map(|(_, group)| group)
    }

    /// Sets an informational browser banner status.
    pub fn set_browser_info(&mut self, msg: impl Into<String>) {
        self.browser_status = Some(msg.into());
        self.browser_status_is_error = false;
    }

    /// Sets an error browser banner status.
    pub fn set_browser_error(&mut self, msg: impl Into<String>) {
        self.browser_status = Some(msg.into());
        self.browser_status_is_error = true;
    }

    /// Clears the browser banner status.
    pub fn clear_browser_status(&mut self) {
        self.browser_status = None;
        self.browser_status_is_error = false;
    }

    /// Clears the lock screen status and field attribution.
    pub fn clear_lock_status(&mut self) {
        self.lock_status = None;
        self.lock_error_field = LockErrorField::None;
    }

    /// Validates unlock inputs and transitions to [`VaultPhase::Unlocking`].
    ///
    /// Returns the `(vault_path, key_file_path, request_generation)` tuple for a
    /// background worker, or `None` if validation fails immediately.
    pub fn begin_unlock(
        &mut self,
        password_empty: bool,
    ) -> Option<(PathBuf, Option<PathBuf>, u64)> {
        let trimmed_vault = self.vault_path.trim();
        if trimmed_vault.is_empty() {
            self.lock_status = Some(String::from("select a .kdbx vault path"));
            self.lock_error_field = LockErrorField::Vault;
            return None;
        }
        let trimmed_key = self.key_file_path.trim();
        if password_empty && trimmed_key.is_empty() {
            self.lock_status = Some(String::from(
                "enter a master password or provide a key file",
            ));
            self.lock_error_field = LockErrorField::Credentials;
            return None;
        }
        self.phase = VaultPhase::Unlocking;
        self.lock_status = Some(String::from("Unlocking vault…"));
        self.lock_error_field = LockErrorField::Info;
        self.unlock_generation = self.unlock_generation.wrapping_add(1);
        let key_path = (!trimmed_key.is_empty()).then(|| PathBuf::from(trimmed_key));
        Some((
            PathBuf::from(trimmed_vault),
            key_path,
            self.unlock_generation,
        ))
    }

    /// Validates new-database creation inputs and transitions to [`VaultPhase::Unlocking`].
    pub fn begin_create(
        &mut self,
        password_empty: bool,
        passwords_match: bool,
    ) -> Option<(PathBuf, Option<PathBuf>, u64)> {
        let trimmed_vault = self.vault_path.trim();
        if trimmed_vault.is_empty() {
            self.lock_status = Some(String::from("enter a .kdbx path for the new vault"));
            self.lock_error_field = LockErrorField::Vault;
            return None;
        }
        if !passwords_match {
            self.lock_status = Some(String::from("master passwords do not match"));
            self.lock_error_field = LockErrorField::Master;
            return None;
        }
        let trimmed_key = self.key_file_path.trim();
        if password_empty && trimmed_key.is_empty() {
            self.lock_status = Some(String::from(
                "enter a master password or provide a key file",
            ));
            self.lock_error_field = LockErrorField::Credentials;
            return None;
        }
        self.phase = VaultPhase::Unlocking;
        self.lock_status = Some(String::from("Creating vault…"));
        self.lock_error_field = LockErrorField::Info;
        self.unlock_generation = self.unlock_generation.wrapping_add(1);
        let key_path = (!trimmed_key.is_empty()).then(|| PathBuf::from(trimmed_key));
        Some((
            PathBuf::from(trimmed_vault),
            key_path,
            self.unlock_generation,
        ))
    }

    /// Applies the result of a background [`open_vault_blocking`] or
    /// [`create_and_open_vault_blocking`] call if it matches the current unlock
    /// generation and the UI is still in [`VaultPhase::Unlocking`].
    pub fn finish_unlock(&mut self, generation: u64, outcome: UnlockOutcome, now_secs: f64) {
        if generation != self.unlock_generation || self.phase != VaultPhase::Unlocking {
            return;
        }
        match outcome.result {
            Ok((service, session, credentials)) => {
                self.service = service;
                self.session = Some(session);
                self.credentials = Some(credentials);
                self.phase = VaultPhase::Unlocked;
                self.dirty = false;
                self.saving = false;
                self.pending_lock_decision = None;
                self.clear_lock_status();
                self.clear_browser_status();
                self.editor = None;
                self.favorites_only = false;
                self.active_tab = WorkspaceTab::Browser;
                self.search_query.clear();
                self.last_activity_secs = now_secs;
                let opened_path = self.vault_path.clone();
                self.record_recent_vault(&opened_path);
                if let Err(err) = self.load_root_group() {
                    self.set_browser_error(err.message().to_owned());
                }
                self.refresh_inject_preview();
            }
            Err(message) => {
                self.phase = VaultPhase::Locked;
                self.lock_status = Some(message);
                self.lock_error_field = outcome.error_field;
            }
        }
    }

    /// Returns whether an active session is currently unlocked.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        matches!(self.phase, VaultPhase::Unlocked) && self.session.is_some()
    }

    /// Returns whether a background vault save operation is currently in flight.
    #[must_use]
    pub const fn is_saving(&self) -> bool {
        self.saving
    }

    /// Immediately locks the vault, drops [`KdbxCredentials`], clears all revealed
    /// secrets, editor drafts, and rendered outputs, and invalidates in-flight workers.
    pub fn lock(&mut self) -> LockCleanup {
        let was_active = self.phase != VaultPhase::Locked
            || self.session.is_some()
            || self.credentials.is_some()
            || self.saving;
        self.unlock_generation = self.unlock_generation.wrapping_add(1);
        self.save_generation = self.save_generation.wrapping_add(1);
        if let Some(session) = self.session.take() {
            let _ = self.service.lock(session);
        }
        self.credentials = None;
        self.phase = VaultPhase::Locked;
        self.dirty = false;
        self.saving = false;
        self.pending_lock_decision = None;
        self.breadcrumbs.clear();
        self.breadcrumb_icons.clear();
        self.group_tree = None;
        self.expanded_groups.clear();
        self.current_group_path.clear();
        self.recycle_bin_enabled = true;
        self.favorites_only = false;
        self.child_groups.clear();
        self.entries.clear();
        self.selected_index = None;
        self.detail = None;
        self.editor = None;
        self.search_query.clear();
        self.clear_browser_status();
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        self.inject_status_is_error = false;
        LockCleanup {
            locked_active_session: was_active,
            clear_clipboard: true,
        }
    }

    /// Masks all revealed secrets across entry detail, entry editor, and inject output.
    pub fn mask_all_reveals(&mut self) {
        if let Some(detail) = self.detail.as_mut() {
            detail.revealed_password = None;
            detail.revealed_standard_fields.clear();
            detail.revealed_custom_fields.clear();
        }
        if let Some(editor) = self.editor.as_mut() {
            editor.password_revealed = false;
            editor.otp_revealed = false;
            for field in &mut editor.custom_fields {
                field.revealed = false;
            }
        }
        self.inject_output_revealed = false;
    }

    fn lock_with_trigger(&mut self, trigger: LockTrigger) -> LockCleanup {
        let was_unlocking = self.phase == VaultPhase::Unlocking;
        let mut cleanup = self.lock();
        if cleanup.locked_active_session {
            match trigger {
                LockTrigger::Manual => {
                    cleanup.clear_clipboard = true;
                }
                LockTrigger::FocusLoss => {
                    cleanup.clear_clipboard = false;
                    let msg = if was_unlocking {
                        "Unlock cancelled when window lost focus"
                    } else {
                        "Locked when window lost focus"
                    };
                    self.lock_status = Some(String::from(msg));
                    self.lock_error_field = LockErrorField::Info;
                }
                LockTrigger::IdleTimeout => {
                    cleanup.clear_clipboard = true;
                    self.lock_status = Some(String::from("Locked after inactivity timeout"));
                    self.lock_error_field = LockErrorField::Info;
                }
            }
        }
        cleanup
    }

    /// Requests a lock for `trigger`.
    ///
    /// When `dirty == false`, locks immediately (preserving active 30s clipboard
    /// leases on focus loss, clearing clipboard on manual lock or idle timeout).
    /// When `dirty == true`, opens [`PendingLockDecision`] without discarding
    /// unsaved edits or dropping credentials.
    pub fn request_lock(&mut self, trigger: LockTrigger) -> LockCleanup {
        if self.phase != VaultPhase::Unlocked {
            if trigger == LockTrigger::Manual
                || (self.phase == VaultPhase::Unlocking && trigger == LockTrigger::FocusLoss)
            {
                return self.lock_with_trigger(trigger);
            }
            return LockCleanup {
                locked_active_session: false,
                clear_clipboard: false,
            };
        }
        if !self.dirty {
            return self.lock_with_trigger(trigger);
        }
        if self.pending_lock_decision.is_none() {
            self.pending_lock_decision = Some(PendingLockDecision {
                trigger,
                save_requested: false,
                error: None,
            });
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Cancels a pending dirty-vault lock decision and returns to the unlocked vault.
    pub fn cancel_pending_lock(&mut self) {
        if self.saving {
            return;
        }
        self.pending_lock_decision = None;
        self.set_browser_info("Lock cancelled; unsaved changes kept");
    }

    /// Discards unsaved changes and locks the vault, dropping credentials.
    pub fn discard_and_lock(&mut self) -> LockCleanup {
        if self.saving {
            return LockCleanup {
                locked_active_session: false,
                clear_clipboard: false,
            };
        }
        let trigger = self
            .pending_lock_decision
            .as_ref()
            .map_or(LockTrigger::Manual, |decision| decision.trigger);
        self.lock_with_trigger(trigger)
    }

    /// Initiates a background vault save for either the header Save button or
    /// `Save & Lock` inside [`PendingLockDecision`].
    ///
    /// Returns `(generation, vault_path, service, credentials)` for a worker
    /// thread, or `None` if saving is unavailable.
    pub fn begin_save(
        &mut self,
        for_lock_decision: bool,
    ) -> Option<(u64, PathBuf, VaultService, KdbxCredentials)> {
        if self.phase != VaultPhase::Unlocked || self.saving || self.session.is_none() {
            return None;
        }
        let trimmed_vault = self.vault_path.trim();
        if trimmed_vault.is_empty() {
            let msg = String::from("missing vault path; cannot save");
            if let Some(pending) = self.pending_lock_decision.as_mut() {
                pending.error = Some(msg);
            } else {
                self.set_browser_error(msg);
            }
            return None;
        }
        let Some(credentials) = self.credentials.take() else {
            let msg = String::from("missing credentials; cannot save");
            if let Some(pending) = self.pending_lock_decision.as_mut() {
                pending.error = Some(msg);
            } else {
                self.set_browser_error(msg);
            }
            return None;
        };
        if for_lock_decision && let Some(pending) = self.pending_lock_decision.as_mut() {
            pending.save_requested = true;
            pending.error = None;
        }
        let service = std::mem::take(&mut self.service);
        self.saving = true;
        self.save_generation = self.save_generation.wrapping_add(1);
        Some((
            self.save_generation,
            PathBuf::from(trimmed_vault),
            service,
            credentials,
        ))
    }

    /// Reinstalls the [`VaultService`] and [`KdbxCredentials`] returned by a
    /// background save worker, clearing `dirty` on success and completing any
    /// pending `Save & Lock` or in-flight `FocusLoss`/`IdleTimeout` lock decision.
    pub fn finish_save(&mut self, outcome: SaveOutcome) -> LockCleanup {
        if outcome.generation != self.save_generation || self.phase != VaultPhase::Unlocked {
            // Vault was already locked/discarded while save ran; drop returned
            // service and credentials immediately so secrets zeroize.
            return LockCleanup {
                locked_active_session: false,
                clear_clipboard: false,
            };
        }
        self.service = outcome.service;
        self.credentials = Some(outcome.credentials);
        self.saving = false;

        match outcome.result {
            Ok(()) => {
                self.dirty = false;
                self.set_browser_info("Vault saved");
                if let Some(pending) = self.pending_lock_decision.take() {
                    if pending.save_requested
                        || matches!(
                            pending.trigger,
                            LockTrigger::FocusLoss | LockTrigger::IdleTimeout
                        )
                    {
                        return self.lock_with_trigger(pending.trigger);
                    }
                    self.pending_lock_decision = Some(pending);
                }
            }
            Err(err_msg) => {
                let msg = format!("Save failed: {err_msg}");
                if let Some(pending) = self.pending_lock_decision.as_mut() {
                    pending.save_requested = false;
                    pending.error = Some(format!(
                        "{msg}. Retry Save & Lock, Discard & Lock, or Cancel."
                    ));
                } else {
                    self.set_browser_error(msg);
                }
            }
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Handles window focus transitions: always masks revealed secrets on focus loss,
    /// and only triggers [`LockTrigger::FocusLoss`] when [`Self::lock_on_focus_loss`]
    /// is explicitly enabled.
    pub fn on_window_focus(&mut self, focused: bool) -> LockCleanup {
        if !focused {
            self.mask_all_reveals();
            if self.lock_on_focus_loss {
                return self.request_lock(LockTrigger::FocusLoss);
            }
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Returns the runtime clock deadline (in seconds) when the active session should idle-lock,
    /// or `None` when auto-lock is set to Never.
    #[must_use]
    pub fn idle_lock_deadline(&self) -> Option<f64> {
        self.auto_lock_secs
            .filter(|secs| secs.is_finite() && *secs > 0.0)
            .map(|secs| self.last_activity_secs + secs)
    }

    /// Checks whether the configured idle timeout ([`Self::auto_lock_secs`]) has elapsed and
    /// requests lock.
    pub fn check_idle_timeout(&mut self, now_secs: f64) -> LockCleanup {
        if self.phase == VaultPhase::Unlocked
            && let Some(deadline) = self.idle_lock_deadline()
            && now_secs >= deadline
        {
            return self.request_lock(LockTrigger::IdleTimeout);
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Refreshes [`Self::group_tree`] and [`Self::recycle_bin_enabled`] from [`VaultService`].
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when locked or tree projection exceeds bounds.
    pub fn refresh_group_tree(&mut self) -> Result<(), ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        let tree = self.service.group_tree(session)?;
        self.recycle_bin_enabled = self
            .service
            .database_settings(session)
            .map_or(true, |s| s.recycle_bin_enabled);
        if self.expanded_groups.is_empty() {
            self.expanded_groups.insert(tree.path.clone());
        }
        self.group_tree = Some(tree);
        self.sync_current_group_path();
        Ok(())
    }

    fn sync_current_group_path(&mut self) {
        let Some(tree) = &self.group_tree else {
            self.current_group_path.clear();
            return;
        };
        let Some(cur_ref) = self.breadcrumbs.last().map(|(_, r)| r) else {
            self.current_group_path.clone_from(&tree.path);
            return;
        };
        if let Some(found) = find_tree_node_by_ref(tree, cur_ref) {
            self.current_group_path.clone_from(&found.path);
            return;
        }
        // Fallback by breadcrumb labels if handles were invalidated prior to refresh.
        let mut node = tree;
        for (label, _) in self.breadcrumbs.iter().skip(1) {
            if let Some(child) = node.children.iter().find(|c| c.label == *label) {
                node = child;
            } else {
                break;
            }
        }
        self.current_group_path.clone_from(&node.path);
    }

    /// Loads the root group's direct children and entries.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when the session is locked or stale.
    pub fn load_root_group(&mut self) -> Result<(), ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        let root = self.service.root_group(session)?;
        let root_icon = self.service.root_icon(session)?;
        self.expanded_groups.clear();
        self.breadcrumbs.clear();
        self.breadcrumbs.push((String::from("Root"), root.clone()));
        self.breadcrumb_icons.clear();
        self.breadcrumb_icons
            .push((root_icon.icon_id(), root_icon.custom_icon_id()));
        self.refresh_group_tree()?;
        self.load_group_contents(&root, None)
    }

    /// Navigates into direct child group `index` of the current group.
    #[cfg(test)]
    pub fn open_child_group(&mut self, index: usize) {
        if self.saving {
            return;
        }
        let Some(group) = self.child_groups.get(index) else {
            return;
        };
        let label = group.label().to_owned();
        let group_ref = group.reference();
        let icon = (group.icon_id(), group.custom_icon_id());
        self.search_query.clear();
        self.favorites_only = false;
        self.editor = None;
        self.breadcrumbs.push((label, group_ref.clone()));
        self.breadcrumb_icons.push(icon);
        self.sync_current_group_path();
        if let Err(err) = self.load_group_contents(&group_ref, None) {
            self.set_browser_error(err.message().to_owned());
        }
    }

    fn fetch_group_page_all(
        service: &mut VaultService,
        group: &GroupRef,
    ) -> Result<(Vec<TreeGroup>, Vec<SearchHit>), ServiceError> {
        let mut child_groups = Vec::new();
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let page = service.tree_page(group, cursor)?;
            child_groups.extend(page.groups);
            entries.extend(page.entries);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok((child_groups, entries))
    }

    fn load_group_contents(
        &mut self,
        group: &GroupRef,
        select_idx: Option<usize>,
    ) -> Result<(), ServiceError> {
        let (child_groups, entries) = Self::fetch_group_page_all(&mut self.service, group)?;
        self.child_groups = child_groups;
        self.entries = entries;
        self.selected_index = None;
        self.detail = None;
        self.clear_browser_status();
        if !self.entries.is_empty() {
            let target = select_idx
                .filter(|idx| *idx < self.entries.len())
                .unwrap_or(0);
            self.select_entry(target, current_unix_seconds());
        }
        Ok(())
    }

    fn rebuild_breadcrumbs_after_mutation(&mut self) -> Result<(), ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        let saved_labels: Vec<String> = self
            .breadcrumbs
            .iter()
            .skip(1)
            .map(|(label, _)| label.clone())
            .collect();
        let root = self.service.root_group(session)?;
        let root_icon = self.service.root_icon(session)?;
        let mut next_breadcrumbs = vec![(String::from("Root"), root.clone())];
        let mut next_icons = vec![(root_icon.icon_id(), root_icon.custom_icon_id())];
        let mut current = root;
        for label in saved_labels {
            let (children, _) = Self::fetch_group_page_all(&mut self.service, &current)?;
            let Some(found) = children.into_iter().find(|child| child.label() == label) else {
                break;
            };
            let icon = (found.icon_id(), found.custom_icon_id());
            let next_ref = found.reference();
            next_breadcrumbs.push((label, next_ref.clone()));
            next_icons.push(icon);
            current = next_ref;
        }
        self.breadcrumbs = next_breadcrumbs;
        self.breadcrumb_icons = next_icons;
        Ok(())
    }

    fn is_favorite_hit(hit: &SearchHit) -> bool {
        hit.tags()
            .iter()
            .any(|tag| tag.eq_ignore_ascii_case(FAVORITE_TAG))
    }

    fn search_entries_filtered(
        &mut self,
        session: SessionId,
        query: &str,
        only_favorites: bool,
    ) -> Result<Vec<SearchHit>, ServiceError> {
        let mut hits = Vec::new();
        let mut cursor = None;
        loop {
            let page = self.service.search_page(session, query, cursor)?;
            for hit in page.hits {
                if !only_favorites || Self::is_favorite_hit(&hit) {
                    hits.push(hit);
                }
            }
            match page.next_cursor {
                Some(next) if hits.len() < 1000 => cursor = Some(next),
                Some(next) => {
                    let _ = self.service.release_search_cursor(next);
                    break;
                }
                None => break,
            }
        }
        Ok(hits)
    }

    fn populate_visible_entries(&mut self) -> Result<(), ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        let trimmed = self.search_query.trim().to_owned();
        if trimmed.is_empty() && !self.favorites_only {
            let current_group = self
                .breadcrumbs
                .last()
                .map(|(_, group)| group.clone())
                .ok_or(ServiceError::Locked)?;
            let (child_groups, entries) =
                Self::fetch_group_page_all(&mut self.service, &current_group)?;
            self.child_groups = child_groups;
            self.entries = entries;
        } else {
            let query = if trimmed.is_empty() {
                FAVORITE_TAG
            } else {
                trimmed.as_str()
            };
            let hits = self.search_entries_filtered(session, query, self.favorites_only)?;
            self.child_groups.clear();
            self.entries = hits;
        }
        Ok(())
    }

    fn reload_after_mutation(
        &mut self,
        preferred_ref: Option<&EntryRef>,
        preferred_path: Option<&str>,
        preferred_index: Option<usize>,
        unix_now: u64,
    ) -> Result<(), ServiceError> {
        self.rebuild_breadcrumbs_after_mutation()?;
        self.refresh_group_tree()?;
        self.populate_visible_entries()?;

        self.selected_index = None;
        self.detail = None;

        if self.entries.is_empty() {
            return Ok(());
        }

        let target_index = preferred_ref
            .and_then(|target| {
                self.entries
                    .iter()
                    .position(|hit| hit.reference() == *target)
            })
            .or_else(|| {
                preferred_path
                    .and_then(|path| self.entries.iter().position(|hit| hit.path() == path))
            })
            .or_else(|| preferred_index.filter(|idx| *idx < self.entries.len()))
            .or(Some(0));

        if let Some(idx) = target_index {
            self.select_entry(idx, unix_now);
        }
        Ok(())
    }

    /// Creates a new subgroup inside the currently viewed group and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or `VaultService::add_group` fails.
    pub fn create_subgroup(&mut self, name: &str) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let parent = self
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("vault is locked"))?;
        let trimmed = name.trim();
        self.service
            .add_group(&parent, trimmed)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        let current_path = self.detail.as_ref().map(|detail| detail.path.clone());
        let current_idx = self.selected_index;
        let fresh_editor_path = self.editor.as_ref().map(|ed| ed.path.clone());
        if let Err(err) = self.reload_after_mutation(
            None,
            current_path.as_deref(),
            current_idx,
            current_unix_seconds(),
        ) {
            return Err(err.message().to_owned());
        }
        if let Some(editor) = self.editor.as_mut()
            && let Some(new_detail) = &self.detail
            && fresh_editor_path.as_deref() == Some(new_detail.path.as_str())
        {
            editor.entry_ref = new_detail.entry_ref.clone();
        }
        self.set_browser_info(format!("Created group \"{trimmed}\""));
        Ok(())
    }

    /// Removes `group` from the vault via [`VaultService::remove_group`], refusing the root group.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic (including refusing root-group deletion).
    pub fn remove_group(&mut self, group: &GroupRef) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        self.service
            .remove_group(group)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        if self.breadcrumbs.last().is_some_and(|(_, cur)| cur == group)
            && self.breadcrumbs.len() > 1
        {
            self.breadcrumbs.pop();
            self.breadcrumb_icons.pop();
        }
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        if let Err(err) = self.reload_after_mutation(None, None, None, current_unix_seconds()) {
            return Err(err.message().to_owned());
        }
        self.set_browser_info("Group deleted (unsaved)");
        Ok(())
    }

    /// Removes the currently viewed non-root group.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if locked, saving, or targeting the root group.
    #[cfg(test)]
    pub fn remove_current_group(&mut self) -> Result<(), String> {
        let target = self
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("vault is locked"))?;
        self.remove_group(&target)
    }

    /// Sets the standard `KeePass` 2.x icon (`0..=68`) on the currently viewed group
    /// via [`VaultService::set_group_icon`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or icon ID is invalid.
    pub fn set_current_group_icon(&mut self, icon_id: u32) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        if !is_valid_standard_icon_id(icon_id) {
            return Err(String::from("invalid icon id"));
        }
        let target = self
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("vault is locked"))?;
        self.service
            .set_group_icon(&target, icon_id)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        let current_path = self.detail.as_ref().map(|detail| detail.path.clone());
        let current_idx = self.selected_index;
        let fresh_editor_path = self.editor.as_ref().map(|ed| ed.path.clone());
        self.reload_after_mutation(
            None,
            current_path.as_deref(),
            current_idx,
            current_unix_seconds(),
        )
        .map_err(|err| err.message().to_owned())?;
        if let Some(editor) = self.editor.as_mut()
            && let Some(new_detail) = &self.detail
            && fresh_editor_path.as_deref() == Some(new_detail.path.as_str())
        {
            editor.entry_ref = new_detail.entry_ref.clone();
        }
        self.set_browser_info("Group icon updated (unsaved)");
        Ok(())
    }

    /// Returns whether the currently selected entry has the `"favorite"` tag.
    #[must_use]
    pub fn is_selected_favorite(&self) -> bool {
        self.detail.as_ref().is_some_and(|detail| {
            detail
                .metadata
                .tags()
                .iter()
                .any(|tag| tag.eq_ignore_ascii_case(FAVORITE_TAG))
        })
    }

    /// Toggles the standard `"favorite"` tag on the currently selected entry via
    /// [`VaultService::set_tags`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or no entry is selected.
    pub fn toggle_selected_favorite(&mut self, unix_now: u64) -> Result<bool, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        let entry_ref = detail.entry_ref.clone();
        let entry_path = detail.path.clone();
        let current_idx = self.selected_index;
        let was_fav = self.is_selected_favorite();
        let mut next_tags: Vec<String> = detail
            .metadata
            .tags()
            .iter()
            .filter(|tag| !tag.eq_ignore_ascii_case(FAVORITE_TAG))
            .cloned()
            .collect();
        if !was_fav {
            next_tags.push(String::from(FAVORITE_TAG));
        }
        self.service
            .set_tags(&entry_ref, next_tags)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.reload_after_mutation(None, Some(&entry_path), current_idx, unix_now)
            .map_err(|err| err.message().to_owned())?;
        let now_fav = !was_fav;
        self.set_browser_info(if now_fav {
            "Added to favorites (unsaved)"
        } else {
            "Removed from favorites (unsaved)"
        });
        Ok(now_fav)
    }

    /// Toggles filtering the entry list to entries tagged `"favorite"`.
    pub fn set_favorites_only(&mut self, enabled: bool, unix_now: u64) {
        if self.saving {
            return;
        }
        self.favorites_only = enabled;
        let query = self.search_query.clone();
        self.set_search_query(query, unix_now);
    }

    /// Runs a search across the unlocked vault, or reloads the current group when empty.
    pub fn set_search_query(&mut self, query: String, unix_now: u64) {
        if self.saving {
            return;
        }
        self.search_query = query;
        self.editor = None;
        if self.session.is_none() {
            return;
        }
        if let Err(err) = self.populate_visible_entries() {
            self.set_browser_error(err.message().to_owned());
            return;
        }
        self.selected_index = None;
        self.detail = None;
        self.clear_browser_status();
        if !self.entries.is_empty() {
            self.select_entry(0, unix_now);
        }
    }

    /// Selects entry `index` from `self.entries` and loads its non-protected metadata.
    pub fn select_entry(&mut self, index: usize, unix_now: u64) {
        if self.saving {
            return;
        }
        let Some(hit) = self.entries.get(index) else {
            return;
        };
        self.editor = None;
        let entry_ref = hit.reference();
        let path = hit.path().to_owned();
        let metadata = match self.service.selected_entry(&entry_ref) {
            Ok(selected) => selected,
            Err(err) => {
                self.set_browser_error(err.message().to_owned());
                return;
            }
        };
        let attachments = match self.service.attachment_metadata(&entry_ref) {
            Ok(list) => list,
            Err(err) => {
                self.set_browser_error(err.message().to_owned());
                Vec::new()
            }
        };

        let is_protected = |name: &str| {
            metadata
                .fields()
                .iter()
                .find(|field| field.name() == name)
                .is_some_and(nkeepass::FieldMetadata::protected)
        };

        let mut protected_standard_fields = BTreeMap::new();
        for std_name in ["UserName", "URL", "Notes"] {
            if is_protected(std_name) {
                protected_standard_fields.insert(std_name, true);
            }
        }

        let read_unprotected = |name: &str| -> String {
            if protected_standard_fields.contains_key(name) {
                return String::new();
            }
            match self.service.reveal_field(&entry_ref, name) {
                Ok(bytes) => String::from_utf8_lossy(bytes.as_slice()).into_owned(),
                Err(_) => String::new(),
            }
        };

        let username = read_unprotected("UserName");
        let url = read_unprotected("URL");
        let notes = read_unprotected("Notes");
        let otp_meta = self.service.otp_metadata(&entry_ref).ok().flatten();
        let totp = if otp_meta
            .as_ref()
            .is_some_and(|meta| meta.kind == ServiceOtpKind::Totp)
        {
            Self::compute_totp(&self.service, &entry_ref, unix_now).ok()
        } else {
            None
        };
        let is_in_recycle_bin = self.is_entry_path_in_recycle_bin(&path);

        self.selected_index = Some(index);
        self.detail = Some(EntryDetailState {
            entry_ref,
            path,
            metadata,
            attachments,
            username,
            url,
            notes,
            protected_standard_fields,
            revealed_standard_fields: BTreeMap::new(),
            revealed_password: None,
            revealed_custom_fields: BTreeMap::new(),
            otp_meta,
            totp,
            hotp_code: None,
            is_in_recycle_bin,
        });
        self.clear_browser_status();
    }

    /// Creates a new entry in the current group via [`VaultService::create_entry_in_group`],
    /// auto-selects it, opens Entry Editor mode, and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or creation fails.
    pub fn create_entry_in_current_group(
        &mut self,
        title: Option<&str>,
        unix_now: u64,
    ) -> Result<EntryRef, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let group = self
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("vault is locked"))?;

        let (chosen_title, entry_ref) = if let Some(explicit) = title {
            let created = self
                .service
                .create_entry_in_group(&group, explicit)
                .map_err(|err| err.message().to_owned())?;
            (explicit.to_owned(), created)
        } else {
            let mut attempt = 1_usize;
            loop {
                let candidate = if attempt == 1 {
                    String::from("New Entry")
                } else {
                    format!("New Entry {attempt}")
                };
                match self.service.create_entry_in_group(&group, &candidate) {
                    Ok(created) => break (candidate, created),
                    Err(ServiceError::Ambiguous) if attempt < 10_000 => {
                        attempt += 1;
                    }
                    Err(err) => return Err(err.message().to_owned()),
                }
            }
        };

        self.dirty = true;
        self.search_query.clear();
        self.reload_after_mutation(Some(&entry_ref), None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.begin_edit_selected_entry()?;
        self.set_browser_info(format!("Created entry \"{chosen_title}\""));
        Ok(entry_ref)
    }

    /// Recycles or permanently deletes the currently selected entry via
    /// [`VaultService::recycle_entry`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if no entry is selected, saving is active,
    /// or recycling/deletion fails.
    pub fn delete_selected_entry(&mut self, unix_now: u64) -> Result<(), String> {
        let entry_ref = self
            .detail
            .as_ref()
            .map(|detail| detail.entry_ref.clone())
            .ok_or_else(|| String::from("no entry selected"))?;
        self.recycle_or_delete_entry(&entry_ref, unix_now)
    }

    /// Recycles `entry_ref` into the Recycle Bin when enabled and outside it, or
    /// permanently deletes it when inside the Recycle Bin or Recycle Bin is disabled.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if saving is active or the service call fails.
    pub fn recycle_or_delete_entry(
        &mut self,
        entry_ref: &EntryRef,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let moved_to_bin = self
            .service
            .recycle_entry(entry_ref)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        self.reload_after_mutation(None, None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info(if moved_to_bin {
            "Moved to Recycle Bin (unsaved)"
        } else {
            "Entry permanently deleted (unsaved)"
        });
        Ok(())
    }

    fn read_field_edit_state(
        service: &VaultService,
        entry_ref: &EntryRef,
        name: &str,
    ) -> (Zeroizing<String>, Option<Zeroizing<String>>) {
        match service.reveal_field(entry_ref, name) {
            Ok(secret) => match std::str::from_utf8(secret.as_slice()) {
                Ok(text) => (Zeroizing::new(text.to_owned()), None),
                Err(_) => (
                    Zeroizing::new(String::new()),
                    Some(format_non_utf8_preview(secret.as_slice())),
                ),
            },
            Err(_) => (Zeroizing::new(String::new()), None),
        }
    }

    fn read_editor_custom_fields(
        service: &VaultService,
        detail: &EntryDetailState,
    ) -> Result<EditorCustomFieldsRead, String> {
        let mut custom_fields = Vec::with_capacity(detail.metadata.custom_fields().len());
        let mut otp_uri = Zeroizing::new(String::new());
        let mut otp_non_utf8 = None;
        let mut had_otp_field = false;
        for descriptor in detail.metadata.custom_fields() {
            let secret = service
                .reveal_custom_field(&descriptor.reference())
                .map_err(|err| err.message().to_owned())?;
            let (value, non_utf8_preview) = match std::str::from_utf8(secret.as_slice()) {
                Ok(text) => (Zeroizing::new(text.to_owned()), None),
                Err(_) => (
                    Zeroizing::new(String::new()),
                    Some(format_non_utf8_preview(secret.as_slice())),
                ),
            };
            if descriptor.name() == "otp" {
                otp_uri = value;
                otp_non_utf8 = non_utf8_preview;
                had_otp_field = true;
                continue;
            }
            custom_fields.push(EditableCustomField {
                name: descriptor.name().to_owned(),
                original_value: value.clone(),
                value,
                non_utf8_preview,
                protected: descriptor.protected(),
                revealed: !descriptor.protected(),
                is_new: false,
                original_protected: descriptor.protected(),
            });
        }
        Ok(EditorCustomFieldsRead {
            custom_fields,
            otp_uri,
            otp_non_utf8,
            had_otp_field,
        })
    }

    /// Opens Entry Editor mode for the currently selected entry.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if no entry is selected or fields cannot be read.
    pub fn begin_edit_selected_entry(&mut self) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        let entry_ref = detail.entry_ref.clone();
        let password_secret = self
            .service
            .reveal_password(&entry_ref)
            .map_err(|err| err.message().to_owned())?;
        let (password, password_non_utf8) = match std::str::from_utf8(password_secret.as_slice()) {
            Ok(text) => (Zeroizing::new(text.to_owned()), None),
            Err(_) => (
                Zeroizing::new(String::new()),
                Some(format_non_utf8_preview(password_secret.as_slice())),
            ),
        };

        let username_protected = detail.protected_standard_fields.contains_key("UserName");
        let url_protected = detail.protected_standard_fields.contains_key("URL");
        let notes_protected = detail.protected_standard_fields.contains_key("Notes");

        let (username, username_non_utf8) =
            Self::read_field_edit_state(&self.service, &entry_ref, "UserName");
        let (url, url_non_utf8) = Self::read_field_edit_state(&self.service, &entry_ref, "URL");
        let (notes, notes_non_utf8) =
            Self::read_field_edit_state(&self.service, &entry_ref, "Notes");

        let EditorCustomFieldsRead {
            custom_fields,
            otp_uri,
            otp_non_utf8,
            had_otp_field,
        } = Self::read_editor_custom_fields(&self.service, detail)?;
        let otp_config = parse_otp_draft_from_uri(&otp_uri, had_otp_field);

        let title = detail.metadata.title().to_owned();
        let tags = detail.metadata.tags().to_vec();
        let icon_id = detail.metadata.icon_id();
        let custom_icon_id = detail.metadata.custom_icon_id();

        self.editor = Some(EntryEditorState {
            entry_ref,
            path: detail.path.clone(),
            original_icon_id: icon_id,
            icon_id,
            original_custom_icon_id: custom_icon_id,
            custom_icon_id,
            icon_changed: false,
            original_title: title.clone(),
            title,
            original_username: username.clone(),
            username,
            username_non_utf8,
            original_username_protected: username_protected,
            username_protected,
            original_password: password.clone(),
            password,
            password_non_utf8,
            password_revealed: false,
            original_url: url.clone(),
            url,
            url_non_utf8,
            original_url_protected: url_protected,
            url_protected,
            original_notes: notes.clone(),
            notes,
            notes_non_utf8,
            original_notes_protected: notes_protected,
            notes_protected,
            original_otp_uri: otp_uri.clone(),
            otp_uri,
            otp_non_utf8,
            otp_revealed: false,
            original_otp_config: otp_config.clone(),
            otp_config,
            had_otp_field,
            original_tags: tags.clone(),
            tags,
            custom_fields,
            removed_custom_fields: Vec::new(),
        });
        self.clear_browser_status();
        Ok(())
    }

    /// Sets the draft standard `KeePass` icon ID (`0..=68`) in the active Entry Editor.
    pub fn set_editor_icon(&mut self, icon_id: u32) {
        if !is_valid_standard_icon_id(icon_id) {
            return;
        }
        if let Some(editor) = self.editor.as_mut() {
            editor.icon_id = icon_id;
            editor.custom_icon_id = None;
            editor.icon_changed = true;
        }
    }

    /// Sets a draft embedded custom KDBX icon in the active Entry Editor.
    pub fn set_editor_custom_icon(&mut self, id: CustomIconId) {
        if let Some(editor) = self.editor.as_mut() {
            editor.custom_icon_id = Some(id);
            editor.icon_changed = true;
        }
    }

    /// Cancels Entry Editor mode and zeroizes all editor secret buffers.
    pub fn cancel_entry_editor(&mut self) {
        self.editor = None;
        self.set_browser_info("Entry edits cancelled");
    }

    /// Generates a new password into the active Entry Editor using the configured
    /// length and character-class policy.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if no editor is active, policy/size is invalid,
    /// or OS randomness fails.
    pub fn generate_editor_password_with(
        &mut self,
        len: usize,
        policy: Policy,
    ) -> Result<Zeroizing<String>, String> {
        let editor = self
            .editor
            .as_mut()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        let generated = VaultService::generate_password_value(len, policy)
            .map_err(|err| err.message().to_owned())?;
        editor.password.clone_from(&generated);
        Ok(generated)
    }

    /// Generates a new password into the active Entry Editor using the current
    /// controller generator settings (`gen_length`, `gen_policy`).
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if no editor is active or OS randomness fails.
    pub fn generate_editor_password(&mut self) -> Result<Zeroizing<String>, String> {
        self.generate_editor_password_with(self.gen_length, self.gen_policy)
    }

    /// Returns the active editor's password buffer for timed secret clipboard copy.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if the editor is not active.
    pub fn editor_password_for_copy(&self) -> Result<Zeroizing<String>, String> {
        let editor = self
            .editor
            .as_ref()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        Ok(editor.password.clone())
    }

    /// Adds one or more comma-separated tags to the active Entry Editor draft.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if no editor is active or any tag is invalid.
    pub fn add_editor_tags_from_input(&mut self, raw: &str) -> Result<(), String> {
        let editor = self
            .editor
            .as_mut()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        validate_and_append_tags(&mut editor.tags, raw)
    }

    /// Removes tag `index` from the active Entry Editor draft.
    pub fn remove_editor_tag(&mut self, index: usize) {
        if let Some(editor) = self.editor.as_mut()
            && index < editor.tags.len()
        {
            editor.tags.remove(index);
        }
    }

    /// Stages a new custom string field in the active Entry Editor draft.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if the editor is inactive or the field name is
    /// empty, invalid, standard, or duplicate.
    pub fn add_editor_custom_field(
        &mut self,
        name: &str,
        value: Zeroizing<String>,
        protected: bool,
    ) -> Result<(), String> {
        let editor = self
            .editor
            .as_mut()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            return Err(String::from("invalid custom field name"));
        }
        if matches!(trimmed, "Title" | "UserName" | "Password" | "URL" | "Notes") {
            return Err(String::from(
                "standard field names cannot be added as custom strings",
            ));
        }
        if trimmed == "otp" {
            return Err(String::from(
                "use the OTP Auth URI field above to configure 'otp'",
            ));
        }
        if editor
            .custom_fields
            .iter()
            .any(|field| field.name == trimmed)
        {
            return Err(String::from("custom field already exists"));
        }
        editor.custom_fields.push(EditableCustomField {
            name: trimmed.to_owned(),
            value,
            non_utf8_preview: None,
            protected,
            revealed: !protected,
            is_new: true,
            original_value: Zeroizing::new(String::new()),
            original_protected: protected,
        });
        Ok(())
    }

    /// Removes custom string `index` from the active Entry Editor draft (staging
    /// pre-existing fields for [`VaultService::remove_custom_field`] on Apply).
    pub fn remove_editor_custom_field(&mut self, index: usize) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        if index >= editor.custom_fields.len() {
            return;
        }
        let removed = editor.custom_fields.remove(index);
        if !removed.is_new && !editor.removed_custom_fields.contains(&removed.name) {
            editor.removed_custom_fields.push(removed.name);
        }
    }

    /// Toggles value visibility for custom string `index` inside the active Entry Editor.
    pub fn toggle_editor_custom_field_reveal(&mut self, index: usize) {
        if let Some(editor) = self.editor.as_mut()
            && let Some(field) = editor.custom_fields.get_mut(index)
        {
            field.revealed = !field.revealed;
        }
    }

    /// Updates the `Protected` flag for custom string `index` inside the active Entry Editor.
    pub fn set_editor_custom_field_protected(&mut self, index: usize, protected: bool) {
        if let Some(editor) = self.editor.as_mut()
            && let Some(field) = editor.custom_fields.get_mut(index)
        {
            field.protected = protected;
            field.revealed = !protected;
        }
    }

    /// Returns custom string `index` from the active Entry Editor for timed secret copy.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if the editor is inactive or index is out of bounds.
    pub fn editor_custom_field_for_copy(&self, index: usize) -> Result<Zeroizing<String>, String> {
        let editor = self
            .editor
            .as_ref()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        let field = editor
            .custom_fields
            .get(index)
            .ok_or_else(|| String::from("custom field not found"))?;
        Ok(field.value.clone())
    }

    fn fresh_entry_ref_mut(
        &mut self,
        expected_path: &str,
        group_entry_index: Option<usize>,
    ) -> Result<EntryRef, ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        if self.search_query.trim().is_empty()
            && !self.favorites_only
            && let Some(idx) = group_entry_index
        {
            let labels: Vec<String> = self
                .breadcrumbs
                .iter()
                .skip(1)
                .map(|(label, _)| label.clone())
                .collect();
            let mut current = self.service.root_group(session)?;
            for label in labels {
                let (children, _) = Self::fetch_group_page_all(&mut self.service, &current)?;
                let found = children
                    .into_iter()
                    .find(|child| child.label() == label)
                    .ok_or(ServiceError::NotFound)?;
                current = found.reference();
            }
            let (_, entries) = Self::fetch_group_page_all(&mut self.service, &current)?;
            if let Some(hit) = entries.get(idx) {
                return Ok(hit.reference());
            }
        }
        let resolved = self.service.resolve_entry(session, expected_path)?;
        Ok(resolved.reference())
    }

    /// Applies the active Entry Editor draft to the live [`VaultService`] via
    /// `set_title`, `set_tags`, `remove_custom_field`, and `set_fields_creating_custom`,
    /// pre-validates all draft changes before the first mutation, tracks any
    /// partial mutations on `dirty` and `draft`, and reloads the entry detail.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or any vault validation fails.
    pub fn apply_entry_editor(&mut self, unix_now: u64) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let mut draft = self
            .editor
            .take()
            .ok_or_else(|| String::from("entry editor is not active"))?;

        let result = self.apply_entry_editor_inner(&mut draft, unix_now);
        if let Err(err) = result {
            if let Ok(()) = self.reload_after_mutation(
                Some(&draft.entry_ref),
                Some(&draft.path),
                self.selected_index,
                unix_now,
            ) && let Some(detail) = &self.detail
            {
                draft.entry_ref = detail.entry_ref.clone();
                draft.path.clone_from(&detail.path);
            }
            self.set_browser_error(err.clone());
            self.editor = Some(draft);
            return Err(err);
        }
        Ok(())
    }

    fn validate_title_text(title: &str) -> Result<(), String> {
        if title.is_empty()
            || title.len() > 4096
            || title.contains('/')
            || title.chars().any(|ch| {
                ch.is_control() || matches!(ch, '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err(String::from("invalid entry title"));
        }
        Ok(())
    }

    fn validate_editor_draft(
        &self,
        draft: &EntryEditorState,
        updates: &[FieldUpdate],
    ) -> Result<(), String> {
        if self.session.is_none() {
            return Err(String::from("vault is locked"));
        }
        if draft.title != draft.original_title {
            Self::validate_title_text(&draft.title)?;
        }
        if draft.icon_changed
            && draft.custom_icon_id.is_none()
            && !is_valid_standard_icon_id(draft.icon_id)
        {
            return Err(String::from("invalid icon id"));
        }
        if draft.otp_non_utf8.is_none() {
            match draft.otp_config.mode {
                OtpEditorMode::None => {}
                OtpEditorMode::RawUri => {
                    let trimmed_otp = draft.otp_uri.trim();
                    if !trimmed_otp.is_empty() && draft.otp_uri != draft.original_otp_uri {
                        OtpUri::parse(trimmed_otp).map_err(|_| {
                            String::from(
                                "invalid OTP Auth URI (expected otpauth://totp/... or otpauth://hotp/... with Base32 secret)",
                            )
                        })?;
                    }
                }
                OtpEditorMode::Totp | OtpEditorMode::Hotp => {
                    if draft.otp_config != draft.original_otp_config {
                        let cfg = otp_config_from_draft(&draft.otp_config, &draft.title);
                        VaultService::format_otp_uri(&cfg, draft.otp_config.secret.trim())
                            .map_err(|_| {
                                String::from("invalid OTP secret or parameters (expected valid Base32 secret)")
                            })?;
                    }
                }
            }
        }
        Self::validate_editor_tags_and_updates(draft, updates)
    }

    fn validate_editor_tags_and_updates(
        draft: &EntryEditorState,
        updates: &[FieldUpdate],
    ) -> Result<(), String> {
        if draft.tags != draft.original_tags {
            if draft.tags.len() > 256 {
                return Err(String::from("at most 256 tags are allowed per entry"));
            }
            for tag in &draft.tags {
                let trimmed = tag.trim();
                if trimmed.is_empty()
                    || trimmed.len() > 256
                    || trimmed.chars().any(is_disallowed_tag_char)
                {
                    return Err(String::from(
                        "tags must be 1..=256 bytes without control characters or ';' / ','",
                    ));
                }
            }
        }
        for name in &draft.removed_custom_fields {
            if name.is_empty()
                || matches!(
                    name.as_str(),
                    "Title" | "UserName" | "Password" | "URL" | "Notes"
                )
            {
                return Err(String::from("invalid custom field removal"));
            }
        }
        let mut seen = BTreeSet::new();
        for update in updates {
            if update.key.is_empty()
                || update.key.chars().any(char::is_control)
                || update.key == "Title"
                || !seen.insert(update.key.as_str())
            {
                return Err(String::from("invalid or duplicate field update"));
            }
        }
        Ok(())
    }

    fn collect_editor_field_updates(draft: &EntryEditorState) -> Vec<FieldUpdate> {
        let mut updates = Vec::new();
        if draft.username_non_utf8.is_none()
            && (draft.username != draft.original_username
                || draft.username_protected != draft.original_username_protected)
        {
            updates.push(FieldUpdate {
                key: String::from("UserName"),
                value: draft.username.clone(),
                protected: Some(draft.username_protected),
                protect_in_memory: Some(draft.username_protected),
            });
        }
        if draft.password_non_utf8.is_none() && draft.password != draft.original_password {
            updates.push(FieldUpdate {
                key: String::from("Password"),
                value: draft.password.clone(),
                protected: Some(true),
                protect_in_memory: Some(true),
            });
        }
        if draft.url_non_utf8.is_none()
            && (draft.url != draft.original_url
                || draft.url_protected != draft.original_url_protected)
        {
            updates.push(FieldUpdate {
                key: String::from("URL"),
                value: draft.url.clone(),
                protected: Some(draft.url_protected),
                protect_in_memory: Some(draft.url_protected),
            });
        }
        if draft.notes_non_utf8.is_none()
            && (draft.notes != draft.original_notes
                || draft.notes_protected != draft.original_notes_protected)
        {
            updates.push(FieldUpdate {
                key: String::from("Notes"),
                value: draft.notes.clone(),
                protected: Some(draft.notes_protected),
                protect_in_memory: Some(draft.notes_protected),
            });
        }
        if draft.otp_non_utf8.is_none() && draft.otp_config.mode == OtpEditorMode::RawUri {
            let trimmed_otp = draft.otp_uri.trim();
            if !trimmed_otp.is_empty() && draft.otp_uri != draft.original_otp_uri {
                updates.push(FieldUpdate {
                    key: String::from("otp"),
                    value: Zeroizing::new(trimmed_otp.to_owned()),
                    protected: Some(true),
                    protect_in_memory: Some(true),
                });
            }
        }
        for field in &draft.custom_fields {
            if field.non_utf8_preview.is_some() {
                continue;
            }
            if field.is_new
                || field.value != field.original_value
                || field.protected != field.original_protected
            {
                updates.push(FieldUpdate {
                    key: field.name.clone(),
                    value: field.value.clone(),
                    protected: Some(field.protected),
                    protect_in_memory: Some(field.protected),
                });
            }
        }
        updates
    }

    fn sync_draft_fields_after_commit(draft: &mut EntryEditorState) {
        draft.original_username = draft.username.clone();
        draft.original_username_protected = draft.username_protected;
        draft.original_password = draft.password.clone();
        draft.original_url = draft.url.clone();
        draft.original_url_protected = draft.url_protected;
        draft.original_notes = draft.notes.clone();
        draft.original_notes_protected = draft.notes_protected;
        let trimmed_otp = draft.otp_uri.trim().to_owned();
        if !trimmed_otp.is_empty() {
            draft.had_otp_field = true;
        }
        draft.original_otp_uri = Zeroizing::new(trimmed_otp);
        draft.original_otp_config = draft.otp_config.clone();
        for field in &mut draft.custom_fields {
            field.is_new = false;
            field.original_value = field.value.clone();
            field.original_protected = field.protected;
        }
    }

    fn apply_editor_icon_and_tags(
        &mut self,
        draft: &mut EntryEditorState,
        entry_ref: &mut EntryRef,
        current_path: &str,
        group_idx: Option<usize>,
    ) -> Result<bool, String> {
        let mut mutated = false;
        if draft.icon_changed
            && (draft.icon_id != draft.original_icon_id
                || draft.custom_icon_id != draft.original_custom_icon_id)
        {
            if let Some(custom_id) = draft.custom_icon_id {
                self.service
                    .set_entry_custom_icon(entry_ref, custom_id)
                    .map_err(|err| err.message().to_owned())?;
            } else {
                self.service
                    .set_entry_icon(entry_ref, draft.icon_id)
                    .map_err(|err| err.message().to_owned())?;
            }
            mutated = true;
            self.dirty = true;
            draft.original_icon_id = draft.icon_id;
            draft.original_custom_icon_id = draft.custom_icon_id;
            draft.icon_changed = false;
            *entry_ref = self
                .fresh_entry_ref_mut(current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
        }
        if draft.tags != draft.original_tags {
            self.service
                .set_tags(entry_ref, draft.tags.clone())
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            self.dirty = true;
            draft.original_tags = draft.tags.clone();
            *entry_ref = self
                .fresh_entry_ref_mut(current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
        }
        Ok(mutated)
    }

    fn apply_editor_otp(
        &mut self,
        draft: &mut EntryEditorState,
        entry_ref: &mut EntryRef,
        current_path: &str,
        group_idx: Option<usize>,
    ) -> Result<bool, String> {
        if draft.otp_non_utf8.is_some() {
            return Ok(false);
        }
        let remove_otp = match draft.otp_config.mode {
            OtpEditorMode::None => draft.had_otp_field,
            OtpEditorMode::RawUri => draft.otp_uri.trim().is_empty() && draft.had_otp_field,
            OtpEditorMode::Totp | OtpEditorMode::Hotp => false,
        };
        if remove_otp {
            self.service
                .remove_custom_field(entry_ref, "otp")
                .map_err(|err| err.message().to_owned())?;
            self.dirty = true;
            draft.had_otp_field = false;
            draft.original_otp_uri = Zeroizing::new(String::new());
            draft.original_otp_config = draft.otp_config.clone();
            *entry_ref = self
                .fresh_entry_ref_mut(current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
            return Ok(true);
        }
        if matches!(
            draft.otp_config.mode,
            OtpEditorMode::Totp | OtpEditorMode::Hotp
        ) && draft.otp_config != draft.original_otp_config
        {
            let cfg = otp_config_from_draft(&draft.otp_config, &draft.title);
            self.service
                .set_entry_otp_config(entry_ref, &cfg, draft.otp_config.secret.trim())
                .map_err(|err| err.message().to_owned())?;
            self.dirty = true;
            draft.had_otp_field = true;
            draft.original_otp_config = draft.otp_config.clone();
            *entry_ref = self
                .fresh_entry_ref_mut(current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
            return Ok(true);
        }
        Ok(false)
    }

    fn apply_entry_editor_inner(
        &mut self,
        draft: &mut EntryEditorState,
        unix_now: u64,
    ) -> Result<(), String> {
        let updates = Self::collect_editor_field_updates(draft);
        self.validate_editor_draft(draft, &updates)?;

        let mut entry_ref = draft.entry_ref.clone();
        let mut current_path = draft.path.clone();
        let group_idx = self.selected_index;
        let mut mutated = false;

        if draft.title != draft.original_title {
            self.service
                .set_title(&entry_ref, &draft.title)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            self.dirty = true;
            draft.original_title.clone_from(&draft.title);
            current_path = match current_path.rsplit_once('/') {
                Some((parent, _)) => format!("{parent}/{}", draft.title),
                None => draft.title.clone(),
            };
            draft.path.clone_from(&current_path);
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
        }

        mutated |=
            self.apply_editor_icon_and_tags(draft, &mut entry_ref, &current_path, group_idx)?;
        mutated |= self.apply_editor_otp(draft, &mut entry_ref, &current_path, group_idx)?;

        while let Some(removed_name) = draft.removed_custom_fields.first().cloned() {
            self.service
                .remove_custom_field(&entry_ref, &removed_name)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            self.dirty = true;
            draft.removed_custom_fields.remove(0);
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
        }

        if !updates.is_empty() {
            self.service
                .set_fields_creating_custom(&entry_ref, updates)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            self.dirty = true;
            Self::sync_draft_fields_after_commit(draft);
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
            draft.entry_ref = entry_ref.clone();
        }

        self.reload_after_mutation(Some(&entry_ref), Some(&current_path), group_idx, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info(if mutated {
            "Entry updated (unsaved)"
        } else {
            "No changes to apply"
        });
        Ok(())
    }

    /// Attaches a binary file from `source_path` to the selected entry using a
    /// bounded `<= 16 MiB` regular-file read and [`VaultService::add_attachment`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if no entry is selected, saving is active,
    /// file validation fails, or [`VaultService::add_attachment`] fails.
    pub fn attach_file(
        &mut self,
        source_path: &Path,
        attachment_name: Option<&str>,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let (entry_ref, entry_path) = self
            .detail
            .as_ref()
            .map(|detail| (detail.entry_ref.clone(), detail.path.clone()))
            .ok_or_else(|| String::from("no entry selected"))?;
        let resolved_name = match attachment_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            Some(explicit) => explicit.to_owned(),
            None => source_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToOwned::to_owned)
                .ok_or_else(|| String::from("cannot determine attachment filename"))?,
        };
        let bytes = read_attachment_file_bounded(source_path)?;
        self.service
            .add_attachment(&entry_ref, &resolved_name, bytes)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.refresh_preserving_editor(&entry_path)?;
        self.set_browser_info(format!("Attached \"{resolved_name}\" (unsaved)"));
        Ok(())
    }

    /// Extracts attachment `attachment_index` privately via
    /// [`VaultService::reveal_attachment`] and [`write_private_noclobber`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if the entry/attachment is missing or
    /// private file creation fails.
    pub fn extract_attachment(
        &mut self,
        attachment_index: usize,
        target_path: &Path,
    ) -> Result<(), String> {
        if target_path.as_os_str().is_empty() {
            return Err(String::from("enter a destination file path"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        let descriptor = detail
            .attachments
            .get(attachment_index)
            .ok_or_else(|| String::from("attachment not found"))?;
        let name = descriptor.name().to_owned();
        let secret_bytes = self
            .service
            .reveal_attachment(&descriptor.reference())
            .map_err(|err| err.message().to_owned())?;
        write_private_noclobber(target_path, secret_bytes.as_slice()).map_err(str::to_owned)?;
        self.set_browser_info(format!(
            "Saved attachment \"{name}\" privately (no-clobber)"
        ));
        Ok(())
    }

    /// Removes attachment `attachment_name` from the selected entry via
    /// [`VaultService::remove_attachment`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if no entry is selected, saving is active,
    /// or removal fails.
    pub fn remove_attachment(&mut self, attachment_name: &str) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let (entry_ref, entry_path) = self
            .detail
            .as_ref()
            .map(|detail| (detail.entry_ref.clone(), detail.path.clone()))
            .ok_or_else(|| String::from("no entry selected"))?;
        self.service
            .remove_attachment(&entry_ref, attachment_name)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.refresh_preserving_editor(&entry_path)?;
        self.set_browser_info(format!(
            "Removed attachment \"{attachment_name}\" (unsaved)"
        ));
        Ok(())
    }

    fn refresh_preserving_editor(&mut self, entry_path: &str) -> Result<(), String> {
        let saved_editor = self.editor.take();
        let group_idx = self.selected_index;
        self.reload_after_mutation(None, Some(entry_path), group_idx, current_unix_seconds())
            .map_err(|err| err.message().to_owned())?;
        if let Some(mut editor) = saved_editor {
            if let Some(detail) = &self.detail {
                editor.entry_ref = detail.entry_ref.clone();
            }
            self.editor = Some(editor);
        }
        Ok(())
    }

    fn compute_totp(
        service: &VaultService,
        entry_ref: &EntryRef,
        unix_now: u64,
    ) -> Result<TotpDisplay, ServiceError> {
        let totp = service.totp_code_with_period(entry_ref, unix_now)?;
        let period = totp.period().max(1);
        let remaining_secs = period - (unix_now % period);
        Ok(TotpDisplay {
            code: Zeroizing::new(totp.code().to_owned()),
            remaining_secs,
            period,
        })
    }

    /// Refreshes the selected entry's TOTP code for `unix_now` if it has TOTP configured.
    pub fn refresh_selected_totp(&mut self, unix_now: u64) {
        if self.saving {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if !detail
            .otp_meta
            .is_some_and(|meta| meta.kind == ServiceOtpKind::Totp)
        {
            return;
        }
        match Self::compute_totp(&self.service, &detail.entry_ref, unix_now) {
            Ok(totp) => detail.totp = Some(totp),
            Err(err) => self.set_browser_error(err.message().to_owned()),
        }
    }

    /// Generates the next HOTP code for the selected entry, incrementing its counter
    /// and marking `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, no entry is selected,
    /// or the entry does not carry a valid HOTP configuration.
    pub fn generate_next_hotp_code(&mut self, unix_now: u64) -> Result<Zeroizing<String>, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let (entry_ref, entry_path, group_idx) = self
            .detail
            .as_ref()
            .map(|d| (d.entry_ref.clone(), d.path.clone(), self.selected_index))
            .ok_or_else(|| String::from("no entry selected"))?;
        let code = self
            .service
            .hotp_next_code(&entry_ref)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.reload_after_mutation(None, Some(&entry_path), group_idx, unix_now)
            .map_err(|err| err.message().to_owned())?;
        if let Some(detail) = self.detail.as_mut() {
            detail.hotp_code = Some(code.clone());
        }
        self.set_browser_info("Generated HOTP code (counter incremented, unsaved)");
        Ok(code)
    }

    /// Toggles explicit password reveal for the selected entry using [`RevealedSecret`].
    pub fn toggle_reveal_password(&mut self) {
        if self.saving {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if detail.revealed_password.is_some() {
            detail.revealed_password = None;
            return;
        }
        match self.service.reveal_password(&detail.entry_ref) {
            Ok(secret) => {
                detail.revealed_password = Some(RevealedSecret::from_bytes(secret.as_slice()));
            }
            Err(err) => {
                self.set_browser_error(err.message().to_owned());
            }
        }
    }

    /// Reveals the selected entry's password briefly for copying to Rune's secret clipboard.
    ///
    /// # Errors
    ///
    /// Returns a fixed status string if no entry is selected, the vault is locked,
    /// or the password is not valid UTF-8.
    pub fn password_for_copy(&self) -> Result<Zeroizing<String>, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        match &detail.revealed_password {
            Some(RevealedSecret::Text(text)) => return Ok(text.clone()),
            Some(RevealedSecret::NonUtf8 { .. }) => {
                return Err(String::from("password is not valid UTF-8"));
            }
            None => {}
        }
        let secret = self
            .service
            .reveal_password(&detail.entry_ref)
            .map_err(|err| err.message().to_owned())?;
        let text = std::str::from_utf8(secret.as_slice())
            .map_err(|_| String::from("password is not valid UTF-8"))?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Toggles explicit reveal for a protected standard field (`UserName`, `URL`, `Notes`).
    pub fn toggle_reveal_standard_field(&mut self, field_name: &'static str) {
        if self.saving {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if detail.revealed_standard_fields.remove(field_name).is_some() {
            return;
        }
        match self.service.reveal_field(&detail.entry_ref, field_name) {
            Ok(secret) => {
                detail
                    .revealed_standard_fields
                    .insert(field_name, RevealedSecret::from_bytes(secret.as_slice()));
            }
            Err(err) => {
                self.set_browser_error(err.message().to_owned());
            }
        }
    }

    /// Reveals a protected standard field briefly for copying via Rune's secret clipboard.
    ///
    /// # Errors
    ///
    /// Returns a fixed status diagnostic if missing, locked, or non-UTF-8.
    pub fn standard_field_for_copy(&self, field_name: &str) -> Result<Zeroizing<String>, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        match detail.revealed_standard_fields.get(field_name) {
            Some(RevealedSecret::Text(text)) => return Ok(text.clone()),
            Some(RevealedSecret::NonUtf8 { .. }) => {
                return Err(String::from("field is not valid UTF-8"));
            }
            None => {}
        }
        let secret = self
            .service
            .reveal_field(&detail.entry_ref, field_name)
            .map_err(|err| err.message().to_owned())?;
        let text = std::str::from_utf8(secret.as_slice())
            .map_err(|_| String::from("field is not valid UTF-8"))?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Toggles explicit reveal for custom field `custom_index` on the selected entry.
    pub fn toggle_reveal_custom_field(&mut self, custom_index: usize) {
        if self.saving {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if detail
            .revealed_custom_fields
            .remove(&custom_index)
            .is_some()
        {
            return;
        }
        let Some(descriptor) = detail.metadata.custom_fields().get(custom_index) else {
            return;
        };
        let reference = descriptor.reference();
        match self.service.reveal_custom_field(&reference) {
            Ok(secret) => {
                detail
                    .revealed_custom_fields
                    .insert(custom_index, RevealedSecret::from_bytes(secret.as_slice()));
            }
            Err(err) => {
                self.set_browser_error(err.message().to_owned());
            }
        }
    }

    /// Reveals custom field `custom_index` for copying via Rune's secret clipboard.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic string if missing, locked, or non-UTF-8.
    pub fn custom_field_for_copy(&self, custom_index: usize) -> Result<Zeroizing<String>, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let detail = self
            .detail
            .as_ref()
            .ok_or_else(|| String::from("no entry selected"))?;
        match detail.revealed_custom_fields.get(&custom_index) {
            Some(RevealedSecret::Text(text)) => return Ok(text.clone()),
            Some(RevealedSecret::NonUtf8 { .. }) => {
                return Err(String::from("custom field is not valid UTF-8"));
            }
            None => {}
        }
        let descriptor = detail
            .metadata
            .custom_fields()
            .get(custom_index)
            .ok_or_else(|| String::from("custom field not found"))?;
        let secret = self
            .service
            .reveal_custom_field(&descriptor.reference())
            .map_err(|err| err.message().to_owned())?;
        let text = std::str::from_utf8(secret.as_slice())
            .map_err(|_| String::from("custom field is not valid UTF-8"))?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Returns flattened visible rows for the collapsible `TreeView` group sidebar.
    #[must_use]
    pub fn visible_tree_groups(&self) -> Vec<VisibleTreeGroup> {
        let Some(tree) = &self.group_tree else {
            return Vec::new();
        };
        let mut out = Vec::new();
        collect_visible_tree_groups(tree, 0, &self.expanded_groups, &mut out);
        out
    }

    /// Toggles expand/collapse state for `group_path` in the `TreeView` sidebar.
    pub fn toggle_group_expanded(&mut self, group_path: &str) {
        if self.expanded_groups.contains(group_path) {
            if self
                .group_tree
                .as_ref()
                .is_some_and(|root| root.path == group_path)
            {
                return;
            }
            self.expanded_groups.remove(group_path);
        } else {
            self.expanded_groups.insert(group_path.to_owned());
        }
    }

    /// Returns whether the currently selected group is the Recycle Bin (or inside it).
    #[must_use]
    pub fn is_current_group_recycle_bin(&self) -> bool {
        let Some(tree) = &self.group_tree else {
            return false;
        };
        is_group_path_in_recycle_bin(tree, &self.current_group_path)
    }

    fn is_entry_path_in_recycle_bin(&self, entry_path: &str) -> bool {
        if self.is_current_group_recycle_bin()
            && self.search_query.trim().is_empty()
            && !self.favorites_only
        {
            return true;
        }
        let Some(tree) = &self.group_tree else {
            return false;
        };
        let Some(bin_node) = find_recycle_bin_node(tree) else {
            return false;
        };
        let rel_bin = strip_root_prefix(&tree.path, &bin_node.path);
        entry_path.starts_with(&format!("{}/", bin_node.path))
            || (!rel_bin.is_empty() && entry_path.starts_with(&format!("{rel_bin}/")))
    }

    /// Navigates to the group at `path`, expanding ancestor nodes and updating breadcrumbs.
    pub fn select_group_by_path(&mut self, path: &str, unix_now: u64) {
        if self.saving {
            return;
        }
        let Some(chain) = self
            .group_tree
            .as_ref()
            .and_then(|tree| find_tree_chain_by_path(tree, path))
        else {
            return;
        };
        self.apply_tree_chain(&chain, unix_now);
    }

    fn apply_tree_chain(&mut self, chain: &[GroupTreeNode], unix_now: u64) {
        let Some(target) = chain.last() else {
            return;
        };
        self.search_query.clear();
        self.favorites_only = false;
        self.editor = None;
        self.breadcrumbs.clear();
        self.breadcrumb_icons.clear();
        for (idx, node) in chain.iter().enumerate() {
            let label = if idx == 0 {
                String::from("Root")
            } else {
                node.label.clone()
            };
            self.breadcrumbs.push((label, node.reference.clone()));
            self.breadcrumb_icons
                .push((node.icon_id, node.custom_icon_id));
            if idx + 1 < chain.len() {
                self.expanded_groups.insert(node.path.clone());
            }
        }
        self.current_group_path.clone_from(&target.path);
        if let Err(err) = self.load_group_contents(&target.reference, None) {
            self.set_browser_error(err.message().to_owned());
        } else if let Some(entry) = self.entries.first().map(SearchHit::reference) {
            let _ = entry;
            self.select_entry(0, unix_now);
        }
    }

    /// Creates a new subgroup inside an explicit `parent` group and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or creation fails.
    pub fn create_subgroup_in(
        &mut self,
        parent: &GroupRef,
        parent_path: &str,
        name: &str,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let trimmed = name.trim();
        self.service
            .add_group(parent, trimmed)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.expanded_groups.insert(parent_path.to_owned());
        let current_path = self.detail.as_ref().map(|detail| detail.path.clone());
        let current_idx = self.selected_index;
        let fresh_editor_path = self.editor.as_ref().map(|ed| ed.path.clone());
        self.reload_after_mutation(
            None,
            current_path.as_deref(),
            current_idx,
            current_unix_seconds(),
        )
        .map_err(|err| err.message().to_owned())?;
        if let Some(editor) = self.editor.as_mut()
            && let Some(new_detail) = &self.detail
            && fresh_editor_path.as_deref() == Some(new_detail.path.as_str())
        {
            editor.entry_ref = new_detail.entry_ref.clone();
        }
        self.set_browser_info(format!("Created group \"{trimmed}\""));
        Ok(())
    }

    /// Renames `group` via [`VaultService::rename_group`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or rename validation fails.
    pub fn rename_group(&mut self, group: &GroupRef, name: &str) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let trimmed = name.trim();
        let old_path = self
            .group_tree
            .as_ref()
            .and_then(|tree| find_tree_node_by_ref(tree, group))
            .map(|n| n.path.clone());
        let was_current = self.current_group_ref().is_some_and(|cur| cur == group);
        let depth_idx = self.breadcrumbs.iter().position(|(_, r)| r == group);
        self.service
            .rename_group(group, trimmed)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        if let Some(idx) = depth_idx
            && idx > 0
        {
            trimmed.clone_into(&mut self.breadcrumbs[idx].0);
        }
        if let Some(old) = old_path {
            let new_path = match old.rsplit_once('/') {
                Some((parent, _)) => format!("{parent}/{trimmed}"),
                None => trimmed.to_owned(),
            };
            if self.expanded_groups.remove(&old) {
                self.expanded_groups.insert(new_path.clone());
            }
            if was_current {
                self.current_group_path = new_path;
            }
        }
        self.editor = None;
        self.reload_after_mutation(None, None, self.selected_index, current_unix_seconds())
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info(format!("Renamed group to \"{trimmed}\" (unsaved)"));
        Ok(())
    }

    /// Sets a standard `KeePass` icon (`0..=68`) on `group` and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or icon ID is invalid.
    pub fn set_group_icon_by_ref(&mut self, group: &GroupRef, icon_id: u32) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        if !is_valid_standard_icon_id(icon_id) {
            return Err(String::from("invalid icon id"));
        }
        self.service
            .set_group_icon(group, icon_id)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.refresh_after_icon_change()?;
        self.set_browser_info("Group icon updated (unsaved)");
        Ok(())
    }

    /// Sets an embedded custom icon on `group` and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or icon UUID is unknown.
    pub fn set_group_custom_icon_by_ref(
        &mut self,
        group: &GroupRef,
        id: CustomIconId,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        self.service
            .set_group_custom_icon(group, id)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.refresh_after_icon_change()?;
        self.set_browser_info("Group custom icon updated (unsaved)");
        Ok(())
    }

    /// Sets a standard `KeePass` icon (`0..=68`) on `entry_ref` and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or icon ID is invalid.
    pub fn set_entry_icon_by_ref(
        &mut self,
        entry_ref: &EntryRef,
        icon_id: u32,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        if !is_valid_standard_icon_id(icon_id) {
            return Err(String::from("invalid icon id"));
        }
        self.service
            .set_entry_icon(entry_ref, icon_id)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.reload_after_mutation(None, None, self.selected_index, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Entry icon updated (unsaved)");
        Ok(())
    }

    /// Sets an embedded custom icon on `entry_ref` and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or icon UUID is unknown.
    pub fn set_entry_custom_icon_by_ref(
        &mut self,
        entry_ref: &EntryRef,
        id: CustomIconId,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        self.service
            .set_entry_custom_icon(entry_ref, id)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.reload_after_mutation(None, None, self.selected_index, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Entry custom icon updated (unsaved)");
        Ok(())
    }

    fn refresh_after_icon_change(&mut self) -> Result<(), String> {
        let current_path = self.detail.as_ref().map(|detail| detail.path.clone());
        let current_idx = self.selected_index;
        let fresh_editor_path = self.editor.as_ref().map(|ed| ed.path.clone());
        self.reload_after_mutation(
            None,
            current_path.as_deref(),
            current_idx,
            current_unix_seconds(),
        )
        .map_err(|err| err.message().to_owned())?;
        if let Some(editor) = self.editor.as_mut()
            && let Some(new_detail) = &self.detail
            && fresh_editor_path.as_deref() == Some(new_detail.path.as_str())
        {
            editor.entry_ref = new_detail.entry_ref.clone();
        }
        Ok(())
    }

    /// Lists embedded custom icons in the open vault.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when locked or icon metadata violates bounds.
    pub fn list_custom_icons(&self) -> Result<Vec<CustomIconSummary>, ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        self.service.list_custom_icons(session)
    }

    /// Returns whether entries in the current list can be reordered in place.
    #[must_use]
    pub fn can_reorder_entries(&self) -> bool {
        self.is_unlocked()
            && !self.saving
            && self.search_query.trim().is_empty()
            && !self.favorites_only
            && self.entries.len() > 1
    }

    /// Moves entry at `from_index` to `to_index` within the current group via
    /// [`VaultService::reorder_entry`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if reordering is unavailable or fails.
    pub fn reorder_entry_to(
        &mut self,
        from_index: usize,
        to_index: usize,
        unix_now: u64,
    ) -> Result<(), String> {
        if !self.can_reorder_entries() {
            return Err(String::from("reordering is only available inside a group"));
        }
        if from_index >= self.entries.len() || to_index >= self.entries.len() {
            return Err(String::from("entry index out of range"));
        }
        if from_index == to_index {
            return Ok(());
        }
        let entry_ref = self.entries[from_index].reference();
        let moved_ref = self
            .service
            .reorder_entry(&entry_ref, to_index)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.reload_after_mutation(Some(&moved_ref), None, Some(to_index), unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Reordered entry (unsaved)");
        Ok(())
    }

    /// Moves the currently selected entry one position up in its group.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if unable to move up.
    pub fn move_selected_entry_up(&mut self, unix_now: u64) -> Result<(), String> {
        let idx = self
            .selected_index
            .ok_or_else(|| String::from("no entry selected"))?;
        if idx == 0 {
            return Err(String::from("entry is already first in group"));
        }
        self.reorder_entry_to(idx, idx - 1, unix_now)
    }

    /// Moves the currently selected entry one position down in its group.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if unable to move down.
    pub fn move_selected_entry_down(&mut self, unix_now: u64) -> Result<(), String> {
        let idx = self
            .selected_index
            .ok_or_else(|| String::from("no entry selected"))?;
        if idx + 1 >= self.entries.len() {
            return Err(String::from("entry is already last in group"));
        }
        self.reorder_entry_to(idx, idx + 1, unix_now)
    }

    /// Moves `entry_ref` into `target_group` via [`VaultService::move_entry`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if saving is active or the move fails.
    pub fn move_entry_to_group(
        &mut self,
        entry_ref: &EntryRef,
        target_group: &GroupRef,
        target_label: &str,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        self.service
            .move_entry(entry_ref, target_group)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.reload_after_mutation(None, None, self.selected_index, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info(format!("Moved entry to \"{target_label}\" (unsaved)"));
        Ok(())
    }

    /// Clones `entry_ref` via [`VaultService::clone_entry`], selects the clone, and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if saving is active or cloning fails.
    pub fn clone_entry(&mut self, entry_ref: &EntryRef, unix_now: u64) -> Result<EntryRef, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let cloned = self
            .service
            .clone_entry(entry_ref)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.reload_after_mutation(Some(&cloned), None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Cloned entry (unsaved)");
        Ok(cloned)
    }

    /// Clones the currently selected entry via [`Self::clone_entry`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if no entry is selected or cloning fails.
    pub fn clone_selected_entry(&mut self, unix_now: u64) -> Result<EntryRef, String> {
        let entry_ref = self
            .detail
            .as_ref()
            .map(|detail| detail.entry_ref.clone())
            .ok_or_else(|| String::from("no entry selected"))?;
        self.clone_entry(&entry_ref, unix_now)
    }

    /// Restores `entry_ref` from the Recycle Bin via [`VaultService::restore_entry`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if saving is active or restore fails.
    pub fn restore_entry(
        &mut self,
        entry_ref: &EntryRef,
        unix_now: u64,
    ) -> Result<EntryRef, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let restored = self
            .service
            .restore_entry(entry_ref)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        self.reload_after_mutation(None, None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Restored entry from Recycle Bin (unsaved)");
        Ok(restored)
    }

    /// Restores the currently selected entry from the Recycle Bin.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if no entry is selected or restore fails.
    pub fn restore_selected_entry(&mut self, unix_now: u64) -> Result<EntryRef, String> {
        let entry_ref = self
            .detail
            .as_ref()
            .map(|detail| detail.entry_ref.clone())
            .ok_or_else(|| String::from("no entry selected"))?;
        self.restore_entry(&entry_ref, unix_now)
    }

    /// Empties the Recycle Bin via [`VaultService::empty_recycle_bin`] and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or emptying fails.
    pub fn empty_recycle_bin(&mut self, unix_now: u64) -> Result<usize, String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let session = self
            .session
            .ok_or_else(|| String::from("vault is locked"))?;
        let count = self
            .service
            .empty_recycle_bin(session)
            .map_err(|err| err.message().to_owned())?;
        if count > 0 {
            self.dirty = true;
        }
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        self.reload_after_mutation(None, None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info(if count == 0 {
            String::from("Recycle Bin is already empty")
        } else {
            format!("Emptied Recycle Bin ({count} item(s) permanently deleted, unsaved)")
        });
        Ok(count)
    }

    /// Reads safe database-level settings via [`VaultService::database_settings`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked or reading settings fails.
    pub fn database_settings(&self) -> Result<DatabaseSettings, String> {
        let session = self
            .session
            .ok_or_else(|| String::from("vault is locked"))?;
        self.service
            .database_settings(session)
            .map_err(|err| err.message().to_owned())
    }

    /// Updates database-level settings via [`VaultService::update_database_settings`] and
    /// marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or validation fails.
    pub fn update_database_settings(
        &mut self,
        update: DatabaseSettingsUpdate,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let session = self
            .session
            .ok_or_else(|| String::from("vault is locked"))?;
        self.service
            .update_database_settings(session, update)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.reload_after_mutation(None, None, self.selected_index, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.set_browser_info("Database settings updated (unsaved)");
        Ok(())
    }

    /// Formats a `full_path` from [`GroupTreeNode`] or [`PathCompletion`] into a `/`-prefixed
    /// display path for the editable Path Bar.
    #[must_use]
    pub fn format_display_path(&self, full_path: &str) -> String {
        let Some(root_name) = self.group_tree.as_ref().map(|t| t.path.as_str()) else {
            return String::from("/");
        };
        let rel = strip_root_prefix(root_name, full_path);
        if rel.is_empty() {
            String::from("/")
        } else {
            format!("/{rel}")
        }
    }

    /// Returns the `/`-prefixed path of the currently selected entry (or current group).
    #[must_use]
    pub fn current_display_path(&self) -> String {
        if let Some(detail) = &self.detail {
            return self.format_display_path(&detail.path);
        }
        self.format_display_path(&self.current_group_path)
    }

    /// Completes group/entry paths up to `limit` items via [`VaultService::complete_path`].
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked or prefix validation fails.
    pub fn complete_path(&self, prefix: &str, limit: usize) -> Result<Vec<PathCompletion>, String> {
        let session = self
            .session
            .ok_or_else(|| String::from("vault is locked"))?;
        self.service
            .complete_path(session, prefix, limit)
            .map_err(|err| err.message().to_owned())
    }

    /// Navigates straight to a selected [`PathCompletion`] group or entry.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if saving is active or navigation fails.
    pub fn navigate_to_completion(
        &mut self,
        completion: &PathCompletion,
        unix_now: u64,
    ) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        if completion.is_group {
            if let Some(chain) = self
                .group_tree
                .as_ref()
                .and_then(|tree| find_tree_chain_by_path(tree, &completion.path))
            {
                self.apply_tree_chain(&chain, unix_now);
                return Ok(());
            }
            return Err(String::from("group not found"));
        }
        let parent_full = completion
            .path
            .rsplit_once('/')
            .map_or("", |(parent, _)| parent);
        let chain = self
            .group_tree
            .as_ref()
            .and_then(|tree| {
                if parent_full.is_empty() {
                    Some(vec![tree.clone()])
                } else {
                    find_tree_chain_by_path(tree, parent_full)
                }
            })
            .ok_or_else(|| String::from("parent group not found"))?;
        self.apply_tree_chain(&chain, unix_now);
        if let Some(target_ref) = &completion.entry_ref
            && let Some(idx) = self
                .entries
                .iter()
                .position(|hit| hit.reference() == *target_ref)
        {
            self.select_entry(idx, unix_now);
            return Ok(());
        }
        let rel_entry = self
            .group_tree
            .as_ref()
            .map_or(completion.path.as_str(), |tree| {
                strip_root_prefix(&tree.path, &completion.path)
            });
        if let Some(idx) = self
            .entries
            .iter()
            .position(|hit| hit.path() == rel_entry || hit.path() == completion.path)
        {
            self.select_entry(idx, unix_now);
        }
        Ok(())
    }

    /// Sets an informational inject banner status.
    pub fn set_inject_info(&mut self, msg: impl Into<String>) {
        self.inject_status = Some(msg.into());
        self.inject_status_is_error = false;
    }

    /// Sets an error inject banner status.
    pub fn set_inject_error(&mut self, msg: impl Into<String>) {
        self.inject_status = Some(msg.into());
        self.inject_status_is_error = true;
    }

    /// Updates `inject_input` and refreshes reference extraction without resolving secrets.
    pub fn set_inject_input(&mut self, input: String) {
        self.inject_input = input;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        self.inject_status_is_error = false;
        self.refresh_inject_preview();
    }

    /// Switches between [`InjectMode::Template`] and [`InjectMode::EnvFile`] and re-parses.
    pub fn set_inject_mode(&mut self, mode: InjectMode) {
        self.inject_mode = mode;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        self.inject_status_is_error = false;
        self.refresh_inject_preview();
    }

    /// Extracts `nkp://` references (and parses `.env` syntax in [`InjectMode::EnvFile`])
    /// without reading any secret values.
    pub fn refresh_inject_preview(&mut self) {
        self.extracted_refs.clear();
        self.parsed_env_lines.clear();
        self.inject_preview_error = None;

        match self.inject_mode {
            InjectMode::Template => match extract_references(&self.inject_input) {
                Ok(refs) => self.extracted_refs = refs,
                Err(err) => self.inject_preview_error = Some(err.to_string()),
            },
            InjectMode::EnvFile => match parse_env_file(&self.inject_input) {
                Ok(lines) => {
                    for line in &lines {
                        if let EnvValueKind::Template(tmpl) = &line.value {
                            match extract_references(tmpl) {
                                Ok(refs) => self.extracted_refs.extend(refs),
                                Err(err) => {
                                    self.extracted_refs.clear();
                                    self.parsed_env_lines.clear();
                                    self.inject_preview_error = Some(err.to_string());
                                    return;
                                }
                            }
                        }
                    }
                    self.parsed_env_lines = lines;
                }
                Err(err) => self.inject_preview_error = Some(err.to_string()),
            },
        }
    }

    /// Renders `inject_input` over the active unlocked [`VaultService`] session.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError`] when the vault is locked or any reference fails resolution.
    pub fn render_inject(&mut self, unix_now: u64) -> Result<(), TemplateError> {
        if self.saving {
            return Err(TemplateError::VaultLocked);
        }
        let session = self.session.ok_or(TemplateError::VaultLocked)?;
        let mut lookup = ServiceSecretLookup::new(&self.service, session, unix_now);
        let output = match self.inject_mode {
            InjectMode::Template => render_text(
                &self.inject_input,
                &mut lookup,
                &RenderOptions {
                    escape: ValueEscape::Raw,
                    allow_newlines: true,
                    ..RenderOptions::default()
                },
            )?,
            InjectMode::EnvFile => {
                let parsed = parse_env_file(&self.inject_input)?;
                let resolved = resolve_env_file(&parsed, &mut lookup)?;
                let capacity = resolved.iter().fold(0_usize, |acc, (name, value)| {
                    acc.saturating_add(name.len())
                        .saturating_add(dotenv_double_quoted_len(value))
                        .saturating_add(2)
                });
                let mut rendered = Zeroizing::new(String::with_capacity(capacity));
                for (name, value) in resolved {
                    rendered.push_str(&name);
                    rendered.push('=');
                    push_dotenv_double_quoted(&mut rendered, &value);
                    rendered.push('\n');
                }
                rendered
            }
        };
        self.rendered_output = Some(output);
        self.inject_output_revealed = false;
        self.set_inject_info("Rendered securely in memory (masked)");
        Ok(())
    }

    /// Saves `rendered_output` to `inject_save_path` with owner-only permissions
    /// and no-clobber installation via [`write_private_noclobber`].
    ///
    /// # Errors
    ///
    /// Returns a fixed status diagnostic if nothing is rendered, path is empty,
    /// or private file creation fails.
    pub fn save_inject_output(&mut self) -> Result<(), &'static str> {
        let target = self.inject_save_path.trim();
        if target.is_empty() {
            let msg = "enter a target path before saving";
            self.set_inject_error(msg);
            return Err(msg);
        }
        let Some(output) = &self.rendered_output else {
            let msg = "render the template before saving";
            self.set_inject_error(msg);
            return Err(msg);
        };
        if let Err(err) = write_private_noclobber(Path::new(target), output.as_bytes()) {
            self.set_inject_error(err);
            return Err(err);
        }
        self.set_inject_info("Saved private output (no-clobber)");
        Ok(())
    }
}

/// Formats a byte size into a compact human-readable label.
#[must_use]
pub fn format_byte_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        let whole = bytes / 1024;
        let tenths = ((bytes % 1024) * 10) / 1024;
        format!("{whole}.{tenths} KiB")
    } else {
        let whole = bytes / (1024 * 1024);
        let tenths = ((bytes % (1024 * 1024)) * 10) / (1024 * 1024);
        format!("{whole}.{tenths} MiB")
    }
}

fn is_bidi_or_line_separator(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Sanitizes an untrusted attachment filename before prefilling a save dialog.
///
/// Extracts the final component across `/` and `\` separators, strips control,
/// NUL, separator, and Unicode BiDi/line-separator characters, and falls back
/// to `"attachment.bin"` if the resulting name is empty, `"."`, or `".."`.
#[must_use]
pub fn sanitize_attachment_prefill(raw_name: &str) -> String {
    let base = raw_name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|&ch| {
            !ch.is_control()
                && !is_bidi_or_line_separator(ch)
                && ch != '/'
                && ch != '\\'
                && ch != '\0'
        })
        .collect();
    let trimmed = cleaned.trim();
    if matches!(trimmed, "" | "." | "..") {
        String::from("attachment.bin")
    } else {
        trimmed.to_owned()
    }
}

fn dotenv_double_quoted_len(value: &str) -> usize {
    let mut len = 2_usize;
    for ch in value.chars() {
        len = len.saturating_add(match ch {
            '\\' | '"' | '\n' | '\r' => 2,
            other => other.len_utf8(),
        });
    }
    len
}

fn push_dotenv_double_quoted(out: &mut Zeroizing<String>, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
}

fn parse_otp_draft_from_uri(raw_uri: &str, had_otp_field: bool) -> OtpDraftConfig {
    let trimmed = raw_uri.trim();
    if trimmed.is_empty() {
        return OtpDraftConfig {
            mode: if had_otp_field {
                OtpEditorMode::RawUri
            } else {
                OtpEditorMode::None
            },
            ..OtpDraftConfig::default()
        };
    }
    let Ok(parsed) = OtpUri::parse(trimmed) else {
        return OtpDraftConfig {
            mode: OtpEditorMode::RawUri,
            ..OtpDraftConfig::default()
        };
    };
    let mode = match parsed.kind {
        OtpKind::Totp => OtpEditorMode::Totp,
        OtpKind::Hotp => OtpEditorMode::Hotp,
    };
    let algorithm = match parsed.algorithm {
        OtpAlgorithm::Sha1 => ServiceOtpAlgorithm::Sha1,
        OtpAlgorithm::Sha256 => ServiceOtpAlgorithm::Sha256,
        OtpAlgorithm::Sha512 => ServiceOtpAlgorithm::Sha512,
    };
    let digits = match parsed.digits {
        OtpDigits::Five => 5,
        OtpDigits::Six => 6,
        OtpDigits::Eight => 8,
    };
    let steam = parsed.encoder == OtpEncoder::Steam;
    OtpDraftConfig {
        mode,
        secret: Zeroizing::new(parsed.secret.clone()),
        algorithm,
        digits: if steam { 6 } else { digits },
        period: parsed.period.unwrap_or(30),
        counter: parsed.counter.unwrap_or(0),
        steam,
    }
}

/// Converts a structured [`OtpDraftConfig`] into a service [`OtpConfig`].
#[must_use]
pub fn otp_config_from_draft(draft: &OtpDraftConfig, entry_title: &str) -> OtpConfig {
    let kind = match draft.mode {
        OtpEditorMode::Hotp => ServiceOtpKind::Hotp,
        OtpEditorMode::Totp | OtpEditorMode::None | OtpEditorMode::RawUri => ServiceOtpKind::Totp,
    };
    let account = if entry_title.trim().is_empty() {
        String::from("account")
    } else {
        entry_title.trim().to_owned()
    };
    OtpConfig {
        kind,
        account,
        issuer: None,
        algorithm: draft.algorithm,
        digits: if draft.steam { 5 } else { draft.digits },
        period: (kind == ServiceOtpKind::Totp).then_some(draft.period.max(1)),
        counter: (kind == ServiceOtpKind::Hotp).then_some(draft.counter),
        steam: draft.steam,
    }
}

fn collect_visible_tree_groups(
    node: &GroupTreeNode,
    depth: usize,
    expanded: &BTreeSet<String>,
    out: &mut Vec<VisibleTreeGroup>,
) {
    let has_children = !node.children.is_empty();
    let is_expanded = depth == 0 || expanded.contains(&node.path);
    out.push(VisibleTreeGroup {
        reference: node.reference.clone(),
        label: if depth == 0 {
            String::from("Root")
        } else {
            node.label.clone()
        },
        path: node.path.clone(),
        depth,
        icon_id: node.icon_id,
        custom_icon_id: node.custom_icon_id,
        entry_count: node.entry_count,
        is_recycle_bin: node.is_recycle_bin,
        has_children,
        expanded: is_expanded,
        is_root: depth == 0,
    });
    if is_expanded {
        for child in &node.children {
            collect_visible_tree_groups(child, depth + 1, expanded, out);
        }
    }
}

fn find_tree_node_by_ref<'a>(
    node: &'a GroupTreeNode,
    target: &GroupRef,
) -> Option<&'a GroupTreeNode> {
    if &node.reference == target {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_tree_node_by_ref(child, target) {
            return Some(found);
        }
    }
    None
}

fn find_tree_chain_by_path(node: &GroupTreeNode, path: &str) -> Option<Vec<GroupTreeNode>> {
    if node.path == path {
        return Some(vec![node.clone()]);
    }
    for child in &node.children {
        if let Some(mut rest) = find_tree_chain_by_path(child, path) {
            let mut chain = Vec::with_capacity(rest.len() + 1);
            chain.push(node.clone());
            chain.append(&mut rest);
            return Some(chain);
        }
    }
    None
}

fn find_recycle_bin_node(node: &GroupTreeNode) -> Option<&GroupTreeNode> {
    if node.is_recycle_bin {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_recycle_bin_node(child) {
            return Some(found);
        }
    }
    None
}

fn is_group_path_in_recycle_bin(root: &GroupTreeNode, path: &str) -> bool {
    let Some(bin) = find_recycle_bin_node(root) else {
        return false;
    };
    path == bin.path || path.starts_with(&format!("{}/", bin.path))
}

fn strip_root_prefix<'a>(root_name: &str, full_path: &'a str) -> &'a str {
    if full_path == root_name {
        return "";
    }
    if let Some(rest) = full_path.strip_prefix(root_name)
        && let Some(stripped) = rest.strip_prefix('/')
    {
        return stripped;
    }
    full_path
}

#[cfg(test)]
mod tests {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxKdf, KdbxWriteOptions, KeePassDatabase,
        ProtectedValue,
    };
    use tempfile::tempdir;

    use super::*;

    fn fast_write_options() -> KdbxWriteOptions {
        KdbxWriteOptions {
            kdf: KdbxKdf::Argon2id,
            argon2_memory_kib: 1024,
            argon2_time: 1,
            argon2_lanes: 1,
            ..KdbxWriteOptions::default()
        }
    }

    fn build_fixture_vault(dir: &Path) -> Result<(PathBuf, Zeroizing<String>), String> {
        let path = dir.join("fixture.kdbx");
        let master = Zeroizing::new(String::from("correct horse battery staple"));

        let mut db = KeePassDatabase::default();
        let mut group = Group::new("Infra");
        let mut prod = Entry::new("ProdAPI");
        prod.username = String::from("deploy-bot");
        prod.url = String::from("https://api.example.internal");
        prod.notes = String::from("Production API token");
        prod.password = ProtectedValue::from_text("s3cr3t-api-token");
        prod.fields.push(neotales_keepass::Field {
            key: String::from("otp"),
            value: ProtectedValue::from_text(
                "otpauth://totp/Example:deploy?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30",
            ),
            protected: true,
            protect_in_memory: true,
        });
        prod.fields.push(neotales_keepass::Field {
            key: String::from("SigningKey"),
            value: ProtectedValue::from_text("sign-key-xyz"),
            protected: true,
            protect_in_memory: true,
        });
        prod.fields.push(neotales_keepass::Field {
            key: String::from("ComplexSecret"),
            value: ProtectedValue::from_text("line1 # comment\n\"quoted\" \\ slash"),
            protected: true,
            protect_in_memory: true,
        });
        let mut protected_note = Entry::new("ProtectedNoteEntry");
        protected_note.fields.push(neotales_keepass::Field {
            key: String::from("Notes"),
            value: ProtectedValue::from_text("classified note body"),
            protected: true,
            protect_in_memory: true,
        });
        group.entries.push(prod);
        group.entries.push(protected_note);
        db.root.groups.push(group);

        let mut creds =
            KdbxCredentials::password(master.as_bytes()).map_err(|err| err.to_string())?;
        let mut file = File::create(&path).map_err(|err| err.to_string())?;
        KdbxFile::save(
            &db,
            &mut file,
            &mut creds,
            fast_write_options(),
            &KDBX_LIMITS,
        )
        .map_err(|err| err.to_string())?;

        Ok((path, master))
    }

    fn run_save_blocking(
        ctrl: &mut VaultController,
        for_lock: bool,
    ) -> Result<LockCleanup, String> {
        let (gen_id, path, service, credentials) = ctrl
            .begin_save(for_lock)
            .ok_or_else(|| String::from("begin_save unexpectedly returned None"))?;
        assert!(ctrl.saving);
        let outcome = save_vault_blocking(gen_id, &path, service, credentials);
        Ok(ctrl.finish_save(outcome))
    }

    #[test]
    fn unlock_search_reveal_totp_and_lock_lifecycle() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock unexpectedly returned None"))?;
        assert_eq!(ctrl.phase, VaultPhase::Unlocking);

        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        assert!(ctrl.is_unlocked());
        assert!(!ctrl.dirty);
        assert_eq!(ctrl.child_groups.len(), 1);
        assert_eq!(ctrl.child_groups[0].label(), "Infra");

        // Navigate into Infra group and inspect entry detail.
        ctrl.open_child_group(0);
        assert_eq!(ctrl.entries.len(), 2);
        assert_eq!(ctrl.entries[0].title(), "ProdAPI");
        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail should be populated on entry selection"))?;
        assert_eq!(detail.username, "deploy-bot");
        assert_eq!(detail.url, "https://api.example.internal");
        assert!(detail.revealed_password.is_none());
        assert!(detail.totp.is_some());

        ctrl.refresh_selected_totp(1_700_000_000);
        let refreshed_totp = ctrl
            .detail
            .as_ref()
            .and_then(|d| d.totp.as_ref())
            .ok_or_else(|| String::from("totp should remain populated after refresh"))?;
        assert_eq!(refreshed_totp.period, 30);
        assert_eq!(refreshed_totp.remaining_secs, 10);
        assert_eq!(refreshed_totp.code.len(), 6);

        // Explicit reveal populates Zeroizing password and custom field.
        ctrl.toggle_reveal_password();
        ctrl.toggle_reveal_custom_field(1);
        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail missing after reveal"))?;
        assert_eq!(
            detail
                .revealed_password
                .as_ref()
                .and_then(RevealedSecret::as_text),
            Some("s3cr3t-api-token")
        );
        assert_eq!(
            detail
                .revealed_custom_fields
                .get(&1)
                .and_then(RevealedSecret::as_text),
            Some("sign-key-xyz")
        );

        // Selecting ProtectedNoteEntry marks Notes as protected and allows explicit reveal.
        ctrl.select_entry(1, 1_700_000_000);
        let note_detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("protected note detail missing"))?;
        assert!(note_detail.protected_standard_fields.contains_key("Notes"));
        assert_eq!(note_detail.notes, "");
        ctrl.toggle_reveal_standard_field("Notes");
        let note_detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("protected note detail missing after reveal"))?;
        assert_eq!(
            note_detail
                .revealed_standard_fields
                .get("Notes")
                .and_then(RevealedSecret::as_text),
            Some("classified note body")
        );

        // Search works from anywhere in unlocked session.
        ctrl.set_search_query(String::from("ProdAPI"), 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);

        // Focus loss does NOT lock by default; when opt-in lock_on_focus_loss is enabled,
        // clean vaults lock immediately while preserving clipboard lease.
        let default_cleanup = ctrl.on_window_focus(false);
        assert!(!default_cleanup.locked_active_session);
        assert!(ctrl.is_unlocked());
        ctrl.lock_on_focus_loss = true;
        let cleanup = ctrl.on_window_focus(false);
        assert!(cleanup.locked_active_session);
        assert!(!cleanup.clear_clipboard);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert!(!ctrl.is_unlocked());
        assert!(!ctrl.has_credentials());
        assert!(!ctrl.has_session());
        assert!(ctrl.detail.is_none());
        assert!(ctrl.entries.is_empty());
        assert!(ctrl.child_groups.is_empty());
        Ok(())
    }

    #[test]
    fn inject_template_env_file_and_idle_lock() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 100.0);

        ctrl.set_inject_mode(InjectMode::EnvFile);
        ctrl.set_inject_input(String::from(
            "export API_TOKEN=nkp://Infra/ProdAPI#Password\nCOMPLEX=nkp://Infra/ProdAPI#ComplexSecret\n",
        ));
        assert!(ctrl.inject_preview_error.is_none());
        assert_eq!(ctrl.extracted_refs.len(), 2);

        ctrl.render_inject(1_700_000_000)
            .map_err(|err| format!("render_inject failed: {err}"))?;
        let expected_env = "API_TOKEN=\"s3cr3t-api-token\"\nCOMPLEX=\"line1 # comment\\n\\\"quoted\\\" \\\\ slash\"\n";
        assert_eq!(
            ctrl.rendered_output.as_deref().map(String::as_str),
            Some(expected_env)
        );
        // Rendered .env output must remain valid and round-trip through parse_env_file.
        let reparsed = parse_env_file(expected_env).map_err(|err| err.to_string())?;
        assert_eq!(reparsed.len(), 2);

        let out_file = dir.path().join("rendered.env");
        ctrl.inject_save_path = out_file.to_string_lossy().into_owned();
        ctrl.save_inject_output().map_err(str::to_owned)?;
        let disk = std::fs::read_to_string(&out_file).map_err(|err| err.to_string())?;
        assert_eq!(disk, expected_env);

        // Second save refuses to clobber existing private file.
        assert!(ctrl.save_inject_output().is_err());

        // Idle timeout at +300s locks, clears clipboard, and wipes rendered output.
        assert!(!ctrl.check_idle_timeout(399.0).locked_active_session);
        let idle_cleanup = ctrl.check_idle_timeout(400.0);
        assert!(idle_cleanup.locked_active_session);
        assert!(idle_cleanup.clear_clipboard);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert!(ctrl.rendered_output.is_none());
        assert_eq!(
            ctrl.render_inject(1_700_000_000),
            Err(TemplateError::VaultLocked)
        );
        Ok(())
    }

    #[test]
    fn regular_file_guard_and_env_preview_error() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let outcome = open_vault_blocking(dir.path(), &Zeroizing::new(String::from("pw")), None);
        assert!(matches!(outcome.result, Err(ref msg) if msg.contains("not a regular file")));

        let mut ctrl = VaultController::new();
        ctrl.set_inject_mode(InjectMode::EnvFile);
        ctrl.set_inject_input(String::from("BAD=nkp://invalid/../path\n"));
        assert!(ctrl.inject_preview_error.is_some());
        assert_eq!(ctrl.extracted_refs.len(), 0);
        Ok(())
    }

    fn exercise_attachments_and_limits(
        ctrl: &mut VaultController,
        dir: &Path,
        bin_payload: &[u8],
    ) -> Result<(), String> {
        let src_bin = dir.join("deploy.key");
        std::fs::write(&src_bin, bin_payload).map_err(|err| err.to_string())?;
        ctrl.attach_file(&src_bin, None)?;

        let src_extra = dir.join("remove.txt");
        std::fs::write(&src_extra, b"ephemeral").map_err(|err| err.to_string())?;
        ctrl.attach_file(&src_extra, Some("ephemeral.txt"))?;

        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail missing after attach"))?;
        assert_eq!(detail.attachments.len(), 2);
        assert_eq!(detail.attachments[0].name(), "deploy.key");
        assert_eq!(detail.attachments[0].size(), bin_payload.len());
        assert!(detail.attachments[0].protected());

        let extract_dest = dir.join("extracted-deploy.key");
        ctrl.extract_attachment(0, &extract_dest)?;
        let extracted = std::fs::read(&extract_dest).map_err(|err| err.to_string())?;
        assert_eq!(extracted, bin_payload);
        assert!(ctrl.extract_attachment(0, &extract_dest).is_err());

        ctrl.remove_attachment("ephemeral.txt")?;
        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail missing after attachment removal"))?;
        assert_eq!(detail.attachments.len(), 1);

        let oversized_path = dir.join("too-big.bin");
        let big_file = File::create(&oversized_path).map_err(|err| err.to_string())?;
        big_file
            .set_len(MAX_ATTACHMENT_BYTES + 1)
            .map_err(|err| err.to_string())?;
        assert!(ctrl.attach_file(&oversized_path, None).is_err());
        Ok(())
    }

    fn verify_reopened_entry(
        vault_path: &Path,
        master: &Zeroizing<String>,
        generated: &Zeroizing<String>,
        bin_payload: &[u8],
    ) -> Result<(), String> {
        let mut reopened = VaultController::new();
        reopened.vault_path = vault_path.to_string_lossy().into_owned();
        let (path2, key2, gen2) = reopened
            .begin_unlock(false)
            .ok_or_else(|| String::from("reopen begin_unlock failed"))?;
        let outcome2 = open_vault_blocking(&path2, master, key2.as_deref());
        reopened.finish_unlock(gen2, outcome2, 20.0);
        assert!(reopened.is_unlocked());
        assert_eq!(reopened.child_groups.len(), 1);
        assert_eq!(reopened.child_groups[0].label(), "Engineering");
        reopened.open_child_group(0);
        assert_eq!(reopened.entries.len(), 1);
        let d = reopened
            .detail
            .as_ref()
            .ok_or_else(|| String::from("reopened detail missing"))?;
        assert_eq!(d.metadata.title(), "GitLab Prod");
        assert_eq!(d.username, "ci-runner");
        assert_eq!(d.url, "https://gitlab.example.org");
        assert_eq!(d.notes, "Line 1\nLine 2");
        assert_eq!(d.metadata.tags(), &["ci", "infra"]);
        assert_eq!(d.metadata.custom_fields().len(), 1);
        assert_eq!(d.metadata.custom_fields()[0].name(), "ApiToken");
        assert!(d.metadata.custom_fields()[0].protected());
        reopened.toggle_reveal_custom_field(0);
        reopened.toggle_reveal_password();
        let d = reopened
            .detail
            .as_ref()
            .ok_or_else(|| String::from("reopened detail missing after reveal"))?;
        assert_eq!(
            d.revealed_custom_fields
                .get(&0)
                .and_then(RevealedSecret::as_text),
            Some("tok-456")
        );
        assert_eq!(
            d.revealed_password
                .as_ref()
                .and_then(RevealedSecret::as_text),
            Some(generated.as_str())
        );
        assert_eq!(d.attachments.len(), 1);
        assert_eq!(d.attachments[0].name(), "deploy.key");
        assert_eq!(d.attachments[0].size(), bin_payload.len());
        Ok(())
    }

    #[test]
    fn create_vault_crud_fields_custom_attachments_save_and_reopen() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let vault_path = dir.path().join("created.kdbx");
        let master = Zeroizing::new(String::from("brand-new-master-passphrase"));

        let mut ctrl = VaultController::new();
        ctrl.lock_mode = LockMode::Create;
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        assert!(ctrl.begin_create(false, false).is_none());
        assert!(
            ctrl.lock_status
                .as_deref()
                .is_some_and(|msg| msg.contains("do not match"))
        );

        let (path, key_path, gen_id) = ctrl
            .begin_create(false, true)
            .ok_or_else(|| String::from("begin_create failed"))?;
        let outcome = create_and_open_vault_with_options(
            &path,
            &master,
            key_path.as_deref(),
            fast_write_options(),
        );
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        assert!(ctrl.is_unlocked());
        assert!(!ctrl.dirty);

        ctrl.create_subgroup("Engineering")?;
        ctrl.open_child_group(0);
        ctrl.create_entry_in_current_group(Some("GitLab"), 1_700_000_000)?;
        let generated = ctrl.generate_editor_password()?;
        assert_eq!(generated.len(), 20);
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.title = String::from("GitLab Prod");
            editor.username = Zeroizing::new(String::from("ci-runner"));
            editor.url = Zeroizing::new(String::from("https://gitlab.example.org"));
            editor.notes = Zeroizing::new(String::from("Line 1\nLine 2"));
        }
        ctrl.add_editor_tags_from_input("ci, infra, CI")?;
        ctrl.add_editor_custom_field("ApiToken", Zeroizing::new(String::from("tok-123")), true)?;
        ctrl.add_editor_custom_field(
            "Environment",
            Zeroizing::new(String::from("staging")),
            false,
        )?;
        ctrl.add_editor_custom_field("TempNote", Zeroizing::new(String::from("remove-me")), false)?;
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.custom_fields[1].value = Zeroizing::new(String::from("production"));
        }
        ctrl.set_editor_custom_field_protected(1, true);
        ctrl.remove_editor_custom_field(2);
        ctrl.apply_entry_editor(1_700_000_000)?;

        ctrl.begin_edit_selected_entry()?;
        if let Some(editor) = ctrl.editor.as_mut() {
            assert_eq!(editor.custom_fields.len(), 2);
            editor.custom_fields[0].value = Zeroizing::new(String::from("tok-456"));
        }
        ctrl.remove_editor_custom_field(1);
        ctrl.apply_entry_editor(1_700_000_000)?;

        let bin_payload = b"-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n";
        exercise_attachments_and_limits(&mut ctrl, dir.path(), bin_payload)?;

        run_save_blocking(&mut ctrl, false)?;
        assert!(!ctrl.dirty);
        assert!(ctrl.lock().locked_active_session);
        assert!(!ctrl.has_credentials());

        verify_reopened_entry(&vault_path, &master, &generated, bin_payload)
    }

    #[test]
    fn delete_entry_and_group_refusing_root() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);

        // Root group deletion must be refused.
        let root_ref = ctrl
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("missing root group"))?;
        let root_err = ctrl.remove_group(&root_ref);
        assert!(root_err.is_err());
        assert!(!ctrl.dirty);

        // Navigate into Infra, delete one entry, then delete the Infra group itself.
        ctrl.open_child_group(0);
        assert_eq!(ctrl.entries.len(), 2);
        ctrl.delete_selected_entry(1_700_000_000)?;
        assert!(ctrl.dirty);
        assert_eq!(ctrl.entries.len(), 1);

        ctrl.remove_current_group()?;
        assert!(ctrl.dirty);
        assert!(ctrl.is_at_root());
        assert!(ctrl.child_groups.is_empty());
        Ok(())
    }

    #[test]
    fn dirty_vault_lock_decision_state_machine() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);

        // Mutate vault -> dirty == true.
        ctrl.create_subgroup("TempGroup")?;
        assert!(ctrl.dirty);

        // Dirty Lock opens modal instead of dropping credentials or discarding edits.
        let cleanup = ctrl.request_lock(LockTrigger::Manual);
        assert!(!cleanup.locked_active_session);
        assert!(ctrl.is_unlocked());
        assert!(ctrl.has_credentials());
        assert!(ctrl.pending_lock_decision.is_some());

        // Cancel stays unlocked & dirty with credentials retained.
        ctrl.cancel_pending_lock();
        assert!(ctrl.pending_lock_decision.is_none());
        assert!(ctrl.is_unlocked());
        assert!(ctrl.dirty);
        assert!(ctrl.has_credentials());

        // Focus loss & idle timeout when dirty also open modal without dropping credentials.
        ctrl.lock_on_focus_loss = true;
        let focus_cleanup = ctrl.on_window_focus(false);
        assert!(!focus_cleanup.locked_active_session);
        assert_eq!(
            ctrl.pending_lock_decision.as_ref().map(|d| d.trigger),
            Some(LockTrigger::FocusLoss)
        );
        assert!(ctrl.has_credentials());

        // Failed Save retains credentials and keeps modal open for retry.
        ctrl.vault_path = dir
            .path()
            .join("nonexistent-dir/vault.kdbx")
            .to_string_lossy()
            .into_owned();
        let failed_cleanup = run_save_blocking(&mut ctrl, true)?;
        assert!(!failed_cleanup.locked_active_session);
        assert!(ctrl.is_unlocked());
        assert!(ctrl.dirty);
        assert!(ctrl.has_credentials());
        assert!(
            ctrl.pending_lock_decision
                .as_ref()
                .and_then(|d| d.error.as_ref())
                .is_some()
        );

        // Discard & Lock drops credentials & discards unsaved edits.
        let discard_cleanup = ctrl.discard_and_lock();
        assert!(discard_cleanup.locked_active_session);
        assert!(!ctrl.is_unlocked());
        assert!(!ctrl.has_credentials());
        assert!(!ctrl.has_session());
        assert!(!ctrl.dirty);
        assert!(ctrl.pending_lock_decision.is_none());

        // Reopen and confirm "TempGroup" was discarded; then test Save & Lock!
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path2, key2, gen2) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("reopen begin_unlock failed"))?;
        let outcome2 = open_vault_blocking(&path2, &master, key2.as_deref());
        ctrl.finish_unlock(gen2, outcome2, 50.0);
        assert_eq!(ctrl.child_groups.len(), 1);
        assert_eq!(ctrl.child_groups[0].label(), "Infra");

        ctrl.create_subgroup("PersistedGroup")?;
        assert!(ctrl.dirty);
        // Idle timeout at +300s opens modal when dirty.
        let idle_dirty = ctrl.check_idle_timeout(350.0);
        assert!(!idle_dirty.locked_active_session);
        assert_eq!(
            ctrl.pending_lock_decision.as_ref().map(|d| d.trigger),
            Some(LockTrigger::IdleTimeout)
        );

        // Save & Lock saves cleanly then drops credentials and clears clipboard!
        let save_lock_cleanup = run_save_blocking(&mut ctrl, true)?;
        assert!(save_lock_cleanup.locked_active_session);
        assert!(save_lock_cleanup.clear_clipboard);
        assert!(!ctrl.is_unlocked());
        assert!(!ctrl.has_credentials());
        assert!(!ctrl.has_session());
        assert!(!ctrl.dirty);

        // Reopen once more and verify PersistedGroup is on disk!
        let (path3, key3, gen3) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("reopen3 begin_unlock failed"))?;
        let outcome3 = open_vault_blocking(&path3, &master, key3.as_deref());
        ctrl.finish_unlock(gen3, outcome3, 60.0);
        assert_eq!(ctrl.child_groups.len(), 2);
        assert!(
            ctrl.child_groups
                .iter()
                .any(|g| g.label() == "PersistedGroup")
        );
        Ok(())
    }

    #[test]
    fn key_file_create_open_editor_cancel_and_search_edit() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let vault_path = dir.path().join("keyfile-only.kdbx");
        let key_path = dir.path().join("master.key");
        std::fs::write(
            &key_path,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .map_err(|err| err.to_string())?;

        let mut ctrl = VaultController::new();
        ctrl.lock_mode = LockMode::Create;
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        ctrl.key_file_path = key_path.to_string_lossy().into_owned();
        let empty_pw = Zeroizing::new(String::new());
        let (path, key, gen_id) = ctrl
            .begin_create(true, true)
            .ok_or_else(|| String::from("begin_create with key file failed"))?;
        let outcome = create_and_open_vault_with_options(
            &path,
            &empty_pw,
            key.as_deref(),
            fast_write_options(),
        );
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        assert!(ctrl.is_unlocked());

        ctrl.create_entry_in_current_group(Some("Alpha"), 1_700_000_000)?;
        ctrl.apply_entry_editor(1_700_000_000)?;
        run_save_blocking(&mut ctrl, false)?;
        assert!(!ctrl.dirty);

        // Cancel in Entry Editor discards staged edits and keeps dirty == false.
        ctrl.begin_edit_selected_entry()?;
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.title = String::from("MutatedTitle");
            editor.notes = Zeroizing::new(String::from("unsaved note"));
        }
        ctrl.cancel_entry_editor();
        assert!(ctrl.editor.is_none());
        assert!(!ctrl.dirty);
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.metadata.title()),
            Some("Alpha")
        );

        // Editing while in Search mode updates live entry and preserves clean state.
        ctrl.set_search_query(String::from("Alpha"), 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);
        ctrl.begin_edit_selected_entry()?;
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.username = Zeroizing::new(String::from("searched-user"));
        }
        ctrl.apply_entry_editor(1_700_000_000)?;
        assert!(ctrl.dirty);
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.username.as_str()),
            Some("searched-user")
        );
        Ok(())
    }

    #[test]
    fn editor_prevalidation_partial_mutation_and_focus_during_save() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);

        ctrl.open_child_group(0);
        ctrl.begin_edit_selected_entry()?;
        // Pre-validation must reject an invalid title BEFORE mutating username or setting dirty.
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.title = String::from("Invalid/Title");
            editor.username = Zeroizing::new(String::from("should-not-commit"));
        }
        assert!(ctrl.apply_entry_editor(1_700_000_000).is_err());
        assert!(!ctrl.dirty);
        assert!(ctrl.browser_status_is_error);
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.username.as_str()),
            Some("deploy-bot")
        );

        // Simulate partial commit: valid title change succeeds, then an unexpected
        // removal of a non-existent custom field fails; dirty and draft/detail must stay synced.
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.title = String::from("ProdAPI Renamed");
            editor.username = Zeroizing::new(String::from("new-bot"));
            editor
                .removed_custom_fields
                .push(String::from("NonExistentField"));
        }
        assert!(ctrl.apply_entry_editor(1_700_000_000).is_err());
        assert!(ctrl.dirty);
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.metadata.title()),
            Some("ProdAPI Renamed")
        );
        // Fixing the bad removal and retrying must succeed without stale EntryRef or NotFound!
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.removed_custom_fields.clear();
        }
        ctrl.apply_entry_editor(1_700_000_000)?;
        assert!(ctrl.editor.is_none());
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.username.as_str()),
            Some("new-bot")
        );

        // Focus loss while a header Save is already in flight opens pending_lock_decision,
        // and finish_save locks cleanly once the save finishes!
        ctrl.lock_on_focus_loss = true;
        let (save_gen, save_path, service, creds) = ctrl
            .begin_save(false)
            .ok_or_else(|| String::from("begin_save failed"))?;
        let focus_during_save = ctrl.on_window_focus(false);
        assert!(!focus_during_save.locked_active_session);
        assert_eq!(
            ctrl.pending_lock_decision.as_ref().map(|d| d.trigger),
            Some(LockTrigger::FocusLoss)
        );
        let save_outcome = save_vault_blocking(save_gen, &save_path, service, creds);
        let finish_cleanup = ctrl.finish_save(save_outcome);
        assert!(finish_cleanup.locked_active_session);
        assert!(!finish_cleanup.clear_clipboard);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert!(!ctrl.has_credentials());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_attachment_is_refused() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;
        let target = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&target, b"secret").map_err(|err| err.to_string())?;
        std::os::unix::fs::symlink(&target, &link).map_err(|err| err.to_string())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        ctrl.open_child_group(0);

        let err = ctrl.attach_file(&link, None);
        assert!(err.is_err());
        assert!(!ctrl.dirty);
        Ok(())
    }

    #[test]
    fn focus_loss_during_unlocking_cancels_and_rejects_late_outcome() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        assert_eq!(ctrl.phase, VaultPhase::Unlocking);

        // Background KDF completes into an Ok(UnlockOutcome) before UI polls it.
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        assert!(outcome.result.is_ok());

        // Window loses focus while still Unlocking: cancel unlock and bump generation.
        ctrl.lock_on_focus_loss = true;
        let cleanup = ctrl.on_window_focus(false);
        assert!(cleanup.locked_active_session);
        assert!(!cleanup.clear_clipboard);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert_eq!(
            ctrl.lock_status.as_deref(),
            Some("Unlock cancelled when window lost focus")
        );
        assert_eq!(ctrl.lock_error_field, LockErrorField::Info);
        assert_ne!(ctrl.unlock_generation, gen_id);

        // Late UnlockOutcome arriving after FocusLoss must be rejected and dropped/wiped.
        ctrl.finish_unlock(gen_id, outcome, 20.0);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert!(!ctrl.is_unlocked());
        assert!(!ctrl.has_session());
        assert!(!ctrl.has_credentials());
        assert_eq!(
            ctrl.lock_status.as_deref(),
            Some("Unlock cancelled when window lost focus")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_key_file_is_refused_while_symlink_vault_is_allowed() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let real_vault = dir.path().join("real.kdbx");
        let link_vault = dir.path().join("link.kdbx");
        let real_key = dir.path().join("real.key");
        let link_key = dir.path().join("link.key");
        std::fs::write(
            &real_key,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .map_err(|err| err.to_string())?;
        std::os::unix::fs::symlink(&real_key, &link_key).map_err(|err| err.to_string())?;

        let empty_pw = Zeroizing::new(String::new());
        let create_outcome = create_and_open_vault_with_options(
            &real_vault,
            &empty_pw,
            Some(&real_key),
            fast_write_options(),
        );
        assert!(create_outcome.result.is_ok());
        drop(create_outcome);

        // Symlinked key file must be refused.
        let refused = open_vault_blocking(&real_vault, &empty_pw, Some(&link_key));
        assert_eq!(refused.error_field, LockErrorField::KeyFile);
        assert!(matches!(
            refused.result,
            Err(ref msg) if msg.contains("symlinks") || msg.contains("regular file")
        ));

        // Symlinked .kdbx vault with a regular key file must be allowed.
        std::os::unix::fs::symlink(&real_vault, &link_vault).map_err(|err| err.to_string())?;
        let allowed = open_vault_blocking(&link_vault, &empty_pw, Some(&real_key));
        assert!(allowed.result.is_ok());
        Ok(())
    }

    #[test]
    fn dotenv_escapes_carriage_return_and_preallocates_exact_capacity() {
        let mut out = Zeroizing::new(String::new());
        push_dotenv_double_quoted(&mut out, "line1\r\n\"\\end");
        assert_eq!(out.as_str(), "\"line1\\r\\n\\\"\\\\end\"");

        let exact = dotenv_double_quoted_len("line1\r\n\"\\end");
        assert_eq!(exact, out.len());
    }

    #[test]
    fn sanitize_attachment_prefill_strips_traversal_controls_and_bidi() {
        assert_eq!(sanitize_attachment_prefill("../../etc/passwd"), "passwd");
        assert_eq!(
            sanitize_attachment_prefill("C:\\Users\\alice\\payload.exe"),
            "payload.exe"
        );
        assert_eq!(sanitize_attachment_prefill("\u{202E}gpj.exe"), "gpj.exe");
        assert_eq!(
            sanitize_attachment_prefill("report\r\n\0.pdf"),
            "report.pdf"
        );
        assert_eq!(sanitize_attachment_prefill(".."), "attachment.bin");
        assert_eq!(sanitize_attachment_prefill("."), "attachment.bin");
        assert_eq!(sanitize_attachment_prefill("dir/"), "attachment.bin");
        assert_eq!(sanitize_attachment_prefill(""), "attachment.bin");
        assert_eq!(sanitize_attachment_prefill("\u{200F}"), "attachment.bin");
        assert_eq!(sanitize_attachment_prefill("my..file.txt"), "my..file.txt");
    }

    #[test]
    fn kdbx_extension_and_inject_file_bounded_checks() -> Result<(), String> {
        assert_eq!(
            ensure_kdbx_extension(PathBuf::from("/tmp/myvault")),
            PathBuf::from("/tmp/myvault.kdbx")
        );
        assert_eq!(
            ensure_kdbx_extension(PathBuf::from("/tmp/already.kdbx")),
            PathBuf::from("/tmp/already.kdbx")
        );
        assert_eq!(
            ensure_kdbx_extension(PathBuf::from("/tmp/custom.ext")),
            PathBuf::from("/tmp/custom.ext")
        );
        assert_eq!(ensure_kdbx_extension(PathBuf::new()), PathBuf::new());

        let dir = tempdir().map_err(|err| err.to_string())?;
        let env_path = dir.path().join("app.env");
        std::fs::write(&env_path, "API_KEY=nkp://Infra/ProdAPI#Password\n")
            .map_err(|err| err.to_string())?;
        let loaded = read_inject_file_bounded(&env_path)?;
        assert!(loaded.contains("nkp://Infra/ProdAPI#Password"));

        let oversized = dir.path().join("huge.env");
        let f = File::create(&oversized).map_err(|err| err.to_string())?;
        f.set_len(MAX_INJECT_FILE_BYTES + 1)
            .map_err(|err| err.to_string())?;
        assert!(read_inject_file_bounded(&oversized).is_err());

        let invalid_utf8 = dir.path().join("bad.env");
        std::fs::write(&invalid_utf8, [0xFF_u8, 0xFE_u8]).map_err(|err| err.to_string())?;
        assert!(read_inject_file_bounded(&invalid_utf8).is_err());
        Ok(())
    }

    #[test]
    fn configured_vaults_loads_aliases_and_ignores_malformed() -> Result<(), String> {
        use std::ffi::OsStr;

        assert!(validated_env_base_dir(OsStr::new("")).is_none());
        assert!(validated_env_base_dir(OsStr::new("relative/dir")).is_none());
        assert!(validated_env_base_dir(OsStr::new("/tmp/../etc")).is_none());
        assert!(validated_env_base_dir(OsStr::new("/tmp/has\0nul")).is_none());
        assert!(validated_env_base_dir(OsStr::new(r"\\?\C:\foo")).is_none());
        assert!(validated_env_base_dir(OsStr::new(r"\\.\pipe\foo")).is_none());

        let dir = tempdir().map_err(|err| err.to_string())?;
        let missing = dir.path().join("does-not-exist.json");
        assert_eq!(load_configured_vaults_from_path(&missing), Vec::new());

        let malformed = dir.path().join("bad.json");
        std::fs::write(&malformed, b"{not valid json").map_err(|err| err.to_string())?;
        assert_eq!(load_configured_vaults_from_path(&malformed), Vec::new());

        let cfg_dir = dir.path().join("safe-cfg");
        std::fs::create_dir_all(&cfg_dir).map_err(|err| err.to_string())?;
        let cfg = cfg_dir.join("config.json");
        std::fs::write(
            &cfg,
            r#"{
                "current": "work",
                "default_vault": "/vaults/default.kdbx",
                "aliases": {
                    "work": { "kind": "vault", "target": "/vaults/work.kdbx" },
                    "bidi": { "kind": "vault", "target": "/vaults/\u202Eevil.kdbx" },
                    "api": { "kind": "entry", "target": "Infra/ProdAPI", "field": "Password" }
                }
            }"#,
        )
        .map_err(|err| err.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
            // Group/world-readable config.json must be rejected.
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644))
                .map_err(|err| err.to_string())?;
            assert_eq!(load_configured_vaults_from_path(&cfg), Vec::new());
            // Owner-only config.json succeeds.
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600))
                .map_err(|err| err.to_string())?;
        }

        let vaults = load_configured_vaults_from_path(&cfg);
        assert_eq!(
            vaults,
            vec![
                ConfiguredVault {
                    label: String::from("work"),
                    path: String::from("/vaults/work.kdbx"),
                },
                ConfiguredVault {
                    label: String::from("Default"),
                    path: String::from("/vaults/default.kdbx"),
                },
            ]
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // World-writable parent directory must be rejected.
            std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o777))
                .map_err(|err| err.to_string())?;
            assert_eq!(load_configured_vaults_from_path(&cfg), Vec::new());

            // Symlinked parent directory must be rejected.
            let link_dir = dir.path().join("link-cfg");
            std::os::unix::fs::symlink(&cfg_dir, &link_dir).map_err(|err| err.to_string())?;
            assert_eq!(
                load_configured_vaults_from_path(&link_dir.join("config.json")),
                Vec::new()
            );
        }
        Ok(())
    }

    #[test]
    fn mask_all_reveals_clears_dirty_session_reveals_on_focus_loss() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        ctrl.open_child_group(0);

        ctrl.toggle_reveal_password();
        ctrl.toggle_reveal_custom_field(1);
        ctrl.begin_edit_selected_entry()?;
        if let Some(ed) = ctrl.editor.as_mut() {
            ed.password_revealed = true;
            ed.otp_revealed = true;
            if let Some(cf) = ed.custom_fields.get_mut(0) {
                cf.revealed = true;
            }
        }
        ctrl.inject_output_revealed = true;
        ctrl.dirty = true;

        ctrl.mask_all_reveals();
        ctrl.lock_on_focus_loss = true;
        let cleanup = ctrl.on_window_focus(false);
        assert!(!cleanup.locked_active_session);
        assert!(ctrl.pending_lock_decision.is_some());
        let detail = ctrl.detail.as_ref().ok_or_else(|| String::from("detail"))?;
        assert!(detail.revealed_password.is_none());
        assert!(detail.revealed_custom_fields.is_empty());
        let ed = ctrl.editor.as_ref().ok_or_else(|| String::from("editor"))?;
        assert!(!ed.password_revealed);
        assert!(!ed.otp_revealed);
        assert!(ed.custom_fields.iter().all(|f| !f.revealed));
        assert!(!ctrl.inject_output_revealed);
        Ok(())
    }

    #[test]
    fn icons_favorites_totp_editor_and_generator_policy() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        assert_eq!(ctrl.recent_vaults, vec![ctrl.vault_path.clone()]);

        // Change group icon and entry icon + favorite + TOTP URI + password generator policy.
        ctrl.open_child_group(0);
        ctrl.set_current_group_icon(3)?;
        assert_eq!(ctrl.current_group_icon(), (3, None));

        ctrl.select_entry(1, 1_700_000_000);
        assert!(!ctrl.is_selected_favorite());
        assert!(ctrl.toggle_selected_favorite(1_700_000_000)?);
        assert!(ctrl.is_selected_favorite());

        ctrl.set_favorites_only(true, 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);
        assert_eq!(ctrl.entries[0].title(), "ProtectedNoteEntry");

        ctrl.begin_edit_selected_entry()?;
        ctrl.set_editor_icon(19);
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.otp_config.mode = OtpEditorMode::RawUri;
            editor.otp_uri = Zeroizing::new(String::from(
                "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&period=30",
            ));
        }
        let digits_only = Policy {
            upper: false,
            lower: false,
            digits: true,
            symbols: false,
        };
        let pin = ctrl.generate_editor_password_with(16, digits_only)?;
        assert_eq!(pin.len(), 16);
        assert!(pin.chars().all(|ch| ch.is_ascii_digit()));
        ctrl.apply_entry_editor(1_700_000_000)?;

        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail missing after editor apply"))?;
        assert_eq!(detail.metadata.icon_id(), 19);
        assert!(detail.metadata.has_otp());
        assert!(detail.totp.is_some());

        // Clear OTP URI removes it cleanly.
        ctrl.begin_edit_selected_entry()?;
        if let Some(editor) = ctrl.editor.as_mut() {
            editor.otp_config.mode = OtpEditorMode::None;
            editor.otp_uri = Zeroizing::new(String::new());
        }
        ctrl.apply_entry_editor(1_700_000_000)?;
        let detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail missing after otp clear"))?;
        assert!(!detail.metadata.has_otp());
        assert!(detail.totp.is_none());

        run_save_blocking(&mut ctrl, false)?;
        let _ = ctrl.lock();

        // Reopen and verify group icon 3, entry icon 19, and favorite tag persisted!
        let (path2, key2, gen2) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("reopen failed"))?;
        let outcome2 = open_vault_blocking(&path2, &master, key2.as_deref());
        ctrl.finish_unlock(gen2, outcome2, 20.0);
        assert_eq!(ctrl.child_groups[0].icon_id(), 3);
        ctrl.open_child_group(0);
        ctrl.select_entry(1, 1_700_000_000);
        assert_eq!(ctrl.detail.as_ref().map(|d| d.metadata.icon_id()), Some(19));
        assert!(ctrl.is_selected_favorite());
        Ok(())
    }

    #[test]
    fn configurable_auto_lock_presets_never_and_focus_loss_default() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let (vault_path, master) = build_fixture_vault(dir.path())?;

        let mut ctrl = VaultController::new();
        assert_eq!(ctrl.auto_lock_secs, Some(DEFAULT_AUTO_LOCK_SECS));
        assert!(!ctrl.lock_on_focus_loss);

        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);

        ctrl.open_child_group(0);
        ctrl.toggle_reveal_password();
        assert!(
            ctrl.detail
                .as_ref()
                .and_then(|d| d.revealed_password.as_ref())
                .is_some()
        );

        // Focus loss defaults to OFF: masks reveals without locking.
        let focus_cleanup = ctrl.on_window_focus(false);
        assert!(!focus_cleanup.locked_active_session);
        assert!(ctrl.is_unlocked());
        assert!(
            ctrl.detail
                .as_ref()
                .and_then(|d| d.revealed_password.as_ref())
                .is_none()
        );

        // Never auto-lock (`None`) stays unlocked even after a long idle duration.
        ctrl.auto_lock_secs = None;
        assert!(!ctrl.check_idle_timeout(100_000.0).locked_active_session);
        assert!(ctrl.is_unlocked());

        // Custom 60s preset locks once 60s elapse after last activity.
        ctrl.auto_lock_secs = Some(60.0);
        ctrl.record_activity(100.0);
        assert!(!ctrl.check_idle_timeout(159.0).locked_active_session);
        let idle_cleanup = ctrl.check_idle_timeout(160.0);
        assert!(idle_cleanup.locked_active_session);
        assert!(idle_cleanup.clear_clipboard);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        Ok(())
    }

    #[test]
    fn empty_and_non_utf8_secret_reveal_and_editor_preservation() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("binary.kdbx");
        let master = Zeroizing::new(String::from("binary-vault-pass"));

        let mut db = KeePassDatabase::default();
        let mut group = Group::new("BinGroup");
        let mut empty_entry = Entry::new("EmptyPw");
        empty_entry.password = ProtectedValue::from_text("");

        let mut bin_entry = Entry::new("BinaryPw");
        let raw_bin = vec![0xff_u8, 0xfe, 0x00, 0x41, 0x80];
        bin_entry.password =
            ProtectedValue::from_bytes(raw_bin.clone()).map_err(|err| err.to_string())?;
        bin_entry.fields.push(neotales_keepass::Field {
            key: String::from("RawToken"),
            value: ProtectedValue::from_bytes(vec![0xc3, 0x28]).map_err(|err| err.to_string())?,
            protected: true,
            protect_in_memory: true,
        });

        group.entries.push(empty_entry);
        group.entries.push(bin_entry);
        db.root.groups.push(group);

        let mut creds =
            KdbxCredentials::password(master.as_bytes()).map_err(|err| err.to_string())?;
        let mut file = File::create(&path).map_err(|err| err.to_string())?;
        KdbxFile::save(
            &db,
            &mut file,
            &mut creds,
            fast_write_options(),
            &KDBX_LIMITS,
        )
        .map_err(|err| err.to_string())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = path.to_string_lossy().into_owned();
        let (vpath, kpath, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&vpath, &master, kpath.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        ctrl.open_child_group(0);

        // Empty password reveals as RevealedSecret::Text("") instead of silent failure or whitespace.
        ctrl.select_entry(0, 1_700_000_000);
        ctrl.toggle_reveal_password();
        let empty_detail = ctrl.detail.as_ref().ok_or_else(|| String::from("detail"))?;
        assert!(matches!(
            empty_detail.revealed_password,
            Some(RevealedSecret::Text(ref s)) if s.is_empty()
        ));

        // Non-UTF-8 password & custom field reveal as safe read-only preview instead of failing.
        ctrl.select_entry(1, 1_700_000_000);
        ctrl.toggle_reveal_password();
        ctrl.toggle_reveal_custom_field(0);
        let bin_detail = ctrl.detail.as_ref().ok_or_else(|| String::from("detail"))?;
        assert!(matches!(
            bin_detail.revealed_password,
            Some(RevealedSecret::NonUtf8 { byte_len: 5, ref preview }) if preview.contains("ff fe")
        ));
        assert!(matches!(
            bin_detail.revealed_custom_fields.get(&0),
            Some(RevealedSecret::NonUtf8 { byte_len: 2, preview }) if preview.contains("c3 28")
        ));

        // Editing Title in Entry Editor keeps non-UTF-8 password & custom field untouched!
        ctrl.begin_edit_selected_entry()?;
        if let Some(ed) = ctrl.editor.as_mut() {
            assert!(ed.password_non_utf8.is_some());
            assert!(ed.custom_fields[0].non_utf8_preview.is_some());
            ed.title = String::from("BinaryPwRenamed");
        }
        ctrl.apply_entry_editor(1_700_000_000)?;
        let saved_ref = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("detail"))?
            .entry_ref
            .clone();
        let revealed_raw = ctrl
            .service
            .reveal_password(&saved_ref)
            .map_err(|err| err.message().to_owned())?;
        assert_eq!(revealed_raw.as_slice(), raw_bin.as_slice());
        Ok(())
    }

    #[test]
    fn create_recommended_defaults_and_http_url_validation() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("recommended.kdbx");
        let master = Zeroizing::new(String::from("recommended-pass"));

        let mut ctrl = VaultController::new();
        ctrl.vault_path = path.to_string_lossy().into_owned();
        let (vpath, kpath, gen_id) = ctrl
            .begin_create(false, true)
            .ok_or_else(|| String::from("begin_create failed"))?;
        let outcome = create_and_open_vault_blocking(&vpath, &master, kpath.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        let settings = ctrl.database_settings()?;
        assert_eq!(settings.compression, nkeepass::VaultCompression::GZip);
        assert!(matches!(
            settings.kdf,
            nkeepass::VaultKdfSummary::Argon2id { .. }
        ));

        assert_eq!(
            validate_http_url("  https://example.com/login?a=1  "),
            Some("https://example.com/login?a=1")
        );
        assert_eq!(
            validate_http_url("http://localhost:8080"),
            Some("http://localhost:8080")
        );
        assert_eq!(validate_http_url("javascript:alert(1)"), None);
        assert_eq!(validate_http_url("file:///etc/passwd"), None);
        assert_eq!(validate_http_url("https://"), None);
        assert_eq!(validate_http_url("https://bad url.com"), None);
        Ok(())
    }

    fn open_fixture_controller(dir: &Path) -> Result<VaultController, String> {
        let (vault_path, master) = build_fixture_vault(dir)?;
        let mut ctrl = VaultController::new();
        ctrl.vault_path = vault_path.to_string_lossy().into_owned();
        let (path, key_path, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&path, &master, key_path.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        Ok(ctrl)
    }

    #[test]
    fn tree_group_expand_rename_reorder_and_move() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let mut ctrl = open_fixture_controller(dir.path())?;

        let initial_tree = ctrl.visible_tree_groups();
        assert!(initial_tree.len() >= 2);
        let root_node = initial_tree[0].clone();
        assert!(root_node.is_root);
        assert_eq!(initial_tree[1].label, "Infra");

        ctrl.create_subgroup_in(&root_node.reference, &root_node.path, "Staging")?;
        let staging = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.label == "Staging")
            .ok_or_else(|| String::from("Staging group missing"))?;
        ctrl.rename_group(&staging.reference, "ProdVault")?;
        let prod_vault_node = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.label == "ProdVault")
            .ok_or_else(|| String::from("ProdVault missing"))?;

        ctrl.create_subgroup_in(&prod_vault_node.reference, &prod_vault_node.path, "Nested")?;
        let expanded_count = ctrl.visible_tree_groups().len();
        ctrl.toggle_group_expanded(&prod_vault_node.path);
        assert_eq!(ctrl.visible_tree_groups().len(), expanded_count - 1);
        ctrl.toggle_group_expanded(&prod_vault_node.path);
        assert_eq!(ctrl.visible_tree_groups().len(), expanded_count);

        ctrl.open_child_group(0);
        ctrl.select_entry(0, 1_700_000_000);
        ctrl.move_selected_entry_down(1_700_000_000)?;
        assert_eq!(ctrl.entries[0].title(), "ProtectedNoteEntry");
        assert_eq!(ctrl.entries[1].title(), "ProdAPI");
        ctrl.move_selected_entry_up(1_700_000_000)?;
        assert_eq!(ctrl.entries[0].title(), "ProdAPI");

        let orig_ref = ctrl.entries[0].reference();
        let fresh_prod_vault_ref = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.label == "ProdVault")
            .map(|g| g.reference)
            .ok_or_else(|| String::from("ProdVault ref missing"))?;
        ctrl.move_entry_to_group(&orig_ref, &fresh_prod_vault_ref, "ProdVault", 1_700_000_000)?;
        assert_eq!(ctrl.entries.len(), 1);
        Ok(())
    }

    #[test]
    fn clone_recycle_restore_and_empty_recycle_bin() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let mut ctrl = open_fixture_controller(dir.path())?;
        ctrl.open_child_group(0);

        let orig_ref = ctrl.entries[0].reference();
        ctrl.clone_entry(&orig_ref, 1_700_000_000)?;
        assert_eq!(ctrl.entries.len(), 3);

        let db_cfg = ctrl.database_settings()?;
        ctrl.update_database_settings(
            nkeepass::DatabaseSettingsUpdate {
                name: db_cfg.name,
                description: db_cfg.description,
                default_username: db_cfg.default_username,
                recycle_bin_enabled: true,
                history_max_items: db_cfg.history_max_items,
                history_max_size: db_cfg.history_max_size,
                outer_cipher: db_cfg.outer_cipher,
                compression: db_cfg.compression,
                kdf: db_cfg.kdf,
            },
            1_700_000_000,
        )?;
        assert!(ctrl.recycle_bin_enabled);

        ctrl.select_entry(1, 1_700_000_000);
        ctrl.delete_selected_entry(1_700_000_000)?;
        assert_eq!(ctrl.entries.len(), 2);
        let bin_path = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.is_recycle_bin)
            .map(|g| g.path)
            .ok_or_else(|| String::from("Recycle Bin group missing after recycle"))?;
        ctrl.select_group_by_path(&bin_path, 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);
        let rec_ref = ctrl.entries[0].reference();
        ctrl.restore_entry(&rec_ref, 1_700_000_000)?;
        assert!(ctrl.entries.is_empty());

        let infra_path = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.label == "Infra")
            .map(|g| g.path)
            .ok_or_else(|| String::from("Infra group missing"))?;
        ctrl.select_group_by_path(&infra_path, 1_700_000_000);
        ctrl.select_entry(1, 1_700_000_000);
        ctrl.delete_selected_entry(1_700_000_000)?;
        let removed_count = ctrl.empty_recycle_bin(1_700_000_000)?;
        assert_eq!(removed_count, 1);
        ctrl.select_group_by_path(&bin_path, 1_700_000_000);
        assert!(ctrl.entries.is_empty());
        Ok(())
    }

    fn open_power_fixture_controller(dir: &Path) -> Result<VaultController, String> {
        let path = dir.join("power.kdbx");
        let master = Zeroizing::new(String::from("power-master-pass"));

        let tiny_png: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        let mut db = KeePassDatabase::default();
        let icon_uuid = neotales_keepass::KdbxUuid::new_random();
        db.meta.custom_icons.push(neotales_keepass::CustomIcon {
            uuid: icon_uuid,
            data: tiny_png,
            name: None,
            last_modification: None,
        });
        let mut work = Group::new("Work");
        let mut prod = Group::new("Prod");
        prod.entries.push(Entry::new("BillingAPI"));
        prod.entries.push(Entry::new("BillingDB"));
        work.groups.push(prod);
        db.root.groups.push(work);

        let mut creds =
            KdbxCredentials::password(master.as_bytes()).map_err(|err| err.to_string())?;
        let mut file = File::create(&path).map_err(|err| err.to_string())?;
        KdbxFile::save(
            &db,
            &mut file,
            &mut creds,
            fast_write_options(),
            &KDBX_LIMITS,
        )
        .map_err(|err| err.to_string())?;

        let mut ctrl = VaultController::new();
        ctrl.vault_path = path.to_string_lossy().into_owned();
        let (vpath, kpath, gen_id) = ctrl
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&vpath, &master, kpath.as_deref());
        ctrl.finish_unlock(gen_id, outcome, 10.0);
        Ok(ctrl)
    }

    #[test]
    fn custom_icons_and_database_settings() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let mut ctrl = open_power_fixture_controller(dir.path())?;

        let icons = ctrl
            .list_custom_icons()
            .map_err(|err| err.message().to_owned())?;
        assert_eq!(icons.len(), 1);
        let custom_id = icons[0].id;
        let work_node = ctrl
            .visible_tree_groups()
            .into_iter()
            .find(|g| g.label == "Work")
            .ok_or_else(|| String::from("Work node missing"))?;
        ctrl.set_group_custom_icon_by_ref(&work_node.reference, custom_id)?;
        ctrl.select_group_by_path("Root/Work/Prod", 1_700_000_000);
        let entry_ref = ctrl.entries[0].reference();
        ctrl.set_entry_custom_icon_by_ref(&entry_ref, custom_id, 1_700_000_000)?;
        assert_eq!(
            ctrl.detail
                .as_ref()
                .and_then(|d| d.metadata.custom_icon_id()),
            Some(custom_id)
        );

        let mut settings = ctrl.database_settings()?;
        settings.name = String::from("Corporate");
        settings.default_username = String::from("svc-acct");
        settings.history_max_items = 25;
        settings.outer_cipher = nkeepass::VaultCipher::ChaCha20;
        ctrl.update_database_settings(
            nkeepass::DatabaseSettingsUpdate {
                name: settings.name.clone(),
                description: settings.description.clone(),
                default_username: settings.default_username.clone(),
                recycle_bin_enabled: settings.recycle_bin_enabled,
                history_max_items: settings.history_max_items,
                history_max_size: settings.history_max_size,
                outer_cipher: settings.outer_cipher,
                compression: settings.compression,
                kdf: settings.kdf,
            },
            1_700_000_000,
        )?;
        assert_eq!(ctrl.database_settings()?.name, "Corporate");
        assert_eq!(
            ctrl.database_settings()?.outer_cipher,
            nkeepass::VaultCipher::ChaCha20
        );
        Ok(())
    }

    #[test]
    fn guided_totp_hotp_path_completion_and_wildcard_search() -> Result<(), String> {
        let dir = tempdir().map_err(|err| err.to_string())?;
        let mut ctrl = open_power_fixture_controller(dir.path())?;
        ctrl.select_group_by_path("Root/Work/Prod", 1_700_000_000);

        ctrl.begin_edit_selected_entry()?;
        if let Some(ed) = ctrl.editor.as_mut() {
            ed.otp_config.mode = OtpEditorMode::Hotp;
            ed.otp_config.secret = Zeroizing::new(String::from("JBSWY3DPEHPK3PXP"));
            ed.otp_config.digits = 6;
            ed.otp_config.counter = 5;
        }
        ctrl.apply_entry_editor(1_700_000_000)?;
        let detail = ctrl.detail.as_ref().ok_or_else(|| String::from("detail"))?;
        assert_eq!(detail.otp_meta.as_ref().and_then(|m| m.counter), Some(5));
        let first_hotp = ctrl.generate_next_hotp_code(1_700_000_000)?;
        assert_eq!(first_hotp.len(), 6);
        assert!(ctrl.dirty);
        assert_eq!(
            ctrl.detail
                .as_ref()
                .and_then(|d| d.otp_meta.as_ref())
                .and_then(|m| m.counter),
            Some(6)
        );
        assert!(
            ctrl.detail
                .as_ref()
                .and_then(|d| d.hotp_code.as_ref())
                .is_some()
        );

        let completions = ctrl.complete_path("/Work/Prod/Billing", 5)?;
        assert_eq!(completions.len(), 2);
        let db_comp = completions
            .iter()
            .find(|c| c.path.ends_with("BillingDB"))
            .ok_or_else(|| String::from("BillingDB completion missing"))?;
        ctrl.navigate_to_completion(db_comp, 1_700_000_000)?;
        assert_eq!(
            ctrl.detail.as_ref().map(|d| d.metadata.title()),
            Some("BillingDB")
        );

        ctrl.set_search_query(String::from("Billing*"), 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 2);
        ctrl.set_search_query(String::from("Billing?B"), 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);
        assert_eq!(ctrl.entries[0].title(), "BillingDB");
        Ok(())
    }
}
