//! Pure, GPU-independent state and controller logic for `nkpui`.
//!
//! Keeps vault session ownership, credential zeroization, database creation,
//! group/entry CRUD, entry editing, search/tree navigation, explicit secret
//! reveal, attachment handling, `.env`/template injection, and dirty-vault
//! focus/idle lock transitions cleanly separated from Rune view rendering.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use neotales_keepass::{CredentialProvider, KdbxCredentials, KdbxWriteOptions, read_key_file};
use nkeepass::env_file::{EnvLine, EnvValueKind, parse_env_file, resolve_env_file};
use nkeepass::password_generator::Policy;
use nkeepass::private_file::write_private_noclobber;
use nkeepass::service::FieldUpdate;
use nkeepass::template::{
    NkpUri, RenderOptions, ServiceSecretLookup, TemplateError, ValueEscape, extract_references,
    render_text,
};
use nkeepass::{
    AttachmentDescriptor, EntryRef, GroupRef, KDBX_LIMITS, SearchHit, SelectedEntry, ServiceError,
    SessionId, TreeGroup, VaultService,
};
use zeroize::Zeroizing;

/// Idle duration in seconds before an unlocked session locks automatically.
pub const IDLE_LOCK_SECS: f64 = 300.0;

/// Maximum attachment file size accepted when attaching a binary (`16 MiB`).
pub const MAX_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Default generated password length in characters.
pub const GENERATED_PASSWORD_LEN: usize = 20;

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
    /// Inactivity timer ([`IDLE_LOCK_SECS`]) elapsed.
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
    pub revealed_standard_fields: BTreeMap<&'static str, Zeroizing<String>>,
    /// Explicitly revealed password buffer, cleared on entry switch or lock.
    pub revealed_password: Option<Zeroizing<String>>,
    /// Explicitly revealed custom field values keyed by custom-field index.
    pub revealed_custom_fields: BTreeMap<usize, Zeroizing<String>>,
    /// Current TOTP code when `metadata.has_otp()` is `true`.
    pub totp: Option<TotpDisplay>,
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
    /// Draft entry title.
    pub title: String,
    /// Draft `UserName` field.
    pub username: Zeroizing<String>,
    /// Whether `UserName` is protected.
    pub username_protected: bool,
    /// Draft `Password` field.
    pub password: Zeroizing<String>,
    /// Whether `Password` is unmasked in the editor.
    pub password_revealed: bool,
    /// Draft `URL` field.
    pub url: Zeroizing<String>,
    /// Whether `URL` is protected.
    pub url_protected: bool,
    /// Draft `Notes` field.
    pub notes: Zeroizing<String>,
    /// Whether `Notes` is protected.
    pub notes_protected: bool,
    /// Draft tag list.
    pub tags: Vec<String>,
    /// Draft custom string fields.
    pub custom_fields: Vec<EditableCustomField>,
    /// Existing custom field names staged for removal on Apply.
    pub removed_custom_fields: Vec<String>,
    original_title: String,
    original_username: Zeroizing<String>,
    original_username_protected: bool,
    original_password: Zeroizing<String>,
    original_url: Zeroizing<String>,
    original_url_protected: bool,
    original_notes: Zeroizing<String>,
    original_notes_protected: bool,
    original_tags: Vec<String>,
}

impl fmt::Debug for EntryEditorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryEditorState")
            .field("path", &self.path)
            .field("title", &self.title)
            .field("password", &"[REDACTED]")
            .field("custom_field_count", &self.custom_fields.len())
            .field("removed_custom_count", &self.removed_custom_fields.len())
            .finish_non_exhaustive()
    }
}

/// Result returned by a background unlock or create worker task.
pub struct UnlockOutcome {
    /// Opened service instance, active session, and owned credentials (or diagnostic message).
    pub result: Result<(VaultService, SessionId, KdbxCredentials), String>,
}

impl fmt::Debug for UnlockOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockOutcome")
            .field("ok", &self.result.is_ok())
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
    /// Last user interaction timestamp (monotonic seconds from runtime clock).
    pub last_activity_secs: f64,
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
            active_tab: WorkspaceTab::Browser,
            dirty: false,
            saving: false,
            pending_lock_decision: None,
            search_query: String::new(),
            breadcrumbs: Vec::new(),
            child_groups: Vec::new(),
            entries: Vec::new(),
            selected_index: None,
            detail: None,
            editor: None,
            browser_status: None,
            inject_mode: InjectMode::Template,
            inject_input: String::from("export API_TOKEN=nkp://Example/API#Password\n"),
            inject_save_path: String::new(),
            extracted_refs: Vec::new(),
            parsed_env_lines: Vec::new(),
            inject_preview_error: None,
            rendered_output: None,
            inject_output_revealed: false,
            inject_status: None,
            last_activity_secs: 0.0,
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

fn ensure_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|_| format!("cannot access {label}"))?;
    if !meta.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    Ok(())
}

fn build_credentials(
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
) -> Result<KdbxCredentials, String> {
    let mut providers: Vec<Box<dyn CredentialProvider + Send>> = Vec::new();
    if let Some(key_path) = key_file_path {
        ensure_regular_file(key_path, "key file")?;
        let Ok(file) = File::open(key_path) else {
            return Err(String::from("cannot open key file"));
        };
        let Ok(key_file) = read_key_file(file) else {
            return Err(String::from("invalid key file"));
        };
        providers.push(Box::new(key_file));
    }

    let password_bytes = (!password.is_empty()).then(|| password.as_bytes());
    KdbxCredentials::from_parts(password_bytes, providers)
        .map_err(|_| String::from("enter a master password or select a key file"))
}

/// Reads a regular attachment source file bounded to [`MAX_ATTACHMENT_BYTES`] (`16 MiB`).
///
/// # Errors
///
/// Returns a fixed diagnostic if the path cannot be opened, is not a regular
/// file, or exceeds [`MAX_ATTACHMENT_BYTES`].
pub fn read_attachment_file_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(path).map_err(|_| String::from("cannot open attachment file"))?;
    let meta = file
        .metadata()
        .map_err(|_| String::from("cannot inspect attachment file"))?;
    if !meta.is_file() {
        return Err(String::from("attachment source is not a regular file"));
    }
    if meta.len() > MAX_ATTACHMENT_BYTES {
        return Err(String::from("attachment exceeds 16 MiB size limit"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_ATTACHMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| String::from("cannot read attachment file"))?;
    if bytes.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(String::from("attachment exceeds 16 MiB size limit"));
    }
    Ok(bytes)
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
    if let Err(err) = ensure_regular_file(vault_path, "vault file") {
        return UnlockOutcome { result: Err(err) };
    }

    let mut credentials = match build_credentials(password, key_file_path) {
        Ok(creds) => creds,
        Err(err) => return UnlockOutcome { result: Err(err) },
    };

    let mut service = VaultService::default();
    match service.open(vault_path, &mut credentials, &KDBX_LIMITS) {
        Ok(session) => UnlockOutcome {
            result: Ok((service, session, credentials)),
        },
        Err(err) => UnlockOutcome {
            result: Err(err.message().to_owned()),
        },
    }
}

/// Executes blocking [`VaultService::create`] followed by [`VaultService::open`]
/// using default KDBX write options.
#[must_use]
pub fn create_and_open_vault_blocking(
    vault_path: &Path,
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
) -> UnlockOutcome {
    create_and_open_vault_with_options(
        vault_path,
        password,
        key_file_path,
        KdbxWriteOptions::default(),
    )
}

/// Executes blocking [`VaultService::create`] with explicit `write_options`
/// followed by [`VaultService::open`].
#[must_use]
pub fn create_and_open_vault_with_options(
    vault_path: &Path,
    password: &Zeroizing<String>,
    key_file_path: Option<&Path>,
    write_options: KdbxWriteOptions,
) -> UnlockOutcome {
    let mut create_creds = match build_credentials(password, key_file_path) {
        Ok(creds) => creds,
        Err(err) => return UnlockOutcome { result: Err(err) },
    };

    let service = VaultService::default();
    if let Err(err) = service.create(vault_path, &mut create_creds, write_options, None) {
        return UnlockOutcome {
            result: Err(err.message().to_owned()),
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

impl VaultController {
    /// Creates a controller pre-seeded with the initial `inject_input` preview parsed.
    #[must_use]
    pub fn new() -> Self {
        let mut controller = Self::default();
        controller.refresh_inject_preview();
        controller
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
            return None;
        }
        let trimmed_key = self.key_file_path.trim();
        if password_empty && trimmed_key.is_empty() {
            self.lock_status = Some(String::from(
                "enter a master password or provide a key file",
            ));
            return None;
        }
        self.phase = VaultPhase::Unlocking;
        self.lock_status = Some(String::from("Unlocking vault…"));
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
            return None;
        }
        if !passwords_match {
            self.lock_status = Some(String::from("master passwords do not match"));
            return None;
        }
        let trimmed_key = self.key_file_path.trim();
        if password_empty && trimmed_key.is_empty() {
            self.lock_status = Some(String::from(
                "enter a master password or provide a key file",
            ));
            return None;
        }
        self.phase = VaultPhase::Unlocking;
        self.lock_status = Some(String::from("Creating vault…"));
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
                self.lock_status = None;
                self.browser_status = None;
                self.editor = None;
                self.active_tab = WorkspaceTab::Browser;
                self.search_query.clear();
                self.last_activity_secs = now_secs;
                if let Err(err) = self.load_root_group() {
                    self.browser_status = Some(err.message().to_owned());
                }
                self.refresh_inject_preview();
            }
            Err(message) => {
                self.phase = VaultPhase::Locked;
                self.lock_status = Some(message);
            }
        }
    }

    /// Returns whether an active session is currently unlocked.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        matches!(self.phase, VaultPhase::Unlocked) && self.session.is_some()
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
        self.child_groups.clear();
        self.entries.clear();
        self.selected_index = None;
        self.detail = None;
        self.editor = None;
        self.search_query.clear();
        self.browser_status = None;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        LockCleanup {
            locked_active_session: was_active,
            clear_clipboard: true,
        }
    }

    fn lock_with_trigger(&mut self, trigger: LockTrigger) -> LockCleanup {
        let mut cleanup = self.lock();
        if cleanup.locked_active_session {
            match trigger {
                LockTrigger::Manual => {
                    cleanup.clear_clipboard = true;
                }
                LockTrigger::FocusLoss => {
                    cleanup.clear_clipboard = false;
                    self.lock_status = Some(String::from("Locked when window lost focus"));
                }
                LockTrigger::IdleTimeout => {
                    cleanup.clear_clipboard = true;
                    self.lock_status = Some(String::from("Locked after inactivity timeout"));
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
            if trigger == LockTrigger::Manual {
                return self.lock();
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
        self.browser_status = Some(String::from("Lock cancelled; unsaved changes kept"));
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
                self.browser_status = Some(msg);
            }
            return None;
        }
        let Some(credentials) = self.credentials.take() else {
            let msg = String::from("missing credentials; cannot save");
            if let Some(pending) = self.pending_lock_decision.as_mut() {
                pending.error = Some(msg);
            } else {
                self.browser_status = Some(msg);
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
    /// pending `Save & Lock` decision.
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
                self.browser_status = Some(String::from("Vault saved"));
                if let Some(pending) = self.pending_lock_decision.take()
                    && pending.save_requested
                {
                    return self.lock_with_trigger(pending.trigger);
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
                    self.browser_status = Some(msg);
                }
            }
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Handles window focus transitions: losing focus triggers [`LockTrigger::FocusLoss`].
    pub fn on_window_focus(&mut self, focused: bool) -> LockCleanup {
        if !focused {
            return self.request_lock(LockTrigger::FocusLoss);
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Returns the runtime clock deadline (in seconds) when the active session should idle-lock.
    #[must_use]
    pub fn idle_lock_deadline(&self) -> f64 {
        self.last_activity_secs + IDLE_LOCK_SECS
    }

    /// Checks whether the idle timeout ([`IDLE_LOCK_SECS`]) has elapsed and requests lock.
    pub fn check_idle_timeout(&mut self, now_secs: f64) -> LockCleanup {
        if self.phase == VaultPhase::Unlocked && now_secs >= self.idle_lock_deadline() {
            return self.request_lock(LockTrigger::IdleTimeout);
        }
        LockCleanup {
            locked_active_session: false,
            clear_clipboard: false,
        }
    }

    /// Loads the root group's direct children and entries.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when the session is locked or stale.
    pub fn load_root_group(&mut self) -> Result<(), ServiceError> {
        let session = self.session.ok_or(ServiceError::Locked)?;
        let root = self.service.root_group(session)?;
        self.breadcrumbs.clear();
        self.breadcrumbs.push((String::from("Root"), root.clone()));
        self.load_group_contents(&root, None)
    }

    /// Navigates into direct child group `index` of the current group.
    pub fn open_child_group(&mut self, index: usize) {
        if self.saving {
            return;
        }
        let Some(group) = self.child_groups.get(index) else {
            return;
        };
        let label = group.label().to_owned();
        let group_ref = group.reference();
        self.search_query.clear();
        self.editor = None;
        self.breadcrumbs.push((label, group_ref.clone()));
        if let Err(err) = self.load_group_contents(&group_ref, None) {
            self.browser_status = Some(err.message().to_owned());
        }
    }

    /// Navigates to breadcrumb depth `index` (`0` = Root).
    pub fn navigate_breadcrumb(&mut self, index: usize) {
        if self.saving {
            return;
        }
        let Some((_, target)) = self.breadcrumbs.get(index).cloned() else {
            return;
        };
        self.breadcrumbs.truncate(index + 1);
        self.search_query.clear();
        self.editor = None;
        if let Err(err) = self.load_group_contents(&target, None) {
            self.browser_status = Some(err.message().to_owned());
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
        self.browser_status = None;
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
        let mut next_breadcrumbs = vec![(String::from("Root"), root.clone())];
        let mut current = root;
        for label in saved_labels {
            let (children, _) = Self::fetch_group_page_all(&mut self.service, &current)?;
            let Some(found) = children.into_iter().find(|child| child.label() == label) else {
                break;
            };
            let next_ref = found.reference();
            next_breadcrumbs.push((label, next_ref.clone()));
            current = next_ref;
        }
        self.breadcrumbs = next_breadcrumbs;
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
        let session = self.session.ok_or(ServiceError::Locked)?;
        let trimmed = self.search_query.trim().to_owned();
        if trimmed.is_empty() {
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
            let page = self.service.search(session, &trimmed)?;
            if let Some(cursor) = page.next_cursor {
                let _ = self.service.release_search_cursor(cursor);
            }
            self.child_groups.clear();
            self.entries = page.hits;
        }

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
        self.browser_status = Some(format!("Created group \"{trimmed}\""));
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
        }
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        if let Err(err) = self.reload_after_mutation(None, None, None, current_unix_seconds()) {
            return Err(err.message().to_owned());
        }
        self.browser_status = Some(String::from("Group deleted (unsaved)"));
        Ok(())
    }

    /// Removes the currently viewed non-root group.
    ///
    /// # Errors
    ///
    /// Returns a non-secret diagnostic if locked, saving, or targeting the root group.
    pub fn remove_current_group(&mut self) -> Result<(), String> {
        let target = self
            .current_group_ref()
            .cloned()
            .ok_or_else(|| String::from("vault is locked"))?;
        self.remove_group(&target)
    }

    /// Runs a search across the unlocked vault, or reloads the current group when empty.
    pub fn set_search_query(&mut self, query: String, unix_now: u64) {
        if self.saving {
            return;
        }
        self.search_query = query;
        self.editor = None;
        let Some(session) = self.session else {
            return;
        };
        let trimmed = self.search_query.trim().to_owned();
        if trimmed.is_empty() {
            if let Some((_, group_ref)) = self.breadcrumbs.last().cloned() {
                if let Err(err) = self.load_group_contents(&group_ref, None) {
                    self.browser_status = Some(err.message().to_owned());
                }
            } else if let Err(err) = self.load_root_group() {
                self.browser_status = Some(err.message().to_owned());
            }
            return;
        }
        match self.service.search(session, &trimmed) {
            Ok(page) => {
                if let Some(cursor) = page.next_cursor {
                    let _ = self.service.release_search_cursor(cursor);
                }
                self.child_groups.clear();
                self.entries = page.hits;
                self.selected_index = None;
                self.detail = None;
                self.browser_status = None;
                if !self.entries.is_empty() {
                    self.select_entry(0, unix_now);
                }
            }
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
            }
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
                self.browser_status = Some(err.message().to_owned());
                return;
            }
        };
        let attachments = match self.service.attachment_metadata(&entry_ref) {
            Ok(list) => list,
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
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
        let totp = if metadata.has_otp() {
            Self::compute_totp(&self.service, &entry_ref, unix_now).ok()
        } else {
            None
        };

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
            totp,
        });
        self.browser_status = None;
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
        self.browser_status = Some(format!("Created entry \"{chosen_title}\""));
        Ok(entry_ref)
    }

    /// Removes the currently selected entry via [`VaultService::remove_entry`]
    /// and marks `dirty = true`.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if no entry is selected, saving is active,
    /// or deletion fails.
    pub fn delete_selected_entry(&mut self, unix_now: u64) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let entry_ref = self
            .detail
            .as_ref()
            .map(|detail| detail.entry_ref.clone())
            .ok_or_else(|| String::from("no entry selected"))?;
        self.service
            .remove_entry(&entry_ref)
            .map_err(|err| err.message().to_owned())?;
        self.dirty = true;
        self.editor = None;
        self.detail = None;
        self.selected_index = None;
        self.reload_after_mutation(None, None, None, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.browser_status = Some(String::from("Entry deleted (unsaved)"));
        Ok(())
    }

    fn read_field_zeroizing(
        service: &VaultService,
        entry_ref: &EntryRef,
        name: &str,
    ) -> Zeroizing<String> {
        match service.reveal_field(entry_ref, name) {
            Ok(secret) => Zeroizing::new(String::from_utf8_lossy(secret.as_slice()).into_owned()),
            Err(_) => Zeroizing::new(String::new()),
        }
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
        let password = match self.service.reveal_password(&entry_ref) {
            Ok(secret) => Zeroizing::new(
                std::str::from_utf8(secret.as_slice())
                    .map_err(|_| String::from("password is not valid UTF-8"))?
                    .to_owned(),
            ),
            Err(_) => Zeroizing::new(String::new()),
        };

        let username_protected = detail.protected_standard_fields.contains_key("UserName");
        let url_protected = detail.protected_standard_fields.contains_key("URL");
        let notes_protected = detail.protected_standard_fields.contains_key("Notes");

        let username = if username_protected {
            Self::read_field_zeroizing(&self.service, &entry_ref, "UserName")
        } else {
            Zeroizing::new(detail.username.clone())
        };
        let url = if url_protected {
            Self::read_field_zeroizing(&self.service, &entry_ref, "URL")
        } else {
            Zeroizing::new(detail.url.clone())
        };
        let notes = if notes_protected {
            Self::read_field_zeroizing(&self.service, &entry_ref, "Notes")
        } else {
            Zeroizing::new(detail.notes.clone())
        };

        let mut custom_fields = Vec::with_capacity(detail.metadata.custom_fields().len());
        for descriptor in detail.metadata.custom_fields() {
            let value = match self.service.reveal_custom_field(&descriptor.reference()) {
                Ok(secret) => Zeroizing::new(
                    std::str::from_utf8(secret.as_slice())
                        .map_err(|_| String::from("custom field is not valid UTF-8"))?
                        .to_owned(),
                ),
                Err(err) => return Err(err.message().to_owned()),
            };
            custom_fields.push(EditableCustomField {
                name: descriptor.name().to_owned(),
                original_value: value.clone(),
                value,
                protected: descriptor.protected(),
                revealed: !descriptor.protected(),
                is_new: false,
                original_protected: descriptor.protected(),
            });
        }

        let title = detail.metadata.title().to_owned();
        let tags = detail.metadata.tags().to_vec();

        self.editor = Some(EntryEditorState {
            entry_ref,
            path: detail.path.clone(),
            original_title: title.clone(),
            title,
            original_username: username.clone(),
            username,
            original_username_protected: username_protected,
            username_protected,
            original_password: password.clone(),
            password,
            password_revealed: false,
            original_url: url.clone(),
            url,
            original_url_protected: url_protected,
            url_protected,
            original_notes: notes.clone(),
            notes,
            original_notes_protected: notes_protected,
            notes_protected,
            original_tags: tags.clone(),
            tags,
            custom_fields,
            removed_custom_fields: Vec::new(),
        });
        self.browser_status = None;
        Ok(())
    }

    /// Cancels Entry Editor mode and zeroizes all editor secret buffers.
    pub fn cancel_entry_editor(&mut self) {
        self.editor = None;
        self.browser_status = Some(String::from("Entry edits cancelled"));
    }

    /// Generates a new 20-character password into the active Entry Editor using
    /// [`VaultService::generate_password_value`].
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic if no editor is active or OS randomness fails.
    pub fn generate_editor_password(&mut self) -> Result<Zeroizing<String>, String> {
        let editor = self
            .editor
            .as_mut()
            .ok_or_else(|| String::from("entry editor is not active"))?;
        let generated =
            VaultService::generate_password_value(GENERATED_PASSWORD_LEN, Policy::default())
                .map_err(|err| err.message().to_owned())?;
        editor.password.clone_from(&generated);
        Ok(generated)
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
    /// marks `dirty = true` if any change occurred, and reloads the entry detail.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error message if locked, saving, or any vault validation fails.
    pub fn apply_entry_editor(&mut self, unix_now: u64) -> Result<(), String> {
        if self.saving {
            return Err(String::from("save in progress"));
        }
        let draft = self
            .editor
            .take()
            .ok_or_else(|| String::from("entry editor is not active"))?;

        let result = self.apply_entry_editor_inner(&draft, unix_now);
        if result.is_err() {
            // Keep draft open on validation failure so user edits are not lost.
            let refreshed = self
                .fresh_entry_ref_mut(&draft.path, self.selected_index)
                .unwrap_or_else(|_| draft.entry_ref.clone());
            let mut restored = draft;
            restored.entry_ref = refreshed;
            self.editor = Some(restored);
        }
        result
    }

    fn collect_editor_field_updates(draft: &EntryEditorState) -> Vec<FieldUpdate> {
        let mut updates = Vec::new();
        if draft.username != draft.original_username
            || draft.username_protected != draft.original_username_protected
        {
            updates.push(FieldUpdate {
                key: String::from("UserName"),
                value: draft.username.clone(),
                protected: Some(draft.username_protected),
                protect_in_memory: Some(draft.username_protected),
            });
        }
        if draft.password != draft.original_password {
            updates.push(FieldUpdate {
                key: String::from("Password"),
                value: draft.password.clone(),
                protected: Some(true),
                protect_in_memory: Some(true),
            });
        }
        if draft.url != draft.original_url || draft.url_protected != draft.original_url_protected {
            updates.push(FieldUpdate {
                key: String::from("URL"),
                value: draft.url.clone(),
                protected: Some(draft.url_protected),
                protect_in_memory: Some(draft.url_protected),
            });
        }
        if draft.notes != draft.original_notes
            || draft.notes_protected != draft.original_notes_protected
        {
            updates.push(FieldUpdate {
                key: String::from("Notes"),
                value: draft.notes.clone(),
                protected: Some(draft.notes_protected),
                protect_in_memory: Some(draft.notes_protected),
            });
        }
        for field in &draft.custom_fields {
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

    fn apply_entry_editor_inner(
        &mut self,
        draft: &EntryEditorState,
        unix_now: u64,
    ) -> Result<(), String> {
        let mut entry_ref = draft.entry_ref.clone();
        let mut current_path = draft.path.clone();
        let group_idx = self.selected_index;
        let mut mutated = false;

        if draft.title != draft.original_title {
            self.service
                .set_title(&entry_ref, &draft.title)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            current_path = match current_path.rsplit_once('/') {
                Some((parent, _)) => format!("{parent}/{}", draft.title),
                None => draft.title.clone(),
            };
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
        }

        if draft.tags != draft.original_tags {
            self.service
                .set_tags(&entry_ref, draft.tags.clone())
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
        }

        for removed_name in &draft.removed_custom_fields {
            self.service
                .remove_custom_field(&entry_ref, removed_name)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
        }

        let updates = Self::collect_editor_field_updates(draft);
        if !updates.is_empty() {
            self.service
                .set_fields_creating_custom(&entry_ref, updates)
                .map_err(|err| err.message().to_owned())?;
            mutated = true;
            entry_ref = self
                .fresh_entry_ref_mut(&current_path, group_idx)
                .map_err(|err| err.message().to_owned())?;
        }

        if mutated {
            self.dirty = true;
        }
        self.reload_after_mutation(Some(&entry_ref), Some(&current_path), group_idx, unix_now)
            .map_err(|err| err.message().to_owned())?;
        self.browser_status = Some(if mutated {
            String::from("Entry updated (unsaved)")
        } else {
            String::from("No changes to apply")
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
        self.browser_status = Some(format!("Attached \"{resolved_name}\" (unsaved)"));
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
        self.browser_status = Some(format!(
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
        self.browser_status = Some(format!(
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

    /// Refreshes the selected entry's TOTP code for `unix_now` if it has OTP configured.
    pub fn refresh_selected_totp(&mut self, unix_now: u64) {
        if self.saving {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if !detail.metadata.has_otp() {
            return;
        }
        match Self::compute_totp(&self.service, &detail.entry_ref, unix_now) {
            Ok(totp) => detail.totp = Some(totp),
            Err(err) => self.browser_status = Some(err.message().to_owned()),
        }
    }

    /// Toggles explicit password reveal for the selected entry using [`Zeroizing<String>`].
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
            Ok(secret) => match std::str::from_utf8(secret.as_slice()) {
                Ok(text) => {
                    detail.revealed_password = Some(Zeroizing::new(text.to_owned()));
                }
                Err(_) => {
                    self.browser_status = Some(String::from("password is not valid UTF-8"));
                }
            },
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
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
        if let Some(revealed) = &detail.revealed_password {
            return Ok(revealed.clone());
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
            Ok(secret) => match std::str::from_utf8(secret.as_slice()) {
                Ok(text) => {
                    detail
                        .revealed_standard_fields
                        .insert(field_name, Zeroizing::new(text.to_owned()));
                }
                Err(_) => {
                    self.browser_status = Some(String::from("field is not valid UTF-8"));
                }
            },
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
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
        if let Some(revealed) = detail.revealed_standard_fields.get(field_name) {
            return Ok(revealed.clone());
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
            Ok(secret) => match std::str::from_utf8(secret.as_slice()) {
                Ok(text) => {
                    detail
                        .revealed_custom_fields
                        .insert(custom_index, Zeroizing::new(text.to_owned()));
                }
                Err(_) => {
                    self.browser_status = Some(String::from("custom field is not valid UTF-8"));
                }
            },
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
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
        if let Some(revealed) = detail.revealed_custom_fields.get(&custom_index) {
            return Ok(revealed.clone());
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

    /// Updates `inject_input` and refreshes reference extraction without resolving secrets.
    pub fn set_inject_input(&mut self, input: String) {
        self.inject_input = input;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        self.refresh_inject_preview();
    }

    /// Switches between [`InjectMode::Template`] and [`InjectMode::EnvFile`] and re-parses.
    pub fn set_inject_mode(&mut self, mode: InjectMode) {
        self.inject_mode = mode;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
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
                let mut rendered = Zeroizing::new(String::new());
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
        self.inject_status = Some(String::from("Rendered securely in memory (masked)"));
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
            self.inject_status = Some(msg.to_owned());
            return Err(msg);
        }
        let Some(output) = &self.rendered_output else {
            let msg = "render the template before saving";
            self.inject_status = Some(msg.to_owned());
            return Err(msg);
        };
        write_private_noclobber(Path::new(target), output.as_bytes()).inspect_err(|err| {
            self.inject_status = Some((*err).to_owned());
        })?;
        self.inject_status = Some(String::from("Saved private output (no-clobber)"));
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

fn push_dotenv_double_quoted(out: &mut Zeroizing<String>, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
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
            detail.revealed_password.as_deref().map(String::as_str),
            Some("s3cr3t-api-token")
        );
        assert_eq!(
            detail.revealed_custom_fields.get(&1).map(|z| z.as_str()),
            Some("sign-key-xyz")
        );

        // Selecting ProtectedNoteEntry marks Notes as protected and allows explicit reveal.
        ctrl.select_entry(1, 1_700_000_000);
        let note_detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("protected note detail missing"))?;
        assert!(note_detail.protected_standard_fields.contains_key("Notes"));
        assert!(note_detail.notes.is_empty());
        ctrl.toggle_reveal_standard_field("Notes");
        let note_detail = ctrl
            .detail
            .as_ref()
            .ok_or_else(|| String::from("protected note detail missing after reveal"))?;
        assert_eq!(
            note_detail
                .revealed_standard_fields
                .get("Notes")
                .map(|z| z.as_str()),
            Some("classified note body")
        );

        // Search works from anywhere in unlocked session.
        ctrl.set_search_query(String::from("ProdAPI"), 1_700_000_000);
        assert_eq!(ctrl.entries.len(), 1);

        // Window focus loss when clean locks immediately while preserving clipboard lease.
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
        assert!(ctrl.extracted_refs.is_empty());
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
            d.revealed_custom_fields.get(&0).map(|v| v.as_str()),
            Some("tok-456")
        );
        assert_eq!(
            d.revealed_password.as_deref().map(String::as_str),
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
}
