//! Pure, GPU-independent state and controller logic for `nkpui`.
//!
//! Keeps vault session ownership, credential zeroization, search/tree
//! navigation, explicit secret reveal, `.env`/template injection, and
//! focus/idle lock transitions cleanly separated from Rune view rendering.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use neotales_keepass::{CredentialProvider, KdbxCredentials, read_key_file};
use nkeepass::env_file::{EnvLine, EnvValueKind, parse_env_file, resolve_env_file};
use nkeepass::private_file::write_private_noclobber;
use nkeepass::template::{
    NkpUri, RenderOptions, ServiceSecretLookup, TemplateError, ValueEscape, extract_references,
    render_text,
};
use nkeepass::{
    EntryRef, GroupRef, KDBX_LIMITS, SearchHit, SelectedEntry, ServiceError, SessionId, TreeGroup,
    VaultService,
};
use zeroize::Zeroizing;

/// Idle duration in seconds before an unlocked session locks automatically.
pub const IDLE_LOCK_SECS: f64 = 300.0;

/// Current lock lifecycle phase of the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPhase {
    /// No active vault session or credentials are held in memory.
    Locked,
    /// A background worker thread is executing KDF + KDBX open.
    Unlocking,
    /// A vault session and its owned credentials are active.
    Unlocked,
}

/// Active workspace view inside an unlocked vault.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceTab {
    /// Group sidebar, searchable entry list, and entry detail pane.
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
            .field("has_revealed_password", &self.revealed_password.is_some())
            .field(
                "revealed_custom_field_count",
                &self.revealed_custom_fields.len(),
            )
            .field("has_totp", &self.totp.is_some())
            .finish_non_exhaustive()
    }
}

/// Result returned by a background unlock worker task.
pub struct UnlockOutcome {
    /// Opened service instance (or fresh locked instance on failure).
    pub result: Result<(VaultService, SessionId, KdbxCredentials), String>,
}

impl fmt::Debug for UnlockOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockOutcome")
            .field("ok", &self.result.is_ok())
            .finish()
    }
}

/// Outcome of locking the vault so the UI shell can mirror cleanup into widgets/clipboard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockCleanup {
    /// Whether an active or in-flight session was cleared.
    pub locked_active_session: bool,
}

/// Pure application state and controller for `nkpui`.
pub struct VaultController {
    /// Current lock phase.
    pub phase: VaultPhase,
    /// Path to the `.kdbx` vault file.
    pub vault_path: String,
    /// Optional path to a `KeePass` key file.
    pub key_file_path: String,
    /// Non-secret status or error message for the lock screen.
    pub lock_status: Option<String>,
    /// Active workspace tab when unlocked.
    pub active_tab: WorkspaceTab,
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
}

impl fmt::Debug for VaultController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultController")
            .field("phase", &self.phase)
            .field("vault_path", &self.vault_path)
            .field("has_session", &self.session.is_some())
            .field("has_credentials", &self.credentials.is_some())
            .field("active_tab", &self.active_tab)
            .field("entry_count", &self.entries.len())
            .field("selected_index", &self.selected_index)
            .field("has_detail", &self.detail.is_some())
            .field("has_rendered_output", &self.rendered_output.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for VaultController {
    fn default() -> Self {
        Self {
            phase: VaultPhase::Locked,
            vault_path: String::new(),
            key_file_path: String::new(),
            lock_status: None,
            active_tab: WorkspaceTab::Browser,
            search_query: String::new(),
            breadcrumbs: Vec::new(),
            child_groups: Vec::new(),
            entries: Vec::new(),
            selected_index: None,
            detail: None,
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

    let mut providers: Vec<Box<dyn CredentialProvider + Send>> = Vec::new();
    if let Some(key_path) = key_file_path {
        if let Err(err) = ensure_regular_file(key_path, "key file") {
            return UnlockOutcome { result: Err(err) };
        }
        let Ok(file) = File::open(key_path) else {
            return UnlockOutcome {
                result: Err(String::from("cannot open key file")),
            };
        };
        let Ok(key_file) = read_key_file(file) else {
            return UnlockOutcome {
                result: Err(String::from("invalid key file")),
            };
        };
        providers.push(Box::new(key_file));
    }

    let password_bytes = (!password.is_empty()).then(|| password.as_bytes());
    let Ok(mut credentials) = KdbxCredentials::from_parts(password_bytes, providers) else {
        return UnlockOutcome {
            result: Err(String::from("enter a master password or select a key file")),
        };
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

    /// Applies the result of a background [`open_vault_blocking`] call if it matches
    /// the current unlock generation and the UI is still in [`VaultPhase::Unlocking`].
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
                self.lock_status = None;
                self.browser_status = None;
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

    /// Locks the vault, drops [`KdbxCredentials`], clears all revealed secrets and
    /// rendered outputs, and invalidates any in-flight unlock attempt.
    pub fn lock(&mut self) -> LockCleanup {
        let was_active = self.phase != VaultPhase::Locked
            || self.session.is_some()
            || self.credentials.is_some();
        self.unlock_generation = self.unlock_generation.wrapping_add(1);
        if let Some(session) = self.session.take() {
            let _ = self.service.lock(session);
        }
        self.credentials = None;
        self.phase = VaultPhase::Locked;
        self.breadcrumbs.clear();
        self.child_groups.clear();
        self.entries.clear();
        self.selected_index = None;
        self.detail = None;
        self.search_query.clear();
        self.browser_status = None;
        self.rendered_output = None;
        self.inject_output_revealed = false;
        self.inject_status = None;
        LockCleanup {
            locked_active_session: was_active,
        }
    }

    /// Handles window focus transitions: losing focus immediately locks the vault.
    pub fn on_window_focus(&mut self, focused: bool) -> LockCleanup {
        if !focused {
            let cleanup = self.lock();
            if cleanup.locked_active_session {
                self.lock_status = Some(String::from("Locked when window lost focus"));
            }
            return cleanup;
        }
        LockCleanup {
            locked_active_session: false,
        }
    }

    /// Returns the runtime clock deadline (in seconds) when the active session should idle-lock.
    #[must_use]
    pub fn idle_lock_deadline(&self) -> f64 {
        self.last_activity_secs + IDLE_LOCK_SECS
    }

    /// Checks whether the idle timeout ([`IDLE_LOCK_SECS`]) has elapsed and locks if so.
    pub fn check_idle_timeout(&mut self, now_secs: f64) -> LockCleanup {
        if self.phase == VaultPhase::Unlocked && now_secs >= self.idle_lock_deadline() {
            let cleanup = self.lock();
            if cleanup.locked_active_session {
                self.lock_status = Some(String::from("Locked after inactivity timeout"));
            }
            return cleanup;
        }
        LockCleanup {
            locked_active_session: false,
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
        self.load_group_contents(&root)
    }

    /// Navigates into direct child group `index` of the current group.
    pub fn open_child_group(&mut self, index: usize) {
        let Some(group) = self.child_groups.get(index) else {
            return;
        };
        let label = group.label().to_owned();
        let group_ref = group.reference();
        self.search_query.clear();
        self.breadcrumbs.push((label, group_ref.clone()));
        if let Err(err) = self.load_group_contents(&group_ref) {
            self.browser_status = Some(err.message().to_owned());
        }
    }

    /// Navigates to breadcrumb depth `index` (`0` = Root).
    pub fn navigate_breadcrumb(&mut self, index: usize) {
        let Some((_, target)) = self.breadcrumbs.get(index).cloned() else {
            return;
        };
        self.breadcrumbs.truncate(index + 1);
        self.search_query.clear();
        if let Err(err) = self.load_group_contents(&target) {
            self.browser_status = Some(err.message().to_owned());
        }
    }

    fn load_group_contents(&mut self, group: &GroupRef) -> Result<(), ServiceError> {
        let mut child_groups = Vec::new();
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let page = self.service.tree_page(group, cursor)?;
            child_groups.extend(page.groups);
            entries.extend(page.entries);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        self.child_groups = child_groups;
        self.entries = entries;
        self.selected_index = None;
        self.detail = None;
        self.browser_status = None;
        if !self.entries.is_empty() {
            self.select_entry(0, current_unix_seconds());
        }
        Ok(())
    }

    /// Runs a search across the unlocked vault, or reloads the current group when empty.
    pub fn set_search_query(&mut self, query: String, unix_now: u64) {
        self.search_query = query;
        let Some(session) = self.session else {
            return;
        };
        let trimmed = self.search_query.trim().to_owned();
        if trimmed.is_empty() {
            if let Some((_, group_ref)) = self.breadcrumbs.last().cloned() {
                if let Err(err) = self.load_group_contents(&group_ref) {
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
        let Some(hit) = self.entries.get(index) else {
            return;
        };
        let entry_ref = hit.reference();
        let path = hit.path().to_owned();
        let metadata = match self.service.selected_entry(&entry_ref) {
            Ok(selected) => selected,
            Err(err) => {
                self.browser_status = Some(err.message().to_owned());
                return;
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

        // Window focus loss locks and wipes session, credentials, and reveal buffers.
        let cleanup = ctrl.on_window_focus(false);
        assert!(cleanup.locked_active_session);
        assert_eq!(ctrl.phase, VaultPhase::Locked);
        assert!(!ctrl.is_unlocked());
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

        // Idle timeout at +300s locks and wipes rendered output.
        assert!(!ctrl.check_idle_timeout(399.0).locked_active_session);
        assert!(ctrl.check_idle_timeout(400.0).locked_active_session);
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
}
