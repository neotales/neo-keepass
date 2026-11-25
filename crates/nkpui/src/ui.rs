//! Rune view layer and UI state adapter for `nkpui`.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use rune::{
    Cx, El, Latest, ScrollSpec, SecretCopy, SecretState, TextEdit, Tx, col, oklch, row, text,
};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, Checkbox, ControlSize, Dialog, Divider, Kit,
    TextArea, TextInput, root as kit_root,
};
use zeroize::Zeroizing;

use crate::controller::{
    EditableCustomField, EntryDetailState, EntryEditorState, InjectMode, LockCleanup,
    LockErrorField, LockMode, LockTrigger, SaveOutcome, TotpDisplay, UnlockOutcome,
    VaultController, VaultPhase, WorkspaceTab, create_and_open_vault_blocking,
    current_unix_seconds, format_byte_size, open_vault_blocking, save_vault_blocking,
};

const SECRET_CLIPBOARD_TTL: Duration = Duration::from_secs(30);

/// Explicit confirmation dialog kind for destructive browser actions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfirmDialog {
    /// Confirm deleting the currently viewed non-root group.
    DeleteGroup {
        /// Group label shown in the confirmation prompt.
        label: String,
    },
    /// Confirm deleting the currently selected entry.
    DeleteEntry {
        /// Entry title shown in the confirmation prompt.
        title: String,
    },
    /// Confirm removing an attachment from the currently selected entry.
    RemoveAttachment {
        /// Attachment filename shown in the confirmation prompt.
        name: String,
    },
}

/// Modal state for privately extracting/saving an attachment via `write_private_noclobber`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractDialogState {
    /// Attachment index in [`EntryDetailState::attachments`].
    pub index: usize,
    /// Attachment filename.
    pub name: String,
    /// Attachment size in bytes.
    pub size: usize,
    /// Non-secret error message if extraction failed.
    pub error: Option<String>,
}

/// Form state for adding a new custom string field in the Entry Editor.
pub struct AddCustomFieldForm {
    /// Field name input.
    pub name_edit: TextEdit,
    /// Field value input (`.secure()` when `protected == true`).
    pub value_edit: TextEdit,
    /// Whether the new custom string is marked `Protected`.
    pub protected: bool,
    /// Whether the protected new custom string value is unmasked.
    pub revealed: bool,
}

impl fmt::Debug for AddCustomFieldForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddCustomFieldForm")
            .field("protected", &self.protected)
            .field("revealed", &self.revealed)
            .finish_non_exhaustive()
    }
}

impl Default for AddCustomFieldForm {
    fn default() -> Self {
        Self {
            name_edit: TextEdit::new(""),
            value_edit: TextEdit::new("").secure(),
            protected: true,
            revealed: false,
        }
    }
}

impl AddCustomFieldForm {
    fn reset(&mut self) {
        self.name_edit.replace_text("");
        self.value_edit.replace_text("");
        self.protected = true;
        self.revealed = false;
        self.value_edit.set_secure(true);
        self.value_edit.set_revealed(false);
    }
}

/// Top-level Rune application state wrapping [`VaultController`] and UI widgets.
pub struct AppState {
    /// Pure controller holding vault session, credentials, and view model.
    pub controller: VaultController,
    /// Path input for `.kdbx` file selection on the lock screen.
    pub vault_path_edit: TextEdit,
    /// Optional key-file path input on the lock screen.
    pub key_file_edit: TextEdit,
    /// Master password editor configured with `.secure()`.
    pub master_input: TextEdit,
    /// Confirm master password editor configured with `.secure()` for new database creation.
    pub confirm_master_edit: TextEdit,
    /// Search input inside the unlocked browser.
    pub search_edit: TextEdit,
    /// Whether the inline new-subgroup form is expanded in the sidebar.
    pub show_new_group_form: bool,
    /// Subgroup name input in the sidebar.
    pub new_group_edit: TextEdit,
    /// Entry editor title input.
    pub edit_title: TextEdit,
    /// Entry editor username input.
    pub edit_username: TextEdit,
    /// Entry editor password input (`.secure()`).
    pub edit_password: TextEdit,
    /// Entry editor URL input.
    pub edit_url: TextEdit,
    /// Entry editor multiline notes input.
    pub edit_notes: TextEdit,
    /// Entry editor tag input (supports comma-separated or single tag add).
    pub edit_new_tag: TextEdit,
    /// Entry editor custom string value inputs matching `editor.custom_fields`.
    pub edit_custom_values: Vec<TextEdit>,
    /// Form state for staging a new custom string in the Entry Editor.
    pub add_custom_form: AddCustomFieldForm,
    /// Safe fallback buffer for indexed `on_edit` closures.
    fallback_edit: TextEdit,
    /// Active confirmation dialog for destructive actions.
    pub pending_confirm: Option<ConfirmDialog>,
    /// Whether the Attach Binary File dialog is open.
    pub attach_dialog_open: bool,
    /// Source file path input in the Attach Binary File dialog.
    pub attach_path_edit: TextEdit,
    /// Optional override attachment name in the Attach Binary File dialog.
    pub attach_name_edit: TextEdit,
    /// Non-secret error message shown inside the Attach Binary File dialog.
    pub attach_dialog_error: Option<String>,
    /// Active Extract Attachment Privately dialog state.
    pub extract_dialog: Option<ExtractDialogState>,
    /// Destination path input in the Extract Attachment dialog.
    pub extract_path_edit: TextEdit,
    /// Template or `.env` source editor inside the inject tool view.
    pub inject_edit: TextEdit,
    /// Output file path editor for private no-clobber saves.
    pub save_path_edit: TextEdit,
    /// Background worker for KDBX open/create KDF so the UI frame loop never stalls.
    pub unlock_worker: Latest<(u64, UnlockOutcome)>,
    /// Background worker for KDBX save so the UI frame loop never stalls.
    pub save_worker: Latest<SaveOutcome>,
    /// Active clipboard lease handle from `Tx::copy_secret`.
    pub secret_copy: Option<SecretCopy>,
    /// Latest runtime clock timestamp in seconds.
    pub clock_secs: f64,
    /// Last UNIX second at which TOTP codes were refreshed.
    pub last_totp_refresh: u64,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("controller", &self.controller)
            .field("has_secret_copy", &self.secret_copy.is_some())
            .field("clock_secs", &self.clock_secs)
            .finish_non_exhaustive()
    }
}

impl Default for AppState {
    fn default() -> Self {
        let controller = VaultController::new();
        let inject_edit = TextEdit::new(controller.inject_input.clone());
        Self {
            controller,
            vault_path_edit: TextEdit::new(""),
            key_file_edit: TextEdit::new(""),
            master_input: TextEdit::new("").secure(),
            confirm_master_edit: TextEdit::new("").secure(),
            search_edit: TextEdit::new(""),
            show_new_group_form: false,
            new_group_edit: TextEdit::new(""),
            edit_title: TextEdit::new(""),
            edit_username: TextEdit::new(""),
            edit_password: TextEdit::new("").secure(),
            edit_url: TextEdit::new(""),
            edit_notes: TextEdit::new(""),
            edit_new_tag: TextEdit::new(""),
            edit_custom_values: Vec::new(),
            add_custom_form: AddCustomFieldForm::default(),
            fallback_edit: TextEdit::new("").secure(),
            pending_confirm: None,
            attach_dialog_open: false,
            attach_path_edit: TextEdit::new(""),
            attach_name_edit: TextEdit::new(""),
            attach_dialog_error: None,
            extract_dialog: None,
            extract_path_edit: TextEdit::new(""),
            inject_edit,
            save_path_edit: TextEdit::new(""),
            unlock_worker: Latest::default(),
            save_worker: Latest::default(),
            secret_copy: None,
            clock_secs: 0.0,
            last_totp_refresh: 0,
        }
    }
}

impl AppState {
    /// Initiates an off-thread `VaultService::open` via [`Latest`].
    pub fn start_unlock(&mut self) {
        self.controller.vault_path = self.vault_path_edit.text.clone();
        self.controller.key_file_path = self.key_file_edit.text.clone();
        let password = Zeroizing::new(self.master_input.text.clone());
        let password_empty = password.is_empty();
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");

        let Some((vault_path, key_file_path, generation)) =
            self.controller.begin_unlock(password_empty)
        else {
            return;
        };

        self.unlock_worker.request(
            (vault_path, key_file_path, password, generation),
            |(vault_path, key_file_path, password, generation)| {
                let outcome = open_vault_blocking(&vault_path, &password, key_file_path.as_deref());
                (generation, outcome)
            },
        );
    }

    /// Initiates an off-thread `VaultService::create` + `open` via [`Latest`].
    pub fn start_create_vault(&mut self) {
        self.controller.vault_path = self.vault_path_edit.text.clone();
        self.controller.key_file_path = self.key_file_edit.text.clone();
        let password = Zeroizing::new(self.master_input.text.clone());
        let confirm = Zeroizing::new(self.confirm_master_edit.text.clone());
        let password_empty = password.is_empty();
        let passwords_match = password.as_str() == confirm.as_str();
        drop(confirm);
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");

        let Some((vault_path, key_file_path, generation)) = self
            .controller
            .begin_create(password_empty, passwords_match)
        else {
            return;
        };

        self.unlock_worker.request(
            (vault_path, key_file_path, password, generation),
            |(vault_path, key_file_path, password, generation)| {
                let outcome = create_and_open_vault_blocking(
                    &vault_path,
                    &password,
                    key_file_path.as_deref(),
                );
                (generation, outcome)
            },
        );
    }

    /// Initiates an off-thread `VaultService::save` via [`Latest`].
    pub fn start_save(&mut self, for_lock_decision: bool) {
        let Some((generation, vault_path, service, credentials)) =
            self.controller.begin_save(for_lock_decision)
        else {
            return;
        };
        self.save_worker.request(
            (generation, vault_path, service, credentials),
            |(generation, vault_path, service, credentials)| {
                save_vault_blocking(generation, &vault_path, service, credentials)
            },
        );
    }

    fn apply_lock_cleanup(&mut self, cleanup: LockCleanup, tx: &mut Tx) {
        if cleanup.locked_active_session {
            self.unlock_worker.cancel();
            self.save_worker.cancel();
            self.wipe_transient_widgets();
            if cleanup.clear_clipboard {
                if let Some(copy) = self.secret_copy.take() {
                    copy.clear_now();
                }
                tx.clear_secret_clipboard();
            }
        }
    }

    /// Requests a lock with dirty-vault protection (`Manual`, `FocusLoss`, or `IdleTimeout`).
    pub fn request_lock_or_modal(&mut self, trigger: LockTrigger, tx: &mut Tx) {
        let cleanup = self.controller.request_lock(trigger);
        self.apply_lock_cleanup(cleanup, tx);
    }

    /// Discards unsaved changes from the dirty-vault modal and locks immediately.
    pub fn discard_and_lock(&mut self, tx: &mut Tx) {
        let cleanup = self.controller.discard_and_lock();
        self.apply_lock_cleanup(cleanup, tx);
    }

    /// Handles window deactivation by requesting a focus-loss lock while preserving
    /// any active 30s timed `SecretCopy` lease for Alt+Tab paste.
    pub fn handle_focus_lost(&mut self, tx: &mut Tx) {
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");
        let cleanup = self.controller.on_window_focus(false);
        self.apply_lock_cleanup(cleanup, tx);
    }

    /// Populates all Entry Editor [`TextEdit`] widgets from `controller.editor`.
    pub fn sync_editor_widgets_from_controller(&mut self) {
        let Some(editor) = &self.controller.editor else {
            self.wipe_editor_widgets();
            return;
        };
        self.edit_title.replace_text(editor.title.clone());
        self.edit_username.set_secure(editor.username_protected);
        self.edit_username.set_revealed(!editor.username_protected);
        self.edit_username
            .replace_text(editor.username.as_str().to_owned());

        self.edit_password.set_secure(true);
        self.edit_password.set_revealed(editor.password_revealed);
        self.edit_password
            .replace_text(editor.password.as_str().to_owned());

        self.edit_url.set_secure(editor.url_protected);
        self.edit_url.set_revealed(!editor.url_protected);
        self.edit_url.replace_text(editor.url.as_str().to_owned());

        self.edit_notes.set_secure(editor.notes_protected);
        self.edit_notes.set_revealed(!editor.notes_protected);
        self.edit_notes
            .replace_text(editor.notes.as_str().to_owned());

        self.edit_new_tag.replace_text("");
        self.edit_custom_values.clear();
        for field in &editor.custom_fields {
            let mut edit = TextEdit::new(field.value.as_str().to_owned());
            if field.protected {
                edit.set_secure(true);
                edit.set_revealed(field.revealed);
            }
            self.edit_custom_values.push(edit);
        }
        self.add_custom_form.reset();
    }

    /// Wipes all Entry Editor [`TextEdit`] buffers cleanly.
    pub fn wipe_editor_widgets(&mut self) {
        self.edit_title.replace_text("");
        self.edit_username.replace_text("");
        self.edit_password.replace_text("");
        self.edit_password.set_revealed(false);
        self.edit_url.replace_text("");
        self.edit_notes.replace_text("");
        self.edit_new_tag.replace_text("");
        for edit in &mut self.edit_custom_values {
            edit.replace_text("");
        }
        self.edit_custom_values.clear();
        self.add_custom_form.reset();
        self.fallback_edit.replace_text("");
    }

    fn wipe_transient_widgets(&mut self) {
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");
        self.search_edit.replace_text("");
        self.new_group_edit.replace_text("");
        self.show_new_group_form = false;
        self.pending_confirm = None;
        self.attach_dialog_open = false;
        self.attach_path_edit.replace_text("");
        self.attach_name_edit.replace_text("");
        self.attach_dialog_error = None;
        self.extract_dialog = None;
        self.extract_path_edit.replace_text("");
        self.wipe_editor_widgets();
    }

    /// Opens Entry Editor mode for the currently selected entry and syncs widgets.
    pub fn open_entry_editor(&mut self) {
        match self.controller.begin_edit_selected_entry() {
            Ok(()) => self.sync_editor_widgets_from_controller(),
            Err(err) => self.controller.set_browser_error(err),
        }
    }

    /// Creates a new entry in the current group, auto-selects it, and opens Entry Editor mode.
    pub fn create_new_entry(&mut self) {
        match self
            .controller
            .create_entry_in_current_group(None, current_unix_seconds())
        {
            Ok(_) => {
                self.search_edit.replace_text("");
                self.sync_editor_widgets_from_controller();
            }
            Err(err) => self.controller.set_browser_error(err),
        }
    }

    /// Applies the active Entry Editor draft (flushing any pending tag input first).
    pub fn apply_entry_editor(&mut self) {
        if !self.edit_new_tag.text.trim().is_empty() {
            let raw = self.edit_new_tag.text.clone();
            if let Err(err) = self.controller.add_editor_tags_from_input(&raw) {
                self.controller.set_browser_error(err);
                return;
            }
            self.edit_new_tag.replace_text("");
        }
        match self.controller.apply_entry_editor(current_unix_seconds()) {
            Ok(()) => self.wipe_editor_widgets(),
            Err(err) => self.controller.set_browser_error(err),
        }
    }

    /// Cancels the active Entry Editor and wipes editor buffers.
    pub fn cancel_entry_editor(&mut self) {
        self.controller.cancel_entry_editor();
        self.wipe_editor_widgets();
    }

    /// Copies a secret string using Rune's history-excluded timed secret clipboard.
    pub fn copy_secret(&mut self, secret: &Zeroizing<String>, label: &str, tx: &mut Tx) {
        if let Some(prev) = self.secret_copy.take() {
            prev.clear_now();
        }
        let copy = tx.copy_secret(secret.as_str(), SECRET_CLIPBOARD_TTL);
        self.secret_copy = Some(copy);
        let msg = format!("Copied {label} to secret clipboard (30s TTL)");
        match self.controller.active_tab {
            WorkspaceTab::Browser => self.controller.set_browser_info(msg),
            WorkspaceTab::Inject => self.controller.inject_status = Some(msg),
        }
    }

    /// Records user interaction using `tx.clock()` and schedules the next wakeup.
    pub fn note_activity(&mut self, tx: &mut Tx) {
        let now = tx.clock();
        self.clock_secs = now;
        self.controller.record_activity(now);
        self.schedule_wakeup(tx);
    }

    /// Schedules the earliest timer wakeup needed while unlocked (idle lock or 1s TOTP tick).
    pub fn schedule_wakeup(&self, tx: &mut Tx) {
        if !self.controller.is_unlocked() {
            return;
        }
        let idle_due = self.controller.idle_lock_deadline();
        let has_otp = self
            .controller
            .detail
            .as_ref()
            .is_some_and(|detail| detail.metadata.has_otp());
        let due = if has_otp {
            idle_due.min(tx.clock() + 1.0)
        } else {
            idle_due
        };
        tx.wake_at(due);
    }

    /// Polls background unlock/save completions, idle timeout, and live TOTP updates.
    pub fn poll_frame(&mut self, secs: f64, tx: &mut Tx) -> bool {
        self.clock_secs = secs;
        let mut changed = false;

        if let Some((generation, outcome)) = self.unlock_worker.take() {
            self.controller.finish_unlock(generation, outcome, secs);
            self.wipe_transient_widgets();
            tx.instant();
            changed = true;
        }

        if let Some(outcome) = self.save_worker.take() {
            let cleanup = self.controller.finish_save(outcome);
            self.apply_lock_cleanup(cleanup, tx);
            tx.instant();
            changed = true;
        }

        let had_pending = self.controller.pending_lock_decision.is_some();
        let idle_cleanup = self.controller.check_idle_timeout(secs);
        if idle_cleanup.locked_active_session
            || (!had_pending && self.controller.pending_lock_decision.is_some())
        {
            self.apply_lock_cleanup(idle_cleanup, tx);
            changed = true;
        }

        if self.controller.is_unlocked() && !self.controller.saving {
            let now = current_unix_seconds();
            if now != self.last_totp_refresh {
                self.last_totp_refresh = now;
                if self
                    .controller
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.metadata.has_otp())
                {
                    self.controller.refresh_selected_totp(now);
                    changed = true;
                }
            }
            self.schedule_wakeup(tx);
        }

        changed
    }
}

/// Builds the top-level Rune element tree for `nkpui`.
pub fn view(state: &AppState, cx: &mut Cx<AppState>) -> El {
    let dark = cx.system_dark();
    let mut k = Kit::neutral(dark);
    if !dark {
        k.c.text_muted = oklch(0.38, 0.01, 265.0);
        k.c.text_faint = oklch(0.41, 0.01, 265.0);
        k.c.bg_accent = oklch(0.44, 0.17, 256.0);
        k.c.text_accent = oklch(0.42, 0.17, 256.0);
    }

    let header = header_bar(&k, state);
    let body = match state.controller.phase {
        VaultPhase::Locked | VaultPhase::Unlocking => lock_view(&k, state),
        VaultPhase::Unlocked => match state.controller.active_tab {
            WorkspaceTab::Browser => browser_view(&k, state),
            WorkspaceTab::Inject => inject_view(&k, state),
        },
    };

    let base = col()
        .key("nkpui-root")
        .role("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_base)
        .child(header)
        .child(Divider::horizontal().build(&k).key("header-divider"))
        .child(body.grow(1.0).min_h(0.0));

    let mut overlays = Vec::new();
    build_modals(&k, state, &mut overlays);

    kit_root(base, overlays).on_window_focus(|s: &mut AppState, focused: bool, tx: &mut Tx| {
        if !focused {
            s.handle_focus_lost(tx);
        }
    })
}

fn build_modals(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    build_unsaved_lock_modal(k, state, overlays);
    build_confirm_modal(k, state, overlays);
    build_attach_modal(k, state, overlays);
    build_extract_modal(k, state, overlays);
}

fn build_unsaved_lock_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(pending) = &state.controller.pending_lock_decision else {
        return;
    };
    let saving = state.controller.saving;
    let trigger_reason = match pending.trigger {
        LockTrigger::Manual => "You requested to lock the vault with unsaved changes.",
        LockTrigger::FocusLoss => {
            "Window focus was lost while the vault has unsaved changes. Changes are kept until you save or discard."
        }
        LockTrigger::IdleTimeout => {
            "Inactivity timeout elapsed while the vault has unsaved changes. Changes are kept until you save or discard."
        }
    };

    let mut content = col().w_full().px(16.0).pb(16.0).gap(12.0);
    if let Some(err) = &pending.error {
        content = content.child(
            text(err.clone())
                .key("unsaved-lock-error")
                .role("status")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.text_small)
                .color(k.c.danger.fg),
        );
    }

    let save_lock_btn = Button::new(if saving { "Saving…" } else { "Save & Lock" })
        .control_size(ControlSize::Regular)
        .variant(if saving {
            ButtonVariant::Loading
        } else {
            ButtonVariant::Submit
        })
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.start_save(true);
        })
        .build(k)
        .key("modal-save-and-lock-btn");

    let discard_lock_btn = Button::new("Discard & Lock")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Danger)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.discard_and_lock(tx);
        })
        .build(k)
        .key("modal-discard-and-lock-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.cancel_pending_lock();
        })
        .build(k)
        .key("modal-cancel-lock-btn");

    content = content.child(
        row()
            .key("unsaved-lock-actions")
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(discard_lock_btn)
            .child(save_lock_btn),
    );

    Dialog::new("unsaved-lock", "Unsaved Changes")
        .open(true)
        .fit()
        .width(460.0)
        .description(trigger_reason)
        .close_disabled(saving)
        .on_close(|s: &mut AppState| s.controller.cancel_pending_lock())
        .child(content)
        .build(k, overlays);
}

fn build_confirm_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(confirm) = &state.pending_confirm else {
        return;
    };
    let (title, description, confirm_label) = match confirm {
        ConfirmDialog::DeleteGroup { label } => (
            "Delete Group?",
            format!(
                "Delete group \"{label}\" and all entries or subgroups inside it? This marks the vault unsaved."
            ),
            "Delete Group",
        ),
        ConfirmDialog::DeleteEntry { title } => (
            "Delete Entry?",
            format!("Delete entry \"{title}\"? This marks the vault unsaved."),
            "Delete Entry",
        ),
        ConfirmDialog::RemoveAttachment { name } => (
            "Remove Attachment?",
            format!("Remove attachment \"{name}\" from this entry? This marks the vault unsaved."),
            "Remove Attachment",
        ),
    };

    let action = confirm.clone();
    let confirm_btn = Button::new(confirm_label)
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Danger)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.pending_confirm = None;
            let res = match &action {
                ConfirmDialog::DeleteGroup { .. } => {
                    let r = s.controller.remove_current_group();
                    if r.is_ok() {
                        s.wipe_editor_widgets();
                    }
                    r
                }
                ConfirmDialog::DeleteEntry { .. } => {
                    let r = s.controller.delete_selected_entry(current_unix_seconds());
                    if r.is_ok() {
                        s.wipe_editor_widgets();
                    }
                    r
                }
                ConfirmDialog::RemoveAttachment { name } => s.controller.remove_attachment(name),
            };
            if let Err(err) = res {
                s.controller.set_browser_error(err);
            }
        })
        .build(k)
        .key("confirm-action-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.pending_confirm = None;
        })
        .build(k)
        .key("confirm-cancel-btn");

    let content = col().w_full().px(16.0).pb(16.0).gap(12.0).child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(confirm_btn),
    );

    Dialog::new("confirm-action", title)
        .open(true)
        .fit()
        .width(440.0)
        .description(description)
        .on_close(|s: &mut AppState| s.pending_confirm = None)
        .child(content)
        .build(k, overlays);
}

fn build_attach_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    if !state.attach_dialog_open {
        return;
    }

    let path_field = TextInput::new(&state.attach_path_edit)
        .label("Source file path (<= 16 MiB)")
        .placeholder("/path/to/file.pem")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.attach_path_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("attach-source-path-input");

    let name_field = TextInput::new(&state.attach_name_edit)
        .label("Attachment name (optional, defaults to filename)")
        .placeholder("Optional name override")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.attach_name_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("attach-name-input");

    let mut content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(labeled_field(
            k,
            "attach-source-field",
            "Source File Path (<= 16 MiB)",
            path_field,
        ))
        .child(labeled_field(
            k,
            "attach-name-field",
            "Attachment Name (optional)",
            name_field,
        ));

    if let Some(err) = &state.attach_dialog_error {
        content = content.child(error_status_text(k, "attach-dialog-error", err));
    }

    let attach_btn = Button::new("Attach File")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let source = PathBuf::from(s.attach_path_edit.text.trim());
            let name_opt = s.attach_name_edit.text.clone();
            match s.controller.attach_file(&source, Some(&name_opt)) {
                Ok(()) => {
                    s.attach_dialog_open = false;
                    s.attach_path_edit.replace_text("");
                    s.attach_name_edit.replace_text("");
                    s.attach_dialog_error = None;
                }
                Err(err) => s.attach_dialog_error = Some(err),
            }
        })
        .build(k)
        .key("attach-submit-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.attach_dialog_open = false;
            s.attach_dialog_error = None;
        })
        .build(k)
        .key("attach-cancel-btn");

    content = content.child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(attach_btn),
    );

    Dialog::new("attach-file", "Attach Binary File")
        .open(true)
        .fit()
        .width(460.0)
        .description(
            "Reads a regular file bounded to 16 MiB into the vault's protected binary pool.",
        )
        .on_close(|s: &mut AppState| {
            s.attach_dialog_open = false;
            s.attach_dialog_error = None;
        })
        .child(content)
        .build(k, overlays);
}

fn build_extract_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(dialog) = &state.extract_dialog else {
        return;
    };

    let dest_field = TextInput::new(&state.extract_path_edit)
        .label("Destination file path (no-clobber)")
        .placeholder("/path/to/output.bin")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.extract_path_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("extract-dest-path-input");

    let mut content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(labeled_field(
            k,
            "extract-dest-field",
            "Destination Path (owner-only, no-clobber)",
            dest_field,
        ));

    if let Some(err) = &dialog.error {
        content = content.child(error_status_text(k, "extract-dialog-error", err));
    }

    let attachment_index = dialog.index;
    let save_btn = Button::new("Save Privately")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let target = PathBuf::from(s.extract_path_edit.text.trim());
            match s.controller.extract_attachment(attachment_index, &target) {
                Ok(()) => {
                    s.extract_dialog = None;
                    s.extract_path_edit.replace_text("");
                }
                Err(err) => {
                    if let Some(dlg) = s.extract_dialog.as_mut() {
                        dlg.error = Some(err);
                    }
                }
            }
        })
        .build(k)
        .key("extract-submit-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.extract_dialog = None;
        })
        .build(k)
        .key("extract-cancel-btn");

    content = content.child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(save_btn),
    );

    Dialog::new("extract-attachment", "Extract Attachment Privately")
        .open(true)
        .fit()
        .width(460.0)
        .description(format!(
            "Write \"{}\" ({}) with owner-only permissions without overwriting existing files.",
            dialog.name,
            format_byte_size(dialog.size)
        ))
        .on_close(|s: &mut AppState| s.extract_dialog = None)
        .child(content)
        .build(k, overlays);
}

fn error_status_text(k: &Kit, key: &str, msg: &str) -> El {
    text(msg.to_owned())
        .key(key)
        .role("status")
        .w_full()
        .wrap_anywhere()
        .font(k.ty.text_small)
        .color(k.c.danger.fg)
}

fn header_clipboard_status(k: &Kit, copy: &SecretCopy) -> El {
    let state_kind = copy.state();
    let label = match state_kind {
        SecretState::Pending => "Clip: pending",
        SecretState::Holding => "Clip: 30s",
        SecretState::Cleared => "Clip: cleared",
        SecretState::Replaced => "Clip: replaced",
        SecretState::Failed(_) => "Clip: wipe refused",
    };
    let mut clip_row = row().key("clipboard-status").gap(4.0).center_y().child(
        Badge::new(label)
            .variant(BadgeVariant::Neutral)
            .build(k)
            .key("clipboard-badge"),
    );
    if matches!(
        state_kind,
        SecretState::Pending | SecretState::Holding | SecretState::Failed(_)
    ) {
        clip_row = clip_row.child(
            Button::new("Clear")
                .control_size(ControlSize::Small)
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    if s.controller.is_unlocked() {
                        s.note_activity(tx);
                    }
                    if let Some(copy) = s.secret_copy.take() {
                        copy.clear_now();
                    }
                    tx.clear_secret_clipboard();
                })
                .build(k)
                .key("clipboard-clear-btn"),
        );
    }
    clip_row
}

fn header_unlocked_actions(k: &Kit, state: &AppState, right: El) -> El {
    let saving = state.controller.saving;
    let dirty = state.controller.dirty;
    let save_btn = Button::new(if saving { "Saving…" } else { "Save" })
        .control_size(ControlSize::Regular)
        .variant(if saving {
            ButtonVariant::Loading
        } else if dirty {
            ButtonVariant::Submit
        } else {
            ButtonVariant::Neutral
        })
        .disabled(!dirty || saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.start_save(false);
        })
        .build(k)
        .key("header-save-btn");

    let browser_btn = Button::new("Browser")
        .control_size(ControlSize::Regular)
        .variant(if state.controller.active_tab == WorkspaceTab::Browser {
            ButtonVariant::Contrast
        } else {
            ButtonVariant::Ghost
        })
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.active_tab = WorkspaceTab::Browser;
        })
        .build(k)
        .key("nav-browser-btn");

    let inject_btn = Button::new("Inject / .env")
        .control_size(ControlSize::Regular)
        .variant(if state.controller.active_tab == WorkspaceTab::Inject {
            ButtonVariant::Contrast
        } else {
            ButtonVariant::Ghost
        })
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.active_tab = WorkspaceTab::Inject;
        })
        .build(k)
        .key("nav-inject-btn");

    let lock_btn = Button::new("Lock")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Danger)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.request_lock_or_modal(LockTrigger::Manual, tx);
        })
        .build(k)
        .key("nav-lock-btn");

    right
        .child(save_btn)
        .child(browser_btn)
        .child(inject_btn)
        .child(lock_btn)
}

fn header_bar(k: &Kit, state: &AppState) -> El {
    let status_badge = match state.controller.phase {
        VaultPhase::Locked => Badge::new("Locked").standard().high_contrast().build(k),
        VaultPhase::Unlocking => Badge::new("Unlocking").standard().build(k),
        VaultPhase::Unlocked => Badge::new("Unlocked")
            .variant(BadgeVariant::Accent)
            .build(k),
    }
    .key("header-status-badge");

    let mut title = row()
        .key("header-title")
        .gap(8.0)
        .center_y()
        .child(
            text("neo-keepass")
                .key("header-app-name")
                .font(k.ty.ui_medium)
                .color(k.c.text_base),
        )
        .child(status_badge);

    if state.controller.is_unlocked() && state.controller.dirty {
        title = title.child(
            Badge::new("• Unsaved")
                .variant(BadgeVariant::Accent)
                .build(k)
                .key("header-unsaved-badge"),
        );
    }

    let mut right = row().key("header-actions").gap(6.0).center_y();
    if let Some(copy) = &state.secret_copy {
        right = right.child(header_clipboard_status(k, copy));
    }
    if state.controller.is_unlocked() {
        right = header_unlocked_actions(k, state, right);
    }

    row()
        .key("header")
        .w_full()
        .h(48.0)
        .px(16.0)
        .justify_between()
        .center_y()
        .fill(k.c.layer_01)
        .child(title)
        .child(right)
}

fn lock_field_errors(
    field: LockErrorField,
    unlocking: bool,
    has_key_file: bool,
) -> (bool, bool, bool) {
    if unlocking {
        return (false, false, false);
    }
    match field {
        LockErrorField::None | LockErrorField::Info => (false, false, false),
        LockErrorField::Vault => (true, false, false),
        LockErrorField::Master => (false, true, false),
        LockErrorField::KeyFile => (false, false, true),
        LockErrorField::Credentials => (false, true, has_key_file),
    }
}

fn submit_lock_screen(state: &mut AppState) {
    if state.controller.lock_mode == LockMode::Create {
        state.start_create_vault();
    } else {
        state.start_unlock();
    }
}

fn lock_mode_switcher(k: &Kit, is_create: bool, unlocking: bool) -> El {
    let open_mode_btn = Button::new("Open Vault")
        .control_size(ControlSize::Regular)
        .variant(if is_create {
            ButtonVariant::Ghost
        } else {
            ButtonVariant::Contrast
        })
        .disabled(unlocking)
        .on_press(|s: &mut AppState| {
            s.controller.lock_mode = LockMode::Open;
            s.controller.clear_lock_status();
            s.confirm_master_edit.replace_text("");
        })
        .build(k)
        .key("lock-mode-open-btn");

    let create_mode_btn = Button::new("Create New Vault")
        .control_size(ControlSize::Regular)
        .variant(if is_create {
            ButtonVariant::Contrast
        } else {
            ButtonVariant::Ghost
        })
        .disabled(unlocking)
        .on_press(|s: &mut AppState| {
            s.controller.lock_mode = LockMode::Create;
            s.controller.clear_lock_status();
        })
        .build(k)
        .key("lock-mode-create-btn");

    row()
        .key("lock-mode-switch")
        .gap(8.0)
        .child(open_mode_btn)
        .child(create_mode_btn)
}

fn lock_form_inputs(
    k: &Kit,
    state: &AppState,
    is_create: bool,
    unlocking: bool,
    invalid: (bool, bool, bool),
) -> El {
    let (vault_invalid, master_invalid, key_invalid) = invalid;

    let vault_field = TextInput::new(&state.vault_path_edit)
        .label("Vault (.kdbx)")
        .placeholder(if is_create {
            "/path/to/new-vault.kdbx"
        } else {
            "/path/to/vault.kdbx"
        })
        .width(None)
        .invalid(vault_invalid)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.vault_path_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.vault_path = s.vault_path_edit.text.clone();
        })
        .on_submit(|s: &mut AppState, _| submit_lock_screen(s))
        .build(k)
        .key("lock-vault-path-input");

    let master_field = TextInput::new(&state.master_input)
        .secure()
        .label("Master Password")
        .placeholder("Master password")
        .width(None)
        .invalid(master_invalid)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.master_input)
        .on_submit(|s: &mut AppState, _| submit_lock_screen(s))
        .build(k)
        .key("lock-master-input");

    let key_field = TextInput::new(&state.key_file_edit)
        .label("Key File (optional)")
        .placeholder("Optional key file path")
        .width(None)
        .invalid(key_invalid)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.key_file_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.key_file_path = s.key_file_edit.text.clone();
        })
        .on_submit(|s: &mut AppState, _| submit_lock_screen(s))
        .build(k)
        .key("lock-key-file-input");

    let mut fields = col()
        .w_full()
        .gap(12.0)
        .child(labeled_field(
            k,
            "lock-vault-field",
            "Vault (.kdbx)",
            vault_field,
        ))
        .child(labeled_field(
            k,
            "lock-master-field",
            "Master Password",
            master_field,
        ));

    if is_create {
        let confirm_field = TextInput::new(&state.confirm_master_edit)
            .secure()
            .label("Confirm Password")
            .placeholder("Confirm master password")
            .width(None)
            .invalid(master_invalid)
            .disabled(unlocking)
            .on_edit(|s: &mut AppState| &mut s.confirm_master_edit)
            .on_submit(|s: &mut AppState, _| s.start_create_vault())
            .build(k)
            .key("lock-confirm-master-input");
        fields = fields.child(labeled_field(
            k,
            "lock-confirm-field",
            "Confirm Password",
            confirm_field,
        ));
    }

    fields.child(labeled_field(
        k,
        "lock-key-field",
        "Key File (optional)",
        key_field,
    ))
}

fn lock_view(k: &Kit, state: &AppState) -> El {
    let unlocking = state.controller.phase == VaultPhase::Unlocking;
    let is_create = state.controller.lock_mode == LockMode::Create;
    let is_info_notice = state.controller.lock_error_field == LockErrorField::Info;
    let invalid = lock_field_errors(
        state.controller.lock_error_field,
        unlocking,
        !state.key_file_edit.text.trim().is_empty(),
    );

    let submit_label = match (is_create, unlocking) {
        (false, false) => "Unlock Vault",
        (false, true) => "Unlocking…",
        (true, false) => "Create & Open Vault",
        (true, true) => "Creating…",
    };

    let mut unlock_btn = Button::new(submit_label)
        .control_size(ControlSize::Large)
        .variant(if unlocking {
            ButtonVariant::Loading
        } else {
            ButtonVariant::Submit
        })
        .disabled(unlocking)
        .on_press(|s: &mut AppState| submit_lock_screen(s))
        .build(k)
        .key("unlock-submit-btn");
    if !unlocking {
        unlock_btn = unlock_btn.default_button();
    }

    let mut card = col()
        .key("lock-card")
        .w(440.0)
        .max_w(440.0)
        .padding(24.0)
        .gap(12.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_muted)
        .child(lock_mode_switcher(k, is_create, unlocking))
        .child(
            text(if is_create {
                "Create New KeePass Vault"
            } else {
                "Unlock KeePass Vault"
            })
            .key("lock-title")
            .font(k.ty.body_medium)
            .color(k.c.text_base),
        )
        .child(
            text(
                "KDF runs on a background worker thread; focus loss locks clean vaults immediately and prompts on unsaved changes.",
            )
            .key("lock-subtitle")
            .w_full()
            .wrap()
            .font(k.ty.text_xsmall)
            .color(k.c.text_muted),
        )
        .child(lock_form_inputs(k, state, is_create, unlocking, invalid))
        .child(row().key("lock-actions").w_full().justify_end().child(unlock_btn));

    if let Some(status) = &state.controller.lock_status {
        card = card.child(
            text(status.clone())
                .key("lock-status")
                .role("status")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.text_small)
                .color(if unlocking {
                    k.c.warning.fg
                } else if is_info_notice {
                    k.c.info.fg
                } else {
                    k.c.danger.fg
                }),
        );
    }

    col()
        .key("lock-screen")
        .w_full()
        .h_full()
        .center()
        .padding(16.0)
        .scroll(ScrollSpec::default())
        .child(card)
}

fn browser_view(k: &Kit, state: &AppState) -> El {
    let sidebar = group_sidebar(k, state);
    let list = entry_list_pane(k, state);
    let detail = entry_detail_pane(k, state);

    row()
        .key("browser-view")
        .w_full()
        .h_full()
        .child(sidebar)
        .child(Divider::vertical().build(k).key("browser-divider-1"))
        .child(list)
        .child(Divider::vertical().build(k).key("browser-divider-2"))
        .child(detail.grow(1.0).min_w(0.0))
}

fn sidebar_button(
    k: &Kit,
    key: impl Into<String>,
    label: String,
    variant: ButtonVariant,
    on_press: impl Fn(&mut AppState, &mut Tx) + 'static,
) -> El {
    let display = label.clone();
    Button::new(label)
        .control_size(ControlSize::Regular)
        .variant(variant)
        .label_with(move |font, ink| {
            text(display)
                .grow(1.0)
                .min_w(0.0)
                .truncate()
                .font(font)
                .color(ink)
        })
        .on_press_tx(on_press)
        .build(k)
        .key(key)
        .w_full()
        .justify_start()
}

fn submit_new_group(state: &mut AppState) {
    let name = state.new_group_edit.text.clone();
    match state.controller.create_subgroup(&name) {
        Ok(()) => {
            state.new_group_edit.replace_text("");
            state.show_new_group_form = false;
        }
        Err(err) => state.controller.set_browser_error(err),
    }
}

fn new_group_form_el(k: &Kit, state: &AppState) -> El {
    let name_input = TextInput::new(&state.new_group_edit)
        .label("New subgroup name")
        .placeholder("Subgroup name")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.new_group_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .on_submit(|s: &mut AppState, tx| {
            s.note_activity(tx);
            submit_new_group(s);
        })
        .build(k)
        .key("new-group-name-input");

    let create_btn = Button::new("Add")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Submit)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            submit_new_group(s);
        })
        .build(k)
        .key("new-group-submit-btn");

    col()
        .key("new-group-form")
        .w_full()
        .gap(6.0)
        .child(name_input)
        .child(row().w_full().justify_end().child(create_btn))
}

fn group_sidebar_list(k: &Kit, state: &AppState) -> El {
    let mut col_groups = col()
        .key("group-list")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(4.0);

    for (idx, (label, _)) in state.controller.breadcrumbs.iter().enumerate() {
        let is_current = idx + 1 == state.controller.breadcrumbs.len();
        col_groups = col_groups.child(sidebar_button(
            k,
            format!("breadcrumb-{idx}"),
            format!("↳ {label}"),
            if is_current {
                ButtonVariant::Neutral
            } else {
                ButtonVariant::Ghost
            },
            move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.controller.navigate_breadcrumb(idx);
                s.search_edit.replace_text("");
                s.wipe_editor_widgets();
            },
        ));
    }

    if !state.controller.child_groups.is_empty() {
        col_groups = col_groups.child(Divider::horizontal().build(k).key("group-divider"));
    }

    for (idx, group) in state.controller.child_groups.iter().enumerate() {
        col_groups = col_groups.child(sidebar_button(
            k,
            format!("child-group-{idx}"),
            group.label().to_owned(),
            ButtonVariant::GhostMuted,
            move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.controller.open_child_group(idx);
                s.search_edit.replace_text("");
                s.wipe_editor_widgets();
            },
        ));
    }

    col_groups
}

fn group_sidebar(k: &Kit, state: &AppState) -> El {
    let add_group_toggle = Button::new(if state.show_new_group_form {
        "Close"
    } else {
        "+ Group"
    })
    .control_size(ControlSize::Small)
    .variant(ButtonVariant::Ghost)
    .disabled(state.controller.saving)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        s.show_new_group_form = !s.show_new_group_form;
        if !s.show_new_group_form {
            s.new_group_edit.replace_text("");
        }
    })
    .build(k)
    .key("sidebar-add-group-toggle");

    let mut sidebar = col()
        .key("group-sidebar")
        .w(190.0)
        .h_full()
        .padding(10.0)
        .gap(8.0)
        .fill(k.c.layer_01)
        .child(
            row()
                .key("group-sidebar-header")
                .w_full()
                .justify_between()
                .center_y()
                .child(
                    text("Groups")
                        .key("group-sidebar-heading")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(add_group_toggle),
        );

    if state.show_new_group_form {
        sidebar = sidebar.child(new_group_form_el(k, state));
    }

    sidebar = sidebar.child(group_sidebar_list(k, state));

    if !state.controller.is_at_root() {
        let current_label = state
            .controller
            .breadcrumbs
            .last()
            .map_or_else(String::new, |(label, _)| label.clone());
        sidebar = sidebar.child(
            Button::new("Delete Group")
                .control_size(ControlSize::Small)
                .variant(ButtonVariant::Danger)
                .disabled(state.controller.saving)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.pending_confirm = Some(ConfirmDialog::DeleteGroup {
                        label: current_label.clone(),
                    });
                })
                .build(k)
                .key("delete-group-btn")
                .w_full(),
        );
    }

    sidebar
}

fn entry_list_items(k: &Kit, state: &AppState) -> El {
    let mut list = col()
        .key("entry-list")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(4.0);

    if state.controller.entries.is_empty() {
        let empty_msg = if state.controller.search_query.trim().is_empty() {
            "No entries in this group"
        } else {
            "No matching entries"
        };
        return list.child(
            text(empty_msg)
                .key("entry-list-empty")
                .w_full()
                .wrap()
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    }

    for (idx, hit) in state.controller.entries.iter().enumerate() {
        let selected = state.controller.selected_index == Some(idx);
        list = list.child(
            col()
                .key(format!("entry-row-{idx}"))
                .w_full()
                .padding(8.0)
                .gap(2.0)
                .radius(k.radius.md)
                .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
                .focusable(true)
                .hover(k.c.hover)
                .press(k.c.pressed)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.controller.select_entry(idx, current_unix_seconds());
                    s.wipe_editor_widgets();
                })
                .child(
                    text(hit.title().to_owned())
                        .w_full()
                        .font(k.ty.ui_medium)
                        .color(k.c.text_base)
                        .truncate(),
                )
                .child(
                    text(hit.path().to_owned())
                        .w_full()
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        );
    }
    list
}

fn entry_list_pane(k: &Kit, state: &AppState) -> El {
    let new_entry_btn = Button::new("+ New Entry")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Submit)
        .disabled(state.controller.saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.create_new_entry();
        })
        .build(k)
        .key("new-entry-btn");

    let search_box = TextInput::new(&state.search_edit)
        .label("Search vault entries")
        .placeholder("Search title, user, URL, path…")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.search_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let query = s.search_edit.text.clone();
            s.controller.set_search_query(query, current_unix_seconds());
            s.wipe_editor_widgets();
        })
        .build(k)
        .key("entry-search-input");

    col()
        .key("entry-list-pane")
        .w(215.0)
        .h_full()
        .padding(10.0)
        .gap(8.0)
        .child(
            row()
                .key("entry-list-header")
                .w_full()
                .justify_between()
                .center_y()
                .child(
                    text("Entries")
                        .key("entry-list-heading")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(new_entry_btn),
        )
        .child(search_box)
        .child(entry_list_items(k, state))
}

fn entry_detail_header(k: &Kit, detail: &EntryDetailState, saving: bool) -> El {
    let edit_btn = Button::new("Edit")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.open_entry_editor();
        })
        .build(k)
        .key("entry-edit-btn");

    let entry_title = detail.metadata.title().to_owned();
    let delete_btn = Button::new("Delete")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Danger)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.pending_confirm = Some(ConfirmDialog::DeleteEntry {
                title: entry_title.clone(),
            });
        })
        .build(k)
        .key("entry-delete-btn");

    row()
        .key("detail-header-row")
        .w_full()
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(
            col()
                .key("detail-title-col")
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(detail.metadata.title().to_owned())
                        .key("detail-title")
                        .w_full()
                        .wrap_anywhere()
                        .font(k.ty.body_medium)
                        .color(k.c.text_base),
                )
                .child(
                    text(detail.path.clone())
                        .key("detail-path")
                        .w_full()
                        .wrap_anywhere()
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_muted),
                ),
        )
        .child(
            row()
                .key("detail-header-actions")
                .gap(6.0)
                .child(edit_btn)
                .child(delete_btn),
        )
}

fn entry_detail_pane(k: &Kit, state: &AppState) -> El {
    let mut pane = col()
        .key("entry-detail-pane")
        .w_full()
        .h_full()
        .padding(16.0)
        .gap(10.0)
        .scroll(ScrollSpec::default());

    if let Some(status) = &state.controller.browser_status {
        pane = pane.child(
            text(status.clone())
                .key("browser-status")
                .role("status")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.text_small)
                .color(if state.controller.browser_status_is_error {
                    k.c.danger.fg
                } else {
                    k.c.info.fg
                }),
        );
    }

    if let Some(editor) = &state.controller.editor {
        return entry_editor_pane(k, state, pane, editor);
    }

    let Some(detail) = &state.controller.detail else {
        let empty_msg = if !state.controller.search_query.trim().is_empty()
            && state.controller.entries.is_empty()
        {
            "No matching entries"
        } else {
            "Select an entry to inspect or edit, or click + New Entry"
        };
        return pane.child(
            text(empty_msg)
                .key("detail-empty")
                .w_full()
                .wrap()
                .font(k.ty.ui)
                .color(k.c.text_muted),
        );
    };

    pane = pane
        .child(entry_detail_header(k, detail, state.controller.saving))
        .child(Divider::horizontal().build(k).key("detail-divider"));

    if !detail.metadata.tags().is_empty() {
        let mut tags_row = row().key("detail-tags-row").w_full().flex_wrap().gap(6.0);
        for tag in detail.metadata.tags() {
            tags_row = tags_row.child(
                Badge::new(tag.clone())
                    .variant(BadgeVariant::Accent)
                    .build(k)
                    .key(format!("detail-tag-{tag}")),
            );
        }
        pane = pane.child(tags_row);
    }

    pane = pane
        .child(standard_field_row(
            k,
            detail,
            "UserName",
            "UserName",
            &detail.username,
        ))
        .child(standard_field_row(k, detail, "URL", "URL", &detail.url))
        .child(password_row(k, detail))
        .child(standard_field_row(
            k,
            detail,
            "Notes",
            "Notes",
            &detail.notes,
        ));

    if let Some(totp) = &detail.totp {
        pane = pane.child(totp_row(k, totp));
    }
    if !detail.metadata.custom_fields().is_empty() {
        pane = custom_fields_section(k, pane, detail);
    }
    attachments_section(k, pane, detail, state.controller.saving)
}

fn editor_header_row(k: &Kit, editor: &EntryEditorState, saving: bool) -> El {
    let apply_btn = Button::new("Apply")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Submit)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.apply_entry_editor();
        })
        .build(k)
        .key("editor-apply-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Neutral)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.cancel_entry_editor();
        })
        .build(k)
        .key("editor-cancel-btn");

    row()
        .key("editor-header-row")
        .w_full()
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(format!("Editing: {}", editor.title))
                        .key("editor-heading")
                        .w_full()
                        .truncate()
                        .font(k.ty.body_medium)
                        .color(k.c.text_base),
                )
                .child(
                    text(editor.path.clone())
                        .key("editor-path")
                        .w_full()
                        .truncate()
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_muted),
                ),
        )
        .child(
            row()
                .key("editor-header-actions")
                .gap(6.0)
                .child(cancel_btn)
                .child(apply_btn),
        )
}

fn editor_password_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    let password_input = TextInput::new(&state.edit_password)
        .secure()
        .revealed(editor.password_revealed)
        .label("Password")
        .placeholder("Password")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.edit_password)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let val = Zeroizing::new(s.edit_password.text.clone());
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.password = val;
            }
        })
        .build(k)
        .key("editor-password-input");

    let pw_reveal_btn = Button::new(if editor.password_revealed {
        "Hide"
    } else {
        "Reveal"
    })
    .control_size(ControlSize::Small)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        if let Some(ed) = s.controller.editor.as_mut() {
            ed.password_revealed = !ed.password_revealed;
            s.edit_password.set_revealed(ed.password_revealed);
        }
    })
    .build(k)
    .key("editor-password-reveal-btn");

    let pw_generate_btn = Button::new("Generate (20)")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            match s.controller.generate_editor_password() {
                Ok(generated) => {
                    s.edit_password.replace_text(generated.as_str());
                    s.controller
                        .set_browser_info("Generated 20-character password");
                }
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("editor-password-generate-btn");

    let pw_copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            match s.controller.editor_password_for_copy() {
                Ok(secret) => s.copy_secret(&secret, "Password", tx),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("editor-password-copy-btn");

    col()
        .key("editor-password-block")
        .w_full()
        .gap(6.0)
        .child(labeled_field(
            k,
            "editor-password-field",
            "Password",
            password_input,
        ))
        .child(
            row()
                .key("editor-password-actions")
                .flex_wrap()
                .gap(6.0)
                .child(pw_reveal_btn)
                .child(pw_generate_btn)
                .child(pw_copy_btn),
        )
}

fn editor_standard_fields(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    let title_input = TextInput::new(&state.edit_title)
        .label("Title")
        .placeholder("Entry title")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.edit_title)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let val = s.edit_title.text.clone();
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.title = val;
            }
        })
        .build(k)
        .key("editor-title-input");

    let username_input = {
        let base = TextInput::new(&state.edit_username)
            .label("UserName")
            .placeholder("Username")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.edit_username)
            .on_change(|s: &mut AppState, tx| {
                s.note_activity(tx);
                let val = Zeroizing::new(s.edit_username.text.clone());
                if let Some(ed) = s.controller.editor.as_mut() {
                    ed.username = val;
                }
            });
        if editor.username_protected {
            base.secure().revealed(true)
        } else {
            base
        }
    }
    .build(k)
    .key("editor-username-input");

    let url_input = {
        let base = TextInput::new(&state.edit_url)
            .label("URL")
            .placeholder("https://example.org")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.edit_url)
            .on_change(|s: &mut AppState, tx| {
                s.note_activity(tx);
                let val = Zeroizing::new(s.edit_url.text.clone());
                if let Some(ed) = s.controller.editor.as_mut() {
                    ed.url = val;
                }
            });
        if editor.url_protected {
            base.secure().revealed(true)
        } else {
            base
        }
    }
    .build(k)
    .key("editor-url-input");

    let notes_input = {
        let base = TextArea::new(&state.edit_notes)
            .label("Notes")
            .placeholder("Multiline notes…")
            .rows(4)
            .max_height(150.0)
            .scroll_bar(true)
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.edit_notes)
            .on_change(|s: &mut AppState, tx| {
                s.note_activity(tx);
                let val = Zeroizing::new(s.edit_notes.text.clone());
                if let Some(ed) = s.controller.editor.as_mut() {
                    ed.notes = val;
                }
            });
        if editor.notes_protected {
            base.secure().revealed(true)
        } else {
            base
        }
    }
    .build(k)
    .key("editor-notes-input");

    col()
        .w_full()
        .gap(10.0)
        .child(labeled_field(k, "editor-title-field", "Title", title_input))
        .child(labeled_field(
            k,
            "editor-username-field",
            "UserName",
            username_input,
        ))
        .child(editor_password_block(k, state, editor))
        .child(labeled_field(k, "editor-url-field", "URL", url_input))
        .child(labeled_field(k, "editor-notes-field", "Notes", notes_input))
}

fn entry_editor_pane(k: &Kit, state: &AppState, mut pane: El, editor: &EntryEditorState) -> El {
    pane = pane
        .child(editor_header_row(k, editor, state.controller.saving))
        .child(Divider::horizontal().build(k).key("editor-divider"))
        .child(editor_standard_fields(k, state, editor));

    pane = editor_tags_section(k, state, pane, editor);
    pane = editor_custom_fields_section(k, state, pane, editor);

    if let Some(detail) = &state.controller.detail {
        pane = attachments_section(k, pane, detail, state.controller.saving);
    }

    pane
}

fn editor_tags_section(k: &Kit, state: &AppState, mut pane: El, editor: &EntryEditorState) -> El {
    let mut chips = row().key("editor-tag-chips").w_full().flex_wrap().gap(6.0);
    if editor.tags.is_empty() {
        chips = chips.child(
            text("No tags")
                .key("editor-tags-empty")
                .font(k.ty.text_xsmall)
                .color(k.c.text_faint),
        );
    } else {
        for (idx, tag) in editor.tags.iter().enumerate() {
            chips = chips.child(
                row()
                    .key(format!("editor-tag-chip-{tag}"))
                    .gap(4.0)
                    .center_y()
                    .child(
                        Badge::new(tag.clone())
                            .variant(BadgeVariant::Accent)
                            .build(k),
                    )
                    .child(
                        Button::new("×")
                            .control_size(ControlSize::Mini)
                            .variant(ButtonVariant::Ghost)
                            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                                s.note_activity(tx);
                                s.controller.remove_editor_tag(idx);
                            })
                            .build(k)
                            .key(format!("editor-tag-remove-{tag}")),
                    ),
            );
        }
    }

    let tag_input = TextInput::new(&state.edit_new_tag)
        .label("Add tags (comma-separated)")
        .placeholder("prod, infra, ssh")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.edit_new_tag)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .on_submit(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let raw = s.edit_new_tag.text.clone();
            match s.controller.add_editor_tags_from_input(&raw) {
                Ok(()) => s.edit_new_tag.replace_text(""),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("editor-tag-input");

    let add_tag_btn = Button::new("+ Add Tag")
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let raw = s.edit_new_tag.text.clone();
            match s.controller.add_editor_tags_from_input(&raw) {
                Ok(()) => s.edit_new_tag.replace_text(""),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("editor-tag-add-btn");

    pane = pane
        .child(Divider::horizontal().build(k).key("editor-tags-divider"))
        .child(
            col()
                .key("editor-tags-section")
                .w_full()
                .gap(6.0)
                .child(text("Tags").font(k.ty.small_medium).color(k.c.text_muted))
                .child(chips)
                .child(
                    row()
                        .w_full()
                        .gap(6.0)
                        .center_y()
                        .child(tag_input.grow(1.0).min_w(0.0))
                        .child(add_tag_btn),
                ),
        );
    pane
}

fn editor_custom_field_card(
    k: &Kit,
    state: &AppState,
    idx: usize,
    field: &EditableCustomField,
) -> El {
    let field_key = &field.name;
    let mut header_row = row()
        .key(format!("editor-cf-head-{field_key}"))
        .w_full()
        .justify_between()
        .center_y()
        .gap(6.0)
        .child(
            row()
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(6.0)
                .center_y()
                .child(
                    text(field.name.clone())
                        .truncate()
                        .font(k.ty.small_medium)
                        .color(k.c.text_base),
                ),
        );
    if field.protected {
        header_row = header_row.child(
            Badge::new("Protected")
                .variant(BadgeVariant::Accent)
                .build(k)
                .key(format!("editor-cf-prot-badge-{field_key}")),
        );
    }
    header_row = header_row.child(
        Button::new("Remove")
            .control_size(ControlSize::Small)
            .variant(ButtonVariant::Danger)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.controller.remove_editor_custom_field(idx);
                if idx < s.edit_custom_values.len() {
                    let mut removed = s.edit_custom_values.remove(idx);
                    removed.replace_text("");
                }
            })
            .build(k)
            .key(format!("editor-cf-remove-{field_key}")),
    );

    let value_edit = state
        .edit_custom_values
        .get(idx)
        .unwrap_or(&state.fallback_edit);
    let mut value_input = TextInput::new(value_edit)
        .label(format!("{} value", field.name))
        .placeholder("Custom string value")
        .width(None)
        .on_edit(move |s: &mut AppState| {
            s.edit_custom_values
                .get_mut(idx)
                .unwrap_or(&mut s.fallback_edit)
        })
        .on_change(move |s: &mut AppState, tx| {
            s.note_activity(tx);
            let text = s
                .edit_custom_values
                .get(idx)
                .map_or_else(String::new, |e| e.text.clone());
            if let Some(ed) = s.controller.editor.as_mut()
                && let Some(cf) = ed.custom_fields.get_mut(idx)
            {
                cf.value = Zeroizing::new(text);
            }
        });
    if field.protected {
        value_input = value_input.secure().revealed(field.revealed);
    }

    let actions = editor_custom_field_actions(k, idx, field);

    col()
        .key(format!("editor-cf-card-{field_key}"))
        .w_full()
        .padding(8.0)
        .gap(6.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(header_row)
        .child(
            value_input
                .build(k)
                .key(format!("editor-cf-input-{field_key}")),
        )
        .child(actions)
}

fn editor_custom_field_actions(k: &Kit, idx: usize, field: &EditableCustomField) -> El {
    let field_key = &field.name;
    let protected_cb = Checkbox::new(field.protected)
        .label("Protected")
        .on_toggle_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let next = s
                .controller
                .editor
                .as_ref()
                .and_then(|ed| ed.custom_fields.get(idx))
                .is_some_and(|cf| !cf.protected);
            s.controller.set_editor_custom_field_protected(idx, next);
            if let Some(edit) = s.edit_custom_values.get_mut(idx) {
                edit.set_secure(next);
                edit.set_revealed(!next);
            }
        })
        .build(k)
        .key(format!("editor-cf-protected-{field_key}"));

    let mut actions = row()
        .key(format!("editor-cf-actions-{field_key}"))
        .w_full()
        .flex_wrap()
        .center_y()
        .gap(8.0)
        .child(protected_cb);

    if field.protected {
        actions = actions.child(
            Button::new(if field.revealed { "Hide" } else { "Reveal" })
                .control_size(ControlSize::Small)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.controller.toggle_editor_custom_field_reveal(idx);
                    let revealed = s
                        .controller
                        .editor
                        .as_ref()
                        .and_then(|ed| ed.custom_fields.get(idx))
                        .is_some_and(|cf| cf.revealed);
                    if let Some(edit) = s.edit_custom_values.get_mut(idx) {
                        edit.set_revealed(revealed);
                    }
                })
                .build(k)
                .key(format!("editor-cf-reveal-{field_key}")),
        );
    }

    let cf_name = field.name.clone();
    actions.child(
        Button::new("Copy (30s)")
            .control_size(ControlSize::Small)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                match s.controller.editor_custom_field_for_copy(idx) {
                    Ok(secret) => s.copy_secret(&secret, &cf_name, tx),
                    Err(err) => s.controller.set_browser_error(err),
                }
            })
            .build(k)
            .key(format!("editor-cf-copy-{field_key}")),
    )
}

fn editor_add_custom_form(k: &Kit, state: &AppState) -> El {
    let form = &state.add_custom_form;
    let new_name_input = TextInput::new(&form.name_edit)
        .label("New custom string name")
        .placeholder("Field name (e.g. ApiKey)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.add_custom_form.name_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("add-custom-name-input");

    let mut new_value_input = TextInput::new(&form.value_edit)
        .label("New custom string value")
        .placeholder("Field value")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.add_custom_form.value_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx));
    if form.protected {
        new_value_input = new_value_input.secure().revealed(form.revealed);
    }

    let add_protected_cb = Checkbox::new(form.protected)
        .label("Protected")
        .on_toggle_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.add_custom_form.protected = !s.add_custom_form.protected;
            let prot = s.add_custom_form.protected;
            s.add_custom_form.value_edit.set_secure(prot);
            s.add_custom_form.revealed = !prot;
            s.add_custom_form.value_edit.set_revealed(!prot);
        })
        .build(k)
        .key("add-custom-protected-cb");

    let mut add_form_actions = row()
        .key("add-custom-actions")
        .w_full()
        .flex_wrap()
        .center_y()
        .gap(8.0)
        .child(add_protected_cb);

    if form.protected {
        add_form_actions = add_form_actions.child(
            Button::new(if form.revealed { "Hide" } else { "Reveal" })
                .control_size(ControlSize::Small)
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.add_custom_form.revealed = !s.add_custom_form.revealed;
                    s.add_custom_form
                        .value_edit
                        .set_revealed(s.add_custom_form.revealed);
                })
                .build(k)
                .key("add-custom-reveal-btn"),
        );
    }

    add_form_actions = add_form_actions.child(
        Button::new("+ Add Custom String")
            .control_size(ControlSize::Small)
            .variant(ButtonVariant::Contrast)
            .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                let name = s.add_custom_form.name_edit.text.clone();
                let value = Zeroizing::new(s.add_custom_form.value_edit.text.clone());
                let protected = s.add_custom_form.protected;
                match s
                    .controller
                    .add_editor_custom_field(&name, value.clone(), protected)
                {
                    Ok(()) => {
                        let mut edit = TextEdit::new(value.as_str().to_owned());
                        if protected {
                            edit.set_secure(true);
                            edit.set_revealed(false);
                        }
                        s.edit_custom_values.push(edit);
                        s.add_custom_form.reset();
                        s.controller.clear_browser_status();
                    }
                    Err(err) => s.controller.set_browser_error(err),
                }
            })
            .build(k)
            .key("add-custom-submit-btn"),
    );

    col()
        .key("add-custom-card")
        .w_full()
        .padding(8.0)
        .gap(6.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_muted)
        .child(
            text("Add Custom String")
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        )
        .child(new_name_input)
        .child(new_value_input.build(k).key("add-custom-value-input"))
        .child(add_form_actions)
}

fn editor_custom_fields_section(
    k: &Kit,
    state: &AppState,
    mut pane: El,
    editor: &EntryEditorState,
) -> El {
    pane = pane
        .child(Divider::horizontal().build(k).key("editor-custom-divider"))
        .child(
            text("Custom Strings")
                .key("editor-custom-heading")
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        );

    for (idx, field) in editor.custom_fields.iter().enumerate() {
        pane = pane.child(editor_custom_field_card(k, state, idx, field));
    }

    pane.child(editor_add_custom_form(k, state))
}

fn attachment_item_row(
    k: &Kit,
    idx: usize,
    name: &str,
    size: usize,
    protected: bool,
    saving: bool,
) -> El {
    let mut info = row()
        .key(format!("attachment-info-{name}"))
        .grow(1.0)
        .min_w(0.0)
        .shrink()
        .center_y()
        .gap(6.0)
        .child(
            text(format!("{name} ({})", format_byte_size(size)))
                .key(format!("attachment-name-{name}"))
                .truncate()
                .font(k.ty.ui)
                .color(k.c.text_base),
        );
    if protected {
        info = info.child(
            Badge::new("Protected")
                .variant(BadgeVariant::Accent)
                .build(k)
                .key(format!("attachment-prot-{name}")),
        );
    }

    let extract_name = name.to_owned();
    let extract_btn = Button::new("Save As…")
        .control_size(ControlSize::Small)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.extract_path_edit.replace_text(extract_name.clone());
            s.extract_dialog = Some(ExtractDialogState {
                index: idx,
                name: extract_name.clone(),
                size,
                error: None,
            });
        })
        .build(k)
        .key(format!("attachment-extract-{name}"));

    let remove_name = name.to_owned();
    let remove_btn = Button::new("Remove")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Danger)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.pending_confirm = Some(ConfirmDialog::RemoveAttachment {
                name: remove_name.clone(),
            });
        })
        .build(k)
        .key(format!("attachment-remove-{name}"));

    row()
        .key(format!("attachment-row-{name}"))
        .w_full()
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(info)
        .child(
            row()
                .key(format!("attachment-actions-{name}"))
                .gap(6.0)
                .child(extract_btn)
                .child(remove_btn),
        )
}

fn attachments_section(k: &Kit, mut pane: El, detail: &EntryDetailState, saving: bool) -> El {
    let attach_btn = Button::new("+ Attach File")
        .control_size(ControlSize::Small)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.attach_dialog_open = true;
            s.attach_dialog_error = None;
        })
        .build(k)
        .key("attach-file-open-btn");

    pane = pane
        .child(Divider::horizontal().build(k).key("attachments-divider"))
        .child(
            row()
                .key("attachments-header")
                .w_full()
                .justify_between()
                .center_y()
                .child(
                    text(format!("Attachments ({})", detail.attachments.len()))
                        .key("attachments-heading")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(attach_btn),
        );

    if detail.attachments.is_empty() {
        return pane.child(
            text("No binary attachments")
                .key("attachments-empty")
                .font(k.ty.text_xsmall)
                .color(k.c.text_faint),
        );
    }

    for (idx, attachment) in detail.attachments.iter().enumerate() {
        pane = pane.child(attachment_item_row(
            k,
            idx,
            attachment.name(),
            attachment.size(),
            attachment.protected(),
            saving,
        ));
    }

    pane
}

fn secret_value_text(k: &Kit, key: impl Into<String>, revealed: Option<&Zeroizing<String>>) -> El {
    if let Some(secret) = revealed {
        text(secret.as_str().to_owned())
            .key(key)
            .w_full()
            .wrap_anywhere()
            .font(k.ty.mono)
            .color(k.c.text_base)
            .secure()
            .revealed(true)
    } else {
        text("••••••••••••")
            .key(key)
            .w_full()
            .wrap_anywhere()
            .font(k.ty.mono)
            .color(k.c.text_muted)
            .secure()
    }
}

struct SecretRowSpec<'a> {
    row_key: String,
    label: String,
    protected_badge: bool,
    value_key: String,
    revealed: Option<&'a Zeroizing<String>>,
    reveal_btn: El,
    copy_btn: El,
}

fn secret_field_row(k: &Kit, spec: SecretRowSpec<'_>) -> El {
    let mut label_row = row().key("label-row").w_full().center_y().gap(6.0).child(
        text(spec.label)
            .key("field-label")
            .shrink()
            .truncate()
            .font(k.ty.small_medium)
            .color(k.c.text_muted),
    );
    if spec.protected_badge {
        label_row = label_row.child(
            Badge::new("Protected")
                .variant(BadgeVariant::Accent)
                .build(k),
        );
    }

    row()
        .key(spec.row_key)
        .w_full()
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(
            col()
                .key("value-col")
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
                .child(label_row)
                .child(secret_value_text(k, spec.value_key, spec.revealed)),
        )
        .child(
            row()
                .key("actions")
                .gap(6.0)
                .child(spec.reveal_btn)
                .child(spec.copy_btn),
        )
}

fn custom_fields_section(k: &Kit, mut pane: El, detail: &EntryDetailState) -> El {
    pane = pane
        .child(Divider::horizontal().build(k).key("custom-fields-divider"))
        .child(
            text("Custom Strings")
                .key("custom-fields-heading")
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        );
    for (idx, field) in detail.metadata.custom_fields().iter().enumerate() {
        let field_name = field.name().to_owned();
        let revealed = detail.revealed_custom_fields.get(&idx);
        let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
            .control_size(ControlSize::Small)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.controller.toggle_reveal_custom_field(idx);
            })
            .build(k)
            .key(format!("custom-reveal-{field_name}"));

        let copy_label = field_name.clone();
        let copy_btn = Button::new("Copy (30s)")
            .control_size(ControlSize::Small)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                match s.controller.custom_field_for_copy(idx) {
                    Ok(secret) => s.copy_secret(&secret, &copy_label, tx),
                    Err(err) => s.controller.set_browser_error(err),
                }
            })
            .build(k)
            .key(format!("custom-copy-{field_name}"));

        pane = pane.child(secret_field_row(
            k,
            SecretRowSpec {
                row_key: format!("custom-field-{field_name}"),
                label: field_name.clone(),
                protected_badge: field.protected(),
                value_key: format!("custom-value-{field_name}"),
                revealed,
                reveal_btn,
                copy_btn,
            },
        ));
    }
    pane
}

fn standard_field_row(
    k: &Kit,
    detail: &EntryDetailState,
    label: &'static str,
    field_key: &'static str,
    unprotected_value: &str,
) -> El {
    if !detail.protected_standard_fields.contains_key(field_key) {
        return metadata_row(k, field_key, label, unprotected_value);
    }

    let revealed = detail.revealed_standard_fields.get(field_key);
    let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
        .control_size(ControlSize::Small)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.toggle_reveal_standard_field(field_key);
        })
        .build(k)
        .key(format!("std-reveal-{field_key}"));

    let copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Small)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            match s.controller.standard_field_for_copy(field_key) {
                Ok(secret) => s.copy_secret(&secret, label, tx),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key(format!("std-copy-{field_key}"));

    secret_field_row(
        k,
        SecretRowSpec {
            row_key: format!("std-protected-{field_key}"),
            label: label.to_owned(),
            protected_badge: true,
            value_key: format!("std-value-{field_key}"),
            revealed,
            reveal_btn,
            copy_btn,
        },
    )
}

fn metadata_row(k: &Kit, key_suffix: &str, label: &str, value: &str) -> El {
    let shown = if value.is_empty() { "—" } else { value };
    col()
        .key(format!("std-meta-{key_suffix}"))
        .w_full()
        .padding(8.0)
        .gap(2.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(
            text(label.to_owned())
                .key("meta-label")
                .w_full()
                .truncate()
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        )
        .child(
            text(shown.to_owned())
                .key("meta-value")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.ui)
                .color(k.c.text_base),
        )
}

fn password_row(k: &Kit, detail: &EntryDetailState) -> El {
    let revealed = detail.revealed_password.as_ref();
    let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.toggle_reveal_password();
        })
        .build(k)
        .key("password-reveal-btn");

    let copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            match s.controller.password_for_copy() {
                Ok(secret) => s.copy_secret(&secret, "Password", tx),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("password-copy-btn");

    secret_field_row(
        k,
        SecretRowSpec {
            row_key: String::from("password-row"),
            label: String::from("Password"),
            protected_badge: true,
            value_key: String::from("password-value"),
            revealed,
            reveal_btn,
            copy_btn,
        },
    )
}

fn totp_row(k: &Kit, totp: &TotpDisplay) -> El {
    let copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(code) = s
                .controller
                .detail
                .as_ref()
                .and_then(|d| d.totp.as_ref())
                .map(|t| t.code.clone())
            {
                s.copy_secret(&code, "TOTP", tx);
            }
        })
        .build(k)
        .key("totp-copy-btn");

    row()
        .key("totp-row")
        .w_full()
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(
            col()
                .key("value-col")
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(format!(
                        "TOTP ({}s / {}s)",
                        totp.remaining_secs, totp.period
                    ))
                    .key("totp-label")
                    .w_full()
                    .truncate()
                    .font(k.ty.small_medium)
                    .color(k.c.text_muted),
                )
                .child(
                    text(totp.code.as_str().to_owned())
                        .key("totp-value")
                        .w_full()
                        .wrap_anywhere()
                        .font(k.ty.mono)
                        .color(k.c.text_base)
                        .secure()
                        .revealed(true),
                ),
        )
        .child(copy_btn)
}

fn inject_view(k: &Kit, state: &AppState) -> El {
    let preview_has_error = state.controller.inject_preview_error.is_some();
    let mode_row = row()
        .key("inject-modes")
        .gap(8.0)
        .center_y()
        .child(
            Button::new("Template")
                .control_size(ControlSize::Regular)
                .variant(if state.controller.inject_mode == InjectMode::Template {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.controller.set_inject_mode(InjectMode::Template);
                })
                .build(k)
                .key("inject-mode-template"),
        )
        .child(
            Button::new(".env File")
                .control_size(ControlSize::Regular)
                .variant(if state.controller.inject_mode == InjectMode::EnvFile {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.controller.set_inject_mode(InjectMode::EnvFile);
                })
                .build(k)
                .key("inject-mode-env"),
        );

    let editor = TextArea::new(&state.inject_edit)
        .label("Template or .env input")
        .placeholder("export API_TOKEN=nkp://Group/Entry#Password")
        .rows(6)
        .max_height(160.0)
        .scroll_bar(true)
        .width(None)
        .invalid(preview_has_error)
        .on_edit(|s: &mut AppState| &mut s.inject_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let input = s.inject_edit.text.clone();
            s.controller.set_inject_input(input);
        })
        .build(k)
        .key("inject-editor");

    let render_btn = Button::new("Render from Active Vault")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .disabled(preview_has_error || state.controller.saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Err(err) = s.controller.render_inject(current_unix_seconds()) {
                s.controller.inject_status = Some(err.to_string());
            }
        })
        .build(k)
        .key("inject-render-btn");

    let mut page = col()
        .key("inject-view")
        .w_full()
        .h_full()
        .padding(16.0)
        .gap(12.0)
        .scroll(ScrollSpec::default())
        .child(
            text("Template & .env Injector (nkp://)")
                .key("inject-heading")
                .w_full()
                .wrap()
                .font(k.ty.body_medium)
                .color(k.c.text_base),
        )
        .child(mode_row)
        .child(editor)
        .child(inject_refs_card(k, state))
        .child(row().key("inject-render-row").gap(8.0).child(render_btn));

    if let Some(output) = &state.controller.rendered_output {
        page = inject_output_section(k, state, page, output);
    }

    if let Some(status) = &state.controller.inject_status {
        page = page.child(
            text(status.clone())
                .key("inject-status")
                .role("status")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.text_small)
                .color(k.c.info.fg),
        );
    }

    page
}

fn inject_refs_card(k: &Kit, state: &AppState) -> El {
    let mut refs_box = col()
        .key("inject-refs")
        .w_full()
        .padding(10.0)
        .gap(4.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(
            text(format!(
                "Referenced entries ({})",
                state.controller.extracted_refs.len()
            ))
            .key("inject-refs-heading")
            .font(k.ty.small_medium)
            .color(k.c.text_muted),
        );

    if let Some(err) = &state.controller.inject_preview_error {
        refs_box = refs_box.child(error_status_text(k, "inject-preview-error", err));
    } else if state.controller.extracted_refs.is_empty() {
        refs_box = refs_box.child(
            text("No nkp:// references found")
                .key("inject-refs-empty")
                .w_full()
                .wrap()
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    } else {
        for (idx, uri) in state.controller.extracted_refs.iter().enumerate() {
            let field = uri.field.as_deref().unwrap_or("Password");
            let prefix = uri
                .vault_alias
                .as_deref()
                .map_or_else(String::new, |alias| format!("@{alias}/"));
            refs_box = refs_box.child(
                text(format!("• {prefix}{}  (#{field})", uri.entry_path))
                    .key(format!("inject-ref-{idx}"))
                    .w_full()
                    .wrap_anywhere()
                    .font(k.ty.mono)
                    .color(k.c.text_base),
            );
        }
    }

    refs_box
}

fn inject_output_section(k: &Kit, state: &AppState, page: El, output: &Zeroizing<String>) -> El {
    let revealed = state.controller.inject_output_revealed;
    let output_text = secret_value_text(k, "inject-output-value", revealed.then_some(output));

    let toggle_btn = Button::new(if revealed {
        "Hide Output"
    } else {
        "Reveal Output"
    })
    .control_size(ControlSize::Small)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        s.controller.inject_output_revealed = !s.controller.inject_output_revealed;
        s.controller.inject_status = Some(if s.controller.inject_output_revealed {
            String::from("Rendered output revealed in memory")
        } else {
            String::from("Rendered securely in memory (masked)")
        });
    })
    .build(k)
    .key("inject-output-toggle");

    let copy_btn = Button::new("Copy Output (30s)")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(rendered) = s.controller.rendered_output.clone() {
                s.copy_secret(&rendered, "rendered output", tx);
            }
        })
        .build(k)
        .key("inject-output-copy");

    let save_path_box = TextInput::new(&state.save_path_edit)
        .label("Private output file path")
        .placeholder("/path/to/rendered.env (no-clobber)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.save_path_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            s.controller.inject_save_path = s.save_path_edit.text.clone();
        })
        .build(k)
        .key("inject-save-path-input");

    let save_btn = Button::new("Save Private File")
        .control_size(ControlSize::Regular)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let _ = s.controller.save_inject_output();
        })
        .build(k)
        .key("inject-save-btn");

    page.child(
        col()
            .key("inject-output-card")
            .w_full()
            .padding(10.0)
            .gap(8.0)
            .radius(k.radius.md)
            .fill(k.c.layer_01)
            .child(
                row()
                    .key("inject-output-header")
                    .w_full()
                    .justify_between()
                    .center_y()
                    .child(
                        text("Rendered Output")
                            .key("inject-output-heading")
                            .font(k.ty.small_medium)
                            .color(k.c.text_muted),
                    )
                    .child(
                        row()
                            .key("inject-output-actions")
                            .gap(6.0)
                            .child(toggle_btn)
                            .child(copy_btn),
                    ),
            )
            .child(output_text),
    )
    .child(
        row()
            .key("inject-save-row")
            .w_full()
            .gap(8.0)
            .center_y()
            .child(save_path_box.grow(1.0).min_w(0.0))
            .child(save_btn),
    )
}

fn labeled_field(k: &Kit, key: impl Into<String>, label: &str, field: El) -> El {
    col()
        .key(key)
        .w_full()
        .gap(4.0)
        .child(
            text(label.to_owned())
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        )
        .child(field)
}
