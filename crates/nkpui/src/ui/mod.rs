//! Rune view layer and UI state adapter for `nkpui`.

mod detail;
mod editor;
mod entry_list;
mod inject;
mod lock;
mod modals;
mod tree;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nkeepass::{
    CustomIconId, EntryRef, GroupRef, GroupTreeNode, PathCompletion, ServiceOtpKind, VaultCipher,
    VaultCompression, VaultKdfSummary,
};
use rune::{
    Cx, El, Image, ImageCache, Key, KeyEvent, Latest, PointerPress, SecretCopy, SecretState,
    TextEdit, Tx, col, el, oklch, row, text,
};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, ControlSize, Divider, Kit, Placement, TextInput,
    popover, root as kit_root, scrim,
};
use zeroize::Zeroizing;

use crate::controller::{
    LockCleanup, LockTrigger, SaveOutcome, UnlockOutcome, VaultController, VaultPhase,
    WorkspaceTab, create_and_open_vault_blocking, current_unix_seconds, open_vault_blocking,
    save_vault_blocking,
};
use crate::icons::{
    MAX_CUSTOM_ICON_DIMENSION, raster_dimensions_within_limit, render_keepass_icon,
};

use detail::entry_detail_pane;
use entry_list::entry_list_pane;
use inject::inject_view;
use lock::lock_view;
use modals::build_modals;
use tree::group_sidebar;

const SECRET_CLIPBOARD_TTL: Duration = Duration::from_secs(30);
const MAX_CUSTOM_ICON_CACHE_ENTRIES: usize = 256;
const MAX_CUSTOM_ICON_LOOKUPS_PER_FRAME: usize = 32;

/// Explicit confirmation dialog kind for destructive browser actions.
#[derive(Clone, Eq, PartialEq)]
pub enum ConfirmDialog {
    /// Confirm deleting a non-root group.
    DeleteGroup {
        /// Group reference to delete.
        group_ref: GroupRef,
        /// Group label shown in the confirmation prompt.
        label: String,
    },
    /// Confirm permanently deleting the currently selected entry.
    DeleteEntryPermanent {
        /// Entry title shown in the confirmation prompt.
        title: String,
    },
    /// Confirm permanently deleting all entries and subgroups in the Recycle Bin.
    EmptyRecycleBin,
    /// Confirm removing an attachment from the currently selected entry.
    RemoveAttachment {
        /// Attachment filename shown in the confirmation prompt.
        name: String,
    },
}

impl fmt::Debug for ConfirmDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeleteGroup { label, .. } => f
                .debug_struct("ConfirmDialog::DeleteGroup")
                .field("label", label)
                .finish_non_exhaustive(),
            Self::DeleteEntryPermanent { title } => f
                .debug_struct("ConfirmDialog::DeleteEntryPermanent")
                .field("title", title)
                .finish(),
            Self::EmptyRecycleBin => f.write_str("ConfirmDialog::EmptyRecycleBin"),
            Self::RemoveAttachment { name } => f
                .debug_struct("ConfirmDialog::RemoveAttachment")
                .field("name", name)
                .finish(),
        }
    }
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

/// Target object mutated when picking an icon from the Icon Picker modal.
#[derive(Clone, Eq, PartialEq)]
pub enum IconPickerTarget {
    /// Updates the draft icon in the active Entry Editor (persisted on Apply).
    EntryEditor,
    /// Updates the currently viewed group's icon.
    CurrentGroup,
    /// Updates a specific `TreeView` group's icon.
    Group(GroupRef),
    /// Updates a specific entry's icon immediately.
    Entry(EntryRef),
}

impl fmt::Debug for IconPickerTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryEditor => f.write_str("IconPickerTarget::EntryEditor"),
            Self::CurrentGroup => f.write_str("IconPickerTarget::CurrentGroup"),
            Self::Group(_) => f.write_str("IconPickerTarget::Group(..)"),
            Self::Entry(_) => f.write_str("IconPickerTarget::Entry(..)"),
        }
    }
}

/// Modal state for the interactive `KeePass` icon picker (embedded custom + 69 standard).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IconPickerState {
    /// Target object mutated on selection.
    pub target: IconPickerTarget,
    /// Currently highlighted standard icon ID (`0..=68`).
    pub selected_id: u32,
}

/// Modal state for renaming any group from the sidebar or `TreeView` context menu.
#[derive(Clone, Eq, PartialEq)]
pub struct RenameGroupModalState {
    /// Target group reference.
    pub group_ref: GroupRef,
    /// Non-secret inline validation error.
    pub error: Option<String>,
}

impl fmt::Debug for RenameGroupModalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenameGroupModalState")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Modal state for moving an entry to any group in the database tree.
#[derive(Clone, Eq, PartialEq)]
pub struct MoveEntryModalState {
    /// Entry being moved.
    pub entry_ref: EntryRef,
    /// Entry title displayed in the dialog heading.
    pub entry_title: String,
    /// Selected destination group path.
    pub selected_group_path: Option<String>,
    /// Selected destination group handle.
    pub selected_group_ref: Option<GroupRef>,
    /// Selected destination group label.
    pub selected_group_label: Option<String>,
    /// Non-secret error message if move fails.
    pub error: Option<String>,
}

impl fmt::Debug for MoveEntryModalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MoveEntryModalState")
            .field("entry_title", &self.entry_title)
            .field("selected_group_path", &self.selected_group_path)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// KDF algorithm selection in [`SettingsModalState`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfChoice {
    /// Argon2id.
    Argon2id,
    /// Argon2d.
    Argon2d,
    /// Legacy AES-KDF.
    Aes,
}

/// Modal state for Database & Desktop Security Settings.
#[derive(Clone, Debug, PartialEq)]
pub struct SettingsModalState {
    /// Draft Recycle Bin enabled toggle.
    pub recycle_bin_enabled: bool,
    /// Draft outer KDBX cipher.
    pub outer_cipher: VaultCipher,
    /// Draft payload compression.
    pub compression: VaultCompression,
    /// Draft KDF variant.
    pub kdf_choice: KdfChoice,
    /// Draft auto-lock timeout (`None` = Never).
    pub auto_lock_secs: Option<f64>,
    /// Draft opt-in focus-loss lock toggle.
    pub lock_on_focus_loss: bool,
    /// Non-secret validation/save error.
    pub error: Option<String>,
}

/// Drop target resolved during an active entry drag gesture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DragDropTarget {
    /// Hovering over visible `TreeView` group index `usize`.
    Group(usize),
    /// Hovering over entry list slot `usize` in the current group.
    EntrySlot(usize),
}

/// Active pointer drag state for moving or reordering an entry row.
#[derive(Clone, Debug)]
pub struct ActiveDragState {
    /// Index of the entry row being dragged.
    pub entry_index: usize,
    /// Entry title shown in the drag pill.
    pub entry_title: String,
    /// Current pointer coordinates in window points.
    pub window_point: [f32; 2],
    /// Currently hovered drop target.
    pub target: Option<DragDropTarget>,
}

/// Target item for an active right-click context menu.
#[derive(Clone, Eq, PartialEq)]
pub enum ContextMenuTarget {
    /// Context menu opened on an entry row.
    Entry {
        /// Row index in `controller.entries`.
        index: usize,
        /// Entry reference.
        entry_ref: EntryRef,
        /// Whether entry is inside Recycle Bin.
        is_in_recycle_bin: bool,
        /// Whether entry has OTP configured.
        has_otp: bool,
    },
    /// Context menu opened on a `TreeView` group row.
    Group {
        /// Group reference.
        group_ref: GroupRef,
        /// Group path.
        path: String,
        /// Group label.
        label: String,
        /// Group standard icon ID.
        icon_id: u32,
        /// Whether this is the root group.
        is_root: bool,
        /// Whether this is the Recycle Bin group.
        is_recycle_bin: bool,
    },
}

impl fmt::Debug for ContextMenuTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry {
                index,
                is_in_recycle_bin,
                has_otp,
                ..
            } => f
                .debug_struct("ContextMenuTarget::Entry")
                .field("index", index)
                .field("is_in_recycle_bin", is_in_recycle_bin)
                .field("has_otp", has_otp)
                .finish_non_exhaustive(),
            Self::Group {
                path,
                label,
                is_root,
                is_recycle_bin,
                ..
            } => f
                .debug_struct("ContextMenuTarget::Group")
                .field("path", path)
                .field("label", label)
                .field("is_root", is_root)
                .field("is_recycle_bin", is_recycle_bin)
                .finish_non_exhaustive(),
        }
    }
}

/// Active right-click context menu anchored at `point`.
#[derive(Clone, Debug)]
pub struct ActiveContextMenu {
    /// Anchor position in window points.
    pub point: PointerPress,
    /// Target entry or group row.
    pub target: ContextMenuTarget,
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent modal, dropdown, and focus flags for UI widgets"
)]
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
    /// Editable `/`-prefixed Path Bar input in the browser top bar.
    pub path_edit: TextEdit,
    /// Current path completion candidates (up to 5).
    pub path_completions: Vec<PathCompletion>,
    /// Whether the Path Bar 5-item completion dropdown is open.
    pub path_dropdown_open: bool,
    /// Highlighted suggestion index inside `path_completions`.
    pub path_dropdown_index: Option<usize>,
    /// Active `/`-prefixed path restored when pressing `Escape` in the Path Bar.
    pub active_display_path: String,
    /// Search input inside the unlocked browser.
    pub search_edit: TextEdit,
    /// Whether the inline new-subgroup form is expanded in the sidebar.
    pub show_new_group_form: bool,
    /// Optional explicit parent group for inline new-subgroup creation.
    pub new_group_target: Option<(GroupRef, String)>,
    /// Subgroup name input in the sidebar.
    pub new_group_edit: TextEdit,
    /// Inline non-secret error message shown inside the sidebar new-group form.
    pub new_group_error: Option<String>,
    /// Active Rename Group modal state.
    pub rename_group_modal: Option<RenameGroupModalState>,
    /// Group name input inside the Rename Group modal.
    pub rename_group_edit: TextEdit,
    /// Active Move Entry to Group modal state.
    pub move_entry_modal: Option<MoveEntryModalState>,
    /// Active Database & Desktop Security Settings modal state.
    pub settings_modal: Option<SettingsModalState>,
    /// Database name input inside Settings modal.
    pub settings_name: TextEdit,
    /// Database description input inside Settings modal.
    pub settings_description: TextEdit,
    /// Default username input inside Settings modal.
    pub settings_default_user: TextEdit,
    /// History max items input inside Settings modal.
    pub settings_history_items: TextEdit,
    /// History max size input inside Settings modal.
    pub settings_history_size: TextEdit,
    /// Argon2 memory (MiB) input inside Settings modal.
    pub settings_kdf_memory_mib: TextEdit,
    /// Argon2 iterations input inside Settings modal.
    pub settings_kdf_iterations: TextEdit,
    /// Argon2 lanes input inside Settings modal.
    pub settings_kdf_lanes: TextEdit,
    /// AES-KDF rounds input inside Settings modal.
    pub settings_kdf_rounds: TextEdit,
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
    /// Entry editor `otpauth://` URI input (`.secure()`).
    pub edit_otp_uri: TextEdit,
    /// Entry editor Base32 OTP secret input (`.secure()`).
    pub edit_otp_secret: TextEdit,
    /// Entry editor TOTP period input.
    pub edit_otp_period: TextEdit,
    /// Entry editor HOTP counter input.
    pub edit_otp_counter: TextEdit,
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
    /// Active interactive `KeePass` icon picker modal state.
    pub icon_picker: Option<IconPickerState>,
    /// Filter query inside the interactive `KeePass` icon picker modal.
    pub icon_search_edit: TextEdit,
    /// Shared Rune image decoder cache initialized in `AppSpec::setup`.
    pub images: Option<ImageCache>,
    /// Session-scoped decoded custom KDBX icon images, cleared on `lock()`.
    pub custom_icons: HashMap<CustomIconId, Image>,
    failed_custom_icons: HashSet<CustomIconId>,
    /// True while a native/scripted OS file picker is open so focus loss does not lock the vault.
    pub file_dialog_active: bool,
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
    /// Active drag-and-drop state for entry rows.
    pub drag_state: Option<ActiveDragState>,
    /// Active right-click context menu state.
    pub context_menu: Option<ActiveContextMenu>,
    /// Background worker for KDBX open/create KDF so the UI frame loop never stalls.
    pub unlock_worker: Latest<(u64, UnlockOutcome)>,
    /// Background worker for KDBX save so the UI frame loop never stalls.
    pub save_worker: Latest<SaveOutcome>,
    /// Active clipboard lease handle from `Tx::copy_secret`.
    pub secret_copy: Option<SecretCopy>,
    /// Clock deadline in seconds when the current [`Self::secret_copy`] lease expires.
    pub secret_copy_deadline_secs: Option<f64>,
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
            path_edit: TextEdit::new("/"),
            path_completions: Vec::new(),
            path_dropdown_open: false,
            path_dropdown_index: None,
            active_display_path: String::from("/"),
            search_edit: TextEdit::new(""),
            show_new_group_form: false,
            new_group_target: None,
            new_group_edit: TextEdit::new(""),
            new_group_error: None,
            rename_group_modal: None,
            rename_group_edit: TextEdit::new(""),
            move_entry_modal: None,
            settings_modal: None,
            settings_name: TextEdit::new(""),
            settings_description: TextEdit::new(""),
            settings_default_user: TextEdit::new(""),
            settings_history_items: TextEdit::new("-1"),
            settings_history_size: TextEdit::new("-1"),
            settings_kdf_memory_mib: TextEdit::new("64"),
            settings_kdf_iterations: TextEdit::new("2"),
            settings_kdf_lanes: TextEdit::new("1"),
            settings_kdf_rounds: TextEdit::new("60000"),
            edit_title: TextEdit::new(""),
            edit_username: TextEdit::new(""),
            edit_password: TextEdit::new("").secure(),
            edit_url: TextEdit::new(""),
            edit_notes: TextEdit::new(""),
            edit_otp_uri: TextEdit::new("").secure(),
            edit_otp_secret: TextEdit::new("").secure(),
            edit_otp_period: TextEdit::new("30"),
            edit_otp_counter: TextEdit::new("0"),
            edit_new_tag: TextEdit::new(""),
            edit_custom_values: Vec::new(),
            add_custom_form: AddCustomFieldForm::default(),
            fallback_edit: TextEdit::new("").secure(),
            pending_confirm: None,
            icon_picker: None,
            icon_search_edit: TextEdit::new(""),
            images: None,
            custom_icons: HashMap::new(),
            failed_custom_icons: HashSet::new(),
            file_dialog_active: false,
            attach_dialog_open: false,
            attach_path_edit: TextEdit::new(""),
            attach_name_edit: TextEdit::new(""),
            attach_dialog_error: None,
            extract_dialog: None,
            extract_path_edit: TextEdit::new(""),
            inject_edit,
            save_path_edit: TextEdit::new(""),
            drag_state: None,
            context_menu: None,
            unlock_worker: Latest::default(),
            save_worker: Latest::default(),
            secret_copy: None,
            secret_copy_deadline_secs: None,
            clock_secs: 0.0,
            last_totp_refresh: 0,
        }
    }
}

/// Computes `(remaining_fraction, ceil_seconds)` for the live draining clipboard progress bar.
#[must_use]
pub fn clipboard_progress(
    state_kind: &SecretState,
    deadline_secs: Option<f64>,
    clock_secs: f64,
) -> Option<(f32, u64)> {
    if !matches!(state_kind, SecretState::Pending | SecretState::Holding) {
        return None;
    }
    let ttl = SECRET_CLIPBOARD_TTL.as_secs_f64();
    let remaining = deadline_secs.map_or(ttl, |d| (d - clock_secs).clamp(0.0, ttl));
    let frac = (remaining / ttl).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "remaining is clamped to 0.0..=30.0"
    )]
    let secs = remaining.ceil() as u64;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "fraction is clamped to 0.0..=1.0"
    )]
    Some((frac as f32, secs))
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

    /// Initiates an off-thread `VaultService::create_recommended` + `open` via [`Latest`].
    pub fn start_create_vault(&mut self) {
        self.controller.vault_path = self.vault_path_edit.text.clone();
        self.controller.key_file_path = self.key_file_edit.text.clone();
        let password = Zeroizing::new(self.master_input.text.clone());
        let confirm = Zeroizing::new(self.confirm_master_edit.text.clone());
        let password_empty = password.is_empty();
        let passwords_match = password.as_str() == confirm.as_str();
        drop(confirm);

        let Some((vault_path, key_file_path, generation)) = self
            .controller
            .begin_create(password_empty, passwords_match)
        else {
            if !passwords_match {
                self.confirm_master_edit.replace_text("");
            }
            return;
        };
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");

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
                self.secret_copy_deadline_secs = None;
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

    /// Masks all revealed secrets in controller state and UI text widgets.
    pub fn mask_all_reveals(&mut self) {
        self.controller.mask_all_reveals();
        self.edit_password.set_revealed(false);
        self.edit_otp_uri.set_revealed(false);
        self.edit_otp_secret.set_revealed(false);
        for edit in &mut self.edit_custom_values {
            edit.set_revealed(false);
        }
        self.add_custom_form.revealed = false;
        if self.add_custom_form.protected {
            self.add_custom_form.value_edit.set_revealed(false);
        }
    }

    /// Masks all revealed secrets immediately, wipes lock-screen master password inputs,
    /// and returns lock cleanup only when `lock_on_focus_loss` is enabled and no file dialog is active.
    #[must_use]
    pub fn focus_lost_lock_cleanup(&mut self) -> Option<LockCleanup> {
        self.mask_all_reveals();
        self.master_input.replace_text("");
        self.confirm_master_edit.replace_text("");
        self.drag_state = None;
        if self.file_dialog_active || !self.controller.lock_on_focus_loss {
            return None;
        }
        Some(self.controller.on_window_focus(false))
    }

    /// Handles OS window focus loss: always masks revealed secrets and wipes lock inputs,
    /// locking only if `lock_on_focus_loss == true` (and `!file_dialog_active`).
    pub fn handle_focus_lost(&mut self, tx: &mut Tx) {
        if let Some(cleanup) = self.focus_lost_lock_cleanup() {
            self.apply_lock_cleanup(cleanup, tx);
        }
    }

    /// Syncs `path_edit` and `active_display_path` to the active group or entry path.
    pub fn sync_path_bar_from_controller(&mut self) {
        let display = self.controller.current_display_path();
        self.active_display_path.clone_from(&display);
        self.path_edit.replace_text(display);
        self.path_completions.clear();
        self.path_dropdown_open = false;
        self.path_dropdown_index = None;
    }

    /// Opens the Rename Group modal for `group_ref`.
    pub fn open_rename_group_modal(&mut self, group_ref: GroupRef, label: String, tx: &mut Tx) {
        self.rename_group_edit.replace_text(label);
        self.rename_group_modal = Some(RenameGroupModalState {
            group_ref,
            error: None,
        });
        tx.focus("rename-group-input", true);
    }

    /// Opens the Move Entry to Group modal for `entry_ref`.
    pub fn open_move_entry_modal(&mut self, entry_ref: EntryRef, entry_title: String) {
        self.move_entry_modal = Some(MoveEntryModalState {
            entry_ref,
            entry_title,
            selected_group_path: None,
            selected_group_ref: None,
            selected_group_label: None,
            error: None,
        });
    }

    /// Opens the Database & Desktop Security Settings modal populated from `VaultService`.
    pub fn open_settings_modal(&mut self) {
        match self.controller.database_settings() {
            Ok(settings) => {
                self.settings_name.replace_text(settings.name);
                self.settings_description.replace_text(settings.description);
                self.settings_default_user
                    .replace_text(settings.default_username);
                self.settings_history_items
                    .replace_text(settings.history_max_items.to_string());
                self.settings_history_size
                    .replace_text(settings.history_max_size.to_string());
                let kdf_choice = match settings.kdf {
                    VaultKdfSummary::Aes { rounds } => {
                        self.settings_kdf_rounds.replace_text(rounds.to_string());
                        KdfChoice::Aes
                    }
                    VaultKdfSummary::Argon2d {
                        memory_kib,
                        iterations,
                        lanes,
                    } => {
                        self.settings_kdf_memory_mib
                            .replace_text((memory_kib / 1024).max(1).to_string());
                        self.settings_kdf_iterations
                            .replace_text(iterations.to_string());
                        self.settings_kdf_lanes.replace_text(lanes.to_string());
                        KdfChoice::Argon2d
                    }
                    VaultKdfSummary::Argon2id {
                        memory_kib,
                        iterations,
                        lanes,
                    } => {
                        self.settings_kdf_memory_mib
                            .replace_text((memory_kib / 1024).max(1).to_string());
                        self.settings_kdf_iterations
                            .replace_text(iterations.to_string());
                        self.settings_kdf_lanes.replace_text(lanes.to_string());
                        KdfChoice::Argon2id
                    }
                };
                self.settings_modal = Some(SettingsModalState {
                    recycle_bin_enabled: settings.recycle_bin_enabled,
                    outer_cipher: settings.outer_cipher,
                    compression: settings.compression,
                    kdf_choice,
                    auto_lock_secs: self.controller.auto_lock_secs,
                    lock_on_focus_loss: self.controller.lock_on_focus_loss,
                    error: None,
                });
            }
            Err(err) => self.controller.set_browser_error(err),
        }
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

        self.edit_otp_uri.set_secure(true);
        self.edit_otp_uri.set_revealed(editor.otp_revealed);
        self.edit_otp_uri
            .replace_text(editor.otp_uri.as_str().to_owned());

        self.edit_otp_secret.set_secure(true);
        self.edit_otp_secret.set_revealed(editor.otp_revealed);
        self.edit_otp_secret
            .replace_text(editor.otp_config.secret.as_str().to_owned());
        self.edit_otp_period
            .replace_text(editor.otp_config.period.to_string());
        self.edit_otp_counter
            .replace_text(editor.otp_config.counter.to_string());

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
        self.edit_otp_uri.replace_text("");
        self.edit_otp_uri.set_revealed(false);
        self.edit_otp_secret.replace_text("");
        self.edit_otp_secret.set_revealed(false);
        self.edit_otp_period.replace_text("30");
        self.edit_otp_counter.replace_text("0");
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
        self.path_edit.replace_text("/");
        self.path_completions.clear();
        self.path_dropdown_open = false;
        self.path_dropdown_index = None;
        self.active_display_path = String::from("/");
        self.search_edit.replace_text("");
        self.new_group_edit.replace_text("");
        self.new_group_error = None;
        self.new_group_target = None;
        self.show_new_group_form = false;
        self.rename_group_modal = None;
        self.rename_group_edit.replace_text("");
        self.move_entry_modal = None;
        self.settings_modal = None;
        self.pending_confirm = None;
        self.icon_picker = None;
        self.icon_search_edit.replace_text("");
        self.custom_icons.clear();
        self.failed_custom_icons.clear();
        self.file_dialog_active = false;
        self.attach_dialog_open = false;
        self.attach_path_edit.replace_text("");
        self.attach_name_edit.replace_text("");
        self.attach_dialog_error = None;
        self.extract_dialog = None;
        self.extract_path_edit.replace_text("");
        self.drag_state = None;
        self.context_menu = None;
        self.wipe_editor_widgets();
    }

    /// Returns whether any text input widget currently holds keyboard focus.
    #[must_use]
    pub fn any_text_input_focused(&self) -> bool {
        let standard_focused = self.vault_path_edit.focused
            || self.key_file_edit.focused
            || self.master_input.focused
            || self.confirm_master_edit.focused
            || self.path_edit.focused
            || self.search_edit.focused
            || self.new_group_edit.focused
            || self.rename_group_edit.focused
            || self.icon_search_edit.focused
            || self.attach_path_edit.focused
            || self.attach_name_edit.focused
            || self.extract_path_edit.focused
            || self.inject_edit.focused
            || self.save_path_edit.focused;
        let editor_focused = self.edit_title.focused
            || self.edit_username.focused
            || self.edit_password.focused
            || self.edit_url.focused
            || self.edit_notes.focused
            || self.edit_otp_uri.focused
            || self.edit_otp_secret.focused
            || self.edit_otp_period.focused
            || self.edit_otp_counter.focused
            || self.edit_new_tag.focused
            || self.add_custom_form.name_edit.focused
            || self.add_custom_form.value_edit.focused
            || self.edit_custom_values.iter().any(|e| e.focused);
        let settings_focused = self.settings_name.focused
            || self.settings_description.focused
            || self.settings_default_user.focused
            || self.settings_history_items.focused
            || self.settings_history_size.focused
            || self.settings_kdf_memory_mib.focused
            || self.settings_kdf_iterations.focused
            || self.settings_kdf_lanes.focused
            || self.settings_kdf_rounds.focused;
        standard_focused || editor_focused || settings_focused
    }

    /// Returns a cached decoded custom KDBX icon image if available.
    #[must_use]
    pub fn custom_icon_for(&self, id: Option<CustomIconId>) -> Option<&Image> {
        id.and_then(|icon_id| self.custom_icons.get(&icon_id))
    }

    fn record_failed_custom_icon(&mut self, id: CustomIconId) {
        if self.failed_custom_icons.len() >= MAX_CUSTOM_ICON_CACHE_ENTRIES
            && let Some(&evict) = self.failed_custom_icons.iter().next()
        {
            self.failed_custom_icons.remove(&evict);
        }
        self.failed_custom_icons.insert(id);
    }

    fn cache_custom_icon_bytes(&mut self, id: CustomIconId, bytes: Vec<u8>) -> bool {
        if self.custom_icons.contains_key(&id) || self.failed_custom_icons.contains(&id) {
            return false;
        }
        let Some(cache) = &self.images else {
            return false;
        };
        if bytes.len() <= nkeepass::icons::MAX_CUSTOM_ICON_BYTES
            && raster_dimensions_within_limit(&bytes, MAX_CUSTOM_ICON_DIMENSION)
        {
            if self.custom_icons.len() >= MAX_CUSTOM_ICON_CACHE_ENTRIES
                && let Some(&evict) = self.custom_icons.keys().next()
            {
                self.custom_icons.remove(&evict);
            }
            let image = cache.load_scaled(bytes, 64.0, 1.0);
            self.custom_icons.insert(id, image);
            true
        } else {
            self.record_failed_custom_icon(id);
            false
        }
    }

    fn cache_custom_icon(&mut self, id: CustomIconId) -> bool {
        if self.custom_icons.contains_key(&id)
            || self.failed_custom_icons.contains(&id)
            || self.images.is_none()
        {
            return false;
        }
        if let Ok(Some(bytes)) = self.controller.custom_icon_bytes(id) {
            self.cache_custom_icon_bytes(id, bytes)
        } else {
            self.record_failed_custom_icon(id);
            false
        }
    }

    /// Ensures up to [`MAX_CUSTOM_ICON_LOOKUPS_PER_FRAME`] uncached visible custom
    /// KDBX icon UUIDs are validated and queued for decoding in `images`.
    pub fn sync_custom_icons(&mut self) -> bool {
        if !self.controller.is_unlocked() || self.controller.saving || self.images.is_none() {
            return false;
        }
        let mut ids: Vec<CustomIconId> = Vec::new();
        for (_, custom_id) in &self.controller.breadcrumb_icons {
            if let Some(id) = custom_id {
                ids.push(*id);
            }
        }
        if let Some(tree) = &self.controller.group_tree {
            collect_tree_custom_icon_ids(tree, &mut ids);
        }
        for hit in &self.controller.entries {
            if let Some(id) = hit.custom_icon_id() {
                ids.push(id);
            }
        }
        if let Some(detail) = &self.controller.detail
            && let Some(id) = detail.metadata.custom_icon_id()
        {
            ids.push(id);
        }
        if let Some(editor) = &self.controller.editor
            && let Some(id) = editor.custom_icon_id
        {
            ids.push(id);
        }
        if self.icon_picker.is_some()
            && let Ok(customs) = self.controller.list_custom_icons()
        {
            for item in customs {
                ids.push(item.id);
            }
        }
        let mut changed = false;
        let mut lookups = 0usize;
        for id in ids {
            if self.custom_icons.contains_key(&id) || self.failed_custom_icons.contains(&id) {
                continue;
            }
            if lookups >= MAX_CUSTOM_ICON_LOOKUPS_PER_FRAME {
                break;
            }
            lookups += 1;
            changed |= self.cache_custom_icon(id);
        }
        changed
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
                self.sync_path_bar_from_controller();
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
            Ok(()) => {
                self.wipe_editor_widgets();
                self.sync_path_bar_from_controller();
            }
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
        let now = tx.clock();
        self.clock_secs = now;
        let copy = tx.copy_secret(secret.as_str(), SECRET_CLIPBOARD_TTL);
        self.secret_copy = Some(copy);
        self.secret_copy_deadline_secs = Some(now + SECRET_CLIPBOARD_TTL.as_secs_f64());
        self.schedule_wakeup(tx);
        let msg = format!("Copied {label} to secret clipboard (30s TTL)");
        match self.controller.active_tab {
            WorkspaceTab::Browser => self.controller.set_browser_info(msg),
            WorkspaceTab::Inject => self.controller.set_inject_info(msg),
        }
    }

    /// Handles `Tab` completion on the editable Path Bar.
    pub fn trigger_path_tab_completion(&mut self, reverse: bool) {
        if self.path_dropdown_open && !self.path_completions.is_empty() {
            let len = self.path_completions.len();
            let next = match (self.path_dropdown_index, reverse) {
                (Some(i), false) => (i + 1) % len,
                (Some(0) | None, true) => len - 1,
                (Some(i), true) => i - 1,
                (None, false) => 0,
            };
            self.path_dropdown_index = Some(next);
            return;
        }
        match self.controller.complete_path(&self.path_edit.text, 5) {
            Ok(matches) => {
                if matches.len() == 1 {
                    let display = self.controller.format_display_path(&matches[0].path);
                    self.path_edit.replace_text(display);
                    self.path_completions.clear();
                    self.path_dropdown_open = false;
                    self.path_dropdown_index = None;
                } else if !matches.is_empty() {
                    self.path_completions = matches;
                    self.path_dropdown_open = true;
                    self.path_dropdown_index = Some(0);
                } else {
                    self.path_completions.clear();
                    self.path_dropdown_open = false;
                    self.path_dropdown_index = None;
                }
            }
            Err(err) => self.controller.set_browser_error(err),
        }
    }

    /// Refreshes live 5-item suggestions while typing with the path dropdown open.
    pub fn refresh_path_completions_live(&mut self) {
        if !self.path_dropdown_open {
            return;
        }
        match self.controller.complete_path(&self.path_edit.text, 5) {
            Ok(matches) if !matches.is_empty() => {
                self.path_completions = matches;
                self.path_dropdown_index = Some(0);
            }
            Ok(_) | Err(_) => {
                self.path_completions.clear();
                self.path_dropdown_open = false;
                self.path_dropdown_index = None;
            }
        }
    }

    /// Navigates to the chosen path completion candidate or resolves the typed path on Enter.
    pub fn submit_path_bar(&mut self) {
        if self.path_dropdown_open
            && let Some(idx) = self.path_dropdown_index
            && let Some(item) = self.path_completions.get(idx).cloned()
        {
            self.navigate_to_completion(&item);
            return;
        }
        if let Ok(matches) = self.controller.complete_path(&self.path_edit.text, 5)
            && let Some(first) = matches.first()
        {
            let target_norm = self.path_edit.text.trim().trim_start_matches('/');
            let exact = matches.iter().find(|m| {
                let disp = self.controller.format_display_path(&m.path);
                disp.trim_start_matches('/')
                    .eq_ignore_ascii_case(target_norm)
                    || m.path.eq_ignore_ascii_case(target_norm)
            });
            let chosen = exact.unwrap_or(first).clone();
            self.navigate_to_completion(&chosen);
        }
    }

    /// Navigates straight to a [`PathCompletion`] and syncs widgets.
    pub fn navigate_to_completion(&mut self, item: &PathCompletion) {
        match self
            .controller
            .navigate_to_completion(item, current_unix_seconds())
        {
            Ok(()) => {
                self.search_edit.replace_text("");
                self.wipe_editor_widgets();
                self.sync_path_bar_from_controller();
            }
            Err(err) => self.controller.set_browser_error(err),
        }
    }

    /// Closes the path dropdown and restores the active path.
    pub fn cancel_path_dropdown(&mut self) {
        self.path_dropdown_open = false;
        self.path_dropdown_index = None;
        self.path_completions.clear();
        self.path_edit
            .replace_text(self.active_display_path.clone());
    }

    /// Records user interaction using `tx.clock()` and schedules the next wakeup.
    pub fn note_activity(&mut self, tx: &mut Tx) {
        let now = tx.clock();
        self.clock_secs = now;
        self.controller.record_activity(now);
        self.schedule_wakeup(tx);
    }

    fn has_active_secret_clipboard(&self) -> bool {
        self.secret_copy
            .as_ref()
            .is_some_and(|copy| matches!(copy.state(), SecretState::Pending | SecretState::Holding))
    }

    /// Schedules the earliest timer wakeup needed (clipboard 0.25s bar, 1s TOTP tick, or idle lock).
    pub fn schedule_wakeup(&self, tx: &mut Tx) {
        let mut due: Option<f64> = None;
        if self.has_active_secret_clipboard() {
            due = Some(tx.clock() + 0.25);
        }
        if self.controller.is_unlocked() {
            if let Some(idle_due) = self.controller.idle_lock_deadline() {
                due = Some(due.map_or(idle_due, |d| d.min(idle_due)));
            }
            let has_totp = self.controller.detail.as_ref().is_some_and(|detail| {
                detail
                    .otp_meta
                    .is_some_and(|m| m.kind == ServiceOtpKind::Totp)
            });
            if has_totp {
                let otp_due = tx.clock() + 1.0;
                due = Some(due.map_or(otp_due, |d| d.min(otp_due)));
            }
        }
        if let Some(next_due) = due {
            tx.wake_at(next_due);
        }
    }

    /// Polls background unlock/save completions, idle timeout, clipboard bar, and live TOTP.
    pub fn poll_frame(&mut self, secs: f64, tx: &mut Tx) -> bool {
        let prev_quarter = (self.clock_secs * 4.0).floor();
        self.clock_secs = secs;
        let next_quarter = (secs * 4.0).floor();
        let mut changed = false;

        if let Some((generation, outcome)) = self.unlock_worker.take() {
            self.controller.finish_unlock(generation, outcome, secs);
            self.wipe_transient_widgets();
            if self.controller.is_unlocked() {
                self.sync_path_bar_from_controller();
            }
            self.sync_custom_icons();
            tx.instant();
            changed = true;
        }

        if let Some(outcome) = self.save_worker.take() {
            let cleanup = self.controller.finish_save(outcome);
            self.apply_lock_cleanup(cleanup, tx);
            tx.instant();
            changed = true;
        }

        if self.has_active_secret_clipboard() {
            if self.secret_copy_deadline_secs.is_none() {
                self.secret_copy_deadline_secs = Some(secs + SECRET_CLIPBOARD_TTL.as_secs_f64());
            }
            if (next_quarter - prev_quarter).abs() >= 1.0 {
                changed = true;
            }
        } else if self.secret_copy_deadline_secs.is_some() {
            self.secret_copy_deadline_secs = None;
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
            if self.sync_custom_icons() {
                changed = true;
            }
            let now = current_unix_seconds();
            if now != self.last_totp_refresh {
                self.last_totp_refresh = now;
                if self.controller.detail.as_ref().is_some_and(|detail| {
                    detail
                        .otp_meta
                        .is_some_and(|m| m.kind == ServiceOtpKind::Totp)
                }) {
                    self.controller.refresh_selected_totp(now);
                    changed = true;
                }
            }
        }
        self.schedule_wakeup(tx);
        changed
    }
}

fn collect_tree_custom_icon_ids(node: &GroupTreeNode, ids: &mut Vec<CustomIconId>) {
    if let Some(id) = node.custom_icon_id {
        ids.push(id);
    }
    for child in &node.children {
        collect_tree_custom_icon_ids(child, ids);
    }
}

fn starting_directory_from_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parent = Path::new(trimmed).parent()?;
    (!parent.as_os_str().is_empty()).then(|| parent.to_path_buf())
}

fn handle_escape_key(state: &mut AppState, tx: &mut Tx) -> bool {
    if state.context_menu.is_some() {
        state.context_menu = None;
        return true;
    }
    if state.path_dropdown_open {
        state.cancel_path_dropdown();
        return true;
    }
    if state.settings_modal.is_some() {
        state.settings_modal = None;
        return true;
    }
    if state.move_entry_modal.is_some() {
        state.move_entry_modal = None;
        return true;
    }
    if state.rename_group_modal.is_some() {
        state.rename_group_modal = None;
        state.rename_group_edit.replace_text("");
        return true;
    }
    if state.icon_picker.is_some() {
        state.icon_picker = None;
        state.icon_search_edit.replace_text("");
        return true;
    }
    if state.attach_dialog_open {
        state.attach_dialog_open = false;
        state.attach_dialog_error = None;
        return true;
    }
    if state.extract_dialog.is_some() {
        state.extract_dialog = None;
        return true;
    }
    if state.pending_confirm.is_some() {
        state.pending_confirm = None;
        return true;
    }
    if state.controller.pending_lock_decision.is_some() && !state.controller.saving {
        state.controller.cancel_pending_lock();
        return true;
    }
    if state.controller.editor.is_some() && !state.controller.saving {
        state.note_activity(tx);
        state.cancel_entry_editor();
        return true;
    }
    false
}

fn handle_browser_shortcuts(state: &mut AppState, ev: &KeyEvent, tx: &mut Tx) -> bool {
    if state.controller.active_tab != WorkspaceTab::Browser {
        return false;
    }
    if ev.is_command('f') {
        state.note_activity(tx);
        tx.focus("entry-search-input", true);
        return true;
    }
    if ev.is_command('k') || ev.is_command('g') {
        state.note_activity(tx);
        tx.focus("path-bar-input", true);
        tx.select_all_text("path-bar-input/input");
        return true;
    }
    if ev.is_command('n') && !state.controller.saving {
        state.note_activity(tx);
        state.create_new_entry();
        return true;
    }
    if ev.is_command('d') && !state.controller.saving && state.controller.detail.is_some() {
        state.note_activity(tx);
        match state
            .controller
            .clone_selected_entry(current_unix_seconds())
        {
            Ok(_) => state.sync_path_bar_from_controller(),
            Err(err) => state.controller.set_browser_error(err),
        }
        return true;
    }
    if ev.mods.alt && !ev.mods.cmd && !ev.mods.ctrl && !state.controller.saving {
        if matches!(ev.key, Key::Up) && state.controller.can_reorder_entries() {
            state.note_activity(tx);
            if let Err(err) = state
                .controller
                .move_selected_entry_up(current_unix_seconds())
            {
                state.controller.set_browser_error(err);
            }
            return true;
        }
        if matches!(ev.key, Key::Down) && state.controller.can_reorder_entries() {
            state.note_activity(tx);
            if let Err(err) = state
                .controller
                .move_selected_entry_down(current_unix_seconds())
            {
                state.controller.set_browser_error(err);
            }
            return true;
        }
    }
    if matches!(ev.key, Key::Delete)
        && !state.controller.saving
        && !state.any_text_input_focused()
        && !tx
            .focused()
            .is_some_and(|k| k == "input" || k.ends_with("/input"))
        && let Some((in_bin, title)) = state
            .controller
            .detail
            .as_ref()
            .map(|d| (d.is_in_recycle_bin, d.metadata.title().to_owned()))
    {
        state.note_activity(tx);
        if in_bin || !state.controller.recycle_bin_enabled {
            state.pending_confirm = Some(ConfirmDialog::DeleteEntryPermanent { title });
        } else if let Err(err) = state
            .controller
            .delete_selected_entry(current_unix_seconds())
        {
            state.controller.set_browser_error(err);
        } else {
            state.wipe_editor_widgets();
            state.sync_path_bar_from_controller();
        }
        return true;
    }
    false
}

fn handle_root_key_preview(state: &mut AppState, ev: &KeyEvent, tx: &mut Tx) -> bool {
    if matches!(ev.key, Key::Escape) {
        return handle_escape_key(state, tx);
    }

    let has_modal = state.settings_modal.is_some()
        || state.move_entry_modal.is_some()
        || state.rename_group_modal.is_some()
        || state.icon_picker.is_some()
        || state.attach_dialog_open
        || state.extract_dialog.is_some()
        || state.pending_confirm.is_some()
        || state.controller.pending_lock_decision.is_some();

    if has_modal || !state.controller.is_unlocked() {
        return false;
    }
    if ev.is_command('s') && state.controller.dirty && !state.controller.saving {
        state.note_activity(tx);
        state.start_save(false);
        return true;
    }
    if ev.is_command('l') && !state.controller.saving {
        state.request_lock_or_modal(LockTrigger::Manual, tx);
        return true;
    }
    if ev.is_command(',') && !state.controller.saving {
        state.note_activity(tx);
        state.open_settings_modal();
        return true;
    }
    handle_browser_shortcuts(state, ev, tx)
}

/// Builds the top-level Rune element tree for `nkpui`.
pub fn view(state: &AppState, cx: &mut Cx<AppState>) -> El {
    cx.web_focus();
    let dark = cx.system_dark();
    let mut k = Kit::neutral(dark);
    if dark {
        k.c.bg_base = oklch(0.145, 0.006, 265.0);
        k.c.layer_01 = oklch(0.185, 0.007, 265.0);
        k.c.layer_03 = oklch(0.255, 0.008, 265.0);
        k.c.surface_raised = oklch(0.21, 0.008, 265.0);
        k.c.surface_raised_base = k.c.surface_raised;
    } else {
        k.c.bg_base = oklch(0.985, 0.002, 265.0);
        k.c.layer_01 = oklch(0.955, 0.004, 265.0);
        k.c.layer_03 = oklch(0.895, 0.004, 265.0);
        k.c.surface_raised = oklch(0.992, 0.002, 265.0);
        k.c.surface_raised_base = k.c.surface_raised;
        k.c.text_muted = oklch(0.38, 0.01, 265.0);
        k.c.text_faint = oklch(0.41, 0.01, 265.0);
        k.c.bg_accent = oklch(0.44, 0.17, 256.0);
        k.c.text_accent = oklch(0.42, 0.17, 256.0);
        k.c.icon_muted = k.c.text_muted;
        k.c.icon_accent = k.c.text_accent;
        k.c.warning.icon = oklch(0.45, 0.15, 80.0);
        k.c.success.icon = oklch(0.43, 0.15, 150.0);
        k.c.danger.icon = oklch(0.45, 0.16, 25.0);
        k.c.info.icon = oklch(0.42, 0.17, 256.0);
    }

    let mut overlays = Vec::new();
    let header = header_bar(&k, state);
    let body = match state.controller.phase {
        VaultPhase::Locked | VaultPhase::Unlocking => lock_view(&k, state),
        VaultPhase::Unlocked => match state.controller.active_tab {
            WorkspaceTab::Browser => browser_view(&k, state, &mut overlays),
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

    build_modals(&k, state, &mut overlays);
    if let Some(drag) = &state.drag_state {
        overlays.push(
            row()
                .key("entry-drag-preview")
                .absolute(drag.window_point[0] + 12.0, drag.window_point[1] + 12.0)
                .px(8.0)
                .py(4.0)
                .radius(k.radius.md)
                .fill(k.c.layer_03)
                .border(1.0, k.c.border_focus)
                .inert()
                .child(
                    text(format!("Move: {}", drag.entry_title))
                        .font(k.ty.small_medium)
                        .color(k.c.text_base),
                ),
        );
    }

    kit_root(base, overlays)
        .on_key_preview(handle_root_key_preview)
        .on_window_focus(|s: &mut AppState, focused: bool, tx: &mut Tx| {
            if !focused {
                s.handle_focus_lost(tx);
            }
        })
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

fn header_clipboard_status(
    k: &Kit,
    copy: &SecretCopy,
    deadline: Option<f64>,
    clock_secs: f64,
) -> El {
    let state_kind = copy.state();
    let mut clip_row = row()
        .key("clipboard-status")
        .instant_changes()
        .gap(4.0)
        .center_y();
    if let Some((frac, secs)) = clipboard_progress(&state_kind, deadline, clock_secs) {
        let bar_fill = if secs <= 5 {
            k.c.warning.icon
        } else {
            k.c.border_active
        };
        clip_row = clip_row
            .child(
                text(format!("Clip {secs}s"))
                    .key("clipboard-label")
                    .font(k.ty.text_xsmall)
                    .color(k.c.text_muted),
            )
            .child(
                row()
                    .key("clipboard-progress-track")
                    .w(36.0)
                    .h(6.0)
                    .radius(999.0)
                    .fill(k.c.surface_base)
                    .border(1.0, k.c.border_weak)
                    .clip_soft(0.0)
                    .child(
                        el().key("clipboard-progress-fill")
                            .h_full()
                            .radius(999.0)
                            .fill(bar_fill)
                            .w_frac(frac),
                    ),
            );
    } else {
        let label = match state_kind {
            SecretState::Pending => "Clip: pending",
            SecretState::Holding => "Clip: 30s",
            SecretState::Cleared => "Clip: cleared",
            SecretState::Replaced => "Clip: replaced",
            SecretState::Failed(_) => "Clip: wipe refused",
        };
        clip_row = clip_row.child(
            Badge::new(label)
                .variant(BadgeVariant::Neutral)
                .build(k)
                .key("clipboard-badge"),
        );
    }

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
                    s.secret_copy_deadline_secs = None;
                    tx.clear_secret_clipboard();
                })
                .build(k)
                .key("clipboard-clear-btn")
                .min_h(24.0),
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

    let browser_btn = Button::new("Browse")
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
        .key("nav-browser-btn")
        .help("Vault browser");

    let inject_btn = Button::new("Inject")
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
        .key("nav-inject-btn")
        .help("Inject / .env secrets");

    let settings_btn = Button::new("Settings")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Ghost)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.open_settings_modal();
        })
        .build(k)
        .key("nav-settings-btn");

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
        .child(settings_btn)
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
            Badge::new("Unsaved")
                .variant(BadgeVariant::Accent)
                .build(k)
                .key("header-unsaved-badge"),
        );
    }

    let mut right = row()
        .key("header-actions")
        .instant_changes()
        .gap(4.0)
        .center_y();
    if let Some(copy) = &state.secret_copy {
        right = right.child(header_clipboard_status(
            k,
            copy,
            state.secret_copy_deadline_secs,
            state.clock_secs,
        ));
    }
    if state.controller.is_unlocked() {
        right = header_unlocked_actions(k, state, right);
    }

    row()
        .key("header")
        .w_full()
        .h(48.0)
        .px(10.0)
        .gap(6.0)
        .justify_between()
        .center_y()
        .fill(k.c.layer_01)
        .child(title)
        .child(right)
}

fn path_completion_dropdown(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    if !state.path_dropdown_open || state.path_completions.is_empty() {
        return;
    }
    overlays.push(scrim("path-dropdown-scrim", |s: &mut AppState| {
        s.cancel_path_dropdown();
    }));

    let mut list = col()
        .key("path-completion-dropdown")
        .role("listbox")
        .label("Path completion suggestions")
        .w(420.0)
        .padding(4.0)
        .gap(2.0);

    for (idx, item) in state.path_completions.iter().take(5).enumerate() {
        let active = state.path_dropdown_index == Some(idx);
        let custom_img = state.custom_icon_for(item.custom_icon_id);
        let display_path = state.controller.format_display_path(&item.path);
        let kind_label = if item.is_group { "Group" } else { "Entry" };
        let item_clone = item.clone();
        list = list.child(
            row()
                .key(format!("path-completion-item-{idx}"))
                .role("option")
                .w_full()
                .min_h(28.0)
                .px(8.0)
                .py(4.0)
                .gap(8.0)
                .center_y()
                .radius(k.radius.sm)
                .fill(if active {
                    k.c.layer_03
                } else {
                    k.c.surface_raised
                })
                .hover(k.c.hover)
                .focusable(true)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.navigate_to_completion(&item_clone);
                })
                .child(render_keepass_icon(
                    k,
                    item.icon_id,
                    custom_img,
                    15.0,
                    format!("path-completion-icon-{idx}"),
                ))
                .child(
                    text(display_path)
                        .grow(1.0)
                        .min_w(0.0)
                        .truncate()
                        .font(k.ty.mono)
                        .color(k.c.text_base),
                )
                .child(
                    Badge::new(kind_label)
                        .variant(BadgeVariant::Neutral)
                        .build(k),
                ),
        );
    }

    let surface = popover::raised(k, list, k.radius.md);
    overlays.push(popover::anchored(
        k,
        surface,
        "path-bar-input",
        Placement::BottomStart,
        4.0,
    ));
}

fn path_nav_bar(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let path_input = TextInput::new(&state.path_edit)
        .label("Vault Path (Tab to complete)")
        .placeholder("/Work/Prod (Tab to complete)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.path_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            s.refresh_path_completions_live();
        })
        .on_key(|s: &mut AppState, ev: &KeyEvent, tx: &mut Tx| {
            if matches!(ev.key, Key::Tab) {
                s.note_activity(tx);
                s.trigger_path_tab_completion(ev.mods.shift);
                return true;
            }
            if s.path_dropdown_open && matches!(ev.key, Key::Down | Key::Up) {
                s.note_activity(tx);
                let len = s.path_completions.len();
                if len > 0 {
                    let next = match (s.path_dropdown_index, matches!(ev.key, Key::Up)) {
                        (Some(i), false) => (i + 1) % len,
                        (Some(0) | None, true) => len - 1,
                        (Some(i), true) => i - 1,
                        (None, false) => 0,
                    };
                    s.path_dropdown_index = Some(next);
                }
                return true;
            }
            if s.path_dropdown_open && matches!(ev.key, Key::Escape) {
                s.cancel_path_dropdown();
                return true;
            }
            false
        })
        .on_submit(|s: &mut AppState, tx| {
            s.note_activity(tx);
            s.submit_path_bar();
        })
        .build(k)
        .key("path-bar-input");

    path_completion_dropdown(k, state, overlays);

    row()
        .key("browser-path-bar")
        .w_full()
        .px(12.0)
        .py(6.0)
        .gap(8.0)
        .center_y()
        .fill(k.c.layer_01)
        .child(text("Path:").font(k.ty.small_medium).color(k.c.text_muted))
        .child(path_input.grow(1.0).min_w(0.0))
        .child(
            text("Tab complete · Ctrl+K focus")
                .font(k.ty.text_xsmall)
                .color(k.c.text_faint),
        )
}

fn browser_view(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let nav_bar = path_nav_bar(k, state, overlays);
    let sidebar = group_sidebar(k, state, overlays);
    let list = entry_list_pane(k, state, overlays);
    let detail = entry_detail_pane(k, state);

    let panes = row()
        .key("browser-panes")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .child(sidebar)
        .child(Divider::vertical().build(k).key("browser-divider-1"))
        .child(list)
        .child(Divider::vertical().build(k).key("browser-divider-2"))
        .child(detail.grow(1.0).min_w(0.0));

    col()
        .key("browser-view")
        .w_full()
        .h_full()
        .min_h(0.0)
        .child(nav_bar)
        .child(Divider::horizontal().build(k).key("path-bar-divider"))
        .child(panes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::LockMode;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn test_custom_icon_id(index: usize) -> Result<CustomIconId, String> {
        let mut bytes = [0_u8; 16];
        let raw = u32::try_from(index + 1)
            .map_err(|err| format!("index overflow: {err}"))?
            .to_be_bytes();
        bytes[..4].copy_from_slice(&raw);
        CustomIconId::from_bytes(bytes).ok_or_else(|| String::from("zero custom icon id"))
    }

    fn png_header_bytes(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = vec![
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
        ];
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    #[test]
    fn focus_loss_defaults_off_and_masks_reveals_without_locking() -> Result<(), String> {
        let temp_dir =
            std::env::temp_dir().join(format!("nkpui-ui-focus-default-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).map_err(|err| format!("mkdir failed: {err}"))?;
        let vault_path = temp_dir.join("focus.kdbx");
        let master = Zeroizing::new(String::from("FocusDefault!Pass99"));

        let mut state = AppState::default();
        assert!(!state.controller.lock_on_focus_loss);
        assert_eq!(state.controller.auto_lock_secs, Some(300.0));
        state.controller.lock_mode = LockMode::Create;
        state.controller.vault_path = vault_path.to_string_lossy().into_owned();

        let Some((path, key, gen_id)) = state.controller.begin_unlock(false) else {
            return Err(String::from("begin_unlock failed"));
        };
        let outcome = create_and_open_vault_blocking(&path, &master, key.as_deref());
        state.controller.finish_unlock(gen_id, outcome, 1.0);
        assert!(state.controller.is_unlocked());

        state
            .controller
            .create_entry_in_current_group(Some("Vault Entry"), 1_700_000_000)?;
        state.sync_editor_widgets_from_controller();
        state.edit_password.set_revealed(true);
        state.edit_otp_uri.set_revealed(true);
        if let Some(editor) = state.controller.editor.as_mut() {
            editor.password_revealed = true;
            editor.otp_revealed = true;
        }
        state.controller.toggle_reveal_password();
        state.controller.inject_output_revealed = true;

        assert!(state.focus_lost_lock_cleanup().is_none());
        assert!(state.controller.is_unlocked());
        assert!(state.controller.pending_lock_decision.is_none());
        assert!(!state.controller.inject_output_revealed);
        assert!(
            state
                .controller
                .detail
                .as_ref()
                .is_some_and(|detail| detail.revealed_password.is_none())
        );
        assert!(
            state
                .controller
                .editor
                .as_ref()
                .is_some_and(|editor| !editor.password_revealed && !editor.otp_revealed)
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn custom_icon_cache_caps_entries_and_per_frame_lookups() -> Result<(), String> {
        let temp_dir =
            std::env::temp_dir().join(format!("nkpui-ui-icon-caps-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).map_err(|err| format!("mkdir failed: {err}"))?;
        let vault_path = temp_dir.join("icons.kdbx");
        let master = Zeroizing::new(String::from("IconsCache!Pass99"));

        let mut state = AppState {
            images: Some(ImageCache::new(Arc::new(|| {}))),
            ..AppState::default()
        };
        state.controller.lock_mode = LockMode::Create;
        state.controller.vault_path = vault_path.to_string_lossy().into_owned();
        let Some((path, key, gen_id)) = state.controller.begin_unlock(false) else {
            return Err(String::from("begin_unlock failed"));
        };
        let outcome = create_and_open_vault_blocking(&path, &master, key.as_deref());
        state.controller.finish_unlock(gen_id, outcome, 1.0);
        assert!(state.controller.is_unlocked());

        let bad_id = test_custom_icon_id(999)?;
        let oversized = png_header_bytes(8192, 8192);
        assert!(!state.cache_custom_icon_bytes(bad_id, oversized));
        assert!(!state.custom_icons.contains_key(&bad_id));
        assert!(state.failed_custom_icons.contains(&bad_id));
        state.failed_custom_icons.clear();

        let valid_png = png_header_bytes(32, 32);
        for idx in 0..300 {
            let id = test_custom_icon_id(idx)?;
            assert!(state.cache_custom_icon_bytes(id, valid_png.clone()));
            state.record_failed_custom_icon(id);
        }
        assert_eq!(state.custom_icons.len(), MAX_CUSTOM_ICON_CACHE_ENTRIES);
        assert_eq!(
            state.failed_custom_icons.len(),
            MAX_CUSTOM_ICON_CACHE_ENTRIES
        );

        state.custom_icons.clear();
        state.failed_custom_icons.clear();
        state.controller.breadcrumb_icons.clear();
        for idx in 0..40 {
            let id = test_custom_icon_id(idx)?;
            state.controller.breadcrumb_icons.push((0, Some(id)));
        }
        let _ = state.sync_custom_icons();
        assert_eq!(
            state.failed_custom_icons.len(),
            MAX_CUSTOM_ICON_LOOKUPS_PER_FRAME
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn clipboard_progress_fraction_and_ceil_seconds() {
        assert_eq!(
            clipboard_progress(&SecretState::Cleared, Some(40.0), 10.0),
            None
        );
        assert_eq!(
            clipboard_progress(&SecretState::Replaced, Some(40.0), 10.0),
            None
        );
        assert_eq!(
            clipboard_progress(&SecretState::Holding, Some(40.0), 10.0),
            Some((1.0, 30))
        );
        assert_eq!(
            clipboard_progress(&SecretState::Holding, Some(40.0), 25.0),
            Some((0.5, 15))
        );
        assert_eq!(
            clipboard_progress(&SecretState::Pending, Some(40.0), 39.2),
            Some((0.8_f32 / 30.0, 1))
        );
        assert_eq!(
            clipboard_progress(&SecretState::Holding, Some(40.0), 45.0),
            Some((0.0, 0))
        );
    }

    #[test]
    fn path_bar_tab_completion_single_and_multi_dropdown_cycle() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("path-tab.kdbx");
        let master = Zeroizing::new(String::from("tab-pass"));

        let mut db = neotales_keepass::KeePassDatabase::default();
        let mut work = neotales_keepass::Group::new("Work");
        let mut prod = neotales_keepass::Group::new("Prod");
        prod.entries.push(neotales_keepass::Entry::new("ApiOne"));
        prod.entries.push(neotales_keepass::Entry::new("ApiTwo"));
        work.groups.push(prod);
        db.root.groups.push(work);

        let mut creds = neotales_keepass::KdbxCredentials::password(master.as_bytes())
            .map_err(|err| err.to_string())?;
        let mut file = std::fs::File::create(&path).map_err(|err| err.to_string())?;
        let opts = neotales_keepass::KdbxWriteOptions {
            kdf: neotales_keepass::KdbxKdf::Argon2id,
            argon2_memory_kib: 1024,
            argon2_time: 1,
            argon2_lanes: 1,
            ..neotales_keepass::KdbxWriteOptions::default()
        };
        neotales_keepass::KdbxFile::save(&db, &mut file, &mut creds, opts, &nkeepass::KDBX_LIMITS)
            .map_err(|err| err.to_string())?;

        let mut state = AppState::default();
        state.controller.vault_path = path.to_string_lossy().into_owned();
        let (vpath, kpath, gen_id) = state
            .controller
            .begin_unlock(false)
            .ok_or_else(|| String::from("begin_unlock failed"))?;
        let outcome = open_vault_blocking(&vpath, &master, kpath.as_deref());
        state.controller.finish_unlock(gen_id, outcome, 10.0);

        // Single match autocompletes immediately without opening dropdown.
        state.path_edit.replace_text("/Work/Prod/ApiO");
        state.trigger_path_tab_completion(false);
        assert!(!state.path_dropdown_open);
        assert_eq!(state.path_edit.text, "/Work/Prod/ApiOne");

        // Multi-match (2..=5) opens dropdown, Tab cycles forward/back, typing refreshes live.
        state.path_edit.replace_text("/Work/Prod/Api");
        state.trigger_path_tab_completion(false);
        assert!(state.path_dropdown_open);
        assert_eq!(state.path_completions.len(), 2);
        assert_eq!(state.path_dropdown_index, Some(0));

        state.trigger_path_tab_completion(false);
        assert_eq!(state.path_dropdown_index, Some(1));
        state.trigger_path_tab_completion(true);
        assert_eq!(state.path_dropdown_index, Some(0));

        state.path_edit.replace_text("/Work/Prod/ApiT");
        state.refresh_path_completions_live();
        assert_eq!(state.path_completions.len(), 1);
        state.submit_path_bar();
        assert!(!state.path_dropdown_open);
        assert_eq!(state.path_edit.text, "/Work/Prod/ApiTwo");
        assert_eq!(
            state.controller.detail.as_ref().map(|d| d.metadata.title()),
            Some("ApiTwo")
        );

        // Escape cancels dropdown and restores active path.
        state.path_dropdown_open = true;
        state.path_edit.replace_text("/garbage");
        state.cancel_path_dropdown();
        assert!(!state.path_dropdown_open);
        assert_eq!(state.path_edit.text, "/Work/Prod/ApiTwo");
        Ok(())
    }
}
