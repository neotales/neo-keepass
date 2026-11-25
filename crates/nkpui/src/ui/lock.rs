//! Lock and database creation screen views for `nkpui`.

use std::fmt;
use std::path::Path;

use rune::{El, FileDialogOptions, ScrollSpec, Tx, col, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, TextInput};

use crate::controller::{LockErrorField, LockMode, VaultPhase, ensure_kdbx_extension};

use super::{AppState, labeled_field, starting_directory_from_path};

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
            if s.controller.lock_mode != LockMode::Open {
                s.controller.lock_mode = LockMode::Open;
                s.controller.clear_lock_status();
                s.master_input.replace_text("");
                s.confirm_master_edit.replace_text("");
            }
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
            if s.controller.lock_mode != LockMode::Create {
                s.controller.lock_mode = LockMode::Create;
                s.controller.clear_lock_status();
                s.master_input.replace_text("");
                s.confirm_master_edit.replace_text("");
            }
        })
        .build(k)
        .key("lock-mode-create-btn");

    row()
        .key("lock-mode-switch")
        .gap(8.0)
        .child(open_mode_btn)
        .child(create_mode_btn)
}

fn handle_lock_vault_dialog_result(
    s: &mut AppState,
    res: Result<Option<std::path::PathBuf>, impl fmt::Display>,
    expected_mode: LockMode,
    ensure_ext: bool,
) {
    s.file_dialog_active = false;
    if s.controller.phase != VaultPhase::Locked || s.controller.lock_mode != expected_mode {
        return;
    }
    match res {
        Ok(Some(path)) => {
            let resolved = if ensure_ext {
                ensure_kdbx_extension(path)
            } else {
                path
            };
            let text = resolved.to_string_lossy().into_owned();
            s.vault_path_edit.replace_text(text.clone());
            s.controller.vault_path = text;
            s.controller.clear_lock_status();
        }
        Ok(None) => {}
        Err(err) => {
            s.controller.lock_status = Some(format!("File dialog unavailable: {err}"));
            s.controller.lock_error_field = LockErrorField::Info;
        }
    }
}

fn launch_lock_vault_file_dialog(s: &mut AppState, tx: &mut Tx, is_create: bool) {
    if s.file_dialog_active {
        return;
    }
    let directory = starting_directory_from_path(&s.vault_path_edit.text);
    let expected_mode = if is_create {
        LockMode::Create
    } else {
        LockMode::Open
    };
    s.file_dialog_active = true;
    if is_create {
        let opts = FileDialogOptions {
            title: String::from("Create KeePass Database"),
            directory,
            file_name: Some(String::from("vault.kdbx")),
            ..FileDialogOptions::default()
        }
        .filter("KeePass Database", &["kdbx"]);
        tx.save_file(opts, move |s: &mut AppState, res, _| {
            handle_lock_vault_dialog_result(s, res, expected_mode, true);
        });
    } else {
        let opts = FileDialogOptions {
            title: String::from("Open KeePass Database"),
            directory,
            ..FileDialogOptions::default()
        }
        .filter("KeePass Database", &["kdbx"]);
        tx.open_file(opts, move |s: &mut AppState, res, _| {
            handle_lock_vault_dialog_result(s, res, expected_mode, false);
        });
    }
}

fn lock_vault_path_row(
    k: &Kit,
    state: &AppState,
    is_create: bool,
    unlocking: bool,
    vault_invalid: bool,
) -> El {
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

    let browse_label = if is_create { "Save As…" } else { "Browse…" };
    let browse_btn = Button::new(browse_label)
        .control_size(ControlSize::Regular)
        .disabled(unlocking)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            launch_lock_vault_file_dialog(s, tx, is_create);
        })
        .build(k)
        .key("lock-vault-browse-btn");

    row()
        .w_full()
        .gap(6.0)
        .center_y()
        .child(vault_field.grow(1.0).min_w(0.0))
        .child(browse_btn)
}

fn lock_keyfile_path_row(k: &Kit, state: &AppState, unlocking: bool, key_invalid: bool) -> El {
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

    let browse_btn = Button::new("Browse…")
        .control_size(ControlSize::Regular)
        .disabled(unlocking)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            if s.file_dialog_active {
                return;
            }
            let opts = FileDialogOptions {
                title: String::from("Select Key File"),
                directory: starting_directory_from_path(&s.key_file_edit.text),
                ..FileDialogOptions::default()
            }
            .filter("Key Files", &["keyx", "key"]);
            s.file_dialog_active = true;
            tx.open_file(opts, |s: &mut AppState, res, _| {
                s.file_dialog_active = false;
                if s.controller.phase != VaultPhase::Locked {
                    return;
                }
                match res {
                    Ok(Some(path)) => {
                        let text = path.to_string_lossy().into_owned();
                        s.key_file_edit.replace_text(text.clone());
                        s.controller.key_file_path = text;
                        if s.controller.lock_error_field == LockErrorField::KeyFile {
                            s.controller.clear_lock_status();
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        s.controller.lock_status = Some(format!("File dialog unavailable: {err}"));
                        s.controller.lock_error_field = LockErrorField::Info;
                    }
                }
            });
        })
        .build(k)
        .key("lock-keyfile-browse-btn");

    row()
        .w_full()
        .gap(6.0)
        .center_y()
        .child(key_field.grow(1.0).min_w(0.0))
        .child(browse_btn)
}

fn lock_vault_chips(k: &Kit, state: &AppState, unlocking: bool) -> Option<El> {
    if state.controller.configured_vaults.is_empty() && state.controller.recent_vaults.is_empty() {
        return None;
    }
    let mut chips = row()
        .key("lock-quick-vault-chips")
        .w_full()
        .flex_wrap()
        .gap(6.0);
    let current = state.vault_path_edit.text.trim();
    for (idx, item) in state.controller.configured_vaults.iter().enumerate() {
        let selected = current == item.path;
        let path_val = item.path.clone();
        chips = chips.child(
            Button::new(item.label.clone())
                .control_size(ControlSize::Regular)
                .variant(if selected {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .disabled(unlocking)
                .on_press(move |s: &mut AppState| {
                    s.vault_path_edit.replace_text(path_val.clone());
                    s.controller.vault_path.clone_from(&path_val);
                    s.controller.clear_lock_status();
                })
                .build(k)
                .key(format!("lock-configured-vault-{idx}"))
                .help(item.path.clone()),
        );
    }
    for (idx, path) in state.controller.recent_vaults.iter().enumerate() {
        if state
            .controller
            .configured_vaults
            .iter()
            .any(|cfg| &cfg.path == path)
        {
            continue;
        }
        let selected = current == path;
        let short = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path.as_str())
            .to_owned();
        let path_val = path.clone();
        chips = chips.child(
            Button::new(format!("Recent: {short}"))
                .control_size(ControlSize::Regular)
                .variant(if selected {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Ghost
                })
                .disabled(unlocking)
                .on_press(move |s: &mut AppState| {
                    s.vault_path_edit.replace_text(path_val.clone());
                    s.controller.vault_path.clone_from(&path_val);
                    s.controller.clear_lock_status();
                })
                .build(k)
                .key(format!("lock-recent-vault-{idx}"))
                .help(path.clone()),
        );
    }
    Some(
        col()
            .key("lock-quick-vaults")
            .w_full()
            .gap(4.0)
            .child(
                text("Quick Vaults")
                    .font(k.ty.text_xsmall)
                    .color(k.c.text_muted),
            )
            .child(chips),
    )
}

fn lock_form_inputs(
    k: &Kit,
    state: &AppState,
    is_create: bool,
    unlocking: bool,
    invalid: (bool, bool, bool),
) -> El {
    let (vault_invalid, master_invalid, key_invalid) = invalid;

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

    let mut fields = col().w_full().gap(12.0);
    if !is_create && let Some(chips) = lock_vault_chips(k, state, unlocking) {
        fields = fields.child(chips);
    }
    fields = fields
        .child(labeled_field(
            k,
            "lock-vault-field",
            "Vault (.kdbx)",
            lock_vault_path_row(k, state, is_create, unlocking, vault_invalid),
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
        lock_keyfile_path_row(k, state, unlocking, key_invalid),
    ))
}

pub(super) fn lock_view(k: &Kit, state: &AppState) -> El {
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
            text(if is_create {
                "New vaults default to Argon2id + GZip + AES-256. KDF runs on a background worker thread."
            } else {
                "KDF runs on a background worker thread; focus loss masks reveals immediately. Auto-lock & focus-loss options live in Settings."
            })
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
        .items_center()
        .padding(16.0)
        .scroll(ScrollSpec::default())
        .child(card)
}
