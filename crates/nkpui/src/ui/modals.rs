//! Modal dialogs for lock confirmation, destructive confirmations, attachments,
//! icon picker (embedded custom + 69 standard), rename group, move-to-group, and settings.

use std::path::PathBuf;

use nkeepass::{
    CustomIconId, CustomIconSummary, DatabaseSettingsUpdate, GroupTreeNode, VaultCipher,
    VaultCompression, VaultKdfSummary,
};
use rune::{El, FileDialogOptions, ScrollSpec, Tx, col, row, text};
use rune_kit::{
    Button, ButtonVariant, Checkbox, ControlSize, Dialog, Kit, SegmentedControl, TextInput,
};

use crate::controller::{
    AUTO_LOCK_PRESETS, LockTrigger, current_unix_seconds, format_byte_size,
    sanitize_attachment_prefill,
};
use crate::icons::render_keepass_icon;
use nkeepass::icons::standard_icons;

use super::{
    AppState, ConfirmDialog, IconPickerTarget, KdfChoice, SettingsModalState, error_status_text,
    labeled_field, starting_directory_from_path,
};

pub(super) fn build_modals(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    build_unsaved_lock_modal(k, state, overlays);
    build_confirm_modal(k, state, overlays);
    build_attach_modal(k, state, overlays);
    build_extract_modal(k, state, overlays);
    build_icon_picker_modal(k, state, overlays);
    build_rename_group_modal(k, state, overlays);
    build_move_entry_modal(k, state, overlays);
    build_settings_modal(k, state, overlays);
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
        ConfirmDialog::DeleteGroup { label, .. } => (
            "Delete Group?",
            format!(
                "Delete group \"{label}\" and all entries or subgroups inside it? This marks the vault unsaved."
            ),
            "Delete Group",
        ),
        ConfirmDialog::DeleteEntryPermanent { title } => (
            "Delete Entry Permanently?",
            format!("Permanently delete entry \"{title}\"? This cannot be undone once saved."),
            "Delete Permanently",
        ),
        ConfirmDialog::EmptyRecycleBin => (
            "Empty Recycle Bin?",
            String::from(
                "Permanently delete all entries and subgroups inside the Recycle Bin? This marks the vault unsaved.",
            ),
            "Empty Recycle Bin",
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
                ConfirmDialog::DeleteGroup { group_ref, .. } => {
                    let r = s.controller.remove_group(group_ref);
                    if r.is_ok() {
                        s.wipe_editor_widgets();
                        s.sync_path_bar_from_controller();
                    }
                    r
                }
                ConfirmDialog::DeleteEntryPermanent { .. } => {
                    let r = s.controller.delete_selected_entry(current_unix_seconds());
                    if r.is_ok() {
                        s.wipe_editor_widgets();
                        s.sync_path_bar_from_controller();
                    }
                    r
                }
                ConfirmDialog::EmptyRecycleBin => {
                    let r = s
                        .controller
                        .empty_recycle_bin(current_unix_seconds())
                        .map(|_| ());
                    if r.is_ok() {
                        s.wipe_editor_widgets();
                        s.sync_path_bar_from_controller();
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

fn attach_source_row(k: &Kit, state: &AppState) -> El {
    let path_field = TextInput::new(&state.attach_path_edit)
        .label("Source file path (<= 16 MiB)")
        .placeholder("/path/to/file.pem")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.attach_path_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("attach-source-path-input");

    let browse_btn = Button::new("Browse…")
        .control_size(ControlSize::Regular)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if s.file_dialog_active {
                return;
            }
            let opts = FileDialogOptions {
                title: String::from("Attach File"),
                directory: starting_directory_from_path(&s.attach_path_edit.text),
                ..FileDialogOptions::default()
            };
            s.file_dialog_active = true;
            tx.open_file(opts, |s: &mut AppState, res, _| {
                s.file_dialog_active = false;
                if !s.controller.is_unlocked() || !s.attach_dialog_open {
                    return;
                }
                match res {
                    Ok(Some(path)) => {
                        let path_text = path.to_string_lossy().into_owned();
                        s.attach_path_edit.replace_text(path_text);
                        if s.attach_name_edit.text.trim().is_empty()
                            && let Some(name) = path.file_name().and_then(|n| n.to_str())
                        {
                            s.attach_name_edit
                                .replace_text(sanitize_attachment_prefill(name));
                        }
                        s.attach_dialog_error = None;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        s.attach_dialog_error = Some(format!("File dialog unavailable: {err}"));
                    }
                }
            });
        })
        .build(k)
        .key("attach-browse-btn");

    row()
        .w_full()
        .gap(6.0)
        .center_y()
        .child(path_field.grow(1.0).min_w(0.0))
        .child(browse_btn)
}

fn build_attach_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    if !state.attach_dialog_open {
        return;
    }

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
            attach_source_row(k, state),
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
        .width(480.0)
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

fn extract_dest_row(k: &Kit, state: &AppState, default_name: String) -> El {
    let dest_field = TextInput::new(&state.extract_path_edit)
        .label("Destination file path (no-clobber)")
        .placeholder("/path/to/output.bin")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.extract_path_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("extract-dest-path-input");

    let save_as_btn = Button::new("Save As…")
        .control_size(ControlSize::Regular)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if s.file_dialog_active {
                return;
            }
            let opts = FileDialogOptions {
                title: String::from("Save Attachment"),
                file_name: Some(default_name.clone()),
                directory: starting_directory_from_path(&s.extract_path_edit.text),
                ..FileDialogOptions::default()
            };
            s.file_dialog_active = true;
            tx.save_file(opts, |s: &mut AppState, res, _| {
                s.file_dialog_active = false;
                if !s.controller.is_unlocked() || s.extract_dialog.is_none() {
                    return;
                }
                match res {
                    Ok(Some(path)) => {
                        s.extract_path_edit
                            .replace_text(path.to_string_lossy().into_owned());
                        if let Some(dlg) = s.extract_dialog.as_mut() {
                            dlg.error = None;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if let Some(dlg) = s.extract_dialog.as_mut() {
                            dlg.error = Some(format!("File dialog unavailable: {err}"));
                        }
                    }
                }
            });
        })
        .build(k)
        .key("extract-browse-btn");

    row()
        .w_full()
        .gap(6.0)
        .center_y()
        .child(dest_field.grow(1.0).min_w(0.0))
        .child(save_as_btn)
}

fn build_extract_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(dialog) = &state.extract_dialog else {
        return;
    };

    let mut content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(labeled_field(
            k,
            "extract-dest-field",
            "Destination Path (owner-only, no-clobber)",
            extract_dest_row(k, state, dialog.name.clone()),
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
        .width(480.0)
        .description(format!(
            "Write \"{}\" ({}) with owner-only permissions without overwriting existing files.",
            dialog.name,
            format_byte_size(dialog.size)
        ))
        .on_close(|s: &mut AppState| s.extract_dialog = None)
        .child(content)
        .build(k, overlays);
}

fn apply_picked_standard_icon(state: &mut AppState, target: &IconPickerTarget, icon_id: u32) {
    let unix_now = current_unix_seconds();
    let res = match target {
        IconPickerTarget::EntryEditor => {
            state.controller.set_editor_icon(icon_id);
            Ok(())
        }
        IconPickerTarget::CurrentGroup => state.controller.set_current_group_icon(icon_id),
        IconPickerTarget::Group(group_ref) => {
            state.controller.set_group_icon_by_ref(group_ref, icon_id)
        }
        IconPickerTarget::Entry(entry_ref) => state
            .controller
            .set_entry_icon_by_ref(entry_ref, icon_id, unix_now),
    };
    if let Err(err) = res {
        state.controller.set_browser_error(err);
    }
    state.icon_picker = None;
    state.icon_search_edit.replace_text("");
}

fn apply_picked_custom_icon(state: &mut AppState, target: &IconPickerTarget, id: CustomIconId) {
    let unix_now = current_unix_seconds();
    let res = match target {
        IconPickerTarget::EntryEditor => {
            state.controller.set_editor_custom_icon(id);
            Ok(())
        }
        IconPickerTarget::CurrentGroup => {
            if let Some(cur) = state.controller.current_group_ref().cloned() {
                state.controller.set_group_custom_icon_by_ref(&cur, id)
            } else {
                Err(String::from("vault is locked"))
            }
        }
        IconPickerTarget::Group(group_ref) => {
            state.controller.set_group_custom_icon_by_ref(group_ref, id)
        }
        IconPickerTarget::Entry(entry_ref) => state
            .controller
            .set_entry_custom_icon_by_ref(entry_ref, id, unix_now),
    };
    if let Err(err) = res {
        state.controller.set_browser_error(err);
    }
    state.icon_picker = None;
    state.icon_search_edit.replace_text("");
}

fn icon_picker_tile(
    k: &Kit,
    icon_id: u32,
    icon_name: &'static str,
    selected: bool,
    target: IconPickerTarget,
) -> El {
    let mut tile = col()
        .key(format!("icon-tile-{icon_id}"))
        .w(76.0)
        .h(56.0)
        .padding(4.0)
        .gap(2.0)
        .center()
        .radius(k.radius.md)
        .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
        .border(
            if selected { 1.5 } else { 1.0 },
            if selected {
                k.c.border_focus
            } else {
                k.c.border_muted
            },
        )
        .focusable(true)
        .checked(selected)
        .press_on_return()
        .hover(k.c.hover)
        .press(k.c.pressed)
        .label(if selected {
            format!("Icon {icon_id}: {icon_name}, selected")
        } else {
            format!("Icon {icon_id}: {icon_name}")
        })
        .help(format!("{icon_id}: {icon_name}"))
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            apply_picked_standard_icon(s, &target, icon_id);
        })
        .child(render_keepass_icon(
            k,
            icon_id,
            None,
            20.0,
            format!("icon-tile-svg-{icon_id}"),
        ))
        .child(
            text(format!("{icon_id}"))
                .font(k.ty.text_xsmall)
                .color(k.c.text_muted),
        );
    if selected {
        tile = tile.focus_selected(true);
    }
    tile
}

fn custom_icon_picker_tile(
    k: &Kit,
    state: &AppState,
    idx: usize,
    summary: &CustomIconSummary,
    selected: bool,
    target: IconPickerTarget,
) -> El {
    let id = summary.id;
    let display_name = if summary.name.is_empty() {
        format!("Custom {}", idx + 1)
    } else {
        summary.name.clone()
    };
    let custom_img = state.custom_icon_for(Some(id));
    let mut tile = col()
        .key(format!("custom-icon-tile-{idx}"))
        .w(88.0)
        .h(58.0)
        .padding(4.0)
        .gap(2.0)
        .center()
        .radius(k.radius.md)
        .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
        .border(
            1.0,
            if selected {
                k.c.border_focus
            } else {
                k.c.border_muted
            },
        )
        .focusable(true)
        .checked(selected)
        .press_on_return()
        .hover(k.c.hover)
        .press(k.c.pressed)
        .label(if selected {
            format!("Custom icon: {display_name}, selected")
        } else {
            format!("Custom icon: {display_name}")
        })
        .help(display_name.clone())
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            apply_picked_custom_icon(s, &target, id);
        })
        .child(render_keepass_icon(
            k,
            0,
            custom_img,
            22.0,
            format!("custom-icon-tile-img-{idx}"),
        ))
        .child(
            text(display_name)
                .w_full()
                .truncate()
                .font(k.ty.text_xsmall)
                .color(k.c.text_muted),
        );
    if selected {
        tile = tile.focus_selected(true);
    }
    tile
}

fn icon_picker_scroll_body(
    k: &Kit,
    state: &AppState,
    picker: &super::IconPickerState,
    needle: &str,
) -> El {
    let custom_list = state.controller.list_custom_icons().unwrap_or_default();
    let mut custom_grid = row()
        .key("icon-picker-custom-grid")
        .w_full()
        .flex_wrap()
        .gap(6.0);
    let mut custom_matches = 0usize;
    for (idx, summary) in custom_list.iter().enumerate() {
        let label = if summary.name.is_empty() {
            format!("custom {}", idx + 1)
        } else {
            summary.name.to_ascii_lowercase()
        };
        if !needle.is_empty() && !label.contains(needle) {
            continue;
        }
        custom_matches += 1;
        custom_grid = custom_grid.child(custom_icon_picker_tile(
            k,
            state,
            idx,
            summary,
            picker.selected_custom_id == Some(summary.id),
            picker.target.clone(),
        ));
    }

    let mut grid = row()
        .key("icon-picker-grid")
        .w_full()
        .flex_wrap()
        .gap(6.0)
        .focus_group();
    let mut matches = 0usize;
    for meta in standard_icons() {
        let id_str = meta.id.to_string();
        if !needle.is_empty()
            && !meta.name.to_ascii_lowercase().contains(needle)
            && !id_str.contains(needle)
        {
            continue;
        }
        matches += 1;
        grid = grid.child(icon_picker_tile(
            k,
            meta.id,
            meta.name,
            picker.selected_custom_id.is_none() && meta.id == picker.selected_id,
            picker.target.clone(),
        ));
    }

    let mut body_col = col().w_full().gap(10.0);
    if custom_matches > 0 {
        body_col = body_col
            .child(
                text(format!("Embedded Custom Icons ({custom_matches})"))
                    .key("icon-picker-custom-heading")
                    .font(k.ty.small_medium)
                    .color(k.c.text_muted),
            )
            .child(custom_grid);
    }
    body_col = body_col.child(
        text(format!("Standard KeePass Icons ({matches})"))
            .key("icon-picker-std-heading")
            .font(k.ty.small_medium)
            .color(k.c.text_muted),
    );
    if matches == 0 && custom_matches == 0 {
        body_col = body_col.child(
            text("No matching KeePass icons")
                .key("icon-picker-empty")
                .padding(12.0)
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        );
    } else if matches > 0 {
        body_col = body_col.child(grid);
    }

    col()
        .key("icon-picker-scroll")
        .w_full()
        .h(320.0)
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.bg_base)
        .border(1.0, k.c.border_muted)
        .scroll(ScrollSpec::default())
        .child(body_col)
}

fn build_icon_picker_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(picker) = state.icon_picker.clone() else {
        return;
    };
    let search_input = TextInput::new(&state.icon_search_edit)
        .label("Filter icons by name or number")
        .placeholder("Filter (e.g. key, folder, 19)…")
        .leading_icon(&crate::icons::SEARCH_ICON)
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.icon_search_edit)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("icon-picker-search-input");

    let needle = state.icon_search_edit.text.trim().to_ascii_lowercase();
    let scroll_area = icon_picker_scroll_body(k, state, &picker, &needle);

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.icon_picker = None;
            s.icon_search_edit.replace_text("");
        })
        .build(k)
        .key("icon-picker-cancel-btn");

    let content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(search_input)
        .child(scroll_area)
        .child(row().w_full().justify_end().child(cancel_btn));

    let title = match picker.target {
        IconPickerTarget::EntryEditor | IconPickerTarget::Entry(_) => "Choose Entry Icon",
        IconPickerTarget::CurrentGroup | IconPickerTarget::Group(_) => "Choose Group Icon",
    };

    Dialog::new("icon-picker", title)
        .open(true)
        .fit()
        .width(560.0)
        .description("Select an embedded custom KDBX icon or one of the 69 standard KeePass icons.")
        .on_close(|s: &mut AppState| {
            s.icon_picker = None;
            s.icon_search_edit.replace_text("");
        })
        .child(content)
        .build(k, overlays);
}

fn build_rename_group_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(modal) = &state.rename_group_modal else {
        return;
    };
    let group_ref = modal.group_ref.clone();
    let input = TextInput::new(&state.rename_group_edit)
        .label("New group name")
        .placeholder("Group name")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.rename_group_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            if let Some(m) = s.rename_group_modal.as_mut() {
                m.error = None;
            }
        })
        .on_submit({
            let group_ref = group_ref.clone();
            move |s: &mut AppState, tx| {
                s.note_activity(tx);
                let next_name = s.rename_group_edit.text.clone();
                match s.controller.rename_group(&group_ref, &next_name) {
                    Ok(()) => {
                        s.rename_group_modal = None;
                        s.rename_group_edit.replace_text("");
                        s.wipe_editor_widgets();
                        s.clear_transient_overlays();
                        s.sync_path_bar_from_controller();
                    }
                    Err(err) => {
                        if let Some(m) = s.rename_group_modal.as_mut() {
                            m.error = Some(err);
                        }
                    }
                }
            }
        })
        .build(k)
        .key("rename-group-input");

    let mut content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(labeled_field(k, "rename-group-field", "Group Name", input));
    if let Some(err) = &modal.error {
        content = content.child(error_status_text(k, "rename-group-error", err));
    }

    let apply_btn = Button::new("Rename")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let next_name = s.rename_group_edit.text.clone();
            match s.controller.rename_group(&group_ref, &next_name) {
                Ok(()) => {
                    s.rename_group_modal = None;
                    s.rename_group_edit.replace_text("");
                    s.wipe_editor_widgets();
                    s.clear_transient_overlays();
                    s.sync_path_bar_from_controller();
                }
                Err(err) => {
                    if let Some(m) = s.rename_group_modal.as_mut() {
                        m.error = Some(err);
                    }
                }
            }
        })
        .build(k)
        .key("rename-group-submit-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.rename_group_modal = None;
            s.rename_group_edit.replace_text("");
        })
        .build(k)
        .key("rename-group-cancel-btn");

    content = content.child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(apply_btn),
    );

    Dialog::new("rename-group", "Rename Group")
        .open(true)
        .fit()
        .width(420.0)
        .on_close(|s: &mut AppState| {
            s.rename_group_modal = None;
            s.rename_group_edit.replace_text("");
        })
        .child(content)
        .build(k, overlays);
}

#[allow(clippy::cast_precision_loss, reason = "group depth is bounded <= 32")]
fn collect_all_move_rows<'a>(
    node: &'a GroupTreeNode,
    depth: usize,
    out: &mut Vec<(usize, &'a GroupTreeNode)>,
) {
    out.push((depth, node));
    for child in &node.children {
        collect_all_move_rows(child, depth + 1, out);
    }
}

#[allow(clippy::cast_precision_loss, reason = "group depth is bounded <= 32")]
fn move_entry_group_list(
    k: &Kit,
    state: &AppState,
    modal: &super::MoveEntryModalState,
    tree: &GroupTreeNode,
) -> El {
    let mut rows_data = Vec::new();
    collect_all_move_rows(tree, 0, &mut rows_data);

    let mut list = col().key("move-entry-group-list").w_full().gap(4.0);
    for (idx, (depth, node)) in rows_data.iter().enumerate() {
        let selected = modal.selected_group_path.as_deref() == Some(node.path.as_str());
        let label = if *depth == 0 {
            String::from("Root")
        } else {
            node.label.clone()
        };
        let path_val = node.path.clone();
        let target_ref = node.reference.clone();
        let custom_img = state.custom_icon_for(node.custom_icon_id);
        let indent = (*depth as f32) * 14.0;

        list = list.child(
            row()
                .key(format!("move-target-row-{idx}"))
                .w_full()
                .min_h(28.0)
                .pl(8.0 + indent)
                .pr(8.0)
                .py(4.0)
                .gap(6.0)
                .center_y()
                .radius(k.radius.md)
                .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
                .border(
                    1.0,
                    if selected {
                        k.c.border_focus
                    } else {
                        k.c.border_muted
                    },
                )
                .focusable(true)
                .press_on_return()
                .hover(k.c.hover)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    if let Some(m) = s.move_entry_modal.as_mut() {
                        m.selected_group_path = Some(path_val.clone());
                        m.selected_group_ref = Some(target_ref.clone());
                        m.selected_group_label = Some(label.clone());
                        m.error = None;
                    }
                })
                .child(render_keepass_icon(
                    k,
                    node.icon_id,
                    custom_img,
                    15.0,
                    format!("move-target-icon-{idx}"),
                ))
                .child(
                    text(if *depth == 0 {
                        String::from("Root")
                    } else {
                        node.label.clone()
                    })
                    .grow(1.0)
                    .min_w(0.0)
                    .truncate()
                    .font(k.ty.ui_compact)
                    .color(k.c.text_base),
                )
                .child(
                    text(format!("{}", node.entry_count))
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_faint),
                ),
        );
    }

    col()
        .w_full()
        .h(260.0)
        .padding(6.0)
        .radius(k.radius.md)
        .fill(k.c.bg_base)
        .border(1.0, k.c.border_muted)
        .scroll(ScrollSpec::default())
        .child(list)
}

fn build_move_entry_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(modal) = &state.move_entry_modal else {
        return;
    };
    let Some(tree) = &state.controller.group_tree else {
        return;
    };

    let scroll = move_entry_group_list(k, state, modal, tree);
    let mut content = col().w_full().px(16.0).pb(16.0).gap(10.0).child(scroll);
    if let Some(err) = &modal.error {
        content = content.child(error_status_text(k, "move-entry-error", err));
    }

    let can_move = modal.selected_group_ref.is_some();
    let move_btn = Button::new("Move Here")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .disabled(!can_move)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let Some(m) = s.move_entry_modal.clone() else {
                return;
            };
            let (Some(target_ref), Some(target_label)) =
                (m.selected_group_ref, m.selected_group_label)
            else {
                return;
            };
            match s.controller.move_entry_to_group(
                &m.entry_ref,
                &target_ref,
                &target_label,
                current_unix_seconds(),
            ) {
                Ok(()) => {
                    s.move_entry_modal = None;
                    s.wipe_editor_widgets();
                    s.sync_path_bar_from_controller();
                }
                Err(err) => {
                    if let Some(active) = s.move_entry_modal.as_mut() {
                        active.error = Some(err);
                    }
                }
            }
        })
        .build(k)
        .key("move-entry-submit-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.move_entry_modal = None;
        })
        .build(k)
        .key("move-entry-cancel-btn");

    content = content.child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(move_btn),
    );

    Dialog::new("move-entry", format!("Move \"{}\"", modal.entry_title))
        .open(true)
        .fit()
        .width(460.0)
        .description("Select the destination group for this entry.")
        .on_close(|s: &mut AppState| s.move_entry_modal = None)
        .child(content)
        .build(k, overlays);
}

fn settings_kdf_params(k: &Kit, state: &AppState, kdf_choice: KdfChoice) -> El {
    let mut kdf_params = row().w_full().gap(8.0);
    if matches!(kdf_choice, KdfChoice::Argon2id | KdfChoice::Argon2d) {
        let mem_in = TextInput::new(&state.settings_kdf_memory_mib)
            .label("Memory (MiB)")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.settings_kdf_memory_mib)
            .on_change(|s: &mut AppState, tx| s.note_activity(tx))
            .build(k)
            .key("settings-kdf-memory-input");
        let iter_in = TextInput::new(&state.settings_kdf_iterations)
            .label("Iterations")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.settings_kdf_iterations)
            .on_change(|s: &mut AppState, tx| s.note_activity(tx))
            .build(k)
            .key("settings-kdf-iter-input");
        let lanes_in = TextInput::new(&state.settings_kdf_lanes)
            .label("Lanes")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.settings_kdf_lanes)
            .on_change(|s: &mut AppState, tx| s.note_activity(tx))
            .build(k)
            .key("settings-kdf-lanes-input");
        kdf_params = kdf_params
            .child(
                labeled_field(k, "settings-kdf-mem-f", "Memory (MiB)", mem_in)
                    .grow(1.0)
                    .min_w(0.0),
            )
            .child(
                labeled_field(k, "settings-kdf-iter-f", "Iterations", iter_in)
                    .grow(1.0)
                    .min_w(0.0),
            )
            .child(
                labeled_field(k, "settings-kdf-lanes-f", "Lanes", lanes_in)
                    .grow(1.0)
                    .min_w(0.0),
            );
    } else {
        let rounds_in = TextInput::new(&state.settings_kdf_rounds)
            .label("AES-KDF Rounds")
            .width(None)
            .on_edit(|s: &mut AppState| &mut s.settings_kdf_rounds)
            .on_change(|s: &mut AppState, tx| s.note_activity(tx))
            .build(k)
            .key("settings-kdf-rounds-input");
        kdf_params = kdf_params.child(
            labeled_field(k, "settings-kdf-rounds-f", "AES-KDF Rounds", rounds_in)
                .grow(1.0)
                .min_w(0.0),
        );
    }
    kdf_params
}

fn settings_crypto_section(k: &Kit, state: &AppState, modal: &SettingsModalState) -> El {
    let cipher_idx = match modal.outer_cipher {
        VaultCipher::Aes => 0,
        VaultCipher::ChaCha20 => 1,
    };
    let cipher_sel = SegmentedControl::new(&["AES-256", "ChaCha20"], Some(cipher_idx))
        .label("Outer Cipher")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(m) = s.settings_modal.as_mut() {
                m.outer_cipher = if idx == 1 {
                    VaultCipher::ChaCha20
                } else {
                    VaultCipher::Aes
                };
            }
        })
        .build(k)
        .key("settings-cipher-sel");

    let comp_idx = match modal.compression {
        VaultCompression::GZip => 0,
        VaultCompression::None => 1,
    };
    let comp_sel = SegmentedControl::new(&["GZip", "None"], Some(comp_idx))
        .label("Compression")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(m) = s.settings_modal.as_mut() {
                m.compression = if idx == 1 {
                    VaultCompression::None
                } else {
                    VaultCompression::GZip
                };
            }
        })
        .build(k)
        .key("settings-compression-sel");

    let kdf_idx = match modal.kdf_choice {
        KdfChoice::Argon2id => 0,
        KdfChoice::Argon2d => 1,
        KdfChoice::Aes => 2,
    };
    let kdf_sel = SegmentedControl::new(&["Argon2id", "Argon2d", "AES-KDF"], Some(kdf_idx))
        .label("KDF")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(m) = s.settings_modal.as_mut() {
                m.kdf_choice = match idx {
                    1 => KdfChoice::Argon2d,
                    2 => KdfChoice::Aes,
                    _ => KdfChoice::Argon2id,
                };
            }
        })
        .build(k)
        .key("settings-kdf-sel");

    col()
        .w_full()
        .gap(8.0)
        .child(
            row()
                .w_full()
                .flex_wrap()
                .gap(8.0)
                .child(labeled_field(k, "settings-cipher-f", "Cipher", cipher_sel))
                .child(labeled_field(k, "settings-comp-f", "Compression", comp_sel)),
        )
        .child(labeled_field(
            k,
            "settings-kdf-f",
            "Key Derivation (KDF)",
            kdf_sel,
        ))
        .child(settings_kdf_params(k, state, modal.kdf_choice))
}

fn settings_desktop_security_section(k: &Kit, modal: &SettingsModalState) -> El {
    let mut presets_row = row()
        .key("settings-autolock-presets")
        .w_full()
        .flex_wrap()
        .gap(6.0);
    for (idx, (val, label)) in AUTO_LOCK_PRESETS.iter().enumerate() {
        let active = modal.auto_lock_secs == *val;
        let preset_val = *val;
        presets_row = presets_row.child(
            Button::new(*label)
                .control_size(ControlSize::Regular)
                .variant(if active {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    if let Some(m) = s.settings_modal.as_mut() {
                        m.auto_lock_secs = preset_val;
                    }
                })
                .build(k)
                .key(format!("settings-autolock-{idx}")),
        );
    }

    let focus_cb = Checkbox::new(modal.lock_on_focus_loss)
        .label("Lock automatically on window focus loss")
        .on_toggle_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(m) = s.settings_modal.as_mut() {
                m.lock_on_focus_loss = !m.lock_on_focus_loss;
            }
        })
        .build(k)
        .key("settings-focus-lock-cb");

    col()
        .key("settings-security-section")
        .w_full()
        .padding(10.0)
        .gap(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_muted)
        .child(
            text("Desktop Security")
                .font(k.ty.small_medium)
                .color(k.c.text_base),
        )
        .child(labeled_field(
            k,
            "settings-autolock-f",
            "Auto-Lock Idle Timer",
            presets_row,
        ))
        .child(focus_cb)
}

fn parse_settings_kdf(s: &mut AppState, kdf_choice: KdfChoice) -> Result<VaultKdfSummary, String> {
    match kdf_choice {
        KdfChoice::Aes => {
            let rounds = s
                .settings_kdf_rounds
                .text
                .trim()
                .parse::<u64>()
                .map_err(|_| String::from("AES-KDF rounds must be a positive integer"))?;
            Ok(VaultKdfSummary::Aes { rounds })
        }
        KdfChoice::Argon2id | KdfChoice::Argon2d => {
            let mem_mib = s
                .settings_kdf_memory_mib
                .text
                .trim()
                .parse::<u32>()
                .map_err(|_| String::from("Argon2 memory (MiB) must be a positive integer"))?;
            let iterations = s
                .settings_kdf_iterations
                .text
                .trim()
                .parse::<u32>()
                .map_err(|_| String::from("Argon2 iterations must be a positive integer"))?;
            let lanes = s
                .settings_kdf_lanes
                .text
                .trim()
                .parse::<u32>()
                .map_err(|_| String::from("Argon2 lanes must be a positive integer"))?;
            let memory_kib = mem_mib
                .checked_mul(1024)
                .ok_or_else(|| String::from("Argon2 memory (MiB) overflows KiB"))?;
            Ok(if kdf_choice == KdfChoice::Argon2id {
                VaultKdfSummary::Argon2id {
                    memory_kib,
                    iterations,
                    lanes,
                }
            } else {
                VaultKdfSummary::Argon2d {
                    memory_kib,
                    iterations,
                    lanes,
                }
            })
        }
    }
}

fn apply_settings_modal(s: &mut AppState) {
    let Some(modal) = s.settings_modal.clone() else {
        return;
    };
    let Ok(history_max_items) = s.settings_history_items.text.trim().parse::<i32>() else {
        if let Some(m) = s.settings_modal.as_mut() {
            m.error = Some(String::from("History Max Items must be an integer (>= -1)"));
        }
        return;
    };
    let Ok(history_max_size) = s.settings_history_size.text.trim().parse::<i64>() else {
        if let Some(m) = s.settings_modal.as_mut() {
            m.error = Some(String::from("History Max Size must be an integer (>= -1)"));
        }
        return;
    };
    let kdf = match parse_settings_kdf(s, modal.kdf_choice) {
        Ok(kdf) => kdf,
        Err(err) => {
            if let Some(m) = s.settings_modal.as_mut() {
                m.error = Some(err);
            }
            return;
        }
    };

    let update = DatabaseSettingsUpdate {
        name: s.settings_name.text.clone(),
        description: s.settings_description.text.clone(),
        default_username: s.settings_default_user.text.clone(),
        recycle_bin_enabled: modal.recycle_bin_enabled,
        history_max_items,
        history_max_size,
        outer_cipher: modal.outer_cipher,
        compression: modal.compression,
        kdf,
    };

    match s
        .controller
        .update_database_settings(update, current_unix_seconds())
    {
        Ok(()) => {
            s.controller.auto_lock_secs = modal.auto_lock_secs;
            s.controller.lock_on_focus_loss = modal.lock_on_focus_loss;
            s.settings_modal = None;
            s.wipe_editor_widgets();
            s.clear_transient_overlays();
            s.sync_path_bar_from_controller();
        }
        Err(err) => {
            if let Some(m) = s.settings_modal.as_mut() {
                m.error = Some(err);
            }
        }
    }
}

fn settings_metadata_fields(k: &Kit, state: &AppState, modal: &SettingsModalState) -> El {
    let name_in = TextInput::new(&state.settings_name)
        .label("Database Name")
        .placeholder("My Passwords")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.settings_name)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("settings-name-input");
    let desc_in = TextInput::new(&state.settings_description)
        .label("Description")
        .placeholder("Optional description")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.settings_description)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("settings-desc-input");
    let def_user_in = TextInput::new(&state.settings_default_user)
        .label("Default UserName")
        .placeholder("Optional default username")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.settings_default_user)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("settings-defuser-input");
    let recycle_cb = Checkbox::new(modal.recycle_bin_enabled)
        .label("Enable Recycle Bin")
        .on_toggle_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(m) = s.settings_modal.as_mut() {
                m.recycle_bin_enabled = !m.recycle_bin_enabled;
            }
        })
        .build(k)
        .key("settings-recycle-cb");

    let hist_items_in = TextInput::new(&state.settings_history_items)
        .label("History Max Items (-1 unlimited)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.settings_history_items)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("settings-hist-items-input");
    let hist_size_in = TextInput::new(&state.settings_history_size)
        .label("History Max Size bytes (-1 unlimited)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.settings_history_size)
        .on_change(|s: &mut AppState, tx| s.note_activity(tx))
        .build(k)
        .key("settings-hist-size-input");

    col()
        .w_full()
        .gap(10.0)
        .child(labeled_field(
            k,
            "settings-name-f",
            "Database Name",
            name_in,
        ))
        .child(labeled_field(k, "settings-desc-f", "Description", desc_in))
        .child(labeled_field(
            k,
            "settings-defuser-f",
            "Default UserName",
            def_user_in,
        ))
        .child(recycle_cb)
        .child(
            row()
                .w_full()
                .gap(8.0)
                .child(
                    labeled_field(
                        k,
                        "settings-hist-items-f",
                        "History Max Items (-1 = unlimited)",
                        hist_items_in,
                    )
                    .grow(1.0)
                    .min_w(0.0),
                )
                .child(
                    labeled_field(
                        k,
                        "settings-hist-size-f",
                        "History Max Size (bytes, -1 = unlimited)",
                        hist_size_in,
                    )
                    .grow(1.0)
                    .min_w(0.0),
                ),
        )
}

fn build_settings_modal(k: &Kit, state: &AppState, overlays: &mut Vec<El>) {
    let Some(modal) = &state.settings_modal else {
        return;
    };
    let scroll_body = col()
        .w_full()
        .gap(10.0)
        .child(settings_metadata_fields(k, state, modal))
        .child(settings_crypto_section(k, state, modal))
        .child(settings_desktop_security_section(k, modal));

    let scroll = col()
        .w_full()
        .h(320.0)
        .shrink()
        .min_h(0.0)
        .max_h(340.0)
        .padding(6.0)
        .scroll(ScrollSpec::default())
        .child(scroll_body);

    let mut content = col()
        .w_full()
        .shrink()
        .min_h(0.0)
        .px(16.0)
        .pb(16.0)
        .gap(10.0)
        .child(scroll);
    if let Some(err) = &modal.error {
        content = content.child(error_status_text(k, "settings-modal-error", err));
    }

    let save_btn = Button::new("Save Settings")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            apply_settings_modal(s);
            s.schedule_wakeup(tx);
        })
        .build(k)
        .key("settings-save-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.settings_modal = None;
        })
        .build(k)
        .key("settings-cancel-btn");

    content = content.child(
        row()
            .w_full()
            .justify_end()
            .gap(8.0)
            .child(cancel_btn)
            .child(save_btn),
    );

    Dialog::new("database-settings", "Database & Security Settings")
        .open(true)
        .fit()
        .width(560.0)
        .description(
            "Configure KDBX metadata, KDF/cipher/compression, and desktop auto-lock policy.",
        )
        .on_close(|s: &mut AppState| s.settings_modal = None)
        .child(content)
        .build(k, overlays);
}
