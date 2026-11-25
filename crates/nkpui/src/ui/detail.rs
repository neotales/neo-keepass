//! Entry detail pane, reveal polish, unprotected field actions, TOTP/HOTP, and attachments.

use nkeepass::ServiceOtpKind;
use rune::{El, ScrollSpec, Tx, col, el, row, text};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, ControlSize, Divider, IconButton,
    IconButtonVariant, Kit,
};
use zeroize::Zeroizing;

use crate::controller::{
    EntryDetailState, RevealedSecret, TotpDisplay, current_unix_seconds, format_byte_size,
    sanitize_attachment_prefill, validate_http_url,
};
use crate::icons::{STAR_FILLED_ICON, STAR_ICON, render_keepass_icon};

use super::editor::entry_editor_body;
use super::{AppState, ConfirmDialog, ExtractDialogState};

pub(super) fn secret_value_text(
    k: &Kit,
    key: impl Into<String>,
    revealed: Option<&RevealedSecret>,
) -> El {
    let key_str = key.into();
    match revealed {
        Some(RevealedSecret::Text(secret)) if secret.is_empty() => text("(empty)")
            .key(key_str)
            .w_full()
            .wrap_anywhere()
            .font(k.ty.mono)
            .color(k.c.text_faint)
            .secure()
            .revealed(true),
        Some(RevealedSecret::Text(secret)) => text(secret.as_str().to_owned())
            .key(key_str)
            .w_full()
            .wrap_anywhere()
            .font(k.ty.mono)
            .color(k.c.text_base)
            .secure()
            .revealed(true),
        Some(RevealedSecret::NonUtf8 { preview, .. }) => row()
            .key(key_str)
            .w_full()
            .gap(6.0)
            .center_y()
            .child(
                Badge::new("non-UTF-8")
                    .variant(BadgeVariant::Neutral)
                    .build(k),
            )
            .child(
                text(preview.as_str().to_owned())
                    .grow(1.0)
                    .min_w(0.0)
                    .wrap_anywhere()
                    .font(k.ty.mono)
                    .color(k.c.text_faint)
                    .secure()
                    .revealed(true),
            ),
        None => text("••••••••••••")
            .key(key_str)
            .w_full()
            .wrap_anywhere()
            .font(k.ty.mono)
            .color(k.c.text_muted)
            .secure(),
    }
}

struct SecretRowSpec<'a> {
    row_key: String,
    label: String,
    protected_badge: bool,
    value_key: String,
    revealed: Option<&'a RevealedSecret>,
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
    let hide_otp = detail.metadata.has_otp();
    for (idx, field) in detail.metadata.custom_fields().iter().enumerate() {
        if hide_otp && field.name() == "otp" {
            continue;
        }
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

fn metadata_row(k: &Kit, key_suffix: &str, label: &str, value: &str) -> El {
    let shown = if value.is_empty() { "—" } else { value };
    let mut actions = row().key(format!("meta-actions-{key_suffix}")).gap(6.0);
    if !value.is_empty() {
        let copy_val = value.to_owned();
        let copy_label = label.to_owned();
        actions = actions.child(
            Button::new("Copy")
                .control_size(ControlSize::Small)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    tx.copy(copy_val.clone());
                    s.controller
                        .set_browser_info(format!("Copied {copy_label} to clipboard"));
                })
                .build(k)
                .key(format!("std-copy-{key_suffix}"))
                .min_h(24.0),
        );
    }
    if key_suffix == "URL"
        && let Some(safe_url) = validate_http_url(value)
    {
        let open_target = safe_url.to_owned();
        actions = actions.child(
            Button::new("Open URL")
                .control_size(ControlSize::Small)
                .variant(ButtonVariant::Contrast)
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    if let Err(err) = tx.open_url(&open_target) {
                        s.controller
                            .set_browser_error(format!("Cannot open URL: {err}"));
                    }
                })
                .build(k)
                .key("std-open-url-btn")
                .min_h(24.0),
        );
    }

    row()
        .key(format!("std-meta-{key_suffix}"))
        .w_full()
        .padding(8.0)
        .gap(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .justify_between()
        .center_y()
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
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
                        .color(if value.is_empty() {
                            k.c.text_faint
                        } else {
                            k.c.text_base
                        }),
                ),
        )
        .child(actions)
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

fn password_row(k: &Kit, detail: &EntryDetailState) -> El {
    let revealed = detail.revealed_password.as_ref();
    let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.controller.toggle_reveal_password();
        })
        .build(k)
        .key("password-reveal-btn")
        .min_h(24.0);

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
        .key("password-copy-btn")
        .min_h(24.0);

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

#[allow(
    clippy::cast_precision_loss,
    reason = "OTP period is small u64 seconds"
)]
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

    let frac = (totp.remaining_secs as f32 / totp.period.max(1) as f32).clamp(0.0, 1.0);
    let bar_fill = if totp.remaining_secs <= 5 {
        k.c.warning.icon
    } else {
        k.c.border_active
    };

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
                .gap(4.0)
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
                )
                .child(
                    row()
                        .key("totp-progress-track")
                        .w_full()
                        .h(4.0)
                        .radius(999.0)
                        .fill(k.c.surface_base)
                        .clip_soft(0.0)
                        .child(el().h_full().radius(999.0).fill(bar_fill).w_frac(frac)),
                ),
        )
        .child(copy_btn)
}

fn hotp_row(k: &Kit, counter: u64, hotp_code: Option<&Zeroizing<String>>, saving: bool) -> El {
    let next_btn = Button::new("Generate Next Code")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Err(err) = s.controller.generate_next_hotp_code(current_unix_seconds()) {
                s.controller.set_browser_error(err);
            }
        })
        .build(k)
        .key("hotp-next-btn");

    let mut actions = row().gap(6.0).child(next_btn);
    if hotp_code.is_some() {
        actions = actions.child(
            Button::new("Copy (30s)")
                .control_size(ControlSize::Small)
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    if let Some(code) = s
                        .controller
                        .detail
                        .as_ref()
                        .and_then(|d| d.hotp_code.as_ref())
                        .cloned()
                    {
                        s.copy_secret(&code, "HOTP", tx);
                    }
                })
                .build(k)
                .key("hotp-copy-btn"),
        );
    }

    let code_el = if let Some(code) = hotp_code {
        text(code.as_str().to_owned())
            .key("hotp-value")
            .w_full()
            .font(k.ty.mono)
            .color(k.c.text_base)
            .secure()
            .revealed(true)
    } else {
        text("Click \"Generate Next Code\" to compute & advance counter")
            .key("hotp-hint")
            .w_full()
            .wrap()
            .font(k.ty.text_xsmall)
            .color(k.c.text_faint)
    };

    row()
        .key("hotp-row")
        .w_full()
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .justify_between()
        .center_y()
        .gap(8.0)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(4.0)
                .child(
                    text(format!("HOTP (Counter: {counter})"))
                        .key("hotp-label")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(code_el),
        )
        .child(actions)
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

    let prefill_name = sanitize_attachment_prefill(name);
    let extract_name = prefill_name.clone();
    let extract_btn = Button::new("Save As…")
        .control_size(ControlSize::Small)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.extract_path_edit.replace_text(prefill_name.clone());
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

pub(super) fn attachments_section(
    k: &Kit,
    mut pane: El,
    detail: &EntryDetailState,
    saving: bool,
) -> El {
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

fn entry_recycle_action_buttons(
    k: &Kit,
    state: &AppState,
    detail: &EntryDetailState,
    saving: bool,
    actions: El,
) -> El {
    let entry_title = detail.metadata.title().to_owned();
    if detail.is_in_recycle_bin {
        let restore_btn = Button::new("Restore")
            .control_size(ControlSize::Small)
            .variant(ButtonVariant::Contrast)
            .disabled(saving)
            .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                if let Err(err) = s.controller.restore_selected_entry(current_unix_seconds()) {
                    s.controller.set_browser_error(err);
                } else {
                    s.sync_path_bar_from_controller();
                }
            })
            .build(k)
            .key("entry-restore-btn");
        let perm_del_btn = Button::new("Delete Permanently")
            .control_size(ControlSize::Small)
            .variant(ButtonVariant::Danger)
            .disabled(saving)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.pending_confirm = Some(ConfirmDialog::DeleteEntryPermanent {
                    title: entry_title.clone(),
                });
            })
            .build(k)
            .key("entry-delete-perm-btn");
        return actions.child(restore_btn).child(perm_del_btn);
    }

    let label = if state.controller.recycle_bin_enabled {
        "Recycle"
    } else {
        "Delete"
    };
    let delete_btn = Button::new(label)
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Danger)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if s.controller.recycle_bin_enabled {
                if let Err(err) = s.controller.delete_selected_entry(current_unix_seconds()) {
                    s.controller.set_browser_error(err);
                } else {
                    s.wipe_editor_widgets();
                    s.sync_path_bar_from_controller();
                }
            } else {
                s.pending_confirm = Some(ConfirmDialog::DeleteEntryPermanent {
                    title: entry_title.clone(),
                });
            }
        })
        .build(k)
        .key("entry-delete-btn");
    actions.child(delete_btn)
}

fn entry_detail_actions(k: &Kit, state: &AppState, detail: &EntryDetailState, saving: bool) -> El {
    let is_fav = state.controller.is_selected_favorite();
    let fav_btn = IconButton::new(if is_fav {
        &STAR_FILLED_ICON
    } else {
        &STAR_ICON
    })
    .control_size(ControlSize::Regular)
    .variant(IconButtonVariant::Ghost)
    .disabled(saving)
    .label(if is_fav {
        "Remove from favorites"
    } else {
        "Add to favorites"
    })
    .help(if is_fav {
        "Remove favorite tag"
    } else {
        "Mark as favorite"
    })
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        if let Err(err) = s
            .controller
            .toggle_selected_favorite(current_unix_seconds())
        {
            s.controller.set_browser_error(err);
        }
    })
    .build(k)
    .key("entry-favorite-btn");

    let move_ref = detail.entry_ref.clone();
    let move_title = detail.metadata.title().to_owned();
    let move_btn = Button::new("Move…")
        .control_size(ControlSize::Small)
        .disabled(saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.open_move_entry_modal(move_ref.clone(), move_title.clone());
        })
        .build(k)
        .key("entry-move-btn")
        .min_h(24.0);

    let clone_btn = Button::new("Clone")
        .control_size(ControlSize::Small)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            match s.controller.clone_selected_entry(current_unix_seconds()) {
                Ok(_) => s.sync_path_bar_from_controller(),
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("entry-clone-btn")
        .min_h(24.0);

    let edit_btn = Button::new("Edit")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.open_entry_editor();
        })
        .build(k)
        .key("entry-edit-btn")
        .min_h(24.0);

    let actions = row()
        .key("detail-header-actions")
        .center_y()
        .flex_wrap()
        .gap(6.0)
        .child(fav_btn)
        .child(move_btn)
        .child(clone_btn)
        .child(edit_btn);
    entry_recycle_action_buttons(k, state, detail, saving, actions)
}

fn entry_detail_header(k: &Kit, state: &AppState, detail: &EntryDetailState, saving: bool) -> El {
    let custom_img = state.custom_icon_for(detail.metadata.custom_icon_id());
    let detail_icon = render_keepass_icon(
        k,
        detail.metadata.icon_id(),
        custom_img,
        24.0,
        "detail-header-icon",
    );

    col()
        .key("detail-header-row")
        .w_full()
        .gap(8.0)
        .child(
            row()
                .w_full()
                .min_w(0.0)
                .gap(10.0)
                .center_y()
                .child(detail_icon)
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
                ),
        )
        .child(entry_detail_actions(k, state, detail, saving))
}

fn entry_detail_scroll_body(k: &Kit, detail: &EntryDetailState, saving: bool) -> El {
    let mut scroll_body = col()
        .key("entry-detail-scroll")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(10.0);

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
        scroll_body = scroll_body.child(tags_row);
    }

    scroll_body = scroll_body
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

    if let Some(meta) = &detail.otp_meta {
        match meta.kind {
            ServiceOtpKind::Totp => {
                if let Some(totp) = &detail.totp {
                    scroll_body = scroll_body.child(totp_row(k, totp));
                }
            }
            ServiceOtpKind::Hotp => {
                scroll_body = scroll_body.child(hotp_row(
                    k,
                    meta.counter.unwrap_or(0),
                    detail.hotp_code.as_ref(),
                    saving,
                ));
            }
        }
    } else if let Some(totp) = &detail.totp {
        scroll_body = scroll_body.child(totp_row(k, totp));
    }

    let has_visible_custom_fields = detail
        .metadata
        .custom_fields()
        .iter()
        .any(|field| !(detail.metadata.has_otp() && field.name() == "otp"));
    if has_visible_custom_fields {
        scroll_body = custom_fields_section(k, scroll_body, detail);
    }
    attachments_section(k, scroll_body, detail, saving)
}

pub(super) fn entry_detail_pane(k: &Kit, state: &AppState) -> El {
    let mut pane = col()
        .key("entry-detail-pane")
        .w_full()
        .h_full()
        .min_w(0.0)
        .min_h(0.0)
        .padding(16.0)
        .gap(10.0);

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
        let mut scroll_body = col()
            .key("entry-editor-scroll")
            .w_full()
            .grow(1.0)
            .min_h(0.0)
            .scroll(ScrollSpec::default())
            .gap(10.0);
        scroll_body = entry_editor_body(k, state, scroll_body, editor);
        return pane
            .child(super::editor::editor_header_row(
                k,
                state,
                editor,
                state.controller.saving,
            ))
            .child(Divider::horizontal().build(k).key("editor-divider"))
            .child(scroll_body);
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

    pane.child(entry_detail_header(
        k,
        state,
        detail,
        state.controller.saving,
    ))
    .child(Divider::horizontal().build(k).key("detail-divider"))
    .child(entry_detail_scroll_body(k, detail, state.controller.saving))
}
