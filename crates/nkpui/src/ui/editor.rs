//! Entry editor views, non-UTF-8 read-only guards, and guided TOTP/HOTP configurator.

use nkeepass::ServiceOtpAlgorithm;
use rune::{El, TextEdit, Tx, col, row, text};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, Checkbox, ControlSize, Divider, IconButton,
    IconButtonVariant, Kit, SegmentedControl, TextArea, TextInput,
};
use zeroize::Zeroizing;

use crate::controller::{EditableCustomField, EntryEditorState, OtpEditorMode};
use crate::icons::render_keepass_icon;

use super::detail::attachments_section;
use super::{AppState, IconPickerState, IconPickerTarget, labeled_field};

fn read_only_non_utf8_box(k: &Kit, key: impl Into<String>, preview: &Zeroizing<String>) -> El {
    row()
        .key(key)
        .w_full()
        .padding(8.0)
        .gap(8.0)
        .center_y()
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_muted)
        .child(
            Badge::new("Read-only (non-UTF-8)")
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
        )
}

pub(super) fn editor_header_row(
    k: &Kit,
    state: &AppState,
    editor: &EntryEditorState,
    saving: bool,
) -> El {
    let custom_icon_id = editor.custom_icon_id;
    let custom_img = state.custom_icon_for(custom_icon_id);
    let icon_id = editor.icon_id;
    let preview_icon =
        render_keepass_icon(k, icon_id, custom_img, 20.0, "editor-header-preview-icon");
    let picker_icon = render_keepass_icon(k, icon_id, custom_img, 16.0, "editor-header-icon");
    let icon_btn = Button::new("Change icon")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .disabled(saving)
        .label_with(move |font, ink| {
            row()
                .gap(6.0)
                .center_y()
                .child(picker_icon)
                .child(text("Change icon").font(font).color(ink))
        })
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            s.icon_search_edit.replace_text("");
            s.icon_picker = Some(IconPickerState {
                target: IconPickerTarget::EntryEditor,
                selected_id: icon_id,
                selected_custom_id: custom_icon_id,
            });
        })
        .build(k)
        .key("editor-icon-picker-btn")
        .label("Change entry icon");

    let apply_btn = Button::new("Apply")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.apply_entry_editor();
        })
        .build(k)
        .key("editor-apply-btn");

    let cancel_btn = Button::new("Cancel")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .disabled(saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.cancel_entry_editor();
        })
        .build(k)
        .key("editor-cancel-btn");

    col()
        .key("editor-header-row")
        .w_full()
        .gap(8.0)
        .child(
            row()
                .key("editor-header-title-row")
                .w_full()
                .center_y()
                .gap(8.0)
                .child(preview_icon)
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
                ),
        )
        .child(
            row()
                .key("editor-header-actions")
                .w_full()
                .justify_between()
                .center_y()
                .gap(6.0)
                .child(icon_btn)
                .child(row().gap(6.0).child(cancel_btn).child(apply_btn)),
        )
}

fn editor_generator_controls(k: &Kit, state: &AppState) -> El {
    let cur_len = state.controller.gen_length;
    let policy = state.controller.gen_policy;
    let mut len_row = row()
        .key("editor-gen-lengths")
        .gap(4.0)
        .center_y()
        .child(text("Len:").font(k.ty.text_xsmall).color(k.c.text_muted));
    for len in [16_usize, 20, 24, 32] {
        len_row = len_row.child(
            Button::new(format!("{len}"))
                .control_size(ControlSize::Regular)
                .variant(if cur_len == len {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Ghost
                })
                .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.controller.gen_length = len;
                })
                .build(k)
                .key(format!("editor-gen-len-{len}")),
        );
    }

    let toggle_class = |label: &'static str, checked: bool, kind: u8| {
        Checkbox::new(checked)
            .label(label)
            .on_toggle_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                let mut p = s.controller.gen_policy;
                match kind {
                    0 => p.upper = !p.upper,
                    1 => p.lower = !p.lower,
                    2 => p.digits = !p.digits,
                    _ => p.symbols = !p.symbols,
                }
                if p.selected() {
                    s.controller.gen_policy = p;
                }
            })
            .build(k)
            .key(format!("editor-gen-class-{kind}"))
    };

    row()
        .key("editor-gen-options")
        .w_full()
        .flex_wrap()
        .center_y()
        .gap(8.0)
        .child(len_row)
        .child(toggle_class("Upper", policy.upper, 0))
        .child(toggle_class("Lower", policy.lower, 1))
        .child(toggle_class("Digits", policy.digits, 2))
        .child(toggle_class("Symbols", policy.symbols, 3))
}

fn editor_password_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    if let Some(preview) = &editor.password_non_utf8 {
        return labeled_field(
            k,
            "editor-password-field",
            "Password",
            read_only_non_utf8_box(k, "editor-password-non-utf8", preview),
        );
    }
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
    .control_size(ControlSize::Regular)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        if let Some(ed) = s.controller.editor.as_mut() {
            ed.password_revealed = !ed.password_revealed;
            s.edit_password.set_revealed(ed.password_revealed);
        }
    })
    .build(k)
    .key("editor-password-reveal-btn");

    let gen_len = state.controller.gen_length;
    let pw_generate_btn = Button::new(format!("Generate ({gen_len})"))
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let len = s.controller.gen_length;
            match s.controller.generate_editor_password() {
                Ok(generated) => {
                    s.edit_password.replace_text(generated.as_str());
                    s.controller
                        .set_browser_info(format!("Generated {len}-character password"));
                }
                Err(err) => s.controller.set_browser_error(err),
            }
        })
        .build(k)
        .key("editor-password-generate-btn");

    let pw_copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Regular)
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
        .child(editor_generator_controls(k, state))
}

fn editor_otp_step_field(k: &Kit, state: &AppState, mode: OtpEditorMode) -> El {
    if mode == OtpEditorMode::Totp {
        let period_in = TextInput::new(&state.edit_otp_period)
            .label("Period (seconds)")
            .placeholder("30")
            .width(Some(90.0))
            .on_edit(|s: &mut AppState| &mut s.edit_otp_period)
            .on_change(|s: &mut AppState, tx| {
                s.note_activity(tx);
                if let Ok(val) = s.edit_otp_period.text.trim().parse::<u64>()
                    && val > 0
                    && let Some(ed) = s.controller.editor.as_mut()
                {
                    ed.otp_config.period = val;
                }
            })
            .build(k)
            .key("editor-otp-period-input");
        labeled_field(k, "editor-otp-period-field", "Period (s)", period_in)
    } else {
        let counter_in = TextInput::new(&state.edit_otp_counter)
            .label("HOTP Counter")
            .placeholder("0")
            .width(Some(110.0))
            .on_edit(|s: &mut AppState| &mut s.edit_otp_counter)
            .on_change(|s: &mut AppState, tx| {
                s.note_activity(tx);
                if let Ok(val) = s.edit_otp_counter.text.trim().parse::<u64>()
                    && let Some(ed) = s.controller.editor.as_mut()
                {
                    ed.otp_config.counter = val;
                }
            })
            .build(k)
            .key("editor-otp-counter-input");
        labeled_field(k, "editor-otp-counter-field", "Counter", counter_in)
    }
}

fn editor_otp_guided_params(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    let cfg = &editor.otp_config;
    let secret_input = TextInput::new(&state.edit_otp_secret)
        .secure()
        .revealed(editor.otp_revealed)
        .label("Base32 Secret")
        .placeholder("JBSWY3DPEHPK3PXP")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.edit_otp_secret)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            let val = Zeroizing::new(s.edit_otp_secret.text.clone());
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.otp_config.secret = val;
            }
        })
        .build(k)
        .key("editor-otp-secret-input");

    let reveal_btn = Button::new(if editor.otp_revealed {
        "Hide"
    } else {
        "Reveal"
    })
    .control_size(ControlSize::Regular)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        if let Some(ed) = s.controller.editor.as_mut() {
            ed.otp_revealed = !ed.otp_revealed;
            s.edit_otp_secret.set_revealed(ed.otp_revealed);
            s.edit_otp_uri.set_revealed(ed.otp_revealed);
        }
    })
    .build(k)
    .key("editor-otp-reveal-btn");

    let algo_idx = match cfg.algorithm {
        ServiceOtpAlgorithm::Sha1 => 0,
        ServiceOtpAlgorithm::Sha256 => 1,
        ServiceOtpAlgorithm::Sha512 => 2,
    };
    let algo_sel = SegmentedControl::new(&["SHA1", "SHA256", "SHA512"], Some(algo_idx))
        .label("OTP Algorithm")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.otp_config.algorithm = match idx {
                    1 => ServiceOtpAlgorithm::Sha256,
                    2 => ServiceOtpAlgorithm::Sha512,
                    _ => ServiceOtpAlgorithm::Sha1,
                };
            }
        })
        .build(k)
        .key("editor-otp-algo");

    let digits_idx = usize::from(cfg.digits == 8);
    let digits_sel = SegmentedControl::new(&["6 digits", "8 digits"], Some(digits_idx))
        .label("OTP Digits")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.otp_config.digits = if idx == 1 { 8 } else { 6 };
            }
        })
        .build(k)
        .key("editor-otp-digits");

    let steam_cb = Checkbox::new(cfg.steam)
        .label("Steam Guard")
        .on_toggle_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.otp_config.steam = !ed.otp_config.steam;
            }
        })
        .build(k)
        .key("editor-otp-steam");

    let step_field = editor_otp_step_field(k, state, cfg.mode);

    col()
        .key("editor-otp-guided")
        .w_full()
        .gap(8.0)
        .child(
            row()
                .w_full()
                .gap(6.0)
                .center_y()
                .child(secret_input.grow(1.0).min_w(0.0))
                .child(reveal_btn),
        )
        .child(
            row()
                .w_full()
                .flex_wrap()
                .center_y()
                .gap(8.0)
                .child(algo_sel)
                .child(digits_sel)
                .child(steam_cb),
        )
        .child(step_field)
}

fn editor_otp_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    if let Some(preview) = &editor.otp_non_utf8 {
        return labeled_field(
            k,
            "editor-otp-field",
            "OTP (protected \"otp\")",
            read_only_non_utf8_box(k, "editor-otp-non-utf8", preview),
        );
    }

    let mode_idx = match editor.otp_config.mode {
        OtpEditorMode::None => 0,
        OtpEditorMode::Totp => 1,
        OtpEditorMode::Hotp => 2,
        OtpEditorMode::RawUri => 3,
    };
    let mode_sel = SegmentedControl::new(&["None", "TOTP", "HOTP", "URI"], Some(mode_idx))
        .label("OTP Mode")
        .fit()
        .on_pick(|s: &mut AppState, idx, tx| {
            s.note_activity(tx);
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.otp_config.mode = match idx {
                    1 => OtpEditorMode::Totp,
                    2 => OtpEditorMode::Hotp,
                    3 => OtpEditorMode::RawUri,
                    _ => OtpEditorMode::None,
                };
            }
        })
        .build(k)
        .key("editor-otp-mode");

    let mut card = col()
        .key("editor-otp-field")
        .w_full()
        .padding(8.0)
        .gap(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(
            row()
                .w_full()
                .justify_between()
                .center_y()
                .flex_wrap()
                .gap(6.0)
                .child(
                    text("Two-Factor OTP")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(mode_sel),
        );

    match editor.otp_config.mode {
        OtpEditorMode::None => {}
        OtpEditorMode::Totp | OtpEditorMode::Hotp => {
            card = card.child(editor_otp_guided_params(k, state, editor));
        }
        OtpEditorMode::RawUri => {
            let otp_input = TextInput::new(&state.edit_otp_uri)
                .secure()
                .revealed(editor.otp_revealed)
                .label("OTP Auth URI (otpauth://...)")
                .placeholder("otpauth://totp/Issuer:user?secret=BASE32&period=30")
                .width(None)
                .on_edit(|s: &mut AppState| &mut s.edit_otp_uri)
                .on_change(|s: &mut AppState, tx| {
                    s.note_activity(tx);
                    let val = Zeroizing::new(s.edit_otp_uri.text.clone());
                    if let Some(ed) = s.controller.editor.as_mut() {
                        ed.otp_uri = val;
                    }
                })
                .build(k)
                .key("editor-otp-input");
            let reveal_btn = Button::new(if editor.otp_revealed {
                "Hide"
            } else {
                "Reveal"
            })
            .control_size(ControlSize::Regular)
            .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                if let Some(ed) = s.controller.editor.as_mut() {
                    ed.otp_revealed = !ed.otp_revealed;
                    s.edit_otp_uri.set_revealed(ed.otp_revealed);
                }
            })
            .build(k)
            .key("editor-otp-reveal-btn");
            card = card.child(
                row()
                    .w_full()
                    .gap(6.0)
                    .center_y()
                    .child(otp_input.grow(1.0).min_w(0.0))
                    .child(reveal_btn),
            );
        }
    }

    card
}

#[derive(Clone, Copy)]
struct ProtectedFieldSpec {
    field_key: &'static str,
    label: &'static str,
    protected: bool,
    revealed: bool,
    toggle_key: &'static str,
}

fn protected_standard_field(
    k: &Kit,
    spec: ProtectedFieldSpec,
    on_toggle: impl Fn(&mut AppState) + Clone + 'static,
    input_el: El,
) -> El {
    if !spec.protected {
        return labeled_field(k, spec.field_key, spec.label, input_el);
    }
    let reveal_btn = Button::new(if spec.revealed { "Hide" } else { "Reveal" })
        .control_size(ControlSize::Regular)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            on_toggle(s);
        })
        .build(k)
        .key(spec.toggle_key);
    col()
        .key(spec.field_key)
        .w_full()
        .gap(4.0)
        .child(
            row()
                .w_full()
                .justify_between()
                .center_y()
                .gap(6.0)
                .child(
                    row()
                        .center_y()
                        .gap(6.0)
                        .child(
                            text(spec.label)
                                .font(k.ty.small_medium)
                                .color(k.c.text_muted),
                        )
                        .child(
                            Badge::new("Protected")
                                .variant(BadgeVariant::Accent)
                                .build(k),
                        ),
                )
                .child(reveal_btn),
        )
        .child(input_el)
}

fn editor_username_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    if let Some(preview) = &editor.username_non_utf8 {
        return labeled_field(
            k,
            "editor-username-field",
            "UserName",
            read_only_non_utf8_box(k, "editor-username-non-utf8", preview),
        );
    }
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
    let input_el = if editor.username_protected {
        base.secure().revealed(editor.username_revealed)
    } else {
        base
    }
    .build(k)
    .key("editor-username-input");
    protected_standard_field(
        k,
        ProtectedFieldSpec {
            field_key: "editor-username-field",
            label: "UserName",
            protected: editor.username_protected,
            revealed: editor.username_revealed,
            toggle_key: "editor-username-reveal-btn",
        },
        |s| {
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.username_revealed = !ed.username_revealed;
                s.edit_username.set_revealed(ed.username_revealed);
            }
        },
        input_el,
    )
}

fn editor_url_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    if let Some(preview) = &editor.url_non_utf8 {
        return labeled_field(
            k,
            "editor-url-field",
            "URL",
            read_only_non_utf8_box(k, "editor-url-non-utf8", preview),
        );
    }
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
    let input_el = if editor.url_protected {
        base.secure().revealed(editor.url_revealed)
    } else {
        base
    }
    .build(k)
    .key("editor-url-input");
    protected_standard_field(
        k,
        ProtectedFieldSpec {
            field_key: "editor-url-field",
            label: "URL",
            protected: editor.url_protected,
            revealed: editor.url_revealed,
            toggle_key: "editor-url-reveal-btn",
        },
        |s| {
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.url_revealed = !ed.url_revealed;
                s.edit_url.set_revealed(ed.url_revealed);
            }
        },
        input_el,
    )
}

fn editor_notes_block(k: &Kit, state: &AppState, editor: &EntryEditorState) -> El {
    if let Some(preview) = &editor.notes_non_utf8 {
        return labeled_field(
            k,
            "editor-notes-field",
            "Notes",
            read_only_non_utf8_box(k, "editor-notes-non-utf8", preview),
        );
    }
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
    let input_el = if editor.notes_protected {
        base.secure().revealed(editor.notes_revealed)
    } else {
        base
    }
    .build(k)
    .key("editor-notes-input");
    protected_standard_field(
        k,
        ProtectedFieldSpec {
            field_key: "editor-notes-field",
            label: "Notes",
            protected: editor.notes_protected,
            revealed: editor.notes_revealed,
            toggle_key: "editor-notes-reveal-btn",
        },
        |s| {
            if let Some(ed) = s.controller.editor.as_mut() {
                ed.notes_revealed = !ed.notes_revealed;
                s.edit_notes.set_revealed(ed.notes_revealed);
            }
        },
        input_el,
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

    col()
        .w_full()
        .gap(10.0)
        .child(labeled_field(k, "editor-title-field", "Title", title_input))
        .child(editor_username_block(k, state, editor))
        .child(editor_password_block(k, state, editor))
        .child(editor_url_block(k, state, editor))
        .child(editor_otp_block(k, state, editor))
        .child(editor_notes_block(k, state, editor))
}

pub(super) fn entry_editor_body(
    k: &Kit,
    state: &AppState,
    mut pane: El,
    editor: &EntryEditorState,
) -> El {
    pane = pane.child(editor_standard_fields(k, state, editor));
    pane = editor_tags_section(k, state, pane, editor);
    pane = editor_custom_fields_section(k, state, pane, editor);

    if let Some(detail) = &state.controller.detail {
        pane = attachments_section(k, pane, detail, state.controller.saving);
    }

    pane
}

fn editor_tags_section(k: &Kit, state: &AppState, mut pane: El, editor: &EntryEditorState) -> El {
    let mut chips = row().key("editor-tag-chips").w_full().flex_wrap().gap(10.0);
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
                    .padding(2.0)
                    .gap(4.0)
                    .radius(k.radius.sm)
                    .fill(k.c.layer_01)
                    .center_y()
                    .child(
                        Badge::new(tag.clone())
                            .variant(BadgeVariant::Accent)
                            .build(k),
                    )
                    .child(
                        IconButton::new(k.glyph.close)
                            .control_size(ControlSize::Regular)
                            .variant(IconButtonVariant::Ghost)
                            .label(format!("Remove tag {tag}"))
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
        .control_size(ControlSize::Regular)
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

fn editor_custom_field_header(k: &Kit, idx: usize, field: &EditableCustomField) -> El {
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
    header_row.child(
        Button::new("Remove")
            .control_size(ControlSize::Regular)
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
    )
}

fn editor_custom_field_card(
    k: &Kit,
    state: &AppState,
    idx: usize,
    field: &EditableCustomField,
) -> El {
    let field_key = &field.name;
    let header_row = editor_custom_field_header(k, idx, field);

    if let Some(preview) = &field.non_utf8_preview {
        return col()
            .key(format!("editor-cf-card-{field_key}"))
            .w_full()
            .padding(8.0)
            .gap(6.0)
            .radius(k.radius.md)
            .fill(k.c.layer_01)
            .child(header_row)
            .child(read_only_non_utf8_box(
                k,
                format!("editor-cf-non-utf8-{field_key}"),
                preview,
            ));
    }

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
                .control_size(ControlSize::Regular)
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
            .control_size(ControlSize::Regular)
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

fn editor_add_custom_actions(k: &Kit, form: &super::AddCustomFieldForm) -> El {
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

    let mut actions = row()
        .key("add-custom-actions")
        .w_full()
        .flex_wrap()
        .center_y()
        .gap(8.0)
        .child(add_protected_cb);

    if form.protected {
        actions = actions.child(
            Button::new(if form.revealed { "Hide" } else { "Reveal" })
                .control_size(ControlSize::Regular)
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

    actions.child(
        Button::new("+ Add Custom String")
            .control_size(ControlSize::Regular)
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

    let add_form_actions = editor_add_custom_actions(k, form);

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
        .child(labeled_field(
            k,
            "add-custom-name-field",
            "Field Name",
            new_name_input,
        ))
        .child(labeled_field(
            k,
            "add-custom-value-field",
            "Field Value",
            new_value_input.build(k).key("add-custom-value-input"),
        ))
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
