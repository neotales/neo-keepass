//! Template and `.env` injector views for `nkpui`.

use rune::{El, FileDialogOptions, ScrollSpec, Tx, col, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, TextArea, TextInput};
use zeroize::Zeroizing;

use crate::controller::{InjectMode, WorkspaceTab, current_unix_seconds, read_inject_file_bounded};

use super::detail::secret_value_text;
use super::{AppState, error_status_text, starting_directory_from_path};

fn inject_mode_bar(k: &Kit, state: &AppState) -> El {
    let open_file_btn = Button::new("Open File…")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Neutral)
        .disabled(state.controller.saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if s.file_dialog_active {
                return;
            }
            let opts = FileDialogOptions {
                title: String::from("Open Template or .env File"),
                ..FileDialogOptions::default()
            }
            .filter("Template / Env Files", &["env", "tmpl", "txt"]);
            s.file_dialog_active = true;
            tx.open_file(opts, |s: &mut AppState, res, _| {
                s.file_dialog_active = false;
                if !s.controller.is_unlocked() || s.controller.active_tab != WorkspaceTab::Inject {
                    return;
                }
                match res {
                    Ok(Some(path)) => match read_inject_file_bounded(&path) {
                        Ok(content) => {
                            s.inject_edit.replace_text(content.clone());
                            s.controller.set_inject_input(content);
                            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                            s.controller.set_inject_info(format!("Loaded \"{name}\""));
                        }
                        Err(err) => {
                            s.controller.set_inject_error(err);
                        }
                    },
                    Ok(None) => {}
                    Err(err) => {
                        s.controller
                            .set_inject_error(format!("File dialog unavailable: {err}"));
                    }
                }
            });
        })
        .build(k)
        .key("inject-open-file-btn");

    row()
        .key("inject-modes")
        .w_full()
        .justify_between()
        .center_y()
        .child(
            row()
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
                ),
        )
        .child(open_file_btn)
}

pub(super) fn inject_view(k: &Kit, state: &AppState) -> El {
    let preview_has_error = state.controller.inject_preview_error.is_some();
    let mode_row = inject_mode_bar(k, state);

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
                s.controller.set_inject_error(err.to_string());
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
        let status_color = if state.controller.inject_status_is_error {
            k.c.danger.fg
        } else {
            k.c.info.fg
        };
        page = page.child(
            text(status.clone())
                .key("inject-status")
                .role("status")
                .w_full()
                .wrap_anywhere()
                .font(k.ty.text_small)
                .color(status_color),
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

fn inject_save_row(k: &Kit, state: &AppState) -> El {
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

    let default_out_name = match state.controller.inject_mode {
        InjectMode::EnvFile => ".env",
        InjectMode::Template => "rendered.txt",
    };
    let save_as_btn = Button::new("Save As…")
        .control_size(ControlSize::Regular)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if s.file_dialog_active {
                return;
            }
            let opts = FileDialogOptions {
                title: String::from("Save Rendered Output"),
                file_name: Some(String::from(default_out_name)),
                directory: starting_directory_from_path(&s.save_path_edit.text),
                ..FileDialogOptions::default()
            };
            s.file_dialog_active = true;
            tx.save_file(opts, |s: &mut AppState, res, _| {
                s.file_dialog_active = false;
                if !s.controller.is_unlocked() || s.controller.active_tab != WorkspaceTab::Inject {
                    return;
                }
                match res {
                    Ok(Some(path)) => {
                        let text = path.to_string_lossy().into_owned();
                        s.save_path_edit.replace_text(text.clone());
                        s.controller.inject_save_path = text;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        s.controller
                            .set_inject_error(format!("File dialog unavailable: {err}"));
                    }
                }
            });
        })
        .build(k)
        .key("inject-save-browse-btn");

    let save_btn = Button::new("Save Private File")
        .control_size(ControlSize::Regular)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            let _ = s.controller.save_inject_output();
        })
        .build(k)
        .key("inject-save-btn");

    row()
        .key("inject-save-row")
        .w_full()
        .gap(8.0)
        .center_y()
        .child(save_path_box.grow(1.0).min_w(0.0))
        .child(save_as_btn)
        .child(save_btn)
}

fn inject_output_section(k: &Kit, state: &AppState, page: El, output: &Zeroizing<String>) -> El {
    let revealed = state.controller.inject_output_revealed;
    let revealed_secret = revealed.then(|| crate::controller::RevealedSecret::Text(output.clone()));
    let output_text = secret_value_text(k, "inject-output-value", revealed_secret.as_ref());

    let toggle_btn = Button::new(if revealed {
        "Hide Output"
    } else {
        "Reveal Output"
    })
    .control_size(ControlSize::Small)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        s.controller.inject_output_revealed = !s.controller.inject_output_revealed;
        let msg = if s.controller.inject_output_revealed {
            String::from("Rendered output revealed in memory")
        } else {
            String::from("Rendered securely in memory (masked)")
        };
        s.controller.set_inject_info(msg);
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
    .child(inject_save_row(k, state))
}
