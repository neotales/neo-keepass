//! Rune view layer and UI state adapter for `nkpui`.

use std::fmt;
use std::time::Duration;

use rune::{Cx, El, Latest, ScrollSpec, SecretCopy, SecretState, TextEdit, Tx, col, row, text};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, ControlSize, Divider, Kit, TextArea, TextInput,
};
use zeroize::Zeroizing;

use crate::controller::{
    EntryDetailState, InjectMode, TotpDisplay, UnlockOutcome, VaultController, VaultPhase,
    WorkspaceTab, current_unix_seconds, open_vault_blocking,
};

const SECRET_CLIPBOARD_TTL: Duration = Duration::from_secs(30);

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
    /// Search input inside the unlocked browser.
    pub search_edit: TextEdit,
    /// Template or `.env` source editor inside the inject tool view.
    pub inject_edit: TextEdit,
    /// Output file path editor for private no-clobber saves.
    pub save_path_edit: TextEdit,
    /// Background worker for KDBX open/KDF so the UI frame loop never stalls.
    pub unlock_worker: Latest<(u64, UnlockOutcome)>,
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
            search_edit: TextEdit::new(""),
            inject_edit,
            save_path_edit: TextEdit::new(""),
            unlock_worker: Latest::default(),
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

    /// Locks the vault, clears secret clipboard leases, and wipes secret inputs.
    pub fn lock_and_clear(&mut self, tx: &mut Tx) {
        self.master_input.replace_text("");
        self.search_edit.replace_text("");
        self.unlock_worker.cancel();
        if let Some(copy) = self.secret_copy.take() {
            copy.clear_now();
        }
        tx.clear_secret_clipboard();
        self.controller.lock();
    }

    /// Handles window deactivation by immediately locking and purging secrets.
    pub fn handle_focus_lost(&mut self, tx: &mut Tx) {
        self.master_input.replace_text("");
        self.search_edit.replace_text("");
        self.unlock_worker.cancel();
        if let Some(copy) = self.secret_copy.take() {
            copy.clear_now();
        }
        tx.clear_secret_clipboard();
        self.controller.on_window_focus(false);
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
            WorkspaceTab::Browser => self.controller.browser_status = Some(msg),
            WorkspaceTab::Inject => self.controller.inject_status = Some(msg),
        }
    }

    /// Polls background unlock completions, idle timeout, and live TOTP updates.
    pub fn poll_frame(&mut self, secs: f64, tx: &mut Tx) -> bool {
        self.clock_secs = secs;
        let mut changed = false;

        if let Some((generation, outcome)) = self.unlock_worker.take() {
            self.controller.finish_unlock(generation, outcome, secs);
            self.search_edit.replace_text("");
            tx.instant();
            changed = true;
        }

        let idle_cleanup = self.controller.check_idle_timeout(secs);
        if idle_cleanup.locked_active_session {
            self.master_input.replace_text("");
            self.search_edit.replace_text("");
            if let Some(copy) = self.secret_copy.take() {
                copy.clear_now();
            }
            tx.clear_secret_clipboard();
            changed = true;
        }

        if self.controller.is_unlocked() {
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
        }

        changed
    }
}

/// Builds the top-level Rune element tree for `nkpui`.
pub fn view(state: &AppState, cx: &mut Cx<AppState>) -> El {
    let dark = cx.system_dark();
    let k = Kit::neutral(dark);

    let header = header_bar(&k, state);
    let body = match state.controller.phase {
        VaultPhase::Locked | VaultPhase::Unlocking => lock_view(&k, state),
        VaultPhase::Unlocked => match state.controller.active_tab {
            WorkspaceTab::Browser => browser_view(&k, state),
            WorkspaceTab::Inject => inject_view(&k, state),
        },
    };

    col()
        .key("nkpui-root")
        .role("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_base)
        .on_window_focus(|s: &mut AppState, focused: bool, tx: &mut Tx| {
            if !focused {
                s.handle_focus_lost(tx);
            }
        })
        .child(header)
        .child(Divider::horizontal().build(&k))
        .child(body.grow(1.0).min_h(0.0))
}

fn header_bar(k: &Kit, state: &AppState) -> El {
    let title = row()
        .gap(8.0)
        .center_y()
        .child(
            text("neo-keepass")
                .font(k.ty.ui_medium)
                .color(k.c.text_base),
        )
        .child(
            Badge::new(match state.controller.phase {
                VaultPhase::Locked => "Locked",
                VaultPhase::Unlocking => "Unlocking",
                VaultPhase::Unlocked => "Unlocked",
            })
            .variant(match state.controller.phase {
                VaultPhase::Unlocked => BadgeVariant::Accent,
                VaultPhase::Unlocking => BadgeVariant::Subtle,
                VaultPhase::Locked => BadgeVariant::Neutral,
            })
            .build(k),
        );

    let mut right = row().gap(8.0).center_y();
    if let Some(copy) = &state.secret_copy {
        let label = match copy.state() {
            SecretState::Pending => "Clipboard: pending",
            SecretState::Holding => "Clipboard: holding (30s)",
            SecretState::Cleared => "Clipboard: cleared",
            SecretState::Replaced => "Clipboard: replaced",
            SecretState::Failed(_) => "Clipboard: wipe refused",
        };
        right = right.child(Badge::new(label).variant(BadgeVariant::Subtle).build(k));
    }

    if state.controller.is_unlocked() {
        let browser_btn = Button::new("Browser")
            .control_size(ControlSize::Regular)
            .variant(if state.controller.active_tab == WorkspaceTab::Browser {
                ButtonVariant::Contrast
            } else {
                ButtonVariant::Ghost
            })
            .on_press(|s: &mut AppState| {
                s.controller.record_activity(s.clock_secs);
                s.controller.active_tab = WorkspaceTab::Browser;
            })
            .build(k);

        let inject_btn = Button::new("Inject / .env")
            .control_size(ControlSize::Regular)
            .variant(if state.controller.active_tab == WorkspaceTab::Inject {
                ButtonVariant::Contrast
            } else {
                ButtonVariant::Ghost
            })
            .on_press(|s: &mut AppState| {
                s.controller.record_activity(s.clock_secs);
                s.controller.active_tab = WorkspaceTab::Inject;
            })
            .build(k);

        let lock_btn = Button::new("Lock")
            .control_size(ControlSize::Regular)
            .variant(ButtonVariant::Danger)
            .on_press_tx(|s: &mut AppState, tx: &mut Tx| s.lock_and_clear(tx))
            .build(k);

        right = right.child(browser_btn).child(inject_btn).child(lock_btn);
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

fn lock_view(k: &Kit, state: &AppState) -> El {
    let unlocking = state.controller.phase == VaultPhase::Unlocking;

    let vault_field = TextInput::new(&state.vault_path_edit)
        .label("Vault file path")
        .placeholder("/path/to/vault.kdbx")
        .width(None)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.vault_path_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.vault_path = s.vault_path_edit.text.clone();
        })
        .build(k);

    let key_field = TextInput::new(&state.key_file_edit)
        .label("Key file path (optional)")
        .placeholder("Optional key file path")
        .width(None)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.key_file_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.key_file_path = s.key_file_edit.text.clone();
        })
        .build(k);

    let master_field = TextInput::new(&state.master_input)
        .secure()
        .label("Master password")
        .placeholder("Master password")
        .width(None)
        .disabled(unlocking)
        .on_edit(|s: &mut AppState| &mut s.master_input)
        .on_submit(|s: &mut AppState, _| s.start_unlock())
        .build(k);

    let unlock_btn = Button::new(if unlocking {
        "Unlocking…"
    } else {
        "Unlock Vault"
    })
    .control_size(ControlSize::Large)
    .variant(if unlocking {
        ButtonVariant::Loading
    } else {
        ButtonVariant::Submit
    })
    .disabled(unlocking)
    .on_press(|s: &mut AppState| s.start_unlock())
    .build(k);

    let mut card = col()
        .key("lock-card")
        .w(440.0)
        .padding(24.0)
        .gap(14.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_muted)
        .child(
            text("Unlock KeePass Vault")
                .font(k.ty.body_medium)
                .color(k.c.text_base),
        )
        .child(
            text("KDF runs on a background worker thread; focus loss locks immediately.")
                .font(k.ty.text_xsmall)
                .color(k.c.text_muted),
        )
        .child(labeled_field(k, "Vault (.kdbx)", vault_field))
        .child(labeled_field(k, "Master Password", master_field))
        .child(labeled_field(k, "Key File (optional)", key_field))
        .child(row().w_full().justify_end().child(unlock_btn));

    if let Some(status) = &state.controller.lock_status {
        card = card.child(
            text(status.clone())
                .key("lock-status")
                .font(k.ty.text_small)
                .color(if unlocking {
                    k.c.warning.fg
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
        .padding(24.0)
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
        .child(Divider::vertical().build(k))
        .child(list)
        .child(Divider::vertical().build(k))
        .child(detail.grow(1.0).min_w(0.0))
}

fn group_sidebar(k: &Kit, state: &AppState) -> El {
    let mut col_groups = col()
        .key("group-list")
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(4.0);

    for (idx, (label, _)) in state.controller.breadcrumbs.iter().enumerate() {
        let is_current = idx + 1 == state.controller.breadcrumbs.len();
        let btn = Button::new(format!("↳ {label}"))
            .control_size(ControlSize::Regular)
            .variant(if is_current {
                ButtonVariant::Neutral
            } else {
                ButtonVariant::Ghost
            })
            .on_press(move |s: &mut AppState| {
                s.controller.record_activity(s.clock_secs);
                s.controller.navigate_breadcrumb(idx);
            })
            .build(k);
        col_groups = col_groups.child(btn);
    }

    if !state.controller.child_groups.is_empty() {
        col_groups = col_groups.child(Divider::horizontal().build(k));
    }

    for (idx, group) in state.controller.child_groups.iter().enumerate() {
        let btn = Button::new(group.label().to_owned())
            .control_size(ControlSize::Regular)
            .variant(ButtonVariant::GhostMuted)
            .on_press(move |s: &mut AppState| {
                s.controller.record_activity(s.clock_secs);
                s.controller.open_child_group(idx);
            })
            .build(k);
        col_groups = col_groups.child(btn);
    }

    col()
        .key("group-sidebar")
        .w(210.0)
        .h_full()
        .padding(12.0)
        .gap(8.0)
        .fill(k.c.layer_01)
        .child(text("Groups").font(k.ty.small_medium).color(k.c.text_muted))
        .child(col_groups)
}

fn entry_list_pane(k: &Kit, state: &AppState) -> El {
    let search_box = TextInput::new(&state.search_edit)
        .label("Search vault entries")
        .placeholder("Search title, user, URL, path…")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.search_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.record_activity(s.clock_secs);
            let query = s.search_edit.text.clone();
            s.controller.set_search_query(query, current_unix_seconds());
        })
        .build(k);

    let mut list = col()
        .key("entry-list")
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(4.0);

    if state.controller.entries.is_empty() {
        list = list.child(
            text("No entries in this view")
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    } else {
        for (idx, hit) in state.controller.entries.iter().enumerate() {
            let selected = state.controller.selected_index == Some(idx);
            let row_btn = col()
                .key(format!("entry-row-{idx}"))
                .w_full()
                .padding(8.0)
                .gap(2.0)
                .radius(k.radius.md)
                .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
                .focusable(true)
                .hover(k.c.hover)
                .press(k.c.pressed)
                .on_press(move |s: &mut AppState| {
                    s.controller.record_activity(s.clock_secs);
                    s.controller.select_entry(idx, current_unix_seconds());
                })
                .child(
                    text(hit.title().to_owned())
                        .font(k.ty.ui_medium)
                        .color(k.c.text_base)
                        .truncate(),
                )
                .child(
                    text(hit.path().to_owned())
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_muted)
                        .truncate(),
                );
            list = list.child(row_btn);
        }
    }

    col()
        .key("entry-list-pane")
        .w(270.0)
        .h_full()
        .padding(12.0)
        .gap(10.0)
        .child(search_box)
        .child(list)
}

fn entry_detail_pane(k: &Kit, state: &AppState) -> El {
    let mut pane = col()
        .key("entry-detail-pane")
        .h_full()
        .padding(16.0)
        .gap(12.0)
        .scroll(ScrollSpec::default());

    if let Some(status) = &state.controller.browser_status {
        pane = pane.child(
            text(status.clone())
                .key("browser-status")
                .font(k.ty.text_small)
                .color(k.c.info.fg),
        );
    }

    let Some(detail) = &state.controller.detail else {
        return pane.child(
            text("Select an entry to inspect its fields")
                .font(k.ty.ui)
                .color(k.c.text_muted),
        );
    };

    pane = pane
        .child(
            text(detail.metadata.title().to_owned())
                .font(k.ty.body_medium)
                .color(k.c.text_base),
        )
        .child(
            text(detail.path.clone())
                .font(k.ty.text_xsmall)
                .color(k.c.text_muted),
        )
        .child(Divider::horizontal().build(k))
        .child(metadata_row(k, "UserName", &detail.username))
        .child(metadata_row(k, "URL", &detail.url))
        .child(password_row(k, detail))
        .child(metadata_row(k, "Notes", &detail.notes));

    if let Some(totp) = &detail.totp {
        pane = pane.child(totp_row(k, totp));
    }

    if !detail.metadata.custom_fields().is_empty() {
        pane = custom_fields_section(k, pane, detail);
    }

    pane
}

fn custom_fields_section(k: &Kit, mut pane: El, detail: &EntryDetailState) -> El {
    pane = pane.child(Divider::horizontal().build(k)).child(
        text("Custom Fields")
            .font(k.ty.small_medium)
            .color(k.c.text_muted),
    );
    for (idx, field) in detail.metadata.custom_fields().iter().enumerate() {
        let revealed = detail.revealed_custom_fields.get(&idx);
        let value_el = if let Some(secret) = revealed {
            text(secret.as_str().to_owned())
                .font(k.ty.mono)
                .color(k.c.text_base)
                .secure()
                .revealed(true)
        } else {
            text("••••••••••••")
                .font(k.ty.mono)
                .color(k.c.text_muted)
                .secure()
        };

        let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
            .control_size(ControlSize::Small)
            .on_press(move |s: &mut AppState| {
                s.controller.record_activity(s.clock_secs);
                s.controller.toggle_reveal_custom_field(idx);
            })
            .build(k);

        let field_name = field.name().to_owned();
        let copy_btn = Button::new("Copy")
            .control_size(ControlSize::Small)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.controller.record_activity(s.clock_secs);
                match s.controller.custom_field_for_copy(idx) {
                    Ok(secret) => s.copy_secret(&secret, &field_name, tx),
                    Err(err) => s.controller.browser_status = Some(err),
                }
            })
            .build(k);

        pane = pane.child(
            row()
                .key(format!("custom-field-{idx}"))
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
                        .gap(2.0)
                        .child(
                            text(field.name().to_owned())
                                .font(k.ty.small_medium)
                                .color(k.c.text_muted),
                        )
                        .child(value_el),
                )
                .child(row().gap(6.0).child(reveal_btn).child(copy_btn)),
        );
    }
    pane
}

fn metadata_row(k: &Kit, label: &str, value: &str) -> El {
    let shown = if value.is_empty() { "—" } else { value };
    col()
        .w_full()
        .padding(8.0)
        .gap(2.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(
            text(label.to_owned())
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        )
        .child(text(shown.to_owned()).font(k.ty.ui).color(k.c.text_base))
}

fn password_row(k: &Kit, detail: &EntryDetailState) -> El {
    let revealed = detail.revealed_password.as_ref();
    let value_el = if let Some(secret) = revealed {
        text(secret.as_str().to_owned())
            .key("password-value")
            .font(k.ty.mono)
            .color(k.c.text_base)
            .secure()
            .revealed(true)
    } else {
        text("••••••••••••")
            .key("password-value")
            .font(k.ty.mono)
            .color(k.c.text_muted)
            .secure()
    };

    let reveal_btn = Button::new(if revealed.is_some() { "Hide" } else { "Reveal" })
        .control_size(ControlSize::Small)
        .on_press(|s: &mut AppState| {
            s.controller.record_activity(s.clock_secs);
            s.controller.toggle_reveal_password();
        })
        .build(k);

    let copy_btn = Button::new("Copy (30s)")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.controller.record_activity(s.clock_secs);
            match s.controller.password_for_copy() {
                Ok(secret) => s.copy_secret(&secret, "Password", tx),
                Err(err) => s.controller.browser_status = Some(err),
            }
        })
        .build(k);

    row()
        .key("password-row")
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
                .gap(2.0)
                .child(
                    text("Password")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(value_el),
        )
        .child(row().gap(6.0).child(reveal_btn).child(copy_btn))
}

fn totp_row(k: &Kit, totp: &TotpDisplay) -> El {
    let copy_btn = Button::new("Copy TOTP")
        .control_size(ControlSize::Small)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.controller.record_activity(s.clock_secs);
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
        .build(k);

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
                .gap(2.0)
                .child(
                    text(format!(
                        "TOTP ({}s / {}s)",
                        totp.remaining_secs, totp.period
                    ))
                    .font(k.ty.small_medium)
                    .color(k.c.text_muted),
                )
                .child(
                    text(totp.code.as_str().to_owned())
                        .font(k.ty.mono)
                        .color(k.c.text_base)
                        .secure()
                        .revealed(true),
                ),
        )
        .child(copy_btn)
}

fn inject_view(k: &Kit, state: &AppState) -> El {
    let mode_row = row()
        .gap(8.0)
        .center_y()
        .child(
            Button::new("Template (render_text)")
                .control_size(ControlSize::Regular)
                .variant(if state.controller.inject_mode == InjectMode::Template {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .on_press(|s: &mut AppState| {
                    s.controller.record_activity(s.clock_secs);
                    s.controller.set_inject_mode(InjectMode::Template);
                })
                .build(k),
        )
        .child(
            Button::new(".env (parse_env_file)")
                .control_size(ControlSize::Regular)
                .variant(if state.controller.inject_mode == InjectMode::EnvFile {
                    ButtonVariant::Contrast
                } else {
                    ButtonVariant::Neutral
                })
                .on_press(|s: &mut AppState| {
                    s.controller.record_activity(s.clock_secs);
                    s.controller.set_inject_mode(InjectMode::EnvFile);
                })
                .build(k),
        );

    let editor = TextArea::new(&state.inject_edit)
        .label("Template or .env input")
        .placeholder("export API_TOKEN=nkp://Group/Entry#Password")
        .rows(6)
        .max_height(160.0)
        .scroll_bar(true)
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.inject_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.record_activity(s.clock_secs);
            let input = s.inject_edit.text.clone();
            s.controller.set_inject_input(input);
        })
        .build(k);

    let render_btn = Button::new("Render from Active Vault")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press(|s: &mut AppState| {
            s.controller.record_activity(s.clock_secs);
            if let Err(err) = s.controller.render_inject(current_unix_seconds()) {
                s.controller.inject_status = Some(err.to_string());
            }
        })
        .build(k);

    let mut page = col()
        .key("inject-view")
        .w_full()
        .h_full()
        .padding(16.0)
        .gap(12.0)
        .scroll(ScrollSpec::default())
        .child(
            text("Template & .env Injector (nkp://)")
                .font(k.ty.body_medium)
                .color(k.c.text_base),
        )
        .child(mode_row)
        .child(editor)
        .child(inject_refs_card(k, state))
        .child(row().gap(8.0).child(render_btn));

    if let Some(output) = &state.controller.rendered_output {
        page = inject_output_section(k, state, page, output);
    }

    if let Some(status) = &state.controller.inject_status {
        page = page.child(
            text(status.clone())
                .key("inject-status")
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
            .font(k.ty.small_medium)
            .color(k.c.text_muted),
        );

    if let Some(err) = &state.controller.inject_preview_error {
        refs_box = refs_box.child(text(err.clone()).font(k.ty.text_small).color(k.c.danger.fg));
    } else if state.controller.extracted_refs.is_empty() {
        refs_box = refs_box.child(
            text("No nkp:// references found")
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    } else {
        for (idx, uri) in state.controller.extracted_refs.iter().enumerate() {
            let field = uri.field.as_deref().unwrap_or("Password");
            refs_box = refs_box.child(
                text(format!("• {}  (#{field})", uri.entry_path))
                    .key(format!("inject-ref-{idx}"))
                    .font(k.ty.mono)
                    .color(k.c.text_base),
            );
        }
    }

    refs_box
}

fn inject_output_section(k: &Kit, state: &AppState, page: El, output: &Zeroizing<String>) -> El {
    let revealed = state.controller.inject_output_revealed;
    let output_text = if revealed {
        text(output.as_str().to_owned())
            .font(k.ty.mono)
            .color(k.c.text_base)
            .secure()
            .revealed(true)
    } else {
        text("••••••••••••")
            .font(k.ty.mono)
            .color(k.c.text_muted)
            .secure()
    };

    let toggle_btn = Button::new(if revealed {
        "Hide Output"
    } else {
        "Reveal Output"
    })
    .control_size(ControlSize::Small)
    .on_press(|s: &mut AppState| {
        s.controller.record_activity(s.clock_secs);
        s.controller.inject_output_revealed = !s.controller.inject_output_revealed;
    })
    .build(k);

    let copy_btn = Button::new("Copy Output (30s)")
        .control_size(ControlSize::Small)
        .variant(ButtonVariant::Contrast)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.controller.record_activity(s.clock_secs);
            if let Some(rendered) = s.controller.rendered_output.clone() {
                s.copy_secret(&rendered, "rendered output", tx);
            }
        })
        .build(k);

    let save_path_box = TextInput::new(&state.save_path_edit)
        .label("Private output file path")
        .placeholder("/path/to/rendered.env (no-clobber)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.save_path_edit)
        .on_change(|s: &mut AppState, _| {
            s.controller.inject_save_path = s.save_path_edit.text.clone();
        })
        .build(k);

    let save_btn = Button::new("Save Private File")
        .control_size(ControlSize::Regular)
        .on_press(|s: &mut AppState| {
            s.controller.record_activity(s.clock_secs);
            let _ = s.controller.save_inject_output();
        })
        .build(k);

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
                    .w_full()
                    .justify_between()
                    .center_y()
                    .child(
                        text("Rendered Output")
                            .font(k.ty.small_medium)
                            .color(k.c.text_muted),
                    )
                    .child(row().gap(6.0).child(toggle_btn).child(copy_btn)),
            )
            .child(output_text),
    )
    .child(
        row()
            .w_full()
            .gap(8.0)
            .center_y()
            .child(save_path_box.grow(1.0).min_w(0.0))
            .child(save_btn),
    )
}

fn labeled_field(k: &Kit, label: &str, field: El) -> El {
    col()
        .w_full()
        .gap(4.0)
        .child(
            text(label.to_owned())
                .font(k.ty.small_medium)
                .color(k.c.text_muted),
        )
        .child(field)
}
