//! Explicit interactive frontend. Secret text is held only in a zeroizing,
//! time-limited widget buffer; terminal scrollback and screenshots remain outside
//! the application's control.

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::clipboard::{ArboardAdapter, ClipboardCopyOutcome, ClipboardLease};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use neotales_keepass::KdbxCredentials;
use nkeepass::{
    KDBX_LIMITS, SearchHit, VaultService,
    glob::Glob,
    service::{EntryRef, GroupRef, ListCursor, ListPage, TreeCursor, TreeGroup},
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_QUERY: usize = 4096;
const MAX_PATH_FILTER: usize = nkeepass::service::MAX_LIST_PATTERN_BYTES;
const REVEAL_TTL: Duration = Duration::from_secs(15);
const CLIPBOARD_TTL: Duration = Duration::from_secs(30);
const IDLE_LOCK: Duration = Duration::from_secs(300);
const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_INTERCHANGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Query,
    Edit,
    PasswordReveal,
    ClipboardCopy,
    TotpReveal,
    Generate,
    GenerateConfirm,
    AddAttachment,
    AddGroup,
    AddEntry,
    ExportAttachment,
    RemoveAttachment,
    ExportInterchange,
    ImportInterchange,
    RevealField,
}

struct UiGroup {
    label: String,
    path: String,
    reference: Option<GroupRef>,
}

impl From<(String, GroupRef)> for UiGroup {
    fn from((path, reference): (String, GroupRef)) -> Self {
        let label = path.rsplit('/').next().unwrap_or(&path).to_owned();
        Self {
            label,
            path,
            reference: Some(reference),
        }
    }
}

impl UiGroup {
    fn from_path(path: String) -> Self {
        let label = path.rsplit('/').next().unwrap_or(&path).to_owned();
        Self {
            label,
            path,
            reference: None,
        }
    }
}

#[derive(Clone, Copy)]
enum DeleteKind {
    Entry,
    Group,
}

enum Modal {
    Help {
        scroll: usize,
    },
    Palette {
        selected: usize,
        scroll: usize,
    },
    Aliases {
        scroll: usize,
    },
    ConfirmDelete {
        kind: DeleteKind,
        path: String,
        entry: Option<EntryRef>,
        group: Option<GroupRef>,
        input: Zeroizing<String>,
    },
}

enum TreeOrListPage {
    Tree(Vec<SearchHit>),
    List(ListPage),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingDecision {
    Exit,
    Lock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionInput {
    RequestExit,
    RequestLock,
    SaveSucceeded,
    SaveFailed,
    Discard,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionEffect {
    None,
    Exit,
    Lock,
}

/// Pure lifecycle reducer shared by the q and idle-lock paths.
fn reduce_decision(
    pending: Option<PendingDecision>,
    dirty: bool,
    input: DecisionInput,
) -> (Option<PendingDecision>, DecisionEffect) {
    match input {
        DecisionInput::RequestExit if dirty => (Some(PendingDecision::Exit), DecisionEffect::None),
        DecisionInput::RequestLock if dirty => (Some(PendingDecision::Lock), DecisionEffect::None),
        DecisionInput::RequestExit => (None, DecisionEffect::Exit),
        DecisionInput::RequestLock => (None, DecisionEffect::Lock),
        DecisionInput::SaveSucceeded | DecisionInput::Discard => match pending {
            Some(PendingDecision::Exit) => (None, DecisionEffect::Exit),
            Some(PendingDecision::Lock) => (None, DecisionEffect::Lock),
            None => (None, DecisionEffect::None),
        },
        DecisionInput::SaveFailed => (pending, DecisionEffect::None),
        DecisionInput::Cancel => (None, DecisionEffect::None),
    }
}

fn needs_decision(dirty: bool, uncommitted_edit: bool) -> bool {
    dirty || uncommitted_edit
}

fn save_service(
    service: &mut VaultService,
    path: &Path,
    credentials: &mut KdbxCredentials,
) -> Result<(), String> {
    service
        .save(path, credentials)
        .map_err(|error| clean(error.message()))
}

struct App {
    service: VaultService,
    session: nkeepass::SessionId,
    hits: Vec<SearchHit>,
    groups: Vec<UiGroup>,
    tree_parent: GroupRef,
    tree_stack: Vec<GroupRef>,
    tree_cursor: Option<TreeCursor>,
    list_cursor: Option<ListCursor>,
    selected: usize,
    query: Zeroizing<String>,
    query_before_input: Zeroizing<String>,
    entry: Option<EntryRef>,
    detail: Vec<String>,
    fields: Vec<(String, bool)>,
    selected_field: usize,
    edit_field: String,
    reveal: Option<Zeroizing<String>>,
    reveal_until: Option<Instant>,
    status: String,
    last_activity: Instant,
    locked: bool,
    input_mode: bool,
    edit_mode: bool,
    input: Zeroizing<String>,
    action: Action,
    pending_group: Option<GroupRef>,
    dirty: bool,
    pending_decision: Option<PendingDecision>,
    attachment_selected: usize,
    field_to_reveal: Zeroizing<String>,
    generation_size: usize,
    clipboard: ClipboardLease<ArboardAdapter>,
    clipboard_may_contain_password: bool,
    include_groups: bool,
    aliases: Vec<String>,
    modal: Option<Modal>,
}

fn clear_input(input: &mut Zeroizing<String>) {
    input.zeroize();
}

fn update_live_query(query: &mut Zeroizing<String>, input: &str) {
    query.zeroize();
    query.push_str(input);
}

fn cancel_live_query(
    query: &mut Zeroizing<String>,
    previous: &mut Zeroizing<String>,
    input: &mut Zeroizing<String>,
) {
    query.zeroize();
    query.push_str(previous);
    previous.zeroize();
    input.zeroize();
}

fn entry_index_for_selection(
    searching: bool,
    group_count: usize,
    selected: usize,
    hit_count: usize,
) -> Option<usize> {
    let index = if searching {
        selected
    } else {
        selected.checked_sub(group_count)?
    };
    (index < hit_count).then_some(index)
}

fn reset_tree_location<T>(parent: &mut T, stack: &mut Vec<T>, root: T) {
    *parent = root;
    stack.clear();
}

fn discard_input_draft(
    input: &mut Zeroizing<String>,
    field_to_reveal: &mut Zeroizing<String>,
    input_mode: &mut bool,
    edit_mode: &mut bool,
) {
    clear_input(input);
    clear_input(field_to_reveal);
    *input_mode = false;
    *edit_mode = false;
}

fn submit_edit_draft(
    field: &str,
    input: &mut Zeroizing<String>,
    input_mode: &mut bool,
    edit_mode: &mut bool,
    set_field: impl FnOnce(&str, &str) -> Result<(), String>,
) -> String {
    if field.is_empty() {
        return "No field selected; draft retained".into();
    }
    if field.len() > 256 || input.len() > 64 * 1024 {
        return "Field input exceeds its limit; draft retained".into();
    }

    match set_field(field, input) {
        Ok(()) => {
            clear_input(input);
            *input_mode = false;
            *edit_mode = false;
            "Field updated in memory; press s to save".into()
        }
        Err(error) => format!(
            "{}; draft retained (retry or Esc to discard)",
            clean(&error)
        ),
    }
}

fn move_field_selection(selected: &mut usize, field_count: usize, down: bool) {
    if down {
        *selected = selected
            .saturating_add(1)
            .min(field_count.saturating_sub(1));
    } else {
        *selected = selected.saturating_sub(1);
    }
}

fn select_field_for_reveal(
    fields: &[(String, bool)],
    selected: usize,
    field_to_reveal: &mut Zeroizing<String>,
) -> bool {
    clear_input(field_to_reveal);
    let Some((field, _)) = fields.get(selected) else {
        return false;
    };
    field_to_reveal.push_str(field);
    true
}

fn approve_field_reveal(
    input: &str,
    field_to_reveal: &mut Zeroizing<String>,
) -> Option<Zeroizing<String>> {
    if input != "YES" || field_to_reveal.is_empty() {
        clear_input(field_to_reveal);
        return None;
    }
    Some(Zeroizing::new(std::mem::take(&mut **field_to_reveal)))
}

fn field_row(name: &str, protected: bool, selected: bool) -> String {
    format!(
        "{} {} [{}]",
        if selected { ">" } else { " " },
        clean(name),
        if protected { "protected" } else { "plain" }
    )
}

fn handle_focus_lost(
    input_mode: &mut bool,
    edit_mode: &mut bool,
    input: &mut Zeroizing<String>,
    field_to_reveal: &mut Zeroizing<String>,
) {
    clear_input(field_to_reveal);
    if *input_mode && *edit_mode {
        // Keep the masked, zeroizing draft active so idle lock and exit still
        // require an explicit save, discard, or cancel decision.
        return;
    }
    clear_input(input);
    *input_mode = false;
    *edit_mode = false;
}

fn bounded_read(path: &Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input is not a regular file",
        ));
    }
    let mut file = File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn begin_action(app: &mut App, action: Action, prompt: &str) {
    app.clear_reveal();
    app.action = action;
    app.input_mode = true;
    clear_input(&mut app.input);
    prompt.clone_into(&mut app.status);
}

fn selected_group(app: &App) -> Option<GroupRef> {
    if app.entry.is_none()
        && let Some(group) = app.groups.get(app.selected)
    {
        return group
            .reference
            .clone()
            .or_else(|| app.service.resolve_group(app.session, &group.path).ok());
    }
    Some(app.tree_parent.clone())
}

fn begin_delete_entry(app: &mut App) {
    let selected = app
        .selected
        .checked_sub(app.groups.len())
        .and_then(|index| app.hits.get(index));
    let reference = app
        .entry
        .clone()
        .or_else(|| selected.map(SearchHit::reference));
    let Some(reference) = reference else {
        app.status = "Select an entry before choosing Remove entry".into();
        return;
    };
    let path = selected.map_or_else(|| "selected entry".to_owned(), |hit| hit.path().to_owned());
    app.modal = Some(Modal::ConfirmDelete {
        kind: DeleteKind::Entry,
        path,
        entry: Some(reference),
        group: None,
        input: Zeroizing::new(String::new()),
    });
}

fn begin_delete_group(app: &mut App) {
    let Some(group) = app.groups.get(app.selected) else {
        app.status = "Select a group before choosing Remove group".into();
        return;
    };
    let reference = group
        .reference
        .clone()
        .or_else(|| app.service.resolve_group(app.session, &group.path).ok());
    let Some(reference) = reference else {
        app.status = "Cannot select group for deletion".into();
        return;
    };
    app.modal = Some(Modal::ConfirmDelete {
        kind: DeleteKind::Group,
        path: group.path.clone(),
        entry: None,
        group: Some(reference),
        input: Zeroizing::new(String::new()),
    });
}

fn select_palette_action(app: &mut App, selected: usize) {
    app.modal = None;
    match selected {
        0 => begin_add(app, Action::AddGroup),
        1 => begin_add(app, Action::AddEntry),
        2 => begin_delete_entry(app),
        3 => begin_delete_group(app),
        4 => app.modal = Some(Modal::Aliases { scroll: 0 }),
        _ => {}
    }
}

fn begin_add(app: &mut App, action: Action) {
    app.pending_group = selected_group(app);
    let (action, prompt) = match action {
        Action::AddGroup => (
            Action::AddGroup,
            "New group name · Enter create · Esc cancel",
        ),
        Action::AddEntry => (
            Action::AddEntry,
            "New entry title · Enter create · Esc cancel",
        ),
        _ => return,
    };
    begin_action(app, action, prompt);
}

fn finish_delete(
    app: &mut App,
    kind: DeleteKind,
    entry: Option<&EntryRef>,
    group: Option<&GroupRef>,
) {
    let result = match kind {
        DeleteKind::Entry => entry
            .ok_or(nkeepass::ServiceError::NotFound)
            .and_then(|reference| app.service.remove_entry(reference)),
        DeleteKind::Group => group
            .ok_or(nkeepass::ServiceError::NotFound)
            .and_then(|reference| app.service.remove_group(reference)),
    };
    match result {
        Ok(()) => {
            app.dirty = true;
            app.entry = None;
            app.detail.clear();
            app.fields.clear();
            app.reset_tree_after_mutation();
            app.refresh();
            app.status = match kind {
                DeleteKind::Entry => "Entry removed in memory; press s to save".into(),
                DeleteKind::Group => "Group removed in memory; press s to save".into(),
            };
        }
        Err(error) => app.status = clean(error.message()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "modal variants share ownership and focus handling"
)]
fn handle_modal_key(app: &mut App, key: KeyCode) {
    let Some(modal) = app.modal.take() else {
        return;
    };
    match modal {
        Modal::Help { mut scroll } => match key {
            KeyCode::Esc => {}
            KeyCode::Up | KeyCode::Char('k') => {
                scroll = scroll.saturating_sub(1);
                app.modal = Some(Modal::Help { scroll });
            }
            KeyCode::Down | KeyCode::Char('j') => {
                scroll = scroll.saturating_add(1);
                app.modal = Some(Modal::Help { scroll });
            }
            KeyCode::PageUp => {
                scroll = scroll.saturating_sub(10);
                app.modal = Some(Modal::Help { scroll });
            }
            KeyCode::PageDown => {
                scroll = scroll.saturating_add(10);
                app.modal = Some(Modal::Help { scroll });
            }
            _ => app.modal = Some(Modal::Help { scroll }),
        },
        Modal::Aliases { mut scroll } => match key {
            KeyCode::Esc => {}
            KeyCode::Up | KeyCode::Char('k') => {
                scroll = scroll.saturating_sub(1);
                app.modal = Some(Modal::Aliases { scroll });
            }
            KeyCode::Down | KeyCode::Char('j') => {
                scroll = scroll.saturating_add(1);
                app.modal = Some(Modal::Aliases { scroll });
            }
            KeyCode::PageUp => {
                scroll = scroll.saturating_sub(10);
                app.modal = Some(Modal::Aliases { scroll });
            }
            KeyCode::PageDown => {
                scroll = scroll.saturating_add(10);
                app.modal = Some(Modal::Aliases { scroll });
            }
            _ => app.modal = Some(Modal::Aliases { scroll }),
        },
        Modal::Palette {
            mut selected,
            mut scroll,
        } => match key {
            KeyCode::Esc => {}
            KeyCode::Up | KeyCode::Char('k') => {
                selected = selected.saturating_sub(1);
                scroll = selected.saturating_sub(3);
                app.modal = Some(Modal::Palette { selected, scroll });
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected = selected.saturating_add(1).min(4);
                scroll = selected.saturating_sub(3);
                app.modal = Some(Modal::Palette { selected, scroll });
            }
            KeyCode::Enter => select_palette_action(app, selected),
            _ => app.modal = Some(Modal::Palette { selected, scroll }),
        },
        Modal::ConfirmDelete {
            kind,
            path,
            entry,
            group,
            mut input,
        } => match key {
            KeyCode::Esc => {
                clear_input(&mut input);
                app.status = "Deletion cancelled".into();
            }
            KeyCode::Backspace => {
                let length = input.chars().count().saturating_sub(1);
                let remaining = input.chars().take(length).collect::<String>();
                clear_input(&mut input);
                input.push_str(&remaining);
                app.modal = Some(Modal::ConfirmDelete {
                    kind,
                    path,
                    entry,
                    group,
                    input,
                });
            }
            KeyCode::Char(value) if input.len() < 3 && value.is_ascii_alphabetic() => {
                input.push(value);
                app.modal = Some(Modal::ConfirmDelete {
                    kind,
                    path,
                    entry,
                    group,
                    input,
                });
            }
            KeyCode::Enter if deletion_confirmed(&input) => {
                clear_input(&mut input);
                finish_delete(app, kind, entry.as_ref(), group.as_ref());
            }
            KeyCode::Enter => {
                clear_input(&mut input);
                app.status = "Deletion not confirmed".into();
            }
            _ => {
                app.modal = Some(Modal::ConfirmDelete {
                    kind,
                    path,
                    entry,
                    group,
                    input,
                });
            }
        },
    }
}

fn create_group_or_entry(app: &mut App, action: Action, name: &str) {
    let Some(parent) = app.pending_group.take() else {
        app.status = "No parent group selected".into();
        return;
    };
    if name.is_empty()
        || name.contains('/')
        || matches!(name, "." | "..")
        || name.chars().any(char::is_control)
    {
        app.status = "Name must be a non-empty path component".into();
        return;
    }
    let result = match action {
        Action::AddGroup => app.service.add_group(&parent, name).map(|()| true),
        Action::AddEntry => match app.service.group_path(&parent) {
            Ok(path) => {
                app.service
                    .ensure_entry(app.session, &format!("{path}/{name}"), None, false)
            }
            Err(error) => Err(error),
        },
        _ => return,
    };
    match result {
        Ok(true) => {
            app.dirty = true;
            app.reset_tree_after_mutation();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = match action {
                Action::AddGroup => "Group added in memory; press s to save".into(),
                Action::AddEntry => "Entry added in memory; press s to save".into(),
                _ => unreachable!(),
            };
        }
        Ok(false) => app.status = "An entry with that title already exists".into(),
        Err(error) => app.status = clean(error.message()),
    }
}

fn reveal_password(app: &mut App) {
    let Some(reference) = &app.entry else { return };
    match app.service.reveal_field(reference, "Password") {
        Ok(bytes) => match std::str::from_utf8(bytes.as_slice()) {
            Ok(value) => {
                app.clear_reveal();
                app.reveal = Some(Zeroizing::new(value.to_owned()));
                app.reveal_until = Some(Instant::now() + REVEAL_TTL);
            }
            Err(_) => app.status = "Password is not valid UTF-8".into(),
        },
        Err(error) => app.status = clean(error.message()),
    }
}

fn copy_password(app: &mut App) {
    let Some(reference) = &app.entry else { return };
    let Ok(bytes) = app.service.reveal_field(reference, "Password") else {
        app.status = "Cannot copy password to clipboard".into();
        return;
    };
    let Ok(value) = std::str::from_utf8(bytes.as_slice()) else {
        app.status = "Cannot copy password to clipboard".into();
        return;
    };
    match app.clipboard.copy(Zeroizing::new(value.to_owned())) {
        Ok(ClipboardCopyOutcome::Copied) => {
            app.clipboard_may_contain_password = true;
            app.status = if app.clipboard.supports_timed_clear() {
                "Password copied; an ownership-safe clear will be attempted after 30s. Verify manually; it may remain.".into()
            } else {
                "Password copied; this platform cannot safely auto-clear it. Clear manually; it may remain.".into()
            };
        }
        Ok(ClipboardCopyOutcome::MayHaveCopied) => {
            app.clipboard_may_contain_password = true;
            app.status = "Clipboard write may have succeeded; clear it manually. A timed clear will be attempted if ownership was captured.".into();
        }
        Ok(ClipboardCopyOutcome::RejectedNul) => {
            app.status = "Password contains NUL; it was not copied".into();
        }
        Err(_) => app.status = "Clipboard unavailable; password was not copied".into(),
    }
}

fn reveal_selected_field(app: &mut App, field: &str) {
    let Some(reference) = &app.entry else { return };
    match app.service.reveal_field(reference, field) {
        Ok(bytes) => match std::str::from_utf8(bytes.as_slice()) {
            Ok(value) => {
                app.clear_reveal();
                app.reveal = Some(Zeroizing::new(value.to_owned()));
                app.reveal_until = Some(Instant::now() + REVEAL_TTL);
                app.status =
                    "Field revealed for 15s; terminal scrollback/screenshots may persist".into();
            }
            Err(_) => app.status = "Field is not valid UTF-8".into(),
        },
        Err(error) => app.status = clean(error.message()),
    }
}

fn reveal_totp(app: &mut App) {
    let Some(reference) = &app.entry else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match app.service.totp_code_with_period(reference, now) {
        Ok(code) => {
            app.clear_reveal();
            app.reveal = Some(Zeroizing::new(code.code().to_owned()));
            let remaining = code.period().saturating_sub(now % code.period()).max(1);
            app.reveal_until = Some(Instant::now() + Duration::from_secs(remaining));
            app.status = format!(
                "TOTP shown until period rolls (about {remaining}s); terminal scrollback may persist"
            );
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn attachment_add(app: &mut App, text: &str) {
    let Some((name, path)) = text.split_once('=') else {
        app.status = "Use name=source-path".into();
        return;
    };
    if name.is_empty() || path.is_empty() {
        app.status = "Use name=source-path".into();
        return;
    }
    let Some(reference) = app.entry.clone() else {
        return;
    };
    match bounded_read(Path::new(path), MAX_ATTACHMENT_BYTES) {
        Ok(bytes) => match app.service.add_attachment(&reference, name, bytes) {
            Ok(()) => {
                app.dirty = true;
                app.reset_tree_after_mutation();
                app.entry = None;
                app.detail.clear();
                app.refresh();
                app.status = "Attachment added; save to persist".into();
            }
            Err(error) => app.status = clean(error.message()),
        },
        Err(_) => app.status = "Cannot read attachment or it exceeds 16 MiB".into(),
    }
}

fn attachment_export(app: &mut App, path: &str) {
    let Some(reference) = app.entry.clone() else {
        return;
    };
    let Ok(attachments) = app.service.attachment_metadata(&reference) else {
        app.status = "Cannot list attachments".into();
        return;
    };
    let Some(selected) = attachments.get(app.attachment_selected) else {
        app.status = "No attachment selected".into();
        return;
    };
    if selected.size() > MAX_ATTACHMENT_BYTES {
        app.status = "Attachment exceeds the 16 MiB export limit".into();
        return;
    }
    let result = app
        .service
        .reveal_attachment(&selected.reference())
        .map_err(|_| "cannot read attachment")
        .and_then(|bytes| {
            nkeepass::private_file::write_private_noclobber(Path::new(path), bytes.as_slice())
        });
    app.status = result.map_or_else(str::to_owned, |()| {
        "Attachment exported to a new owner-only file".into()
    });
}

fn attachment_remove(app: &mut App, name: &str) {
    let Some(reference) = app.entry.clone() else {
        return;
    };
    match app.service.remove_attachment(&reference, name) {
        Ok(()) => {
            app.dirty = true;
            app.reset_tree_after_mutation();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = "Attachment removed; save to persist".into();
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn snapshot_export(app: &mut App, path: &str) {
    match app.service.export_snapshot() {
        Ok(snapshot) => {
            app.status =
                nkeepass::private_file::write_private_noclobber(Path::new(path), snapshot.bytes())
                    .map_or_else(str::to_owned, |()| {
                        "Interchange exported to a new owner-only file".into()
                    });
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn snapshot_import(app: &mut App, path: &str) {
    let Ok(bytes) = bounded_read(Path::new(path), MAX_INTERCHANGE_BYTES) else {
        app.status = "Cannot read interchange file or it exceeds 16 MiB".into();
        return;
    };
    match app
        .service
        .import_snapshot(&bytes, nkeepass::service::ImportOptions::default())
    {
        Ok(_) => {
            app.dirty = true;
            app.reset_tree_after_mutation();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = "Interchange imported; save to persist".into();
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn clean(input: &str) -> String {
    let mut output = String::new();
    for c in input.chars() {
        if c.is_control() || c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}

fn clean_secret(input: &str) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::new());
    for c in input.chars() {
        if c.is_control() || c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}

fn matching_group_paths(paths: &[String], pattern: &str, include_groups: bool) -> Vec<String> {
    if !include_groups {
        return Vec::new();
    }
    let glob = Glob::new(pattern);
    paths
        .iter()
        .filter(|path| glob.is_match(path))
        .cloned()
        .collect()
}

fn deletion_confirmed(input: &str) -> bool {
    input == "YES"
}

impl App {
    fn visible_row_count(&self) -> usize {
        self.groups.len().saturating_add(self.hits.len())
    }

    fn list_groups(&mut self, tree_groups: Vec<TreeGroup>) {
        self.groups = tree_groups
            .into_iter()
            .filter_map(|group| {
                let reference = group.reference();
                self.service
                    .group_path(&reference)
                    .ok()
                    .map(|path| UiGroup::from((path, reference)))
            })
            .collect();
    }

    fn matching_groups(&mut self, pattern: &str) -> Result<Vec<UiGroup>, nkeepass::ServiceError> {
        let paths = self.service.completion_metadata()?.groups;
        Ok(matching_group_paths(&paths, pattern, self.include_groups)
            .into_iter()
            .map(UiGroup::from_path)
            .collect())
    }

    fn refresh(&mut self) {
        if let Some(cursor) = self.tree_cursor.take() {
            let _ = self.service.release_tree_cursor(cursor);
        }
        if let Some(cursor) = self.list_cursor.take() {
            let _ = self.service.release_list_cursor(cursor);
        }
        self.entry = None;
        self.detail.clear();
        self.fields.clear();
        self.clear_reveal();
        self.hits.clear();
        self.groups.clear();
        let page = if self.query.is_empty() {
            let result = self.service.tree_page(&self.tree_parent, None);
            let result = if matches!(&result, Err(error) if *error == nkeepass::ServiceError::Stale)
            {
                if let Ok(root) = self.service.root_group(self.session) {
                    self.tree_parent = root;
                    self.tree_stack.clear();
                    self.service.tree_page(&self.tree_parent, None)
                } else {
                    result
                }
            } else {
                result
            };
            result.map(|page| {
                self.list_groups(page.groups);
                self.tree_cursor = page.next_cursor;
                page.entries
            })
        } else {
            let pattern = self.query.to_string();
            let groups = self.matching_groups(&pattern);
            let entries = self
                .service
                .list_page(self.session, Some(&pattern), None)
                .map(|page| {
                    self.list_cursor = page.next_cursor;
                    page.hits
                });
            match (groups, entries) {
                (Ok(groups), Ok(entries)) => {
                    self.groups = groups;
                    Ok(entries)
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        match page {
            Ok(hits) => {
                self.hits = hits;
                self.selected = self
                    .selected
                    .min(self.visible_row_count().saturating_sub(1));
                self.status = format!(
                    "{} groups, {} entries{} · / path glob · g toggle groups · ? help · Ctrl-P palette · q quit",
                    self.groups.len(),
                    self.hits.len(),
                    if self.tree_cursor.is_some() || self.list_cursor.is_some() {
                        " · more available"
                    } else {
                        ""
                    }
                );
            }
            Err(error) => {
                self.hits.clear();
                self.status = clean(error.message());
            }
        }
    }

    fn reset_tree_after_mutation(&mut self) {
        if let Some(cursor) = self.tree_cursor.take() {
            let _ = self.service.release_tree_cursor(cursor);
        }
        if let Ok(root) = self.service.root_group(self.session) {
            reset_tree_location(&mut self.tree_parent, &mut self.tree_stack, root);
        }
    }

    fn next_page(&mut self) {
        self.clear_reveal();
        self.hits.clear();
        let page = if self.query.is_empty() {
            self.groups.clear();
            self.tree_cursor
                .take()
                .map(|cursor| self.service.tree_page(&self.tree_parent, Some(cursor)))
                .transpose()
                .map(|page| {
                    page.map(|page| {
                        self.list_groups(page.groups);
                        self.tree_cursor = page.next_cursor;
                        TreeOrListPage::Tree(page.entries)
                    })
                })
        } else {
            self.list_cursor
                .take()
                .map(|cursor| {
                    self.service
                        .list_page(self.session, Some(&self.query), Some(cursor))
                })
                .transpose()
                .map(|page| {
                    page.map(|page| {
                        self.list_cursor = page.next_cursor;
                        TreeOrListPage::List(page)
                    })
                })
        };
        match page {
            Ok(Some(TreeOrListPage::Tree(hits))) => {
                self.selected = 0;
                self.hits = hits;
                self.status = format!(
                    "{} groups, {} entries{} · n next page · Enter open · ? help · q quit",
                    self.groups.len(),
                    self.hits.len(),
                    if self.tree_cursor.is_some() {
                        " · more available"
                    } else {
                        ""
                    }
                );
            }
            Ok(Some(TreeOrListPage::List(page))) => {
                self.selected = self.groups.len();
                self.hits = page.hits;
                self.status = format!(
                    "{} groups, {} entries{} · n next page · Enter open · q quit",
                    self.groups.len(),
                    self.hits.len(),
                    if self.list_cursor.is_some() {
                        " · more available"
                    } else {
                        ""
                    }
                );
            }
            Ok(None) => self.status = "No more entries".into(),
            Err(error) => self.status = clean(error.message()),
        }
    }

    fn select(&mut self) {
        self.clear_reveal();
        self.attachment_selected = 0;
        if self.selected < self.groups.len() {
            let path = self.groups[self.selected].path.clone();
            let group = self.groups[self.selected]
                .reference
                .clone()
                .or_else(|| self.service.resolve_group(self.session, &path).ok());
            let Some(group) = group else {
                self.status = "Cannot open selected group".into();
                return;
            };
            self.tree_stack.push(self.tree_parent.clone());
            self.tree_parent = group;
            self.query.zeroize();
            self.selected = 0;
            self.refresh();
            return;
        }
        let Some(entry_index) =
            entry_index_for_selection(false, self.groups.len(), self.selected, self.hits.len())
        else {
            return;
        };
        let Some(hit) = self.hits.get(entry_index) else {
            return;
        };
        let reference = hit.reference();
        match self.service.selected_entry(&reference) {
            Ok(view) => {
                self.detail = vec![
                    format!("Title: {}", clean(view.title())),
                    format!(
                        "Tags: {}",
                        view.tags()
                            .iter()
                            .map(|s| clean(s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    format!(
                        "OTP: {} · Auto-type: {} ({} associations)",
                        if view.has_otp() { "present" } else { "none" },
                        if view.auto_type_enabled() {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        view.auto_type_associations()
                    ),
                    "Fields (values hidden):".to_owned(),
                ];
                self.fields = view
                    .fields()
                    .iter()
                    .map(|field| (field.name().to_owned(), field.protected()))
                    .collect();
                self.selected_field = self.selected_field.min(self.fields.len().saturating_sub(1));
                self.detail.push("Attachments:".to_owned());
                self.detail
                    .extend(view.attachments().iter().enumerate().map(|(index, a)| {
                        format!(
                            "{} {} ({} bytes)",
                            if index == self.attachment_selected {
                                ">"
                            } else {
                                " "
                            },
                            clean(a.name()),
                            a.size()
                        )
                    }));
                self.entry = Some(reference);
                self.status = "↑/↓ select field · e edit value · r reveal password for 15s · s save · Esc back".into();
            }
            Err(error) => self.status = clean(error.message()),
        }
    }

    fn clear_reveal(&mut self) {
        if let Some(mut reveal) = self.reveal.take() {
            reveal.zeroize();
        }
        self.reveal_until = None;
    }

    fn tick(&mut self) {
        if self
            .reveal_until
            .is_some_and(|until| Instant::now() >= until)
        {
            self.clear_reveal();
            self.status = "Transient reveal expired".into();
        }
        match self.clipboard.tick(Instant::now()) {
            Ok(Some(true)) => {
                self.clipboard_may_contain_password = false;
                self.status = "Clipboard lease expired and clipboard was cleared".into();
            }
            Ok(Some(false)) | Err(_) => {
                self.clipboard_may_contain_password = true;
                self.status = "Clipboard expiry could not safely clear it; it may still contain the password. Clear it manually.".into();
            }
            Ok(None) => {}
        }
        if !self.locked
            && self.pending_decision.is_none()
            && self.last_activity.elapsed() >= IDLE_LOCK
        {
            let (pending, effect) = reduce_decision(
                self.pending_decision,
                needs_decision(
                    self.dirty,
                    self.input_mode && self.edit_mode && !self.input.is_empty(),
                ),
                DecisionInput::RequestLock,
            );
            self.pending_decision = pending;
            if effect == DecisionEffect::None {
                self.status =
                    "Idle lock requested. Unsaved changes: s save · d discard · c cancel".into();
                self.last_activity = Instant::now();
                return;
            }
            self.lock_vault();
        }
    }

    fn lock_vault(&mut self) {
        self.clear_reveal();
        let had_clipboard_lease = self.clipboard.has_lease();
        if had_clipboard_lease {
            match self.clipboard.release() {
                Ok(true) => self.clipboard_may_contain_password = false,
                Ok(false) | Err(_) => self.clipboard_may_contain_password = true,
            }
        }
        let clipboard_warning = self.clipboard_may_contain_password;
        self.query.zeroize();
        self.query_before_input.zeroize();
        clear_input(&mut self.input);
        clear_input(&mut self.field_to_reveal);
        self.edit_field.clear();
        self.input_mode = false;
        self.edit_mode = false;
        self.pending_group = None;
        self.modal = None;
        self.action = Action::Query;
        if let Some(cursor) = self.tree_cursor.take() {
            let _ = self.service.release_tree_cursor(cursor);
        }
        self.list_cursor = None;
        let _ = self.service.lock(self.session);
        self.groups.clear();
        self.hits.clear();
        self.entry = None;
        self.detail.clear();
        self.fields.clear();
        self.locked = true;
        self.status = if clipboard_warning {
            "Vault locked; clipboard may still contain the password. Clear it manually. Press q to exit.".into()
        } else {
            "Vault locked after 5 minutes idle. Press q to exit.".into()
        };
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the compact two-pane Ratatui projection together"
)]
fn draw(frame: &mut Frame<'_>, app: &App) {
    let reveal_render = app.reveal.as_deref().map(|value| clean_secret(value));
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(areas[1]);
    let groups_state = if app.include_groups {
        "groups included"
    } else {
        "entries only"
    };
    let path_filter = if app.query.is_empty() {
        "(none)".to_owned()
    } else {
        clean(&app.query)
    };
    frame.render_widget(
        Paragraph::new(format!(
            "Path filter: {path_filter}  ·  {groups_state}  ·  / edit  ·  g toggle groups"
        )),
        areas[0],
    );
    let items = app
        .groups
        .iter()
        .map(|group| {
            ListItem::new(Line::from(vec![
                Span::styled("▸ ", Style::default().fg(Color::Cyan)),
                Span::raw(clean(if app.query.is_empty() {
                    &group.label
                } else {
                    &group.path
                })),
            ]))
        })
        .chain(app.hits.iter().map(|hit| {
            ListItem::new(Line::from(vec![
                Span::raw(if app.query.is_empty() { "  " } else { "" }),
                Span::raw(clean(hit.title())),
                Span::styled(
                    format!("  {}", clean(hit.path())),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        }))
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select((!app.locked && app.entry.is_none()).then_some(app.selected));
    let title = if app.locked {
        "LOCKED".to_owned()
    } else if app.query.is_empty() {
        let path = app
            .service
            .group_path(&app.tree_parent)
            .map_or_else(|_| "current folder".to_owned(), |path| clean(&path));
        format!("Vault tree · ▾ {path} · ▸ child folders")
    } else {
        "Path matches · Enter opens group/entry".to_owned()
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        body[0],
        &mut state,
    );
    let mut detail = app
        .detail
        .iter()
        .flat_map(|line| {
            let mut rows = vec![Line::from(line.clone())];
            if line == "Fields (values hidden):" {
                rows.extend(
                    app.fields
                        .iter()
                        .enumerate()
                        .map(|(index, (name, protected))| {
                            let text = field_row(name, *protected, index == app.selected_field);
                            if index == app.selected_field {
                                Line::from(Span::styled(
                                    text,
                                    Style::default()
                                        .fg(Color::Yellow)
                                        .add_modifier(Modifier::BOLD),
                                ))
                            } else {
                                Line::from(text)
                            }
                        }),
                );
            }
            rows
        })
        .collect::<Vec<_>>();
    if app.input_mode && !app.locked {
        detail.push(Line::from(if app.edit_mode {
            format!("Edit: {}", "•".repeat(app.input.len()))
        } else {
            format!("Query: {}", clean(&app.input))
        }));
    }
    if !app.locked
        && let Some(value) = reveal_render.as_deref()
    {
        detail.push(Line::from(vec![
            Span::raw("REVEALED (15s): "),
            Span::styled(
                value,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]));
        detail.push(Line::from(
            "Warning: terminal scrollback and screenshots persist.",
        ));
    } else if !app.locked && app.entry.is_some() {
        detail.push(Line::from("Password: ••••••••"));
    }
    if needs_decision(
        app.dirty,
        app.input_mode && app.edit_mode && !app.input.is_empty(),
    ) {
        detail.push(Line::from(Span::styled(
            "UNSAVED CHANGES",
            Style::default().fg(Color::Yellow),
        )));
    }
    if !app.locked && app.entry.is_some() {
        detail.push(Line::from("↑/↓ select field · e edit selected (value only) · r reveal · c copy password · t TOTP · g generate · a add attachment · n/p attachment · x export · d remove · o export · i import · s save"));
    }
    frame.render_widget(
        Paragraph::new(detail).block(
            Block::default()
                .title(if app.locked {
                    "LOCKED"
                } else if app.pending_decision == Some(PendingDecision::Lock) {
                    "IDLE LOCK PENDING · unsaved changes"
                } else {
                    "Entry detail · secrets masked"
                })
                .borders(Borders::ALL),
        ),
        body[1],
    );
    frame.render_widget(
        Paragraph::new(clean(&app.status)).block(Block::default().borders(Borders::TOP)),
        areas[2],
    );
    if let Some(modal) = &app.modal {
        draw_modal(frame, modal, &app.aliases);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn help_lines() -> Vec<Line<'static>> {
    [
        "q                 Quit (unsaved changes require a decision)",
        "?                 Open this help; Esc closes it",
        "Ctrl-P            Open command palette",
        "/                 Search paths with glob patterns; Enter applies",
        "g (tree)          Toggle matching groups in path results",
        "Up/Down or j/k    Move selection",
        "Enter             Open selected group or entry",
        "Backspace         Go to parent group (when path filter is empty)",
        "n                 Load next result page",
        "a / e             Add group / entry beneath selected or current group",
        "x / X             Remove selected entry / group (type YES to confirm)",
        "s                 Save unsaved vault changes",
        "d                 Discard unsaved changes in exit prompt",
        "c                 Cancel an exit prompt",
        "Ctrl-P palette    Add group, add entry, remove entry/group, view aliases",
        "Entry view:",
        "  e edit selected field · r reveal password · v reveal selected field",
        "  c copy password · t reveal TOTP · g generate password (entry view)",
        "  a add attachment · x export attachment · d remove attachment",
        "  o export interchange · i import interchange · s save",
        "  Esc/Enter back to tree · n/p select attachment",
        "Palette/help/aliases: Up/Down or j/k scroll; Esc closes",
        "Deletion confirmation requires typing YES exactly.",
    ]
    .into_iter()
    .map(Line::from)
    .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the small modal renderer together"
)]
fn draw_modal(frame: &mut Frame<'_>, modal: &Modal, aliases: &[String]) {
    let area = centered_rect(78, 78, frame.area());
    frame.render_widget(Clear, area);
    match modal {
        Modal::Help { scroll } => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1)])
                .split(area);
            frame.render_widget(
                Tabs::new(vec![Line::from("Keybindings")]).select(0).block(
                    Block::default()
                        .title("Help · Tab 1/1")
                        .borders(Borders::ALL),
                ),
                chunks[0],
            );
            frame.render_widget(
                Paragraph::new(help_lines())
                    .wrap(Wrap { trim: false })
                    .scroll((u16::try_from(*scroll).unwrap_or(u16::MAX), 0))
                    .block(Block::default().borders(Borders::ALL)),
                chunks[1],
            );
        }
        Modal::Palette { selected, scroll } => {
            let choices = [
                "Add group",
                "Add entry",
                "Remove entry",
                "Remove group",
                "View aliases",
            ];
            let rows = choices
                .iter()
                .enumerate()
                .map(|(index, label)| {
                    let marker = if index == *selected { "> " } else { "  " };
                    ListItem::new(format!("{marker}{label}"))
                })
                .collect::<Vec<_>>();
            let mut state = ListState::default();
            state.select(Some(*selected));
            frame.render_stateful_widget(
                List::new(rows)
                    .block(
                        Block::default()
                            .title("Command palette · Enter select · Esc close")
                            .borders(Borders::ALL),
                    )
                    .highlight_style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                area,
                &mut state,
            );
            let _ = scroll;
        }
        Modal::Aliases { scroll } => {
            let lines = if aliases.is_empty() {
                vec![Line::from("No aliases configured")]
            } else {
                aliases
                    .iter()
                    .map(|alias| Line::from(clean(alias)))
                    .collect()
            };
            frame.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((u16::try_from(*scroll).unwrap_or(u16::MAX), 0))
                    .block(
                        Block::default()
                            .title("Aliases · Esc close")
                            .borders(Borders::ALL),
                    ),
                area,
            );
        }
        Modal::ConfirmDelete {
            kind, path, input, ..
        } => {
            let label = match kind {
                DeleteKind::Entry => "entry",
                DeleteKind::Group => "group and all its contents",
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(format!("Remove {label}?")),
                    Line::from(clean(path)),
                    Line::from("Type YES and press Enter to confirm; Esc cancels."),
                    Line::from(format!("Confirmation: {}", clean(input))),
                ])
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .title("Confirm deletion")
                        .borders(Borders::ALL),
                ),
                area,
            );
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the compact reducer and terminal lifecycle together"
)]
fn run_ui(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    credentials: &mut KdbxCredentials,
    path: &Path,
) -> io::Result<()> {
    let mut reveal_was_drawn = false;
    loop {
        let was_revealed = reveal_was_drawn;
        app.tick();
        if was_revealed && app.reveal.is_none() {
            // Drop Ratatui's retained frame/cell contents and repaint the screen.
            // This does not erase terminal-emulator scrollback or screenshots.
            terminal.clear()?;
        }
        terminal.draw(|frame| draw(frame, app))?;
        reveal_was_drawn = app.reveal.is_some();
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let event = event::read()?;
        if matches!(event, Event::FocusLost) {
            app.clear_reveal();
            app.modal = None;
            app.pending_group = None;
            let query_was_active = app.input_mode && app.action == Action::Query;
            handle_focus_lost(
                &mut app.input_mode,
                &mut app.edit_mode,
                &mut app.input,
                &mut app.field_to_reveal,
            );
            if query_was_active {
                app.query_before_input.zeroize();
            }
            continue;
        }
        let Event::Key(key) = event else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        app.last_activity = Instant::now();
        if app.locked {
            if key.code == KeyCode::Char('q') {
                break;
            }
            continue;
        }
        if let Some(pending) = app.pending_decision {
            let input = match key.code {
                KeyCode::Char('s') => DecisionInput::SaveSucceeded,
                KeyCode::Char('d') => DecisionInput::Discard,
                KeyCode::Char('c') | KeyCode::Esc => DecisionInput::Cancel,
                _ => continue,
            };
            let effect = if input == DecisionInput::SaveSucceeded
                && app.edit_mode
                && app.input_mode
                && !app.input.is_empty()
            {
                app.status =
                    "Finish or cancel the pending edit before saving; press c to return to it"
                        .into();
                DecisionInput::SaveFailed
            } else if input == DecisionInput::SaveSucceeded {
                match app.service.save(path, credentials) {
                    Ok(()) => {
                        app.dirty = false;
                        app.status = "Saved".into();
                        DecisionInput::SaveSucceeded
                    }
                    Err(error) => {
                        app.status = format!(
                            "Save failed: {}. Choose save, discard, or cancel",
                            clean(error.message())
                        );
                        DecisionInput::SaveFailed
                    }
                }
            } else if input == DecisionInput::Discard {
                app.dirty = false;
                discard_input_draft(
                    &mut app.input,
                    &mut app.field_to_reveal,
                    &mut app.input_mode,
                    &mut app.edit_mode,
                );
                app.edit_field.clear();
                DecisionInput::Discard
            } else {
                DecisionInput::Cancel
            };
            let (next, effect) = reduce_decision(Some(pending), app.dirty, effect);
            app.pending_decision = next;
            match effect {
                DecisionEffect::Exit => break,
                DecisionEffect::Lock => app.lock_vault(),
                DecisionEffect::None if next.is_none() => {
                    app.last_activity = Instant::now();
                    app.status = "Decision cancelled; returned to the vault".into();
                }
                DecisionEffect::None => {}
            }
            continue;
        }
        if !app.input_mode && key.code == KeyCode::Char('q') {
            let (pending, effect) = reduce_decision(
                app.pending_decision,
                needs_decision(
                    app.dirty,
                    app.input_mode && app.edit_mode && !app.input.is_empty(),
                ),
                DecisionInput::RequestExit,
            );
            app.pending_decision = pending;
            if effect == DecisionEffect::Exit {
                break;
            }
            app.status = "Unsaved changes: s save · d discard · c cancel".into();
            continue;
        }
        if app.modal.is_some() {
            handle_modal_key(app, key.code);
            continue;
        }
        if !app.input_mode
            && key.code == KeyCode::Char('p')
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            app.modal = Some(Modal::Palette {
                selected: 0,
                scroll: 0,
            });
            continue;
        }
        if !app.input_mode && key.code == KeyCode::Char('?') {
            app.modal = Some(Modal::Help { scroll: 0 });
            continue;
        }
        if app.input_mode {
            match key.code {
                KeyCode::Esc => {
                    if app.action == Action::Query {
                        cancel_live_query(
                            &mut app.query,
                            &mut app.query_before_input,
                            &mut app.input,
                        );
                        app.input_mode = false;
                        app.edit_mode = false;
                        app.refresh();
                    } else {
                        discard_input_draft(
                            &mut app.input,
                            &mut app.field_to_reveal,
                            &mut app.input_mode,
                            &mut app.edit_mode,
                        );
                        app.edit_field.clear();
                        app.pending_group = None;
                    }
                }
                KeyCode::Backspace => {
                    let retained_chars = app.input.chars().count().saturating_sub(1);
                    let mut remaining =
                        Zeroizing::new(app.input.chars().take(retained_chars).collect::<String>());
                    clear_input(&mut app.input);
                    app.input.push_str(&remaining);
                    clear_input(&mut remaining);
                    if app.action == Action::Query {
                        update_live_query(&mut app.query, &app.input);
                        app.refresh();
                    }
                }
                KeyCode::Enter if app.edit_mode => {
                    let reference = app.entry.clone();
                    let status = submit_edit_draft(
                        &app.edit_field,
                        &mut app.input,
                        &mut app.input_mode,
                        &mut app.edit_mode,
                        |field, value| {
                            let Some(reference) = reference.as_ref() else {
                                return Err("No selected entry".into());
                            };
                            app.service
                                .set_field(reference, field, value)
                                .map_err(|error| error.message().to_owned())
                        },
                    );
                    let succeeded = !app.input_mode;
                    app.status = status;
                    if succeeded {
                        app.edit_field.clear();
                        app.dirty = true;
                        app.reset_tree_after_mutation();
                        app.entry = None;
                        app.detail.clear();
                        app.refresh();
                    }
                }
                KeyCode::Enter if !app.edit_mode && app.action != Action::Query => {
                    let value = Zeroizing::new(app.input.to_string());
                    match app.action {
                        Action::PasswordReveal => {
                            if value.as_str() == "YES" {
                                reveal_password(app);
                            } else {
                                app.status = "Reveal cancelled; type YES to confirm".into();
                            }
                        }
                        Action::ClipboardCopy => {
                            if value.as_str() == "YES" {
                                copy_password(app);
                            } else {
                                app.status = "Clipboard copy cancelled".into();
                            }
                        }
                        Action::TotpReveal => {
                            if value.as_str() == "YES" {
                                reveal_totp(app);
                            } else {
                                app.status = "TOTP reveal cancelled".into();
                            }
                        }
                        Action::Generate => match value.parse::<usize>() {
                            Ok(size @ 1..=4096) => {
                                app.generation_size = size;
                                begin_action(
                                    app,
                                    Action::GenerateConfirm,
                                    "This replaces the current password. Type YES to confirm; any other input cancels.",
                                );
                            }
                            _ => app.status = "Password size must be 1..=4096".into(),
                        },
                        Action::GenerateConfirm => {
                            if value.as_str() == "YES" {
                                if let Some(reference) = &app.entry {
                                    match app
                                        .service
                                        .generate_entry_password(reference, app.generation_size)
                                    {
                                        Ok(()) => {
                                            app.dirty = true;
                                            app.reset_tree_after_mutation();
                                            app.status =
                                                "Password replaced in memory; save to persist"
                                                    .into();
                                            app.entry = None;
                                            app.detail.clear();
                                            app.refresh();
                                        }
                                        Err(error) => app.status = clean(error.message()),
                                    }
                                }
                            } else {
                                app.status = "Password generation cancelled".into();
                            }
                        }
                        Action::AddAttachment => attachment_add(app, &value),
                        Action::ExportAttachment => attachment_export(app, &value),
                        Action::RemoveAttachment => attachment_remove(app, &value),
                        Action::AddGroup | Action::AddEntry => {
                            create_group_or_entry(app, app.action, &value);
                            app.pending_group = None;
                        }
                        Action::ExportInterchange => snapshot_export(app, &value),
                        Action::ImportInterchange => snapshot_import(app, &value),
                        Action::RevealField => {
                            if let Some(field) =
                                approve_field_reveal(&value, &mut app.field_to_reveal)
                            {
                                reveal_selected_field(app, &field);
                            } else if value.as_str() == "YES" {
                                app.status = "No field selected".into();
                            } else {
                                app.status = "Field reveal cancelled".into();
                            }
                        }
                        Action::Query | Action::Edit => unreachable!(),
                    }
                    clear_input(&mut app.input);
                    app.input_mode = false;
                    app.edit_mode = false;
                }
                KeyCode::Enter => {
                    app.query.zeroize();
                    app.query.push_str(&app.input);
                    app.query_before_input.zeroize();
                    clear_input(&mut app.input);
                    app.input_mode = false;
                    app.refresh();
                }
                KeyCode::Char(c)
                    if !c.is_control()
                        && app.input.len() + c.len_utf8()
                            <= if app.edit_mode {
                                64 * 1024
                            } else if app.action == Action::Query {
                                MAX_PATH_FILTER
                            } else {
                                MAX_QUERY
                            } =>
                {
                    app.input.push(c);
                    if app.action == Action::Query {
                        update_live_query(&mut app.query, &app.input);
                        app.refresh();
                    }
                }
                _ => {}
            }
        } else if app.entry.is_none() {
            match key.code {
                KeyCode::Char('n') => app.next_page(),
                KeyCode::Char('s') => match save_service(&mut app.service, path, credentials) {
                    Ok(()) => {
                        app.dirty = false;
                        app.status = "Saved".into();
                    }
                    Err(error) => app.status = error,
                },
                KeyCode::Char('a') => begin_add(app, Action::AddGroup),
                KeyCode::Char('e') => begin_add(app, Action::AddEntry),
                KeyCode::Char('x') => begin_delete_entry(app),
                KeyCode::Char('X') => begin_delete_group(app),
                KeyCode::Char('g') => {
                    app.include_groups = !app.include_groups;
                    if app.query.is_empty() {
                        app.status = if app.include_groups {
                            "Path results will include matching groups".into()
                        } else {
                            "Path results will include entries only".into()
                        };
                    } else {
                        app.refresh();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.clear_reveal();
                    app.selected = app
                        .selected
                        .saturating_add(1)
                        .min(app.visible_row_count().saturating_sub(1));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.clear_reveal();
                    app.selected = app.selected.saturating_sub(1);
                }
                KeyCode::Enter => app.select(),
                KeyCode::Backspace if app.query.is_empty() => {
                    if let Some(parent) = app.tree_stack.pop() {
                        app.clear_reveal();
                        app.tree_parent = parent;
                        app.selected = 0;
                        app.refresh();
                    }
                }
                KeyCode::Char('/') => {
                    app.clear_reveal();
                    app.input_mode = true;
                    clear_input(&mut app.input);
                    app.query_before_input.zeroize();
                    app.query_before_input.push_str(&app.query);
                    app.action = Action::Query;
                    app.edit_mode = false;
                    app.input.push_str(&app.query);
                    app.status =
                        "Path glob (max 1024 bytes); type to filter · Enter done · Esc cancel"
                            .into();
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    app.entry = None;
                    app.detail.clear();
                    app.fields.clear();
                    app.clear_reveal();
                }
                KeyCode::Char('e') => {
                    app.clear_reveal();
                    let Some((field, _)) = app.fields.get(app.selected_field) else {
                        app.status = "No field selected".into();
                        continue;
                    };
                    if field == "Title" {
                        app.status = "Title cannot be edited as a field".into();
                        continue;
                    }
                    field.clone_into(&mut app.edit_field);
                    app.input_mode = true;
                    app.edit_mode = true;
                    app.action = Action::Edit;
                    clear_input(&mut app.input);
                    app.status = format!(
                        "Edit {} value; input is masked · Enter apply · Esc cancel",
                        clean(&app.edit_field)
                    );
                }
                KeyCode::Char('g') => {
                    begin_action(
                        app,
                        Action::Generate,
                        "Enter new password length (1..=4096). Confirming replaces the old password; save persists it.",
                    );
                }
                KeyCode::Char('r') => {
                    begin_action(
                        app,
                        Action::PasswordReveal,
                        "Reveal password? Type YES. WARNING: terminal scrollback and screenshots may retain it; shown for 15s.",
                    );
                }
                KeyCode::Char('c') => begin_action(
                    app,
                    Action::ClipboardCopy,
                    if app.clipboard.supports_timed_clear() {
                        "Copy password? Other apps can read it. Windows will attempt an ownership-safe clear in 30s, but it may remain. Type YES to confirm."
                    } else {
                        "Copy password? Other apps can read it. This platform cannot safely auto-clear; clear manually when done. Type YES to confirm."
                    },
                ),
                KeyCode::Char('t') => begin_action(
                    app,
                    Action::TotpReveal,
                    "Reveal current TOTP? Type YES. HOTP is unsupported. WARNING: terminal scrollback may retain the code.",
                ),
                KeyCode::Char('v') => {
                    if !select_field_for_reveal(
                        &app.fields,
                        app.selected_field,
                        &mut app.field_to_reveal,
                    ) {
                        app.status = "No field selected".into();
                        continue;
                    }
                    begin_action(
                        app,
                        Action::RevealField,
                        "Reveal selected field? Type YES. Warning: terminal scrollback and screenshots may persist.",
                    );
                }
                KeyCode::Char('a') => begin_action(
                    app,
                    Action::AddAttachment,
                    "Add attachment as name=source-path (bounded to 16 MiB)",
                ),
                KeyCode::Char('x') => begin_action(
                    app,
                    Action::ExportAttachment,
                    "Export selected attachment to a NEW owner-only path; no overwrite. Enter destination.",
                ),
                KeyCode::Char('d') => begin_action(
                    app,
                    Action::RemoveAttachment,
                    "Enter exact attachment name to remove",
                ),
                KeyCode::Char('o') => begin_action(
                    app,
                    Action::ExportInterchange,
                    "Export interchange to a new owner-only path; no overwrite. Enter destination.",
                ),
                KeyCode::Char('i') => begin_action(
                    app,
                    Action::ImportInterchange,
                    "Import interchange from path (max 16 MiB); existing non-empty vaults are refused.",
                ),
                KeyCode::Char('n') => {
                    if let Some(reference) = &app.entry
                        && let Ok(items) = app.service.attachment_metadata(reference)
                    {
                        app.attachment_selected = app
                            .attachment_selected
                            .saturating_add(1)
                            .min(items.len().saturating_sub(1));
                        app.status = format!(
                            "Selected attachment {}/{}",
                            app.attachment_selected + 1,
                            items.len()
                        );
                    }
                }
                KeyCode::Char('p') => {
                    app.attachment_selected = app.attachment_selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    move_field_selection(&mut app.selected_field, app.fields.len(), true);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    move_field_selection(&mut app.selected_field, app.fields.len(), false);
                }
                KeyCode::Char('s') => match save_service(&mut app.service, path, credentials) {
                    Ok(()) => {
                        app.dirty = false;
                        app.status = "Saved".into();
                    }
                    Err(error) => app.status = error,
                },
                _ => {}
            }
        }
    }
    app.clear_reveal();
    clear_input(&mut app.input);
    clear_input(&mut app.field_to_reveal);
    app.edit_field.clear();
    app.query.zeroize();
    app.query_before_input.zeroize();
    let _ = app.clipboard.release();
    let _ = app.service.lock(app.session);
    Ok(())
}

/// Starts the explicitly selected TUI command and restores the terminal through
/// Ratatui's `run` lifecycle wrapper, including unwind/error paths.
pub fn launch(path: &Path, aliases: Vec<String>) -> io::Result<()> {
    let mut password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    let mut credentials = KdbxCredentials::password(&password)
        .map_err(|_| io::Error::other("invalid credentials"))?;
    password.zeroize();
    drop(password);
    let mut service = VaultService::default();
    let session = service
        .open(path, &mut credentials, &KDBX_LIMITS)
        .map_err(|_| io::Error::other("cannot unlock vault"))?;
    let tree_parent = service
        .root_group(session)
        .map_err(|_| io::Error::other("cannot read vault root"))?;
    let mut app = App {
        service,
        session,
        hits: Vec::new(),
        groups: Vec::new(),
        tree_parent,
        tree_stack: Vec::new(),
        tree_cursor: None,
        list_cursor: None,
        selected: 0,
        query: Zeroizing::new(String::new()),
        query_before_input: Zeroizing::new(String::new()),
        entry: None,
        detail: Vec::new(),
        fields: Vec::new(),
        selected_field: 0,
        edit_field: String::new(),
        reveal: None,
        reveal_until: None,
        status: String::new(),
        last_activity: Instant::now(),
        locked: false,
        input_mode: false,
        edit_mode: false,
        input: Zeroizing::new(String::new()),
        action: Action::Query,
        pending_group: None,
        dirty: false,
        pending_decision: None,
        attachment_selected: 0,
        field_to_reveal: Zeroizing::new(String::new()),
        generation_size: 32,
        clipboard: ClipboardLease::new(ArboardAdapter::default(), CLIPBOARD_TTL),
        clipboard_may_contain_password: false,
        include_groups: true,
        aliases,
        modal: None,
    };
    app.refresh();
    let result = ratatui::run(|terminal| run_ui(terminal, &mut app, &mut credentials, path));
    app.clear_reveal();
    app.query.zeroize();
    app.query_before_input.zeroize();
    clear_input(&mut app.input);
    clear_input(&mut app.field_to_reveal);
    app.edit_field.clear();
    let _ = app.clipboard.release();
    let _ = app.service.lock(app.session);
    result
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn path_filter_globs_group_paths_and_can_hide_groups() {
        let paths = [
            "Root/Work".to_owned(),
            "Root/Work/Archive".to_owned(),
            "Root/Home".to_owned(),
        ];
        assert_eq!(
            super::matching_group_paths(&paths, "Root/Work*", true),
            ["Root/Work", "Root/Work/Archive"]
        );
        assert!(super::matching_group_paths(&paths, "Root/*", false).is_empty());
        assert!(super::deletion_confirmed("YES"));
        assert!(!super::deletion_confirmed("yes"));
        assert!(!super::deletion_confirmed("YES "));
    }

    #[test]
    fn help_modal_documents_quit_palette_and_all_tree_mutations() {
        let help = super::help_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        for binding in ["q", "Ctrl-P", "a / e", "x / X", "type YES"] {
            assert!(help.contains(binding), "help omitted {binding}");
        }
        assert!(
            help.lines().count() > 12,
            "help content should require scrolling"
        );
    }

    #[test]
    fn sanitizes_terminal_controls_without_dropping_following_text() {
        assert_eq!(clean("a\u{1b}[2Jb\u{85}c"), "a\\u{1b}[2Jb\\u{85}c");
    }

    #[test]
    fn bounded_input_rejects_oversized_and_non_regular_sources() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("bounded");
        std::fs::write(&file, b"12345").unwrap();
        assert!(super::bounded_read(&file, 4).is_err());
        assert_eq!(super::bounded_read(&file, 5).unwrap().as_slice(), b"12345");
        assert!(super::bounded_read(directory.path(), 100).is_err());
    }

    #[test]
    fn tree_mutation_can_be_saved_without_opening_an_entry() {
        use super::{KDBX_LIMITS, VaultService, save_service};
        use neotales_keepass::{KdbxCredentials, KdbxWriteOptions};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tree-save.kdbx");
        let mut credentials = KdbxCredentials::password("tree-save-test").unwrap();
        let creator = VaultService::default();
        creator
            .create(
                &path,
                &mut credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..Default::default()
                },
                None,
            )
            .unwrap();

        let mut service = VaultService::default();
        let session = service.open(&path, &mut credentials, &KDBX_LIMITS).unwrap();
        let root = service.root_group(session).unwrap();
        service.add_group(&root, "created-in-tree").unwrap();

        save_service(&mut service, &path, &mut credentials).unwrap();

        let mut reopened = VaultService::default();
        let session = reopened
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .unwrap();
        let root = reopened.root_group(session).unwrap();
        let page = reopened.tree_page(&root, None).unwrap();
        assert_eq!(page.groups.len(), 1);
        assert_eq!(page.groups[0].label(), "created-in-tree");
        assert!(page.entries.is_empty());
    }

    #[test]
    fn clearing_input_erases_the_live_buffer() {
        let mut input = zeroize::Zeroizing::new("transient-value".to_owned());
        super::clear_input(&mut input);
        assert!(input.is_empty());
    }

    #[test]
    fn field_navigation_stays_within_metadata_rows() {
        let mut selected = 0;
        super::move_field_selection(&mut selected, 3, false);
        assert_eq!(selected, 0);
        super::move_field_selection(&mut selected, 3, true);
        assert_eq!(selected, 1);
        super::move_field_selection(&mut selected, 3, true);
        super::move_field_selection(&mut selected, 3, true);
        assert_eq!(selected, 2);
        super::move_field_selection(&mut selected, 0, true);
        assert_eq!(selected, 0);
    }

    #[test]
    fn selected_field_reveal_targets_the_selected_metadata_name() {
        let fields = vec![
            ("Title".to_owned(), false),
            ("Recovery code".to_owned(), true),
            ("Password".to_owned(), true),
        ];
        let mut field_to_reveal = zeroize::Zeroizing::new(String::new());

        assert!(super::select_field_for_reveal(
            &fields,
            1,
            &mut field_to_reveal
        ));
        assert_eq!(field_to_reveal.as_str(), "Recovery code");
    }

    #[test]
    fn selected_field_reveal_requires_yes_and_clears_missing_selection_target() {
        let mut field_to_reveal = zeroize::Zeroizing::new("Recovery code".to_owned());
        let approved = super::approve_field_reveal("YES", &mut field_to_reveal).unwrap();
        assert_eq!(approved.as_str(), "Recovery code");
        assert!(field_to_reveal.is_empty());

        let mut field_to_reveal = zeroize::Zeroizing::new("Recovery code".to_owned());
        assert!(super::approve_field_reveal("yes", &mut field_to_reveal).is_none());
        assert!(field_to_reveal.is_empty());

        let mut field_to_reveal = zeroize::Zeroizing::new("stale field".to_owned());
        assert!(!super::select_field_for_reveal(
            &[],
            0,
            &mut field_to_reveal
        ));
        assert!(super::approve_field_reveal("YES", &mut field_to_reveal).is_none());
        assert!(field_to_reveal.is_empty());
    }

    #[test]
    fn field_rows_render_only_name_and_protection_metadata() {
        let row = super::field_row("Recovery code", true, true);
        assert_eq!(row, "> Recovery code [protected]");
    }

    #[test]
    fn invalid_edit_submission_retains_draft_and_edit_mode() {
        let mut input = zeroize::Zeroizing::new(String::new());
        let mut input_mode = true;
        let mut edit_mode = true;

        let status =
            super::submit_edit_draft("", &mut input, &mut input_mode, &mut edit_mode, |_, _| {
                panic!("invalid draft must not reach the service")
            });

        assert_eq!(status, "No field selected; draft retained");
        assert!(input.is_empty());
        assert!(input_mode);
        assert!(edit_mode);
    }

    #[test]
    fn oversized_edit_submission_retains_draft_and_edit_mode() {
        let mut input = zeroize::Zeroizing::new("x".repeat(64 * 1024 + 1));
        let mut input_mode = true;
        let mut edit_mode = true;

        let status = super::submit_edit_draft(
            "Password",
            &mut input,
            &mut input_mode,
            &mut edit_mode,
            |_, _| panic!("oversized draft must not reach the service"),
        );

        assert_eq!(status, "Field input exceeds its limit; draft retained");
        assert_eq!(input.len(), 64 * 1024 + 1);
        assert!(input_mode);
        assert!(edit_mode);
    }

    #[test]
    fn service_failure_retains_edit_draft_and_sanitizes_feedback() {
        let mut input = zeroize::Zeroizing::new("temporary".to_owned());
        let mut input_mode = true;
        let mut edit_mode = true;

        let status = super::submit_edit_draft(
            "Password",
            &mut input,
            &mut input_mode,
            &mut edit_mode,
            |field, value| {
                assert_eq!(field, "Password");
                assert_eq!(value, "temporary");
                Err("stale\u{1b}[2J reference".to_owned())
            },
        );

        assert_eq!(
            status,
            "stale\\u{1b}[2J reference; draft retained (retry or Esc to discard)"
        );
        assert_eq!(input.as_str(), "temporary");
        assert!(input_mode);
        assert!(edit_mode);
    }

    #[test]
    fn successful_edit_submission_zeroizes_draft_and_exits_edit_mode() {
        let mut input = zeroize::Zeroizing::new("temporary".to_owned());
        let mut input_mode = true;
        let mut edit_mode = true;

        let status = super::submit_edit_draft(
            "Password",
            &mut input,
            &mut input_mode,
            &mut edit_mode,
            |field, value| {
                assert_eq!(field, "Password");
                assert_eq!(value, "temporary");
                Ok(())
            },
        );

        assert_eq!(status, "Field updated in memory; press s to save");
        assert!(input.is_empty());
        assert!(!input_mode);
        assert!(!edit_mode);
    }

    #[test]
    fn focus_loss_keeps_edit_draft_visible_to_idle_lock_guard() {
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};

        let mut input_mode = true;
        let mut edit_mode = true;
        let mut input = zeroize::Zeroizing::new("Password=temporary".to_owned());
        let mut field_to_reveal = zeroize::Zeroizing::new("SecretField".to_owned());

        super::handle_focus_lost(
            &mut input_mode,
            &mut edit_mode,
            &mut input,
            &mut field_to_reveal,
        );

        assert!(input_mode);
        assert!(edit_mode);
        assert_eq!(input.as_str(), "Password=temporary");
        assert!(field_to_reveal.is_empty());
        assert!(super::needs_decision(
            false,
            input_mode && edit_mode && !input.is_empty()
        ));
        assert_eq!(
            super::reduce_decision(None, true, Input::RequestLock),
            (Some(Pending::Lock), Effect::None)
        );
    }

    #[test]
    fn focus_loss_clears_non_edit_input_and_clean_idle_lock_stays_immediate() {
        use super::{DecisionEffect as Effect, DecisionInput as Input};

        let mut input_mode = true;
        let mut edit_mode = false;
        let mut input = zeroize::Zeroizing::new("search text".to_owned());
        let mut field_to_reveal = zeroize::Zeroizing::new("SecretField".to_owned());

        super::handle_focus_lost(
            &mut input_mode,
            &mut edit_mode,
            &mut input,
            &mut field_to_reveal,
        );

        assert!(!input_mode);
        assert!(!edit_mode);
        assert!(input.is_empty());
        assert!(field_to_reveal.is_empty());
        assert_eq!(
            super::reduce_decision(None, false, Input::RequestLock),
            (None, Effect::Lock)
        );
    }

    #[test]
    fn deliberate_draft_discard_zeroizes_input_and_resets_edit_mode() {
        let mut input = zeroize::Zeroizing::new("Password=temporary".to_owned());
        let mut field_to_reveal = zeroize::Zeroizing::new("SecretField".to_owned());
        let mut input_mode = true;
        let mut edit_mode = true;

        super::discard_input_draft(
            &mut input,
            &mut field_to_reveal,
            &mut input_mode,
            &mut edit_mode,
        );

        assert!(input.is_empty());
        assert!(field_to_reveal.is_empty());
        assert!(!input_mode);
        assert!(!edit_mode);
    }

    #[test]
    fn dirty_q_requires_a_deliberate_decision_and_clean_q_exits() {
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};

        assert_eq!(
            super::reduce_decision(None, true, Input::RequestExit),
            (Some(Pending::Exit), Effect::None)
        );
        assert_eq!(
            super::reduce_decision(None, false, Input::RequestExit),
            (None, Effect::Exit)
        );
        assert_eq!(
            super::reduce_decision(Some(Pending::Exit), true, Input::SaveSucceeded),
            (None, Effect::Exit)
        );
        assert_eq!(
            super::reduce_decision(Some(Pending::Exit), true, Input::Discard),
            (None, Effect::Exit)
        );
    }

    #[test]
    fn dirty_idle_lock_stays_visible_until_saved_or_discarded() {
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};

        assert_eq!(
            super::reduce_decision(None, true, Input::RequestLock),
            (Some(Pending::Lock), Effect::None)
        );
        assert_eq!(
            super::reduce_decision(Some(Pending::Lock), true, Input::SaveSucceeded),
            (None, Effect::Lock)
        );
        assert_eq!(
            super::reduce_decision(Some(Pending::Lock), true, Input::Discard),
            (None, Effect::Lock)
        );
        assert_eq!(
            super::reduce_decision(None, false, Input::RequestLock),
            (None, Effect::Lock)
        );
    }

    #[test]
    fn save_failure_keeps_dirty_decision_and_cancel_returns_to_tui() {
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};

        for pending in [Pending::Exit, Pending::Lock] {
            assert_eq!(
                super::reduce_decision(Some(pending), true, Input::SaveFailed),
                (Some(pending), Effect::None)
            );
            assert_eq!(
                super::reduce_decision(Some(pending), true, Input::Cancel),
                (None, Effect::None)
            );
        }
    }

    #[test]
    fn uncommitted_edit_drafts_also_require_a_decision() {
        assert!(super::needs_decision(false, true));
        assert!(super::needs_decision(true, false));
        assert!(!super::needs_decision(false, false));
    }

    #[test]
    fn live_query_tracks_each_input_state_without_enter() {
        let mut query = zeroize::Zeroizing::new(String::new());
        let mut draft = zeroize::Zeroizing::new(String::new());
        draft.push_str("bank");
        super::update_live_query(&mut query, &draft);
        assert_eq!(query.as_str(), "bank");
        draft.pop();
        super::update_live_query(&mut query, &draft);
        assert_eq!(query.as_str(), "ban");
        draft.clear();
        super::update_live_query(&mut query, &draft);
        assert!(query.is_empty());
    }

    #[test]
    fn cancelling_live_search_restores_previous_and_empty_queries() {
        let mut query = zeroize::Zeroizing::new("changed".to_owned());
        let mut previous = zeroize::Zeroizing::new("prior".to_owned());
        let mut input = zeroize::Zeroizing::new("changed".to_owned());
        super::cancel_live_query(&mut query, &mut previous, &mut input);
        assert_eq!(query.as_str(), "prior");
        assert!(previous.is_empty());
        assert!(input.is_empty());

        let mut query = zeroize::Zeroizing::new("temporary".to_owned());
        let mut previous = zeroize::Zeroizing::new(String::new());
        let mut input = zeroize::Zeroizing::new(String::new());
        super::cancel_live_query(&mut query, &mut previous, &mut input);
        assert!(query.is_empty());
    }

    #[test]
    fn combined_tree_rows_select_groups_before_entries_and_never_select_out_of_range() {
        assert_eq!(super::entry_index_for_selection(false, 2, 0, 3), None);
        assert_eq!(super::entry_index_for_selection(false, 2, 2, 3), Some(0));
        assert_eq!(super::entry_index_for_selection(false, 2, 4, 3), Some(2));
        assert_eq!(super::entry_index_for_selection(false, 2, 5, 3), None);
        assert_eq!(super::entry_index_for_selection(true, 0, 1, 3), Some(1));
        assert_eq!(super::entry_index_for_selection(true, 0, 3, 3), None);
    }

    #[test]
    fn mutation_tree_reset_discards_stale_nested_navigation_handles() {
        let root = 0;
        let mut parent = 99;
        let mut stack = vec![1, 2, 3];
        super::reset_tree_location(&mut parent, &mut stack, root);
        assert_eq!(parent, 0);
        assert!(stack.is_empty());
    }
}
