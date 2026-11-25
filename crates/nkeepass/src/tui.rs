//! Explicit interactive frontend. Live input/reveal buffers are zeroizing;
//! credentials are owned until lock/exit. This is not whole-heap erasure:
//! model/rendering copies, terminal scrollback, and screenshots may persist.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsFd;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::clipboard::{ArboardAdapter, ClipboardCopyOutcome, ClipboardLease};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use neotales_keepass::KdbxCredentials;
use nkeepass::{
    CustomIconId, KDBX_LIMITS, SearchHit, VaultService,
    glob::Glob,
    icons::{DEFAULT_GROUP_ICON_ID, IconCategory, StandardIcon, standard_icon, standard_icons},
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
const MIN_COLUMNS: u16 = 40;
const MIN_ROWS: u16 = 12;
const CLIPBOARD_WARNING: &str = "Clipboard could not be safely cleared; it may still contain the password. Clear it manually. Acknowledging does not clear it.";

/// Explicit color preference passed from the CLI `--color` / `NO_COLOR` / `FORCE_COLOR` options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColorOverride {
    Auto,
    Always,
    Never,
    Basic,
    TrueColor,
}

/// Detected terminal color capability tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColorTier {
    TrueColor,
    Ansi256,
    Basic16,
    None,
}

#[allow(clippy::too_many_arguments)]
fn detect_color_tier(
    override_mode: ColorOverride,
    no_color: Option<&OsStr>,
    term: Option<&str>,
    colorterm: Option<&str>,
    wt_session: Option<&OsStr>,
    kitty_window_id: Option<&OsStr>,
    wezterm_pane: Option<&OsStr>,
) -> ColorTier {
    if override_mode == ColorOverride::Never || term == Some("dumb") {
        return ColorTier::None;
    }
    if override_mode == ColorOverride::Auto && no_color.is_some_and(|value| !value.is_empty()) {
        return ColorTier::None;
    }
    if override_mode == ColorOverride::Basic {
        return ColorTier::Basic16;
    }
    if colorterm.is_some_and(|value| {
        value.eq_ignore_ascii_case("truecolor") || value.eq_ignore_ascii_case("24bit")
    }) || wt_session.is_some_and(|value| !value.is_empty())
        || kitty_window_id.is_some_and(|value| !value.is_empty())
        || wezterm_pane.is_some_and(|value| !value.is_empty())
    {
        ColorTier::TrueColor
    } else if term.is_some_and(|value| value.contains("256color")) {
        ColorTier::Ansi256
    } else {
        ColorTier::Basic16
    }
}

fn detect_color_tier_from_env(override_mode: ColorOverride) -> ColorTier {
    let no_color = std::env::var_os("NO_COLOR");
    let term = std::env::var("TERM").ok();
    let colorterm = std::env::var("COLORTERM").ok();
    let wt_session = std::env::var_os("WT_SESSION");
    let kitty_window_id = std::env::var_os("KITTY_WINDOW_ID");
    let wezterm_pane = std::env::var_os("WEZTERM_PANE");
    detect_color_tier(
        override_mode,
        no_color.as_deref(),
        term.as_deref(),
        colorterm.as_deref(),
        wt_session.as_deref(),
        kitty_window_id.as_deref(),
        wezterm_pane.as_deref(),
    )
}

/// Adaptive 4-tier TUI palette covering headers, selections, diagnostics, and icon categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TuiTheme {
    tier: ColorTier,
    header: Style,
    muted: Style,
    selection: Style,
    dirty: Style,
    error: Style,
    warning: Style,
    cat_security: Style,
    cat_network: Style,
    cat_system: Style,
    cat_personal: Style,
    cat_folders: Style,
    cat_media: Style,
    cat_misc: Style,
}

impl TuiTheme {
    fn from_tier(tier: ColorTier) -> Self {
        match tier {
            ColorTier::TrueColor => Self {
                tier,
                header: Style::default()
                    .fg(Color::Rgb(80, 190, 255))
                    .add_modifier(Modifier::BOLD),
                muted: Style::default().fg(Color::Rgb(130, 140, 155)),
                selection: Style::default()
                    .fg(Color::Rgb(240, 190, 70))
                    .add_modifier(Modifier::BOLD),
                dirty: Style::default()
                    .fg(Color::Rgb(255, 175, 65))
                    .add_modifier(Modifier::BOLD),
                error: Style::default()
                    .fg(Color::Rgb(255, 90, 90))
                    .add_modifier(Modifier::BOLD),
                warning: Style::default().fg(Color::Rgb(240, 190, 70)),
                cat_security: Style::default().fg(Color::Rgb(240, 190, 70)),
                cat_network: Style::default().fg(Color::Rgb(80, 190, 255)),
                cat_system: Style::default().fg(Color::Rgb(175, 135, 255)),
                cat_personal: Style::default().fg(Color::Rgb(90, 210, 130)),
                cat_folders: Style::default().fg(Color::Rgb(100, 165, 245)),
                cat_media: Style::default().fg(Color::Rgb(240, 125, 185)),
                cat_misc: Style::default().fg(Color::Rgb(185, 195, 210)),
            },
            ColorTier::Ansi256 => Self {
                tier,
                header: Style::default()
                    .fg(Color::Indexed(39))
                    .add_modifier(Modifier::BOLD),
                muted: Style::default().fg(Color::Indexed(244)),
                selection: Style::default()
                    .fg(Color::Indexed(220))
                    .add_modifier(Modifier::BOLD),
                dirty: Style::default()
                    .fg(Color::Indexed(214))
                    .add_modifier(Modifier::BOLD),
                error: Style::default()
                    .fg(Color::Indexed(203))
                    .add_modifier(Modifier::BOLD),
                warning: Style::default().fg(Color::Indexed(220)),
                cat_security: Style::default().fg(Color::Indexed(220)),
                cat_network: Style::default().fg(Color::Indexed(39)),
                cat_system: Style::default().fg(Color::Indexed(141)),
                cat_personal: Style::default().fg(Color::Indexed(78)),
                cat_folders: Style::default().fg(Color::Indexed(75)),
                cat_media: Style::default().fg(Color::Indexed(212)),
                cat_misc: Style::default().fg(Color::Indexed(250)),
            },
            ColorTier::Basic16 => Self {
                tier,
                header: Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                muted: Style::default().fg(Color::DarkGray),
                selection: Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                dirty: Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                error: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                warning: Style::default().fg(Color::Yellow),
                cat_security: Style::default().fg(Color::Yellow),
                cat_network: Style::default().fg(Color::Cyan),
                cat_system: Style::default().fg(Color::LightBlue),
                cat_personal: Style::default().fg(Color::Green),
                cat_folders: Style::default().fg(Color::Blue),
                cat_media: Style::default().fg(Color::Magenta),
                cat_misc: Style::default().fg(Color::Gray),
            },
            ColorTier::None => Self {
                tier,
                header: Style::default().add_modifier(Modifier::BOLD),
                muted: Style::default().add_modifier(Modifier::DIM),
                selection: Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
                dirty: Style::default().add_modifier(Modifier::BOLD),
                error: Style::default().add_modifier(Modifier::BOLD),
                warning: Style::default().add_modifier(Modifier::BOLD),
                cat_security: Style::default(),
                cat_network: Style::default(),
                cat_system: Style::default(),
                cat_personal: Style::default(),
                cat_folders: Style::default(),
                cat_media: Style::default(),
                cat_misc: Style::default(),
            },
        }
    }

    const fn category_style(&self, category: IconCategory) -> Style {
        match category {
            IconCategory::Security => self.cat_security,
            IconCategory::Network => self.cat_network,
            IconCategory::System => self.cat_system,
            IconCategory::Personal => self.cat_personal,
            IconCategory::Folders => self.cat_folders,
            IconCategory::Media => self.cat_media,
            IconCategory::Misc => self.cat_misc,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Query,
    Edit,
    RenameTitle,
    EditTags,
    SetOtp,
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
    icon_id: u32,
    custom_icon_id: Option<CustomIconId>,
}

impl From<(String, GroupRef, u32, Option<CustomIconId>)> for UiGroup {
    fn from(
        (path, reference, icon_id, custom_icon_id): (String, GroupRef, u32, Option<CustomIconId>),
    ) -> Self {
        let label = path.rsplit('/').next().unwrap_or(&path).to_owned();
        Self {
            label,
            path,
            reference: Some(reference),
            icon_id,
            custom_icon_id,
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
            icon_id: DEFAULT_GROUP_ICON_ID,
            custom_icon_id: None,
        }
    }
}

#[derive(Clone, Copy)]
enum DeleteKind {
    Entry,
    Group,
}

enum IconTarget {
    EntryItem(EntryRef),
    GroupItem(GroupRef),
}

enum Modal {
    ClipboardWarning {
        previous: Option<Box<Modal>>,
    },
    Target {
        label: String,
        target: String,
        offset: usize,
    },
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
    IconPicker {
        target: IconTarget,
        filter: String,
        filtering: bool,
        selected: usize,
        scroll: usize,
    },
    ConfirmDelete {
        kind: DeleteKind,
        path: String,
        entry: Option<EntryRef>,
        group: Option<GroupRef>,
        input: Zeroizing<String>,
        offset: usize,
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

struct App {
    service: VaultService,
    session: nkeepass::SessionId,
    // No outer launch/run_ui borrow may keep these alive after lock.
    credentials: Option<KdbxCredentials>,
    hits: Vec<SearchHit>,
    groups: Vec<UiGroup>,
    tree_parent: GroupRef,
    tree_stack: Vec<GroupRef>,
    tree_cursor: Option<TreeCursor>,
    list_cursor: Option<ListCursor>,
    page_failure: Option<String>,
    selected: usize,
    query: Zeroizing<String>,
    query_before_input: Zeroizing<String>,
    entry: Option<EntryRef>,
    entry_icon: Option<(u32, Option<CustomIconId>)>,
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
    // Captured when the interaction begins; asynchronous notices only change
    // status, never the instructions for the action Enter/YES will submit.
    action_prompt: String,
    pending_group: Option<GroupRef>,
    pending_entry: Option<EntryRef>,
    dirty: bool,
    pending_decision: Option<PendingDecision>,
    attachment_selected: usize,
    action_target: Option<AttachmentTarget>,
    field_to_reveal: Zeroizing<String>,
    generation_size: usize,
    clipboard: ClipboardLease<ArboardAdapter>,
    clipboard_may_contain_password: bool,
    clipboard_warning_pending: bool,
    include_groups: bool,
    aliases: Vec<String>,
    modal: Option<Modal>,
    theme: TuiTheme,
}

#[derive(Clone)]
struct AttachmentTarget {
    label: String,
    name: String,
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
    let (mut file, _) = nkeepass::fs_safe::open_regular_file_nofollow(path)?;
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
    prompt.clone_into(&mut app.action_prompt);
    app.action_target = None;
    app.input_mode = true;
    app.edit_mode = false;
    clear_input(&mut app.input);
    prompt.clone_into(&mut app.status);
}

fn begin_field_reveal(app: &mut App) {
    if !select_field_for_reveal(&app.fields, app.selected_field, &mut app.field_to_reveal) {
        app.status = "No field selected".into();
        return;
    }
    // Only bounded instructions/index go in the heading. The full captured
    // name has its own viewport and can be inspected without submitting.
    let prompt = format!("Field {}/{}", app.selected_field + 1, app.fields.len());
    begin_action(app, Action::RevealField, &prompt);
}

fn confirm_generation(app: &mut App, value: &str) {
    if value != "YES" {
        app.status = "Password generation cancelled".into();
        return;
    }
    let Some(reference) = &app.entry else { return };
    match app
        .service
        .generate_entry_password(reference, app.generation_size)
    {
        Ok(()) => {
            app.dirty = true;
            app.reset_tree_after_mutation();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = "Password replaced in memory; save to persist".into();
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn open_clipboard_warning(app: &mut App) {
    if app.clipboard_warning_pending && !matches!(&app.modal, Some(Modal::ClipboardWarning { .. }))
    {
        app.clear_reveal();
        app.modal = Some(Modal::ClipboardWarning {
            previous: app.modal.take().map(Box::new),
        });
    }
}

fn selected_attachment(app: &App) -> Option<AttachmentTarget> {
    let items = app.service.attachment_metadata(app.entry.as_ref()?).ok()?;
    let item = items.get(app.attachment_selected)?;
    Some(AttachmentTarget {
        label: format!("Attachment {}/{}", app.attachment_selected + 1, items.len()),
        name: item.name().to_owned(),
    })
}

fn begin_attachment_action(app: &mut App, action: Action) {
    let Some(target) = selected_attachment(app) else {
        app.status = "No attachment selected".into();
        return;
    };
    let instruction = if action == Action::ExportAttachment {
        "Export to a NEW owner-only path; no overwrite. Destination:"
    } else {
        "Remove this attachment? Type YES to confirm."
    };
    begin_action(
        app,
        action,
        &format!("{}\n{instruction}\nF2 inspect full target", target.label),
    );
    app.action_target = Some(target);
}

fn inspect_action_target(app: &mut App) {
    if app.input_mode && app.action == Action::RevealField {
        app.modal = Some(Modal::Target {
            label: app.action_prompt.clone(),
            target: app.field_to_reveal.to_string(),
            offset: 0,
        });
        return;
    }
    let target = if app.input_mode {
        app.action_target.clone()
    } else {
        selected_attachment(app)
    };
    let Some(target) = target else {
        app.status = "No attachment selected".into();
        return;
    };
    app.clear_reveal();
    app.modal = Some(Modal::Target {
        label: target.label,
        target: target.name,
        offset: 0,
    });
}

// Offset is in sanitized Unicode characters, not bytes or terminal columns.
// Keep a final 32-character window so colliding prefixes can be distinguished
// even on the minimum-size terminal.
fn move_target_offset(offset: usize, target: &str, key: KeyCode) -> usize {
    let end = clean(target).chars().count().saturating_sub(32);
    match key {
        KeyCode::Left | KeyCode::Up => offset.saturating_sub(1),
        KeyCode::Right | KeyCode::Down => offset.saturating_add(1).min(end),
        KeyCode::PageUp => offset.saturating_sub(32),
        KeyCode::PageDown => offset.saturating_add(32).min(end),
        KeyCode::Home => 0,
        KeyCode::End => end,
        _ => offset,
    }
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
        path: format!(
            "Entry row {}/{}: {path}",
            app.selected + 1,
            app.visible_row_count()
        ),
        entry: Some(reference),
        group: None,
        input: Zeroizing::new(String::new()),
        offset: 0,
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
        path: format!(
            "Group row {}/{}: {}",
            app.selected + 1,
            app.visible_row_count(),
            group.path
        ),
        entry: None,
        group: Some(reference),
        input: Zeroizing::new(String::new()),
        offset: 0,
    });
}

const PALETTE_CHOICES: [&str; 10] = [
    "Add group",
    "Add entry",
    "Remove entry",
    "Remove group",
    "View aliases",
    "Change entry icon",
    "Change group icon",
    "Rename entry title",
    "Edit entry tags",
    "Set/update OTP URI",
];

const fn icon_category_label(category: IconCategory) -> &'static str {
    match category {
        IconCategory::Security => "Security",
        IconCategory::Network => "Network",
        IconCategory::System => "System",
        IconCategory::Personal => "Personal",
        IconCategory::Folders => "Folders",
        IconCategory::Media => "Media",
        IconCategory::Misc => "Misc",
    }
}

fn filtered_standard_icons(filter: &str) -> Vec<&'static StandardIcon> {
    let needle = filter.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return standard_icons().iter().collect();
    }
    standard_icons()
        .iter()
        .filter(|icon| {
            icon.name.to_ascii_lowercase().contains(&needle)
                || icon_category_label(icon.category)
                    .to_ascii_lowercase()
                    .contains(&needle)
                || icon.id.to_string().contains(&needle)
        })
        .collect()
}

fn valid_unpadded_base32(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return false,
        };
        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            buffer &= (1_u32 << bits) - 1;
        }
    }
    bits == 0 || buffer == 0
}

fn validate_totp_uri(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || nkeepass::template::is_bidi_or_line_separator(c))
    {
        return Err("Invalid OTP URI: disallowed or empty input");
    }
    let rest = value
        .strip_prefix("otpauth://")
        .ok_or("OTP URI must start with otpauth://totp/")?;
    let (label, query) = rest
        .split_once('?')
        .ok_or("OTP URI must include ?secret=...&period=30")?;
    match label.split('/').next().unwrap_or_default() {
        "totp" => {}
        "hotp" => return Err("HOTP is unsupported; use otpauth://totp/"),
        _ => return Err("OTP URI type must be totp"),
    }
    let mut values = BTreeMap::new();
    for part in query.split('&') {
        let (key, val) = part
            .split_once('=')
            .ok_or("Malformed OTP URI query parameter")?;
        if values.insert(key, val).is_some() {
            return Err("Duplicate OTP URI parameter");
        }
    }
    let secret = values
        .remove("secret")
        .ok_or("OTP URI secret parameter is required")?;
    if !valid_unpadded_base32(secret) {
        return Err("OTP URI secret must be valid unpadded Base32");
    }
    let _issuer = values.remove("issuer");
    if let Some(counter) = values.remove("counter")
        && counter.parse::<u64>().is_err()
    {
        return Err("Invalid OTP URI counter");
    }
    let period = values
        .remove("period")
        .ok_or("TOTP URI requires positive period (e.g. period=30)")?;
    if period.parse::<u64>().is_err_and(|_| true) || period.parse::<u64>().ok() == Some(0) {
        return Err("TOTP URI period must be a positive integer");
    }
    if let Some(algorithm) = values.remove("algorithm")
        && !matches!(algorithm, "SHA1" | "SHA256" | "SHA512")
    {
        return Err("Unsupported OTP algorithm (use SHA1, SHA256, or SHA512)");
    }
    if let Some(digits) = values.remove("digits")
        && !matches!(digits, "6" | "8")
    {
        return Err("Unsupported OTP digits (use 6 or 8)");
    }
    if !values.is_empty() {
        return Err("Unknown OTP URI parameter");
    }
    Ok(())
}

fn selected_entry_ref(app: &App) -> Option<EntryRef> {
    app.entry.clone().or_else(|| {
        app.selected
            .checked_sub(app.groups.len())
            .and_then(|index| app.hits.get(index))
            .map(SearchHit::reference)
    })
}

fn begin_icon_picker(app: &mut App, prefer_group: Option<bool>) {
    app.clear_reveal();
    let (target, current_icon_id) = match prefer_group {
        Some(false) => {
            let Some(reference) = selected_entry_ref(app) else {
                app.status = "Select an entry before choosing Change entry icon".into();
                return;
            };
            let icon_id = app
                .service
                .selected_entry(&reference)
                .map_or(0, |view| view.icon_id());
            (IconTarget::EntryItem(reference), icon_id)
        }
        Some(true) => {
            let Some(reference) = selected_group(app) else {
                app.status = "Select a group before choosing Change group icon".into();
                return;
            };
            let icon_id = if app.entry.is_none() {
                app.groups
                    .get(app.selected)
                    .map_or(DEFAULT_GROUP_ICON_ID, |group| group.icon_id)
            } else {
                DEFAULT_GROUP_ICON_ID
            };
            (IconTarget::GroupItem(reference), icon_id)
        }
        None => {
            if let Some(reference) = app.entry.clone() {
                let icon_id = app
                    .service
                    .selected_entry(&reference)
                    .map_or(0, |view| view.icon_id());
                (IconTarget::EntryItem(reference), icon_id)
            } else if let Some(group) = app.groups.get(app.selected) {
                let reference = group
                    .reference
                    .clone()
                    .or_else(|| app.service.resolve_group(app.session, &group.path).ok());
                let Some(reference) = reference else {
                    app.status = "Cannot select group for icon change".into();
                    return;
                };
                (IconTarget::GroupItem(reference), group.icon_id)
            } else if let Some(hit) = app
                .selected
                .checked_sub(app.groups.len())
                .and_then(|index| app.hits.get(index))
            {
                (IconTarget::EntryItem(hit.reference()), hit.icon_id())
            } else {
                (
                    IconTarget::GroupItem(app.tree_parent.clone()),
                    DEFAULT_GROUP_ICON_ID,
                )
            }
        }
    };
    let selected = usize::try_from(current_icon_id).unwrap_or(0).min(68);
    app.modal = Some(Modal::IconPicker {
        target,
        filter: String::new(),
        filtering: false,
        selected,
        scroll: selected.saturating_sub(3),
    });
}

fn begin_entry_mutation(app: &mut App, action: Action) {
    let Some(reference) = selected_entry_ref(app) else {
        app.status = "Select an entry first".into();
        return;
    };
    let current = app.service.selected_entry(&reference).ok();
    app.pending_entry = Some(reference);
    match action {
        Action::RenameTitle => {
            begin_action(
                app,
                Action::RenameTitle,
                "Rename entry title · Enter apply · Esc cancel",
            );
            if let Some(view) = current {
                app.input.push_str(view.title());
            }
        }
        Action::EditTags => {
            begin_action(
                app,
                Action::EditTags,
                "Edit tags (comma-separated; empty clears) · Enter apply · Esc cancel",
            );
            if let Some(view) = current {
                app.input.push_str(&view.tags().join(", "));
            }
        }
        Action::SetOtp => {
            begin_action(
                app,
                Action::SetOtp,
                "Set/update OTP URI (otpauth://totp/...); input is masked · Enter apply · Esc cancel",
            );
            app.edit_mode = true;
        }
        _ => {}
    }
}

fn apply_icon_selection(app: &mut App, target: &IconTarget, icon: &StandardIcon) {
    let result = match target {
        IconTarget::EntryItem(reference) => app.service.set_entry_icon(reference, icon.id),
        IconTarget::GroupItem(reference) => app.service.set_group_icon(reference, icon.id),
    };
    match result {
        Ok(()) => {
            app.dirty = true;
            app.reset_tree_after_mutation();
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.refresh();
            app.status = format!(
                "Icon set to {} {} ({}) in memory; press s to save",
                icon.glyph, icon.name, icon.id
            );
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn select_palette_action(app: &mut App, selected: usize) {
    app.modal = None;
    match selected {
        0 => begin_add(app, Action::AddGroup),
        1 => begin_add(app, Action::AddEntry),
        2 => begin_delete_entry(app),
        3 => begin_delete_group(app),
        4 => app.modal = Some(Modal::Aliases { scroll: 0 }),
        5 => begin_icon_picker(app, Some(false)),
        6 => begin_icon_picker(app, Some(true)),
        7 => begin_entry_mutation(app, Action::RenameTitle),
        8 => begin_entry_mutation(app, Action::EditTags),
        9 => begin_entry_mutation(app, Action::SetOtp),
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
        Modal::ClipboardWarning { previous } => match key {
            KeyCode::Char('a') => {
                app.clipboard_warning_pending = false;
                app.status =
                    "Clipboard warning acknowledged; this does not clear the clipboard.".into();
                app.modal = previous.map(|modal| *modal);
            }
            KeyCode::Esc | KeyCode::Enter => app.modal = previous.map(|modal| *modal),
            _ => app.modal = Some(Modal::ClipboardWarning { previous }),
        },
        Modal::Target {
            label,
            target,
            offset,
        } => {
            if !matches!(key, KeyCode::Esc | KeyCode::Enter | KeyCode::F(2)) {
                let offset = move_target_offset(offset, &target, key);
                app.modal = Some(Modal::Target {
                    label,
                    target,
                    offset,
                });
            }
        }
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
                selected = selected
                    .saturating_add(1)
                    .min(PALETTE_CHOICES.len().saturating_sub(1));
                scroll = selected.saturating_sub(3);
                app.modal = Some(Modal::Palette { selected, scroll });
            }
            KeyCode::Enter => select_palette_action(app, selected),
            _ => app.modal = Some(Modal::Palette { selected, scroll }),
        },
        Modal::IconPicker {
            target,
            mut filter,
            mut filtering,
            mut selected,
            mut scroll,
        } => {
            let matches = filtered_standard_icons(&filter);
            let count = matches.len();
            let current = selected.min(count.saturating_sub(1));
            match key {
                KeyCode::Esc => {
                    app.status = "Icon selection cancelled".into();
                }
                KeyCode::Enter => {
                    if let Some(icon) = matches.get(current).copied() {
                        apply_icon_selection(app, &target, icon);
                    } else {
                        app.status = "No matching icon selected".into();
                    }
                }
                KeyCode::Char('/') if !filtering => {
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering: true,
                        selected: current,
                        scroll,
                    });
                }
                KeyCode::Up => {
                    selected = current.saturating_sub(1);
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::Down => {
                    selected = current.saturating_add(1).min(count.saturating_sub(1));
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::PageUp => {
                    selected = current.saturating_sub(10);
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::PageDown => {
                    selected = current.saturating_add(10).min(count.saturating_sub(1));
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::Home => {
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected: 0,
                        scroll: 0,
                    });
                }
                KeyCode::End => {
                    selected = count.saturating_sub(1);
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::Char('k') if !filtering => {
                    selected = current.saturating_sub(1);
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::Char('j') if !filtering => {
                    selected = current.saturating_add(1).min(count.saturating_sub(1));
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected,
                        scroll,
                    });
                }
                KeyCode::Backspace => {
                    if filter.is_empty() {
                        filtering = false;
                    } else {
                        filter.pop();
                    }
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected: 0,
                        scroll: 0,
                    });
                }
                KeyCode::Char(c) if filtering && !c.is_control() && filter.len() < 64 => {
                    filter.push(c);
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected: 0,
                        scroll: 0,
                    });
                }
                _ => {
                    app.modal = Some(Modal::IconPicker {
                        target,
                        filter,
                        filtering,
                        selected: current,
                        scroll,
                    });
                }
            }
        }
        Modal::ConfirmDelete {
            kind,
            path,
            entry,
            group,
            mut input,
            offset,
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
                    offset,
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
                    offset,
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
                let offset = move_target_offset(offset, &path, key);
                app.modal = Some(Modal::ConfirmDelete {
                    kind,
                    path,
                    entry,
                    group,
                    input,
                    offset,
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
        || !nkeepass::template::is_safe_display_text(name)
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
            if !app.clipboard.supports_timed_clear() {
                app.clipboard_warning_pending = true;
            }
            app.status = if app.clipboard.supports_timed_clear() {
                "Password copied; an ownership-safe clear will be attempted after 30s. Verify manually; it may remain.".into()
            } else {
                "Password copied; this platform cannot safely auto-clear it. Clear manually; it may remain.".into()
            };
        }
        Ok(ClipboardCopyOutcome::MayHaveCopied) => {
            app.clipboard_may_contain_password = true;
            app.clipboard_warning_pending = true;
            app.status = "Clipboard write may have succeeded; clear it manually. A timed clear will be attempted if ownership was captured.".into();
        }
        Ok(ClipboardCopyOutcome::RejectedNul) => {
            app.status = "Password contains NUL; it was not copied".into();
        }
        Ok(ClipboardCopyOutcome::TimedClearFailed) => {
            app.clipboard_may_contain_password = true;
            app.clipboard_warning_pending = true;
            app.status = "Clipboard could not be cleared; the copied password may remain".into();
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
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control()
            || c == '\u{7f}'
            || ('\u{80}'..='\u{9f}').contains(&c)
            || nkeepass::template::is_bidi_or_line_separator(c)
        {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}

fn clean_secret(input: &str) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::with_capacity(input.len()));
    for c in input.chars() {
        if c.is_control()
            || c == '\u{7f}'
            || ('\u{80}'..='\u{9f}').contains(&c)
            || nkeepass::template::is_bidi_or_line_separator(c)
        {
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
    fn save(&mut self, path: &Path) -> Result<(), String> {
        let credentials = self.credentials.as_mut().ok_or("Vault locked")?;
        self.service
            .save(path, credentials)
            .map_err(|error| clean(error.message()))
    }

    // The real decision path is shared with lifecycle tests: failed saves and
    // cancelled decisions must keep the unlocked credentials for retry.
    fn resolve_pending_decision(&mut self, input: DecisionInput, path: &Path) -> DecisionEffect {
        let Some(pending) = self.pending_decision else {
            return DecisionEffect::None;
        };
        let input = if input == DecisionInput::SaveSucceeded
            && self.edit_mode
            && self.input_mode
            && !self.input.is_empty()
        {
            self.status =
                "Finish or cancel the pending edit before saving; press c to return to it".into();
            DecisionInput::SaveFailed
        } else if input == DecisionInput::SaveSucceeded {
            match self.save(path) {
                Ok(()) => {
                    self.dirty = false;
                    self.status = "Saved".into();
                    DecisionInput::SaveSucceeded
                }
                Err(error) => {
                    self.status = format!("Save failed: {error}. Choose save, discard, or cancel");
                    DecisionInput::SaveFailed
                }
            }
        } else if input == DecisionInput::Discard {
            self.dirty = false;
            discard_input_draft(
                &mut self.input,
                &mut self.field_to_reveal,
                &mut self.input_mode,
                &mut self.edit_mode,
            );
            self.edit_field.clear();
            DecisionInput::Discard
        } else {
            DecisionInput::Cancel
        };
        let (next, effect) = reduce_decision(Some(pending), self.dirty, input);
        self.pending_decision = next;
        match effect {
            DecisionEffect::Lock => self.lock_vault(),
            DecisionEffect::None if next.is_none() => {
                self.last_activity = Instant::now();
                self.status = "Decision cancelled; returned to the vault".into();
            }
            DecisionEffect::Exit | DecisionEffect::None => {}
        }
        effect
    }

    fn move_attachment(&mut self, forward: bool) {
        let Some(reference) = &self.entry else { return };
        let Ok(items) = self.service.attachment_metadata(reference) else {
            self.status = "Cannot list attachments".into();
            return;
        };
        if items.is_empty() {
            self.attachment_selected = 0;
            self.status = "No attachment selected".into();
            return;
        }
        self.attachment_selected = if forward {
            self.attachment_selected.saturating_add(1)
        } else {
            self.attachment_selected.saturating_sub(1)
        }
        .min(items.len() - 1);
        self.status = format!(
            "Selected attachment {}/{}: {} · x export · n/p select",
            self.attachment_selected + 1,
            items.len(),
            clean(items[self.attachment_selected].name())
        );
    }

    fn visible_row_count(&self) -> usize {
        self.groups.len().saturating_add(self.hits.len())
    }

    fn list_groups(&mut self, tree_groups: Vec<TreeGroup>) {
        self.groups = tree_groups
            .into_iter()
            .filter_map(|group| {
                let reference = group.reference();
                let icon_id = group.icon_id();
                let custom_icon_id = group.custom_icon_id();
                self.service
                    .group_path(&reference)
                    .ok()
                    .map(|path| UiGroup::from((path, reference, icon_id, custom_icon_id)))
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
        self.page_failure = None;
        if let Some(cursor) = self.tree_cursor.take() {
            let _ = self.service.release_tree_cursor(cursor);
        }
        if let Some(cursor) = self.list_cursor.take() {
            let _ = self.service.release_list_cursor(cursor);
        }
        self.entry = None;
        self.entry_icon = None;
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
                self.record_page_failure(error);
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
        if let Some(message) = &self.page_failure {
            self.status.clone_from(message);
            return;
        }
        let page = if self.query.is_empty() {
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
            Err(error) => self.record_page_failure(error),
        }
    }

    fn record_page_failure(&mut self, error: nkeepass::ServiceError) {
        // Continuations are consumed even on error. Do not mistake an absent
        // cursor for exhaustion or restart and silently duplicate earlier rows.
        self.status = format!(
            "Page failed. Use / then Enter to restart; q quits. Cause: {}",
            clean(error.message())
        );
        self.page_failure = Some(self.status.clone());
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
                let icon = standard_icon(view.icon_id());
                self.entry_icon = Some((view.icon_id(), view.custom_icon_id()));
                self.detail = vec![
                    format!("Title: {}", clean(view.title())),
                    format!(
                        "Icon: {} {}{}",
                        icon.glyph,
                        icon.name,
                        if view.custom_icon_id().is_some() {
                            " [custom]"
                        } else {
                            ""
                        }
                    ),
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
                self.entry = Some(reference);
                self.status = "↑/↓ select field · e edit value · r reveal password for 15s · I icon · s save · Esc back".into();
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
        let clipboard_tick = self.clipboard.tick(Instant::now());
        self.apply_clipboard_tick(clipboard_tick);
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

    fn apply_clipboard_tick(
        &mut self,
        outcome: Result<Option<bool>, crate::clipboard::ClipboardError>,
    ) {
        match outcome {
            Ok(Some(true)) => {
                self.clipboard_may_contain_password = false;
                self.status = "Clipboard lease expired and clipboard was cleared".into();
            }
            Ok(Some(false)) | Err(_) => {
                self.clipboard_may_contain_password = true;
                self.clipboard_warning_pending = true;
                self.status = "Clipboard expiry could not safely clear it; it may still contain the password. Clear it manually.".into();
            }
            Ok(None) => {}
        }
    }

    fn lock_vault(&mut self) {
        // Drop immediately, before clipboard/terminal operations can fail.
        // KdbxCredentials::drop zeroizes its owned password buffer.
        drop(self.credentials.take());
        self.clear_reveal();
        let had_clipboard_lease = self.clipboard.has_lease();
        if had_clipboard_lease {
            if let Ok(true) = self.clipboard.release() {
                self.clipboard_may_contain_password = false;
            } else {
                self.clipboard_may_contain_password = true;
                self.clipboard_warning_pending = true;
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
        self.pending_entry = None;
        self.action_target = None;
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
        self.entry_icon = None;
        self.entry_icon = None;
        self.detail.clear();
        self.fields.clear();
        self.locked = true;
        self.pending_decision = None;
        self.status = if clipboard_warning {
            "Vault locked; clipboard may still contain the password. Clear it manually. Press q to exit.".into()
        } else {
            "Vault locked. Press q to exit; restart TUI to unlock again.".into()
        };
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the compact two-pane Ratatui projection together"
)]
fn draw(frame: &mut Frame<'_>, app: &App) {
    if !usable_size(frame.area()) {
        frame.render_widget(
            Paragraph::new("Resize terminal to at least 40 columns by 12 rows. Input paused.")
                .wrap(Wrap { trim: false }),
            frame.area(),
        );
        return;
    }
    let reveal_render = app.reveal.as_deref().map(|value| clean_secret(value));
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(5),
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
        Paragraph::new(Line::from(vec![
            Span::styled("nkp", app.theme.header),
            Span::raw(format!(
                " · Path: {path_filter} · {groups_state} · / edit · g groups"
            )),
        ])),
        areas[0],
    );
    let items = app
        .groups
        .iter()
        .map(|group| {
            let icon = standard_icon(group.icon_id);
            let mut spans = vec![
                Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                Span::raw(" "),
                Span::raw(clean(if app.query.is_empty() {
                    &group.label
                } else {
                    &group.path
                })),
            ];
            if group.custom_icon_id.is_some() {
                spans.push(Span::styled(" [custom]", app.theme.muted));
            }
            ListItem::new(Line::from(spans))
        })
        .chain(app.hits.iter().map(|hit| {
            let icon = standard_icon(hit.icon_id());
            ListItem::new(Line::from(vec![
                Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                Span::raw(" "),
                Span::raw(clean(hit.title())),
                Span::styled(format!("  {}", clean(hit.path())), app.theme.muted),
            ]))
        }))
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select((!app.locked && app.entry.is_none()).then_some(app.selected));
    let title = if app.locked {
        "nkp · LOCKED".to_owned()
    } else if app.query.is_empty() {
        let path = app
            .service
            .group_path(&app.tree_parent)
            .map_or_else(|_| "current folder".to_owned(), |path| clean(&path));
        format!("nkp · Vault tree · ▾ {path} · ▸ child folders")
    } else {
        "nkp · Path matches · Enter opens group/entry".to_owned()
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(app.theme.selection),
        body[0],
        &mut state,
    );
    let mut detail = app
        .detail
        .iter()
        .flat_map(|line| {
            let styled_line = if line.starts_with("Title: ")
                && let Some((icon_id, _)) = app.entry_icon
            {
                let icon = standard_icon(icon_id);
                Line::from(vec![
                    Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                    Span::raw(" "),
                    Span::raw(line.clone()),
                ])
            } else if line.starts_with("Icon: ")
                && let Some((icon_id, custom_icon_id)) = app.entry_icon
            {
                let icon = standard_icon(icon_id);
                Line::from(vec![
                    Span::raw("Icon: "),
                    Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                    Span::raw(format!(
                        " {}{}",
                        icon.name,
                        if custom_icon_id.is_some() {
                            " [custom]"
                        } else {
                            ""
                        }
                    )),
                ])
            } else {
                Line::from(line.clone())
            };
            let mut rows = vec![styled_line];
            if line == "Fields (values hidden):" {
                rows.extend(
                    app.fields
                        .iter()
                        .enumerate()
                        .map(|(index, (name, protected))| {
                            let text = field_row(name, *protected, index == app.selected_field);
                            if index == app.selected_field {
                                Line::from(Span::styled(text, app.theme.selection))
                            } else {
                                Line::from(text)
                            }
                        }),
                );
            }
            if line == "Attachments:"
                && let Some(reference) = &app.entry
                && let Ok(items) = app.service.attachment_metadata(reference)
            {
                rows.extend(items.iter().enumerate().map(|(index, item)| {
                    Line::from(format!(
                        "{} {} ({} bytes)",
                        if index == app.attachment_selected {
                            ">"
                        } else {
                            " "
                        },
                        clean(item.name()),
                        item.size()
                    ))
                }));
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
            Span::styled(value, app.theme.error),
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
        detail.push(Line::from(Span::styled("UNSAVED CHANGES", app.theme.dirty)));
    }
    if !app.locked && app.entry.is_some() {
        detail.push(Line::from("↑/↓ select field · e edit selected (value only) · r reveal · c copy password · t TOTP · g generate · I icon · a add attachment · n/p attachment · x export · d remove · o export · i import · s save"));
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
    if app.clipboard_warning_pending {
        let footer = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(areas[2]);
        frame.render_widget(
            Paragraph::new(clean(&app.status)).wrap(Wrap { trim: false }),
            footer[0],
        );
        frame.render_widget(
            Paragraph::new("Clipboard may contain password.\nClear it manually. F3 review/ack.")
                .style(app.theme.warning)
                .wrap(Wrap { trim: false }),
            footer[1],
        );
    } else {
        frame.render_widget(
            Paragraph::new(clean(&app.status)).wrap(Wrap { trim: false }),
            areas[2],
        );
    }
    if !app.locked && app.entry.is_some() && (body[1].height < 12 || body[1].width < 40) {
        draw_compact_entry(frame, app, areas[1]);
    }
    if let Some(modal @ Modal::ClipboardWarning { .. }) = &app.modal {
        draw_modal(frame, modal, &app.aliases, &app.theme);
    } else if app.pending_decision.is_some() {
        draw_action_dialog(
            frame,
            "Unsaved changes",
            &app.status,
            "",
            if app.clipboard_warning_pending {
                "s save · d discard · c cancel\nF3 clipboard warning pending"
            } else {
                "s save · d discard · c cancel"
            },
            None,
        );
    } else if let Some(modal @ Modal::Target { .. }) = &app.modal {
        draw_modal(frame, modal, &app.aliases, &app.theme);
    } else if app.input_mode && app.action == Action::RevealField {
        draw_target_dialog(
            frame,
            &app.action_prompt,
            "Type YES to reveal.\nWARNING: scrollback and\nscreenshots may persist.",
            &format!("Reveal field: {}", app.field_to_reveal.as_str()),
            0,
            &clean(&app.input),
            if app.clipboard_warning_pending {
                "F2 inspect full target\nEnter submit · Esc cancel\nF3 clipboard warning pending"
            } else {
                "F2 inspect full target\nEnter submit · Esc cancel"
            },
        );
    } else if app.input_mode && app.action != Action::Query {
        let input = if app.edit_mode {
            "•".repeat(app.input.chars().count().min(64))
        } else {
            clean(&app.input)
        };
        draw_action_dialog(
            frame,
            if app.clipboard_warning_pending {
                "Action · F3 clipboard warning"
            } else {
                "Action"
            },
            &app.action_prompt,
            &input,
            "Enter submit · Esc cancel",
            (app.status != app.action_prompt).then_some(app.status.as_str()),
        );
    } else if !app.locked
        && let Some(value) = reveal_render.as_deref()
    {
        let area = frame.area();
        frame.render_widget(Clear, area);
        let block = Block::default()
            .title("REVEALED (15s maximum)")
            .borders(Borders::ALL);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).split(inner);
        frame.render_widget(
            Paragraph::new(if app.clipboard_warning_pending {
                "WARNING: scrollback/screenshots persist.\nEsc hides value. F3 clipboard warning."
            } else {
                "WARNING: terminal scrollback and screenshots persist. Esc hides the value."
            })
            .style(app.theme.warning)
            .wrap(Wrap { trim: false }),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(value.as_str())
                .style(app.theme.error)
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    } else if let Some(modal) = &app.modal {
        draw_modal(frame, modal, &app.aliases, &app.theme);
    }
}

fn draw_compact_entry(frame: &mut Frame<'_>, app: &App, area: Rect) {
    // On small screens metadata headings used to occupy every visible row.
    // Give fields the full width and let List keep the selected row in view.
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Entry detail · secrets masked")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(inner);
    let title_line = match (app.detail.first(), app.entry_icon) {
        (Some(title), Some((icon_id, _))) => {
            let icon = standard_icon(icon_id);
            Line::from(vec![
                Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                Span::raw(" "),
                Span::raw(title.as_str()),
            ])
        }
        (Some(title), None) => Line::from(title.as_str()),
        (None, _) => Line::from(""),
    };
    frame.render_widget(Paragraph::new(title_line), chunks[0]);
    let rows = app
        .fields
        .iter()
        .enumerate()
        .map(|(index, (name, protected))| {
            ListItem::new(field_row(name, *protected, index == app.selected_field))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select((!rows.is_empty()).then_some(app.selected_field));
    frame.render_stateful_widget(
        List::new(rows).highlight_style(app.theme.selection),
        chunks[1],
        &mut state,
    );
}

fn usable_size(area: Rect) -> bool {
    area.width >= MIN_COLUMNS && area.height >= MIN_ROWS
}

fn draw_action_dialog(
    frame: &mut Frame<'_>,
    title: &str,
    prompt: &str,
    input: &str,
    keys: &str,
    notice: Option<&str>,
) {
    // Full width and separate control rows keep confirmation text visible on
    // narrow terminals even when metadata or the input is very long.
    let area = frame.area();
    frame.render_widget(Clear, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(2),
        Constraint::Length(2),
    ])
    .split(inner);
    let prompt = prompt.lines().map(clean).collect::<Vec<_>>().join("\n");
    frame.render_widget(Paragraph::new(prompt).wrap(Wrap { trim: false }), chunks[0]);
    let tail: String = input.chars().rev().take(usize::from(inner.width)).collect();
    let input_rows =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(chunks[1]);
    frame.render_widget(
        Paragraph::new(tail.chars().rev().collect::<String>()),
        input_rows[0],
    );
    // A separate summary row cannot displace instructions or the target.
    // Esc preserves status and returns to its full-width, multiline display.
    if let Some(notice) = notice {
        frame.render_widget(
            Paragraph::new(format!("Notice: {}", clean(notice))),
            input_rows[1],
        );
    }
    let keys = if notice.is_some() {
        format!("{keys}\nEsc: full notice in status")
    } else {
        keys.to_owned()
    };
    frame.render_widget(Paragraph::new(keys).wrap(Wrap { trim: false }), chunks[2]);
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
        "nkp interactive TUI keybindings:",
        "q                 Quit (unsaved changes require a decision)",
        "?                 Open this help; Esc closes it",
        "Ctrl-P            Open nkp command palette",
        "/                 Search paths with glob patterns; Enter applies",
        "g (tree)          Toggle matching groups in path results",
        "Up/Down or j/k    Move selection",
        "Enter             Open selected group or entry",
        "Backspace         Go to parent group (when path filter is empty)",
        "n                 Load next result page",
        "a / e             Add group / entry beneath selected or current group",
        "x / X             Remove selected entry / group (type YES to confirm)",
        "I                 Change KeePass icon (entry or group; 0..=68)",
        "s                 Save unsaved vault changes",
        "d                 Discard unsaved changes in exit prompt",
        "c                 Cancel an exit prompt",
        "Ctrl-P palette    Add/remove entry or group, change icon, rename title,",
        "                  edit tags, set/update OTP URI, view aliases",
        "Entry view:",
        "  e edit selected field · r reveal password · v reveal selected field",
        "  c copy password · t reveal TOTP · g generate password · I change icon",
        "  a add attachment · x export selected · d remove selected (type YES)",
        "  F2 inspect full attachment or field-consent target; arrows/Home/End pan",
        "  F3 review pending clipboard warning; a acknowledges only in that view",
        "  o export interchange · i import interchange · s save",
        "  Esc/Enter back to tree · n/p select attachment",
        "Icon picker: j/k or Up/Down move · / type filter · Enter apply · Esc cancel",
        "Colors: adaptive 4-tier (TrueColor / 256-color / Basic16 / NO_COLOR)",
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
fn draw_modal(frame: &mut Frame<'_>, modal: &Modal, aliases: &[String], theme: &TuiTheme) {
    let area = centered_rect(78, 78, frame.area());
    frame.render_widget(Clear, area);
    match modal {
        Modal::ClipboardWarning { .. } => draw_action_dialog(
            frame,
            "Clipboard warning",
            CLIPBOARD_WARNING,
            "",
            "a acknowledge · Esc back",
            None,
        ),
        Modal::Target {
            label,
            target,
            offset,
        } => draw_target_dialog(
            frame,
            "Inspect target",
            label,
            target,
            *offset,
            "",
            "Arrows/PgUp/PgDn inspect full target\nHome/End · Enter/Esc back",
        ),
        Modal::Help { scroll } => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1)])
                .split(area);
            frame.render_widget(
                Tabs::new(vec![Line::from("Keybindings")]).select(0).block(
                    Block::default()
                        .title("nkp Help · Tab 1/1")
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
            let rows = PALETTE_CHOICES
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
                            .title("nkp Palette · Enter select · Esc close")
                            .borders(Borders::ALL),
                    )
                    .highlight_style(theme.selection),
                area,
                &mut state,
            );
            let _ = scroll;
        }
        Modal::IconPicker {
            filter,
            filtering,
            selected,
            scroll,
            ..
        } => {
            let matches = filtered_standard_icons(filter);
            let block = Block::default()
                .title("nkp Icons · Enter apply · Esc cancel")
                .borders(Borders::ALL);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let chunks = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(inner);
            let filter_line = if *filtering || !filter.is_empty() {
                Line::from(vec![
                    Span::styled("Filter: ", theme.header),
                    Span::raw(clean(filter)),
                ])
            } else {
                Line::from(Span::styled(
                    format!("/ filter · {} icons · j/k move", matches.len()),
                    theme.muted,
                ))
            };
            frame.render_widget(Paragraph::new(filter_line), chunks[0]);
            let rows = if matches.is_empty() {
                vec![ListItem::new(Line::from(Span::styled(
                    "No matching icons",
                    theme.muted,
                )))]
            } else {
                matches
                    .iter()
                    .map(|icon| {
                        ListItem::new(Line::from(vec![
                            Span::styled(format!("{:>2} ", icon.id), theme.muted),
                            Span::styled(icon.glyph, theme.category_style(icon.category)),
                            Span::raw(format!(" {} ", icon.name)),
                            Span::styled(
                                format!("[{}]", icon_category_label(icon.category)),
                                theme.muted,
                            ),
                        ]))
                    })
                    .collect()
            };
            let mut state = ListState::default();
            if !matches.is_empty() {
                state.select(Some((*selected).min(matches.len().saturating_sub(1))));
            }
            frame.render_stateful_widget(
                List::new(rows).highlight_style(theme.selection),
                chunks[1],
                &mut state,
            );
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    if *filtering {
                        "Type to filter · Backspace · Enter apply · Esc cancel"
                    } else {
                        "Enter apply · / filter · Esc cancel"
                    },
                    theme.muted,
                ))),
                chunks[2],
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
                            .title("nkp Aliases · Esc close")
                            .borders(Borders::ALL),
                    ),
                area,
            );
        }
        Modal::ConfirmDelete {
            kind,
            path,
            input,
            offset,
            ..
        } => {
            let label = match kind {
                DeleteKind::Entry => "entry",
                DeleteKind::Group => "group and all its contents",
            };
            draw_target_dialog(
                frame,
                "Confirm deletion",
                &format!(
                    "{}\nRemove {label}?\nType YES to confirm.",
                    path.split_once(": ")
                        .map_or("Selected target", |(label, _)| label)
                ),
                path,
                *offset,
                &clean(input),
                "Arrows/PgUp/PgDn inspect full target\nHome/End · Enter delete · Esc cancel",
            );
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "private target projection shared by inspection and confirmation"
)]
fn draw_target_dialog(
    frame: &mut Frame<'_>,
    title: &str,
    prompt: &str,
    target: &str,
    offset: usize,
    input: &str,
    keys: &str,
) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(inner);
    let prompt = prompt.lines().map(clean).collect::<Vec<_>>().join("\n");
    frame.render_widget(Paragraph::new(prompt).wrap(Wrap { trim: false }), chunks[0]);
    let visible: String = clean(target).chars().skip(offset).collect();
    frame.render_widget(
        Paragraph::new(visible).wrap(Wrap { trim: false }),
        chunks[1],
    );
    frame.render_widget(Paragraph::new(clean(input)), chunks[2]);
    frame.render_widget(Paragraph::new(keys).wrap(Wrap { trim: false }), chunks[3]);
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the compact reducer and terminal lifecycle together"
)]
fn run_ui(terminal: &mut DefaultTerminal, app: &mut App, path: &Path) -> io::Result<()> {
    let mut reveal_was_drawn = false;
    loop {
        let was_revealed = reveal_was_drawn;
        app.tick();
        if !usable_size(terminal.size()?.into()) {
            app.clear_reveal();
        }
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
            app.action_target = None;
            let query_was_active = app.input_mode && app.action == Action::Query;
            handle_focus_lost(
                &mut app.input_mode,
                &mut app.edit_mode,
                &mut app.input,
                &mut app.field_to_reveal,
            );
            if !app.input_mode {
                app.pending_entry = None;
            }
            if query_was_active {
                app.query_before_input.zeroize();
            }
            continue;
        }
        let Event::Key(key) = event else { continue };
        if !usable_size(terminal.size()?.into()) {
            app.clear_reveal();
            continue;
        }
        if key.kind != KeyEventKind::Press {
            continue;
        }
        app.last_activity = Instant::now();
        // Warning inspection/acknowledgement is independent of an action,
        // unsaved decision, disclosure, or lock screen. Other keys cannot
        // accidentally acknowledge it or submit the interaction beneath it.
        if key.code == KeyCode::F(3) && app.clipboard_warning_pending {
            open_clipboard_warning(app);
            continue;
        }
        if matches!(&app.modal, Some(Modal::ClipboardWarning { .. })) {
            handle_modal_key(app, key.code);
            continue;
        }
        if app.locked {
            if key.code == KeyCode::Char('q') {
                break;
            }
            continue;
        }
        // Disclosure owns focus: other interactions must not open invisibly
        // behind it and consume the one Escape needed to hide the value.
        if app.reveal.is_some() {
            app.modal = None;
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                app.clear_reveal();
                app.status = "Revealed value hidden".into();
            }
            continue;
        }
        if app.pending_decision.is_some() {
            let input = match key.code {
                KeyCode::Char('s') => DecisionInput::SaveSucceeded,
                KeyCode::Char('d') => DecisionInput::Discard,
                KeyCode::Char('c') | KeyCode::Esc => DecisionInput::Cancel,
                _ => continue,
            };
            if app.resolve_pending_decision(input, path) == DecisionEffect::Exit {
                break;
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
        if key.code == KeyCode::F(2)
            && app.entry.is_some()
            && (!app.input_mode || app.action_target.is_some() || app.action == Action::RevealField)
        {
            inspect_action_target(app);
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
                    app.action_target = None;
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
                        app.pending_entry = None;
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
                KeyCode::Enter if app.edit_mode && app.action == Action::SetOtp => {
                    match validate_totp_uri(&app.input) {
                        Ok(()) => {
                            let Some(reference) = app.pending_entry.as_ref().or(app.entry.as_ref())
                            else {
                                clear_input(&mut app.input);
                                app.input_mode = false;
                                app.edit_mode = false;
                                app.pending_entry = None;
                                app.status = "No selected entry".into();
                                continue;
                            };
                            match app.service.set_custom_field(reference, "otp", &app.input) {
                                Ok(()) => {
                                    clear_input(&mut app.input);
                                    app.input_mode = false;
                                    app.edit_mode = false;
                                    app.pending_entry = None;
                                    app.dirty = true;
                                    app.reset_tree_after_mutation();
                                    app.entry = None;
                                    app.entry_icon = None;
                                    app.detail.clear();
                                    app.fields.clear();
                                    app.refresh();
                                    app.status =
                                        "OTP URI updated in memory; press s to save".into();
                                }
                                Err(error) => {
                                    app.status = format!(
                                        "{}; draft retained (retry or Esc to discard)",
                                        clean(error.message())
                                    );
                                }
                            }
                        }
                        Err(message) => {
                            app.status =
                                format!("{message}; draft retained (retry or Esc to discard)");
                        }
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
                        app.entry_icon = None;
                        app.detail.clear();
                        app.fields.clear();
                        app.refresh();
                    }
                }
                KeyCode::Enter if !app.edit_mode && app.action != Action::Query => {
                    let value = Zeroizing::new(app.input.to_string());
                    match app.action {
                        Action::RenameTitle => {
                            if let Some(reference) =
                                app.pending_entry.take().or_else(|| app.entry.clone())
                            {
                                match app.service.set_title(&reference, &value) {
                                    Ok(()) => {
                                        app.dirty = true;
                                        app.reset_tree_after_mutation();
                                        app.entry = None;
                                        app.entry_icon = None;
                                        app.detail.clear();
                                        app.fields.clear();
                                        app.refresh();
                                        app.status =
                                            "Entry title renamed in memory; press s to save".into();
                                    }
                                    Err(error) => app.status = clean(error.message()),
                                }
                            } else {
                                app.status = "No entry selected".into();
                            }
                        }
                        Action::EditTags => {
                            if let Some(reference) =
                                app.pending_entry.take().or_else(|| app.entry.clone())
                            {
                                let tags = value
                                    .split(',')
                                    .map(str::trim)
                                    .filter(|tag| !tag.is_empty())
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>();
                                match app.service.set_tags(&reference, tags) {
                                    Ok(()) => {
                                        app.dirty = true;
                                        app.reset_tree_after_mutation();
                                        app.entry = None;
                                        app.entry_icon = None;
                                        app.detail.clear();
                                        app.fields.clear();
                                        app.refresh();
                                        app.status =
                                            "Entry tags updated in memory; press s to save".into();
                                    }
                                    Err(error) => app.status = clean(error.message()),
                                }
                            } else {
                                app.status = "No entry selected".into();
                            }
                        }
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
                                // A transition to another input action must not
                                // fall through the common input_mode cleanup.
                                continue;
                            }
                            _ => app.status = "Password size must be 1..=4096".into(),
                        },
                        Action::GenerateConfirm => confirm_generation(app, &value),
                        Action::AddAttachment => attachment_add(app, &value),
                        Action::ExportAttachment => attachment_export(app, &value),
                        Action::RemoveAttachment => {
                            if value.as_str() == "YES" {
                                if let Some(target) = app.action_target.take() {
                                    attachment_remove(app, &target.name);
                                }
                            } else {
                                app.status = "Attachment removal cancelled".into();
                            }
                        }
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
                        Action::Query | Action::Edit | Action::SetOtp => unreachable!(),
                    }
                    clear_input(&mut app.input);
                    app.input_mode = false;
                    app.edit_mode = false;
                    app.action_target = None;
                    app.pending_entry = None;
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
                KeyCode::Char('s') => match app.save(path) {
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
                KeyCode::Char('I') => begin_icon_picker(app, None),
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
                    app.entry_icon = None;
                    app.detail.clear();
                    app.fields.clear();
                    app.clear_reveal();
                }
                KeyCode::Char('I') => begin_icon_picker(app, None),
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
                    let prompt = format!(
                        "Edit {} value; input is masked · Enter apply · Esc cancel",
                        clean(&app.edit_field)
                    );
                    begin_action(app, Action::Edit, &prompt);
                    app.edit_mode = true;
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
                        "Copy password? Other apps can read it. nkp will attempt an ownership-safe clear in 30s, but it may remain. Type YES to confirm."
                    } else {
                        "Copy password? Other apps can read it. This platform cannot safely auto-clear; clear manually when done. Type YES to confirm."
                    },
                ),
                KeyCode::Char('t') => begin_action(
                    app,
                    Action::TotpReveal,
                    "Reveal current TOTP? Type YES. HOTP is unsupported. WARNING: terminal scrollback may retain the code.",
                ),
                KeyCode::Char('v') => begin_field_reveal(app),
                KeyCode::Char('a') => begin_action(
                    app,
                    Action::AddAttachment,
                    "Add attachment as name=source-path (bounded to 16 MiB)",
                ),
                KeyCode::Char('x') => begin_attachment_action(app, Action::ExportAttachment),
                KeyCode::Char('d') => begin_attachment_action(app, Action::RemoveAttachment),
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
                KeyCode::Char('n') => app.move_attachment(true),
                KeyCode::Char('p') => app.move_attachment(false),
                KeyCode::Down | KeyCode::Char('j') => {
                    move_field_selection(&mut app.selected_field, app.fields.len(), true);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    move_field_selection(&mut app.selected_field, app.fields.len(), false);
                }
                KeyCode::Char('s') => match app.save(path) {
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
    app.lock_vault();
    Ok(())
}

/// Starts the explicitly selected TUI command.
/// Unix restoration discards queued typeahead while echo/signals are disabled,
/// then reinstates exact prior modes. No primary-screen clearing is performed.
/// Escaping UI errors lock the App before potentially blocking terminal teardown;
/// recoverable save failures retain the unlocked App for an explicit retry.
pub fn launch(path: &Path, aliases: Vec<String>, color_override: ColorOverride) -> io::Result<()> {
    #[cfg(unix)]
    let mut password =
        terminal_password::read_controlling("Vault password: ", Duration::from_secs(300))?;
    #[cfg(not(unix))]
    let mut password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    let mut credentials = KdbxCredentials::password(&password)
        .map_err(|_| io::Error::other("invalid credentials"))?;
    password.zeroize();
    drop(password);
    let mut service = VaultService::default();
    let session = service
        .open(path, &mut credentials, &KDBX_LIMITS)
        .map_err(|_| io::Error::other("cannot unlock vault"))?;
    let theme = TuiTheme::from_tier(detect_color_tier_from_env(color_override));
    let mut app = new_app_with_theme(service, session, credentials, aliases, theme)?;
    app.refresh();
    #[cfg(unix)]
    let result = run_terminal(&mut app, path);
    #[cfg(not(unix))]
    let result = ratatui::run(|terminal| {
        app_result_before_teardown(&mut app, |app| run_ui(terminal, app, path))
    });
    app.lock_vault();
    result
}

fn app_result_before_teardown(
    app: &mut App,
    run: impl FnOnce(&mut App) -> io::Result<()>,
) -> io::Result<()> {
    let result = run(app);
    // Normal run_ui completion already locks the vault. Escaping errors must
    // do so too, before screen writes or mode restoration can block/fail.
    // Recoverable save errors stay inside run_ui and never cross this boundary.
    if result.is_err() {
        app.lock_vault();
    }
    result
}

#[cfg(unix)]
fn run_initialized_terminal<T>(
    app: &mut App,
    initialized: io::Result<T>,
    run: impl FnOnce(&mut T, &mut App) -> io::Result<()>,
) -> io::Result<()> {
    match initialized {
        Ok(mut terminal) => {
            // Keep ownership OUTSIDE the callback: Terminal::drop can write a
            // cursor-restoration command. Escaping errors must lock the App
            // while this terminal is still alive, before even that first write.
            let result = app_result_before_teardown(app, |app| run(&mut terminal, app));
            drop(terminal);
            result
        }
        Err(error) => {
            // No successfully initialized terminal to own/drop on this path.
            // Lock before the caller's explicit mode/screen teardown.
            app.lock_vault();
            Err(error)
        }
    }
}

#[cfg(unix)]
fn run_terminal(app: &mut App, path: &Path) -> io::Result<()> {
    use std::io::IsTerminal;
    // Match Crossterm's existing mode-descriptor selection, without changing
    // split-terminal admission or installing a second signal architecture.
    let terminal = if io::stdin().is_terminal() {
        io::stdin().as_fd().try_clone_to_owned().map(File::from)?
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?
    };
    let mut modes = terminal_password::QuietTerminal::new(terminal)?;
    // Ratatui's panic hook also restores its QUIET snapshot, before unwinding
    // reaches modes. It cannot replay input under the original echo/ISIG bits.
    let result = run_initialized_terminal(app, ratatui::try_init(), |terminal, app| {
        run_ui(terminal, app, path)
    });
    restore_terminal_with(
        result,
        crossterm::terminal::disable_raw_mode,
        || leave_alternate_screen(&mut io::stdout()),
        || modes.restore(),
    )
}

#[cfg(unix)]
fn leave_alternate_screen(output: &mut impl io::Write) -> io::Result<()> {
    crossterm::execute!(output, crossterm::terminal::LeaveAlternateScreen)
}

#[cfg(unix)]
fn restore_terminal_with(
    result: io::Result<()>,
    disable_raw: impl FnOnce() -> io::Result<()>,
    leave_screen: impl FnOnce() -> io::Result<()>,
    restore_modes: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Never short-circuit: a failed backend mode restore must not strand the
    // alternate screen, and a failed screen write must not skip exact modes.
    let result = finish_terminal(result, disable_raw());
    let result = finish_terminal(result, leave_screen());
    finish_terminal(result, restore_modes())
}

#[cfg(unix)]
fn finish_terminal(result: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => Err(io::Error::new(
            primary.kind(),
            format!("{primary}; terminal restoration also failed: {cleanup}"),
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
fn new_app(
    service: VaultService,
    session: nkeepass::SessionId,
    credentials: KdbxCredentials,
    aliases: Vec<String>,
) -> io::Result<App> {
    new_app_with_theme(
        service,
        session,
        credentials,
        aliases,
        TuiTheme::from_tier(ColorTier::Basic16),
    )
}

fn new_app_with_theme(
    service: VaultService,
    session: nkeepass::SessionId,
    credentials: KdbxCredentials,
    aliases: Vec<String>,
    theme: TuiTheme,
) -> io::Result<App> {
    let tree_parent = service
        .root_group(session)
        .map_err(|_| io::Error::other("cannot read vault root"))?;
    Ok(App {
        service,
        session,
        credentials: Some(credentials),
        hits: Vec::new(),
        groups: Vec::new(),
        tree_parent,
        tree_stack: Vec::new(),
        tree_cursor: None,
        list_cursor: None,
        page_failure: None,
        selected: 0,
        query: Zeroizing::new(String::new()),
        query_before_input: Zeroizing::new(String::new()),
        entry: None,
        entry_icon: None,
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
        action_prompt: String::new(),
        pending_group: None,
        pending_entry: None,
        dirty: false,
        pending_decision: None,
        attachment_selected: 0,
        action_target: None,
        field_to_reveal: Zeroizing::new(String::new()),
        generation_size: 32,
        clipboard: ClipboardLease::new(ArboardAdapter::default(), CLIPBOARD_TTL),
        clipboard_may_contain_password: false,
        clipboard_warning_pending: false,
        include_groups: true,
        aliases,
        modal: None,
        theme,
    })
}

#[cfg(test)]
mod tests {
    // Private branching cleanup orchestration: every failure combination must
    // preserve ordering, attempt all stages and retain every error.
    #[cfg(unix)]
    #[test]
    fn terminal_cleanup_faults_never_skip_screen_exit_or_exact_modes() -> std::io::Result<()> {
        use std::cell::RefCell;
        use std::io;
        for faults in 0u8..16 {
            let calls = RefCell::new(Vec::new());
            let operation = |bit, label| {
                calls.borrow_mut().push(label);
                if faults & bit != 0 {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, label))
                } else {
                    Ok(())
                }
            };
            let primary = if faults & 1 != 0 {
                Err(io::Error::new(io::ErrorKind::InvalidData, "primary"))
            } else {
                Ok(())
            };
            let result = super::restore_terminal_with(
                primary,
                || operation(2, "backend mode"),
                || operation(4, "screen exit"),
                || operation(8, "exact modes"),
            );
            assert_eq!(
                *calls.borrow(),
                ["backend mode", "screen exit", "exact modes"]
            );
            if faults == 0 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
            if let Err(error) = result {
                assert_eq!(
                    error.kind(),
                    if faults & 1 != 0 {
                        io::ErrorKind::InvalidData
                    } else {
                        io::ErrorKind::BrokenPipe
                    }
                );
                for (bit, label) in [
                    (1, "primary"),
                    (2, "backend mode"),
                    (4, "screen exit"),
                    (8, "exact modes"),
                ] {
                    assert_eq!(error.to_string().contains(label), faults & bit != 0);
                }
            }
        }
        let mut output = Vec::new();
        super::leave_alternate_screen(&mut output)?;
        assert_eq!(
            output, b"\x1b[?1049l",
            "screen exit must not erase primary screen"
        );
        Ok(())
    }

    use super::clean;

    // Private lifecycle ownership is not observable through a terminal transcript.
    // The provider observes destruction safely, without inspecting freed memory.
    struct DropProbe(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl neotales_keepass::CredentialProvider for DropProbe {
        fn key_component(&mut self) -> Result<[u8; 32], neotales_keepass::KdbxError> {
            Ok([0x42; 32])
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[allow(
        clippy::unwrap_used,
        reason = "disposable credential lifecycle fixture"
    )]
    fn lifecycle_fixture() -> (
        tempfile::TempDir,
        super::App,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use neotales_keepass::{KdbxCredentials, KdbxWriteOptions};
        use std::sync::{Arc, atomic::AtomicBool};

        let dropped = Arc::new(AtomicBool::new(false));
        let mut credentials = KdbxCredentials::with_provider(
            Some("disposable-lifecycle-password"),
            Box::new(DropProbe(Arc::clone(&dropped))),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lifecycle.kdbx");
        let mut service = super::VaultService::default();
        service
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
        let session = service
            .open(&path, &mut credentials, &super::KDBX_LIMITS)
            .unwrap();
        let app = super::new_app(service, session, credentials, Vec::new()).unwrap();
        (directory, app, dropped)
    }

    // Private return/teardown ordering is not visible in a PTY transcript.
    // Inject an escaping UI/init error and observe ownership at the FIRST
    // teardown operation, without actually blocking a terminal or timing it.
    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "disposable lifecycle/teardown fault fixture"
    )]
    fn escaping_app_errors_lock_credentials_and_session_before_terminal_teardown() {
        use std::cell::RefCell;
        use std::io;
        use std::sync::atomic::Ordering::SeqCst;
        for primary in ["UI read/draw failure", "terminal initialization failure"] {
            let (directory, mut app, dropped) = lifecycle_fixture();
            let path = directory.path().join("lifecycle.kdbx");
            let original = std::fs::read(&path).unwrap();
            app.service.add_group(&app.tree_parent, "unsaved").unwrap();
            app.dirty = true;
            app.input.push_str("synthetic-live-draft");
            let result = super::app_result_before_teardown(&mut app, |app| {
                assert!(app.credentials.is_some());
                assert!(!dropped.load(SeqCst));
                assert!(app.service.root_group(app.session).is_ok());
                Err(io::Error::new(io::ErrorKind::ConnectionReset, primary))
            });
            let calls = RefCell::new(Vec::new());
            let teardown = |stage| {
                // Even a stuck FIRST teardown call can no longer retain an
                // unlocked App. Later cleanup failures cannot resurrect it.
                assert!(dropped.load(SeqCst), "credentials survived until teardown");
                assert!(app.credentials.is_none());
                assert!(app.locked);
                assert!(app.service.root_group(app.session).is_err());
                assert!(app.input.is_empty());
                calls.borrow_mut().push(stage);
                Err(io::Error::new(io::ErrorKind::BrokenPipe, stage))
            };
            let result = super::restore_terminal_with(
                result,
                || teardown("backend modes"),
                || teardown("screen exit"),
                || teardown("exact modes"),
            );
            assert_eq!(
                *calls.borrow(),
                ["backend modes", "screen exit", "exact modes"]
            );
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            for diagnostic in [primary, "backend modes", "screen exit", "exact modes"] {
                assert!(error.to_string().contains(diagnostic));
            }
            assert!(app.save(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }

    // Private ownership/drop order: a real Ratatui Terminal restores its hidden
    // cursor in Drop, before the explicit backend/screen teardown callbacks.
    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "disposable real-terminal drop-order fixture"
    )]
    fn app_error_destroys_credentials_before_terminal_drop_writes_cursor() -> std::io::Result<()> {
        use std::cell::{Cell, RefCell};
        use std::io;
        use std::rc::Rc;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering::SeqCst},
        };
        struct CursorWriter {
            armed: Rc<Cell<bool>>,
            dropped: Arc<AtomicBool>,
            closed_at_write: Rc<Cell<Option<bool>>>,
            bytes: Rc<RefCell<Vec<u8>>>,
        }
        impl io::Write for CursorWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.armed.get() {
                    self.closed_at_write.set(Some(
                        self.closed_at_write.get().unwrap_or(true) && self.dropped.load(SeqCst),
                    ));
                    self.bytes.borrow_mut().extend_from_slice(bytes);
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (directory, mut app, dropped) = lifecycle_fixture();
        let path = directory.path().join("lifecycle.kdbx");
        let original = std::fs::read(&path)?;
        let armed = Rc::new(Cell::new(false));
        let closed_at_write = Rc::new(Cell::new(None));
        let bytes = Rc::new(RefCell::new(Vec::new()));
        let writer = CursorWriter {
            armed: Rc::clone(&armed),
            dropped: Arc::clone(&dropped),
            closed_at_write: Rc::clone(&closed_at_write),
            bytes: Rc::clone(&bytes),
        };
        // Fixed viewport avoids real terminal queries; this is the production
        // Crossterm writer and Ratatui destructor, not a fake Drop implementation.
        let terminal = ratatui::Terminal::with_options(
            ratatui::backend::CrosstermBackend::new(writer),
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(super::Rect::new(0, 0, 40, 12)),
            },
        )?;
        let result = super::run_initialized_terminal(&mut app, Ok(terminal), |terminal, app| {
            assert!(app.credentials.is_some());
            terminal.hide_cursor()?;
            armed.set(true);
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "synthetic draw/read error",
            ))
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(
            closed_at_write.get(),
            Some(true),
            "credentials alive at cursor-restoration write"
        );
        assert_eq!(bytes.borrow().as_slice(), b"\x1b[?25h");
        assert!(app.credentials.is_none());
        assert!(app.locked);
        assert!(app.service.root_group(app.session).is_err());
        assert_eq!(std::fs::read(&path)?, original);

        let (_directory, mut app, dropped) = lifecycle_fixture();
        let ran = Cell::new(false);
        let result = super::run_initialized_terminal::<()>(
            &mut app,
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "synthetic initialization error",
            )),
            |(), _| {
                ran.set(true);
                Ok(())
            },
        );
        assert!(!ran.get());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(dropped.load(SeqCst));
        assert!(app.service.root_group(app.session).is_err());
        Ok(())
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "disposable credential lifecycle fixture"
    )]
    fn lock_destroys_owned_credentials_before_app_exit() {
        let (directory, mut app, dropped) = lifecycle_fixture();
        let path = directory.path().join("lifecycle.kdbx");
        let original = std::fs::read(&path).unwrap();
        let old_root = app.tree_parent.clone();
        app.last_activity = super::Instant::now().checked_sub(super::IDLE_LOCK).unwrap();
        app.tick();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(app.locked);
        assert!(app.credentials.is_none());
        assert!(app.service.tree_page(&old_root, None).is_err());
        assert!(app.save(&path).is_err());
        let absent = directory.path().join("must-not-be-created.kdbx");
        assert!(app.save(&absent).is_err());
        assert!(!absent.exists());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        app.lock_vault(); // Repeated lock cannot restore credentials.
        assert!(app.save(&path).is_err());
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "disposable credential lifecycle fixture"
    )]
    fn dirty_lock_cancel_failed_save_and_discard_preserve_lifecycle() {
        // Private pending-decision I/O path, including an unfinished masked edit.
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};
        use std::sync::atomic::Ordering::SeqCst;

        for pending in [Pending::Lock, Pending::Exit] {
            let (directory, mut app, dropped) = lifecycle_fixture();
            let path = directory.path().join("lifecycle.kdbx");
            let original = std::fs::read(&path).unwrap();
            app.service.add_group(&app.tree_parent, "unsaved").unwrap();
            app.dirty = true;
            app.last_activity = super::Instant::now().checked_sub(super::IDLE_LOCK).unwrap();
            app.tick();
            assert_eq!(app.pending_decision, Some(Pending::Lock));
            assert!(!dropped.load(SeqCst));
            assert!(!app.locked);
            app.pending_decision = Some(pending);
            assert_eq!(
                app.resolve_pending_decision(Input::Cancel, &path),
                Effect::None
            );
            assert!(app.dirty);
            assert!(app.credentials.is_some());
            assert!(!dropped.load(SeqCst));
            assert!(app.pending_decision.is_none());

            app.pending_decision = Some(pending);
            app.input_mode = true;
            app.edit_mode = true;
            app.input.push_str("unfinished-disposable-edit");
            assert_eq!(
                app.resolve_pending_decision(Input::SaveSucceeded, &path),
                Effect::None
            );
            assert_eq!(app.pending_decision, Some(pending));
            assert!(app.dirty);
            assert!(!app.input.is_empty());
            assert!(!dropped.load(SeqCst));
            assert_eq!(std::fs::read(&path).unwrap(), original);
            super::discard_input_draft(
                &mut app.input,
                &mut app.field_to_reveal,
                &mut app.input_mode,
                &mut app.edit_mode,
            );
            // An absent parent fails staging without modifying the real fixture.
            let bad_path = directory.path().join("absent").join("vault.kdbx");
            assert_eq!(
                app.resolve_pending_decision(Input::SaveSucceeded, &bad_path),
                Effect::None
            );
            assert_eq!(app.pending_decision, Some(pending));
            assert!(app.dirty);
            assert!(!dropped.load(SeqCst));
            let expected = if pending == Pending::Lock {
                Effect::Lock
            } else {
                Effect::Exit
            };
            assert_eq!(
                app.resolve_pending_decision(Input::Discard, &path),
                expected
            );
            assert!(!app.dirty);
            if pending == Pending::Lock {
                assert!(app.locked);
                assert!(dropped.load(SeqCst));
                assert!(app.save(&path).is_err());
            }
            drop(app);
            assert!(dropped.load(SeqCst));
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "disposable credential lifecycle fixture"
    )]
    fn dirty_decision_save_persists_before_lock_or_exit_and_requires_fresh_unlock() {
        // Private pending-decision path with actual encrypted save/reopen.
        use super::{DecisionEffect as Effect, DecisionInput as Input, PendingDecision as Pending};
        use std::sync::atomic::Ordering::SeqCst;

        for pending in [Pending::Lock, Pending::Exit] {
            let (directory, mut app, dropped) = lifecycle_fixture();
            let path = directory.path().join("lifecycle.kdbx");
            app.service.add_group(&app.tree_parent, "saved").unwrap();
            app.dirty = true;
            app.pending_decision = Some(pending);
            let bad_path = directory.path().join("absent").join("vault.kdbx");
            assert_eq!(
                app.resolve_pending_decision(Input::SaveSucceeded, &bad_path),
                Effect::None
            );
            assert_eq!(app.pending_decision, Some(pending));
            assert!(app.dirty);
            assert!(!dropped.load(SeqCst));
            let expected = if pending == Pending::Lock {
                Effect::Lock
            } else {
                Effect::Exit
            };
            assert_eq!(
                app.resolve_pending_decision(Input::SaveSucceeded, &path),
                expected
            );
            assert!(!app.dirty);
            assert!(app.pending_decision.is_none());
            if pending == Pending::Lock {
                assert!(dropped.load(SeqCst));
                assert!(app.save(&path).is_err());
            }
            drop(app);
            assert!(dropped.load(SeqCst));
            // Fresh credentials only: no lock-screen re-unlock or cached retry.
            let mut credentials = neotales_keepass::KdbxCredentials::with_provider(
                Some("disposable-lifecycle-password"),
                Box::new(DropProbe(std::sync::Arc::new(
                    std::sync::atomic::AtomicBool::new(false),
                ))),
            )
            .unwrap();
            let mut reopened = super::VaultService::default();
            let session = reopened
                .open(&path, &mut credentials, &super::KDBX_LIMITS)
                .unwrap();
            let root = reopened.root_group(session).unwrap();
            let page = reopened.tree_page(&root, None).unwrap();
            assert_eq!(page.groups.len(), 1);
            assert_eq!(page.groups[0].label(), "saved");
        }
    }

    #[test]
    #[allow(
        clippy::panic,
        reason = "exercise credential destruction during unwind"
    )]
    fn dropping_unlocked_app_destroys_credentials_on_return_or_unwind() {
        // Private ownership boundary; no terminal admission/signal claim.
        let (_directory, app, dropped) = lifecycle_fixture();
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        drop(app);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        let (_directory, app, dropped) = lifecycle_fixture();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _app = app;
            panic!("disposable lifecycle unwind");
        }));
        assert!(result.is_err());
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    // Private projection branches need exact cells, not an escape-sequence transcript.
    #[allow(clippy::unwrap_used, reason = "disposable UI fixture")]
    fn app_fixture() -> (tempfile::TempDir, super::App) {
        use neotales_keepass::{
            Attachment, Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
            KeePassDatabase,
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.kdbx");
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("Example");
        entry.username = "disposable-user".into();
        entry.url = "https://example.invalid".into();
        entry.notes = "disposable-notes".into();
        entry.password = neotales_keepass::ProtectedValue::from_text("disposable-password");
        for (name, bytes) in [("first.bin", b"first"), ("second.bin", b"other")] {
            let reference = database.binary_pool.add(bytes.to_vec(), true);
            entry.attachments.push(Attachment {
                name: name.into(),
                reference,
            });
        }
        database.root.entries.push(entry);
        let mut credentials = KdbxCredentials::password("disposable-tui-fixture").unwrap();
        KdbxFile::save(
            &database,
            std::fs::File::create(&path).unwrap(),
            &mut credentials,
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        let mut service = nkeepass::VaultService::default();
        let session = service
            .open(&path, &mut credentials, &nkeepass::KDBX_LIMITS)
            .unwrap();
        let mut app = super::new_app(service, session, credentials, Vec::new()).unwrap();
        app.refresh();
        (directory, app)
    }

    #[allow(clippy::unwrap_used, reason = "in-memory test renderer must succeed")]
    fn screen(app: &super::App, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| super::draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn clipboard_warning_returns_to_modal_position_and_deletion_draft() {
        // Private modal ownership branches: warning review must not consume
        // the previous interaction, its scroll position, or typed consent.
        for close in [
            super::KeyCode::Esc,
            super::KeyCode::Enter,
            super::KeyCode::Char('a'),
        ] {
            let (_directory, mut app) = app_fixture();
            app.clipboard_warning_pending = true;
            app.modal = Some(super::Modal::Target {
                label: "Field 2/2".into(),
                target: "long-name".repeat(100),
                offset: 137,
            });
            super::open_clipboard_warning(&mut app);
            super::open_clipboard_warning(&mut app); // Repeated F3 must not nest.
            super::handle_modal_key(&mut app, close);
            assert!(
                matches!(&app.modal, Some(super::Modal::Target { label, offset: 137, .. }) if label == "Field 2/2")
            );
            assert_eq!(
                app.clipboard_warning_pending,
                close != super::KeyCode::Char('a')
            );
            app.clipboard_warning_pending = true;
            app.modal = Some(super::Modal::ConfirmDelete {
                kind: super::DeleteKind::Entry,
                path: "Entry row 1/1: long-name".repeat(30),
                entry: None,
                group: None,
                input: zeroize::Zeroizing::new("YE".into()),
                offset: 71,
            });
            super::open_clipboard_warning(&mut app);
            super::handle_modal_key(&mut app, close);
            assert!(
                matches!(&app.modal, Some(super::Modal::ConfirmDelete { offset: 71, input, .. }) if input.as_str() == "YE")
            );
            assert!(!app.dirty); // Enter in the warning must not submit deletion.
        }
    }

    #[test]
    #[allow(clippy::unwrap_used, reason = "disposable private deletion workflow")]
    fn warning_enter_retains_valid_entry_with_complete_deletion_consent() {
        // Private modal focus regression: use a real selectable entry and YES,
        // so a leaked Enter would actually delete, not merely cancel a draft.
        let (_directory, mut app) = app_fixture();
        let reference = app.hits[0].reference();
        super::begin_delete_entry(&mut app);
        for character in ['Y', 'E', 'S'] {
            super::handle_modal_key(&mut app, super::KeyCode::Char(character));
        }
        assert!(app.service.selected_entry(&reference).is_ok());
        app.clipboard_warning_pending = true;
        super::open_clipboard_warning(&mut app);
        super::handle_modal_key(&mut app, super::KeyCode::Enter);
        assert!(matches!(&app.modal,
            Some(super::Modal::ConfirmDelete { entry: Some(_), input, .. })
                if input.as_str() == "YES"));
        assert!(app.service.selected_entry(&reference).is_ok());
        assert_eq!(
            app.service
                .list_page(app.session, None, None)
                .unwrap()
                .hits
                .len(),
            1
        );
        assert!(!app.dirty);
        assert!(app.clipboard_warning_pending);

        // Positive control: a separate Enter in the restored confirmation
        // deletes this disposable entry in memory. The target/YES were live.
        super::handle_modal_key(&mut app, super::KeyCode::Enter);
        assert!(app.dirty);
        assert_eq!(
            app.service
                .list_page(app.session, None, None)
                .unwrap()
                .hits
                .len(),
            0
        );
    }

    #[test]
    fn unsaved_decision_exposes_clipboard_warning_hint_at_minimum_size() {
        // Exact private projection: this full-screen dialog covers the footer.
        let (_directory, mut app) = app_fixture();
        app.dirty = true;
        app.clipboard_warning_pending = true;
        for decision in [super::PendingDecision::Exit, super::PendingDecision::Lock] {
            app.pending_decision = Some(decision);
            app.status = "Unsaved changes: s save · d discard · c cancel".into();
            let text = screen(&app, 40, 12);
            for required in ["s save", "d discard", "c cancel", "F3 clipboard warning"] {
                assert!(text.contains(required));
            }
        }
    }

    #[test]
    fn long_field_targets_cannot_displace_consent_or_disclosure_warning() {
        // Private minimum-size projection: arbitrarily long metadata must not
        // consume the rows reserved for consent and disclosure warnings.
        let (_directory, mut app) = app_fixture();
        app.select();
        app.fields = ["FIRST-FIELD", "SECOND-FIELD"]
            .into_iter()
            .map(|suffix| (format!("{}{suffix}", "shared-prefix-".repeat(40)), true))
            .collect();
        for (selected, suffix) in ["FIRST-FIELD", "SECOND-FIELD"].into_iter().enumerate() {
            app.selected_field = selected;
            super::begin_field_reveal(&mut app);
            let text = screen(&app, 40, 12);
            for required in [
                "Type YES",
                "WARNING:",
                "screenshots may persist.",
                "F2 inspect full target",
            ] {
                assert!(text.contains(required));
            }
            super::inspect_action_target(&mut app);
            super::handle_modal_key(&mut app, super::KeyCode::End);
            let text = screen(&app, 40, 12);
            assert!(text.contains(suffix));
            assert!(text.contains(&format!("Field {}/2", selected + 1)));
            super::handle_modal_key(&mut app, super::KeyCode::Esc);
            assert!(app.input_mode);
            assert!(screen(&app, 40, 12).contains("Type YES"));
        }
    }

    #[test]
    fn failed_clipboard_clear_warning_survives_confirmation_status() {
        // Private async notice reduction: action success must not erase an
        // unacknowledged warning about an external copy of the password.
        let (_directory, mut app) = app_fixture();
        app.select();
        super::begin_action(
            &mut app,
            super::Action::GenerateConfirm,
            "Type YES to replace password.",
        );
        app.apply_clipboard_tick(Err(crate::clipboard::ClipboardError));
        assert!(app.clipboard_warning_pending);
        super::open_clipboard_warning(&mut app);
        let text = screen(&app, 40, 12);
        for required in [
            "Clear it manually.",
            "Acknowledging",
            "a acknowledge",
            "Esc back",
        ] {
            assert!(text.contains(required));
        }
        super::handle_modal_key(&mut app, super::KeyCode::Esc);
        assert!(app.clipboard_warning_pending);
        assert!(app.input_mode);
        super::confirm_generation(&mut app, "YES");
        app.input_mode = false;
        assert!(app.dirty);
        assert!(app.status.contains("Password replaced in memory"));
        let text = screen(&app, 40, 12);
        assert!(text.contains("Clear it manually."));
        assert!(text.contains("F3"));
        app.status = "Saved".into();
        app.refresh();
        assert!(app.clipboard_warning_pending);
        super::open_clipboard_warning(&mut app);
        let text = screen(&app, 40, 12);
        assert!(text.contains("Clear it manually."));
        assert!(text.contains("Acknowledging"));
        super::handle_modal_key(&mut app, super::KeyCode::Enter);
        assert!(app.clipboard_warning_pending); // Enter is not acknowledgement.
        app.lock_vault();
        assert!(app.clipboard_warning_pending);
        assert!(screen(&app, 40, 12).contains("Clear it manually."));
        super::open_clipboard_warning(&mut app);
        super::handle_modal_key(&mut app, super::KeyCode::Char('a'));
        assert!(!app.clipboard_warning_pending);
        assert!(app.clipboard_may_contain_password); // Ack does not claim a clear.
    }

    #[test]
    fn compact_entry_keeps_each_selected_field_visible() {
        // Exact private viewport projection at the supported minimum size.
        let (_directory, mut app) = app_fixture();
        app.select();
        assert_eq!(app.fields.len(), 5);
        for selected in 0..app.fields.len() {
            app.selected_field = selected;
            let text = screen(&app, 40, 12);
            assert!(text.contains(&format!("> {}", app.fields[selected].0)));
            let name = app.fields[selected].0.clone();
            super::begin_field_reveal(&mut app);
            let text = screen(&app, 40, 12);
            assert!(text.contains(&format!("Reveal field: {name}")));
            assert!(text.contains("Type YES"));
            assert_eq!(app.field_to_reveal.as_str(), name);
            app.input_mode = false;
        }
    }

    #[test]
    #[allow(clippy::unwrap_used, reason = "in-memory clipboard expiry fixture")]
    fn clipboard_lease_expiry_does_not_replace_live_consent_instructions() {
        // Private projection/async reduction with an actual expired lease and
        // a fake adapter: no system clipboard, clock sleeps, or user data.
        use crate::clipboard::{
            ClipboardAdapter, ClipboardError, ClipboardLease, ClipboardSetOutcome,
        };
        struct Adapter(u8);
        impl ClipboardAdapter for Adapter {
            fn set_text(&mut self, _: &str) -> Result<ClipboardSetOutcome, ClipboardError> {
                Ok(ClipboardSetOutcome::Copied)
            }
            fn clear_if_current(&mut self, _: &str) -> Result<bool, ClipboardError> {
                match self.0 {
                    0 => Ok(true),
                    1 => Ok(false),
                    _ => Err(ClipboardError),
                }
            }
        }
        for outcome in 0..3 {
            let (_directory, mut app) = app_fixture();
            super::begin_action(
                &mut app,
                super::Action::GenerateConfirm,
                "This replaces the current password. Type YES to confirm; any other input cancels.",
            );
            let instructions = app.action_prompt.clone();
            let mut lease = ClipboardLease::new(Adapter(outcome), std::time::Duration::ZERO);
            lease
                .copy(zeroize::Zeroizing::new("disposable-copy".into()))
                .unwrap();
            app.apply_clipboard_tick(lease.tick(std::time::Instant::now()));
            assert!(!lease.has_lease());
            assert_eq!(app.clipboard_warning_pending, outcome != 0);
            assert_eq!(app.action, super::Action::GenerateConfirm);
            assert!(app.input_mode);
            assert_eq!(app.action_prompt, instructions);
            assert!(app.status.contains(if outcome == 0 {
                "Clipboard lease expired"
            } else {
                "Clear it manually"
            }));
            let text = screen(&app, 40, 12);
            assert!(text.contains("This replaces the current password."));
            assert!(text.contains("Type YES"));
            assert!(text.contains("Notice: Clipboard"));
            assert!(text.contains("Esc: full notice in status"));
        }
    }

    #[test]
    fn status_warning_and_action_confirmation_are_visible_at_narrow_size() {
        let (_directory, mut app) = app_fixture();
        app.status = "Clipboard expiry could not safely clear it; it may still contain the password. Clear it manually.".into();
        let text = screen(&app, 40, 12);
        assert!(text.contains("Clipboard expiry"));
        assert!(text.contains("Clear it manually."));
        super::begin_action(
            &mut app,
            super::Action::PasswordReveal,
            "Reveal password? Type YES. WARNING: terminal scrollback and screenshots may retain it; shown for 15s.",
        );
        let text = screen(&app, 40, 12);
        assert!(text.contains("Type YES."));
        assert!(text.contains("WARNING:"));
        assert!(text.contains("Esc cancel"));
        app.input_mode = false;
        app.pending_decision = Some(super::PendingDecision::Exit);
        app.status = "Save failed: cannot save vault.".into();
        let text = screen(&app, 40, 12);
        for expected in ["Save failed:", "s save", "d discard", "c cancel"] {
            assert!(text.contains(expected));
        }
        app.pending_decision = Some(super::PendingDecision::Lock);
        app.status = "Idle lock requested. Unsaved changes: s save · d discard · c cancel".into();
        let text = screen(&app, 40, 12);
        assert!(text.contains("Idle lock requested."));
        assert!(text.contains("d discard"));
        app.pending_decision = None;
        app.clipboard_may_contain_password = true;
        app.lock_vault();
        let text = screen(&app, 40, 12);
        assert!(text.contains("Vault locked; clipboard"));
        assert!(text.contains("Press q to exit."));
    }

    #[test]
    fn last_tree_and_filter_pages_remain_visible_without_a_next_cursor() {
        let (_directory, mut app) = app_fixture();
        assert_eq!(app.hits.len(), 1);
        app.next_page();
        assert_eq!(app.hits.len(), 1);
        app.query.push('*');
        app.refresh();
        assert_eq!(app.hits.len(), 1);
        app.next_page();
        assert_eq!(app.hits.len(), 1);
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "private continuation failure with disposable data"
    )]
    fn failed_continuations_retain_rows_and_error_until_explicit_restart() {
        for filtered in [false, true] {
            let (_directory, mut app) = app_fixture();
            let path = app.service.group_path(&app.tree_parent).unwrap();
            for index in 0..if filtered { 350 } else { 130 } {
                let title = if filtered {
                    format!("row-{index}-{}", "x".repeat(3500))
                } else {
                    format!("row-{index}")
                };
                app.service
                    .ensure_entry(app.session, &format!("{path}/{title}"), None, false)
                    .unwrap();
            }
            if filtered {
                app.query.push('*');
            }
            app.refresh();
            assert!(if filtered {
                app.list_cursor.is_some()
            } else {
                app.tree_cursor.is_some()
            });
            let rows = app.hits.len();
            app.service
                .ensure_entry(
                    app.session,
                    &format!("{path}/invalidate-continuation"),
                    None,
                    false,
                )
                .unwrap();
            app.next_page();
            let failure = app.status.clone();
            assert!(failure.contains("restart"));
            app.status = "unrelated status".into();
            app.next_page();
            assert_eq!(app.status, failure);
            assert_eq!(app.hits.len(), rows);
            app.refresh();
            assert!(app.page_failure.is_none()); // Explicit refresh rebases stale handles.
        }
    }

    #[test]
    fn deletion_and_reveal_warnings_survive_long_metadata_and_small_screens() {
        let (_directory, mut app) = app_fixture();
        app.modal = Some(super::Modal::ConfirmDelete {
            kind: super::DeleteKind::Group,
            path: format!("Group row 2/2: {}TAIL", "long-target".repeat(200)),
            entry: None,
            group: None,
            input: zeroize::Zeroizing::new(String::new()),
            offset: 0,
        });
        let text = screen(&app, 40, 12);
        assert!(text.contains("Type YES"));
        assert!(text.contains("Esc cancel"));
        super::handle_modal_key(&mut app, super::KeyCode::End);
        let text = screen(&app, 40, 12);
        assert!(text.contains("TAIL"));
        assert!(text.contains("Group row 2/2"));
        app.modal = None;
        app.reveal = Some(zeroize::Zeroizing::new("disposable-render-marker".into()));
        app.detail = vec!["metadata".into(); 100];
        let text = screen(&app, 40, 12);
        assert!(text.contains("WARNING:"));
        assert!(text.contains("disposable-render-marker"));
        let text = screen(&app, 30, 8);
        assert!(text.contains("Resize terminal"));
        assert!(!text.contains("disposable-render-marker"));
    }

    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "private attachment projection and disposable export"
    )]
    fn attachment_marker_and_action_target_follow_live_selection() {
        let (directory, mut app) = app_fixture();
        app.select();
        app.move_attachment(true);
        let text = screen(&app, 120, 40);
        assert!(text.contains("> second.bin"));
        assert!(!text.contains("> first.bin"));
        super::begin_attachment_action(&mut app, super::Action::ExportAttachment);
        super::inspect_action_target(&mut app);
        let text = screen(&app, 40, 12);
        assert!(text.contains("Attachment 2/2"));
        assert!(text.contains("second.bin"));
        super::handle_modal_key(&mut app, super::KeyCode::Esc);
        assert!(app.input_mode);
        let destination = directory.path().join("export.bin");
        super::attachment_export(&mut app, destination.to_str().unwrap());
        let selected_bytes_match = std::fs::read(destination).unwrap() == b"other";
        assert!(
            selected_bytes_match,
            "export did not match the marked target"
        );
        app.input_mode = false;
        app.move_attachment(false);
        let text = screen(&app, 120, 40);
        assert!(text.contains("> first.bin"));
        assert!(!text.contains("> second.bin"));
    }

    #[test]
    fn target_offsets_use_sanitized_characters_and_reach_distinct_suffixes() {
        let target = format!("{}SECOND.bin\u{1b}", "界".repeat(100));
        let end = super::move_target_offset(0, &target, super::KeyCode::End);
        let tail: String = clean(&target).chars().skip(end).collect();
        assert!(tail.ends_with("SECOND.bin\\u{1b}"));
        assert_eq!(tail.chars().count(), 32);
        assert_eq!(
            super::move_target_offset(end, &target, super::KeyCode::Right),
            end
        );
        assert_eq!(
            super::move_target_offset(end, &target, super::KeyCode::Home),
            0
        );
    }

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
        assert_eq!(
            clean("a\u{202e}b\u{2066}c\u{2028}d\u{2029}e\u{061c}f\u{200e}g"),
            "a\\u{202e}b\\u{2066}c\\u{2028}d\\u{2029}e\\u{61c}f\\u{200e}g"
        );
        assert_eq!(
            super::clean_secret("sec\u{202e}ret\u{2028}1").as_str(),
            "sec\\u{202e}ret\\u{2028}1"
        );
    }

    #[test]
    fn bounded_input_rejects_oversized_and_non_regular_sources() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("bounded");
        std::fs::write(&file, b"12345").unwrap();
        assert!(super::bounded_read(&file, 4).is_err());
        assert_eq!(super::bounded_read(&file, 5).unwrap().as_slice(), b"12345");
        assert!(super::bounded_read(directory.path(), 100).is_err());
        #[cfg(unix)]
        {
            let link = directory.path().join("bounded.link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(super::bounded_read(&link, 100).is_err());

            let fifo = directory.path().join("bounded.fifo");
            if std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .is_ok_and(|status| status.success())
            {
                assert!(super::bounded_read(&fifo, 100).is_err());
            }
        }
    }

    #[test]
    #[cfg(not(windows))]
    #[allow(clippy::unwrap_used, reason = "disposable tree save/reopen fixture")]
    fn tree_mutation_can_be_saved_without_opening_an_entry() {
        use super::{KDBX_LIMITS, VaultService};
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

        let mut app = super::new_app(service, session, credentials, Vec::new()).unwrap();
        app.save(&path).unwrap();

        let mut reopened = VaultService::default();
        let mut credentials = KdbxCredentials::password("tree-save-test").unwrap();
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
    #[cfg(windows)]
    fn vault_creation_uses_private_windows_permissions() {
        use super::VaultService;
        use neotales_keepass::{KdbxCredentials, KdbxWriteOptions};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unsupported.kdbx");
        let mut credentials = KdbxCredentials::password("windows-permissions-test").unwrap();
        VaultService::default()
            .create(&path, &mut credentials, KdbxWriteOptions::default(), None)
            .unwrap();
        windows_private_file::verify(&std::fs::File::open(path).unwrap()).unwrap();
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

    #[test]
    fn adaptive_color_tiers_select_and_fall_back_gracefully() {
        use std::collections::HashSet;
        use std::ffi::OsStr;

        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                Some(OsStr::new("1")),
                Some("xterm-256color"),
                Some("truecolor"),
                None,
                None,
                None,
            ),
            super::ColorTier::None
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                None,
                Some("dumb"),
                Some("truecolor"),
                Some(OsStr::new("1")),
                None,
                None,
            ),
            super::ColorTier::None
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Never,
                None,
                Some("xterm-256color"),
                Some("truecolor"),
                None,
                None,
                None,
            ),
            super::ColorTier::None
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                Some(OsStr::new("")),
                Some("xterm-256color"),
                Some("truecolor"),
                None,
                None,
                None,
            ),
            super::ColorTier::TrueColor
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                None,
                Some("xterm"),
                Some("24bit"),
                None,
                None,
                None,
            ),
            super::ColorTier::TrueColor
        );
        for env_flag in ["wt", "kitty", "wezterm"] {
            let tier = super::detect_color_tier(
                super::ColorOverride::Auto,
                None,
                Some("xterm"),
                None,
                (env_flag == "wt").then_some(OsStr::new("session")),
                (env_flag == "kitty").then_some(OsStr::new("1")),
                (env_flag == "wezterm").then_some(OsStr::new("0")),
            );
            assert_eq!(tier, super::ColorTier::TrueColor, "{env_flag}");
        }
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                None,
                Some("xterm-256color"),
                None,
                None,
                None,
                None,
            ),
            super::ColorTier::Ansi256
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Auto,
                None,
                Some("xterm"),
                None,
                None,
                None,
                None,
            ),
            super::ColorTier::Basic16
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::Basic,
                None,
                Some("xterm-256color"),
                Some("truecolor"),
                None,
                None,
                None,
            ),
            super::ColorTier::Basic16
        );

        let none_theme = super::TuiTheme::from_tier(super::ColorTier::None);
        for style in [
            none_theme.header,
            none_theme.muted,
            none_theme.selection,
            none_theme.dirty,
            none_theme.error,
            none_theme.warning,
        ] {
            assert_eq!(style.fg, None);
            assert_eq!(style.bg, None);
        }
        let categories = [
            nkeepass::icons::IconCategory::Security,
            nkeepass::icons::IconCategory::Network,
            nkeepass::icons::IconCategory::System,
            nkeepass::icons::IconCategory::Personal,
            nkeepass::icons::IconCategory::Folders,
            nkeepass::icons::IconCategory::Media,
            nkeepass::icons::IconCategory::Misc,
        ];
        for tier in [
            super::ColorTier::TrueColor,
            super::ColorTier::Ansi256,
            super::ColorTier::Basic16,
        ] {
            let theme = super::TuiTheme::from_tier(tier);
            let distinct: HashSet<_> = categories
                .iter()
                .map(|cat| theme.category_style(*cat).fg)
                .collect();
            assert_eq!(distinct.len(), categories.len(), "{tier:?}");
            assert!(!distinct.contains(&None), "{tier:?}");
        }
    }

    #[test]
    fn icons_render_on_groups_entries_detail_and_picker_persists() {
        use crossterm::event::KeyCode;
        use nkeepass::icons::standard_icon;

        let (_dir, mut app) = app_fixture();
        // Path-only group defaults to standard KeePass folder icon 48.
        let path_group = super::UiGroup::from_path("Root/Work".to_owned());
        assert_eq!(path_group.icon_id, 48);
        assert_eq!(path_group.custom_icon_id, None);

        // Add a child group and assign a custom standard icon to entry + group via IconPicker.
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Mail").unwrap();
        app.reset_tree_after_mutation();
        app.refresh();
        assert_eq!(app.groups.len(), 1);
        assert_eq!(app.groups[0].icon_id, 48);

        let rendered_tree = screen(&app, 80, 20);
        assert!(rendered_tree.contains(standard_icon(48).glyph));
        assert!(rendered_tree.contains(standard_icon(0).glyph));
        assert!(rendered_tree.contains("nkp"));

        // Open IconPicker on group row (selected == 0), filter for "Email" (19), apply.
        super::begin_icon_picker(&mut app, Some(true));
        assert!(matches!(app.modal, Some(super::Modal::IconPicker { .. })));
        let picker_screen = screen(&app, 40, 12);
        assert!(picker_screen.contains("nkp Icons"));

        super::handle_modal_key(&mut app, KeyCode::Char('/'));
        for ch in "Email".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        let filtered = super::filtered_standard_icons("Email");
        assert!(filtered.iter().any(|icon| icon.id == 19));
        // Cancel first with Esc to verify no dirty mutation.
        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());
        assert!(!app.dirty);

        // Now apply icon 19 ("Email") to the group.
        super::begin_icon_picker(&mut app, Some(true));
        super::handle_modal_key(&mut app, KeyCode::Char('/'));
        for ch in "19".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.dirty);
        assert_eq!(app.groups[0].icon_id, 19);
        let rendered_updated = screen(&app, 80, 20);
        assert!(rendered_updated.contains(standard_icon(19).glyph));

        // Select entry (row 1 after 1 group) and open detail view; verify Icon header.
        app.selected = 1;
        app.select();
        let detail_screen = screen(&app, 80, 24);
        assert!(detail_screen.contains("Icon: ⚷ Key"));
        assert!(!detail_screen.contains("[custom]"));

        // Simulate custom icon indicator on selected entry header.
        app.entry_icon = Some((19, nkeepass::CustomIconId::from_bytes([0x22; 16])));
        app.detail[1] = "Icon: ✉ Email [custom]".to_owned();
        let custom_detail_screen = screen(&app, 80, 24);
        assert!(custom_detail_screen.contains("Icon: ✉ Email [custom]"));
    }

    #[test]
    fn totp_uri_validation_and_entry_ergonomic_mutations_work() {
        let (_dir, mut app) = app_fixture();
        assert!(
            super::validate_totp_uri(
                "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30"
            )
            .is_ok()
        );
        assert!(super::validate_totp_uri("not-a-uri").is_err());
        assert!(
            super::validate_totp_uri("otpauth://hotp/mail?secret=JBSWY3DPEHPK3PXP&counter=0")
                .is_err()
        );
        assert!(
            super::validate_totp_uri("otpauth://totp/mail?secret=BAD!BASE32&period=30").is_err()
        );
        assert!(
            super::validate_totp_uri("otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP&period=0")
                .is_err()
        );

        let entry_ref = app.hits[0].reference();
        app.service.set_title(&entry_ref, "renamed-entry").unwrap();
        let renamed_ref = app
            .service
            .resolve_entry(app.session, "renamed-entry")
            .unwrap()
            .reference();
        app.service
            .set_tags(&renamed_ref, vec!["work".into(), "mail".into()])
            .unwrap();
        let tagged_ref = app
            .service
            .resolve_entry(app.session, "renamed-entry")
            .unwrap()
            .reference();
        app.service
            .set_custom_field(
                &tagged_ref,
                "otp",
                "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
            )
            .unwrap();
        let final_ref = app
            .service
            .resolve_entry(app.session, "renamed-entry")
            .unwrap()
            .reference();
        let view = app.service.selected_entry(&final_ref).unwrap();
        assert_eq!(view.title(), "renamed-entry");
        assert_eq!(view.tags(), ["work", "mail"]);
        assert!(view.has_otp());
        assert!(app.service.totp_code_with_period(&final_ref, 59).is_ok());
    }
}
