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
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use neotales_keepass::KdbxCredentials;
use nkeepass::{
    CustomIconId, KDBX_LIMITS, SearchHit, VaultService,
    glob::Glob,
    icons::{DEFAULT_GROUP_ICON_ID, IconCategory, StandardIcon, standard_icon, standard_icons},
    service::{
        DatabaseSettings, DatabaseSettingsUpdate, EntryRef, GroupRef, GroupTreeNode, ListCursor,
        ListPage, OtpConfig, OtpMetadata, PathCompletion, ServiceOtpAlgorithm, ServiceOtpKind,
        TreeCursor, TreeGroup, VaultCipher, VaultCompression, VaultKdfSummary,
    },
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
    if override_mode == ColorOverride::TrueColor {
        return ColorTier::TrueColor;
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
    focused_border: Style,
    unfocused_border: Style,
    cat_security: Style,
    cat_network: Style,
    cat_system: Style,
    cat_personal: Style,
    cat_folders: Style,
    cat_media: Style,
    cat_misc: Style,
}

impl TuiTheme {
    #[allow(
        clippy::too_many_lines,
        reason = "defines all four adaptive color tiers in one table"
    )]
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
                focused_border: Style::default()
                    .fg(Color::Rgb(80, 190, 255))
                    .add_modifier(Modifier::BOLD),
                unfocused_border: Style::default().fg(Color::Rgb(90, 100, 115)),
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
                focused_border: Style::default()
                    .fg(Color::Indexed(39))
                    .add_modifier(Modifier::BOLD),
                unfocused_border: Style::default().fg(Color::Indexed(240)),
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
                focused_border: Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                unfocused_border: Style::default().fg(Color::DarkGray),
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
                focused_border: Style::default().add_modifier(Modifier::BOLD),
                unfocused_border: Style::default().add_modifier(Modifier::DIM),
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
    PermanentEntry,
    Group,
    EmptyRecycleBin,
}

enum IconTarget {
    EntryItem(EntryRef),
    GroupItem(GroupRef),
}

struct MoveGroupRow {
    group_ref: GroupRef,
    row_label: String,
    row_path: String,
    depth: usize,
    std_icon: u32,
    recycle_bin: bool,
}

#[derive(Clone)]
struct PathCompletionItem {
    full_path: String,
    leaf_label: String,
    is_group_item: bool,
    std_icon: u32,
    target_group: Option<GroupRef>,
    target_entry: Option<EntryRef>,
}

struct PathBarState {
    buffer: String,
    completions: Vec<PathCompletionItem>,
    selected: usize,
    dropdown_open: bool,
    error_msg: Option<String>,
}

struct OtpConfigDraft {
    entry_ref: EntryRef,
    otp_kind: ServiceOtpKind,
    otp_algorithm: ServiceOtpAlgorithm,
    otp_digits: u8,
    period_text: String,
    counter_text: String,
    use_steam: bool,
    acct_label: String,
    issuer_label: String,
    secret_b32: Zeroizing<String>,
    selected_row: usize,
    editing_text: bool,
    error_msg: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DbKdfKind {
    Argon2id,
    Argon2d,
    Aes,
}

struct DbSettingsDraft {
    db_name: String,
    db_desc: String,
    db_default_user: String,
    recycle_enabled: bool,
    hist_max_items: String,
    hist_max_size: String,
    cipher: VaultCipher,
    compression: VaultCompression,
    kdf_kind: DbKdfKind,
    aes_rounds: String,
    argon_mem: String,
    argon_iters: String,
    argon_lanes: String,
    selected_row: usize,
    editing_text: bool,
    error_msg: Option<String>,
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
    MoveEntry {
        entry_ref: EntryRef,
        entry_title: String,
        rows: Vec<MoveGroupRow>,
        selected: usize,
        scroll: usize,
        error_msg: Option<String>,
    },
    OtpConfig(OtpConfigDraft),
    PathBar(PathBarState),
    DbSettings(DbSettingsDraft),
}

enum TreeOrListPage {
    Tree(Vec<SearchHit>, usize),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FocusPane {
    Groups,
    Entries,
    Detail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyOutcome {
    Continue,
    Exit,
}

struct App {
    service: VaultService,
    session: nkeepass::SessionId,
    // No outer launch/run_ui borrow may keep these alive after lock.
    credentials: Option<KdbxCredentials>,
    vault_name: String,
    focus: FocusPane,
    hits: Vec<SearchHit>,
    groups: Vec<UiGroup>,
    tree_parent: GroupRef,
    tree_stack: Vec<GroupRef>,
    tree_cursor: Option<TreeCursor>,
    list_cursor: Option<ListCursor>,
    tree_page_index: usize,
    tree_withheld: usize,
    page_failure: Option<String>,
    group_selected: usize,
    entry_selected: usize,
    groups_offset: usize,
    entries_offset: usize,
    detail_scroll: usize,
    detail_max_scroll: usize,
    compact_detail: bool,
    compact_fields_offset: usize,
    compact_fields_area: Rect,
    header_area: Rect,
    groups_area: Rect,
    entries_area: Rect,
    detail_area: Rect,
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

#[cfg(test)]
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
            app.re_resolve_current_tree();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = "Password replaced in memory; press Ctrl+S or s to save".into();
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
        && app.focus == FocusPane::Groups
        && let Some(idx) = app.group_index_for_row(app.group_selected)
        && let Some(group) = app.groups.get(idx)
    {
        return group
            .reference
            .clone()
            .or_else(|| app.service.resolve_group(app.session, &group.path).ok());
    }
    Some(app.tree_parent.clone())
}

fn begin_delete_entry(app: &mut App) {
    let selected = app.hits.get(app.entry_selected);
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
            app.entry_selected + 1,
            app.hits.len().max(1)
        ),
        entry: Some(reference),
        group: None,
        input: Zeroizing::new(String::new()),
        offset: 0,
    });
}

fn begin_delete_group(app: &mut App) {
    let Some(group_idx) = (app.focus == FocusPane::Groups)
        .then(|| app.group_index_for_row(app.group_selected))
        .flatten()
    else {
        app.status = "Select a child group in Groups pane before choosing Remove group".into();
        return;
    };
    let Some(group) = app.groups.get(group_idx) else {
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
            group_idx + 1,
            app.groups.len(),
            group.path
        ),
        entry: None,
        group: Some(reference),
        input: Zeroizing::new(String::new()),
        offset: 0,
    });
}

const PALETTE_CHOICES: [&str; 21] = [
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
    "Move entry to group",
    "Move entry up",
    "Move entry down",
    "Clone entry",
    "Recycle entry",
    "Restore entry from Recycle Bin",
    "Empty Recycle Bin",
    "Reveal OTP / Generate HOTP",
    "Configure OTP (TOTP/HOTP)",
    "Go to path (Path Bar)",
    "Database settings",
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

fn strip_ascii_whitespace_zeroizing(value: &str) -> Zeroizing<String> {
    let mut cleaned = Zeroizing::new(String::with_capacity(value.len()));
    for ch in value.chars() {
        if !ch.is_ascii_whitespace() {
            cleaned.push(ch);
        }
    }
    cleaned
}

fn valid_base32_secret(value: &str) -> bool {
    let normalized = strip_ascii_whitespace_zeroizing(value);
    let trimmed = normalized.trim_end_matches('=');
    let pad_len = normalized.len().saturating_sub(trimmed.len());
    if pad_len > 0 && (!normalized.len().is_multiple_of(8) || !matches!(pad_len, 1 | 3 | 4 | 6)) {
        return false;
    }
    // Decoded Base32 payload must be >= 1 byte (at least two 5-bit symbols).
    trimmed.len() >= 2 && valid_unpadded_base32(trimmed)
}

#[cfg(test)]
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

fn validate_otp_uri(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || nkeepass::template::is_bidi_or_line_separator(c))
    {
        return Err("Invalid OTP URI: disallowed or empty input");
    }
    let rest = value
        .strip_prefix("otpauth://")
        .ok_or("OTP URI must start with otpauth://totp/ or otpauth://hotp/")?;
    let (kind, account_and_query) = rest
        .split_once('/')
        .ok_or("OTP URI must include / after totp or hotp")?;
    if !matches!(kind, "totp" | "hotp") {
        return Err("OTP URI type must be totp or hotp");
    }
    let (_label, query) = account_and_query
        .split_once('?')
        .ok_or("OTP URI must include ?secret=... query parameters")?;
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
    if !valid_base32_secret(secret) {
        return Err("OTP URI secret must be valid Base32");
    }
    let _issuer = values.remove("issuer");
    let _image = values.remove("image");
    let encoder = values.remove("encoder");
    if let Some(enc) = encoder {
        if !matches!(enc, "steam" | "default" | "standard") {
            return Err("Unsupported OTP encoder (use steam, default, or standard)");
        }
        if kind == "hotp" && enc == "steam" {
            return Err("Steam encoder is only supported for TOTP");
        }
    }
    if let Some(counter) = values.remove("counter") {
        if counter.parse::<u64>().is_err() {
            return Err("Invalid OTP URI counter");
        }
    } else if kind == "hotp" {
        return Err("HOTP URI requires counter parameter (e.g. counter=0)");
    }
    if let Some(period) = values.remove("period")
        && period.parse::<u64>().ok().is_none_or(|p| p == 0)
    {
        return Err("OTP URI period must be a positive integer");
    }
    if let Some(algorithm) = values.remove("algorithm")
        && !matches!(algorithm, "SHA1" | "SHA256" | "SHA512")
    {
        return Err("Unsupported OTP algorithm (use SHA1, SHA256, or SHA512)");
    }
    if let Some(digits) = values.remove("digits") {
        let valid = if encoder == Some("steam") {
            digits == "5"
        } else {
            matches!(digits, "6" | "8")
        };
        if !valid {
            return Err("Unsupported OTP digits (use 6 or 8, or 5 for Steam)");
        }
    }
    if !values.is_empty() {
        return Err("Unknown OTP URI parameter");
    }
    Ok(())
}

fn selected_entry_ref(app: &App) -> Option<EntryRef> {
    app.entry
        .clone()
        .or_else(|| app.hits.get(app.entry_selected).map(SearchHit::reference))
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
            let icon_id = if app.entry.is_none() && app.focus == FocusPane::Groups {
                app.group_index_for_row(app.group_selected)
                    .and_then(|idx| app.groups.get(idx))
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
            } else if app.focus == FocusPane::Groups {
                if let Some(group) = app
                    .group_index_for_row(app.group_selected)
                    .and_then(|idx| app.groups.get(idx))
                {
                    let reference = group
                        .reference
                        .clone()
                        .or_else(|| app.service.resolve_group(app.session, &group.path).ok());
                    let Some(reference) = reference else {
                        app.status = "Cannot select group for icon change".into();
                        return;
                    };
                    (IconTarget::GroupItem(reference), group.icon_id)
                } else {
                    (
                        IconTarget::GroupItem(app.tree_parent.clone()),
                        DEFAULT_GROUP_ICON_ID,
                    )
                }
            } else if let Some(hit) = app.hits.get(app.entry_selected) {
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
                "Set/update OTP URI (otpauth://totp|hotp/...); input is masked · Enter apply · Esc cancel",
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
            app.re_resolve_current_tree();
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.refresh();
            app.status = format!(
                "Icon set to {} {} ({}) in memory; press Ctrl+S or s to save",
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
        10 => begin_move_entry(app),
        11 => reorder_selected_entry(app, true),
        12 => reorder_selected_entry(app, false),
        13 => clone_selected_entry(app),
        14 => recycle_selected_entry(app),
        15 => restore_selected_entry(app),
        16 => begin_empty_recycle_bin(app),
        17 => begin_otp_reveal(app),
        18 => begin_otp_config(app),
        19 => begin_path_bar(app),
        20 => begin_db_settings(app),
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

fn capture_tree_paths(app: &App) -> (Option<String>, Vec<String>) {
    let active_path = app.service.group_path(&app.tree_parent).ok();
    let stack_paths = app
        .tree_stack
        .iter()
        .filter_map(|group| app.service.group_path(group).ok())
        .collect();
    (active_path, stack_paths)
}

fn finish_delete(
    app: &mut App,
    kind: DeleteKind,
    entry: Option<&EntryRef>,
    group: Option<&GroupRef>,
) {
    let (active_path, stack_paths) = capture_tree_paths(app);
    enum DeleteOutcome {
        EntryRemoved,
        GroupRemoved,
        PermanentEntry,
        EmptyBin(usize),
    }
    let result = match kind {
        DeleteKind::Entry => entry
            .ok_or(nkeepass::ServiceError::NotFound)
            .and_then(|reference| app.service.remove_entry(reference))
            .map(|()| DeleteOutcome::EntryRemoved),
        DeleteKind::PermanentEntry => entry
            .ok_or(nkeepass::ServiceError::NotFound)
            .and_then(|reference| app.service.remove_entry(reference))
            .map(|()| DeleteOutcome::PermanentEntry),
        DeleteKind::Group => group
            .ok_or(nkeepass::ServiceError::NotFound)
            .and_then(|reference| app.service.remove_group(reference))
            .map(|()| DeleteOutcome::GroupRemoved),
        DeleteKind::EmptyRecycleBin => app
            .service
            .empty_recycle_bin(app.session)
            .map(DeleteOutcome::EmptyBin),
    };
    match result {
        Ok(outcome) => {
            if !matches!(outcome, DeleteOutcome::EmptyBin(0)) {
                app.dirty = true;
            }
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.refresh();
            app.status = match outcome {
                DeleteOutcome::EntryRemoved => format!(
                    "Entry removed in memory — press Ctrl+S or s to save to {}",
                    app.vault_name
                ),
                DeleteOutcome::PermanentEntry => {
                    "Entry permanently deleted — press Ctrl+S or s to save".into()
                }
                DeleteOutcome::GroupRemoved => format!(
                    "Group removed in memory — press Ctrl+S or s to save to {}",
                    app.vault_name
                ),
                DeleteOutcome::EmptyBin(count) => {
                    format!("Emptied Recycle Bin ({count} removed) — press Ctrl+S or s to save")
                }
            };
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn flatten_group_tree(node: GroupTreeNode, depth: usize, out: &mut Vec<MoveGroupRow>) {
    let GroupTreeNode {
        reference,
        label,
        path,
        icon_id,
        custom_icon_id: _,
        entry_count: _,
        is_recycle_bin,
        children,
    } = node;
    out.push(MoveGroupRow {
        group_ref: reference,
        row_label: label,
        row_path: path,
        depth,
        std_icon: icon_id,
        recycle_bin: is_recycle_bin,
    });
    for child in children {
        flatten_group_tree(child, depth.saturating_add(1), out);
    }
}

fn find_recycle_bin_path(node: &GroupTreeNode) -> Option<&str> {
    if node.is_recycle_bin {
        return Some(node.path.as_str());
    }
    for child in &node.children {
        if let Some(found) = find_recycle_bin_path(child) {
            return Some(found);
        }
    }
    None
}

fn begin_move_entry(app: &mut App) {
    app.clear_reveal();
    let Some(entry_ref) = selected_entry_ref(app) else {
        app.status = "Select an entry before choosing Move entry".into();
        return;
    };
    let entry_title = app.service.selected_entry(&entry_ref).map_or_else(
        |_| "Selected entry".to_owned(),
        |view| view.title().to_owned(),
    );
    let tree = match app.service.group_tree(app.session) {
        Ok(tree) => tree,
        Err(error) => {
            app.status = clean(error.message());
            return;
        }
    };
    let mut rows = Vec::new();
    flatten_group_tree(tree, 0, &mut rows);
    if rows.is_empty() {
        app.status = "No groups available".into();
        return;
    }
    app.modal = Some(Modal::MoveEntry {
        entry_ref,
        entry_title,
        rows,
        selected: 0,
        scroll: 0,
        error_msg: None,
    });
}

fn reorder_selected_entry(app: &mut App, move_up: bool) {
    app.clear_reveal();
    if !app.query.is_empty() {
        app.status = "Cannot reorder entries while search filter is active".into();
        return;
    }
    if app.tree_page_index > 0 || app.tree_withheld > 0 {
        app.status = "Cannot reorder entries on a paginated or withheld page".into();
        return;
    }
    let Some(hit) = app.hits.get(app.entry_selected) else {
        app.status = "Select an entry before reordering".into();
        return;
    };
    if app.hits.len() < 2 {
        app.status = "Need at least two entries in group to reorder".into();
        return;
    }
    let new_index = if move_up {
        if app.entry_selected == 0 {
            app.status = "Entry is already at the top".into();
            return;
        }
        app.entry_selected - 1
    } else {
        if app.entry_selected + 1 >= app.hits.len() {
            app.status = "Entry is already at the bottom".into();
            return;
        }
        app.entry_selected + 1
    };
    let was_detail = app.entry.is_some();
    let entry_ref = hit.reference();
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app.service.reorder_entry(&entry_ref, new_index) {
        Ok(_fresh_ref) => {
            app.dirty = true;
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.entry_selected = new_index;
            app.refresh();
            if was_detail && let Some(updated_hit) = app.hits.get(app.entry_selected) {
                let updated_ref = updated_hit.reference();
                if app.load_entry_from_ref(&updated_ref) {
                    app.entry = Some(updated_ref);
                    app.focus = FocusPane::Detail;
                }
            }
            app.status = if move_up {
                "Moved entry up — press Ctrl+S or s to save".into()
            } else {
                "Moved entry down — press Ctrl+S or s to save".into()
            };
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn clone_selected_entry(app: &mut App) {
    app.clear_reveal();
    let Some(entry_ref) = selected_entry_ref(app) else {
        app.status = "Select an entry before choosing Clone entry".into();
        return;
    };
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app.service.clone_entry(&entry_ref) {
        Ok(cloned_ref) => {
            app.dirty = true;
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.refresh();
            if let Some(idx) = app
                .hits
                .iter()
                .position(|hit| hit.reference() == cloned_ref)
            {
                app.entry_selected = idx;
                app.focus = FocusPane::Entries;
                app.load_entry_preview();
                app.status = "Cloned entry — press Ctrl+S or s to save".into();
            } else {
                app.status = "Cloned entry (on another page) — press Ctrl+S or s to save".into();
            }
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn recycle_selected_entry(app: &mut App) {
    app.clear_reveal();
    let Some(entry_ref) = selected_entry_ref(app) else {
        app.status = "Select an entry before choosing Recycle entry".into();
        return;
    };
    let DatabaseSettings {
        recycle_bin_enabled,
        ..
    } = match app.service.database_settings(app.session) {
        Ok(settings) => settings,
        Err(error) => {
            app.status = clean(error.message());
            return;
        }
    };
    let path_desc = app
        .hits
        .iter()
        .find(|hit| hit.reference() == entry_ref)
        .map_or_else(|| "selected entry".to_owned(), |hit| hit.path().to_owned());
    let prompt_permanent = |app: &mut App, reason: &str, entry_ref: EntryRef| {
        app.modal = Some(Modal::ConfirmDelete {
            kind: DeleteKind::PermanentEntry,
            path: format!("{reason}: {path_desc}"),
            entry: Some(entry_ref),
            group: None,
            input: Zeroizing::new(String::new()),
            offset: 0,
        });
    };
    if !recycle_bin_enabled {
        prompt_permanent(app, "Recycle Bin disabled", entry_ref);
        return;
    }
    let tree = match app.service.group_tree(app.session) {
        Ok(tree) => tree,
        Err(error) => {
            app.status = clean(error.message());
            return;
        }
    };
    if let Some(bin_path) = find_recycle_bin_path(&tree) {
        let entry_path = app
            .hits
            .iter()
            .find(|hit| hit.reference() == entry_ref)
            .map(|hit| hit.path().to_owned())
            .or_else(|| app.service.group_path(&app.tree_parent).ok());
        let Some(entry_path) = entry_path else {
            prompt_permanent(app, "Cannot verify Recycle Bin location", entry_ref);
            return;
        };
        if entry_path == bin_path || entry_path.starts_with(&format!("{bin_path}/")) {
            prompt_permanent(app, "Already in Recycle Bin", entry_ref);
            return;
        }
    }
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app.service.recycle_entry(&entry_ref) {
        Ok(moved_to_bin) => {
            app.dirty = true;
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.clear_reveal();
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.refresh();
            app.status = if moved_to_bin {
                "Moved to Recycle Bin — press Ctrl+S or s to save".into()
            } else {
                "Entry permanently deleted — press Ctrl+S or s to save".into()
            };
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn restore_selected_entry(app: &mut App) {
    app.clear_reveal();
    let Some(entry_ref) = selected_entry_ref(app) else {
        app.status = "Select an entry inside the Recycle Bin first".into();
        return;
    };
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app.service.restore_entry(&entry_ref) {
        Ok(_restored_ref) => {
            app.dirty = true;
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.clear_reveal();
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.refresh();
            app.status = "Restored entry — press Ctrl+S or s to save".into();
        }
        Err(nkeepass::ServiceError::InvalidInput) => {
            app.status = "Entry is not in the Recycle Bin".into();
        }
        Err(error) => app.status = clean(error.message()),
    }
}

fn begin_empty_recycle_bin(app: &mut App) {
    app.clear_reveal();
    app.modal = Some(Modal::ConfirmDelete {
        kind: DeleteKind::EmptyRecycleBin,
        path: "Recycle Bin: permanently delete all recycled entries and subgroups".into(),
        entry: None,
        group: None,
        input: Zeroizing::new(String::new()),
        offset: 0,
    });
}

fn format_otp_metadata(meta: Option<OtpMetadata>, has_otp_fallback: bool) -> String {
    match meta {
        Some(OtpMetadata {
            kind: ServiceOtpKind::Totp,
            algorithm: _,
            digits,
            period,
            counter: _,
            steam,
        }) => {
            let secs = period.unwrap_or(30);
            if steam {
                format!("TOTP ({digits}d, {secs}s, Steam)")
            } else {
                format!("TOTP ({digits}d, {secs}s)")
            }
        }
        Some(OtpMetadata {
            kind: ServiceOtpKind::Hotp,
            algorithm: _,
            digits,
            period: _,
            counter,
            steam: _,
        }) => {
            format!("HOTP ({digits}d, counter {})", counter.unwrap_or(0))
        }
        None => {
            if has_otp_fallback {
                "present (invalid)".into()
            } else {
                "none".into()
            }
        }
    }
}

fn begin_otp_reveal(app: &mut App) {
    let Some(reference) = selected_entry_ref(app) else {
        app.status = "Select an entry first".into();
        return;
    };
    let is_hotp = matches!(
        app.service.otp_metadata(&reference),
        Ok(Some(OtpMetadata {
            kind: ServiceOtpKind::Hotp,
            ..
        }))
    );
    app.pending_entry = Some(reference);
    let prompt = if is_hotp {
        "Generate next HOTP (increments counter)? Type YES. WARNING: terminal scrollback may retain the code."
    } else {
        "Reveal current TOTP? Type YES. WARNING: terminal scrollback may retain the code."
    };
    begin_action(app, Action::TotpReveal, prompt);
}

fn begin_otp_config(app: &mut App) {
    app.clear_reveal();
    let Some(entry_ref) = selected_entry_ref(app) else {
        app.status = "Select an entry before choosing Configure OTP".into();
        return;
    };
    let acct_label = app
        .service
        .selected_entry(&entry_ref)
        .map(|view| view.title().to_owned())
        .ok()
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| "account".to_owned());
    let existing = app.service.otp_metadata(&entry_ref).ok().flatten();
    let (otp_kind, otp_algorithm, otp_digits, period_text, counter_text, use_steam) = match existing
    {
        Some(OtpMetadata {
            kind,
            algorithm,
            digits,
            period,
            counter,
            steam,
        }) => (
            kind,
            algorithm,
            digits,
            period.unwrap_or(30).to_string(),
            counter.unwrap_or(0).to_string(),
            steam,
        ),
        None => (
            ServiceOtpKind::Totp,
            ServiceOtpAlgorithm::Sha1,
            6,
            "30".to_owned(),
            "0".to_owned(),
            false,
        ),
    };
    app.modal = Some(Modal::OtpConfig(OtpConfigDraft {
        entry_ref,
        otp_kind,
        otp_algorithm,
        otp_digits,
        period_text,
        counter_text,
        use_steam,
        acct_label,
        issuer_label: String::new(),
        secret_b32: Zeroizing::new(String::with_capacity(260)),
        selected_row: 0,
        editing_text: false,
        error_msg: None,
    }));
}

fn apply_otp_config(app: &mut App, draft: &mut OtpConfigDraft) -> bool {
    if draft.acct_label.trim().is_empty() {
        draft.error_msg = Some("Account label is required".into());
        return false;
    }
    let cleaned_secret = strip_ascii_whitespace_zeroizing(&draft.secret_b32);
    if !valid_base32_secret(&cleaned_secret) {
        draft.error_msg = Some("Secret must be valid Base32".into());
        return false;
    }
    let (period, counter) = match draft.otp_kind {
        ServiceOtpKind::Totp => {
            let Ok(secs) = draft.period_text.trim().parse::<u64>() else {
                draft.error_msg = Some("Period must be a positive integer".into());
                return false;
            };
            if secs == 0 {
                draft.error_msg = Some("Period must be greater than 0".into());
                return false;
            }
            (Some(secs), None)
        }
        ServiceOtpKind::Hotp => {
            let Ok(cnt) = draft.counter_text.trim().parse::<u64>() else {
                draft.error_msg = Some("Counter must be a non-negative integer".into());
                return false;
            };
            (None, Some(cnt))
        }
    };
    let config = OtpConfig {
        kind: draft.otp_kind,
        account: draft.acct_label.trim().to_owned(),
        issuer: (!draft.issuer_label.trim().is_empty())
            .then(|| draft.issuer_label.trim().to_owned()),
        algorithm: draft.otp_algorithm,
        digits: if draft.use_steam { 5 } else { draft.otp_digits },
        period,
        counter,
        steam: draft.use_steam,
    };
    let was_open = app.entry.is_some();
    let target_path = app
        .hits
        .iter()
        .find(|hit| hit.reference() == draft.entry_ref)
        .map(|hit| hit.path().to_owned());
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app
        .service
        .set_entry_otp_config(&draft.entry_ref, &config, &cleaned_secret)
    {
        Ok(()) => {
            draft.secret_b32.zeroize();
            app.dirty = true;
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.refresh();
            if was_open {
                if let Some(idx) = target_path
                    .as_deref()
                    .and_then(|path| app.hits.iter().position(|hit| hit.path() == path))
                {
                    app.entry_selected = idx;
                    let fresh = app.hits[idx].reference();
                    if app.load_entry_from_ref(&fresh) {
                        app.entry = Some(fresh);
                        app.focus = FocusPane::Detail;
                    }
                } else {
                    app.entry = None;
                }
            }
            app.status = "OTP configured in memory — press Ctrl+S or s to save".into();
            true
        }
        Err(error) => {
            draft.error_msg = Some(clean(error.message()));
            false
        }
    }
}

fn strip_root_prefix(root_name: &str, full_path: &str) -> String {
    if root_name.is_empty() {
        if full_path.is_empty() {
            return "/".to_owned();
        }
        return format!("/{}", full_path.trim_start_matches('/'));
    }
    if full_path == root_name {
        return "/".to_owned();
    }
    if let Some(rest) = full_path.strip_prefix(&format!("{root_name}/")) {
        return format!("/{rest}");
    }
    format!("/{}", full_path.trim_start_matches('/'))
}

fn begin_path_bar(app: &mut App) {
    app.clear_reveal();
    app.modal = Some(Modal::PathBar(PathBarState {
        buffer: app.display_group_path(),
        completions: Vec::new(),
        selected: 0,
        dropdown_open: false,
        error_msg: None,
    }));
}

fn path_bar_complete(app: &App, state: &mut PathBarState) {
    state.error_msg = None;
    let root_name = app
        .service
        .root_group(app.session)
        .and_then(|root| app.service.group_path(&root))
        .unwrap_or_default();
    match app.service.complete_path(app.session, &state.buffer, 5) {
        Ok(matches) => {
            let items: Vec<PathCompletionItem> = matches
                .into_iter()
                .map(|item| {
                    let PathCompletion {
                        path,
                        label,
                        is_group,
                        icon_id,
                        custom_icon_id: _,
                        group_ref,
                        entry_ref,
                    } = item;
                    PathCompletionItem {
                        full_path: path,
                        leaf_label: label,
                        is_group_item: is_group,
                        std_icon: icon_id,
                        target_group: group_ref,
                        target_entry: entry_ref,
                    }
                })
                .collect();
            if items.is_empty() {
                state.completions.clear();
                state.dropdown_open = false;
                state.selected = 0;
                state.error_msg = Some("No matching path".into());
            } else if items.len() == 1 {
                state.buffer = strip_root_prefix(&root_name, &items[0].full_path);
                state.completions = items;
                state.selected = 0;
                state.dropdown_open = false;
            } else {
                state.completions = items;
                state.selected = 0;
                state.dropdown_open = true;
            }
        }
        Err(error) => {
            state.completions.clear();
            state.dropdown_open = false;
            state.error_msg = Some(clean(error.message()));
        }
    }
}

fn navigate_to_path_completion(app: &mut App, item: &PathCompletionItem) -> bool {
    let root_path = app
        .service
        .root_group(app.session)
        .and_then(|root| app.service.group_path(&root))
        .unwrap_or_default();
    app.clear_reveal();
    app.query.zeroize();
    app.query_before_input.zeroize();
    if item.is_group_item {
        let target_path = item
            .target_group
            .as_ref()
            .and_then(|group_ref| app.service.group_path(group_ref).ok())
            .or_else(|| Some(item.full_path.clone()));
        let stack_paths = rebuild_stack_paths(&root_path, target_path.as_deref());
        app.re_resolve_tree_after_mutation(target_path.as_deref(), &stack_paths);
        app.group_selected = 0;
        app.entry_selected = 0;
        app.entry = None;
        app.refresh();
        app.focus = if app.groups.is_empty() && !app.hits.is_empty() {
            FocusPane::Entries
        } else {
            FocusPane::Groups
        };
        app.status = format!("Navigated to {}", app.display_group_path());
        true
    } else {
        let parent_path = item
            .full_path
            .rsplit_once('/')
            .map_or_else(|| root_path.clone(), |(parent, _)| parent.to_owned());
        let stack_paths = rebuild_stack_paths(&root_path, Some(&parent_path));
        app.re_resolve_tree_after_mutation(Some(&parent_path), &stack_paths);
        app.refresh();
        let entry_idx = app.hits.iter().position(|hit| {
            item.target_entry
                .as_ref()
                .is_some_and(|target| hit.reference() == *target)
                || hit.path() == item.full_path
        });
        if let Some(idx) = entry_idx {
            app.entry_selected = idx;
            app.focus = FocusPane::Entries;
            app.select();
            app.status = format!("Navigated to /{}", clean(&item.full_path));
        } else {
            app.entry = None;
            app.focus = FocusPane::Entries;
            app.status = format!(
                "Navigated to parent group; use n for next page ({})",
                clean(&item.leaf_label)
            );
        }
        true
    }
}

fn submit_path_bar(app: &mut App, state: &mut PathBarState) -> bool {
    if state.dropdown_open
        && let Some(item) = state.completions.get(state.selected).cloned()
    {
        return navigate_to_path_completion(app, &item);
    }
    let trimmed = state.buffer.trim();
    if trimmed == "/" || trimmed.is_empty() {
        app.clear_reveal();
        app.query.zeroize();
        app.query_before_input.zeroize();
        app.reset_tree_after_mutation();
        app.group_selected = 0;
        app.entry_selected = 0;
        app.entry = None;
        app.refresh();
        app.status = "Navigated to /".into();
        return true;
    }
    let root_path = app
        .service
        .root_group(app.session)
        .and_then(|root| app.service.group_path(&root))
        .unwrap_or_default();
    let rel = trimmed.trim_start_matches('/');
    let full_candidate =
        if root_path.is_empty() || rel == root_path || rel.starts_with(&format!("{root_path}/")) {
            rel.to_owned()
        } else {
            format!("{root_path}/{rel}")
        };
    if let Ok(group_ref) = app.service.resolve_group(app.session, &full_candidate) {
        let label = rel.rsplit('/').next().unwrap_or(rel).to_owned();
        return navigate_to_path_completion(
            app,
            &PathCompletionItem {
                full_path: full_candidate,
                leaf_label: label,
                is_group_item: true,
                std_icon: DEFAULT_GROUP_ICON_ID,
                target_group: Some(group_ref),
                target_entry: None,
            },
        );
    }
    if let Ok(resolved) = app.service.resolve_entry(app.session, &full_candidate) {
        let entry_ref = resolved.reference();
        let path = resolved.path().to_owned();
        let label = path.rsplit('/').next().unwrap_or(&path).to_owned();
        return navigate_to_path_completion(
            app,
            &PathCompletionItem {
                full_path: path,
                leaf_label: label,
                is_group_item: false,
                std_icon: 0,
                target_group: None,
                target_entry: Some(entry_ref),
            },
        );
    }
    if let Ok(matches) = app.service.complete_path(app.session, trimmed, 5) {
        if matches.len() == 1
            && let Some(first) = matches.into_iter().next()
        {
            let PathCompletion {
                path,
                label,
                is_group,
                icon_id,
                custom_icon_id: _,
                group_ref,
                entry_ref,
            } = first;
            return navigate_to_path_completion(
                app,
                &PathCompletionItem {
                    full_path: path,
                    leaf_label: label,
                    is_group_item: is_group,
                    std_icon: icon_id,
                    target_group: group_ref,
                    target_entry: entry_ref,
                },
            );
        }
        path_bar_complete(app, state);
        return false;
    }
    state.error_msg = Some("Path not found".into());
    false
}

fn begin_db_settings(app: &mut App) {
    app.clear_reveal();
    let settings = match app.service.database_settings(app.session) {
        Ok(settings) => settings,
        Err(error) => {
            app.status = clean(error.message());
            return;
        }
    };
    let DatabaseSettings {
        name,
        description,
        default_username,
        recycle_bin_enabled,
        history_max_items,
        history_max_size,
        outer_cipher,
        compression,
        kdf,
    } = settings;
    let (kdf_kind, aes_rounds, argon_mem, argon_iters, argon_lanes) = match kdf {
        VaultKdfSummary::Aes { rounds } => (
            DbKdfKind::Aes,
            rounds.to_string(),
            "65536".to_owned(),
            "2".to_owned(),
            "2".to_owned(),
        ),
        VaultKdfSummary::Argon2d {
            memory_kib,
            iterations,
            lanes,
        } => (
            DbKdfKind::Argon2d,
            "60000".to_owned(),
            memory_kib.to_string(),
            iterations.to_string(),
            lanes.to_string(),
        ),
        VaultKdfSummary::Argon2id {
            memory_kib,
            iterations,
            lanes,
        } => (
            DbKdfKind::Argon2id,
            "60000".to_owned(),
            memory_kib.to_string(),
            iterations.to_string(),
            lanes.to_string(),
        ),
    };
    app.modal = Some(Modal::DbSettings(DbSettingsDraft {
        db_name: name,
        db_desc: description,
        db_default_user: default_username,
        recycle_enabled: recycle_bin_enabled,
        hist_max_items: history_max_items.to_string(),
        hist_max_size: history_max_size.to_string(),
        cipher: outer_cipher,
        compression,
        kdf_kind,
        aes_rounds,
        argon_mem,
        argon_iters,
        argon_lanes,
        selected_row: 0,
        editing_text: false,
        error_msg: None,
    }));
}

fn db_settings_row_count(kdf_kind: DbKdfKind) -> usize {
    match kdf_kind {
        DbKdfKind::Aes => 11,
        DbKdfKind::Argon2id | DbKdfKind::Argon2d => 13,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "explicit validation checks keep per-field error messages concise"
)]
fn apply_db_settings(app: &mut App, draft: &mut DbSettingsDraft) -> bool {
    let Ok(history_max_items) = draft.hist_max_items.trim().parse::<i32>() else {
        draft.error_msg = Some("History Max Items must be >= -1".into());
        return false;
    };
    if history_max_items < -1 {
        draft.error_msg = Some("History Max Items must be >= -1".into());
        return false;
    }
    let Ok(history_max_size) = draft.hist_max_size.trim().parse::<i64>() else {
        draft.error_msg = Some("History Max Size must be >= -1".into());
        return false;
    };
    if history_max_size < -1 {
        draft.error_msg = Some("History Max Size must be >= -1".into());
        return false;
    }
    let kdf = match draft.kdf_kind {
        DbKdfKind::Aes => {
            let Ok(rounds) = draft.aes_rounds.trim().parse::<u64>() else {
                draft.error_msg = Some("AES KDF rounds must be > 0".into());
                return false;
            };
            if rounds == 0 {
                draft.error_msg = Some("AES KDF rounds must be > 0".into());
                return false;
            }
            VaultKdfSummary::Aes { rounds }
        }
        DbKdfKind::Argon2d | DbKdfKind::Argon2id => {
            let Ok(memory_kib) = draft.argon_mem.trim().parse::<u32>() else {
                draft.error_msg = Some("Argon2 Memory KiB must be > 0".into());
                return false;
            };
            if memory_kib == 0 {
                draft.error_msg = Some("Argon2 Memory KiB must be > 0".into());
                return false;
            }
            let Ok(iterations) = draft.argon_iters.trim().parse::<u32>() else {
                draft.error_msg = Some("Argon2 Iterations must be > 0".into());
                return false;
            };
            if iterations == 0 {
                draft.error_msg = Some("Argon2 Iterations must be > 0".into());
                return false;
            }
            let Ok(lanes) = draft.argon_lanes.trim().parse::<u32>() else {
                draft.error_msg = Some("Argon2 Lanes must be > 0".into());
                return false;
            };
            if lanes == 0 {
                draft.error_msg = Some("Argon2 Lanes must be > 0".into());
                return false;
            }
            if u64::from(memory_kib) < u64::from(lanes).saturating_mul(8) {
                draft.error_msg = Some("Argon2 Memory must be >= 8 * Lanes".into());
                return false;
            }
            if draft.kdf_kind == DbKdfKind::Argon2id {
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
            }
        }
    };
    let update = DatabaseSettingsUpdate {
        name: draft.db_name.clone(),
        description: draft.db_desc.clone(),
        default_username: draft.db_default_user.clone(),
        recycle_bin_enabled: draft.recycle_enabled,
        history_max_items,
        history_max_size,
        outer_cipher: draft.cipher,
        compression: draft.compression,
        kdf,
    };
    let (active_path, stack_paths) = capture_tree_paths(app);
    match app.service.update_database_settings(app.session, update) {
        Ok(()) => {
            app.dirty = true;
            app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
            app.entry = None;
            app.entry_icon = None;
            app.detail.clear();
            app.fields.clear();
            app.refresh();
            app.status = "Database settings updated — press Ctrl+S or s to save".into();
            true
        }
        Err(error) => {
            draft.error_msg = Some(clean(error.message()));
            false
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "modal variants share ownership and focus handling"
)]
fn handle_modal_key_event(app: &mut App, key_event: KeyEvent) {
    let key = key_event.code;
    let modifiers = key_event.modifiers;
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
        Modal::MoveEntry {
            entry_ref,
            entry_title,
            rows,
            mut selected,
            mut scroll,
            mut error_msg,
        } => {
            let count = rows.len();
            match key {
                KeyCode::Esc => {
                    app.status = "Move cancelled".into();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                    scroll = selected.saturating_sub(3);
                    error_msg = None;
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg,
                    });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    selected = selected.saturating_add(1).min(count.saturating_sub(1));
                    scroll = selected.saturating_sub(3);
                    error_msg = None;
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg,
                    });
                }
                KeyCode::PageUp => {
                    selected = selected.saturating_sub(10);
                    scroll = selected.saturating_sub(3);
                    error_msg = None;
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg,
                    });
                }
                KeyCode::PageDown => {
                    selected = selected.saturating_add(10).min(count.saturating_sub(1));
                    scroll = selected.saturating_sub(3);
                    error_msg = None;
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg,
                    });
                }
                KeyCode::Home => {
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected: 0,
                        scroll: 0,
                        error_msg: None,
                    });
                }
                KeyCode::End => {
                    selected = count.saturating_sub(1);
                    scroll = selected.saturating_sub(3);
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg: None,
                    });
                }
                KeyCode::Enter => {
                    if let Some(target) = rows.get(selected) {
                        let moved_path = target.row_path.clone();
                        let (active_path, stack_paths) = capture_tree_paths(app);
                        match app.service.move_entry(&entry_ref, &target.group_ref) {
                            Ok(_) => {
                                app.dirty = true;
                                app.entry = None;
                                app.entry_icon = None;
                                app.detail.clear();
                                app.fields.clear();
                                app.re_resolve_tree_after_mutation(
                                    active_path.as_deref(),
                                    &stack_paths,
                                );
                                app.refresh();
                                app.status = format!(
                                    "Moved entry to {} — press Ctrl+S or s to save",
                                    clean(&moved_path)
                                );
                            }
                            Err(error) => {
                                let msg = clean(error.message());
                                app.status.clone_from(&msg);
                                app.modal = Some(Modal::MoveEntry {
                                    entry_ref,
                                    entry_title,
                                    rows,
                                    selected,
                                    scroll,
                                    error_msg: Some(msg),
                                });
                            }
                        }
                    }
                }
                _ => {
                    app.modal = Some(Modal::MoveEntry {
                        entry_ref,
                        entry_title,
                        rows,
                        selected,
                        scroll,
                        error_msg,
                    });
                }
            }
        }
        Modal::OtpConfig(mut draft) => {
            if handle_otp_config_key(app, &mut draft, key, modifiers) {
                app.modal = Some(Modal::OtpConfig(draft));
            }
        }
        Modal::PathBar(mut state) => {
            if handle_path_bar_key(app, &mut state, key, modifiers) {
                app.modal = Some(Modal::PathBar(state));
            }
        }
        Modal::DbSettings(mut draft) => {
            if handle_db_settings_key(app, &mut draft, key, modifiers) {
                app.modal = Some(Modal::DbSettings(draft));
            }
        }
    }
}

#[cfg(test)]
fn handle_modal_key(app: &mut App, key: KeyCode) {
    handle_modal_key_event(app, KeyEvent::new(key, KeyModifiers::NONE));
}

fn handle_otp_config_edit_key(draft: &mut OtpConfigDraft, key: KeyCode, modifiers: KeyModifiers) {
    match key {
        KeyCode::Esc | KeyCode::Enter => {
            draft.editing_text = false;
        }
        KeyCode::Backspace => match draft.selected_row {
            1 => {
                draft.acct_label.pop();
            }
            2 => {
                draft.issuer_label.pop();
            }
            5 => {
                if draft.otp_kind == ServiceOtpKind::Totp {
                    draft.period_text.pop();
                } else {
                    draft.counter_text.pop();
                }
            }
            7 => {
                let _ = draft.secret_b32.pop();
            }
            _ => {}
        },
        KeyCode::Char(c)
            if !c.is_control()
                && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            draft.error_msg = None;
            match draft.selected_row {
                1 if draft.acct_label.len() < 128 => draft.acct_label.push(c),
                2 if draft.issuer_label.len() < 128 => draft.issuer_label.push(c),
                5 if c.is_ascii_digit() => {
                    if draft.otp_kind == ServiceOtpKind::Totp && draft.period_text.len() < 10 {
                        draft.period_text.push(c);
                    } else if draft.otp_kind == ServiceOtpKind::Hotp
                        && draft.counter_text.len() < 20
                    {
                        draft.counter_text.push(c);
                    }
                }
                7 if draft.secret_b32.len() < 256 => draft.secret_b32.push(c),
                _ => {}
            }
        }
        _ => {}
    }
}

fn handle_otp_config_key(
    app: &mut App,
    draft: &mut OtpConfigDraft,
    key: KeyCode,
    modifiers: KeyModifiers,
) -> bool {
    if key == KeyCode::Char('s') && modifiers.contains(KeyModifiers::CONTROL) {
        return !apply_otp_config(app, draft);
    }
    if draft.editing_text {
        handle_otp_config_edit_key(draft, key, modifiers);
        return true;
    }
    match key {
        KeyCode::Esc => {
            draft.secret_b32.zeroize();
            app.status = "OTP configuration cancelled".into();
            false
        }
        KeyCode::Up | KeyCode::Char('k') => {
            draft.selected_row = draft.selected_row.saturating_sub(1);
            true
        }
        KeyCode::Down | KeyCode::Char('j') => {
            draft.selected_row = draft.selected_row.saturating_add(1).min(8);
            true
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
            draft.error_msg = None;
            match draft.selected_row {
                0 => {
                    draft.otp_kind = match draft.otp_kind {
                        ServiceOtpKind::Totp => ServiceOtpKind::Hotp,
                        ServiceOtpKind::Hotp => ServiceOtpKind::Totp,
                    };
                    if draft.otp_kind == ServiceOtpKind::Hotp && draft.use_steam {
                        draft.use_steam = false;
                        draft.otp_digits = 6;
                    }
                }
                3 => {
                    let forward = key != KeyCode::Left;
                    draft.otp_algorithm = match (draft.otp_algorithm, forward) {
                        (ServiceOtpAlgorithm::Sha1, true)
                        | (ServiceOtpAlgorithm::Sha512, false) => ServiceOtpAlgorithm::Sha256,
                        (ServiceOtpAlgorithm::Sha256, true)
                        | (ServiceOtpAlgorithm::Sha1, false) => ServiceOtpAlgorithm::Sha512,
                        (ServiceOtpAlgorithm::Sha512, true)
                        | (ServiceOtpAlgorithm::Sha256, false) => ServiceOtpAlgorithm::Sha1,
                    };
                }
                4 => {
                    if !draft.use_steam {
                        draft.otp_digits = if draft.otp_digits == 6 { 8 } else { 6 };
                    }
                }
                6 => {
                    if draft.otp_kind == ServiceOtpKind::Totp {
                        draft.use_steam = !draft.use_steam;
                        draft.otp_digits = if draft.use_steam { 5 } else { 6 };
                    }
                }
                _ => {}
            }
            true
        }
        KeyCode::Enter => match draft.selected_row {
            0 | 3 | 4 | 6 => handle_otp_config_key(app, draft, KeyCode::Char(' '), modifiers),
            1 | 2 | 5 | 7 => {
                draft.editing_text = true;
                true
            }
            8 => !apply_otp_config(app, draft),
            _ => true,
        },
        _ => true,
    }
}

fn handle_path_bar_key(
    app: &mut App,
    state: &mut PathBarState,
    key: KeyCode,
    modifiers: KeyModifiers,
) -> bool {
    match key {
        KeyCode::Esc => {
            app.status = "Path bar closed".into();
            false
        }
        KeyCode::Tab => {
            if state.dropdown_open && state.completions.len() > 1 {
                state.selected = (state.selected + 1) % state.completions.len();
            } else {
                path_bar_complete(app, state);
            }
            true
        }
        KeyCode::BackTab => {
            if state.dropdown_open && state.completions.len() > 1 {
                state.selected = if state.selected == 0 {
                    state.completions.len() - 1
                } else {
                    state.selected - 1
                };
            }
            true
        }
        KeyCode::Down if state.dropdown_open && !state.completions.is_empty() => {
            state.selected = state
                .selected
                .saturating_add(1)
                .min(state.completions.len().saturating_sub(1));
            true
        }
        KeyCode::Up if state.dropdown_open && !state.completions.is_empty() => {
            state.selected = state.selected.saturating_sub(1);
            true
        }
        KeyCode::Enter => !submit_path_bar(app, state),
        KeyCode::Backspace => {
            state.buffer.pop();
            state.dropdown_open = false;
            state.completions.clear();
            state.selected = 0;
            state.error_msg = None;
            true
        }
        KeyCode::Char(c)
            if !c.is_control()
                && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                && state.buffer.len() < 1024 =>
        {
            state.buffer.push(c);
            state.dropdown_open = false;
            state.completions.clear();
            state.selected = 0;
            state.error_msg = None;
            true
        }
        _ => true,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "database settings modal fields share clean state transitions"
)]
fn handle_db_settings_key(
    app: &mut App,
    draft: &mut DbSettingsDraft,
    key: KeyCode,
    modifiers: KeyModifiers,
) -> bool {
    if key == KeyCode::Char('s') && modifiers.contains(KeyModifiers::CONTROL) {
        return !apply_db_settings(app, draft);
    }
    let row_count = db_settings_row_count(draft.kdf_kind);
    let apply_row = row_count - 1;
    if draft.editing_text {
        match key {
            KeyCode::Esc | KeyCode::Enter => {
                draft.editing_text = false;
            }
            KeyCode::Backspace => match draft.selected_row {
                0 => {
                    draft.db_name.pop();
                }
                1 => {
                    draft.db_desc.pop();
                }
                2 => {
                    draft.db_default_user.pop();
                }
                4 => {
                    draft.hist_max_items.pop();
                }
                5 => {
                    draft.hist_max_size.pop();
                }
                9 if draft.kdf_kind == DbKdfKind::Aes => {
                    draft.aes_rounds.pop();
                }
                9 => {
                    draft.argon_mem.pop();
                }
                10 if draft.kdf_kind != DbKdfKind::Aes => {
                    draft.argon_iters.pop();
                }
                11 if draft.kdf_kind != DbKdfKind::Aes => {
                    draft.argon_lanes.pop();
                }
                _ => {}
            },
            KeyCode::Char(c)
                if !c.is_control()
                    && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                draft.error_msg = None;
                match draft.selected_row {
                    0 if draft.db_name.len() < 128 => draft.db_name.push(c),
                    1 if draft.db_desc.len() < 512 => draft.db_desc.push(c),
                    2 if draft.db_default_user.len() < 128 => draft.db_default_user.push(c),
                    4 if (c.is_ascii_digit() || (c == '-' && draft.hist_max_items.is_empty()))
                        && draft.hist_max_items.len() < 12 =>
                    {
                        draft.hist_max_items.push(c);
                    }
                    5 if (c.is_ascii_digit() || (c == '-' && draft.hist_max_size.is_empty()))
                        && draft.hist_max_size.len() < 20 =>
                    {
                        draft.hist_max_size.push(c);
                    }
                    9 if draft.kdf_kind == DbKdfKind::Aes
                        && c.is_ascii_digit()
                        && draft.aes_rounds.len() < 12 =>
                    {
                        draft.aes_rounds.push(c);
                    }
                    9 if draft.kdf_kind != DbKdfKind::Aes
                        && c.is_ascii_digit()
                        && draft.argon_mem.len() < 12 =>
                    {
                        draft.argon_mem.push(c);
                    }
                    10 if draft.kdf_kind != DbKdfKind::Aes
                        && c.is_ascii_digit()
                        && draft.argon_iters.len() < 10 =>
                    {
                        draft.argon_iters.push(c);
                    }
                    11 if draft.kdf_kind != DbKdfKind::Aes
                        && c.is_ascii_digit()
                        && draft.argon_lanes.len() < 6 =>
                    {
                        draft.argon_lanes.push(c);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        return true;
    }
    match key {
        KeyCode::Esc => {
            app.status = "Database settings cancelled".into();
            false
        }
        KeyCode::Up | KeyCode::Char('k') => {
            draft.selected_row = draft.selected_row.saturating_sub(1);
            true
        }
        KeyCode::Down | KeyCode::Char('j') => {
            draft.selected_row = draft.selected_row.saturating_add(1).min(apply_row);
            true
        }
        KeyCode::PageUp => {
            draft.selected_row = draft.selected_row.saturating_sub(5);
            true
        }
        KeyCode::PageDown => {
            draft.selected_row = draft.selected_row.saturating_add(5).min(apply_row);
            true
        }
        KeyCode::Home => {
            draft.selected_row = 0;
            true
        }
        KeyCode::End => {
            draft.selected_row = apply_row;
            true
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
            draft.error_msg = None;
            match draft.selected_row {
                3 => draft.recycle_enabled = !draft.recycle_enabled,
                6 => {
                    draft.cipher = match draft.cipher {
                        VaultCipher::Aes => VaultCipher::ChaCha20,
                        VaultCipher::ChaCha20 => VaultCipher::Aes,
                    };
                }
                7 => {
                    draft.compression = match draft.compression {
                        VaultCompression::GZip => VaultCompression::None,
                        VaultCompression::None => VaultCompression::GZip,
                    };
                }
                8 => {
                    let forward = key != KeyCode::Left;
                    draft.kdf_kind = match (draft.kdf_kind, forward) {
                        (DbKdfKind::Argon2id, true) | (DbKdfKind::Aes, false) => DbKdfKind::Argon2d,
                        (DbKdfKind::Argon2d, true) | (DbKdfKind::Argon2id, false) => DbKdfKind::Aes,
                        (DbKdfKind::Aes, true) | (DbKdfKind::Argon2d, false) => DbKdfKind::Argon2id,
                    };
                    let max_row = db_settings_row_count(draft.kdf_kind) - 1;
                    draft.selected_row = draft.selected_row.min(max_row);
                }
                _ => {}
            }
            true
        }
        KeyCode::Enter => {
            if draft.selected_row == apply_row {
                !apply_db_settings(app, draft)
            } else if matches!(draft.selected_row, 3 | 6 | 7 | 8) {
                handle_db_settings_key(app, draft, KeyCode::Char(' '), modifiers)
            } else {
                draft.editing_text = true;
                true
            }
        }
        _ => true,
    }
}

fn rebuild_stack_paths(root_path: &str, target_path: Option<&str>) -> Vec<String> {
    let Some(target) = target_path else {
        return Vec::new();
    };
    let parts: Vec<&str> = target.split('/').collect();
    if root_path.is_empty() {
        if target.is_empty() {
            return Vec::new();
        }
        let mut paths = vec![String::new()];
        for len in 1..parts.len() {
            paths.push(parts[..len].join("/"));
        }
        paths
    } else {
        if parts.len() <= 1 {
            return Vec::new();
        }
        (1..parts.len()).map(|len| parts[..len].join("/")).collect()
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
    let root_path = app
        .service
        .root_group(app.session)
        .and_then(|root| app.service.group_path(&root))
        .unwrap_or_default();
    let active_path = app.service.group_path(&app.tree_parent).ok();
    let parent_path = app.service.group_path(&parent).ok();
    let stack_paths: Vec<String> = app
        .tree_stack
        .iter()
        .filter_map(|group| app.service.group_path(group).ok())
        .collect();
    enum Created {
        Group,
        Entry(EntryRef),
    }
    let result = match action {
        Action::AddGroup => app
            .service
            .add_group(&parent, name)
            .map(|()| Created::Group),
        Action::AddEntry => app
            .service
            .create_entry_in_group(&parent, name)
            .map(Created::Entry),
        _ => return,
    };
    match result {
        Ok(created) => {
            app.dirty = true;
            app.entry = None;
            app.detail.clear();
            app.fields.clear();
            let (target_path, target_stack_paths) = match &created {
                Created::Entry(_) => {
                    app.query.zeroize();
                    app.query_before_input.zeroize();
                    let chosen = if parent_path.is_some() && parent_path != active_path {
                        parent_path
                    } else {
                        active_path
                    };
                    let rebuilt = rebuild_stack_paths(&root_path, chosen.as_deref());
                    (chosen, rebuilt)
                }
                Created::Group => (active_path, stack_paths),
            };
            app.re_resolve_tree_after_mutation(target_path.as_deref(), &target_stack_paths);
            app.refresh();
            match created {
                Created::Group => {
                    if let Some(idx) = app
                        .groups
                        .iter()
                        .position(|group| group.label.eq_ignore_ascii_case(name))
                    {
                        app.group_selected = idx + usize::from(app.has_parent_row());
                        app.focus = FocusPane::Groups;
                    }
                    app.status = format!(
                        "Group added in memory — press Ctrl+S or s to save to {}",
                        app.vault_name
                    );
                }
                Created::Entry(entry_ref) => {
                    if let Some(idx) = app
                        .hits
                        .iter()
                        .position(|hit| hit.reference() == entry_ref)
                        .or_else(|| {
                            app.hits
                                .iter()
                                .position(|hit| hit.title().eq_ignore_ascii_case(name))
                        })
                    {
                        app.entry_selected = idx;
                    }
                    app.focus = FocusPane::Entries;
                    app.load_entry_preview();
                    if app.hits.get(app.entry_selected).is_none() {
                        app.load_entry_from_ref(&entry_ref);
                    }
                    app.status = format!(
                        "Entry added in memory — press Ctrl+S or s to save to {}",
                        app.vault_name
                    );
                }
            }
        }
        Err(nkeepass::ServiceError::Ambiguous) => {
            app.status = "An entry with that title already exists".into();
        }
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
            if !app.clipboard.supports_atomic_ownership_clear() {
                app.clipboard_warning_pending = true;
            }
            app.status = if app.clipboard.supports_atomic_ownership_clear() {
                "Password copied; an ownership-safe clear will be attempted after 30s. Verify manually; it may remain.".into()
            } else if app.clipboard.supports_timed_clear() {
                "Password copied; best-effort compare-and-clear in 30s (verify manually; clipboard history or concurrent copies may retain it).".into()
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

fn reveal_otp(app: &mut App) {
    let Some(reference) = app.pending_entry.clone().or_else(|| app.entry.clone()) else {
        return;
    };
    let is_hotp = matches!(
        app.service.otp_metadata(&reference),
        Ok(Some(OtpMetadata {
            kind: ServiceOtpKind::Hotp,
            ..
        }))
    );
    if is_hotp {
        let was_open = app.entry.is_some();
        let target_path = app
            .hits
            .iter()
            .find(|hit| hit.reference() == reference)
            .map(|hit| hit.path().to_owned());
        let (active_path, stack_paths) = capture_tree_paths(app);
        match app.service.hotp_next_code(&reference) {
            Ok(code) => {
                app.dirty = true;
                app.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
                app.refresh();
                if was_open {
                    if let Some(idx) = target_path
                        .as_deref()
                        .and_then(|path| app.hits.iter().position(|hit| hit.path() == path))
                    {
                        app.entry_selected = idx;
                        let fresh = app.hits[idx].reference();
                        if app.load_entry_from_ref(&fresh) {
                            app.entry = Some(fresh);
                            app.focus = FocusPane::Detail;
                        }
                    } else {
                        app.entry = None;
                    }
                }
                app.clear_reveal();
                app.reveal = Some(code);
                app.reveal_until = Some(Instant::now() + REVEAL_TTL);
                app.status =
                    "HOTP generated (counter incremented) — press Ctrl+S or s to save".into();
            }
            Err(error) => app.status = clean(error.message()),
        }
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match app.service.totp_code_with_period(&reference, now) {
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
                app.re_resolve_current_tree();
                app.entry = None;
                app.detail.clear();
                app.refresh();
                app.status = "Attachment added; press Ctrl+S or s to save".into();
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
            app.re_resolve_current_tree();
            app.entry = None;
            app.detail.clear();
            app.refresh();
            app.status = "Attachment removed; press Ctrl+S or s to save".into();
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

    fn save_with_status(&mut self, path: &Path) {
        match self.save(path) {
            Ok(()) => {
                self.dirty = false;
                self.status = format!("Saved to {}", self.vault_name);
            }
            Err(error) => self.status = error,
        }
    }

    fn has_parent_row(&self) -> bool {
        self.query.is_empty() && !self.tree_stack.is_empty()
    }

    fn group_row_count(&self) -> usize {
        usize::from(self.has_parent_row()).saturating_add(self.groups.len())
    }

    fn group_index_for_row(&self, row: usize) -> Option<usize> {
        row.checked_sub(usize::from(self.has_parent_row()))
            .filter(|&index| index < self.groups.len())
    }

    fn display_group_path(&self) -> String {
        if self.tree_stack.is_empty() {
            return "/".to_owned();
        }
        match self.service.group_path(&self.tree_parent) {
            Ok(path) => {
                let rel = path.split_once('/').map_or(path.as_str(), |(_, rest)| rest);
                if rel.is_empty() {
                    "/".to_owned()
                } else {
                    format!("/{}", clean(rel))
                }
            }
            Err(_) => "/".to_owned(),
        }
    }

    // The real decision path is shared with lifecycle tests: failed saves and
    // cancelled decisions must keep the unlocked credentials for retry.
    fn resolve_pending_decision(&mut self, input: DecisionInput, path: &Path) -> DecisionEffect {
        let Some(pending) = self.pending_decision else {
            return DecisionEffect::None;
        };
        let has_unapplied_draft = (self.edit_mode && self.input_mode && !self.input.is_empty())
            || matches!(self.modal, Some(Modal::OtpConfig(_) | Modal::DbSettings(_)));
        let input = if input == DecisionInput::SaveSucceeded && has_unapplied_draft {
            self.status =
                "Finish or cancel the pending edit before saving; press c to return to it".into();
            DecisionInput::SaveFailed
        } else if input == DecisionInput::SaveSucceeded {
            match self.save(path) {
                Ok(()) => {
                    self.dirty = false;
                    self.status = format!("Saved to {}", self.vault_name);
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
            if matches!(self.modal, Some(Modal::OtpConfig(_) | Modal::DbSettings(_))) {
                self.modal = None;
            }
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
        self.detail_scroll = 0;
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
                self.tree_page_index = 0;
                self.tree_withheld = page.withheld;
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
                    self.tree_page_index = 0;
                    self.tree_withheld = page.withheld;
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
                self.group_selected = self
                    .group_selected
                    .min(self.group_row_count().saturating_sub(1));
                self.entry_selected = self.entry_selected.min(self.hits.len().saturating_sub(1));
                if self.focus == FocusPane::Detail {
                    self.focus = FocusPane::Entries;
                }
                if self.hits.is_empty()
                    && self.group_row_count() > 0
                    && self.focus == FocusPane::Entries
                {
                    self.focus = FocusPane::Groups;
                }
                self.load_entry_preview();
                self.status = format!(
                    "{} groups, {} entries{} · Tab pane · / search · ? help · Ctrl-P palette · q quit",
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

    fn re_resolve_current_tree(&mut self) {
        let active_path = self.service.group_path(&self.tree_parent).ok();
        let stack_paths: Vec<String> = self
            .tree_stack
            .iter()
            .filter_map(|group| self.service.group_path(group).ok())
            .collect();
        self.re_resolve_tree_after_mutation(active_path.as_deref(), &stack_paths);
    }

    fn re_resolve_tree_after_mutation(
        &mut self,
        target_path: Option<&str>,
        stack_paths: &[String],
    ) {
        if let Some(cursor) = self.tree_cursor.take() {
            let _ = self.service.release_tree_cursor(cursor);
        }
        let Ok(root) = self.service.root_group(self.session) else {
            return;
        };
        if stack_paths.is_empty() {
            reset_tree_location(&mut self.tree_parent, &mut self.tree_stack, root);
            return;
        }
        let Some(target) = target_path else {
            reset_tree_location(&mut self.tree_parent, &mut self.tree_stack, root);
            return;
        };
        let Ok(resolved_parent) = self.service.resolve_group(self.session, target) else {
            reset_tree_location(&mut self.tree_parent, &mut self.tree_stack, root);
            return;
        };
        let mut resolved_stack = Vec::with_capacity(stack_paths.len());
        for (idx, path) in stack_paths.iter().enumerate() {
            if idx == 0 {
                resolved_stack.push(root.clone());
            } else if let Ok(group) = self.service.resolve_group(self.session, path) {
                resolved_stack.push(group);
            } else {
                reset_tree_location(&mut self.tree_parent, &mut self.tree_stack, root);
                return;
            }
        }
        self.tree_parent = resolved_parent;
        self.tree_stack = resolved_stack;
    }

    fn navigate_up(&mut self) {
        if let Some(parent) = self.tree_stack.pop() {
            self.clear_reveal();
            self.entry = None;
            self.tree_parent = parent;
            self.group_selected = 0;
            self.entry_selected = 0;
            self.detail_scroll = 0;
            self.focus = FocusPane::Groups;
            self.refresh();
        }
    }

    fn enter_group(&mut self, group_idx: usize) {
        let Some(ui_group) = self.groups.get(group_idx) else {
            return;
        };
        let path = ui_group.path.clone();
        let group = ui_group
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
        self.group_selected = 0;
        self.entry_selected = 0;
        self.detail_scroll = 0;
        self.entry = None;
        self.refresh();
        if self.groups.is_empty() && !self.hits.is_empty() {
            self.focus = FocusPane::Entries;
        } else {
            self.focus = FocusPane::Groups;
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
                        TreeOrListPage::Tree(page.entries, page.withheld)
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
            Ok(Some(TreeOrListPage::Tree(hits, withheld))) => {
                self.tree_page_index = self.tree_page_index.saturating_add(1);
                self.tree_withheld = withheld;
                self.group_selected = 0;
                self.entry_selected = 0;
                self.hits = hits;
                self.load_entry_preview();
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
                self.tree_page_index = self.tree_page_index.saturating_add(1);
                self.tree_withheld = page.withheld;
                self.entry_selected = 0;
                self.hits = page.hits;
                self.load_entry_preview();
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

    fn load_entry_from_ref(&mut self, reference: &EntryRef) -> bool {
        match self.service.selected_entry(reference) {
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
                        format_otp_metadata(
                            self.service.otp_metadata(reference).ok().flatten(),
                            view.has_otp(),
                        ),
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
                true
            }
            Err(error) => {
                self.status = clean(error.message());
                false
            }
        }
    }

    fn load_entry_preview(&mut self) {
        let Some(hit) = self.hits.get(self.entry_selected) else {
            self.entry_icon = None;
            self.detail.clear();
            self.fields.clear();
            return;
        };
        let reference = hit.reference();
        self.load_entry_from_ref(&reference);
    }

    fn select(&mut self) {
        self.clear_reveal();
        self.attachment_selected = 0;
        if self.focus == FocusPane::Groups {
            if self.has_parent_row() && self.group_selected == 0 {
                self.navigate_up();
            } else if let Some(group_idx) = self.group_index_for_row(self.group_selected) {
                self.enter_group(group_idx);
            }
            return;
        }
        let Some(hit) = self.hits.get(self.entry_selected) else {
            return;
        };
        let reference = hit.reference();
        if self.load_entry_from_ref(&reference) {
            self.entry = Some(reference);
            self.focus = FocusPane::Detail;
            self.detail_scroll = 0;
            self.status = "↑/↓ select field · e edit value · r reveal password for 15s · I icon · Ctrl+S/s save · Esc back".into();
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
                    (self.input_mode && self.edit_mode && !self.input.is_empty())
                        || matches!(self.modal, Some(Modal::OtpConfig(_) | Modal::DbSettings(_))),
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
                if self.clipboard.supports_atomic_ownership_clear() {
                    self.clipboard_may_contain_password = false;
                    self.status = "Clipboard lease expired and clipboard was cleared".into();
                } else {
                    self.clipboard_may_contain_password = true;
                    self.clipboard_warning_pending = true;
                    self.status = "Clipboard lease expired; best-effort compare-and-clear attempted (verify manually; clipboard history or concurrent copies may retain it).".into();
                }
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
            if self.clipboard.release() == Ok(true)
                && self.clipboard.supports_atomic_ownership_clear()
            {
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
    reason = "keeps the three-pane Ratatui projection and rect tracking together"
)]
fn draw(frame: &mut Frame<'_>, app: &mut App) {
    if !usable_size(frame.area()) {
        app.header_area = Rect::default();
        app.groups_area = Rect::default();
        app.entries_area = Rect::default();
        app.detail_area = Rect::default();
        app.compact_detail = false;
        app.compact_fields_area = Rect::default();
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

    let is_dirty = needs_decision(
        app.dirty,
        app.input_mode && app.edit_mode && !app.input.is_empty(),
    );
    let group_path = app.display_group_path();
    let header_line = if frame.area().width >= 72 {
        let mut spans = vec![
            Span::styled("nkp", app.theme.header),
            Span::raw(format!(" · {} · {}", app.vault_name, group_path)),
        ];
        if is_dirty {
            spans.push(Span::raw(" "));
            spans.push(Span::styled("[UNSAVED · Ctrl+S]", app.theme.dirty));
        }
        if app.query.is_empty() {
            spans.push(Span::styled(
                " · Tab pane · / search · ? help",
                app.theme.muted,
            ));
        } else {
            spans.push(Span::raw(format!(" · Filter: {}", clean(&app.query))));
        }
        Line::from(spans)
    } else if is_dirty {
        Line::from(vec![
            Span::styled("nkp", app.theme.header),
            Span::raw(format!(" · {}", app.vault_name)),
            Span::raw(" "),
            Span::styled("[UNSAVED · Ctrl+S]", app.theme.dirty),
        ])
    } else {
        let mut spans = vec![
            Span::styled("nkp", app.theme.header),
            Span::raw(format!(" · {} · {}", app.vault_name, group_path)),
        ];
        if !app.query.is_empty() {
            spans.push(Span::raw(format!(" · /{}", clean(&app.query))));
        }
        Line::from(spans)
    };
    app.header_area = areas[0];
    frame.render_widget(Paragraph::new(header_line), areas[0]);

    let (groups_area, entries_area, detail_area) = if areas[1].width >= 72 {
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(22),
                Constraint::Percentage(30),
                Constraint::Percentage(48),
            ])
            .split(areas[1]);
        (panes[0], panes[1], panes[2])
    } else if !app.groups.is_empty() || !app.tree_stack.is_empty() {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(areas[1]);
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(3)])
            .split(body[0]);
        (left[0], left[1], body[1])
    } else {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(areas[1]);
        (Rect::default(), body[0], body[1])
    };
    app.groups_area = groups_area;
    app.entries_area = entries_area;
    app.detail_area = detail_area;

    if groups_area.width > 0 && groups_area.height > 0 {
        let mut group_items = Vec::new();
        if app.has_parent_row() {
            group_items.push(ListItem::new(Line::from(vec![
                Span::styled("..", app.theme.header),
                Span::styled(" (parent)", app.theme.muted),
            ])));
        }
        group_items.extend(app.groups.iter().map(|group| {
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
        }));
        let mut group_state = ListState::default().with_offset(app.groups_offset);
        group_state.select(
            (!app.locked && !group_items.is_empty())
                .then_some(app.group_selected.min(group_items.len().saturating_sub(1))),
        );
        let groups_focused = !app.locked && app.focus == FocusPane::Groups;
        let groups_title = if app.locked {
            "Groups · LOCKED".to_owned()
        } else {
            format!("Groups ({})", app.groups.len())
        };
        frame.render_stateful_widget(
            List::new(group_items)
                .block(
                    Block::default()
                        .title(groups_title)
                        .borders(Borders::ALL)
                        .border_style(if groups_focused {
                            app.theme.focused_border
                        } else {
                            app.theme.unfocused_border
                        }),
                )
                .highlight_style(app.theme.selection),
            groups_area,
            &mut group_state,
        );
        app.groups_offset = group_state.offset();
    } else {
        app.groups_offset = 0;
    }

    let entry_items = app
        .hits
        .iter()
        .map(|hit| {
            let icon = standard_icon(hit.icon_id());
            ListItem::new(Line::from(vec![
                Span::styled(icon.glyph, app.theme.category_style(icon.category)),
                Span::raw(" "),
                Span::raw(clean(hit.title())),
                Span::styled(format!("  {}", clean(hit.path())), app.theme.muted),
            ]))
        })
        .collect::<Vec<_>>();
    let mut entry_state = ListState::default().with_offset(app.entries_offset);
    entry_state.select(
        (!app.locked && !entry_items.is_empty())
            .then_some(app.entry_selected.min(entry_items.len().saturating_sub(1))),
    );
    let entries_focused = !app.locked && app.focus == FocusPane::Entries;
    let entries_title = if app.locked {
        "Entries · LOCKED".to_owned()
    } else if app.query.is_empty() {
        format!("Entries ({})", app.hits.len())
    } else {
        format!("Matches ({})", app.hits.len())
    };
    frame.render_stateful_widget(
        List::new(entry_items)
            .block(
                Block::default()
                    .title(entries_title)
                    .borders(Borders::ALL)
                    .border_style(if entries_focused {
                        app.theme.focused_border
                    } else {
                        app.theme.unfocused_border
                    }),
            )
            .highlight_style(app.theme.selection),
        entries_area,
        &mut entry_state,
    );
    app.entries_offset = entry_state.offset();

    let show_detail_body = !app.locked
        && (app.entry.is_some() || (detail_area.width >= 32 && detail_area.height >= 10));
    let preview_ref = app
        .entry
        .clone()
        .or_else(|| app.hits.get(app.entry_selected).map(SearchHit::reference));
    let mut detail =
        if show_detail_body {
            app.detail
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
                        rows.extend(app.fields.iter().enumerate().map(
                            |(index, (name, protected))| {
                                let text = field_row(
                                    name,
                                    *protected,
                                    app.entry.is_some() && index == app.selected_field,
                                );
                                if app.entry.is_some() && index == app.selected_field {
                                    Line::from(Span::styled(text, app.theme.selection))
                                } else {
                                    Line::from(text)
                                }
                            },
                        ));
                    }
                    if line == "Attachments:"
                        && let Some(reference) = &preview_ref
                        && let Ok(items) = app.service.attachment_metadata(reference)
                    {
                        rows.extend(items.iter().enumerate().map(|(index, item)| {
                            Line::from(format!(
                                "{} {} ({} bytes)",
                                if app.entry.is_some() && index == app.attachment_selected {
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
                .collect::<Vec<_>>()
        } else if !app.locked {
            vec![Line::from(Span::styled(
                "Enter: open · Tab: pane",
                app.theme.muted,
            ))]
        } else {
            Vec::new()
        };
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
    } else if show_detail_body && preview_ref.is_some() {
        detail.push(Line::from("Password: ••••••••"));
    }
    if is_dirty {
        detail.push(Line::from(Span::styled(
            "UNSAVED CHANGES · Ctrl+S or s to save",
            app.theme.dirty,
        )));
    }
    if !app.locked && app.entry.is_some() {
        detail.push(Line::from("↑/↓ select field · e edit · r reveal · c copy · t TOTP · g generate · I icon · a/n/p/x/d attachments · Ctrl+S/s save · Esc back"));
    }
    let detail_inner_height = usize::from(detail_area.height.saturating_sub(2));
    app.detail_max_scroll = detail.len().saturating_sub(detail_inner_height);
    let detail_scroll = app.detail_scroll.min(app.detail_max_scroll);
    app.detail_scroll = detail_scroll;
    let detail_focused = !app.locked && app.focus == FocusPane::Detail;
    frame.render_widget(
        Paragraph::new(detail)
            .scroll((u16::try_from(detail_scroll).unwrap_or(u16::MAX), 0))
            .block(
                Block::default()
                    .title(if app.locked {
                        "LOCKED"
                    } else if app.pending_decision == Some(PendingDecision::Lock) {
                        "IDLE LOCK PENDING · unsaved changes"
                    } else {
                        "Entry detail · secrets masked"
                    })
                    .borders(Borders::ALL)
                    .border_style(if detail_focused {
                        app.theme.focused_border
                    } else {
                        app.theme.unfocused_border
                    }),
            ),
        detail_area,
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
    if !app.locked && app.entry.is_some() && (areas[1].width < 72 || areas[1].height < 10) {
        app.groups_area = Rect::default();
        app.entries_area = Rect::default();
        app.detail_area = areas[1];
        app.compact_detail = true;
        draw_compact_entry(frame, app, areas[1]);
    } else {
        app.compact_detail = false;
        app.compact_fields_area = Rect::default();
        app.compact_fields_offset = 0;
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

fn draw_compact_entry(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    // On small screens metadata headings used to occupy every visible row.
    // Give fields the full width and let List keep the selected row in view.
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Entry detail · secrets masked")
        .borders(Borders::ALL)
        .border_style(app.theme.focused_border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(inner);
    app.compact_fields_area = chunks[1];
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
    let mut state = ListState::default().with_offset(app.compact_fields_offset);
    state.select((!rows.is_empty()).then_some(app.selected_field));
    frame.render_stateful_widget(
        List::new(rows).highlight_style(app.theme.selection),
        chunks[1],
        &mut state,
    );
    app.compact_fields_offset = state.offset();
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
        "Ctrl+K / Ctrl+G / : Open editable Path Bar (Tab completes, 5-item list)",
        "S / Ctrl+O        Database-level settings modal",
        "g (tree)          Toggle matching groups in path results",
        "Tab / Shift-Tab   Switch focus between Groups and Entries",
        "Up/Down or j/k    Move selection",
        "Enter / Right     Open selected group or entry",
        "Backspace / Left  Go to parent group / return from detail",
        "n                 Load next result page",
        "a / e             Add group / entry beneath selected or current group",
        "m                 Move selected entry to another group",
        "Alt+Up/Dn or K/J  Reorder selected entry up / down within group",
        "C / Ctrl+D        Clone / duplicate selected entry",
        "R                 Recycle selected entry (or confirm permanent delete)",
        "x / X             Remove selected entry / group (type YES to confirm)",
        "I                 Change KeePass icon (entry or group; 0..=68)",
        "o (tree)          Reveal TOTP or generate next HOTP for selected entry",
        "Ctrl+S / s        Save unsaved vault changes",
        "Mouse             Click header for Path Bar; click/wheel panes & modals",
        "d                 Discard unsaved changes in exit prompt",
        "c                 Cancel an exit prompt",
        "Ctrl-P palette    Add/remove/move/reorder/clone/recycle/restore entries,",
        "                  empty Recycle Bin, OTP reveal/config, Path Bar, DB settings",
        "Entry view:",
        "  e edit selected field · r reveal password · v reveal selected field",
        "  c copy password · t reveal TOTP / next HOTP · g generate password · I icon",
        "  m move to group · C clone · R recycle · a/n/p/x/d attachments",
        "  F2 inspect full attachment or field-consent target; arrows/Home/End pan",
        "  F3 review pending clipboard warning; a acknowledges only in that view",
        "  o export interchange · i import interchange · s save",
        "  Esc/Enter back to tree · n/p select attachment",
        "Icon picker: j/k or Up/Down move · / type filter · Enter apply · Esc cancel",
        "Colors: adaptive 4-tier (TrueColor / 256-color / Basic16 / NO_COLOR)",
        "Palette/help/aliases: Up/Down or j/k scroll; Esc closes",
        "Deletion & Empty Recycle Bin require typing YES exactly.",
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
                .title("nkp Icons · Enter · Esc")
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
                        "Type filter · Enter · Esc"
                    } else {
                        "/ filter · Enter · Esc"
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
            let prompt = match kind {
                DeleteKind::Entry => format!(
                    "{}\nRemove entry?\nType YES to confirm.",
                    path.split_once(": ")
                        .map_or("Selected target", |(label, _)| label)
                ),
                DeleteKind::PermanentEntry => {
                    "Permanent delete\nRemove entry?\nType YES to confirm.".to_owned()
                }
                DeleteKind::Group => format!(
                    "{}\nRemove group and all its contents?\nType YES to confirm.",
                    path.split_once(": ")
                        .map_or("Selected target", |(label, _)| label)
                ),
                DeleteKind::EmptyRecycleBin => {
                    "Recycle Bin\nEmpty Recycle Bin?\nType YES to confirm.".to_owned()
                }
            };
            draw_target_dialog(
                frame,
                "Confirm deletion",
                &prompt,
                path,
                *offset,
                &clean(input),
                "Arrows/PgUp/PgDn inspect full target\nHome/End · Enter delete · Esc cancel",
            );
        }
        Modal::MoveEntry {
            entry_title,
            rows,
            selected,
            scroll,
            error_msg,
            ..
        } => draw_move_entry_modal(
            frame,
            entry_title,
            rows,
            *selected,
            *scroll,
            error_msg.as_deref(),
            theme,
        ),
        Modal::OtpConfig(draft) => draw_otp_config_modal(frame, draft, theme),
        Modal::PathBar(state) => draw_path_bar_modal(frame, state, theme),
        Modal::DbSettings(draft) => draw_db_settings_modal(frame, draft, theme),
    }
}

fn compact_or_centered_area(frame: &Frame<'_>) -> Rect {
    let full = frame.area();
    if full.width < 68 || full.height < 18 {
        full
    } else {
        centered_rect(78, 78, full)
    }
}

fn draw_move_entry_modal(
    frame: &mut Frame<'_>,
    entry_title: &str,
    rows: &[MoveGroupRow],
    selected: usize,
    _scroll: usize,
    error_msg: Option<&str>,
    theme: &TuiTheme,
) {
    let area = compact_or_centered_area(frame);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Move entry to group · Enter · Esc")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Entry: ", theme.header),
            Span::raw(clean(entry_title)),
        ])),
        chunks[0],
    );
    let items: Vec<ListItem<'_>> = rows
        .iter()
        .map(|row| {
            let icon = standard_icon(row.std_icon);
            let indent = "  ".repeat(row.depth);
            let mut spans = vec![
                Span::raw(indent),
                Span::styled(icon.glyph, theme.category_style(icon.category)),
                Span::raw(format!(" {}", clean(&row.row_label))),
            ];
            if row.recycle_bin {
                spans.push(Span::styled(" [Recycle Bin]", theme.warning));
            }
            if row.depth > 0 {
                spans.push(Span::styled(
                    format!("  ({})", clean(&row.row_path)),
                    theme.muted,
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(selected.min(items.len().saturating_sub(1))));
    }
    frame.render_stateful_widget(
        List::new(items).highlight_style(theme.selection),
        chunks[1],
        &mut state,
    );
    let footer = error_msg.map_or_else(
        || {
            Line::from(Span::styled(
                "j/k move · Enter move · Esc cancel",
                theme.muted,
            ))
        },
        |err| Line::from(Span::styled(clean(err), theme.error)),
    );
    frame.render_widget(Paragraph::new(footer), chunks[2]);
}

fn draw_otp_config_modal(frame: &mut Frame<'_>, draft: &OtpConfigDraft, theme: &TuiTheme) {
    let area = compact_or_centered_area(frame);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Configure OTP (TOTP/HOTP)")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(inner);
    let kind_str = match draft.otp_kind {
        ServiceOtpKind::Totp => "TOTP",
        ServiceOtpKind::Hotp => "HOTP",
    };
    let algo_str = match draft.otp_algorithm {
        ServiceOtpAlgorithm::Sha1 => "SHA1",
        ServiceOtpAlgorithm::Sha256 => "SHA256",
        ServiceOtpAlgorithm::Sha512 => "SHA512",
    };
    let masked_secret = "•".repeat(draft.secret_b32.chars().count());
    let param_label = if draft.otp_kind == ServiceOtpKind::Totp {
        format!("Period (s): {}", clean(&draft.period_text))
    } else {
        format!("Counter: {}", clean(&draft.counter_text))
    };
    let rows = [
        format!("Kind: < {kind_str} >"),
        format!("Account: {}", clean(&draft.acct_label)),
        format!("Issuer: {}", clean(&draft.issuer_label)),
        format!("Algorithm: < {algo_str} >"),
        format!(
            "Digits: < {} >",
            if draft.use_steam { 5 } else { draft.otp_digits }
        ),
        param_label,
        format!("Steam: < {} >", if draft.use_steam { "Yes" } else { "No" }),
        format!("Secret (Base32): {masked_secret}"),
        "[Apply OTP Config]".to_owned(),
    ];
    let items: Vec<ListItem<'_>> = rows
        .into_iter()
        .enumerate()
        .map(|(idx, text)| {
            let prefix = if idx == draft.selected_row {
                if draft.editing_text { "* " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{prefix}{text}"))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(draft.selected_row.min(8)));
    frame.render_stateful_widget(
        List::new(items).highlight_style(theme.selection),
        chunks[0],
        &mut state,
    );
    let footer_lines = if let Some(err) = &draft.error_msg {
        vec![
            Line::from(Span::styled(clean(err), theme.error)),
            Line::from(Span::styled("Edit & retry · Esc cancel", theme.muted)),
        ]
    } else if draft.editing_text {
        vec![
            Line::from(Span::styled(
                "Editing field (secret is masked)",
                theme.header,
            )),
            Line::from(Span::styled(
                "Type text · Enter/Esc done field",
                theme.muted,
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled("↑/↓ move · ←/→/Space toggle", theme.muted)),
            Line::from(Span::styled(
                "Enter edit/apply · Ctrl+S apply · Esc",
                theme.muted,
            )),
        ]
    };
    frame.render_widget(Paragraph::new(footer_lines), chunks[1]);
}

fn draw_path_bar_modal(frame: &mut Frame<'_>, state: &PathBarState, theme: &TuiTheme) {
    let full = frame.area();
    let dropdown_rows = if state.dropdown_open && !state.completions.is_empty() {
        u16::try_from(state.completions.len().min(5)).unwrap_or(5) + 2
    } else {
        0
    };
    let total_height = (3 + dropdown_rows + 1).min(full.height);
    let overlay = Rect::new(full.x, full.y, full.width, total_height);
    frame.render_widget(Clear, overlay);
    let mut constraints = vec![Constraint::Length(3)];
    if dropdown_rows > 0 {
        constraints.push(Constraint::Length(dropdown_rows));
    }
    constraints.push(Constraint::Length(1));
    let chunks = Layout::vertical(constraints).split(overlay);
    frame.render_widget(
        Paragraph::new(format!("> {}", clean(&state.buffer))).block(
            Block::default()
                .title("Go to path · Tab complete · Enter go · Esc")
                .borders(Borders::ALL)
                .border_style(theme.focused_border),
        ),
        chunks[0],
    );
    let footer_idx = if dropdown_rows > 0 {
        let items: Vec<ListItem<'_>> = state
            .completions
            .iter()
            .take(5)
            .map(|item| {
                let icon = standard_icon(item.std_icon);
                let kind_tag = if item.is_group_item {
                    "[group]"
                } else {
                    "[entry]"
                };
                ListItem::new(Line::from(vec![
                    Span::styled(icon.glyph, theme.category_style(icon.category)),
                    Span::raw(" "),
                    Span::styled(kind_tag, theme.muted),
                    Span::raw(format!(" {}", clean(&item.full_path))),
                ]))
            })
            .collect();
        let mut list_state = ListState::default();
        list_state.select(Some(
            state
                .selected
                .min(state.completions.len().min(5).saturating_sub(1)),
        ));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::default().borders(Borders::ALL))
                .highlight_style(theme.selection),
            chunks[1],
            &mut list_state,
        );
        2
    } else {
        1
    };
    let footer = if let Some(err) = &state.error_msg {
        Line::from(Span::styled(clean(err), theme.error))
    } else {
        Line::from(Span::styled(
            "Tab complete · ↑/↓ cycle · Enter go · Esc",
            theme.muted,
        ))
    };
    frame.render_widget(Paragraph::new(footer), chunks[footer_idx]);
}

fn draw_db_settings_modal(frame: &mut Frame<'_>, draft: &DbSettingsDraft, theme: &TuiTheme) {
    let area = compact_or_centered_area(frame);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Database Settings")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(inner);
    let cipher_str = match draft.cipher {
        VaultCipher::Aes => "AES-256",
        VaultCipher::ChaCha20 => "ChaCha20",
    };
    let comp_str = match draft.compression {
        VaultCompression::GZip => "GZip",
        VaultCompression::None => "None",
    };
    let kdf_str = match draft.kdf_kind {
        DbKdfKind::Argon2id => "Argon2id",
        DbKdfKind::Argon2d => "Argon2d",
        DbKdfKind::Aes => "AES-KDF",
    };
    let mut rows = vec![
        format!("Database Name: {}", clean(&draft.db_name)),
        format!("Description: {}", clean(&draft.db_desc)),
        format!("Default Username: {}", clean(&draft.db_default_user)),
        format!(
            "Recycle Bin: < {} >",
            if draft.recycle_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        ),
        format!("History Max Items: {}", clean(&draft.hist_max_items)),
        format!("History Max Size (B): {}", clean(&draft.hist_max_size)),
        format!("Outer Cipher: < {cipher_str} >"),
        format!("Compression: < {comp_str} >"),
        format!("KDF: < {kdf_str} >"),
    ];
    match draft.kdf_kind {
        DbKdfKind::Aes => rows.push(format!("AES Rounds: {}", clean(&draft.aes_rounds))),
        DbKdfKind::Argon2id | DbKdfKind::Argon2d => {
            rows.push(format!("Argon2 Memory (KiB): {}", clean(&draft.argon_mem)));
            rows.push(format!("Argon2 Iterations: {}", clean(&draft.argon_iters)));
            rows.push(format!("Argon2 Lanes: {}", clean(&draft.argon_lanes)));
        }
    }
    rows.push("[Apply Settings]".to_owned());
    let row_count = rows.len();
    let items: Vec<ListItem<'_>> = rows
        .into_iter()
        .enumerate()
        .map(|(idx, text)| {
            let prefix = if idx == draft.selected_row {
                if draft.editing_text { "* " } else { "> " }
            } else {
                "  "
            };
            ListItem::new(format!("{prefix}{text}"))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(draft.selected_row.min(row_count.saturating_sub(1))));
    frame.render_stateful_widget(
        List::new(items).highlight_style(theme.selection),
        chunks[0],
        &mut state,
    );
    let footer_lines = if let Some(err) = &draft.error_msg {
        vec![
            Line::from(Span::styled(clean(err), theme.error)),
            Line::from(Span::styled("Fix & retry · Esc cancel", theme.muted)),
        ]
    } else if draft.editing_text {
        vec![
            Line::from(Span::styled("Editing field", theme.header)),
            Line::from(Span::styled("Type value · Enter/Esc done", theme.muted)),
        ]
    } else {
        vec![
            Line::from(Span::styled("↑/↓ move · ←/→/Space cycle", theme.muted)),
            Line::from(Span::styled(
                "Enter edit/apply · Ctrl+S apply · Esc",
                theme.muted,
            )),
        ]
    };
    frame.render_widget(Paragraph::new(footer_lines), chunks[1]);
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

#[cfg(test)]
fn handle_input_mode_key(app: &mut App, key: KeyCode) {
    handle_input_mode_key_event(app, KeyEvent::new(key, KeyModifiers::NONE));
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps input-mode submission and key handling together"
)]
fn handle_input_mode_key_event(app: &mut App, key_event: KeyEvent) {
    let key = key_event.code;
    let modifiers = key_event.modifiers;
    match key {
        KeyCode::Esc => {
            app.action_target = None;
            if app.action == Action::Query {
                cancel_live_query(&mut app.query, &mut app.query_before_input, &mut app.input);
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
            match validate_otp_uri(&app.input) {
                Ok(()) => {
                    let Some(reference) = app.pending_entry.as_ref().or(app.entry.as_ref()) else {
                        clear_input(&mut app.input);
                        app.input_mode = false;
                        app.edit_mode = false;
                        app.pending_entry = None;
                        app.status = "No selected entry".into();
                        return;
                    };
                    match app.service.set_custom_field(reference, "otp", &app.input) {
                        Ok(()) => {
                            clear_input(&mut app.input);
                            app.input_mode = false;
                            app.edit_mode = false;
                            app.pending_entry = None;
                            app.dirty = true;
                            app.re_resolve_current_tree();
                            app.entry = None;
                            app.entry_icon = None;
                            app.detail.clear();
                            app.fields.clear();
                            app.refresh();
                            app.status =
                                "OTP URI updated in memory; press Ctrl+S or s to save".into();
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
                    app.status = format!("{message}; draft retained (retry or Esc to discard)");
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
                app.re_resolve_current_tree();
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
                    if let Some(reference) = app.pending_entry.take().or_else(|| app.entry.clone())
                    {
                        match app.service.set_title(&reference, &value) {
                            Ok(()) => {
                                app.dirty = true;
                                app.re_resolve_current_tree();
                                app.entry = None;
                                app.entry_icon = None;
                                app.detail.clear();
                                app.fields.clear();
                                app.refresh();
                                app.status =
                                    "Entry title renamed in memory; press Ctrl+S or s to save"
                                        .into();
                            }
                            Err(error) => app.status = clean(error.message()),
                        }
                    } else {
                        app.status = "No entry selected".into();
                    }
                }
                Action::EditTags => {
                    if let Some(reference) = app.pending_entry.take().or_else(|| app.entry.clone())
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
                                app.re_resolve_current_tree();
                                app.entry = None;
                                app.entry_icon = None;
                                app.detail.clear();
                                app.fields.clear();
                                app.refresh();
                                app.status =
                                    "Entry tags updated in memory; press Ctrl+S or s to save"
                                        .into();
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
                        reveal_otp(app);
                    } else {
                        app.status = "OTP reveal cancelled".into();
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
                        return;
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
                    if let Some(field) = approve_field_reveal(&value, &mut app.field_to_reveal) {
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
                && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
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
}

struct MouseCaptureGuard {
    active: bool,
}

impl MouseCaptureGuard {
    fn enter() -> io::Result<Self> {
        crossterm::execute!(io::stdout(), crossterm::event::EnableMouseCapture)?;
        Ok(Self { active: true })
    }

    fn disable(&mut self) -> io::Result<()> {
        if self.active {
            self.active = false;
            crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture)?;
        }
        Ok(())
    }
}

impl Drop for MouseCaptureGuard {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
        }
    }
}

fn should_handle_key_event(kind: KeyEventKind, code: KeyCode) -> bool {
    match kind {
        KeyEventKind::Press => true,
        KeyEventKind::Repeat => matches!(
            code,
            KeyCode::Up
                | KeyCode::Down
                | KeyCode::Left
                | KeyCode::Right
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
                | KeyCode::End
        ),
        KeyEventKind::Release => false,
    }
}

fn rect_contains(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}

fn list_row_at(area: Rect, column: u16, row: u16, offset: usize, count: usize) -> Option<usize> {
    if area.width < 3 || area.height < 3 {
        return None;
    }
    let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);
    if !rect_contains(inner, column, row) {
        return None;
    }
    let idx = offset.saturating_add(usize::from(row - inner.y));
    (idx < count).then_some(idx)
}

fn scroll_modal(modal: &mut Modal, down: bool) {
    match modal {
        Modal::Help { scroll } | Modal::Aliases { scroll } => {
            *scroll = if down {
                scroll.saturating_add(1)
            } else {
                scroll.saturating_sub(1)
            };
        }
        Modal::Palette { selected, scroll } => {
            *selected = if down {
                selected
                    .saturating_add(1)
                    .min(PALETTE_CHOICES.len().saturating_sub(1))
            } else {
                selected.saturating_sub(1)
            };
            *scroll = selected.saturating_sub(3);
        }
        Modal::IconPicker {
            filter,
            selected,
            scroll,
            ..
        } => {
            let count = filtered_standard_icons(filter).len();
            *selected = if down {
                selected.saturating_add(1).min(count.saturating_sub(1))
            } else {
                selected.saturating_sub(1)
            };
            *scroll = selected.saturating_sub(3);
        }
        Modal::Target { target, offset, .. } => {
            let key = if down { KeyCode::Down } else { KeyCode::Up };
            *offset = move_target_offset(*offset, target, key);
        }
        Modal::ConfirmDelete { path, offset, .. } => {
            let key = if down { KeyCode::Down } else { KeyCode::Up };
            *offset = move_target_offset(*offset, path, key);
        }
        Modal::MoveEntry {
            rows,
            selected,
            scroll,
            ..
        } => {
            let count = rows.len();
            *selected = if down {
                selected.saturating_add(1).min(count.saturating_sub(1))
            } else {
                selected.saturating_sub(1)
            };
            *scroll = selected.saturating_sub(3);
        }
        Modal::PathBar(state) => {
            if state.dropdown_open && !state.completions.is_empty() {
                state.selected = if down {
                    state
                        .selected
                        .saturating_add(1)
                        .min(state.completions.len().saturating_sub(1))
                } else {
                    state.selected.saturating_sub(1)
                };
            }
        }
        Modal::OtpConfig(draft) => {
            if !draft.editing_text {
                draft.selected_row = if down {
                    draft.selected_row.saturating_add(1).min(8)
                } else {
                    draft.selected_row.saturating_sub(1)
                };
            }
        }
        Modal::DbSettings(draft) => {
            if !draft.editing_text {
                let max_row = db_settings_row_count(draft.kdf_kind).saturating_sub(1);
                draft.selected_row = if down {
                    draft.selected_row.saturating_add(1).min(max_row)
                } else {
                    draft.selected_row.saturating_sub(1)
                };
            }
        }
        Modal::ClipboardWarning { .. } => {}
    }
}

fn handle_mouse_left_click(app: &mut App, column: u16, row: u16) {
    if rect_contains(app.header_area, column, row) {
        begin_path_bar(app);
        return;
    }
    if let Some(row_idx) = list_row_at(
        app.groups_area,
        column,
        row,
        app.groups_offset,
        app.group_row_count(),
    ) {
        app.entry = None;
        app.clear_reveal();
        if app.has_parent_row() && row_idx == 0 {
            app.focus = FocusPane::Groups;
            app.navigate_up();
        } else if let Some(group_idx) = app.group_index_for_row(row_idx) {
            if app.focus == FocusPane::Groups && app.group_selected == row_idx {
                app.enter_group(group_idx);
            } else {
                app.focus = FocusPane::Groups;
                app.group_selected = row_idx;
            }
        }
        return;
    }
    if rect_contains(app.groups_area, column, row) {
        app.entry = None;
        app.clear_reveal();
        app.focus = FocusPane::Groups;
        return;
    }
    if let Some(entry_idx) = list_row_at(
        app.entries_area,
        column,
        row,
        app.entries_offset,
        app.hits.len(),
    ) {
        app.clear_reveal();
        if app.focus == FocusPane::Entries && app.entry_selected == entry_idx && app.entry.is_none()
        {
            app.select();
        } else {
            app.entry = None;
            app.focus = FocusPane::Entries;
            app.entry_selected = entry_idx;
            app.detail_scroll = 0;
            app.load_entry_preview();
        }
        return;
    }
    if rect_contains(app.entries_area, column, row) {
        app.entry = None;
        app.clear_reveal();
        app.focus = FocusPane::Entries;
        return;
    }
    if rect_contains(app.detail_area, column, row) {
        app.clear_reveal();
        if app.compact_detail {
            if rect_contains(app.compact_fields_area, column, row) {
                let idx = app
                    .compact_fields_offset
                    .saturating_add(usize::from(row - app.compact_fields_area.y));
                if idx < app.fields.len() {
                    app.selected_field = idx;
                }
            }
        } else if app.entry.is_none() && app.hits.get(app.entry_selected).is_some() {
            app.focus = FocusPane::Entries;
            app.select();
        }
    }
}

fn handle_mouse_scroll(app: &mut App, column: u16, row: u16, down: bool) {
    if rect_contains(app.groups_area, column, row) {
        app.group_selected = if down {
            app.group_selected
                .saturating_add(1)
                .min(app.group_row_count().saturating_sub(1))
        } else {
            app.group_selected.saturating_sub(1)
        };
    } else if rect_contains(app.entries_area, column, row) {
        app.entry = None;
        app.focus = FocusPane::Entries;
        app.clear_reveal();
        app.entry_selected = if down {
            app.entry_selected
                .saturating_add(1)
                .min(app.hits.len().saturating_sub(1))
        } else {
            app.entry_selected.saturating_sub(1)
        };
        app.detail_scroll = 0;
        app.load_entry_preview();
    } else if rect_contains(app.detail_area, column, row) {
        if app.compact_detail {
            move_field_selection(&mut app.selected_field, app.fields.len(), down);
        } else {
            app.detail_scroll = if down {
                app.detail_scroll
                    .saturating_add(1)
                    .min(app.detail_max_scroll)
            } else {
                app.detail_scroll.saturating_sub(1)
            };
        }
    }
}

fn handle_mouse_event(app: &mut App, mouse: MouseEvent) {
    if app.locked || app.pending_decision.is_some() || app.reveal.is_some() || app.input_mode {
        return;
    }
    if let Some(modal) = app.modal.as_mut() {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                app.last_activity = Instant::now();
                scroll_modal(modal, false);
            }
            MouseEventKind::ScrollDown => {
                app.last_activity = Instant::now();
                scroll_modal(modal, true);
            }
            _ => {}
        }
        return;
    }
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            app.last_activity = Instant::now();
            handle_mouse_left_click(app, mouse.column, mouse.row);
        }
        MouseEventKind::ScrollUp => {
            app.last_activity = Instant::now();
            handle_mouse_scroll(app, mouse.column, mouse.row, false);
        }
        MouseEventKind::ScrollDown => {
            app.last_activity = Instant::now();
            handle_mouse_scroll(app, mouse.column, mouse.row, true);
        }
        _ => {}
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps key event dispatch and focus routing together"
)]
fn handle_key_event(app: &mut App, key: KeyEvent, path: &Path) -> KeyOutcome {
    if !should_handle_key_event(key.kind, key.code) {
        return KeyOutcome::Continue;
    }
    app.last_activity = Instant::now();
    // Warning inspection/acknowledgement is independent of an action,
    // unsaved decision, disclosure, or lock screen. Other keys cannot
    // accidentally acknowledge it or submit the interaction beneath it.
    if key.code == KeyCode::F(3) && app.clipboard_warning_pending {
        open_clipboard_warning(app);
        return KeyOutcome::Continue;
    }
    if matches!(&app.modal, Some(Modal::ClipboardWarning { .. })) {
        handle_modal_key_event(app, key);
        return KeyOutcome::Continue;
    }
    if app.locked {
        if key.code == KeyCode::Char('q') {
            return KeyOutcome::Exit;
        }
        return KeyOutcome::Continue;
    }
    // Disclosure owns focus: other interactions must not open invisibly
    // behind it and consume the one Escape needed to hide the value.
    if app.reveal.is_some() {
        app.modal = None;
        if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
            app.clear_reveal();
            app.status = "Revealed value hidden".into();
        }
        return KeyOutcome::Continue;
    }
    if app.pending_decision.is_some() {
        let input = match key.code {
            KeyCode::Char('s') => DecisionInput::SaveSucceeded,
            KeyCode::Char('d') => DecisionInput::Discard,
            KeyCode::Char('c') | KeyCode::Esc => DecisionInput::Cancel,
            _ => return KeyOutcome::Continue,
        };
        if app.resolve_pending_decision(input, path) == DecisionEffect::Exit {
            return KeyOutcome::Exit;
        }
        return KeyOutcome::Continue;
    }
    if app.modal.is_some() {
        handle_modal_key_event(app, key);
        return KeyOutcome::Continue;
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
            return KeyOutcome::Exit;
        }
        app.status = "Unsaved changes: s save · d discard · c cancel".into();
        return KeyOutcome::Continue;
    }
    if key.code == KeyCode::F(2)
        && app.entry.is_some()
        && (!app.input_mode || app.action_target.is_some() || app.action == Action::RevealField)
    {
        inspect_action_target(app);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && key.code == KeyCode::Char('p')
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        app.modal = Some(Modal::Palette {
            selected: 0,
            scroll: 0,
        });
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && key.code == KeyCode::Char('s')
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        app.save_with_status(path);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && ((matches!(key.code, KeyCode::Char('k' | 'g'))
            && key.modifiers.contains(KeyModifiers::CONTROL))
            || key.code == KeyCode::Char(':'))
    {
        begin_path_bar(app);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && ((key.code == KeyCode::Char('d') && key.modifiers.contains(KeyModifiers::CONTROL))
            || key.code == KeyCode::Char('C'))
    {
        clone_selected_entry(app);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && ((key.code == KeyCode::Char('o') && key.modifiers.contains(KeyModifiers::CONTROL))
            || key.code == KeyCode::Char('S'))
    {
        begin_db_settings(app);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && ((key.code == KeyCode::Up && key.modifiers.contains(KeyModifiers::ALT))
            || key.code == KeyCode::Char('K'))
    {
        reorder_selected_entry(app, true);
        return KeyOutcome::Continue;
    }
    if !app.input_mode
        && ((key.code == KeyCode::Down && key.modifiers.contains(KeyModifiers::ALT))
            || key.code == KeyCode::Char('J'))
    {
        reorder_selected_entry(app, false);
        return KeyOutcome::Continue;
    }
    if !app.input_mode && key.code == KeyCode::Char('?') {
        app.modal = Some(Modal::Help { scroll: 0 });
        return KeyOutcome::Continue;
    }
    if app.input_mode {
        handle_input_mode_key_event(app, key);
        return KeyOutcome::Continue;
    }
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        app.clear_reveal();
        app.entry = None;
        app.focus = match app.focus {
            FocusPane::Groups => FocusPane::Entries,
            FocusPane::Entries | FocusPane::Detail => FocusPane::Groups,
        };
        if app.focus == FocusPane::Entries {
            app.load_entry_preview();
        }
        return KeyOutcome::Continue;
    }
    if app.entry.is_none() {
        match key.code {
            KeyCode::Char('n') => app.next_page(),
            KeyCode::Char('s') => app.save_with_status(path),
            KeyCode::Char('a') => begin_add(app, Action::AddGroup),
            KeyCode::Char('e') => begin_add(app, Action::AddEntry),
            KeyCode::Char('m') => begin_move_entry(app),
            KeyCode::Char('R') => recycle_selected_entry(app),
            KeyCode::Char('o' | 't') => begin_otp_reveal(app),
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
                if app.focus == FocusPane::Groups {
                    app.group_selected = app
                        .group_selected
                        .saturating_add(1)
                        .min(app.group_row_count().saturating_sub(1));
                } else {
                    app.entry_selected = app
                        .entry_selected
                        .saturating_add(1)
                        .min(app.hits.len().saturating_sub(1));
                    app.detail_scroll = 0;
                    app.load_entry_preview();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.clear_reveal();
                if app.focus == FocusPane::Groups {
                    app.group_selected = app.group_selected.saturating_sub(1);
                } else {
                    app.entry_selected = app.entry_selected.saturating_sub(1);
                    app.detail_scroll = 0;
                    app.load_entry_preview();
                }
            }
            KeyCode::Right => {
                if app.focus == FocusPane::Groups || app.hits.get(app.entry_selected).is_some() {
                    app.select();
                }
            }
            KeyCode::Left => {
                if app.focus == FocusPane::Groups && app.query.is_empty() {
                    app.navigate_up();
                } else if app.focus == FocusPane::Entries {
                    app.focus = FocusPane::Groups;
                }
            }
            KeyCode::Enter => app.select(),
            KeyCode::Backspace if app.query.is_empty() => app.navigate_up(),
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
                    "Path glob (max 1024 bytes); type to filter · Enter done · Esc cancel".into();
            }
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Left => {
                app.entry = None;
                app.focus = FocusPane::Entries;
                app.clear_reveal();
                app.load_entry_preview();
            }
            KeyCode::Char('I') => begin_icon_picker(app, None),
            KeyCode::Char('m') => begin_move_entry(app),
            KeyCode::Char('R') => recycle_selected_entry(app),
            KeyCode::Char('e') => {
                app.clear_reveal();
                let Some((field, _)) = app.fields.get(app.selected_field) else {
                    app.status = "No field selected".into();
                    return KeyOutcome::Continue;
                };
                if field == "Title" {
                    app.status = "Title cannot be edited as a field".into();
                    return KeyOutcome::Continue;
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
                if app.clipboard.supports_atomic_ownership_clear() {
                    "Copy password? Other apps can read it. Windows will attempt an ownership-safe clear in 30s, but it may remain. Type YES to confirm."
                } else if app.clipboard.supports_timed_clear() {
                    "Copy password? Other apps can read it. nkp will attempt a best-effort compare-and-clear in 30s (verify manually; clipboard history or concurrent copies may retain it). Type YES to confirm."
                } else {
                    "Copy password? Other apps can read it. This platform cannot safely auto-clear; clear manually when done. Type YES to confirm."
                },
            ),
            KeyCode::Char('t') => begin_otp_reveal(app),
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
            KeyCode::Char('s') => app.save_with_status(path),
            _ => {}
        }
    }
    KeyOutcome::Continue
}

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
        if !usable_size(terminal.size()?.into()) {
            app.clear_reveal();
            continue;
        }
        match event {
            Event::Key(key) => {
                if handle_key_event(app, key, path) == KeyOutcome::Exit {
                    break;
                }
            }
            Event::Mouse(mouse) => handle_mouse_event(app, mouse),
            _ => {}
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
    let vault_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "vault.kdbx".to_owned(), clean);
    let mut app = new_app_with_theme(service, session, credentials, aliases, theme, vault_name)?;
    app.refresh();
    #[cfg(unix)]
    let result = run_terminal(&mut app, path);
    #[cfg(not(unix))]
    let result = ratatui::run(|terminal| {
        let mut mouse_guard = MouseCaptureGuard::enter()?;
        let result = app_result_before_teardown(&mut app, |app| run_ui(terminal, app, path));
        finish_terminal(result, mouse_guard.disable())
    });
    app.lock_vault();
    result
}

struct LockOnDrop<'a>(&'a mut App);

impl Drop for LockOnDrop<'_> {
    fn drop(&mut self) {
        self.0.lock_vault();
    }
}

fn app_result_before_teardown(
    app: &mut App,
    run: impl FnOnce(&mut App) -> io::Result<()>,
) -> io::Result<()> {
    let guard = LockOnDrop(app);
    let result = run(guard.0);
    // Normal run_ui completion already locks the vault. Escaping errors and
    // unwinding panics must do so too, before screen writes, MouseCaptureGuard,
    // or mode restoration can block/fail. Recoverable save errors stay inside
    // run_ui and never cross this boundary.
    if result.is_err() {
        guard.0.lock_vault();
    }
    std::mem::forget(guard);
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
    // Declare MouseCaptureGuard outside run_initialized_terminal /
    // app_result_before_teardown so app.lock_vault() always drops credentials
    // before DisableMouseCapture writes to stdout, including during panics.
    let mut mouse_guard = None;
    // Ratatui's panic hook also restores its QUIET snapshot, before unwinding
    // reaches modes. It cannot replay input under the original echo/ISIG bits.
    let result = run_initialized_terminal(app, ratatui::try_init(), |terminal, app| {
        mouse_guard = Some(MouseCaptureGuard::enter()?);
        run_ui(terminal, app, path)
    });
    let result = finish_terminal(
        result,
        mouse_guard
            .as_mut()
            .map_or(Ok(()), MouseCaptureGuard::disable),
    );
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
        "vault.kdbx".to_owned(),
    )
}

fn new_app_with_theme(
    service: VaultService,
    session: nkeepass::SessionId,
    credentials: KdbxCredentials,
    aliases: Vec<String>,
    theme: TuiTheme,
    vault_name: String,
) -> io::Result<App> {
    let tree_parent = service
        .root_group(session)
        .map_err(|_| io::Error::other("cannot read vault root"))?;
    Ok(App {
        service,
        session,
        credentials: Some(credentials),
        vault_name,
        focus: FocusPane::Entries,
        hits: Vec::new(),
        groups: Vec::new(),
        tree_parent,
        tree_stack: Vec::new(),
        tree_cursor: None,
        list_cursor: None,
        tree_page_index: 0,
        tree_withheld: 0,
        page_failure: None,
        group_selected: 0,
        entry_selected: 0,
        groups_offset: 0,
        entries_offset: 0,
        detail_scroll: 0,
        detail_max_scroll: 0,
        compact_detail: false,
        compact_fields_offset: 0,
        compact_fields_area: Rect::default(),
        header_area: Rect::default(),
        groups_area: Rect::default(),
        entries_area: Rect::default(),
        detail_area: Rect::default(),
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
    fn screen(app: &mut super::App, width: u16, height: u16) -> String {
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
            let text = screen(&mut app, 40, 12);
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
            let text = screen(&mut app, 40, 12);
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
            let text = screen(&mut app, 40, 12);
            assert!(text.contains(suffix));
            assert!(text.contains(&format!("Field {}/2", selected + 1)));
            super::handle_modal_key(&mut app, super::KeyCode::Esc);
            assert!(app.input_mode);
            assert!(screen(&mut app, 40, 12).contains("Type YES"));
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
        let text = screen(&mut app, 40, 12);
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
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Clear it manually."));
        assert!(text.contains("F3"));
        app.status = "Saved".into();
        app.refresh();
        assert!(app.clipboard_warning_pending);
        super::open_clipboard_warning(&mut app);
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Clear it manually."));
        assert!(text.contains("Acknowledging"));
        super::handle_modal_key(&mut app, super::KeyCode::Enter);
        assert!(app.clipboard_warning_pending); // Enter is not acknowledgement.
        app.lock_vault();
        assert!(app.clipboard_warning_pending);
        assert!(screen(&mut app, 40, 12).contains("Clear it manually."));
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
            let text = screen(&mut app, 40, 12);
            assert!(text.contains(&format!("> {}", app.fields[selected].0)));
            let name = app.fields[selected].0.clone();
            super::begin_field_reveal(&mut app);
            let text = screen(&mut app, 40, 12);
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
            assert_eq!(
                app.clipboard_warning_pending,
                outcome != 0 || !app.clipboard.supports_atomic_ownership_clear()
            );
            assert_eq!(app.action, super::Action::GenerateConfirm);
            assert!(app.input_mode);
            assert_eq!(app.action_prompt, instructions);
            assert!(app.status.contains(if outcome == 0 {
                "Clipboard lease expired"
            } else {
                "Clear it manually"
            }));
            let text = screen(&mut app, 40, 12);
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
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Clipboard expiry"));
        assert!(text.contains("Clear it manually."));
        super::begin_action(
            &mut app,
            super::Action::PasswordReveal,
            "Reveal password? Type YES. WARNING: terminal scrollback and screenshots may retain it; shown for 15s.",
        );
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Type YES."));
        assert!(text.contains("WARNING:"));
        assert!(text.contains("Esc cancel"));
        app.input_mode = false;
        app.pending_decision = Some(super::PendingDecision::Exit);
        app.status = "Save failed: cannot save vault.".into();
        let text = screen(&mut app, 40, 12);
        for expected in ["Save failed:", "s save", "d discard", "c cancel"] {
            assert!(text.contains(expected));
        }
        app.pending_decision = Some(super::PendingDecision::Lock);
        app.status = "Idle lock requested. Unsaved changes: s save · d discard · c cancel".into();
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Idle lock requested."));
        assert!(text.contains("d discard"));
        app.pending_decision = None;
        app.clipboard_may_contain_password = true;
        app.lock_vault();
        let text = screen(&mut app, 40, 12);
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
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("Type YES"));
        assert!(text.contains("Esc cancel"));
        super::handle_modal_key(&mut app, super::KeyCode::End);
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("TAIL"));
        assert!(text.contains("Group row 2/2"));
        app.modal = None;
        app.reveal = Some(zeroize::Zeroizing::new("disposable-render-marker".into()));
        app.detail = vec!["metadata".into(); 100];
        let text = screen(&mut app, 40, 12);
        assert!(text.contains("WARNING:"));
        assert!(text.contains("disposable-render-marker"));
        let text = screen(&mut app, 30, 8);
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
        let text = screen(&mut app, 120, 40);
        assert!(text.contains("> second.bin"));
        assert!(!text.contains("> first.bin"));
        super::begin_attachment_action(&mut app, super::Action::ExportAttachment);
        super::inspect_action_target(&mut app);
        let text = screen(&mut app, 40, 12);
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
        let text = screen(&mut app, 120, 40);
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
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::TrueColor,
                None,
                Some("xterm"),
                None,
                None,
                None,
                None,
            ),
            super::ColorTier::TrueColor
        );
        assert_eq!(
            super::detect_color_tier(
                super::ColorOverride::TrueColor,
                None,
                Some("dumb"),
                None,
                None,
                None,
                None,
            ),
            super::ColorTier::None
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

        let rendered_tree = screen(&mut app, 80, 20);
        assert!(rendered_tree.contains(standard_icon(48).glyph));
        assert!(rendered_tree.contains(standard_icon(0).glyph));
        assert!(rendered_tree.contains("nkp"));

        // Open IconPicker on group row (selected == 0), filter for "Email" (19), apply.
        app.focus = super::FocusPane::Groups;
        app.group_selected = 0;
        super::begin_icon_picker(&mut app, Some(true));
        assert!(matches!(app.modal, Some(super::Modal::IconPicker { .. })));
        let picker_screen = screen(&mut app, 40, 12);
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
        let rendered_updated = screen(&mut app, 80, 20);
        assert!(rendered_updated.contains(standard_icon(19).glyph));

        // Select entry and open detail view; verify Icon header.
        app.focus = super::FocusPane::Entries;
        app.entry_selected = 0;
        app.select();
        let detail_screen = screen(&mut app, 80, 24);
        assert!(detail_screen.contains("Icon: ⚷ Key"));
        assert!(!detail_screen.contains("[custom]"));

        // Simulate custom icon indicator on selected entry header.
        app.entry_icon = Some((19, nkeepass::CustomIconId::from_bytes([0x22; 16])));
        app.detail[1] = "Icon: ✉ Email [custom]".to_owned();
        let custom_detail_screen = screen(&mut app, 80, 24);
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

    #[test]
    fn entry_title_tags_and_otp_input_modals_render_and_manage_lifecycle() {
        use crossterm::event::KeyCode;

        let (_dir, mut app) = app_fixture();

        // Palette item 7: Rename entry title (unmasked, pre-populated, Esc clears pending_entry).
        super::select_palette_action(&mut app, 7);
        assert!(app.input_mode);
        assert!(!app.edit_mode);
        assert!(app.pending_entry.is_some());
        assert_eq!(app.input.as_str(), "Example");
        let rename_screen = screen(&mut app, 80, 24);
        assert!(rename_screen.contains("Rename entry title"));
        assert!(rename_screen.contains("Example"));

        super::handle_input_mode_key(&mut app, KeyCode::Esc);
        assert!(!app.input_mode);
        assert!(app.pending_entry.is_none());
        assert!(app.input.is_empty());

        // Rename via key events: clear pre-populated "Example", type "MailBox", Enter.
        super::select_palette_action(&mut app, 7);
        for _ in 0.."Example".len() {
            super::handle_input_mode_key(&mut app, KeyCode::Backspace);
        }
        for ch in "MailBox".chars() {
            super::handle_input_mode_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_input_mode_key(&mut app, KeyCode::Enter);
        assert!(!app.input_mode);
        assert!(app.pending_entry.is_none());
        assert!(app.dirty);
        assert_eq!(app.hits[0].title(), "MailBox");

        // Palette item 8: Edit entry tags via key events.
        super::select_palette_action(&mut app, 8);
        assert!(app.input_mode);
        assert!(!app.edit_mode);
        assert!(app.pending_entry.is_some());
        for ch in "ops, prod".chars() {
            super::handle_input_mode_key(&mut app, KeyCode::Char(ch));
        }
        let tags_screen = screen(&mut app, 80, 24);
        assert!(tags_screen.contains("Edit tags"));
        assert!(tags_screen.contains("ops, prod"));
        super::handle_input_mode_key(&mut app, KeyCode::Enter);
        assert!(!app.input_mode);
        assert!(app.pending_entry.is_none());
        assert_eq!(app.hits[0].tags(), ["ops", "prod"]);

        // Palette item 9: Set/update OTP URI (masked with '•', retains draft & pending_entry on invalid URI).
        super::select_palette_action(&mut app, 9);
        assert!(app.input_mode);
        assert!(app.edit_mode);
        assert!(app.pending_entry.is_some());
        for ch in "bad-otp".chars() {
            super::handle_input_mode_key(&mut app, KeyCode::Char(ch));
        }
        let masked_screen = screen(&mut app, 80, 24);
        assert!(masked_screen.contains("Set/update OTP URI"));
        assert!(masked_screen.contains(&"•".repeat("bad-otp".len())));
        assert!(!masked_screen.contains("bad-otp"));

        super::handle_input_mode_key(&mut app, KeyCode::Enter);
        assert!(app.input_mode);
        assert!(app.edit_mode);
        assert!(app.pending_entry.is_some());
        assert!(app.status.contains("draft retained"));

        // Replace with valid TOTP URI and submit.
        for _ in 0.."bad-otp".len() {
            super::handle_input_mode_key(&mut app, KeyCode::Backspace);
        }
        let uri = "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30";
        for ch in uri.chars() {
            super::handle_input_mode_key(&mut app, KeyCode::Char(ch));
        }
        let masked_valid = screen(&mut app, 80, 24);
        assert!(!masked_valid.contains("GEZDGNBVGY3TQOJQ"));
        assert!(masked_valid.contains(&"•".repeat(64)));

        super::handle_input_mode_key(&mut app, KeyCode::Enter);
        assert!(!app.input_mode);
        assert!(!app.edit_mode);
        assert!(app.pending_entry.is_none());
        assert!(app.input.is_empty());

        let entry_ref = app.hits[0].reference();
        let view = app.service.selected_entry(&entry_ref).unwrap();
        assert!(view.has_otp());

        // Also verify IconPicker 40x12 filtering footer fits without clipping.
        super::begin_icon_picker(&mut app, Some(false));
        super::handle_modal_key(&mut app, KeyCode::Char('/'));
        let picker_40x12 = screen(&mut app, 40, 12);
        assert!(picker_40x12.contains("Type filter · Enter · Esc"));
    }

    #[test]
    fn mouse_click_and_wheel_scroll_work_across_panes_and_modals() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let (_dir, mut app) = app_fixture();
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Work").unwrap();
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Personal").unwrap();
        let work_ref = app.service.resolve_group(app.session, "Root/Work").unwrap();
        app.service
            .create_entry_in_group(&work_ref, "WorkSecret")
            .unwrap();
        let root_after = app.service.root_group(app.session).unwrap();
        app.service
            .create_entry_in_group(&root_after, "SecondEntry")
            .unwrap();
        app.reset_tree_after_mutation();
        app.refresh();

        // Render at 100x24 so Groups, Entries, and Detail areas are recorded.
        let rendered = screen(&mut app, 100, 24);
        assert!(rendered.contains("Work"));
        assert!(rendered.contains("Personal"));
        assert!(rendered.contains("SecondEntry"));
        assert!(app.groups_area.width > 0);
        assert!(app.entries_area.width > 0);
        assert!(app.detail_area.width > 0);

        // Left-click second entry row in entries_area: switches focus to Entries, selects it, loads detail.
        app.focus = super::FocusPane::Groups;
        let entries_x = app.entries_area.x;
        let entries_y = app.entries_area.y;
        let groups_x = app.groups_area.x;
        let groups_y = app.groups_area.y;
        let second_entry_y = entries_y + 2;
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: entries_x + 2,
                row: second_entry_y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert_eq!(app.focus, super::FocusPane::Entries);
        assert_eq!(app.entry_selected, 1);
        assert!(
            app.detail
                .first()
                .is_some_and(|line| line.contains("SecondEntry"))
        );

        // Mouse scroll up over entries_area selects previous entry.
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: entries_x + 2,
                row: entries_y + 1,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert_eq!(app.entry_selected, 0);

        // Left-click first group row ("Work") in groups_area: first click selects, second enters!
        let work_row_y = groups_y + 1;
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: groups_x + 2,
                row: work_row_y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert_eq!(app.focus, super::FocusPane::Groups);
        assert_eq!(app.group_selected, 0);
        assert!(app.tree_stack.is_empty());

        // Second click on already-selected "Work" navigates into it.
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: groups_x + 2,
                row: work_row_y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert_eq!(app.tree_stack.len(), 1);
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "WorkSecret");
        let work_screen = screen(&mut app, 100, 24);
        assert!(work_screen.contains("/Work"));
        assert!(work_screen.contains(".. (parent)"));
        let work_groups_x = app.groups_area.x;
        let work_groups_y = app.groups_area.y;

        // Clicking ".." parent row navigates back up to root.
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: work_groups_x + 2,
                row: work_groups_y + 1,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert!(app.tree_stack.is_empty());

        // Mouse scroll wheel over an open modal scrolls smoothly.
        app.modal = Some(super::Modal::Help { scroll: 0 });
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 10,
                row: 5,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert!(matches!(app.modal, Some(super::Modal::Help { scroll: 1 })));
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: 10,
                row: 5,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert!(matches!(app.modal, Some(super::Modal::Help { scroll: 0 })));
        app.modal = None;

        // Passive MouseEventKind::Moved must NOT reset last_activity.
        let stale_activity = std::time::Instant::now() - std::time::Duration::from_secs(120);
        app.last_activity = stale_activity;
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Moved,
                column: 5,
                row: 5,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert_eq!(app.last_activity, stale_activity);

        // Scrolling entries_area while an entry is open clears app.entry and syncs preview.
        app.focus = super::FocusPane::Entries;
        app.entry_selected = 0;
        app.select();
        assert!(app.entry.is_some());
        assert_eq!(app.focus, super::FocusPane::Detail);
        let _ = screen(&mut app, 100, 24);
        let entries_x = app.entries_area.x;
        let entries_y = app.entries_area.y;
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: entries_x + 2,
                row: entries_y + 1,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
        );
        assert!(app.entry.is_none());
        assert_eq!(app.focus, super::FocusPane::Entries);
        assert_eq!(app.entry_selected, 1);
        assert!(
            app.detail
                .first()
                .is_some_and(|line| line.contains("SecondEntry"))
        );
    }

    #[test]
    fn compact_entry_overlay_clears_hidden_hit_rects_and_routes_mouse_to_fields() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        for (width, height) in [(60, 16), (40, 12)] {
            let (_dir, mut app) = app_fixture();
            let root = app.service.root_group(app.session).unwrap();
            app.service.add_group(&root, "Work").unwrap();
            let root = app.service.root_group(app.session).unwrap();
            app.service
                .create_entry_in_group(&root, "SecondEntry")
                .unwrap();
            app.reset_tree_after_mutation();
            app.refresh();

            app.focus = super::FocusPane::Entries;
            app.entry_selected = 0;
            app.select();
            assert!(app.entry.is_some());
            assert_eq!(app.selected_field, 0);

            let _ = screen(&mut app, width, height);
            assert!(app.compact_detail);
            assert_eq!(app.groups_area, super::Rect::default());
            assert_eq!(app.entries_area, super::Rect::default());
            assert!(app.compact_fields_area.height >= 2);

            // Clicking on the left side (where hidden groups/entries used to live) hits compact detail fields, never hidden lists.
            let click_x = app.compact_fields_area.x + 1;
            let click_y = app.compact_fields_area.y + 1;
            super::handle_mouse_event(
                &mut app,
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: click_x,
                    row: click_y,
                    modifiers: crossterm::event::KeyModifiers::NONE,
                },
            );
            assert_eq!(app.selected_field, 1);
            assert_eq!(app.entry_selected, 0);
            assert_eq!(app.group_selected, 0);
            assert!(app.entry.is_some());

            // Scrolling on the left side of detail_area moves selected_field cleanly.
            super::handle_mouse_event(
                &mut app,
                MouseEvent {
                    kind: MouseEventKind::ScrollDown,
                    column: click_x,
                    row: click_y,
                    modifiers: crossterm::event::KeyModifiers::NONE,
                },
            );
            assert_eq!(app.selected_field, 2);
            assert_eq!(app.entry_selected, 0);
            assert!(app.entry.is_some());
        }
    }

    #[test]
    fn creating_entry_inside_nested_subgroup_stays_in_subgroup_and_auto_selects() {
        let (_dir, mut app) = app_fixture();
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Work").unwrap();
        let work_ref = app.service.resolve_group(app.session, "Root/Work").unwrap();
        app.service.add_group(&work_ref, "Infra").unwrap();
        app.reset_tree_after_mutation();
        app.refresh();

        // Navigate into Work -> Infra.
        app.focus = super::FocusPane::Groups;
        app.enter_group(0);
        app.enter_group(0);
        assert_eq!(app.tree_stack.len(), 2);
        assert_eq!(app.display_group_path(), "/Work/Infra");

        // Create a new entry inside /Work/Infra via the real input flow ('e' -> type -> Enter).
        super::begin_add(&mut app, super::Action::AddEntry);
        for ch in "ProdDb".chars() {
            super::handle_input_mode_key(&mut app, crossterm::event::KeyCode::Char(ch));
        }
        super::handle_input_mode_key(&mut app, crossterm::event::KeyCode::Enter);
        assert!(!app.input_mode);
        assert!(app.dirty);
        assert_eq!(app.tree_stack.len(), 2);
        assert_eq!(app.display_group_path(), "/Work/Infra");
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "ProdDb");
        assert_eq!(app.entry_selected, 0);
        assert_eq!(app.focus, super::FocusPane::Entries);
        assert!(
            app.detail
                .first()
                .is_some_and(|line| line == "Title: ProdDb")
        );
        assert!(app.status.contains("Entry added in memory"));

        let wide = screen(&mut app, 100, 24);
        assert!(wide.contains("ProdDb"));
        assert!(wide.contains("/Work/Infra"));
        assert!(wide.contains("[UNSAVED · Ctrl+S]"));

        // Creating an entry while a `/` search filter is active clears the filter and rebuilds ancestors.
        app.query.push_str("nonexistent-filter");
        app.refresh();
        assert!(app.hits.is_empty());
        super::begin_add(&mut app, super::Action::AddEntry);
        for ch in "StagingDb".chars() {
            super::handle_input_mode_key(&mut app, crossterm::event::KeyCode::Char(ch));
        }
        super::handle_input_mode_key(&mut app, crossterm::event::KeyCode::Enter);
        assert!(app.query.is_empty());
        assert_eq!(app.tree_stack.len(), 2);
        assert_eq!(app.display_group_path(), "/Work/Infra");
        assert!(app.hits.iter().any(|hit| hit.title() == "StagingDb"));
        assert_eq!(app.hits[app.entry_selected].title(), "StagingDb");
    }

    #[test]
    fn ctrl_s_saves_vault_and_shows_filename_and_release_events_are_ignored() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("work.kdbx");
        app.vault_name = "work.kdbx".to_owned();
        app.refresh();

        // Save initial state to work.kdbx first via `Ctrl+S`.
        app.dirty = true;
        let dirty_screen = screen(&mut app, 80, 20);
        assert!(dirty_screen.contains("[UNSAVED · Ctrl+S]"));
        assert!(dirty_screen.contains("work.kdbx"));

        // `KeyEventKind::Release` for Ctrl+S or 'j' must be ignored cleanly.
        let release_save = KeyEvent::new_with_kind(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
            KeyEventKind::Release,
        );
        super::handle_key_event(&mut app, release_save, &vault_path);
        assert!(app.dirty);

        // `KeyEventKind::Repeat` for non-navigation keys must be ignored; allowed for arrows.
        let repeat_quit =
            KeyEvent::new_with_kind(KeyCode::Char('q'), KeyModifiers::NONE, KeyEventKind::Repeat);
        let outcome = super::handle_key_event(&mut app, repeat_quit, &vault_path);
        assert_eq!(outcome, super::KeyOutcome::Continue);
        assert!(super::should_handle_key_event(
            KeyEventKind::Repeat,
            KeyCode::Down
        ));
        assert!(!super::should_handle_key_event(
            KeyEventKind::Release,
            KeyCode::Down
        ));

        // `KeyEventKind::Press` for `Ctrl+S` saves and shows `"Saved to work.kdbx"`.
        let press_save = KeyEvent::new_with_kind(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        super::handle_key_event(&mut app, press_save, &vault_path);
        assert!(!app.dirty);
        assert!(app.status.contains("Saved to work.kdbx"));
        assert!(vault_path.exists());
    }

    #[allow(clippy::unwrap_used, reason = "disposable test fixture")]
    #[test]
    fn move_entry_modal_and_reorder_entry_up_down_work_at_40x12_and_wide() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Work").unwrap();
        let root = app.service.root_group(app.session).unwrap();
        app.service.create_entry_in_group(&root, "Beta").unwrap();
        app.reset_tree_after_mutation();
        app.refresh();
        assert_eq!(app.hits.len(), 2);
        assert_eq!(app.hits[0].title(), "Example");
        assert_eq!(app.hits[1].title(), "Beta");

        // Reorder entry down with Alt+Down and up with 'K'.
        app.focus = super::FocusPane::Entries;
        app.entry_selected = 0;
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Down, KeyModifiers::ALT),
            &vault_path,
        );
        assert!(app.dirty);
        assert_eq!(app.entry_selected, 1);
        assert_eq!(app.hits[0].title(), "Beta");
        assert_eq!(app.hits[1].title(), "Example");
        assert!(app.status.contains("Moved entry down"));

        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('K'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert_eq!(app.entry_selected, 0);
        assert_eq!(app.hits[0].title(), "Example");
        assert!(app.status.contains("Moved entry up"));

        // Reordering while search filter is active is refused cleanly.
        app.query.push_str("Example");
        app.refresh();
        super::select_palette_action(&mut app, 11);
        assert!(app.status.contains("search filter"));
        app.query.clear();
        app.refresh();

        // Reordering while paginated or with withheld rows is refused cleanly.
        app.tree_page_index = 1;
        super::select_palette_action(&mut app, 11);
        assert!(app.status.contains("paginated"));
        app.tree_page_index = 0;
        app.tree_withheld = 1;
        super::select_palette_action(&mut app, 11);
        assert!(app.status.contains("withheld"));
        app.tree_withheld = 0;

        // Open MoveEntry modal via 'm', verify Esc cancels, then move "Example" into "Work".
        app.dirty = false;
        app.entry_selected = 0;
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
            &vault_path,
        );
        assert!(matches!(app.modal, Some(super::Modal::MoveEntry { .. })));
        let wide = screen(&mut app, 80, 24);
        assert!(wide.contains("Move entry to group"));
        assert!(wide.contains("Work"));
        let narrow = screen(&mut app, 40, 12);
        assert!(narrow.contains("Move entry"));

        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());
        assert!(!app.dirty);

        // Open via palette index 10 ("Move entry to group"), navigate to Work (index 1), Enter.
        super::select_palette_action(&mut app, 10);
        super::handle_modal_key(&mut app, KeyCode::Char('j'));
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.modal.is_none());
        assert!(app.dirty);
        assert!(app.status.contains("Moved entry to"));
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "Beta");

        // Enter Work and verify "Example" arrived.
        app.enter_group(0);
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "Example");
    }

    #[allow(clippy::unwrap_used, reason = "disposable test fixture")]
    #[test]
    fn clone_entry_duplicates_in_group_and_auto_selects_clone() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");
        app.focus = super::FocusPane::Entries;
        app.entry_selected = 0;

        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('C'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert!(app.dirty);
        assert_eq!(app.hits.len(), 2);
        assert_eq!(app.entry_selected, 1);
        assert_eq!(app.hits[1].title(), "Example (Copy)");
        assert!(app.status.contains("Cloned entry"));

        // Ctrl+D also clones and keeps incrementing copy suffix.
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
            &vault_path,
        );
        assert_eq!(app.hits.len(), 3);
        assert_eq!(app.entry_selected, 2);
        assert_eq!(app.hits[2].title(), "Example (Copy) (Copy)");
    }

    #[allow(
        clippy::unwrap_used,
        clippy::too_many_lines,
        reason = "disposable test fixture"
    )]
    #[test]
    fn recycle_restore_and_empty_recycle_bin_require_confirm_for_permanent_purge() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use nkeepass::service::{DatabaseSettings, DatabaseSettingsUpdate};

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");
        let root = app.service.root_group(app.session).unwrap();
        app.service.create_entry_in_group(&root, "Temp").unwrap();
        app.reset_tree_after_mutation();
        app.refresh();
        assert_eq!(app.hits.len(), 2);

        // When Recycle Bin is disabled by default, 'R' requires explicit YES confirmation!
        app.entry_selected = 1;
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert!(matches!(
            app.modal,
            Some(super::Modal::ConfirmDelete {
                kind: super::DeleteKind::PermanentEntry,
                ..
            })
        ));
        let perm_40x12 = screen(&mut app, 40, 12);
        assert!(perm_40x12.contains("Type YES to confirm."));
        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());

        // When session/service errors (e.g. stale session), recycle_selected_entry fails closed.
        let mut other_service = nkeepass::VaultService::default();
        let mut other_creds =
            neotales_keepass::KdbxCredentials::password("disposable-tui-fixture").unwrap();
        let stale_session = other_service
            .open(&vault_path, &mut other_creds, &nkeepass::KDBX_LIMITS)
            .unwrap();
        let saved_session = app.session;
        app.session = stale_session;
        super::recycle_selected_entry(&mut app);
        assert!(app.modal.is_none());
        assert!(!app.dirty);
        assert_eq!(app.hits.len(), 2);
        app.session = saved_session;

        // Enable Recycle Bin in database settings.
        let DatabaseSettings {
            name,
            description,
            default_username,
            history_max_items,
            history_max_size,
            outer_cipher,
            compression,
            kdf,
            ..
        } = app.service.database_settings(app.session).unwrap();
        app.service
            .update_database_settings(
                app.session,
                DatabaseSettingsUpdate {
                    name,
                    description,
                    default_username,
                    recycle_bin_enabled: true,
                    history_max_items,
                    history_max_size,
                    outer_cipher,
                    compression,
                    kdf,
                },
            )
            .unwrap();
        app.re_resolve_current_tree();
        app.refresh();

        // Recycle "Temp" via shortcut 'R'.
        app.entry_selected = 1;
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert!(app.modal.is_none());
        assert!(app.dirty);
        assert!(app.status.contains("Moved to Recycle Bin"));
        assert_eq!(app.hits.len(), 1);
        assert!(app.groups.iter().any(|group| group.label == "Recycle Bin"));

        // Enter Recycle Bin and verify Restore entry restores "Temp" to Root.
        let bin_idx = app
            .groups
            .iter()
            .position(|group| group.label == "Recycle Bin")
            .unwrap();
        app.enter_group(bin_idx);
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "Temp");

        // Attempting 'R' while already inside Recycle Bin requires explicit YES confirmation!
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert!(matches!(
            app.modal,
            Some(super::Modal::ConfirmDelete {
                kind: super::DeleteKind::PermanentEntry,
                ..
            })
        ));
        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());
        assert_eq!(app.hits.len(), 1);

        // Palette 15: Restore entry from Recycle Bin.
        super::select_palette_action(&mut app, 15);
        assert!(app.status.contains("Restored entry"));
        assert!(app.hits.is_empty());

        // Navigate back to Root, recycle "Temp" again, then Empty Recycle Bin with confirmation.
        app.navigate_up();
        assert_eq!(app.hits.len(), 2);
        app.entry_selected = 1;
        super::select_palette_action(&mut app, 14);
        assert_eq!(app.hits.len(), 1);

        // Palette 16: Empty Recycle Bin -> must require YES confirmation!
        super::select_palette_action(&mut app, 16);
        assert!(matches!(
            app.modal,
            Some(super::Modal::ConfirmDelete {
                kind: super::DeleteKind::EmptyRecycleBin,
                ..
            })
        ));
        let confirm_40x12 = screen(&mut app, 40, 12);
        assert!(confirm_40x12.contains("Confirm deletion"));
        assert!(confirm_40x12.contains("Type YES to confirm."));
        for ch in "YES".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.modal.is_none());
        assert!(app.status.contains("Emptied Recycle Bin (1 removed)"));

        // Re-verify Recycle Bin is empty.
        let bin_idx = app
            .groups
            .iter()
            .position(|group| group.label == "Recycle Bin")
            .unwrap();
        app.enter_group(bin_idx);
        assert!(app.hits.is_empty());

        // Verify PermanentEntry confirmation ('YES') permanently deletes via remove_entry.
        app.navigate_up();
        assert_eq!(app.hits.len(), 1);
        app.entry_selected = 0;
        super::select_palette_action(&mut app, 14);
        let bin_idx = app
            .groups
            .iter()
            .position(|group| group.label == "Recycle Bin")
            .unwrap();
        app.enter_group(bin_idx);
        assert_eq!(app.hits.len(), 1);
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT),
            &vault_path,
        );
        for ch in "YES".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.modal.is_none());
        assert!(app.status.contains("Entry permanently deleted"));
        assert!(app.hits.is_empty());
    }

    #[allow(clippy::unwrap_used, reason = "disposable test fixture")]
    #[test]
    fn hotp_totp_display_generation_and_otp_config_modal_mask_and_zeroize_secret() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        assert!(
            super::validate_otp_uri(
                "otpauth://totp/Issuer:user?secret=MZXW6===&issuer=Issuer&digits=6&period=30"
            )
            .is_ok()
        );
        assert!(
            super::validate_otp_uri(
                "otpauth://hotp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&algorithm=SHA256&digits=8"
            )
            .is_ok()
        );
        assert!(
            super::validate_otp_uri(
                "otpauth://totp/Steam:user?secret=JBSWY3DPEHPK3PXP&digits=5&encoder=steam"
            )
            .is_ok()
        );
        assert!(
            super::validate_otp_uri(
                "otpauth://totp/mail?secret=JBSW Y3DP EHPK 3PXP&encoder=default&image=https://example.invalid/icon.png"
            )
            .is_ok()
        );
        assert!(
            super::validate_otp_uri("otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP&encoder=standard")
                .is_ok()
        );
        assert!(super::validate_otp_uri("otpauth://totp?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(
            super::validate_otp_uri("otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP&algorithm=sha256")
                .is_err()
        );
        assert!(
            super::validate_otp_uri(
                "otpauth://totp/Steam:user?secret=JBSWY3DPEHPK3PXP&digits=5&encoder=STEAM"
            )
            .is_err()
        );
        assert!(
            super::validate_otp_uri(
                "otpauth://hotp/mail?secret=JBSWY3DPEHPK3PXP&counter=0&encoder=steam"
            )
            .is_err()
        );
        assert!(super::validate_otp_uri("otpauth://totp/mail?secret=A=======").is_err());
        assert!(super::validate_otp_uri("otpauth://totp/mail?secret=A").is_err());
        assert!(super::validate_otp_uri("otpauth://hotp/mail?secret=JBSWY3DPEHPK3PXP").is_err());

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");

        // Open OtpConfig modal via palette 18, enter a secret with Ctrl+C ignored and Backspace pop, verify masking & Esc zeroization.
        super::select_palette_action(&mut app, 18);
        assert!(matches!(app.modal, Some(super::Modal::OtpConfig(_))));
        // Navigate to Secret row (index 7), edit, type secret + extra char, Ctrl+C ignored, Backspace pops.
        for _ in 0..7 {
            super::handle_modal_key(&mut app, KeyCode::Down);
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for ch in secret.chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        super::handle_modal_key(&mut app, KeyCode::Char('Z'));
        super::handle_modal_key(&mut app, KeyCode::Backspace);
        assert!(matches!(
            &app.modal,
            Some(super::Modal::OtpConfig(draft)) if draft.secret_b32.as_str() == secret
        ));
        super::handle_modal_key(&mut app, KeyCode::Enter);

        let wide_otp = screen(&mut app, 80, 24);
        assert!(!wide_otp.contains("GEZDGNBVGY3TQOJQ"));
        assert!(wide_otp.contains(&"•".repeat(secret.len())));
        let narrow_otp = screen(&mut app, 40, 12);
        assert!(!narrow_otp.contains("GEZDGNBVGY3TQOJQ"));
        assert!(narrow_otp.contains("Configure OTP"));

        // Esc cancels and leaves vault clean.
        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());
        assert!(!app.dirty);

        // Configure HOTP via OtpConfig modal and apply!
        super::select_palette_action(&mut app, 18);
        // Row 0: toggle Kind -> HOTP.
        super::handle_modal_key(&mut app, KeyCode::Char(' '));
        // Move to Secret row (index 7), edit, enter RFC 4226 test secret, apply with Ctrl+S.
        for _ in 0..7 {
            super::handle_modal_key(&mut app, KeyCode::Down);
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        for ch in secret.chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        super::handle_modal_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
        assert!(app.modal.is_none());
        assert!(app.dirty);
        assert!(app.status.contains("OTP configured"));

        // Verify detail pane shows HOTP (6d, counter 0).
        app.select();
        let detail_screen = screen(&mut app, 100, 24);
        assert!(detail_screen.contains("OTP: HOTP (6d, counter 0)"));

        // Trigger OTP reveal ('t' -> confirm YES) and verify RFC 4226 HOTP code (755224 at counter 0).
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
            &vault_path,
        );
        assert!(app.input_mode);
        for ch in "YES".chars() {
            super::handle_input_mode_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_input_mode_key(&mut app, KeyCode::Enter);
        assert_eq!(app.reveal.as_deref().map(String::as_str), Some("755224"));
        assert!(app.status.contains("HOTP generated (counter incremented)"));

        // Hide reveal with Esc and verify counter incremented to 1 in detail pane.
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &vault_path,
        );
        assert!(app.reveal.is_none());
        let after_detail = screen(&mut app, 100, 24);
        assert!(after_detail.contains("OTP: HOTP (6d, counter 1)"));

        // Lock clears reveal & modal cleanly.
        app.lock_vault();
        assert!(app.locked);
        assert!(app.reveal.is_none());
        assert!(app.modal.is_none());
    }

    #[allow(clippy::unwrap_used, reason = "disposable test fixture")]
    #[test]
    fn path_bar_tab_completion_dropdown_and_navigation_work_at_40x12_and_wide() {
        use crossterm::event::{
            KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
        };

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");
        let root = app.service.root_group(app.session).unwrap();
        app.service.add_group(&root, "Work").unwrap();
        let work_ref = app.service.resolve_group(app.session, "Root/Work").unwrap();
        app.service.add_group(&work_ref, "Prod").unwrap();
        let work_ref = app.service.resolve_group(app.session, "Root/Work").unwrap();
        app.service
            .create_entry_in_group(&work_ref, "WorkMail")
            .unwrap();
        let prod_ref = app
            .service
            .resolve_group(app.session, "Root/Work/Prod")
            .unwrap();
        app.service
            .create_entry_in_group(&prod_ref, "ProdDb")
            .unwrap();
        app.reset_tree_after_mutation();
        app.refresh();

        // Render once so header_area is recorded, then click header to open PathBar.
        let _ = screen(&mut app, 80, 24);
        let hx = app.header_area.x + 2;
        let hy = app.header_area.y;
        super::handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: hx,
                row: hy,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(matches!(app.modal, Some(super::Modal::PathBar(_))));
        super::handle_modal_key(&mut app, KeyCode::Esc);
        assert!(app.modal.is_none());

        // Open via Ctrl+K, clear "/", type "Work" -> Tab shows 3-item dropdown (Work, Work/Prod, Work/WorkMail).
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
            &vault_path,
        );
        super::handle_modal_key(&mut app, KeyCode::Backspace);
        for ch in "Work".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Tab);
        let wide_pb = screen(&mut app, 80, 24);
        assert!(wide_pb.contains("[group]"));
        assert!(wide_pb.contains("[entry]"));
        assert!(wide_pb.contains("Root/Work/Prod"));
        let narrow_pb = screen(&mut app, 40, 12);
        assert!(narrow_pb.contains("Go to path"));

        // Cycle down to Root/Work/Prod and press Enter to jump to group /Work/Prod.
        super::handle_modal_key(&mut app, KeyCode::Down);
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.modal.is_none());
        assert_eq!(app.display_group_path(), "/Work/Prod");
        assert_eq!(app.hits.len(), 1);
        assert_eq!(app.hits[0].title(), "ProdDb");

        // Open PathBar via ':', type "/Work/WorkM", Tab autocompletes 1-match immediately, Enter opens entry!
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE),
            &vault_path,
        );
        // Replace prefilled "/Work/Prod" with "/Work/WorkM".
        for _ in 0.."/Work/Prod".len() {
            super::handle_modal_key(&mut app, KeyCode::Backspace);
        }
        for ch in "/Work/WorkM".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Tab);
        assert!(matches!(
            &app.modal,
            Some(super::Modal::PathBar(state))
                if !state.dropdown_open && state.buffer == "/Work/WorkMail"
        ));
        super::handle_modal_key(&mut app, KeyCode::Enter);
        assert!(app.modal.is_none());
        assert_eq!(app.display_group_path(), "/Work");
        assert!(app.entry.is_some());
        assert!(
            app.detail
                .first()
                .is_some_and(|line| line == "Title: WorkMail")
        );
    }

    #[allow(clippy::unwrap_used, reason = "disposable test fixture")]
    #[test]
    fn db_settings_modal_edits_validates_preserves_draft_and_applies_at_40x12() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use nkeepass::service::{DatabaseSettings, VaultCipher, VaultCompression, VaultKdfSummary};

        let (dir, mut app) = app_fixture();
        let vault_path = dir.path().join("fixture.kdbx");

        // Open DbSettings via uppercase 'S'.
        super::handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT),
            &vault_path,
        );
        assert!(matches!(app.modal, Some(super::Modal::DbSettings(_))));
        let narrow = screen(&mut app, 40, 12);
        assert!(narrow.contains("Database Settings"));

        // Edit Database Name (row 0) -> "VaultX".
        super::handle_modal_key(&mut app, KeyCode::Enter);
        for ch in "VaultX".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);

        // Move to Recycle Bin (row 3) and toggle.
        for _ in 0..3 {
            super::handle_modal_key(&mut app, KeyCode::Down);
        }
        super::handle_modal_key(&mut app, KeyCode::Char(' '));

        // Move to Cipher (row 6) -> ChaCha20, Compression (row 7) -> None, KDF (row 8) -> Argon2id.
        for _ in 0..3 {
            super::handle_modal_key(&mut app, KeyCode::Down);
        }
        super::handle_modal_key(&mut app, KeyCode::Right);
        super::handle_modal_key(&mut app, KeyCode::Down);
        super::handle_modal_key(&mut app, KeyCode::Right);
        super::handle_modal_key(&mut app, KeyCode::Down);
        // Cycle KDF until Argon2id is selected.
        while !matches!(
            &app.modal,
            Some(super::Modal::DbSettings(draft)) if draft.kdf_kind == super::DbKdfKind::Argon2id
        ) {
            super::handle_modal_key(&mut app, KeyCode::Right);
        }

        // Move to Argon2 Memory (row 9), set invalid small memory "4" (< 8 * lanes), attempt Ctrl+S!
        super::handle_modal_key(&mut app, KeyCode::Down);
        super::handle_modal_key(&mut app, KeyCode::Enter);
        for _ in 0..10 {
            super::handle_modal_key(&mut app, KeyCode::Backspace);
        }
        super::handle_modal_key(&mut app, KeyCode::Char('4'));
        super::handle_modal_key(&mut app, KeyCode::Enter);
        super::handle_modal_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
        // Must preserve modal + edits + show concise <=38-char validation error without marking dirty!
        assert!(!app.dirty);
        assert!(matches!(
            &app.modal,
            Some(super::Modal::DbSettings(draft))
                if draft.error_msg.as_deref() == Some("Argon2 Memory must be >= 8 * Lanes")
                    && draft.db_name == "VaultX"
        ));

        // Unapplied DbSettings modal blocks pending_decision SaveSucceeded instead of discarding draft.
        app.pending_decision = Some(super::PendingDecision::Exit);
        let effect = app.resolve_pending_decision(super::DecisionInput::SaveSucceeded, &vault_path);
        assert_eq!(effect, super::DecisionEffect::None);
        assert!(app.status.contains("Finish or cancel the pending edit"));
        app.pending_decision = None;

        // Fix Argon2 Memory to "64", apply via Ctrl+S!
        super::handle_modal_key(&mut app, KeyCode::Enter);
        super::handle_modal_key(&mut app, KeyCode::Backspace);
        for ch in "64".chars() {
            super::handle_modal_key(&mut app, KeyCode::Char(ch));
        }
        super::handle_modal_key(&mut app, KeyCode::Enter);
        super::handle_modal_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        );
        assert!(app.modal.is_none());
        assert!(app.dirty);
        assert!(app.status.contains("Database settings updated"));

        let DatabaseSettings {
            name,
            recycle_bin_enabled,
            outer_cipher,
            compression,
            kdf,
            ..
        } = app.service.database_settings(app.session).unwrap();
        assert_eq!(name, "VaultX");
        assert!(recycle_bin_enabled);
        assert_eq!(outer_cipher, VaultCipher::ChaCha20);
        assert_eq!(compression, VaultCompression::GZip);
        assert!(matches!(
            kdf,
            VaultKdfSummary::Argon2id { memory_kib: 64, .. }
        ));
    }

    #[test]
    fn help_modal_documents_new_power_shortcuts() {
        let (_dir, mut app) = app_fixture();
        app.modal = Some(super::Modal::Help { scroll: 0 });
        let help_text: String = super::help_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            "Ctrl+K",
            "S / Ctrl+O",
            "Move selected entry",
            "Alt+Up/Dn",
            "Clone / duplicate",
            "Recycle selected entry",
            "Empty Recycle Bin",
        ] {
            assert!(help_text.contains(needle), "missing {needle} in help");
        }
        let help_40x12 = screen(&mut app, 40, 12);
        assert!(help_40x12.contains("nkp Help"));
    }
}
