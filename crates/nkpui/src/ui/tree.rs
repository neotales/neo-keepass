//! Collapsible `TreeView` group sidebar, group context menus, and inline subgroup creation.

use rune::{El, Key, KeyEvent, ScrollSpec, Tx, col, el, row, text};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, ControlSize, Kit, MenuEntry, MenuItem, TextInput,
    context_menu,
};

use crate::controller::{VisibleTreeGroup, current_unix_seconds};
use crate::icons::render_keepass_icon;

use super::{
    ActiveContextMenu, AppState, ConfirmDialog, ContextMenuTarget, DragDropTarget, IconPickerState,
    IconPickerTarget, error_status_text,
};

fn submit_new_group(state: &mut AppState) {
    let name = state.new_group_edit.text.clone();
    let res = if let Some((parent_ref, parent_path)) = state.new_group_target.clone() {
        state
            .controller
            .create_subgroup_in(&parent_ref, &parent_path, &name)
    } else {
        state.controller.create_subgroup(&name)
    };
    match res {
        Ok(()) => {
            state.new_group_edit.replace_text("");
            state.new_group_error = None;
            state.show_new_group_form = false;
            state.new_group_target = None;
            state.clear_transient_overlays();
            state.wipe_editor_widgets();
            state.sync_path_bar_from_controller();
        }
        Err(err) => {
            state.new_group_error = Some(err.clone());
            state.controller.set_browser_error(err);
        }
    }
}

fn new_group_form_el(k: &Kit, state: &AppState) -> El {
    let name_input = TextInput::new(&state.new_group_edit)
        .label("New subgroup name")
        .placeholder("Subgroup name")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.new_group_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            s.new_group_error = None;
        })
        .on_submit(|s: &mut AppState, tx| {
            s.note_activity(tx);
            submit_new_group(s);
        })
        .build(k)
        .key("new-group-name-input");

    let create_btn = Button::new("Add")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            submit_new_group(s);
        })
        .build(k)
        .key("new-group-submit-btn");

    let mut form = col()
        .key("new-group-form")
        .w_full()
        .gap(6.0)
        .child(name_input);
    if let Some(err) = &state.new_group_error {
        form = form.child(error_status_text(k, "new-group-error", err));
    }
    form.child(row().w_full().justify_end().child(create_btn))
}

fn can_mutate_tree(s: &AppState) -> bool {
    s.controller.is_unlocked() && !s.controller.saving && !s.has_open_modal()
}

fn group_context_menu_entries(state: &AppState, node: &VisibleTreeGroup) -> Vec<MenuEntry> {
    let saving = state.controller.saving;
    let group_ref = node.reference.clone();
    let group_path = node.path.clone();
    let group_label = node.label.clone();
    let icon_id = node.icon_id;
    let custom_icon_id = node.custom_icon_id;

    let mut entries = Vec::new();
    let g_new_entry_path = group_path.clone();
    entries.push(MenuEntry::item(
        MenuItem::new("New Entry").disabled(saving).on_select_tx(
            move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_tree(s) {
                    return;
                }
                s.note_activity(tx);
                s.clear_transient_overlays();
                s.controller
                    .select_group_by_path(&g_new_entry_path, current_unix_seconds());
                s.create_new_entry();
            },
        ),
    ));

    let g_sub_ref = group_ref.clone();
    let g_sub_path = group_path.clone();
    entries.push(MenuEntry::item(
        MenuItem::new("New Subgroup").disabled(saving).on_select_tx(
            move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_tree(s) {
                    return;
                }
                s.note_activity(tx);
                s.clear_transient_overlays();
                s.new_group_target = Some((g_sub_ref.clone(), g_sub_path.clone()));
                s.show_new_group_form = true;
                s.new_group_error = None;
            },
        ),
    ));

    let g_ren_ref = group_ref.clone();
    let g_ren_label = group_label.clone();
    entries.push(MenuEntry::item(
        MenuItem::new("Rename Group…")
            .disabled(saving)
            .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_tree(s) {
                    return;
                }
                s.note_activity(tx);
                s.open_rename_group_modal(g_ren_ref.clone(), g_ren_label.clone(), tx);
            }),
    ));

    let g_icon_ref = group_ref.clone();
    entries.push(MenuEntry::item(
        MenuItem::new("Change Icon…").disabled(saving).on_select_tx(
            move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_tree(s) {
                    return;
                }
                s.note_activity(tx);
                s.clear_transient_overlays();
                s.icon_search_edit.replace_text("");
                s.icon_picker = Some(IconPickerState {
                    target: IconPickerTarget::Group(g_icon_ref.clone()),
                    selected_id: icon_id,
                    selected_custom_id: custom_icon_id,
                });
            },
        ),
    ));

    append_group_danger_menu_entries(&mut entries, node, saving);
    entries
}

fn append_group_danger_menu_entries(
    entries: &mut Vec<MenuEntry>,
    node: &VisibleTreeGroup,
    saving: bool,
) {
    let group_ref = node.reference.clone();
    let group_label = node.label.clone();

    if node.is_recycle_bin {
        entries.push(MenuEntry::Separator);
        entries.push(MenuEntry::item(
            MenuItem::new("Empty Recycle Bin")
                .danger(true)
                .disabled(saving)
                .on_select_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_tree(s) {
                        return;
                    }
                    s.note_activity(tx);
                    s.clear_transient_overlays();
                    s.pending_confirm = Some(ConfirmDialog::EmptyRecycleBin);
                }),
        ));
    }

    if !node.is_root {
        entries.push(MenuEntry::Separator);
        entries.push(MenuEntry::item(
            MenuItem::new("Delete Group")
                .danger(true)
                .disabled(saving)
                .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_tree(s) {
                        return;
                    }
                    s.note_activity(tx);
                    s.clear_transient_overlays();
                    s.pending_confirm = Some(ConfirmDialog::DeleteGroup {
                        group_ref: group_ref.clone(),
                        label: group_label.clone(),
                    });
                }),
        ));
    }
}

fn tree_chevron_el(k: &Kit, idx: usize, node: &VisibleTreeGroup) -> El {
    if !node.has_children || node.is_root {
        return el().size(24.0, 24.0).a11y_hidden();
    }
    let glyph = if node.expanded { "▾" } else { "▸" };
    let path_for_toggle = node.path.clone();
    row()
        .key(format!("tree-chevron-{idx}"))
        .role("button")
        .label(if node.expanded {
            format!("Collapse {}", node.label)
        } else {
            format!("Expand {}", node.label)
        })
        .size(24.0, 24.0)
        .center()
        .radius(k.radius.sm)
        .hover(k.c.hover)
        .press(k.c.pressed)
        .focusable(true)
        .press_on_return()
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            s.controller.toggle_group_expanded(&path_for_toggle);
        })
        .child(text(glyph).font(k.ty.small_medium).color(k.c.text_muted))
}

fn tree_group_row_content(
    k: &Kit,
    state: &AppState,
    idx: usize,
    node: &VisibleTreeGroup,
    is_active: bool,
) -> El {
    let custom_img = state.custom_icon_for(node.custom_icon_id);
    let icon_el = render_keepass_icon(
        k,
        node.icon_id,
        custom_img,
        15.0,
        format!("tree-group-icon-{idx}"),
    );

    let mut content = row()
        .grow(1.0)
        .min_w(0.0)
        .shrink()
        .gap(5.0)
        .center_y()
        .child(tree_chevron_el(k, idx, node))
        .child(icon_el)
        .child(
            text(node.label.clone())
                .grow(1.0)
                .min_w(0.0)
                .truncate()
                .font(if is_active {
                    k.ty.ui_medium
                } else {
                    k.ty.ui_compact
                })
                .color(if is_active {
                    k.c.text_strong
                } else {
                    k.c.text_base
                }),
        );

    if node.is_recycle_bin {
        content = content.child(
            Badge::new("Bin")
                .variant(BadgeVariant::Neutral)
                .build(k)
                .key(format!("tree-group-bin-{idx}")),
        );
    }
    content.child(
        text(format!("{}", node.entry_count))
            .key(format!("tree-group-count-{idx}"))
            .font(k.ty.text_xsmall)
            .color(k.c.text_faint),
    )
}

#[allow(clippy::cast_precision_loss, reason = "tree depth is bounded <= 32")]
fn tree_group_row(
    k: &Kit,
    state: &AppState,
    idx: usize,
    node: &VisibleTreeGroup,
    overlays: &mut Vec<El>,
) -> El {
    let is_active = state.controller.current_group_path == node.path
        && state.controller.search_query.trim().is_empty()
        && !state.controller.favorites_only;
    let is_drop_target = state
        .drag_state
        .as_ref()
        .and_then(|d| d.target.as_ref())
        .is_some_and(|t| matches!(t, DragDropTarget::Group(target_idx) if *target_idx == idx));
    let indent_px = (node.depth as f32) * 12.0;
    let content = tree_group_row_content(k, state, idx, node, is_active);

    let path_click = node.path.clone();
    let ctx_ref = node.reference.clone();
    let ctx_path = node.path.clone();
    let ctx_label = node.label.clone();
    let ctx_icon = node.icon_id;
    let ctx_root = node.is_root;
    let ctx_bin = node.is_recycle_bin;

    let mut row_el = row()
        .key(format!("tree-group-row-{idx}"))
        .role("treeitem")
        .label(format!("{}, {} entries", node.label, node.entry_count))
        .w_full()
        .min_h(28.0)
        .pl(6.0 + indent_px)
        .pr(6.0)
        .py(3.0)
        .center_y()
        .radius(k.radius.md)
        .fill(if is_active {
            k.c.layer_03
        } else {
            k.c.layer_01
        })
        .border(
            if is_drop_target { 2.0 } else { 1.0 },
            if is_drop_target {
                k.c.border_focus
            } else if is_active {
                k.c.border_base
            } else {
                k.c.layer_01
            },
        )
        .focusable(true)
        .press_on_return()
        .hover(k.c.hover)
        .press(k.c.pressed)
        .child(content);

    if !state.controller.saving {
        row_el = row_el
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                s.clear_transient_overlays();
                s.controller
                    .select_group_by_path(&path_click, current_unix_seconds());
                s.search_edit.replace_text("");
                s.wipe_editor_widgets();
                s.sync_path_bar_from_controller();
            })
            .on_secondary_press(move |s: &mut AppState, point, tx: &mut Tx| {
                s.note_activity(tx);
                s.drag_state = None;
                s.context_menu = Some(ActiveContextMenu {
                    point,
                    target: ContextMenuTarget::Group {
                        group_ref: ctx_ref.clone(),
                        path: ctx_path.clone(),
                        label: ctx_label.clone(),
                        icon_id: ctx_icon,
                        is_root: ctx_root,
                        is_recycle_bin: ctx_bin,
                    },
                    move_submenu_open: false,
                });
            });
    }

    let menu_point = state.context_menu.as_ref().and_then(|menu| {
        if let ContextMenuTarget::Group { group_ref, .. } = &menu.target
            && *group_ref == node.reference
        {
            Some(menu.point)
        } else {
            None
        }
    });

    if let Some(point) = menu_point {
        let mut menu = context_menu(format!("group-ctx-{idx}"), row_el, Some(point))
            .label(format!("Actions for {}", node.label))
            .on_close(|s: &mut AppState| s.context_menu = None);
        for entry in group_context_menu_entries(state, node) {
            menu = match entry {
                MenuEntry::Item(item) => menu.item(*item),
                MenuEntry::Separator => menu.separator(),
                MenuEntry::Label(label) => menu.group_label(label),
            };
        }
        menu.build(k, overlays)
    } else {
        row_el
    }
}

fn select_tree_row(s: &mut AppState, visible: &[VisibleTreeGroup], target_idx: usize, tx: &mut Tx) {
    let Some(node) = visible.get(target_idx) else {
        return;
    };
    s.clear_transient_overlays();
    s.controller
        .select_group_by_path(&node.path, current_unix_seconds());
    s.search_edit.replace_text("");
    s.wipe_editor_widgets();
    s.sync_path_bar_from_controller();
    tx.focus(format!("tree-group-row-{target_idx}"), true);
}

fn handle_tree_key(s: &mut AppState, ev: &KeyEvent, tx: &mut Tx) -> bool {
    if !can_mutate_tree(s)
        || s.context_menu.is_some()
        || ev.mods.ctrl
        || ev.mods.cmd
        || ev.mods.alt
        || ev.mods.shift
    {
        return false;
    }
    let visible = s.controller.visible_tree_groups();
    if visible.is_empty() {
        return false;
    }
    let cur_idx = visible
        .iter()
        .position(|g| g.path == s.controller.current_group_path)
        .unwrap_or(0);
    match ev.key {
        Key::Down => {
            if cur_idx + 1 < visible.len() {
                s.note_activity(tx);
                select_tree_row(s, &visible, cur_idx + 1, tx);
            }
            true
        }
        Key::Up => {
            if cur_idx > 0 {
                s.note_activity(tx);
                select_tree_row(s, &visible, cur_idx - 1, tx);
            }
            true
        }
        Key::Right => {
            let cur = &visible[cur_idx];
            if cur.has_children && !cur.expanded {
                s.note_activity(tx);
                s.controller.toggle_group_expanded(&cur.path);
            } else if cur.has_children && cur.expanded && cur_idx + 1 < visible.len() {
                s.note_activity(tx);
                select_tree_row(s, &visible, cur_idx + 1, tx);
            }
            true
        }
        Key::Left => {
            let cur = &visible[cur_idx];
            if cur.has_children && cur.expanded && !cur.is_root {
                s.note_activity(tx);
                s.controller.toggle_group_expanded(&cur.path);
            } else if cur.depth > 0
                && let Some(parent_idx) = visible[..cur_idx]
                    .iter()
                    .rposition(|g| g.depth + 1 == cur.depth)
            {
                s.note_activity(tx);
                select_tree_row(s, &visible, parent_idx, tx);
            }
            true
        }
        _ => false,
    }
}

fn group_tree_list(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let mut col_groups = col()
        .key("group-tree-scroll")
        .role("tree")
        .label("Vault groups")
        .instant_changes()
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(2.0)
        .on_key(handle_tree_key);

    let visible = state.controller.visible_tree_groups();
    for (idx, node) in visible.iter().enumerate() {
        col_groups = col_groups.child(tree_group_row(k, state, idx, node, overlays));
    }
    col_groups
}

fn sidebar_header_controls(k: &Kit, state: &AppState) -> El {
    let (cur_group_icon_id, cur_group_custom_id) = state.controller.current_group_icon();
    let cur_group_label = state
        .controller
        .breadcrumbs
        .last()
        .map_or("Root", |(label, _)| label.as_str())
        .to_owned();
    let cur_group_custom = state.custom_icon_for(cur_group_custom_id);
    let cur_group_icon_el = render_keepass_icon(
        k,
        cur_group_icon_id,
        cur_group_custom,
        16.0,
        "current-group-icon",
    );
    let icon_btn = Button::new("Change group icon")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Ghost)
        .disabled(state.controller.saving)
        .label_with(move |_font, _ink| row().gap(6.0).center_y().child(cur_group_icon_el))
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            s.icon_search_edit.replace_text("");
            s.icon_picker = Some(IconPickerState {
                target: IconPickerTarget::CurrentGroup,
                selected_id: cur_group_icon_id,
                selected_custom_id: cur_group_custom_id,
            });
        })
        .build(k)
        .key("group-icon-picker-btn")
        .label("Change group icon")
        .help("Change group icon");

    let add_group_toggle = Button::new(if state.show_new_group_form {
        "Close"
    } else {
        "+ Group"
    })
    .control_size(ControlSize::Regular)
    .variant(ButtonVariant::Ghost)
    .disabled(state.controller.saving)
    .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
        s.note_activity(tx);
        s.clear_transient_overlays();
        s.show_new_group_form = !s.show_new_group_form;
        s.new_group_target = None;
        if !s.show_new_group_form {
            s.new_group_edit.replace_text("");
            s.new_group_error = None;
        }
    })
    .build(k)
    .key("sidebar-add-group-toggle");

    let rename_label = cur_group_label.clone();
    let rename_btn = Button::new("Rename")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Ghost)
        .disabled(state.controller.saving)
        .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            if let Some(group_ref) = s.controller.current_group_ref().cloned() {
                s.open_rename_group_modal(group_ref, rename_label.clone(), tx);
            }
        })
        .build(k)
        .key("rename-group-btn");

    col()
        .key("group-sidebar-header")
        .w_full()
        .gap(6.0)
        .child(
            row().w_full().center_y().gap(6.0).child(icon_btn).child(
                text(cur_group_label)
                    .key("group-sidebar-heading")
                    .grow(1.0)
                    .min_w(0.0)
                    .truncate()
                    .font(k.ty.small_medium)
                    .color(k.c.text_base),
            ),
        )
        .child(
            row()
                .key("group-sidebar-actions")
                .w_full()
                .justify_between()
                .center_y()
                .gap(4.0)
                .child(rename_btn)
                .child(add_group_toggle),
        )
}

pub(super) fn group_sidebar(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let mut sidebar = col()
        .key("group-sidebar")
        .w(220.0)
        .h_full()
        .min_h(0.0)
        .padding(10.0)
        .gap(8.0)
        .fill(k.c.layer_01)
        .child(sidebar_header_controls(k, state));

    if state.show_new_group_form {
        sidebar = sidebar.child(new_group_form_el(k, state));
    }

    sidebar = sidebar.child(group_tree_list(k, state, overlays));

    if state.controller.is_current_group_recycle_bin() {
        sidebar = sidebar.child(
            Button::new("Empty Recycle Bin")
                .control_size(ControlSize::Regular)
                .variant(ButtonVariant::Danger)
                .disabled(state.controller.saving)
                .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
                    s.note_activity(tx);
                    s.clear_transient_overlays();
                    s.pending_confirm = Some(ConfirmDialog::EmptyRecycleBin);
                })
                .build(k)
                .key("empty-recycle-bin-btn")
                .w_full(),
        );
    }

    if !state.controller.is_at_root() {
        let current_label = state
            .controller
            .breadcrumbs
            .last()
            .map_or_else(String::new, |(label, _)| label.clone());
        if let Some(cur_ref) = state.controller.current_group_ref().cloned() {
            sidebar = sidebar.child(
                Button::new("Delete Group")
                    .control_size(ControlSize::Regular)
                    .variant(ButtonVariant::Danger)
                    .disabled(state.controller.saving)
                    .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                        s.note_activity(tx);
                        s.clear_transient_overlays();
                        s.pending_confirm = Some(ConfirmDialog::DeleteGroup {
                            group_ref: cur_ref.clone(),
                            label: current_label.clone(),
                        });
                    })
                    .build(k)
                    .key("delete-group-btn")
                    .w_full(),
            );
        }
    }

    sidebar
}
