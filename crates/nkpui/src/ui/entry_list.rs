//! Entry list pane with wildcard search, reordering, drag-and-drop, and right-click menus.

use nkeepass::{EntryRef, SearchHit};
use rune::{Drag, El, Phase, Pick, Picked, ScrollSpec, Tx, col, row, text};
use rune_kit::{
    Button, ButtonVariant, ControlSize, Kit, MenuEntry, MenuItem, TextInput, context_menu,
};

use crate::controller::current_unix_seconds;
use crate::icons::{STAR_FILLED_ICON, STAR_ICON, render_keepass_icon};

use super::{
    ActiveContextMenu, ActiveDragState, AppState, ConfirmDialog, ContextMenuTarget, DragDropTarget,
    IconPickerState, IconPickerTarget,
};

fn parse_picked_index(picked: &Picked, prefix: &str) -> Option<usize> {
    if let Some(key) = picked.key()
        && let Some(rest) = key.strip_prefix(prefix)
        && let Ok(idx) = rest.parse::<usize>()
    {
        return Some(idx);
    }
    for segment in picked.path().split('/') {
        if let Some(rest) = segment.strip_prefix(prefix)
            && let Ok(idx) = rest.parse::<usize>()
        {
            return Some(idx);
        }
    }
    None
}

fn update_drag_hover_target(_s: &mut AppState, tx: &mut Tx, pt: [f32; 2]) {
    tx.element_at_in_with(
        "group-tree-scroll",
        pt[0],
        pt[1],
        Pick::new().interactive(true),
        move |s: &mut AppState, picked, tx| {
            if let Some(target_group_idx) = picked
                .as_ref()
                .and_then(|p| parse_picked_index(p, "tree-group-row-"))
            {
                if let Some(drag) = s.drag_state.as_mut() {
                    drag.target = Some(DragDropTarget::Group(target_group_idx));
                }
                return;
            }
            if !s.controller.can_reorder_entries() {
                if let Some(drag) = s.drag_state.as_mut() {
                    drag.target = None;
                }
                return;
            }
            tx.element_at_in_with(
                "entry-list",
                pt[0],
                pt[1],
                Pick::new().interactive(true),
                |s: &mut AppState, entry_picked, _| {
                    let slot = entry_picked
                        .as_ref()
                        .and_then(|p| parse_picked_index(p, "entry-row-"))
                        .map(DragDropTarget::EntrySlot);
                    if let Some(drag) = s.drag_state.as_mut() {
                        drag.target = slot;
                    }
                },
            );
        },
    );
}

fn live_entry_index(s: &AppState, target_ref: &EntryRef) -> Option<usize> {
    s.controller
        .entries
        .iter()
        .position(|h| h.reference() == *target_ref)
}

fn can_mutate_ui(s: &AppState) -> bool {
    s.controller.is_unlocked() && !s.controller.saving && !s.has_open_modal()
}

fn finish_entry_drag_drop(_s: &mut AppState, drag_ref: EntryRef, pt: [f32; 2], tx: &mut Tx) {
    let entry_ref_inner = drag_ref.clone();
    tx.element_at_in_with(
        "group-tree-scroll",
        pt[0],
        pt[1],
        Pick::new().interactive(true),
        move |s: &mut AppState, picked, tx| {
            let Some(active_drag) = s.drag_state.clone() else {
                return;
            };
            if !can_mutate_ui(s) || active_drag.entry_ref != drag_ref {
                s.drag_state = None;
                return;
            }
            let group_hit = picked
                .as_ref()
                .and_then(|p| parse_picked_index(p, "tree-group-row-"));
            if let Some(group_idx) = group_hit {
                if let Some(from_idx) = live_entry_index(s, &drag_ref) {
                    commit_drop_to_group(s, from_idx, group_idx);
                }
                s.drag_state = None;
                return;
            }
            let entry_ref_slot = entry_ref_inner.clone();
            tx.element_at_in_with(
                "entry-list",
                pt[0],
                pt[1],
                Pick::new().interactive(true),
                move |s: &mut AppState, entry_picked, _| {
                    let Some(active_drag) = s.drag_state.clone() else {
                        return;
                    };
                    if !can_mutate_ui(s) || active_drag.entry_ref != entry_ref_slot {
                        s.drag_state = None;
                        return;
                    }
                    let Some(from_idx) = live_entry_index(s, &entry_ref_slot) else {
                        s.drag_state = None;
                        return;
                    };
                    if let Some(slot) = entry_picked
                        .as_ref()
                        .and_then(|p| parse_picked_index(p, "entry-row-"))
                    {
                        commit_drop_to_entry_slot(s, from_idx, slot);
                    } else if let Some(DragDropTarget::Group(g_idx)) = active_drag.target {
                        commit_drop_to_group(s, from_idx, g_idx);
                    } else if let Some(DragDropTarget::EntrySlot(slot)) = active_drag.target {
                        commit_drop_to_entry_slot(s, from_idx, slot);
                    }
                    s.drag_state = None;
                },
            );
        },
    );
}

fn commit_drop_to_group(s: &mut AppState, from_idx: usize, target_group_idx: usize) {
    let visible = s.controller.visible_tree_groups();
    let Some(target) = visible.get(target_group_idx) else {
        return;
    };
    let Some(hit) = s.controller.entries.get(from_idx) else {
        return;
    };
    let entry_ref = hit.reference();
    if let Err(err) = s.controller.move_entry_to_group(
        &entry_ref,
        &target.reference,
        &target.label,
        current_unix_seconds(),
    ) {
        s.controller.set_browser_error(err);
    } else {
        s.wipe_editor_widgets();
        s.sync_path_bar_from_controller();
    }
}

fn commit_drop_to_entry_slot(s: &mut AppState, from_idx: usize, slot: usize) {
    if from_idx == slot || !s.controller.can_reorder_entries() {
        return;
    }
    if let Err(err) = s
        .controller
        .reorder_entry_to(from_idx, slot, current_unix_seconds())
    {
        s.controller.set_browser_error(err);
    } else {
        s.wipe_editor_widgets();
        s.sync_path_bar_from_controller();
    }
}

fn handle_entry_drag(s: &mut AppState, idx: usize, d: &mut Drag, tx: &mut Tx) {
    if !can_mutate_ui(s) || s.context_menu.is_some() {
        s.drag_state = None;
        return;
    }
    match d.phase {
        Phase::Down => {
            s.drag_state = None;
        }
        Phase::Move => {
            let moved = d.dx.hypot(d.dy) >= 4.0;
            if !moved && s.drag_state.is_none() {
                return;
            }
            let Some(hit) = s.controller.entries.get(idx) else {
                s.drag_state = None;
                return;
            };
            let pt = d.window_point();
            if s.drag_state.is_none() {
                s.drag_state = Some(ActiveDragState {
                    entry_index: idx,
                    entry_ref: hit.reference(),
                    entry_title: hit.title().to_owned(),
                    window_point: pt,
                    target: None,
                });
            } else if let Some(drag) = s.drag_state.as_mut() {
                drag.window_point = pt;
            }
            s.note_activity(tx);
            update_drag_hover_target(s, tx, pt);
        }
        Phase::Up => {
            if d.cancelled() {
                s.drag_state = None;
                return;
            }
            if let Some(drag_ref) = s.drag_state.as_ref().map(|drag| drag.entry_ref.clone()) {
                let pt = d.window_point();
                finish_entry_drag_drop(s, drag_ref, pt, tx);
            }
        }
    }
}

fn select_entry_by_ref(s: &mut AppState, target_ref: &EntryRef) -> bool {
    let Some(idx) = live_entry_index(s, target_ref) else {
        return false;
    };
    s.controller.select_entry(idx, current_unix_seconds());
    true
}

fn push_entry_copy_menu_items(
    items: &mut Vec<MenuEntry>,
    target_ref: &EntryRef,
    saving: bool,
    has_otp: bool,
    is_pw_revealed: bool,
) {
    let u_ref = target_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new("Copy Username")
            .disabled(saving)
            .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) || !select_entry_by_ref(s, &u_ref) {
                    return;
                }
                s.note_activity(tx);
                match s.controller.standard_field_for_copy("UserName") {
                    Ok(secret) => s.copy_secret(&secret, "UserName", tx),
                    Err(err) => s.controller.set_browser_error(err),
                }
            }),
    ));
    let p_ref = target_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new("Copy Password (30s)")
            .disabled(saving)
            .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) || !select_entry_by_ref(s, &p_ref) {
                    return;
                }
                s.note_activity(tx);
                match s.controller.password_for_copy() {
                    Ok(secret) => s.copy_secret(&secret, "Password", tx),
                    Err(err) => s.controller.set_browser_error(err),
                }
            }),
    ));
    if has_otp {
        let o_ref = target_ref.clone();
        items.push(MenuEntry::item(
            MenuItem::new("Copy TOTP").disabled(saving).on_select_tx(
                move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_ui(s) || !select_entry_by_ref(s, &o_ref) {
                        return;
                    }
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
                },
            ),
        ));
    }
    let r_ref = target_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new(if is_pw_revealed {
            "Hide Password"
        } else {
            "Reveal Password"
        })
        .disabled(saving)
        .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
            s.context_menu = None;
            if !can_mutate_ui(s) {
                return;
            }
            let already_selected = s
                .controller
                .detail
                .as_ref()
                .is_some_and(|d| d.entry_ref == r_ref);
            if !already_selected && !select_entry_by_ref(s, &r_ref) {
                return;
            }
            s.note_activity(tx);
            s.controller.toggle_reveal_password();
        }),
    ));
    items.push(MenuEntry::Separator);
}

fn build_move_submenu_entries(
    entry_ref: &EntryRef,
    entry_title: String,
    idx: usize,
    total_entries: usize,
    can_reorder: bool,
    saving: bool,
) -> Vec<MenuEntry> {
    let move_ref = entry_ref.clone();
    let up_ref = entry_ref.clone();
    let down_ref = entry_ref.clone();
    vec![
        MenuEntry::item(
            MenuItem::new("Move to Group…")
                .disabled(saving)
                .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_ui(s) || !select_entry_by_ref(s, &move_ref) {
                        return;
                    }
                    s.note_activity(tx);
                    s.open_move_entry_modal(move_ref.clone(), entry_title.clone());
                }),
        ),
        MenuEntry::item(
            MenuItem::new("Move Up")
                .shortcut("Alt+Up")
                .disabled(saving || !can_reorder || idx == 0)
                .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_ui(s) || !select_entry_by_ref(s, &up_ref) {
                        return;
                    }
                    s.note_activity(tx);
                    if let Err(err) = s.controller.move_selected_entry_up(current_unix_seconds()) {
                        s.controller.set_browser_error(err);
                    } else {
                        s.wipe_editor_widgets();
                    }
                }),
        ),
        MenuEntry::item(
            MenuItem::new("Move Down")
                .shortcut("Alt+Down")
                .disabled(saving || !can_reorder || idx + 1 >= total_entries)
                .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_ui(s) || !select_entry_by_ref(s, &down_ref) {
                        return;
                    }
                    s.note_activity(tx);
                    if let Err(err) = s
                        .controller
                        .move_selected_entry_down(current_unix_seconds())
                    {
                        s.controller.set_browser_error(err);
                    } else {
                        s.wipe_editor_widgets();
                    }
                }),
        ),
    ]
}

fn push_entry_mutation_menu_items(
    items: &mut Vec<MenuEntry>,
    state: &AppState,
    idx: usize,
    hit: &SearchHit,
    in_recycle_bin: bool,
    move_submenu_open: bool,
) {
    let saving = state.controller.saving;
    let entry_ref = hit.reference();
    let entry_title = hit.title().to_owned();
    let icon_id = hit.icon_id();
    let custom_icon_id = hit.custom_icon_id();
    let can_reorder = state.controller.can_reorder_entries();
    let total_entries = state.controller.entries.len();

    let edit_ref = entry_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new("Edit Entry").disabled(saving).on_select_tx(
            move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) || !select_entry_by_ref(s, &edit_ref) {
                    return;
                }
                s.note_activity(tx);
                s.open_entry_editor();
            },
        ),
    ));
    let move_sub = build_move_submenu_entries(
        &entry_ref,
        entry_title.clone(),
        idx,
        total_entries,
        can_reorder,
        saving,
    );
    items.push(MenuEntry::item(
        MenuItem::new("Move")
            .disabled(saving)
            .submenu(move_sub, move_submenu_open)
            .on_select(|s: &mut AppState| {
                if let Some(menu) = s.context_menu.as_mut() {
                    menu.move_submenu_open = !menu.move_submenu_open;
                }
            }),
    ));
    let clone_ref = entry_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new("Clone Entry")
            .shortcut("Ctrl+D")
            .disabled(saving)
            .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) {
                    return;
                }
                s.note_activity(tx);
                match s.controller.clone_entry(&clone_ref, current_unix_seconds()) {
                    Ok(_) => {
                        s.wipe_editor_widgets();
                        s.sync_path_bar_from_controller();
                    }
                    Err(err) => s.controller.set_browser_error(err),
                }
            }),
    ));
    let icon_ref = entry_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new("Change Icon…").disabled(saving).on_select_tx(
            move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) {
                    return;
                }
                s.note_activity(tx);
                s.icon_search_edit.replace_text("");
                s.icon_picker = Some(IconPickerState {
                    target: IconPickerTarget::Entry(icon_ref.clone()),
                    selected_id: icon_id,
                    selected_custom_id: custom_icon_id,
                });
            },
        ),
    ));
    push_entry_recycle_menu_items(items, state, &entry_ref, entry_title, in_recycle_bin);
}

fn push_entry_recycle_menu_items(
    items: &mut Vec<MenuEntry>,
    state: &AppState,
    entry_ref: &EntryRef,
    entry_title: String,
    in_recycle_bin: bool,
) {
    let saving = state.controller.saving;
    let recycle_enabled = state.controller.recycle_bin_enabled;
    items.push(MenuEntry::Separator);
    if in_recycle_bin {
        let restore_ref = entry_ref.clone();
        items.push(MenuEntry::item(
            MenuItem::new("Restore").disabled(saving).on_select_tx(
                move |s: &mut AppState, tx: &mut Tx| {
                    s.context_menu = None;
                    if !can_mutate_ui(s) {
                        return;
                    }
                    s.note_activity(tx);
                    if let Err(err) = s
                        .controller
                        .restore_entry(&restore_ref, current_unix_seconds())
                    {
                        s.controller.set_browser_error(err);
                    } else {
                        s.wipe_editor_widgets();
                        s.sync_path_bar_from_controller();
                    }
                },
            ),
        ));
    }
    let del_label = if !in_recycle_bin && recycle_enabled {
        "Recycle"
    } else {
        "Delete Permanently"
    };
    let del_ref = entry_ref.clone();
    items.push(MenuEntry::item(
        MenuItem::new(del_label)
            .danger(true)
            .disabled(saving)
            .on_select_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.context_menu = None;
                if !can_mutate_ui(s) || !select_entry_by_ref(s, &del_ref) {
                    return;
                }
                s.note_activity(tx);
                if !in_recycle_bin && recycle_enabled {
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
            }),
    ));
}

fn entry_context_menu_entries(
    state: &AppState,
    idx: usize,
    hit: &SearchHit,
    move_submenu_open: bool,
) -> Vec<MenuEntry> {
    let saving = state.controller.saving;
    let is_selected = state.controller.selected_index == Some(idx);
    let detail = is_selected
        .then_some(state.controller.detail.as_ref())
        .flatten();
    let has_otp = detail.is_some_and(|d| d.otp_meta.is_some() || d.metadata.has_otp());
    let is_pw_revealed = detail.is_some_and(|d| d.revealed_password.is_some());
    let in_recycle_bin = detail.map_or_else(
        || state.controller.is_current_group_recycle_bin(),
        |d| d.is_in_recycle_bin,
    );
    let entry_ref = hit.reference();
    let mut items = Vec::new();
    push_entry_copy_menu_items(&mut items, &entry_ref, saving, has_otp, is_pw_revealed);
    push_entry_mutation_menu_items(
        &mut items,
        state,
        idx,
        hit,
        in_recycle_bin,
        move_submenu_open,
    );
    items
}

fn entry_row_body(
    k: &Kit,
    state: &AppState,
    idx: usize,
    hit: &SearchHit,
    selected: bool,
    is_dragging: bool,
    is_drop_target: bool,
) -> El {
    let custom_img = state.custom_icon_for(hit.custom_icon_id());
    let icon_el = render_keepass_icon(
        k,
        hit.icon_id(),
        custom_img,
        18.0,
        format!("entry-row-icon-{idx}"),
    );
    row()
        .key(format!("entry-row-{idx}"))
        .w_full()
        .min_h(36.0)
        .padding(8.0)
        .gap(8.0)
        .center_y()
        .radius(k.radius.md)
        .fill(if selected { k.c.layer_03 } else { k.c.layer_01 })
        .border(
            if is_drop_target { 2.0 } else { 1.0 },
            if is_drop_target {
                k.c.border_focus
            } else if selected {
                k.c.border_base
            } else {
                k.c.layer_01
            },
        )
        .opacity(if is_dragging { 0.55 } else { 1.0 })
        .child(icon_el)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(hit.title().to_owned())
                        .w_full()
                        .font(k.ty.ui_medium)
                        .color(k.c.text_base)
                        .truncate(),
                )
                .child(
                    text(hit.path().to_owned())
                        .w_full()
                        .font(k.ty.text_xsmall)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        )
}

fn entry_row(k: &Kit, state: &AppState, idx: usize, hit: &SearchHit, overlays: &mut Vec<El>) -> El {
    let selected = state.controller.selected_index == Some(idx);
    let is_dragging = state
        .drag_state
        .as_ref()
        .is_some_and(|d| d.entry_index == idx);
    let is_drop_target = state
        .drag_state
        .as_ref()
        .and_then(|d| d.target.as_ref())
        .is_some_and(|t| matches!(t, DragDropTarget::EntrySlot(slot) if *slot == idx));
    let mut row_el = entry_row_body(k, state, idx, hit, selected, is_dragging, is_drop_target);

    let saving = state.controller.is_saving();
    if !saving {
        let ctx_ref = hit.reference();
        let ctx_in_bin = state.controller.is_current_group_recycle_bin();
        let ctx_has_otp = hit.field_names().iter().any(|n| n == "otp");
        row_el = row_el
            .focusable(true)
            .press_on_return()
            .hover(k.c.hover)
            .press(k.c.pressed)
            .on_press_tx(move |s: &mut AppState, tx: &mut Tx| {
                s.note_activity(tx);
                if s.controller.is_saving() {
                    return;
                }
                s.clear_transient_overlays();
                s.controller.select_entry(idx, current_unix_seconds());
                s.wipe_editor_widgets();
                s.sync_path_bar_from_controller();
            })
            .on_drag(move |s: &mut AppState, d: &mut Drag, tx: &mut Tx| {
                handle_entry_drag(s, idx, d, tx);
            })
            .on_secondary_press(move |s: &mut AppState, point, tx: &mut Tx| {
                s.note_activity(tx);
                s.drag_state = None;
                s.context_menu = Some(ActiveContextMenu {
                    point,
                    target: ContextMenuTarget::Entry {
                        index: idx,
                        entry_ref: ctx_ref.clone(),
                        is_in_recycle_bin: ctx_in_bin,
                        has_otp: ctx_has_otp,
                    },
                    move_submenu_open: false,
                });
            });
    }

    let menu_state = state.context_menu.as_ref().and_then(|menu| {
        if let ContextMenuTarget::Entry { entry_ref, .. } = &menu.target
            && *entry_ref == hit.reference()
        {
            Some((menu.point, menu.move_submenu_open))
        } else {
            None
        }
    });

    if let Some((point, move_submenu_open)) = menu_state {
        let mut menu = context_menu(format!("entry-ctx-{idx}"), row_el, Some(point))
            .label(format!("Actions for {}", hit.title()))
            .on_close(|s: &mut AppState| s.context_menu = None);
        for entry in entry_context_menu_entries(state, idx, hit, move_submenu_open) {
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

fn entry_list_items(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let mut list = col()
        .key("entry-list")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec::default())
        .gap(4.0);

    if state.controller.entries.is_empty() {
        let empty_msg = if state.controller.favorites_only {
            "No favorite entries match"
        } else if state.controller.search_query.trim().is_empty() {
            "No entries in this group"
        } else {
            "No matching entries"
        };
        return list.child(
            text(empty_msg)
                .key("entry-list-empty")
                .w_full()
                .wrap()
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    }

    for (idx, hit) in state.controller.entries.iter().enumerate() {
        list = list.child(entry_row(k, state, idx, hit, overlays));
    }
    list
}

fn entry_list_controls_row(k: &Kit, state: &AppState) -> El {
    let fav_active = state.controller.favorites_only;
    let warn_icon_color = k.c.warning.icon;
    let fav_btn = Button::new("Favorites")
        .control_size(ControlSize::Regular)
        .variant(if fav_active {
            ButtonVariant::Contrast
        } else {
            ButtonVariant::Ghost
        })
        .disabled(state.controller.saving)
        .label_with(move |font, ink| {
            row()
                .gap(4.0)
                .center_y()
                .child(
                    rune::icon(
                        if fav_active {
                            &STAR_FILLED_ICON
                        } else {
                            &STAR_ICON
                        },
                        13.0,
                    )
                    .color(if fav_active { ink } else { warn_icon_color }),
                )
                .child(text("Favorites").font(font).color(ink))
        })
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            let next = !s.controller.favorites_only;
            s.controller
                .set_favorites_only(next, current_unix_seconds());
            s.wipe_editor_widgets();
        })
        .build(k)
        .key("entry-favorites-filter-btn");

    let can_reorder = state.controller.can_reorder_entries();
    let sel_idx = state.controller.selected_index;
    let total = state.controller.entries.len();

    let move_up_btn = Button::new("↑")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Ghost)
        .disabled(!can_reorder || sel_idx.is_none_or(|i| i == 0))
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            if let Err(err) = s.controller.move_selected_entry_up(current_unix_seconds()) {
                s.controller.set_browser_error(err);
            } else {
                s.wipe_editor_widgets();
            }
        })
        .build(k)
        .key("entry-move-up-btn")
        .min_w(24.0)
        .label("Move entry up")
        .help("Move entry up (Alt+Up)");

    let move_down_btn = Button::new("↓")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Ghost)
        .disabled(!can_reorder || sel_idx.is_none_or(|i| i + 1 >= total))
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            if let Err(err) = s
                .controller
                .move_selected_entry_down(current_unix_seconds())
            {
                s.controller.set_browser_error(err);
            } else {
                s.wipe_editor_widgets();
            }
        })
        .build(k)
        .key("entry-move-down-btn")
        .min_w(24.0)
        .label("Move entry down")
        .help("Move entry down (Alt+Down)");

    row()
        .w_full()
        .justify_between()
        .center_y()
        .gap(4.0)
        .child(fav_btn)
        .child(row().gap(4.0).child(move_up_btn).child(move_down_btn))
}

pub(super) fn entry_list_pane(k: &Kit, state: &AppState, overlays: &mut Vec<El>) -> El {
    let new_entry_btn = Button::new("+ New Entry")
        .control_size(ControlSize::Regular)
        .variant(ButtonVariant::Submit)
        .disabled(state.controller.saving)
        .on_press_tx(|s: &mut AppState, tx: &mut Tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            s.create_new_entry();
        })
        .build(k)
        .key("new-entry-btn");

    let search_box = TextInput::new(&state.search_edit)
        .label("Search vault entries")
        .placeholder("Search (* and ? wildcards)")
        .width(None)
        .on_edit(|s: &mut AppState| &mut s.search_edit)
        .on_change(|s: &mut AppState, tx| {
            s.note_activity(tx);
            s.clear_transient_overlays();
            let query = s.search_edit.text.clone();
            s.controller.set_search_query(query, current_unix_seconds());
            s.wipe_editor_widgets();
            s.sync_path_bar_from_controller();
        })
        .build(k)
        .key("entry-search-input");

    col()
        .key("entry-list-pane")
        .w(230.0)
        .h_full()
        .min_h(0.0)
        .padding(10.0)
        .gap(8.0)
        .child(
            row()
                .key("entry-list-header")
                .w_full()
                .justify_between()
                .center_y()
                .child(
                    text("Entries")
                        .key("entry-list-heading")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                )
                .child(new_entry_btn),
        )
        .child(search_box)
        .child(entry_list_controls_row(k, state))
        .child(entry_list_items(k, state, overlays))
}
