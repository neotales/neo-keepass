//! Integration coverage for the `KeePass` 2.x standard icon catalog, default
//! entry/group icons, and `VaultService` icon read/write/custom-icon APIs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test fixture setup and assertions"
)]

use std::collections::HashSet;

use neotales_keepass::{
    CustomIcon, Entry, Group, KdbxCredentials, KdbxFile, KdbxKdf, KdbxReadLimits, KdbxUuid,
    KdbxWriteOptions, KeePassDatabase,
};
use nkeepass::icons::{
    DEFAULT_ENTRY_ICON_ID, DEFAULT_GROUP_ICON_ID, MAX_CUSTOM_ICON_BYTES, MAX_STANDARD_ICON_ID,
    STANDARD_ICON_COUNT, is_valid_standard_icon_id, lookup_standard_icon, standard_icon,
    standard_icons,
};
use nkeepass::{CustomIconId, ServiceError, SessionId, VaultService};
use tempfile::TempDir;
use unicode_width::UnicodeWidthStr;

fn fast_write_options() -> KdbxWriteOptions {
    KdbxWriteOptions {
        kdf: KdbxKdf::Argon2id,
        argon2_memory_kib: 1024,
        argon2_time: 1,
        argon2_lanes: 1,
        ..KdbxWriteOptions::default()
    }
}

fn credentials() -> KdbxCredentials {
    KdbxCredentials::password("icons-test-master-password").unwrap()
}

fn create_and_open_vault() -> (TempDir, std::path::PathBuf, VaultService, SessionId) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut service = VaultService::default();
    service
        .create(&path, &mut credentials(), fast_write_options(), None)
        .unwrap();
    let session = service
        .open(&path, &mut credentials(), &KdbxReadLimits::default())
        .unwrap();
    (dir, path, service, session)
}

fn reopen_vault(path: &std::path::Path) -> (VaultService, SessionId) {
    let mut service = VaultService::default();
    let session = service
        .open(path, &mut credentials(), &KdbxReadLimits::default())
        .unwrap();
    (service, session)
}

fn save_db(path: &std::path::Path, db: &KeePassDatabase) {
    let mut creds = credentials();
    let mut file = Vec::new();
    KdbxFile::save(
        db,
        &mut file,
        &mut creds,
        fast_write_options(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    std::fs::write(path, file).unwrap();
}

fn is_forbidden_bidi_or_format(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061C
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2066..=0x2069
            | 0xFE00..=0xFE0F
            | 0xFEFF
    )
}

fn is_emoji_presentation_bmp(ch: char) -> bool {
    matches!(
        ch as u32,
        0x231A..=0x231B
            | 0x23E9..=0x23EC
            | 0x23F0
            | 0x23F3
            | 0x25FD..=0x25FE
            | 0x2614..=0x2615
            | 0x2648..=0x2653
            | 0x267F
            | 0x2693
            | 0x26A1
            | 0x26AA..=0x26AB
            | 0x26BD..=0x26BE
            | 0x26C4..=0x26C5
            | 0x26CE
            | 0x26D4
            | 0x26EA
            | 0x26F2..=0x26F3
            | 0x26F5
            | 0x26FA
            | 0x26FD
            | 0x2705
            | 0x270A..=0x270B
            | 0x2728
            | 0x274C
            | 0x274E
            | 0x2753..=0x2755
            | 0x2757
            | 0x2795..=0x2797
            | 0x27B0
            | 0x27BF
            | 0x2B1B..=0x2B1C
            | 0x2B50
            | 0x2B55
    )
}

#[test]
fn standard_icon_catalog_is_complete_and_tui_safe() {
    let icons = standard_icons();
    assert_eq!(icons.len(), STANDARD_ICON_COUNT);
    assert_eq!(STANDARD_ICON_COUNT, 69);
    assert_eq!(MAX_STANDARD_ICON_ID, 68);
    assert_eq!(DEFAULT_ENTRY_ICON_ID, 0);
    assert_eq!(DEFAULT_GROUP_ICON_ID, 48);

    let mut seen_names = HashSet::new();
    for (index, icon) in icons.iter().enumerate() {
        let expected_id = u32::try_from(index).unwrap();
        assert_eq!(icon.id, expected_id);
        assert!(!icon.name.is_empty(), "icon {expected_id} has empty name");
        assert!(
            seen_names.insert(icon.name),
            "duplicate icon name: {}",
            icon.name
        );

        let glyph_chars: Vec<char> = icon.glyph.chars().collect();
        assert_eq!(
            glyph_chars.len(),
            1,
            "icon {} ({}) glyph must be 1 char",
            icon.id,
            icon.name
        );
        let ch = glyph_chars[0];
        assert!(
            (ch as u32) <= 0xFFFF,
            "icon {} ({}) glyph must be BMP",
            icon.id,
            icon.name
        );
        assert!(
            !ch.is_control(),
            "icon {} ({}) glyph must not be control",
            icon.id,
            icon.name
        );
        assert!(
            !is_forbidden_bidi_or_format(ch),
            "icon {} ({}) glyph must not be BiDi/format/variation selector",
            icon.id,
            icon.name
        );
        assert!(
            !is_emoji_presentation_bmp(ch),
            "icon {} ({}) glyph must not use Emoji_Presentation",
            icon.id,
            icon.name
        );
        assert_eq!(
            UnicodeWidthStr::width(icon.glyph),
            1,
            "icon {} ({}) glyph {:?} must have display width 1",
            icon.id,
            icon.name,
            icon.glyph
        );

        let ascii_chars: Vec<char> = icon.ascii.chars().collect();
        assert_eq!(
            ascii_chars.len(),
            1,
            "icon {} ({}) ascii must be 1 char",
            icon.id,
            icon.name
        );
        assert!(
            ascii_chars[0].is_ascii_graphic(),
            "icon {} ({}) ascii {:?} must be printable ASCII",
            icon.id,
            icon.name,
            icon.ascii
        );

        assert_eq!(lookup_standard_icon(expected_id), Some(icon));
        assert_eq!(standard_icon(expected_id), icon);
        assert!(is_valid_standard_icon_id(expected_id));
    }

    assert_eq!(lookup_standard_icon(0).unwrap().name, "Key");
    assert_eq!(lookup_standard_icon(48).unwrap().name, "Folder");
    assert_eq!(lookup_standard_icon(68).unwrap().name, "BlackBerry");
    assert_eq!(lookup_standard_icon(69), None);
    assert_eq!(lookup_standard_icon(999), None);
    assert!(!is_valid_standard_icon_id(69));
    assert!(!is_valid_standard_icon_id(u32::MAX));

    assert_eq!(standard_icon(999), &icons[0]);
    assert_eq!(standard_icon(u32::MAX).id, 0);
}

#[test]
fn model_entry_and_group_default_icons() {
    let entry = Entry::new("example");
    assert_eq!(entry.icon_id, DEFAULT_ENTRY_ICON_ID);
    assert_eq!(entry.icon_id, 0);

    let group = Group::new("folder");
    assert_eq!(group.icon_id, DEFAULT_GROUP_ICON_ID);
    assert_eq!(group.icon_id, 48);
}

#[test]
fn projections_expose_default_icons_and_reject_invalid_ids() {
    let (_dir, _path, mut service, session) = create_and_open_vault();

    let root_info = service.root_icon(session).unwrap();
    assert_eq!(root_info.icon_id(), DEFAULT_GROUP_ICON_ID);
    assert_eq!(root_info.custom_icon_id(), None);

    let root = service.root_group(session).unwrap();
    service.add_group(&root, "Work").unwrap();
    let root = service.root_group(session).unwrap();
    let entry_ref = service.create_entry_in_group(&root, "Mail").unwrap();

    // Check default icon_id across SelectedEntry, tree_page, search_page, and list_page.
    let selected = service.selected_entry(&entry_ref).unwrap();
    assert_eq!(selected.icon_id(), DEFAULT_ENTRY_ICON_ID);
    assert_eq!(selected.custom_icon_id(), None);

    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    assert_eq!(tree.groups.len(), 1);
    assert_eq!(tree.groups[0].icon_id(), DEFAULT_GROUP_ICON_ID);
    assert_eq!(tree.groups[0].custom_icon_id(), None);
    assert_eq!(tree.entries.len(), 1);
    assert_eq!(tree.entries[0].icon_id(), DEFAULT_ENTRY_ICON_ID);
    assert_eq!(tree.entries[0].custom_icon_id(), None);

    let search = service.search_page(session, "Mail", None).unwrap();
    assert_eq!(search.hits.len(), 1);
    assert_eq!(search.hits[0].icon_id(), DEFAULT_ENTRY_ICON_ID);
    assert_eq!(search.hits[0].custom_icon_id(), None);

    let listed = service.list_page(session, None, None).unwrap();
    assert_eq!(listed.hits.len(), 1);
    assert_eq!(listed.hits[0].icon_id(), DEFAULT_ENTRY_ICON_ID);
    assert_eq!(listed.hits[0].custom_icon_id(), None);

    // Invalid icon IDs fail with InvalidInput without mutating or invalidating handles.
    assert_eq!(
        service.set_entry_icon(&entry_ref, 69),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        service.set_entry_icon(&entry_ref, u32::MAX),
        Err(ServiceError::InvalidInput)
    );
    let group_ref = tree.groups[0].reference();
    assert_eq!(
        service.set_group_icon(&group_ref, 69),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        service.set_group_icon(&group_ref, u32::MAX),
        Err(ServiceError::InvalidInput)
    );
}

#[test]
fn set_icon_apis_persist_and_enforce_session_and_lock_contracts() {
    let (_dir, path, mut service, session) = create_and_open_vault();

    let root = service.root_group(session).unwrap();
    service.add_group(&root, "Work").unwrap();
    let root = service.root_group(session).unwrap();
    service.create_entry_in_group(&root, "Mail").unwrap();

    // Valid icon IDs succeed and invalidate prior handles.
    for valid_id in [0, 19, 48, 68] {
        let current_entry = service.resolve_entry(session, "Mail").unwrap().reference();
        service.set_entry_icon(&current_entry, valid_id).unwrap();
        assert_eq!(
            service.set_entry_icon(&current_entry, valid_id),
            Err(ServiceError::Stale)
        );
        let refreshed_entry = service.resolve_entry(session, "Mail").unwrap().reference();
        let selected = service.selected_entry(&refreshed_entry).unwrap();
        assert_eq!(selected.icon_id(), valid_id);
        assert_eq!(selected.custom_icon_id(), None);
    }

    // Set entry to 19 (Email), child group to 4 (Marked Directory), and root group to 60 (Home).
    let current_entry = service.resolve_entry(session, "Mail").unwrap().reference();
    service.set_entry_icon(&current_entry, 19).unwrap();

    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    let work_ref = tree.groups[0].reference();
    service.set_group_icon(&work_ref, 4).unwrap();
    assert_eq!(
        service.set_group_icon(&work_ref, 4),
        Err(ServiceError::Stale)
    );

    let root = service.root_group(session).unwrap();
    service.set_group_icon(&root, 60).unwrap();
    assert_eq!(service.set_group_icon(&root, 60), Err(ServiceError::Stale));
    let root_info = service.root_icon(session).unwrap();
    assert_eq!(root_info.icon_id(), 60);
    assert_eq!(root_info.custom_icon_id(), None);

    service.save(&path, &mut credentials()).unwrap();

    let (mut reopened, reopened_session) = reopen_vault(&path);
    let sample_icon_id = CustomIconId::from_bytes([0x11; 16]).unwrap();
    assert_eq!(reopened.root_icon(session), Err(ServiceError::Stale));
    assert_eq!(
        reopened.custom_icon_bytes(session, sample_icon_id),
        Err(ServiceError::Stale)
    );

    let reopened_root_info = reopened.root_icon(reopened_session).unwrap();
    assert_eq!(reopened_root_info.icon_id(), 60);
    assert_eq!(reopened_root_info.custom_icon_id(), None);

    let reopened_entry = reopened
        .resolve_entry(reopened_session, "Mail")
        .unwrap()
        .reference();
    let reopened_selected = reopened.selected_entry(&reopened_entry).unwrap();
    assert_eq!(reopened_selected.icon_id(), 19);
    assert_eq!(reopened_selected.custom_icon_id(), None);

    let reopened_root = reopened.root_group(reopened_session).unwrap();
    let reopened_tree = reopened.tree_page(&reopened_root, None).unwrap();
    assert_eq!(reopened_tree.groups[0].icon_id(), 4);
    assert_eq!(reopened_tree.entries[0].icon_id(), 19);

    let reopened_search = reopened
        .search_page(reopened_session, "Mail", None)
        .unwrap();
    assert_eq!(reopened_search.hits[0].icon_id(), 19);
    let reopened_list = reopened.list_page(reopened_session, None, None).unwrap();
    assert_eq!(reopened_list.hits[0].icon_id(), 19);

    reopened.lock(reopened_session).unwrap();
    assert_eq!(
        reopened.root_icon(reopened_session),
        Err(ServiceError::Locked)
    );
    assert_eq!(
        reopened.custom_icon_bytes(reopened_session, sample_icon_id),
        Err(ServiceError::Locked)
    );
    assert_eq!(
        reopened.set_entry_icon(&reopened_entry, 0),
        Err(ServiceError::Locked)
    );
    assert_eq!(
        reopened.set_group_icon(&reopened_tree.groups[0].reference(), 48),
        Err(ServiceError::Locked)
    );
}

struct CustomIconFixture {
    dir: TempDir,
    path: std::path::PathBuf,
    small_id: CustomIconId,
    exact_limit_id: CustomIconId,
    oversized_id: CustomIconId,
    empty_id: CustomIconId,
    group_custom_id: CustomIconId,
    root_custom_id: CustomIconId,
    duplicate_custom_id: CustomIconId,
    png_bytes: Vec<u8>,
    exact_bytes: Vec<u8>,
}

fn build_custom_icon_fixture() -> CustomIconFixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("custom_icons.kdbx");

    let small_uuid = KdbxUuid::from_bytes([0x11; 16]);
    let exact_limit_uuid = KdbxUuid::from_bytes([0x22; 16]);
    let oversized_uuid = KdbxUuid::from_bytes([0x33; 16]);
    let empty_uuid = KdbxUuid::from_bytes([0x44; 16]);
    let group_custom_uuid = KdbxUuid::from_bytes([0x55; 16]);
    let root_custom_uuid = KdbxUuid::from_bytes([0x66; 16]);
    let duplicate_custom_uuid = KdbxUuid::from_bytes([0x77; 16]);

    let png_bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
    let exact_bytes = vec![0xAB; MAX_CUSTOM_ICON_BYTES];
    let oversized_bytes = vec![0xCD; MAX_CUSTOM_ICON_BYTES + 1];

    let mut db = KeePassDatabase::default();
    db.root.icon_id = 49;
    db.root.custom_icon_id = root_custom_uuid;
    for (uuid, name, data) in [
        (small_uuid, Some("small".to_owned()), png_bytes.clone()),
        (exact_limit_uuid, None, exact_bytes.clone()),
        (oversized_uuid, None, oversized_bytes),
        (empty_uuid, None, Vec::new()),
        (group_custom_uuid, None, png_bytes.clone()),
        (root_custom_uuid, None, png_bytes.clone()),
        (duplicate_custom_uuid, None, png_bytes.clone()),
        (duplicate_custom_uuid, None, vec![1, 2, 3]),
    ] {
        db.meta.custom_icons.push(CustomIcon {
            uuid,
            name,
            last_modification: None,
            data,
        });
    }

    let mut group = Group::new("CustomGroup");
    group.icon_id = 4;
    group.custom_icon_id = group_custom_uuid;
    let mut entry = Entry::new("CustomEntry");
    entry.icon_id = 19;
    entry.custom_icon_id = small_uuid;
    group.add_entry(entry);
    db.root.add_group(group);

    save_db(&path, &db);

    CustomIconFixture {
        dir,
        path,
        small_id: CustomIconId::from_bytes(*small_uuid.as_bytes()).unwrap(),
        exact_limit_id: CustomIconId::from_bytes(*exact_limit_uuid.as_bytes()).unwrap(),
        oversized_id: CustomIconId::from_bytes(*oversized_uuid.as_bytes()).unwrap(),
        empty_id: CustomIconId::from_bytes(*empty_uuid.as_bytes()).unwrap(),
        group_custom_id: CustomIconId::from_bytes(*group_custom_uuid.as_bytes()).unwrap(),
        root_custom_id: CustomIconId::from_bytes(*root_custom_uuid.as_bytes()).unwrap(),
        duplicate_custom_id: CustomIconId::from_bytes(*duplicate_custom_uuid.as_bytes()).unwrap(),
        png_bytes,
        exact_bytes,
    }
}

#[test]
fn custom_icon_lookup_is_bounded_and_cleared_by_set_icon() {
    assert_eq!(CustomIconId::from_bytes([0; 16]), None);

    let fixture = build_custom_icon_fixture();
    let _dir = &fixture.dir;
    let (mut service, session) = reopen_vault(&fixture.path);

    // Root icon exposes custom UUID.
    let root_info = service.root_icon(session).unwrap();
    assert_eq!(root_info.icon_id(), 49);
    assert_eq!(root_info.custom_icon_id(), Some(fixture.root_custom_id));
    assert_eq!(root_info.custom_icon_id().unwrap().as_bytes(), &[0x66; 16]);

    // Bounded custom icon lookup checks + duplicate UUID fail-closed rejection.
    let unknown_id = CustomIconId::from_bytes([0x99; 16]).unwrap();
    assert_eq!(
        service.custom_icon_bytes(session, unknown_id).unwrap(),
        None
    );
    assert_eq!(
        service
            .custom_icon_bytes(session, fixture.empty_id)
            .unwrap(),
        None
    );
    assert_eq!(
        service
            .custom_icon_bytes(session, fixture.oversized_id)
            .unwrap(),
        None
    );
    assert_eq!(
        service
            .custom_icon_bytes(session, fixture.small_id)
            .unwrap(),
        Some(fixture.png_bytes)
    );
    assert_eq!(
        service
            .custom_icon_bytes(session, fixture.exact_limit_id)
            .unwrap(),
        Some(fixture.exact_bytes)
    );
    assert_eq!(
        service.custom_icon_bytes(session, fixture.duplicate_custom_id),
        Err(ServiceError::DuplicateIds)
    );

    // Projections expose custom_icon_id across tree, selected, search, and list.
    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    assert_eq!(tree.groups[0].icon_id(), 4);
    assert_eq!(
        tree.groups[0].custom_icon_id(),
        Some(fixture.group_custom_id)
    );
    let group_ref = tree.groups[0].reference();

    let entry_ref = service
        .resolve_entry(session, "CustomGroup/CustomEntry")
        .unwrap()
        .reference();
    let selected = service.selected_entry(&entry_ref).unwrap();
    assert_eq!(selected.icon_id(), 19);
    assert_eq!(selected.custom_icon_id(), Some(fixture.small_id));

    let search = service.search_page(session, "CustomEntry", None).unwrap();
    assert_eq!(search.hits[0].icon_id(), 19);
    assert_eq!(search.hits[0].custom_icon_id(), Some(fixture.small_id));

    let listed = service.list_page(session, None, None).unwrap();
    assert_eq!(listed.hits[0].icon_id(), 19);
    assert_eq!(listed.hits[0].custom_icon_id(), Some(fixture.small_id));

    // Setting a standard icon clears custom_icon_id on entry, child group, and root group.
    service.set_entry_icon(&entry_ref, 0).unwrap();
    let refreshed_entry = service
        .resolve_entry(session, "CustomGroup/CustomEntry")
        .unwrap()
        .reference();
    let refreshed_selected = service.selected_entry(&refreshed_entry).unwrap();
    assert_eq!(refreshed_selected.icon_id(), 0);
    assert_eq!(refreshed_selected.custom_icon_id(), None);

    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    let refreshed_group_ref = tree.groups[0].reference();
    assert!(refreshed_group_ref != group_ref);
    service.set_group_icon(&refreshed_group_ref, 48).unwrap();

    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    assert_eq!(tree.groups[0].icon_id(), 48);
    assert_eq!(tree.groups[0].custom_icon_id(), None);

    let root = service.root_group(session).unwrap();
    service.set_group_icon(&root, 48).unwrap();
    let refreshed_root = service.root_icon(session).unwrap();
    assert_eq!(refreshed_root.icon_id(), 48);
    assert_eq!(refreshed_root.custom_icon_id(), None);
}

#[test]
fn icon_mutations_invalidate_tree_cursors_and_reject_duplicate_object_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("paginated.kdbx");

    let mut db = KeePassDatabase::default();
    for index in 0..130 {
        db.root.add_entry(Entry::new(format!("entry-{index:03}")));
    }
    save_db(&path, &db);

    let (mut service, session) = reopen_vault(&path);
    let root = service.root_group(session).unwrap();
    let first_page = service.tree_page(&root, None).unwrap();
    let cursor = first_page
        .next_cursor
        .expect("130 entries should require a TreeCursor");
    let first_entry = first_page.entries[0].reference();

    service.set_entry_icon(&first_entry, 19).unwrap();
    let root = service.root_group(session).unwrap();
    assert_eq!(
        service.tree_page(&root, Some(cursor)).err(),
        Some(ServiceError::Stale)
    );

    let second_page = service.tree_page(&root, None).unwrap();
    let cursor_before_group_icon = second_page
        .next_cursor
        .expect("130 entries should require a TreeCursor");
    service.set_group_icon(&root, 49).unwrap();
    let root = service.root_group(session).unwrap();
    assert_eq!(
        service
            .tree_page(&root, Some(cursor_before_group_icon))
            .err(),
        Some(ServiceError::Stale)
    );

    // Duplicate object UUIDs fail closed on set_entry_icon and set_group_icon.
    let dup_path = dir.path().join("dup_ids.kdbx");
    let shared_id = KdbxUuid::from_bytes([0xA5; 16]);
    let mut dup_db = KeePassDatabase::default();
    let mut e1 = Entry::new("first");
    e1.id = shared_id;
    let mut e2 = Entry::new("second");
    e2.id = shared_id;
    dup_db.root.add_entry(e1);
    dup_db.root.add_entry(e2);
    save_db(&dup_path, &dup_db);

    let (mut dup_service, dup_session) = reopen_vault(&dup_path);
    let dup_root = dup_service.root_group(dup_session).unwrap();
    let dup_tree = dup_service.tree_page(&dup_root, None).unwrap();
    let dup_entry_ref = dup_tree.entries[0].reference();
    assert_eq!(
        dup_service.set_entry_icon(&dup_entry_ref, 19),
        Err(ServiceError::DuplicateIds)
    );
    assert_eq!(
        dup_service.set_group_icon(&dup_root, 49),
        Err(ServiceError::DuplicateIds)
    );
}
