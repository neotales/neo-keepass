//! Integration coverage for KDBX entry history preservation/growth and
//! Recycle Bin metadata/group round-tripping through `neotales_keepass` and
//! `VaultService`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test fixture setup and assertions"
)]

use neotales_keepass::{
    Attachment, DeletedObject, Entry, Group, KdbxCredentials, KdbxFile, KdbxKdf, KdbxReadLimits,
    KdbxTimestamp, KdbxUuid, KdbxWriteOptions, KeePassDatabase, ProtectedValue,
};
use nkeepass::service::ImportOptions;
use nkeepass::{KDBX_LIMITS, VaultService};

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
    KdbxCredentials::password("history-recycle-test-password").unwrap()
}

fn save_db(path: &std::path::Path, db: &KeePassDatabase) {
    let mut creds = credentials();
    let mut bytes = Vec::new();
    KdbxFile::save(
        db,
        &mut bytes,
        &mut creds,
        fast_write_options(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn load_db(path: &std::path::Path) -> KeePassDatabase {
    let mut creds = credentials();
    let file = std::fs::File::open(path).unwrap();
    KdbxFile::load(file, &mut creds, &KDBX_LIMITS).unwrap()
}

#[test]
fn entry_history_preserves_snapshots_growth_and_attachments_across_service_saves() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.kdbx");

    let mut db = KeePassDatabase::default();
    db.meta.history_max_items = Some(10);
    db.meta.history_max_size = Some(6 * 1024 * 1024);

    let history_bin_ref = db.binary_pool.add(b"old-key-material".to_vec(), true);

    let mut snap1 = Entry::new("Account");
    snap1.id = KdbxUuid::from_bytes([0x11; 16]);
    snap1.password = ProtectedValue::from_text("pass-v1");
    snap1.times.modified = KdbxTimestamp(1_700_000_001);
    snap1.attachments.push(Attachment {
        name: "recovery-v1.txt".into(),
        reference: history_bin_ref,
    });

    let mut snap2 = Entry::new("Account");
    snap2.id = KdbxUuid::from_bytes([0x12; 16]);
    snap2.password = ProtectedValue::from_text("pass-v2");
    snap2.times.modified = KdbxTimestamp(1_700_000_002);

    let mut current = Entry::new("Account");
    current.id = KdbxUuid::from_bytes([0x13; 16]);
    current.username = "alice".into();
    current.password = ProtectedValue::from_text("pass-v3");
    current.times.modified = KdbxTimestamp(1_700_000_003);
    current.history = vec![snap1, snap2];
    db.add_entry(current);
    save_db(&path, &db);

    // Open through VaultService, mutate fields/title/icon, save, and verify history survives.
    let mut service = VaultService::default();
    let session = service
        .open(&path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();
    let entry_ref = service
        .resolve_entry(session, "Account")
        .unwrap()
        .reference();
    service
        .set_field(&entry_ref, "Password", "pass-v4")
        .unwrap();
    let entry_ref = service
        .resolve_entry(session, "Account")
        .unwrap()
        .reference();
    service.set_entry_icon(&entry_ref, 19).unwrap();
    let entry_ref = service
        .resolve_entry(session, "Account")
        .unwrap()
        .reference();
    service.set_title(&entry_ref, "Account Primary").unwrap();
    service.save(&path, &mut credentials()).unwrap();

    let reopened = load_db(&path);
    assert_eq!(reopened.meta.history_max_items, Some(10));
    assert_eq!(reopened.meta.history_max_size, Some(6 * 1024 * 1024));
    assert_eq!(reopened.root.entries.len(), 1);
    let saved_entry = &reopened.root.entries[0];
    assert_eq!(saved_entry.title, "Account Primary");
    assert_eq!(saved_entry.icon_id, 19);
    assert_eq!(
        saved_entry.password.reveal_bytes().unwrap().as_slice(),
        b"pass-v4"
    );
    assert_eq!(saved_entry.history.len(), 2);
    assert_eq!(
        saved_entry.history[0]
            .password
            .reveal_bytes()
            .unwrap()
            .as_slice(),
        b"pass-v1"
    );
    assert_eq!(
        saved_entry.history[1]
            .password
            .reveal_bytes()
            .unwrap()
            .as_slice(),
        b"pass-v2"
    );
    assert_eq!(saved_entry.history[0].attachments.len(), 1);
    assert_eq!(
        saved_entry.history[0].attachments[0].name,
        "recovery-v1.txt"
    );
    let preserved_bin = reopened
        .binary_pool
        .get(saved_entry.history[0].attachments[0].reference)
        .expect("history attachment must remain in binary pool after save");
    assert_eq!(preserved_bin.data, b"old-key-material");

    // Append a 3rd history snapshot and verify growth + service snapshot accounting.
    let mut grown = reopened;
    let mut snap3 = Entry::new("Account Primary");
    snap3.id = KdbxUuid::from_bytes([0x14; 16]);
    snap3.password = ProtectedValue::from_text("pass-v4");
    snap3.times.modified = KdbxTimestamp(1_700_000_004);
    grown.root.entries[0].history.push(snap3);
    let v5 = ProtectedValue::from_text("pass-v5");
    grown.root.entries[0].password = v5.clone();
    grown.root.entries[0].set_field(neotales_keepass::Field {
        key: "Password".into(),
        value: v5,
        protected: true,
        protect_in_memory: true,
    });
    save_db(&path, &grown);

    let mut service = VaultService::default();
    let session = service
        .open(&path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();
    let snapshot = service.export_snapshot().unwrap();
    let report = service
        .import_snapshot(
            snapshot.bytes(),
            ImportOptions {
                replace: true,
                dry_run: true,
                ..ImportOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.history_entries, 3);
    let refreshed = service
        .resolve_entry(session, "Account Primary")
        .unwrap()
        .reference();
    assert_eq!(
        service.reveal_password(&refreshed).unwrap().as_slice(),
        b"pass-v5"
    );
}

#[test]
fn recycle_bin_metadata_group_and_deleted_objects_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recycle_bin.kdbx");

    let recycle_uuid = KdbxUuid::from_bytes([0x43; 16]);
    let deleted_uuid = KdbxUuid::from_bytes([0x99; 16]);
    let recycle_changed = KdbxTimestamp(1_700_000_500);
    let deleted_at = KdbxTimestamp(1_700_000_600);

    let mut db = KeePassDatabase::default();
    db.meta.recycle_bin_enabled = true;
    db.meta.recycle_bin_uuid = recycle_uuid;
    db.meta.recycle_bin_changed = Some(recycle_changed);
    db.deleted_objects.push(DeletedObject {
        id: deleted_uuid,
        deleted_at,
    });

    let mut recycle_group = Group::new("Recycle Bin");
    recycle_group.id = recycle_uuid;
    recycle_group.icon_id = 43;
    let mut trashed = Entry::new("Old Login");
    trashed.username = "retired".into();
    trashed.password = ProtectedValue::from_text("old-secret");
    recycle_group.add_entry(trashed);
    db.root.add_group(recycle_group);

    let mut active = Entry::new("Active Login");
    active.password = ProtectedValue::from_text("active-secret");
    db.add_entry(active);
    save_db(&path, &db);

    // Open through VaultService, mutate the active entry, and save back to disk.
    let mut service = VaultService::default();
    let session = service
        .open(&path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();

    let root = service.root_group(session).unwrap();
    let tree = service.tree_page(&root, None).unwrap();
    assert_eq!(tree.groups.len(), 1);
    assert_eq!(tree.groups[0].label(), "Recycle Bin");
    assert_eq!(tree.groups[0].icon_id(), 43);

    let active_ref = service
        .resolve_entry(session, "Active Login")
        .unwrap()
        .reference();
    service
        .set_field(&active_ref, "Password", "rotated-secret")
        .unwrap();
    service.save(&path, &mut credentials()).unwrap();

    // Verify Recycle Bin metadata, group icon, trashed entry, and deleted objects round-trip.
    let reopened = load_db(&path);
    assert!(reopened.meta.recycle_bin_enabled);
    assert_eq!(reopened.meta.recycle_bin_uuid, recycle_uuid);
    assert_eq!(reopened.meta.recycle_bin_changed, Some(recycle_changed));
    assert_eq!(
        reopened.deleted_objects,
        vec![DeletedObject {
            id: deleted_uuid,
            deleted_at,
        }]
    );
    assert_eq!(reopened.root.groups.len(), 1);
    let bin = &reopened.root.groups[0];
    assert_eq!(bin.name, "Recycle Bin");
    assert_eq!(bin.id, recycle_uuid);
    assert_eq!(bin.icon_id, 43);
    assert_eq!(bin.entries.len(), 1);
    assert_eq!(bin.entries[0].title, "Old Login");
    assert_eq!(
        bin.entries[0].password.reveal_bytes().unwrap().as_slice(),
        b"old-secret"
    );

    let mut reopened_service = VaultService::default();
    let reopened_session = reopened_service
        .open(&path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();
    let trashed_ref = reopened_service
        .resolve_entry(reopened_session, "Recycle Bin/Old Login")
        .unwrap()
        .reference();
    assert_eq!(
        reopened_service
            .reveal_password(&trashed_ref)
            .unwrap()
            .as_slice(),
        b"old-secret"
    );
}
