//! Comprehensive integration tests for desktop-facing `VaultService` APIs,
//! KDBX 4 option preservation, HOTP/Steam/KeePass 2.x OTP, Recycle Bin,
//! wildcard search, and binary-search path completion.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test fixture setup and assertions"
)]

use std::path::{Path, PathBuf};

use neotales_keepass::{
    Attachment, AutoType, AutoTypeAssociation, CustomIcon, Entry, Field, Group, KdbxCompression,
    KdbxCredentials, KdbxFile, KdbxKdf, KdbxOuterCipher, KdbxUuid, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use nkeepass::{
    CustomIconId, DatabaseSettingsUpdate, KDBX_LIMITS, OtpConfig, ServiceError,
    ServiceOtpAlgorithm, ServiceOtpKind, SessionId, VaultCipher, VaultCompression, VaultKdfSummary,
    VaultService,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn fast_options() -> KdbxWriteOptions {
    KdbxWriteOptions {
        cipher: KdbxOuterCipher::Aes,
        compression: KdbxCompression::GZip,
        kdf: KdbxKdf::Argon2id,
        argon2_memory_kib: 64,
        argon2_time: 1,
        argon2_lanes: 1,
        ..KdbxWriteOptions::default()
    }
}

fn credentials() -> KdbxCredentials {
    KdbxCredentials::password("desktop-service-apis-password").unwrap()
}

fn create_and_open() -> (TempDir, PathBuf, VaultService, SessionId) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut service = VaultService::default();
    service
        .create(&path, &mut credentials(), fast_options(), None)
        .unwrap();
    let session = service
        .open(&path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();
    (dir, path, service, session)
}

fn reopen(path: &Path) -> (VaultService, SessionId) {
    let mut service = VaultService::default();
    let session = service
        .open(path, &mut credentials(), &KDBX_LIMITS)
        .unwrap();
    (service, session)
}

fn save_raw(path: &Path, db: &KeePassDatabase, opts: KdbxWriteOptions) {
    let mut file = std::fs::File::create(path).unwrap();
    KdbxFile::save(db, &mut file, &mut credentials(), opts, &KDBX_LIMITS).unwrap();
}

fn load_raw(path: &Path) -> KeePassDatabase {
    let file = std::fs::File::open(path).unwrap();
    KdbxFile::load(file, &mut credentials(), &KDBX_LIMITS).unwrap()
}

#[test]
fn create_recommended_and_save_preserve_kdbx4_cipher_compression_and_kdf() {
    let dir = tempfile::tempdir().unwrap();
    let rec_path = dir.path().join("recommended.kdbx");
    let service = VaultService::default();
    service
        .create_recommended(&rec_path, &mut credentials(), None)
        .unwrap();
    let raw_rec = load_raw(&rec_path);
    let rec_opts = raw_rec.write_options.unwrap();
    assert_eq!(rec_opts.kdf, KdbxKdf::Argon2id);
    assert_eq!(rec_opts.compression, KdbxCompression::GZip);

    // Custom ChaCha20 + Argon2d + GZip vault saved via VaultService::save preserves its header params.
    let custom_path = dir.path().join("chacha-argon2d.kdbx");
    let mut db = KeePassDatabase::default();
    db.add_entry(Entry::new("alpha"));
    let custom_opts = KdbxWriteOptions {
        cipher: KdbxOuterCipher::ChaCha20,
        compression: KdbxCompression::GZip,
        kdf: KdbxKdf::Argon2d,
        argon2_memory_kib: 128,
        argon2_time: 2,
        argon2_lanes: 2,
        ..KdbxWriteOptions::default()
    };
    save_raw(&custom_path, &db, custom_opts);

    let (mut svc, session) = reopen(&custom_path);
    let settings = svc.database_settings(session).unwrap();
    assert_eq!(settings.outer_cipher, VaultCipher::ChaCha20);
    assert_eq!(settings.compression, VaultCompression::GZip);
    assert_eq!(
        settings.kdf,
        VaultKdfSummary::Argon2d {
            memory_kib: 128,
            iterations: 2,
            lanes: 2,
        }
    );
    let root = svc.root_group(session).unwrap();
    svc.create_entry_in_group(&root, "beta").unwrap();
    svc.save(&custom_path, &mut credentials()).unwrap();

    let reloaded = load_raw(&custom_path);
    let preserved = reloaded.write_options.unwrap();
    assert_eq!(preserved.cipher, KdbxOuterCipher::ChaCha20);
    assert_eq!(preserved.compression, KdbxCompression::GZip);
    assert_eq!(preserved.kdf, KdbxKdf::Argon2d);
    assert_eq!(preserved.argon2_memory_kib, 128);
    assert_eq!(preserved.argon2_time, 2);
    assert_eq!(preserved.argon2_lanes, 2);
}

#[test]
fn group_tree_projects_hierarchy_recycle_bin_and_enforces_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.kdbx");
    let icon_uuid = KdbxUuid::from_bytes([0x12; 16]);
    let bin_uuid = KdbxUuid::from_bytes([0x43; 16]);

    let mut db = KeePassDatabase::default();
    db.meta.custom_icons.push(CustomIcon {
        uuid: icon_uuid,
        data: vec![0x89, 0x50, 0x4e, 0x47],
        name: Some("work-icon".into()),
        last_modification: None,
    });
    db.meta.recycle_bin_enabled = true;
    db.meta.recycle_bin_uuid = bin_uuid;

    let mut work = Group::new("Work");
    work.icon_id = 48;
    work.custom_icon_id = icon_uuid;
    work.add_entry(Entry::new("mail"));
    let mut sub = Group::new("Cloud");
    sub.add_entry(Entry::new("aws"));
    sub.add_entry(Entry::new("gcp"));
    work.add_group(sub);

    let mut bin = Group::new("Recycle Bin");
    bin.id = bin_uuid;
    bin.icon_id = 43;

    db.add_group(work);
    db.add_group(bin);
    save_raw(&path, &db, fast_options());

    let (mut svc, session) = reopen(&path);
    let (_other_svc, foreign_session) = reopen(&path);

    let tree = svc.group_tree(session).unwrap();
    assert_eq!(tree.label, "Root");
    assert_eq!(tree.path, "Root");
    assert!(!tree.is_recycle_bin);
    assert_eq!(tree.children.len(), 2);

    let work_node = &tree.children[0];
    assert_eq!(work_node.label, "Work");
    assert_eq!(work_node.path, "Root/Work");
    assert_eq!(work_node.icon_id, 48);
    assert_eq!(
        work_node.custom_icon_id,
        CustomIconId::from_bytes([0x12; 16])
    );
    assert_eq!(work_node.entry_count, 1);
    assert!(!work_node.is_recycle_bin);
    assert_eq!(work_node.children.len(), 1);
    assert_eq!(work_node.children[0].path, "Root/Work/Cloud");
    assert_eq!(work_node.children[0].entry_count, 2);

    let bin_node = &tree.children[1];
    assert_eq!(bin_node.label, "Recycle Bin");
    assert!(bin_node.is_recycle_bin);

    // Foreign session is Stale; locked service is Locked.
    assert_eq!(
        svc.group_tree(foreign_session).err(),
        Some(ServiceError::Stale)
    );
    svc.lock(session).unwrap();
    assert_eq!(svc.group_tree(session).err(), Some(ServiceError::Locked));

    // Unsafe group name fails closed.
    let mut bad_db = KeePassDatabase::default();
    bad_db.add_group(Group::new("bad\nname"));
    let bad_path = dir.path().join("bad-tree.kdbx");
    save_raw(&bad_path, &bad_db, fast_options());
    let (bad_svc, bad_session) = reopen(&bad_path);
    assert_eq!(
        bad_svc.group_tree(bad_session).err(),
        Some(ServiceError::InvalidInput)
    );
}

#[test]
fn custom_icons_list_assign_bounds_and_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("icons.kdbx");
    let valid_id = KdbxUuid::from_bytes([0x21; 16]);
    let empty_id = KdbxUuid::from_bytes([0x22; 16]);
    let oversized_id = KdbxUuid::from_bytes([0x23; 16]);

    let mut db = KeePassDatabase::default();
    db.meta.custom_icons.push(CustomIcon {
        uuid: valid_id,
        data: vec![1, 2, 3, 4],
        name: Some("logo".into()),
        last_modification: None,
    });
    db.meta.custom_icons.push(CustomIcon {
        uuid: empty_id,
        data: Vec::new(),
        name: Some("empty".into()),
        last_modification: None,
    });
    db.meta.custom_icons.push(CustomIcon {
        uuid: oversized_id,
        data: vec![7u8; nkeepass::icons::MAX_CUSTOM_ICON_BYTES + 1],
        name: Some("huge".into()),
        last_modification: None,
    });
    db.add_group(Group::new("Work"));
    db.add_entry(Entry::new("Login"));
    save_raw(&path, &db, fast_options());

    let (mut svc, session) = reopen(&path);
    let icons = svc.list_custom_icons(session).unwrap();
    assert_eq!(icons.len(), 1);
    let cid = CustomIconId::from_bytes([0x21; 16]).unwrap();
    assert_eq!(icons[0].id, cid);
    assert_eq!(icons[0].name, "logo");
    assert_eq!(icons[0].size, 4);

    let entry_ref = svc.resolve_entry(session, "Login").unwrap().reference();
    let missing_cid = CustomIconId::from_bytes([0x99; 16]).unwrap();
    assert_eq!(
        svc.set_entry_custom_icon(&entry_ref, missing_cid),
        Err(ServiceError::NotFound)
    );
    svc.set_entry_custom_icon(&entry_ref, cid).unwrap();
    assert_eq!(
        svc.selected_entry(&entry_ref).err(),
        Some(ServiceError::Stale)
    );

    let group_ref = svc.resolve_group(session, "Work").unwrap();
    svc.set_group_custom_icon(&group_ref, cid).unwrap();
    assert_eq!(svc.group_path(&group_ref), Err(ServiceError::Stale));

    svc.save(&path, &mut credentials()).unwrap();
    let (reopened, rsession) = reopen(&path);
    let rentry = reopened
        .resolve_entry(rsession, "Login")
        .unwrap()
        .reference();
    assert_eq!(
        reopened.selected_entry(&rentry).unwrap().custom_icon_id(),
        Some(cid)
    );
    let rtree = reopened.group_tree(rsession).unwrap();
    assert_eq!(rtree.children[0].custom_icon_id, Some(cid));

    // Duplicate custom icon UUID fails closed.
    let dup_path = dir.path().join("dup-icons.kdbx");
    let mut dup_db = KeePassDatabase::default();
    dup_db.meta.custom_icons.push(CustomIcon {
        uuid: valid_id,
        data: vec![1, 2],
        name: None,
        last_modification: None,
    });
    dup_db.meta.custom_icons.push(CustomIcon {
        uuid: valid_id,
        data: vec![3, 4],
        name: None,
        last_modification: None,
    });
    save_raw(&dup_path, &dup_db, fast_options());
    let (dup_svc, dup_sess) = reopen(&dup_path);
    assert_eq!(
        dup_svc.list_custom_icons(dup_sess),
        Err(ServiceError::DuplicateIds)
    );

    // > 512 valid custom icons fails closed with ResourceLimit.
    let many_path = dir.path().join("many-icons.kdbx");
    let mut many_db = KeePassDatabase::default();
    for i in 1u16..=513 {
        let mut bytes = [0u8; 16];
        bytes[..2].copy_from_slice(&i.to_le_bytes());
        many_db.meta.custom_icons.push(CustomIcon {
            uuid: KdbxUuid::from_bytes(bytes),
            data: vec![1],
            name: None,
            last_modification: None,
        });
    }
    save_raw(&many_path, &many_db, fast_options());
    let (many_svc, many_sess) = reopen(&many_path);
    assert_eq!(
        many_svc.list_custom_icons(many_sess),
        Err(ServiceError::ResourceLimit)
    );
}

#[test]
fn rename_group_move_entry_reorder_entry_and_clone_entry_round_trip() {
    let (_dir, path, mut svc, session) = create_and_open();
    let root = svc.root_group(session).unwrap();
    svc.add_group(&root, "Alpha").unwrap();
    let root = svc.root_group(session).unwrap();
    svc.add_group(&root, "Beta").unwrap();

    // Group rename validation & collision.
    let alpha = svc.resolve_group(session, "Alpha").unwrap();
    assert_eq!(
        svc.rename_group(&alpha, ""),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        svc.rename_group(&alpha, "a/b"),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        svc.rename_group(&alpha, ".."),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        svc.rename_group(&alpha, "BETA"),
        Err(ServiceError::GroupExists)
    );
    svc.rename_group(&alpha, "alpha").unwrap(); // case-only self-rename ok
    assert_eq!(svc.group_path(&alpha), Err(ServiceError::Stale));

    let alpha = svc.resolve_group(session, "alpha").unwrap();
    svc.rename_group(&alpha, "Work").unwrap();
    let root = svc.root_group(session).unwrap();
    svc.rename_group(&root, "VaultRoot").unwrap();
    let tree = svc.group_tree(session).unwrap();
    assert_eq!(tree.label, "VaultRoot");
    assert_eq!(tree.children[0].label, "Work");

    // Create entries in Work and test reorder_entry.
    let work = svc.resolve_group(session, "Work").unwrap();
    let e1 = svc.create_entry_in_group(&work, "First").unwrap();
    let work = svc.resolve_group(session, "Work").unwrap();
    let e2 = svc.create_entry_in_group(&work, "Second").unwrap();
    let work = svc.resolve_group(session, "Work").unwrap();
    let e3 = svc.create_entry_in_group(&work, "Third").unwrap();
    assert_eq!(svc.selected_entry(&e1).err(), Some(ServiceError::Stale));
    assert_eq!(svc.selected_entry(&e2).err(), Some(ServiceError::Stale));

    let e3_reordered = svc.reorder_entry(&e3, 0).unwrap();
    assert_eq!(svc.selected_entry(&e3).err(), Some(ServiceError::Stale));
    assert_eq!(svc.selected_entry(&e3_reordered).unwrap().title(), "Third");
    let e3_end = svc.reorder_entry(&e3_reordered, usize::MAX).unwrap();
    let work = svc.resolve_group(session, "Work").unwrap();
    let page = svc.tree_page(&work, None).unwrap();
    let titles: Vec<_> = page.entries.iter().map(|h| h.title()).collect();
    assert_eq!(titles, ["First", "Second", "Third"]);

    // Clone entry with fields, tags, attachment, and verify cleared history & Copy/Copy 2 naming.
    svc.set_tags(&e3_end, vec!["prod".into(), "ops".into()])
        .unwrap();
    let e3_ref = svc
        .resolve_entry(session, "Work/Third")
        .unwrap()
        .reference();
    svc.add_attachment(&e3_ref, "note.bin", Zeroizing::new(b"ATTACH".to_vec()))
        .unwrap();
    let e3_ref = svc
        .resolve_entry(session, "Work/Third")
        .unwrap()
        .reference();
    svc.set_field(&e3_ref, "Password", "clone-pw").unwrap();
    let e3_ref = svc
        .resolve_entry(session, "Work/Third")
        .unwrap()
        .reference();
    svc.set_field(&e3_ref, "Notes", "clone-notes").unwrap();
    let e3_ref = svc
        .resolve_entry(session, "Work/Third")
        .unwrap()
        .reference();
    let copy1 = svc.clone_entry(&e3_ref).unwrap();
    assert_eq!(svc.selected_entry(&e3_ref).err(), Some(ServiceError::Stale));
    assert_eq!(svc.selected_entry(&copy1).unwrap().title(), "Third (Copy)");
    assert_eq!(svc.reveal_password(&copy1).unwrap().as_slice(), b"clone-pw");
    assert_eq!(
        svc.reveal_native_field(&copy1, "Notes").unwrap().as_slice(),
        b"clone-notes"
    );
    let copy1_sel = svc.selected_entry(&copy1).unwrap();
    assert_eq!(copy1_sel.tags(), &["prod", "ops"]);
    assert_eq!(copy1_sel.attachments().len(), 1);
    let att_ref = svc.attachment_metadata(&copy1).unwrap()[0].reference();
    assert_eq!(
        svc.reveal_attachment(&att_ref).unwrap().as_slice(),
        b"ATTACH"
    );

    let e3_ref = svc
        .resolve_entry(session, "Work/Third")
        .unwrap()
        .reference();
    let copy2 = svc.clone_entry(&e3_ref).unwrap();
    assert_eq!(
        svc.selected_entry(&copy2).unwrap().title(),
        "Third (Copy 2)"
    );

    // Move entry to Beta and reject collision.
    let beta = svc.resolve_group(session, "Beta").unwrap();
    svc.create_entry_in_group(&beta, "First").unwrap();
    let first_in_work = svc
        .resolve_entry(session, "Work/First")
        .unwrap()
        .reference();
    let beta = svc.resolve_group(session, "Beta").unwrap();
    assert_eq!(
        svc.move_entry(&first_in_work, &beta).err(),
        Some(ServiceError::Ambiguous)
    );
    let second_in_work = svc
        .resolve_entry(session, "Work/Second")
        .unwrap()
        .reference();
    let moved = svc.move_entry(&second_in_work, &beta).unwrap();
    assert_eq!(
        svc.selected_entry(&second_in_work).err(),
        Some(ServiceError::Stale)
    );
    assert_eq!(svc.selected_entry(&moved).unwrap().title(), "Second");

    svc.save(&path, &mut credentials()).unwrap();
    let (reopened, rsess) = reopen(&path);
    assert!(reopened.resolve_entry(rsess, "Beta/Second").is_ok());
    assert!(reopened.resolve_entry(rsess, "Work/Third (Copy)").is_ok());
    assert!(reopened.resolve_entry(rsess, "Work/Third (Copy 2)").is_ok());
}

#[test]
fn clone_entry_clears_history_and_preserves_auto_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clone-history.kdbx");
    let mut db = KeePassDatabase::default();
    let mut entry = Entry::new("Account");
    entry.password = ProtectedValue::from_text("curr");
    entry.auto_type = AutoType {
        enabled: Some(true),
        obfuscated: Some(false),
        default_sequence: "{USERNAME}{TAB}{PASSWORD}".into(),
        associations: vec![AutoTypeAssociation {
            window: "App*".into(),
            keystrokes: "{PASSWORD}".into(),
        }],
    };
    let mut hist = Entry::new("Account");
    hist.password = ProtectedValue::from_text("old");
    entry.history.push(hist);
    db.add_entry(entry);
    save_raw(&path, &db, fast_options());

    let (mut svc, sess) = reopen(&path);
    let orig = svc.resolve_entry(sess, "Account").unwrap().reference();
    let cloned = svc.clone_entry(&orig).unwrap();
    let sel = svc.selected_entry(&cloned).unwrap();
    assert!(sel.auto_type_enabled());
    assert_eq!(sel.auto_type_associations(), 1);
    svc.save(&path, &mut credentials()).unwrap();

    let raw = load_raw(&path);
    assert_eq!(raw.root.entries[0].history.len(), 1);
    assert!(raw.root.entries[1].history.is_empty());
    assert_eq!(raw.root.entries[1].auto_type.associations.len(), 1);
}

#[test]
fn recycle_restore_and_empty_recycle_bin_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recycle.kdbx");
    let mut db = KeePassDatabase::default();
    db.meta.recycle_bin_enabled = true;
    let bin_ref = db.binary_pool.add(b"bin-only-attachment".to_vec(), true);
    let mut work = Group::new("Work");
    let mut e1 = Entry::new("ServiceA");
    e1.attachments.push(Attachment {
        name: "a.bin".into(),
        reference: bin_ref,
    });
    work.add_entry(e1);
    work.add_entry(Entry::new("ServiceB"));
    db.add_group(work);
    save_raw(&path, &db, fast_options());

    let (mut svc, sess) = reopen(&path);
    let a_ref = svc
        .resolve_entry(sess, "Work/ServiceA")
        .unwrap()
        .reference();
    // Not in recycle bin -> restore_entry rejects.
    assert_eq!(
        svc.restore_entry(&a_ref).err(),
        Some(ServiceError::InvalidInput)
    );

    // Recycle moves to auto-created Recycle Bin group (icon 43) and returns true.
    assert!(svc.recycle_entry(&a_ref).unwrap());
    assert_eq!(svc.selected_entry(&a_ref).err(), Some(ServiceError::Stale));

    let tree = svc.group_tree(sess).unwrap();
    let bin_node = tree
        .children
        .iter()
        .find(|n| n.is_recycle_bin)
        .expect("Recycle Bin node");
    assert_eq!(bin_node.label, "Recycle Bin");
    assert_eq!(bin_node.icon_id, 43);
    assert_eq!(bin_node.entry_count, 1);

    // Restore brings ServiceA back into Work.
    let recycled_a = svc
        .resolve_entry(sess, "Recycle Bin/ServiceA")
        .unwrap()
        .reference();
    let restored_a = svc.restore_entry(&recycled_a).unwrap();
    assert_eq!(svc.selected_entry(&restored_a).unwrap().title(), "ServiceA");
    assert!(svc.resolve_entry(sess, "Work/ServiceA").is_ok());

    // Recycle ServiceB, then remove Work, then restore ServiceB -> falls back to Root.
    let b_ref = svc
        .resolve_entry(sess, "Work/ServiceB")
        .unwrap()
        .reference();
    assert!(svc.recycle_entry(&b_ref).unwrap());
    let a_ref = svc
        .resolve_entry(sess, "Work/ServiceA")
        .unwrap()
        .reference();
    assert!(svc.recycle_entry(&a_ref).unwrap());
    let work_ref = svc.resolve_group(sess, "Work").unwrap();
    svc.remove_group(&work_ref).unwrap();

    let recycled_b = svc
        .resolve_entry(sess, "Recycle Bin/ServiceB")
        .unwrap()
        .reference();
    let restored_b = svc.restore_entry(&recycled_b).unwrap();
    assert_eq!(svc.selected_entry(&restored_b).unwrap().title(), "ServiceB");
    assert!(svc.resolve_entry(sess, "Root/ServiceB").is_ok());

    // Recycle an entry already inside Recycle Bin -> permanently deletes it and returns false.
    let recycled_a = svc
        .resolve_entry(sess, "Recycle Bin/ServiceA")
        .unwrap()
        .reference();
    assert!(!svc.recycle_entry(&recycled_a).unwrap());
    assert!(svc.resolve_entry(sess, "Recycle Bin/ServiceA").is_err());

    // Re-add entries + subgroup inside Recycle Bin, then empty_recycle_bin.
    let bin_ref = svc.resolve_group(sess, "Recycle Bin").unwrap();
    svc.create_entry_in_group(&bin_ref, "Trash1").unwrap();
    let bin_ref = svc.resolve_group(sess, "Recycle Bin").unwrap();
    svc.add_group(&bin_ref, "TrashSub").unwrap();
    let sub_ref = svc.resolve_group(sess, "Recycle Bin/TrashSub").unwrap();
    svc.create_entry_in_group(&sub_ref, "Trash2").unwrap();

    let removed = svc.empty_recycle_bin(sess).unwrap();
    assert_eq!(removed, 3); // Trash1, TrashSub, Trash2
    svc.save(&path, &mut credentials()).unwrap();

    let raw = load_raw(&path);
    assert!(raw.binary_pool.is_empty());
    assert!(raw.deleted_objects.len() >= 4);

    // When recycle_bin_enabled == false, recycle_entry permanently deletes immediately.
    let (mut svc2, sess2) = reopen(&path);
    let mut settings = svc2.database_settings(sess2).unwrap();
    svc2.update_database_settings(
        sess2,
        DatabaseSettingsUpdate {
            name: settings.name,
            description: settings.description,
            default_username: settings.default_username,
            recycle_bin_enabled: false,
            history_max_items: settings.history_max_items,
            history_max_size: settings.history_max_size,
            outer_cipher: settings.outer_cipher,
            compression: settings.compression,
            kdf: settings.kdf,
        },
    )
    .unwrap();
    let b_ref = svc2
        .resolve_entry(sess2, "Root/ServiceB")
        .unwrap()
        .reference();
    assert!(!svc2.recycle_entry(&b_ref).unwrap());
    assert!(svc2.resolve_entry(sess2, "Root/ServiceB").is_err());
    settings.recycle_bin_enabled = false;
    assert!(!settings.recycle_bin_enabled);
}

#[test]
fn database_settings_update_validates_and_persists_across_save_reopen() {
    let (_dir, path, mut svc, sess) = create_and_open();
    let invalid = DatabaseSettingsUpdate {
        name: "bad\0name".into(),
        description: String::new(),
        default_username: String::new(),
        recycle_bin_enabled: true,
        history_max_items: 10,
        history_max_size: 1024,
        outer_cipher: VaultCipher::Aes,
        compression: VaultCompression::GZip,
        kdf: VaultKdfSummary::Aes { rounds: 10 },
    };
    assert_eq!(
        svc.update_database_settings(sess, invalid),
        Err(ServiceError::InvalidInput)
    );
    assert_eq!(
        svc.update_database_settings(
            sess,
            DatabaseSettingsUpdate {
                name: "ok".into(),
                description: String::new(),
                default_username: String::new(),
                recycle_bin_enabled: true,
                history_max_items: -2,
                history_max_size: 1024,
                outer_cipher: VaultCipher::Aes,
                compression: VaultCompression::GZip,
                kdf: VaultKdfSummary::Aes { rounds: 10 },
            },
        ),
        Err(ServiceError::InvalidInput)
    );

    svc.update_database_settings(
        sess,
        DatabaseSettingsUpdate {
            name: "Personal Vault".into(),
            description: "Line 1\nLine 2".into(),
            default_username: "alice".into(),
            recycle_bin_enabled: false,
            history_max_items: 25,
            history_max_size: 8_388_608,
            outer_cipher: VaultCipher::ChaCha20,
            compression: VaultCompression::None,
            kdf: VaultKdfSummary::Argon2d {
                memory_kib: 128,
                iterations: 3,
                lanes: 2,
            },
        },
    )
    .unwrap();
    svc.save(&path, &mut credentials()).unwrap();

    let (reopened, rsess) = reopen(&path);
    let got = reopened.database_settings(rsess).unwrap();
    assert_eq!(got.name, "Personal Vault");
    assert_eq!(got.description, "Line 1\nLine 2");
    assert_eq!(got.default_username, "alice");
    assert!(!got.recycle_bin_enabled);
    assert_eq!(got.history_max_items, 25);
    assert_eq!(got.history_max_size, 8_388_608);
    assert_eq!(got.outer_cipher, VaultCipher::ChaCha20);
    assert_eq!(got.compression, VaultCompression::None);
    assert_eq!(
        got.kdf,
        VaultKdfSummary::Argon2d {
            memory_kib: 128,
            iterations: 3,
            lanes: 2,
        }
    );
}

#[test]
fn otp_metadata_hotp_next_code_steam_and_keepass2_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("otp-apis.kdbx");

    let mut db = KeePassDatabase::default();
    db.add_entry(Entry::new("NoOtp"));

    let mut steam = Entry::new("SteamEntry");
    steam.set_field(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text(
            "otpauth://totp/Steam:alice?secret=JBSWY3DPEHPK3PXP&encoder=steam",
        ),
        protected: true,
        protect_in_memory: true,
    });
    db.add_entry(steam);

    let mut kp2 = Entry::new("Kp2Entry");
    kp2.set_field(Field {
        key: "TimeOtp-Secret-Base32".into(),
        value: ProtectedValue::from_text("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"),
        protected: true,
        protect_in_memory: true,
    });
    kp2.set_field(Field::new("TimeOtp-Algorithm", "HMAC-SHA-1"));
    kp2.set_field(Field::new("TimeOtp-Length", "6"));
    kp2.set_field(Field::new("TimeOtp-Period", "30"));
    db.add_entry(kp2);

    let mut unprot = Entry::new("UnprotectedOtp");
    unprot.set_field(Field::new(
        "otp",
        "otpauth://totp/Unprot?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    ));
    db.add_entry(unprot);

    save_raw(&path, &db, fast_options());

    let (mut svc, sess) = reopen(&path);
    let no_otp_ref = svc.resolve_entry(sess, "NoOtp").unwrap().reference();
    assert_eq!(svc.otp_metadata(&no_otp_ref).unwrap(), None);
    assert_eq!(
        svc.hotp_next_code(&no_otp_ref).err(),
        Some(ServiceError::InvalidOtp)
    );

    // Steam OTP metadata & code generation.
    let steam_ref = svc.resolve_entry(sess, "SteamEntry").unwrap().reference();
    let steam_meta = svc.otp_metadata(&steam_ref).unwrap().unwrap();
    assert_eq!(steam_meta.kind, ServiceOtpKind::Totp);
    assert_eq!(steam_meta.digits, 5);
    assert_eq!(steam_meta.period, Some(30));
    assert!(steam_meta.steam);
    assert!(!format!("{steam_meta:?}").contains("JBSWY3DPEHPK3PXP"));
    let steam_code = svc.totp_code_with_period(&steam_ref, 59).unwrap();
    assert_eq!(steam_code.code().len(), 5);
    assert_eq!(steam_code.period(), 30);

    // KeePass 2.x TimeOtp fallback & unprotected otp.
    let kp2_ref = svc.resolve_entry(sess, "Kp2Entry").unwrap().reference();
    assert!(svc.selected_entry(&kp2_ref).unwrap().has_otp());
    assert_eq!(&*svc.otp_code(&kp2_ref, 59).unwrap(), "287082");
    let unprot_ref = svc
        .resolve_entry(sess, "UnprotectedOtp")
        .unwrap()
        .reference();
    assert_eq!(&*svc.otp_code(&unprot_ref, 59).unwrap(), "287082");

    // format_otp_uri + set_entry_otp_config + hotp_next_code.
    let hotp_cfg = OtpConfig {
        kind: ServiceOtpKind::Hotp,
        account: "Example:bob".into(),
        issuer: Some("Example".into()),
        algorithm: ServiceOtpAlgorithm::Sha1,
        digits: 6,
        period: None,
        counter: Some(0),
        steam: false,
    };
    let formatted =
        VaultService::format_otp_uri(&hotp_cfg, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    assert!(formatted.starts_with("otpauth://hotp/Example:bob?"));

    svc.set_entry_otp_config(&no_otp_ref, &hotp_cfg, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .unwrap();
    assert_eq!(
        svc.selected_entry(&no_otp_ref).err(),
        Some(ServiceError::Stale)
    );
    let hotp_ref = svc.resolve_entry(sess, "NoOtp").unwrap().reference();
    assert_eq!(
        svc.otp_code(&hotp_ref, 59),
        Err(ServiceError::HotpUnsupported)
    );
    let c0 = svc.hotp_next_code(&hotp_ref).unwrap();
    assert_eq!(&*c0, "755224");
    assert_eq!(
        svc.selected_entry(&hotp_ref).err(),
        Some(ServiceError::Stale)
    );

    let hotp_ref = svc.resolve_entry(sess, "NoOtp").unwrap().reference();
    let meta = svc.otp_metadata(&hotp_ref).unwrap().unwrap();
    assert_eq!(meta.counter, Some(1));
    let c1 = svc.hotp_next_code(&hotp_ref).unwrap();
    assert_eq!(&*c1, "287082");

    svc.save(&path, &mut credentials()).unwrap();
    let (mut reopened, rsess) = reopen(&path);
    let rhotp = reopened.resolve_entry(rsess, "NoOtp").unwrap().reference();
    assert_eq!(
        reopened.otp_metadata(&rhotp).unwrap().unwrap().counter,
        Some(2)
    );
    let c2 = reopened.hotp_next_code(&rhotp).unwrap();
    assert_eq!(&*c2, "359152");
}

#[test]
fn wildcard_glob_search_and_binary_search_path_completion() {
    let (_dir, _path, mut svc, sess) = create_and_open();
    let root = svc.root_group(sess).unwrap();
    svc.add_group(&root, "Next").unwrap();
    let next = svc.resolve_group(sess, "Next").unwrap();
    svc.add_group(&next, "Checkout").unwrap();
    let checkout = svc.resolve_group(sess, "Next/Checkout").unwrap();
    let ch_entry = svc.create_entry_in_group(&checkout, "ChromeProd").unwrap();
    svc.set_field(&ch_entry, "UserName", "admin-chrome")
        .unwrap();
    let ch_entry = svc
        .resolve_entry(sess, "Next/Checkout/ChromeProd")
        .unwrap()
        .reference();
    svc.set_field(&ch_entry, "URL", "https://chrome.example.org")
        .unwrap();
    let ch_entry = svc
        .resolve_entry(sess, "Next/Checkout/ChromeProd")
        .unwrap()
        .reference();
    svc.set_field(&ch_entry, "Password", "TOP-SECRET-VALUE-999")
        .unwrap();
    let ch_entry = svc
        .resolve_entry(sess, "Next/Checkout/ChromeProd")
        .unwrap()
        .reference();
    svc.set_tags(&ch_entry, vec!["browser".into()]).unwrap();

    let next = svc.resolve_group(sess, "Next").unwrap();
    svc.create_entry_in_group(&next, "Channel").unwrap();

    // Substring search (no * or ?) remains unchanged and never searches secrets.
    let sub_hits = svc.search(sess, "chrome").unwrap();
    assert_eq!(sub_hits.hits.len(), 1);
    assert!(
        svc.search(sess, "TOP-SECRET-VALUE")
            .unwrap()
            .hits
            .is_empty()
    );

    // Wildcard search with * and ? (case-insensitive) against title, username, url, tags, group path.
    assert_eq!(svc.search(sess, "Ch*Prod").unwrap().hits.len(), 1);
    assert_eq!(svc.search(sess, "admin-ch?ome").unwrap().hits.len(), 1);
    assert_eq!(
        svc.search(sess, "https://*.example.org")
            .unwrap()
            .hits
            .len(),
        1
    );
    assert_eq!(svc.search(sess, "brow?er").unwrap().hits.len(), 1);
    assert_eq!(svc.search(sess, "Root/Next/*").unwrap().hits.len(), 2);
    assert!(svc.search(sess, "*TOP-SECRET*").unwrap().hits.is_empty());

    // Path completion: normalized leading `/`, partial segments, explicit root, glob, limit cap 50.
    let c1 = svc.complete_path(sess, "/next/ch", 10).unwrap();
    let paths1: Vec<_> = c1.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths1,
        [
            "Root/Next/Channel",
            "Root/Next/Checkout",
            "Root/Next/Checkout/ChromeProd"
        ]
    );
    assert!(!c1[0].is_group && c1[0].entry_ref.is_some() && c1[0].group_ref.is_none());
    assert!(c1[1].is_group && c1[1].group_ref.is_some() && c1[1].entry_ref.is_none());

    // Explicit root prefix works too.
    let c2 = svc.complete_path(sess, "Root/next/ch", 10).unwrap();
    assert_eq!(c2.len(), 3);

    // Glob path completion works.
    let c3 = svc.complete_path(sess, "*chrome*", 10).unwrap();
    assert_eq!(c3.len(), 1);
    assert_eq!(c3[0].path, "Root/Next/Checkout/ChromeProd");

    // Secrets are never matched or exposed by complete_path.
    assert!(
        svc.complete_path(sess, "TOP-SECRET", 10)
            .unwrap()
            .is_empty()
    );

    // Unsafe prefix is rejected.
    assert_eq!(
        svc.complete_path(sess, "bad\nprefix", 10),
        Err(ServiceError::InvalidInput)
    );

    // Limit is capped at 50 even if caller asks for more.
    let root = svc.root_group(sess).unwrap();
    for i in 0..60 {
        let root_fresh = svc.root_group(sess).unwrap();
        svc.create_entry_in_group(&root_fresh, &format!("Bulk-{i:02}"))
            .unwrap();
    }
    let _ = root;
    let bulk = svc.complete_path(sess, "bulk-", 100).unwrap();
    assert_eq!(bulk.len(), 50);
}
