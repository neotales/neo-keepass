//! Integration coverage for `VaultService` entry creation, title/tag editing,
//! custom field protection flags, and policy-backed password generation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test fixture setup and assertions"
)]

use neotales_keepass::{KdbxCredentials, KdbxKdf, KdbxReadLimits, KdbxWriteOptions};
use nkeepass::password_generator::Policy;
use nkeepass::service::FieldUpdate;
use nkeepass::{EntryRef, ServiceError, SessionId, VaultService};
use tempfile::TempDir;
use zeroize::Zeroizing;

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
    KdbxCredentials::password("crud-test-master-password").unwrap()
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

fn field_update(key: &str, value: &str, protected: Option<bool>) -> FieldUpdate {
    FieldUpdate {
        key: key.to_owned(),
        value: Zeroizing::new(value.to_owned()),
        protected,
        protect_in_memory: protected,
    }
}

fn assert_entry_ref_works_after_creation(
    service: &mut VaultService,
    entry_ref: &EntryRef,
    expected_title: &str,
) {
    let selected = service.selected_entry(entry_ref).unwrap();
    assert_eq!(selected.title(), expected_title);
}

#[test]
fn create_entry_in_root_group_populates_fields_and_round_trips() {
    let (_dir, path, mut service, session) = create_and_open_vault();

    // Create an entry directly in the root group and verify immediate handle use.
    let root = service.root_group(session).unwrap();
    let root_entry_ref = service.create_entry_in_group(&root, "root-entry").unwrap();
    // Group handle from before mutation is now stale.
    assert_eq!(
        service.create_entry_in_group(&root, "another").err(),
        Some(ServiceError::Stale)
    );
    assert_entry_ref_works_after_creation(&mut service, &root_entry_ref, "root-entry");

    // Immediate field population with returned EntryRef.
    service
        .set_fields_creating_custom(
            &root_entry_ref,
            vec![
                field_update("UserName", "alice", Some(false)),
                field_update("Password", "s3cr3t!", Some(true)),
            ],
        )
        .unwrap();
    assert_eq!(
        service.selected_entry(&root_entry_ref).err(),
        Some(ServiceError::Stale)
    );

    service.save(&path, &mut credentials()).unwrap();

    let (reopened, reopened_session) = reopen_vault(&path);
    let reopened_root_entry = reopened
        .resolve_entry(reopened_session, "root-entry")
        .unwrap()
        .reference();
    assert_eq!(
        reopened
            .reveal_field(&reopened_root_entry, "UserName")
            .unwrap()
            .as_slice(),
        b"alice"
    );
    assert_eq!(
        reopened
            .reveal_password(&reopened_root_entry)
            .unwrap()
            .as_slice(),
        b"s3cr3t!"
    );
}

#[test]
fn create_entry_in_nested_group_full_crud_round_trip() {
    let (_dir, path, mut service, session) = create_and_open_vault();

    // Create a nested group and an entry inside it.
    let root = service.root_group(session).unwrap();
    service.add_group(&root, "Work").unwrap();
    let work = service.resolve_group(session, "Work").unwrap();
    service.add_group(&work, "Cloud").unwrap();
    let cloud = service.resolve_group(session, "Work/Cloud").unwrap();

    let nested_ref = service.create_entry_in_group(&cloud, "aws-prod").unwrap();
    assert_entry_ref_works_after_creation(&mut service, &nested_ref, "aws-prod");

    // Duplicate title (ASCII case-insensitive) in the same group fails closed.
    let cloud_fresh = service.resolve_group(session, "Work/Cloud").unwrap();
    assert_eq!(
        service
            .create_entry_in_group(&cloud_fresh, "AWS-PROD")
            .err(),
        Some(ServiceError::Ambiguous)
    );
    // Same title in root group is allowed because it is a different group.
    let root_fresh = service.root_group(session).unwrap();
    let _other_group_same_title = service
        .create_entry_in_group(&root_fresh, "AWS-PROD")
        .unwrap();

    // Re-resolve nested entry and exercise set_title, set_tags, add_attachment, remove_attachment.
    let nested_ref = service
        .resolve_entry(session, "Work/Cloud/aws-prod")
        .unwrap()
        .reference();
    service.set_title(&nested_ref, "aws-staging").unwrap();
    assert_eq!(
        service.selected_entry(&nested_ref).err(),
        Some(ServiceError::Stale)
    );

    let nested_ref = service
        .resolve_entry(session, "Work/Cloud/aws-staging")
        .unwrap()
        .reference();
    service
        .set_tags(&nested_ref, vec!["prod".into(), "cloud".into()])
        .unwrap();

    let nested_ref = service
        .resolve_entry(session, "Work/Cloud/aws-staging")
        .unwrap()
        .reference();
    service
        .add_attachment(
            &nested_ref,
            "key.pem",
            Zeroizing::new(b"PEM-BYTES".to_vec()),
        )
        .unwrap();

    let nested_ref = service
        .resolve_entry(session, "Work/Cloud/aws-staging")
        .unwrap()
        .reference();
    service
        .add_attachment(
            &nested_ref,
            "temp.txt",
            Zeroizing::new(b"TEMP-BYTES".to_vec()),
        )
        .unwrap();

    let nested_ref = service
        .resolve_entry(session, "Work/Cloud/aws-staging")
        .unwrap()
        .reference();
    service.remove_attachment(&nested_ref, "temp.txt").unwrap();

    service.save(&path, &mut credentials()).unwrap();

    // Reopen from disk and verify everything survived.
    let (reopened, reopened_session) = reopen_vault(&path);
    let reopened_nested = reopened
        .resolve_entry(reopened_session, "Work/Cloud/aws-staging")
        .unwrap()
        .reference();
    let selected = reopened.selected_entry(&reopened_nested).unwrap();
    assert_eq!(selected.title(), "aws-staging");
    assert_eq!(selected.tags(), &["prod", "cloud"]);
    assert_eq!(selected.attachments().len(), 1);
    assert_eq!(selected.attachments()[0].name(), "key.pem");
    let attachments = reopened.attachment_metadata(&reopened_nested).unwrap();
    assert_eq!(
        reopened
            .reveal_attachment(&attachments[0].reference())
            .unwrap()
            .as_slice(),
        b"PEM-BYTES"
    );
}

#[test]
fn create_entry_in_group_immediate_operations_with_returned_ref() {
    let (_dir, _path, mut service, session) = create_and_open_vault();

    // Verify each mutating method accepts the fresh EntryRef returned by create_entry_in_group
    // directly without needing a separate resolve_entry call.
    let root = service.root_group(session).unwrap();
    let r1 = service.create_entry_in_group(&root, "e1").unwrap();
    service.set_title(&r1, "e1-renamed").unwrap();

    let root = service.root_group(session).unwrap();
    let r2 = service.create_entry_in_group(&root, "e2").unwrap();
    service.set_tags(&r2, vec!["alpha".into()]).unwrap();

    let root = service.root_group(session).unwrap();
    let r3 = service.create_entry_in_group(&root, "e3").unwrap();
    service
        .add_attachment(&r3, "doc.txt", Zeroizing::new(b"hello".to_vec()))
        .unwrap();

    // Invalid titles and locked session fail closed.
    let root = service.root_group(session).unwrap();
    assert_eq!(
        service.create_entry_in_group(&root, "").err(),
        Some(ServiceError::InvalidInput)
    );
    assert_eq!(
        service.create_entry_in_group(&root, "bad/title").err(),
        Some(ServiceError::InvalidInput)
    );
    assert_eq!(
        service
            .create_entry_in_group(&root, "bad\u{202E}title")
            .err(),
        Some(ServiceError::InvalidInput)
    );

    service.lock(session).unwrap();
    assert_eq!(
        service.create_entry_in_group(&root, "locked").err(),
        Some(ServiceError::Locked)
    );
}

#[test]
fn set_title_validation_projection_sync_and_set_field_invariants() {
    let (_dir, path, mut service, session) = create_and_open_vault();
    let root = service.root_group(session).unwrap();
    let entry_ref = service.create_entry_in_group(&root, "initial").unwrap();

    // Reject empty, overlong, slash, control chars, and BiDi/line-separator overrides.
    let too_long = "t".repeat(4097);
    let mut invalid_titles = vec![
        String::new(),
        too_long,
        "group/entry".to_owned(),
        "line\nbreak".to_owned(),
        "nul\0byte".to_owned(),
        "tab\tchar".to_owned(),
        "del\x7fchar".to_owned(),
        "c1\u{0085}char".to_owned(),
    ];
    for code in (0x2028..=0x202E).chain(0x2066..=0x2069) {
        let ch = char::from_u32(code).unwrap();
        invalid_titles.push(format!("prefix{ch}suffix"));
    }
    for bad in &invalid_titles {
        assert_eq!(
            service.set_title(&entry_ref, bad),
            Err(ServiceError::InvalidInput),
            "title {bad:?} must be rejected"
        );
    }

    // Max valid length (4096 bytes) is accepted.
    let max_title = "m".repeat(4096);
    service.set_title(&entry_ref, &max_title).unwrap();
    let fresh = service
        .resolve_entry(session, &max_title)
        .unwrap()
        .reference();
    assert_eq!(service.selected_entry(&fresh).unwrap().title(), max_title);

    // Update to a short title and verify Title projection & existing set_field invariants.
    service.set_title(&fresh, "renamed-entry").unwrap();
    assert_eq!(service.set_title(&fresh, "stale"), Err(ServiceError::Stale));

    let fresh = service
        .resolve_entry(session, "renamed-entry")
        .unwrap()
        .reference();
    let selected = service.selected_entry(&fresh).unwrap();
    assert_eq!(selected.title(), "renamed-entry");
    assert!(selected.fields().iter().any(|f| f.name() == "Title"));
    assert_eq!(
        service.reveal_field(&fresh, "Title").unwrap().as_slice(),
        b"renamed-entry"
    );
    assert_eq!(
        service
            .reveal_native_field(&fresh, "Title")
            .unwrap()
            .as_slice(),
        b"renamed-entry"
    );

    // Existing set_field / set_fields / set_fields_creating_custom MUST still reject "Title".
    assert_eq!(
        service.set_field(&fresh, "Title", "forbidden"),
        Err(ServiceError::FieldConflict)
    );
    assert_eq!(
        service.set_fields(
            &fresh,
            vec![field_update("Title", "forbidden", Some(false))]
        ),
        Err(ServiceError::FieldConflict)
    );
    assert_eq!(
        service.set_fields_creating_custom(
            &fresh,
            vec![field_update("Title", "forbidden", Some(false))]
        ),
        Err(ServiceError::FieldConflict)
    );

    // Save, reopen, and rename again (now "Title" definitely came from KDBX XML).
    service.save(&path, &mut credentials()).unwrap();
    let (mut reopened, reopened_session) = reopen_vault(&path);
    let loaded_ref = reopened
        .resolve_entry(reopened_session, "renamed-entry")
        .unwrap()
        .reference();
    assert_eq!(
        reopened.selected_entry(&loaded_ref).unwrap().title(),
        "renamed-entry"
    );
    reopened.set_title(&loaded_ref, "final-title").unwrap();
    reopened.save(&path, &mut credentials()).unwrap();

    let (reopened_again, reopened_again_session) = reopen_vault(&path);
    let final_ref = reopened_again
        .resolve_entry(reopened_again_session, "final-title")
        .unwrap()
        .reference();
    assert_eq!(
        reopened_again.selected_entry(&final_ref).unwrap().title(),
        "final-title"
    );
    assert_eq!(
        reopened_again
            .reveal_field(&final_ref, "Title")
            .unwrap()
            .as_slice(),
        b"final-title"
    );
}

#[test]
fn set_tags_validation_normalization_clearing_and_round_trip() {
    let (_dir, path, mut service, session) = create_and_open_vault();
    let root = service.root_group(session).unwrap();
    let entry_ref = service.create_entry_in_group(&root, "tagged").unwrap();

    // Excess tag count (> 256) rejected.
    let excess_tags = (0..257).map(|i| format!("tag-{i}")).collect();
    assert_eq!(
        service.set_tags(&entry_ref, excess_tags),
        Err(ServiceError::InvalidInput)
    );

    // Invalid individual tags rejected (empty, whitespace-only, >256 bytes, ';', ',', control, BiDi).
    let invalid_tag_cases = vec![
        vec![String::new()],
        vec!["   ".to_owned()],
        vec!["a".repeat(257)],
        vec!["semi;colon".to_owned()],
        vec!["com,ma".to_owned()],
        vec!["ctrl\n".to_owned()],
        vec!["\ttrimmed-ctrl".to_owned()],
        vec!["null\0byte".to_owned()],
        vec!["bidi\u{202E}tag".to_owned()],
        vec!["bidi\u{2066}tag".to_owned()],
        vec!["sep\u{2028}tag".to_owned()],
    ];
    for bad in invalid_tag_cases {
        assert_eq!(
            service.set_tags(&entry_ref, bad),
            Err(ServiceError::InvalidInput)
        );
    }

    // Add tags with whitespace trimming and case-insensitive deduplication preserving first spelling.
    service
        .set_tags(
            &entry_ref,
            vec![
                "  Work  ".to_owned(),
                "work".to_owned(),
                "Finance".to_owned(),
                "FINANCE".to_owned(),
                "Personal".to_owned(),
            ],
        )
        .unwrap();
    assert_eq!(
        service.set_tags(&entry_ref, vec![]),
        Err(ServiceError::Stale)
    );

    let fresh = service
        .resolve_entry(session, "tagged")
        .unwrap()
        .reference();
    assert_eq!(
        service.selected_entry(&fresh).unwrap().tags(),
        &["Work", "Finance", "Personal"]
    );

    service.save(&path, &mut credentials()).unwrap();
    let (mut reopened, reopened_session) = reopen_vault(&path);
    let fresh = reopened
        .resolve_entry(reopened_session, "tagged")
        .unwrap()
        .reference();
    assert_eq!(
        reopened.selected_entry(&fresh).unwrap().tags(),
        &["Work", "Finance", "Personal"]
    );

    // Update tags.
    reopened
        .set_tags(&fresh, vec!["Ops".to_owned(), "256".to_owned()])
        .unwrap();
    reopened.save(&path, &mut credentials()).unwrap();

    let (mut reopened, reopened_session) = reopen_vault(&path);
    let fresh = reopened
        .resolve_entry(reopened_session, "tagged")
        .unwrap()
        .reference();
    assert_eq!(
        reopened.selected_entry(&fresh).unwrap().tags(),
        &["Ops", "256"]
    );

    // Clear tags to empty and verify round-trip.
    reopened.set_tags(&fresh, Vec::new()).unwrap();
    reopened.save(&path, &mut credentials()).unwrap();

    let (reopened, reopened_session) = reopen_vault(&path);
    let fresh = reopened
        .resolve_entry(reopened_session, "tagged")
        .unwrap()
        .reference();
    assert!(reopened.selected_entry(&fresh).unwrap().tags().is_empty());
}

#[test]
fn custom_fields_protected_and_unprotected_create_remove_round_trip() {
    let (_dir, path, mut service, session) = create_and_open_vault();
    let root = service.root_group(session).unwrap();
    let entry_ref = service.create_entry_in_group(&root, "custom-host").unwrap();

    service
        .set_fields_creating_custom(
            &entry_ref,
            vec![
                field_update("api_key", "secret-token-value", Some(true)),
                field_update("region", "us-east-1", Some(false)),
            ],
        )
        .unwrap();

    let fresh = service
        .resolve_entry(session, "custom-host")
        .unwrap()
        .reference();
    let selected = service.selected_entry(&fresh).unwrap();
    let api_meta = selected
        .fields()
        .iter()
        .find(|f| f.name() == "api_key")
        .unwrap();
    assert!(api_meta.protected());
    assert!(api_meta.protect_in_memory());
    let region_meta = selected
        .fields()
        .iter()
        .find(|f| f.name() == "region")
        .unwrap();
    assert!(!region_meta.protected());
    assert!(!region_meta.protect_in_memory());

    service.save(&path, &mut credentials()).unwrap();

    // Reopen and verify protected flags and values survived.
    let (mut reopened, reopened_session) = reopen_vault(&path);
    let fresh = reopened
        .resolve_entry(reopened_session, "custom-host")
        .unwrap()
        .reference();
    let selected = reopened.selected_entry(&fresh).unwrap();
    assert!(
        selected
            .fields()
            .iter()
            .find(|f| f.name() == "api_key")
            .unwrap()
            .protected()
    );
    assert!(
        !selected
            .fields()
            .iter()
            .find(|f| f.name() == "region")
            .unwrap()
            .protected()
    );
    let api_handle = selected
        .custom_fields()
        .iter()
        .find(|f| f.name() == "api_key")
        .unwrap()
        .reference();
    assert_eq!(
        reopened
            .reveal_custom_field(&api_handle)
            .unwrap()
            .as_slice(),
        b"secret-token-value"
    );

    // Remove the unprotected custom field and persist.
    reopened.remove_custom_field(&fresh, "region").unwrap();
    reopened.save(&path, &mut credentials()).unwrap();

    let (reopened, reopened_session) = reopen_vault(&path);
    let fresh = reopened
        .resolve_entry(reopened_session, "custom-host")
        .unwrap()
        .reference();
    let selected = reopened.selected_entry(&fresh).unwrap();
    assert_eq!(selected.custom_fields().len(), 1);
    assert_eq!(selected.custom_fields()[0].name(), "api_key");
    assert_eq!(
        reopened.reveal_field(&fresh, "region").err(),
        Some(ServiceError::NotFound)
    );
}

#[test]
fn generate_password_value_respects_policy_bounds_and_character_classes() {
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    // Default policy enables all four classes.
    assert_eq!(
        VaultService::generate_password_value(3, Policy::default()),
        Err(ServiceError::InvalidSize)
    );
    assert_eq!(
        VaultService::generate_password_value(0, Policy::default()),
        Err(ServiceError::InvalidSize)
    );
    assert_eq!(
        VaultService::generate_password_value(4097, Policy::default()),
        Err(ServiceError::InvalidSize)
    );

    let default_pw = VaultService::generate_password_value(24, Policy::default()).unwrap();
    assert_eq!(default_pw.len(), 24);
    assert!(default_pw.bytes().any(|b| UPPER.contains(&b)));
    assert!(default_pw.bytes().any(|b| LOWER.contains(&b)));
    assert!(default_pw.bytes().any(|b| DIGITS.contains(&b)));
    assert!(default_pw.bytes().any(|b| SYMBOLS.contains(&b)));

    // Upper boundary (4096) succeeds.
    let max_pw = VaultService::generate_password_value(4096, Policy::default()).unwrap();
    assert_eq!(max_pw.len(), 4096);

    // Digits-only policy guarantees only digits and accepts size == 1.
    let digits_only = Policy {
        digits: true,
        ..Policy::default()
    };
    assert_eq!(
        VaultService::generate_password_value(0, digits_only),
        Err(ServiceError::InvalidSize)
    );
    let pin = VaultService::generate_password_value(1, digits_only).unwrap();
    assert_eq!(pin.len(), 1);
    assert!(pin.bytes().all(|b| DIGITS.contains(&b)));

    // Mixed subset (upper + symbols) excludes lower and digits and guarantees both selected classes.
    let upper_symbols = Policy {
        upper: true,
        symbols: true,
        ..Policy::default()
    };
    assert_eq!(
        VaultService::generate_password_value(1, upper_symbols),
        Err(ServiceError::InvalidSize)
    );
    let sample = VaultService::generate_password_value(16, upper_symbols).unwrap();
    assert_eq!(sample.len(), 16);
    assert!(sample.bytes().any(|b| UPPER.contains(&b)));
    assert!(sample.bytes().any(|b| SYMBOLS.contains(&b)));
    assert!(!sample.bytes().any(|b| LOWER.contains(&b)));
    assert!(!sample.bytes().any(|b| DIGITS.contains(&b)));
}
