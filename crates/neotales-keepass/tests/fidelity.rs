// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Attachment, CustomIcon, Entry, Field, KdbxFile, KdbxReadLimits, KdbxTimestamp, KdbxUuid,
    KdbxWriteOptions, KdbxXml, KeePassDatabase, ProtectedValue, VariantValue,
};

fn timestamp(seconds: i64) -> KdbxTimestamp {
    KdbxTimestamp::from_unix_seconds(seconds)
}

#[test]
fn xml_rejects_duplicate_fields_and_multiple_document_roots() {
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("duplicate"));
    let xml = String::from_utf8(KdbxXml::export(&database).unwrap()).unwrap();
    let start = xml.find("<String><Key>Title</Key>").unwrap();
    let end = xml[start..].find("</String>").unwrap() + start + "</String>".len();
    let duplicate = xml[start..end].to_owned();
    let duplicated = xml.replacen("</Entry>", &format!("{duplicate}</Entry>"), 1);
    assert!(KdbxXml::import(duplicated.as_bytes(), &KdbxReadLimits::default()).is_err());

    let two_roots = format!("{xml}<KeePassFile/>");
    assert!(KdbxXml::import(two_roots.as_bytes(), &KdbxReadLimits::default()).is_err());
}

#[test]
fn unprotected_field_protect_in_memory_and_username_setting_round_trip() {
    let mut database = KeePassDatabase::default();
    database.meta.memory_protection = true;
    database.meta.protect_username = true;
    let mut entry = Entry::new("protected-in-memory flag");
    entry.set_field(Field {
        key: "UnprotectedButPinned".into(),
        value: ProtectedValue::from_text("field value"),
        protected: false,
        protect_in_memory: true,
    });
    database.root.entries.push(entry);

    let xml = KdbxXml::export(&database).unwrap();
    let xml_text = std::str::from_utf8(&xml).unwrap();
    assert!(xml_text.contains("<ProtectUserName>True</ProtectUserName>"));
    assert!(!xml_text.contains("<ProtectUsername>"));
    assert!(xml_text.contains("<Value ProtectInMemory=\"True\">field value</Value>"));
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    let field = loaded.root.entries[0]
        .field("UnprotectedButPinned")
        .unwrap();
    assert!(!field.protected);
    assert!(field.protect_in_memory);

    let legacy_spelling = xml_text.replace("ProtectUserName", "ProtectUsername");
    let legacy_loaded =
        KdbxXml::import(legacy_spelling.as_bytes(), &KdbxReadLimits::default()).unwrap();
    assert!(legacy_loaded.meta.protect_username);
    let canonical_again = KdbxXml::export(&legacy_loaded).unwrap();
    assert!(
        std::str::from_utf8(&canonical_again)
            .unwrap()
            .contains("<ProtectUserName>True</ProtectUserName>")
    );

    let limits = KdbxReadLimits::default();
    let mut kdbx = Vec::new();
    KdbxFile::save(
        &loaded,
        &mut kdbx,
        &mut neotales_keepass::KdbxCredentials::password("xml-interop-test").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let reopened = KdbxFile::load_password(kdbx.as_slice(), "xml-interop-test", &limits).unwrap();
    let final_field = reopened.root.entries[0]
        .field("UnprotectedButPinned")
        .unwrap();
    assert!(!final_field.protected);
    assert!(final_field.protect_in_memory);
    let final_xml = KdbxXml::export(&reopened).unwrap();
    assert!(
        std::str::from_utf8(&final_xml)
            .unwrap()
            .contains("<Value ProtectInMemory=\"True\">field value</Value>")
    );
}

#[test]
fn memory_protection_settings_require_valid_booleans_and_nonconflicting_aliases() {
    let mut database = KeePassDatabase::default();
    database.meta.memory_protection = true;
    let xml = String::from_utf8(KdbxXml::export(&database).unwrap()).unwrap();
    for setting in [
        "ProtectPassword",
        "ProtectTitle",
        "ProtectUserName",
        "ProtectURL",
        "ProtectNotes",
    ] {
        let invalid = xml.replace(
            &format!("<{setting}>False</{setting}>"),
            &format!("<{setting}>sometimes</{setting}>"),
        );
        assert!(KdbxXml::import(invalid.as_bytes(), &KdbxReadLimits::default()).is_err());
    }

    let conflicting = xml.replace(
        "</MemoryProtection>",
        "<ProtectUsername>True</ProtectUsername></MemoryProtection>",
    );
    assert!(KdbxXml::import(conflicting.as_bytes(), &KdbxReadLimits::default()).is_err());

    let matching_aliases = xml.replace(
        "<ProtectUserName>False</ProtectUserName>",
        "<ProtectUserName>True</ProtectUserName><ProtectUsername>True</ProtectUsername>",
    );
    let loaded = KdbxXml::import(matching_aliases.as_bytes(), &KdbxReadLimits::default()).unwrap();
    assert!(loaded.can_save_losslessly);
    assert!(loaded.meta.protect_username);
}

#[test]
fn xml_allows_legal_whitespace_and_comments_outside_document_element() {
    let database = KeePassDatabase::default();
    let xml = String::from_utf8(KdbxXml::export(&database).unwrap()).unwrap();
    let declaration_end = xml.find("?>").unwrap() + 2;
    let legal = format!(
        "{} \t\r\n<!-- before root -->{} \n<!-- after root -->\r\n",
        &xml[..declaration_end],
        &xml[declaration_end..]
    );
    assert!(KdbxXml::import(legal.as_bytes(), &KdbxReadLimits::default()).is_ok());

    let without_declaration = &xml[declaration_end..];
    assert!(
        KdbxXml::import(
            format!(" \r\n{without_declaration}\t\n").as_bytes(),
            &KdbxReadLimits::default()
        )
        .is_ok()
    );

    for malformed in [
        format!("x{xml}"),
        format!("{xml}x"),
        format!("&#65;{xml}"),
        format!("{xml}&amp;"),
        format!("&#32;{xml}"),
        format!("{xml}&#xA;"),
    ] {
        assert!(KdbxXml::import(malformed.as_bytes(), &KdbxReadLimits::default()).is_err());
    }
}

#[test]
fn history_limits_reject_malformed_ranges_and_preserve_minus_one_sentinel() {
    let xml = String::from_utf8(KdbxXml::export(&KeePassDatabase::default()).unwrap()).unwrap();
    let with_limits = xml.replace(
        "<Meta>",
        "<Meta><HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>0</HistoryMaxSize>",
    );
    let loaded = KdbxXml::import(with_limits.as_bytes(), &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.meta.history_max_items, Some(-1));
    assert_eq!(loaded.meta.history_max_size, Some(0));
    let saved = KdbxXml::export(&loaded).unwrap();
    let saved = std::str::from_utf8(&saved).unwrap();
    assert!(saved.contains("<HistoryMaxItems>-1</HistoryMaxItems>"));
    assert!(saved.contains("<HistoryMaxSize>0</HistoryMaxSize>"));

    let mut maxima = KeePassDatabase::default();
    maxima.meta.history_max_items = Some(i64::from(i32::MAX));
    maxima.meta.history_max_size = Some(i64::MAX);
    let maximum_xml = KdbxXml::export(&maxima).unwrap();
    let maximum_loaded = KdbxXml::import(&maximum_xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(
        maximum_loaded.meta.history_max_items,
        Some(i64::from(i32::MAX))
    );
    assert_eq!(maximum_loaded.meta.history_max_size, Some(i64::MAX));

    for (items, size) in [
        (Some(-2), None),
        (Some(i64::from(i32::MAX) + 1), None),
        (None, Some(-2)),
    ] {
        let mut invalid = KeePassDatabase::default();
        invalid.meta.history_max_items = items;
        invalid.meta.history_max_size = size;
        assert!(KdbxXml::export(&invalid).is_err());
        let mut bytes = Vec::new();
        let mut credentials =
            neotales_keepass::KdbxCredentials::password("invalid-history-test").unwrap();
        assert!(
            KdbxFile::save(
                &invalid,
                &mut bytes,
                &mut credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..KdbxWriteOptions::default()
                },
                &KdbxReadLimits::default(),
            )
            .is_err()
        );
    }

    for (element, value) in [
        ("HistoryMaxItems", "bad"),
        ("HistoryMaxSize", "bad"),
        ("HistoryMaxItems", "-2"),
        ("HistoryMaxSize", "-2"),
        ("HistoryMaxItems", "2147483648"),
        ("HistoryMaxItems", "9223372036854775808"),
        ("HistoryMaxSize", "9223372036854775808"),
    ] {
        let invalid = xml.replace("<Meta>", &format!("<Meta><{element}>{value}</{element}>"));
        assert!(KdbxXml::import(invalid.as_bytes(), &KdbxReadLimits::default()).is_err());
    }
}

#[test]
fn metadata_custom_icons_and_custom_data_round_trip_through_xml() {
    let icon_id = KdbxUuid::from_bytes([0x11; 16]);
    let mut database = KeePassDatabase::default();
    database.root.id = KdbxUuid::from_bytes([0x01; 16]);
    database.root.custom_icon_id = icon_id;
    database.meta.generator = "KeePassXC".into();
    database.meta.name = "Metadata".into();
    database.meta.description = "Preserved <metadata>".into();
    database.meta.default_username = "keeper".into();
    database.meta.settings_changed = Some(timestamp(1_700_000_000));
    database.meta.database_name_changed = Some(timestamp(1_700_000_001));
    database.meta.database_description_changed = Some(timestamp(1_700_000_002));
    database.meta.default_username_changed = Some(timestamp(1_700_000_003));
    database.meta.master_key_changed = Some(timestamp(1_700_000_004));
    database
        .meta
        .custom_data
        .set("Plugin_Mode", "fidelity", Some(timestamp(1_700_000_005)));
    database
        .meta
        .custom_data
        .set("Plugin_Count", "7", Some(timestamp(1_700_000_006)));
    database.meta.custom_icons.push(CustomIcon {
        uuid: icon_id,
        data: vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
        name: Some("custom & icon".into()),
        last_modification: Some(timestamp(1_700_000_007)),
    });

    let mut entry = Entry::new("icon user");
    entry.id = KdbxUuid::from_bytes([0x02; 16]);
    entry.custom_icon_id = icon_id;
    entry.icon_id = 17;
    entry.custom_data.set("Entry_Plugin", "value", None);
    database.root.entries.push(entry);

    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.meta, database.meta);
    assert_eq!(loaded.root.id, database.root.id);
    assert_eq!(loaded.root.custom_icon_id, icon_id);
    assert_eq!(loaded.root.entries[0].id, database.root.entries[0].id);
    assert_eq!(loaded.root.entries[0].icon_id, 17);
    assert_eq!(loaded.root.entries[0].custom_icon_id, icon_id);
    assert_eq!(
        loaded.root.entries[0].custom_data,
        database.root.entries[0].custom_data
    );

    let limits = KdbxReadLimits::default();
    let mut kdbx = Vec::new();
    KdbxFile::save(
        &loaded,
        &mut kdbx,
        &mut neotales_keepass::KdbxCredentials::password("custom-icon-test").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let reopened = KdbxFile::load_password(kdbx.as_slice(), "custom-icon-test", &limits).unwrap();
    assert_eq!(reopened.root.custom_icon_id, icon_id);
    assert_eq!(reopened.meta.custom_icons[0].uuid, icon_id);
    let reexported = KdbxXml::export(&reopened).unwrap();
    let reimported = KdbxXml::import(&reexported, &limits).unwrap();
    assert_eq!(reimported.root.custom_icon_id, icon_id);
    assert_eq!(reimported.meta.custom_icons[0].uuid, icon_id);
}

#[test]
fn save_preserves_entry_and_history_tags_and_nested_group_custom_icons() {
    let limits = KdbxReadLimits::default();
    let icon_id = KdbxUuid::from_bytes([0x31; 16]);
    let mut database = KeePassDatabase::default();
    database.meta.custom_icons.push(CustomIcon {
        uuid: icon_id,
        data: vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff],
        name: Some("nested group icon".into()),
        last_modification: None,
    });

    let mut nested = neotales_keepass::Group::new("nested");
    nested.custom_icon_id = icon_id;
    let mut entry = Entry::new("current");
    entry.tags = vec!["work".into(), "finance".into()];
    let mut snapshot = Entry::new("previous");
    snapshot.tags = vec!["archived".into(), "review".into()];
    entry.history.push(snapshot);
    nested.entries.push(entry);
    database.root.groups.push(nested);

    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let mut loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(loaded.root.groups[0].custom_icon_id, icon_id);
    assert_eq!(loaded.meta.custom_icons[0].uuid, icon_id);
    assert_eq!(
        loaded.meta.custom_icons[0].data,
        [0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]
    );
    assert_eq!(loaded.root.groups[0].entries[0].tags, ["work", "finance"]);
    assert_eq!(
        loaded.root.groups[0].entries[0].history[0].tags,
        ["archived", "review"]
    );

    loaded.meta.name = "edited independently".into();
    let mut saved = Vec::new();
    KdbxFile::save(
        &loaded,
        &mut saved,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let reopened = KdbxFile::load_password(saved.as_slice(), "pw", &limits).unwrap();
    assert_eq!(reopened.root.groups[0].custom_icon_id, icon_id);
    assert_eq!(
        reopened.meta.custom_icons[0].data,
        loaded.meta.custom_icons[0].data
    );
    assert_eq!(reopened.root.groups[0].entries[0].tags, ["work", "finance"]);
    assert_eq!(
        reopened.root.groups[0].entries[0].history[0].tags,
        ["archived", "review"]
    );
}

#[test]
fn tag_constraints_reject_unrepresentable_current_and_history_tags_before_output() {
    let limits = KdbxReadLimits::default();
    for bad_tag in ["", "a;b"] {
        for history in [false, true] {
            let mut database = KeePassDatabase::default();
            let mut entry = Entry::new("tagged");
            if history {
                let mut snapshot = Entry::new("snapshot");
                snapshot.tags.push(bad_tag.into());
                entry.history.push(snapshot);
            } else {
                entry.tags.push(bad_tag.into());
            }
            database.root.entries.push(entry);

            let mut output = b"existing".to_vec();
            let error = KdbxFile::save(
                &database,
                &mut output,
                &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..KdbxWriteOptions::default()
                },
                &limits,
            )
            .unwrap_err();
            assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
            assert_eq!(output, b"existing");
        }
    }
}

#[test]
fn tags_with_xml_special_characters_round_trip_in_current_and_history_entries() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("tagged");
    entry.tags = vec![
        "research & planning".into(),
        "<review>".into(),
        "carriage\rreturn".into(),
        "line\r\nbreak".into(),
    ];
    let mut snapshot = Entry::new("snapshot");
    snapshot.tags = vec![
        "history & archive".into(),
        "<old>".into(),
        "history\rtag".into(),
        "history\r\nline".into(),
    ];
    entry.history.push(snapshot);
    database.root.tags = vec!["group\rtag".into(), "group\r\nline".into()];
    database.root.entries.push(entry);

    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(
        loaded.root.entries[0].tags,
        [
            "research & planning",
            "<review>",
            "carriage\rreturn",
            "line\r\nbreak"
        ]
    );
    assert_eq!(
        loaded.root.entries[0].history[0].tags,
        [
            "history & archive",
            "<old>",
            "history\rtag",
            "history\r\nline"
        ]
    );
    assert_eq!(loaded.root.tags, ["group\rtag", "group\r\nline"]);
}

#[test]
fn public_header_custom_data_preserves_all_variant_types() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.typed_public_custom_data.set("u32", 7_u32);
    database.typed_public_custom_data.set("u64", 8_u64);
    database.typed_public_custom_data.set("bool", true);
    database.typed_public_custom_data.set("i32", -9_i32);
    database.typed_public_custom_data.set("i64", -10_i64);
    database
        .typed_public_custom_data
        .set("string", "header plugin");
    database
        .typed_public_custom_data
        .set("bytes", vec![0x00, 0xff, 0x42]);
    database.typed_public_custom_data.set("u32", 11_u32);

    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(
        loaded.typed_public_custom_data,
        database.typed_public_custom_data
    );
    assert_eq!(
        loaded.public_custom_data.get("string"),
        Some("header plugin")
    );
    assert_eq!(
        loaded.typed_public_custom_data.items()[0].value,
        VariantValue::UInt32(11)
    );
    assert!(KdbxXml::export(&loaded).is_err());
}

#[test]
fn string_public_header_custom_data_preserves_existing_api() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .public_custom_data
        .set("Plugin_Key", "plugin value", None);
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(loaded.public_custom_data, database.public_custom_data);
    assert!(matches!(
        loaded.typed_public_custom_data.get("Plugin_Key"),
        Some(VariantValue::String(value)) if value == "plugin value"
    ));
}

#[test]
fn protected_empty_and_shared_attachments_round_trip_in_order() {
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    let shared = database
        .binary_pool
        .add(b"shared protected attachment".to_vec(), true);
    let empty = database.binary_pool.add(Vec::new(), true);
    let plain = database.binary_pool.add(b"plain".to_vec(), false);

    let mut entry = Entry::new("attachments");
    entry.set_field(Field {
        key: "Password".into(),
        value: ProtectedValue::from_text("first protected field"),
        protected: true,
        protect_in_memory: true,
    });
    entry.attachments.push(Attachment {
        name: "shared.txt".into(),
        reference: shared,
    });
    entry.attachments.push(Attachment {
        name: "empty.bin".into(),
        reference: empty,
    });
    entry.attachments.push(Attachment {
        name: "plain.bin".into(),
        reference: plain,
    });

    let mut snapshot = Entry::new("attachments");
    snapshot.id = entry.id;
    snapshot.attachments.push(Attachment {
        name: "history-shared.txt".into(),
        reference: shared,
    });
    entry.history.push(snapshot);
    database.root.entries.push(entry);

    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            compression: neotales_keepass::KdbxCompression::GZip,
            ..KdbxWriteOptions::default()
        },
        &limits,
    )
    .unwrap();
    let loaded = KdbxFile::load_password(bytes.as_slice(), "pw", &limits).unwrap();
    assert_eq!(loaded.binary_pool.records().len(), 3);
    assert!(loaded.binary_pool.records()[0].protected);
    assert_eq!(
        loaded.binary_pool.records()[0].data,
        b"shared protected attachment"
    );
    assert!(loaded.binary_pool.records()[1].protected);
    assert!(loaded.binary_pool.records()[1].data.is_empty());
    assert!(!loaded.binary_pool.records()[2].protected);
    assert_eq!(loaded.binary_pool.records()[2].data, b"plain");

    let entry = &loaded.root.entries[0];
    assert_eq!(entry.attachments[0].reference, shared);
    assert_eq!(entry.attachments[1].reference, empty);
    assert_eq!(entry.history[0].attachments[0].reference, shared);
    assert_eq!(
        entry
            .field("Password")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "first protected field"
    );
}

#[test]
fn shared_legacy_xml_attachments_round_trip() {
    let mut database = KeePassDatabase::default();
    let shared = database.binary_pool.add(b"one shared pool".to_vec(), false);
    database.binary_pool.add(Vec::new(), false);
    let mut first = Entry::new("first");
    first.attachments.push(Attachment {
        name: "first.bin".into(),
        reference: shared,
    });
    first.attachments.push(Attachment {
        name: "first-alias.bin".into(),
        reference: shared,
    });
    let mut second = Entry::new("second");
    second.attachments.push(Attachment {
        name: "second.bin".into(),
        reference: shared,
    });
    database.root.entries.push(first);
    database.root.entries.push(second);

    let xml = KdbxXml::export(&database).unwrap();
    let loaded = KdbxXml::import(&xml, &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.meta.legacy_binaries.len(), 2);
    assert_eq!(loaded.binary_pool.records()[0].data, b"one shared pool");
    assert_eq!(loaded.root.entries[0].attachments[0].reference, 0);
    assert_eq!(loaded.root.entries[0].attachments[1].reference, 0);
    assert_eq!(loaded.root.entries[1].attachments[0].reference, 0);
}

#[test]
fn mixed_legacy_and_inline_xml_binaries_normalize_and_round_trip() {
    let mut source = KeePassDatabase::default();
    let declared = source.binary_pool.add(b"declared-payload".to_vec(), false);
    let mut entry = Entry::new("mixed attachments");
    entry.attachments.push(Attachment {
        name: "declared.bin".into(),
        reference: declared,
    });
    source.root.add_entry(entry);

    let xml = String::from_utf8(KdbxXml::export(&source).unwrap()).unwrap();
    let mixed = xml.replacen(
        "</Entry>",
        "<Binary><Key>inline.bin</Key><Value>aW5saW5lLXBheWxvYWQ=</Value></Binary></Entry>",
        1,
    );
    let loaded = KdbxXml::import(mixed.as_bytes(), &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.binary_pool.len(), 2);
    assert_eq!(loaded.meta.legacy_binaries.len(), 2);
    assert_eq!(loaded.meta.legacy_binaries[0], b"declared-payload");
    assert_eq!(loaded.meta.legacy_binaries[1], b"inline-payload");

    let mut kdbx = Vec::new();
    KdbxFile::save(
        &loaded,
        &mut kdbx,
        &mut neotales_keepass::KdbxCredentials::password("mixed-binary-test").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let reopened = KdbxFile::load_password(
        kdbx.as_slice(),
        "mixed-binary-test",
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert!(reopened.meta.legacy_binaries.is_empty());
    assert_eq!(reopened.binary_pool.len(), 2);
    let exported = KdbxXml::export(&reopened).unwrap();
    let round_trip = KdbxXml::import(&exported, &KdbxReadLimits::default()).unwrap();
    assert_eq!(round_trip.meta.legacy_binaries.len(), 2);
    assert_eq!(round_trip.root.entries[0].attachments.len(), 2);
    for attachment in &round_trip.root.entries[0].attachments {
        let data = &round_trip.binary_pool.records()[attachment.reference].data;
        match attachment.name.as_str() {
            "declared.bin" => assert_eq!(data, b"declared-payload"),
            "inline.bin" => assert_eq!(data, b"inline-payload"),
            other => panic!("unexpected attachment name: {other}"),
        }
    }
}

#[test]
fn unknown_xml_extensions_load_but_block_lossless_save() {
    let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Generator>test</Generator><Plugin><Payload>keep</Payload></Plugin></Meta>
<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#;
    let database = KdbxXml::import(xml, &KdbxReadLimits::default()).unwrap();
    assert!(!database.can_save_losslessly);
    assert!(KdbxXml::export(&database).is_err());

    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}

#[test]
fn writer_rejects_disagreeing_binary_pools_and_converts_legacy_only_data() {
    let mut database = KeePassDatabase::default();
    database.binary_pool.add(b"inner".to_vec(), false);
    database.meta.legacy_binaries.push(b"different".to_vec());
    let error = KdbxFile::save(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);

    let mut database = KeePassDatabase::default();
    database.meta.legacy_binaries.push(b"legacy only".to_vec());
    let mut entry = Entry::new("legacy attachment");
    entry.attachments.push(Attachment {
        name: "data.bin".into(),
        reference: 0,
    });
    database.root.entries.push(entry);
    let mut bytes = Vec::new();
    KdbxFile::save(
        &database,
        &mut bytes,
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let loaded =
        KdbxFile::load_password(bytes.as_slice(), "pw", &KdbxReadLimits::default()).unwrap();
    assert_eq!(loaded.binary_pool.get(0).unwrap().data, b"legacy only");
}

#[test]
fn writer_rejects_invalid_unprotected_field_bytes_instead_of_replacing_them() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("invalid utf8");
    entry.set_field(Field {
        key: "Note".into(),
        value: ProtectedValue::from_bytes_unprotected(vec![0xff]),
        protected: false,
        protect_in_memory: false,
    });
    database.root.entries.push(entry);
    let error = KdbxFile::save(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Malformed);
}

#[test]
fn kdbx3_writer_rejects_kdbx4_only_public_data_and_fields() {
    let mut database = KeePassDatabase::default();
    database
        .typed_public_custom_data
        .set("plugin", "must not be dropped");
    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);

    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("quality"));
    database.root.entries[0].quality_check = Some(true);
    let error = KdbxFile::save_kdbx3(
        &database,
        &mut Vec::new(),
        &mut neotales_keepass::KdbxCredentials::password("pw").unwrap(),
        neotales_keepass::Kdbx3WriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}

#[test]
fn plain_xml_rejects_a_protected_password_in_history() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("current");
    let mut snapshot = Entry::new("historical password");
    snapshot.password = ProtectedValue::from_text("history secret");
    entry.history.push(snapshot);
    database.root.entries.push(entry);

    let error = KdbxXml::export(&database).unwrap_err();
    assert_eq!(error.kind, neotales_keepass::KdbxFailureKind::Unsupported);
}
