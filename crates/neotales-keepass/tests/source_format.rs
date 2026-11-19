#![allow(missing_docs)]

use neotales_keepass::{
    Kdbx3WriteOptions, KdbxCompression, KdbxCredentials, KdbxFile, KdbxKdf, KdbxOuterCipher,
    KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

fn credentials() -> KdbxCredentials {
    KdbxCredentials::password("test-only-password").unwrap()
}

#[test]
fn scalar_edits_reject_xml_invalid_characters_without_mutation() {
    let limits = KdbxReadLimits::default();
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut credentials(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &limits,
    )
    .unwrap();
    let mut doc =
        KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
    for invalid in ["\0", "\u{1}", "\u{b}", "\u{fffe}"] {
        assert!(doc.create_entry(&[], invalid).is_err());
    }
    assert!(doc.database().root.entries.is_empty());
    let index = doc.create_entry(&[], "valid λ\r\n\t").unwrap();
    for invalid in ["\0", "\u{1}", "\u{b}", "\u{fffe}"] {
        assert!(doc.set_entry_field(&[], index, invalid, "good").is_err());
        assert!(
            doc.set_entry_field(&[], index, "Password", invalid)
                .is_err()
        );
        assert!(doc.set_entry_field(&[], index, "custom", invalid).is_err());
    }
    assert!(doc.database().root.entries[index].fields.is_empty());
    doc.set_entry_field(&[], index, "custom λ", "valid 🦀\r\n\t")
        .unwrap();
    let mut saved = Vec::new();
    doc.save_preserving_source(&mut saved, &mut credentials(), &limits)
        .unwrap();
    let loaded = KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits).unwrap();
    let entry = &loaded.database().root.entries[index];
    assert_eq!(entry.title, "valid λ\r\n\t");
    assert_eq!(
        entry
            .field("custom λ")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "valid 🦀\r\n\t"
    );
}

#[test]
fn scalar_edits_create_and_update_nested_entries_without_imports() {
    let limits = KdbxReadLimits::default();
    let mut model = KeePassDatabase::default();
    model
        .root
        .groups
        .push(neotales_keepass::Group::new("nested"));
    let mut bytes = Vec::new();
    KdbxFile::save(
        &model,
        &mut bytes,
        &mut credentials(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &limits,
    )
    .unwrap();
    let mut doc =
        KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
    assert!(doc.create_entry(&[1], "bad").is_err());
    let index = doc.create_entry(&[0], "entry").unwrap();
    doc.set_entry_field(&[0], index, "Password", "test-value")
        .unwrap();
    doc.set_entry_field(&[0], index, "UserName", "test-user")
        .unwrap();
    doc.set_entry_field(&[0], index, "Title", "renamed")
        .unwrap();
    doc.set_entry_field(&[0], index, "custom", "first").unwrap();
    doc.set_entry_field(&[0], index, "custom", "second")
        .unwrap();
    assert!(
        doc.set_entry_field(&[0], index + 1, "custom", "bad")
            .is_err()
    );
    let entry = &doc.database().root.groups[0].entries[index];
    assert_eq!(entry.title, "renamed");
    assert_eq!(entry.username, "test-user");
    assert!(entry.field("Password").unwrap().protected);
    assert_eq!(
        entry
            .field("custom")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "second"
    );
    let mut saved = Vec::new();
    doc.save_preserving_source(&mut saved, &mut credentials(), &limits)
        .unwrap();
    let loaded = KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits).unwrap();
    let entry = &loaded.database().root.groups[0].entries[index];
    assert_eq!(entry.title, "renamed");
    assert_eq!(
        entry
            .field("Password")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "test-value"
    );
    assert!(entry.field("Password").unwrap().protected);
}

#[test]
fn different_databases_cannot_exchange_source_settings() {
    let limits = KdbxReadLimits::default();
    let mut strong = Vec::new();
    let mut weak = Vec::new();
    for (out, rounds) in [(&mut strong, 41), (&mut weak, 17)] {
        KdbxFile::save(
            &KeePassDatabase::default(),
            out,
            &mut credentials(),
            KdbxWriteOptions {
                aes_kdf_rounds: rounds,
                ..Default::default()
            },
            &limits,
        )
        .unwrap();
    }
    let mut strong_doc =
        KdbxFile::load_with_source(strong.as_slice(), &mut credentials(), &limits).unwrap();
    let mut weak_doc =
        KdbxFile::load_with_source(weak.as_slice(), &mut credentials(), &limits).unwrap();
    strong_doc.create_entry(&[], "strong").unwrap();
    weak_doc.create_entry(&[], "weak").unwrap();
    for (doc, rounds, label) in [(&strong_doc, 41, "strong"), (&weak_doc, 17, "weak")] {
        let mut saved = Vec::new();
        doc.save_preserving_source(&mut saved, &mut credentials(), &limits)
            .unwrap();
        let loaded =
            KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits).unwrap();
        assert_eq!(loaded.source_options().aes_kdf_rounds, rounds);
        assert_eq!(loaded.database().root.entries[0].title, label);
    }
}

#[test]
fn preserving_roundtrips_all_supported_kdf_cipher_and_compression_modes() {
    let limits = KdbxReadLimits::default();
    for kdf in [KdbxKdf::Aes, KdbxKdf::Argon2d, KdbxKdf::Argon2id] {
        for cipher in [KdbxOuterCipher::Aes, KdbxOuterCipher::ChaCha20] {
            for compression in [KdbxCompression::None, KdbxCompression::GZip] {
                let original = KdbxWriteOptions {
                    kdf,
                    cipher,
                    compression,
                    aes_kdf_rounds: 17,
                    argon2_memory_kib: 64,
                    argon2_time: 2,
                    argon2_lanes: 2,
                    ..Default::default()
                };
                let mut bytes = Vec::new();
                KdbxFile::save(
                    &KeePassDatabase::default(),
                    &mut bytes,
                    &mut credentials(),
                    original,
                    &limits,
                )
                .unwrap();
                let document =
                    KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits)
                        .unwrap();
                assert_eq!(document.source_version(), 0x0004_0001);
                let options = document.source_options();
                assert_eq!(options.kdf, kdf);
                assert_eq!(options.cipher, cipher);
                assert_eq!(options.compression, compression);
                if kdf == KdbxKdf::Aes {
                    assert_eq!(options.aes_kdf_rounds, 17);
                } else {
                    assert_eq!(
                        (
                            options.argon2_memory_kib,
                            options.argon2_time,
                            options.argon2_lanes
                        ),
                        (64, 2, 2)
                    );
                }
                let mut saved = Vec::new();
                document
                    .save_preserving_source(&mut saved, &mut credentials(), &limits)
                    .unwrap();
                let reloaded =
                    KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits)
                        .unwrap();
                assert_eq!(document.source_options(), reloaded.source_options());
                assert_ne!(bytes, saved);
            }
        }
    }
}

#[test]
fn preserving_kdbx3_roundtrips_and_rejects_wrong_credentials() {
    let limits = KdbxReadLimits::default();
    let mut bytes = Vec::new();
    KdbxFile::save_kdbx3(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut credentials(),
        Kdbx3WriteOptions {
            compression: KdbxCompression::GZip,
            aes_kdf_rounds: 23,
            ..Default::default()
        },
        &limits,
    )
    .unwrap();
    assert!(
        KdbxFile::load_with_source(
            bytes.as_slice(),
            &mut KdbxCredentials::password("wrong").unwrap(),
            &limits
        )
        .is_err()
    );
    let document =
        KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
    assert_eq!(document.source_version(), 0x0003_0001);
    let options = document.source_options();
    assert_eq!(options.aes_kdf_rounds, 23);
    assert_eq!(options.compression, KdbxCompression::GZip);
    let mut saved = Vec::new();
    document
        .save_preserving_source(&mut saved, &mut credentials(), &limits)
        .unwrap();
    let reloaded =
        KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits).unwrap();
    assert_eq!(document.source_options(), reloaded.source_options());
}

#[test]
fn tampered_header_and_wrong_password_return_no_metadata() {
    let limits = KdbxReadLimits::default();
    let mut bytes = Vec::new();
    KdbxFile::save(
        &KeePassDatabase::default(),
        &mut bytes,
        &mut credentials(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &limits,
    )
    .unwrap();
    assert!(
        KdbxFile::load_with_source(
            bytes.as_slice(),
            &mut KdbxCredentials::password("wrong").unwrap(),
            &limits
        )
        .is_err()
    );
    bytes[8] = 0;
    assert!(KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).is_err());
}

#[test]
#[ignore = "requires keepassxc-cli"]
fn keepassxc_reads_source_preserving_writes() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let limits = KdbxReadLimits::default();
    let dir = tempfile::tempdir().unwrap();
    for legacy in [false, true] {
        let mut bytes = Vec::new();
        if legacy {
            KdbxFile::save_kdbx3(
                &KeePassDatabase::default(),
                &mut bytes,
                &mut credentials(),
                Kdbx3WriteOptions {
                    aes_kdf_rounds: 17,
                    ..Default::default()
                },
                &limits,
            )
            .unwrap();
        } else {
            KdbxFile::save(
                &KeePassDatabase::default(),
                &mut bytes,
                &mut credentials(),
                KdbxWriteOptions {
                    kdf: KdbxKdf::Argon2id,
                    cipher: KdbxOuterCipher::ChaCha20,
                    argon2_memory_kib: 64,
                    argon2_time: 2,
                    argon2_lanes: 2,
                    ..Default::default()
                },
                &limits,
            )
            .unwrap();
        }
        let mut document =
            KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
        let entry = document.create_entry(&[], "valid λ\r\n\t").unwrap();
        document
            .set_entry_field(&[], entry, "custom λ", "valid 🦀\r\n\t")
            .unwrap();
        let path = dir
            .path()
            .join(if legacy { "legacy.kdbx" } else { "modern.kdbx" });
        document
            .save_preserving_source(
                std::fs::File::create(&path).unwrap(),
                &mut credentials(),
                &limits,
            )
            .unwrap();
        let mut child = Command::new("keepassxc-cli")
            .arg("db-info")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"test-only-password\n")
            .unwrap();
        assert!(child.wait().unwrap().success());
    }
}
