#![allow(missing_docs)]

use neotales_keepass::{
    Kdbx3WriteOptions, KdbxCompression, KdbxCredentials, KdbxFile, KdbxKdf, KdbxOuterCipher,
    KdbxPreservingWriteOptions, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

fn credentials() -> KdbxCredentials {
    KdbxCredentials::password("test-only-password").unwrap()
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
                let (database, source) =
                    KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits)
                        .unwrap();
                assert_eq!(source.version(), 0x0004_0001);
                let KdbxPreservingWriteOptions::Kdbx4(options) =
                    source.write_options(&limits).unwrap()
                else {
                    panic!("wrong version")
                };
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
                KdbxFile::save_preserving_source(
                    &database,
                    &mut saved,
                    &mut credentials(),
                    source,
                    &limits,
                )
                .unwrap();
                let (_, reloaded) =
                    KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits)
                        .unwrap();
                assert_eq!(source, reloaded);
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
    let (database, source) =
        KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
    assert_eq!(source.version(), 0x0003_0001);
    let KdbxPreservingWriteOptions::Kdbx3(options) = source.write_options(&limits).unwrap() else {
        panic!("wrong version")
    };
    assert_eq!(options.aes_kdf_rounds, 23);
    assert_eq!(options.compression, KdbxCompression::GZip);
    let mut saved = Vec::new();
    KdbxFile::save_preserving_source(&database, &mut saved, &mut credentials(), source, &limits)
        .unwrap();
    let (_, reloaded) =
        KdbxFile::load_with_source(saved.as_slice(), &mut credentials(), &limits).unwrap();
    assert_eq!(source, reloaded);
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
        let (database, source) =
            KdbxFile::load_with_source(bytes.as_slice(), &mut credentials(), &limits).unwrap();
        let path = dir
            .path()
            .join(if legacy { "legacy.kdbx" } else { "modern.kdbx" });
        KdbxFile::save_preserving_source(
            &database,
            std::fs::File::create(&path).unwrap(),
            &mut credentials(),
            source,
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
