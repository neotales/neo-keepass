// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

//! Optional external-client check. Fixture tests remain unconditional in roundtrip.rs.
use std::io::Write;
use std::process::{Command, Stdio};

use neotales_keepass::{
    Attachment, Entry, Kdbx3WriteOptions, KdbxCompression, KdbxCredentials, KdbxFile, KdbxKdf,
    KdbxOuterCipher, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase, ProtectedValue,
};

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_argon2_variants() {
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database.root.entries.push(Entry::new("argon2-interop"));
    for kdf in [KdbxKdf::Argon2d, KdbxKdf::Argon2id] {
        let path = directory.path().join(format!("{kdf:?}.kdbx"));
        let mut file = std::fs::File::create(&path).unwrap();
        KdbxFile::save(
            &database,
            &mut file,
            &mut KdbxCredentials::password("argon2-interop-password").unwrap(),
            KdbxWriteOptions {
                kdf,
                argon2_memory_kib: 32,
                argon2_time: 1,
                argon2_lanes: 1,
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &limits,
        )
        .unwrap();
        drop(file);

        let mut child = Command::new("keepassxc-cli")
            .arg("db-info")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"argon2-interop-password\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "KeePassXC could not list {kdf:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Number of entries: 1"));
    }
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_kdbx3_variants() {
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .root
        .entries
        .push(Entry::new("kdbx3-external-client-check"));

    for compression in [KdbxCompression::None, KdbxCompression::GZip] {
        let path = directory.path().join(format!("kdbx3-{compression:?}.kdbx"));
        let mut file = std::fs::File::create(&path).unwrap();
        KdbxFile::save_kdbx3(
            &database,
            &mut file,
            &mut KdbxCredentials::password("kdbx3-interop-password").unwrap(),
            Kdbx3WriteOptions {
                compression,
                aes_kdf_rounds: 8,
                block_bytes: 1024,
            },
            &limits,
        )
        .unwrap();
        drop(file);

        let mut child = Command::new("keepassxc-cli")
            .arg("db-info")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"kdbx3-interop-password\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "KeePassXC could not list KDBX3/{compression:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info = String::from_utf8_lossy(&output.stdout);
        assert!(
            info.contains("Number of entries: 1"),
            "KeePassXC did not read the KDBX3 entry count: {info}"
        );
    }
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_opens_written_cipher_and_compression_matrix() {
    // Only absence skips this test; an installed but broken CLI fails the gate.
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );

    let directory = tempfile::tempdir().unwrap();
    let limits = KdbxReadLimits::default();
    let mut database = KeePassDatabase::default();
    database
        .root
        .entries
        .push(Entry::new("external-client-check"));

    for cipher in [KdbxOuterCipher::Aes, KdbxOuterCipher::ChaCha20] {
        for compression in [KdbxCompression::None, KdbxCompression::GZip] {
            let path = directory
                .path()
                .join(format!("{cipher:?}-{compression:?}.kdbx"));
            let mut file = std::fs::File::create(&path).unwrap();
            KdbxFile::save(
                &database,
                &mut file,
                &mut KdbxCredentials::password("interop-test-password").unwrap(),
                KdbxWriteOptions {
                    cipher,
                    compression,
                    aes_kdf_rounds: 8,
                    ..KdbxWriteOptions::default()
                },
                &limits,
            )
            .unwrap();
            drop(file);

            let mut child = Command::new("keepassxc-cli")
                .arg("db-info")
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"interop-test-password\n")
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "KeePassXC could not list {cipher:?}/{compression:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let info = String::from_utf8_lossy(&output.stdout);
            assert!(
                info.contains("Number of entries: 1"),
                "KeePassXC did not read the entry count for {cipher:?}/{compression:?}: {info}"
            );
            let expected_cipher = match cipher {
                KdbxOuterCipher::Aes => "Cipher: AES 256-bit",
                KdbxOuterCipher::ChaCha20 => "Cipher: ChaCha20 256-bit",
            };
            assert!(
                info.contains(expected_cipher),
                "KeePassXC cipher mismatch: {info}"
            );
        }
    }
}

fn run_keepassxc(args: &[&str], stdin_data: &str) -> std::process::Output {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_roundtrips_protected_attachment_and_entry_password() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("protected-attachment.kdbx");
    let export_path = directory.path().join("exported.bin");

    let mut database = KeePassDatabase::default();
    let payload = b"protected-kdbx4-attachment-payload-0123456789";
    let reference = database.binary_pool.add(payload.to_vec(), true);
    let mut entry = Entry::new("AttachmentEntry");
    entry.username = "alice".into();
    entry.password = ProtectedValue::from_text("entry-password-after-attachment");
    entry.attachments.push(Attachment {
        name: "secret.bin".into(),
        reference,
    });
    database.root.entries.push(entry);

    let mut file = std::fs::File::create(&vault_path).unwrap();
    KdbxFile::save(
        &database,
        &mut file,
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        KdbxWriteOptions {
            cipher: KdbxOuterCipher::ChaCha20,
            compression: KdbxCompression::GZip,
            kdf: KdbxKdf::Argon2id,
            argon2_memory_kib: 64,
            argon2_time: 2,
            argon2_lanes: 1,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    drop(file);

    let show = run_keepassxc(
        &[
            "show",
            "-s",
            vault_path.to_str().unwrap(),
            "AttachmentEntry",
        ],
        "interop-pw\n",
    );
    assert!(
        show.status.success(),
        "keepassxc-cli show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(
        stdout.contains("Password: entry-password-after-attachment"),
        "expected clear password from keepassxc-cli show -s, got:\n{stdout}"
    );

    let export = run_keepassxc(
        &[
            "attachment-export",
            vault_path.to_str().unwrap(),
            "AttachmentEntry",
            "secret.bin",
            export_path.to_str().unwrap(),
        ],
        "interop-pw\n",
    );
    assert!(
        export.status.success(),
        "keepassxc-cli attachment-export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(std::fs::read(&export_path).unwrap(), payload);

    // Reload and verify our own loader preserves the exact bytes, flag, password, and write options.
    let loaded = KdbxFile::load(
        std::fs::File::open(&vault_path).unwrap(),
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert!(loaded.binary_pool.records()[0].protected);
    assert_eq!(loaded.binary_pool.records()[0].data, payload);
    assert_eq!(
        loaded.root.entries[0]
            .password
            .reveal_text()
            .unwrap()
            .as_str(),
        "entry-password-after-attachment"
    );
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
fn keepassxc_cli_edit_history_and_argon2id_chacha20_gzip_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("history-roundtrip.kdbx");
    let resaved_path = directory.path().join("resaved.kdbx");

    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("HistoryItem");
    entry.username = "bob".into();
    entry.password = ProtectedValue::from_text("initial-secret");
    database.root.entries.push(entry);

    KdbxFile::save(
        &database,
        std::fs::File::create(&vault_path).unwrap(),
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        KdbxWriteOptions {
            cipher: KdbxOuterCipher::ChaCha20,
            compression: KdbxCompression::GZip,
            kdf: KdbxKdf::Argon2id,
            argon2_memory_kib: 64,
            argon2_time: 2,
            argon2_lanes: 1,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    // Have keepassxc-cli edit the entry password, creating a real KeePassXC history snapshot.
    let edit = run_keepassxc(
        &["edit", "-p", vault_path.to_str().unwrap(), "HistoryItem"],
        "interop-pw\nupdated-secret\n",
    );
    assert!(
        edit.status.success(),
        "keepassxc-cli edit failed: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let show = run_keepassxc(
        &["show", "-s", vault_path.to_str().unwrap(), "HistoryItem"],
        "interop-pw\n",
    );
    assert!(show.status.success());
    let show_stdout = String::from_utf8_lossy(&show.stdout);
    assert!(
        show_stdout.contains("Password: updated-secret"),
        "expected updated-secret from keepassxc-cli show -s: {show_stdout}"
    );

    // Load the keepassxc-edited vault, verify current + history passwords and preserved KDBX4 options,
    // re-save with preserved write_options, and verify keepassxc-cli db-info + show -s match.
    let loaded = KdbxFile::load(
        std::fs::File::open(&vault_path).unwrap(),
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let loaded_entry = &loaded.root.entries[0];
    assert_eq!(
        loaded_entry.password.reveal_text().unwrap().as_str(),
        "updated-secret"
    );
    assert_eq!(loaded_entry.history.len(), 1);
    assert_eq!(
        loaded_entry.history[0]
            .password
            .reveal_text()
            .unwrap()
            .as_str(),
        "initial-secret"
    );
    let preserved = loaded.write_options.unwrap();
    assert_eq!(preserved.cipher, KdbxOuterCipher::ChaCha20);
    assert_eq!(preserved.compression, KdbxCompression::GZip);
    assert_eq!(preserved.kdf, KdbxKdf::Argon2id);
    assert_eq!(preserved.argon2_memory_kib, 64);
    assert_eq!(preserved.argon2_time, 2);
    assert_eq!(preserved.argon2_lanes, 1);

    KdbxFile::save(
        &loaded,
        std::fs::File::create(&resaved_path).unwrap(),
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        preserved,
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let info = run_keepassxc(&["db-info", resaved_path.to_str().unwrap()], "interop-pw\n");
    assert!(info.status.success());
    let info_stdout = String::from_utf8_lossy(&info.stdout);
    assert!(
        info_stdout.contains("Cipher: ChaCha20 256-bit"),
        "{info_stdout}"
    );
    assert!(
        info_stdout.contains("KDF: Argon2id (2 rounds, 64 KB)"),
        "{info_stdout}"
    );

    let reloaded = KdbxFile::load(
        std::fs::File::open(&resaved_path).unwrap(),
        &mut KdbxCredentials::password("interop-pw").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let reloaded_opts = reloaded.write_options.unwrap();
    assert_eq!(reloaded_opts.cipher, KdbxOuterCipher::ChaCha20);
    assert_eq!(reloaded_opts.compression, KdbxCompression::GZip);
    assert_eq!(reloaded_opts.kdf, KdbxKdf::Argon2id);

    let reshow = run_keepassxc(
        &["show", "-s", resaved_path.to_str().unwrap(), "HistoryItem"],
        "interop-pw\n",
    );
    assert!(reshow.status.success());
    assert!(String::from_utf8_lossy(&reshow.stdout).contains("Password: updated-secret"));
}
