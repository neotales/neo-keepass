use std::process::{Command, Stdio};

use neotales_keepass::{
    KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

#[test]
fn password_value_compatibility_is_documented_and_stdin_conflicts_fail_closed() {
    let help = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .arg("--help")
        .output()
        .unwrap();
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help.status.success());
    assert!(help_text.contains("--password VALUE"));
    assert!(help_text.contains("process listings and"));
    assert!(help_text.contains("shell history"));

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("password-mode.kdbx");
    // The command must reject the ambiguous input before it tries to open a
    // vault, so this disposable path need not contain a valid database.
    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "setx",
            "--key",
            "LOGIN",
            "--stdin",
            "--password-stdin",
        ])
        .env("XDG_CONFIG_HOME", tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("stdin cannot carry both password and value"));
    assert!(!stderr.contains("LOGIN"));

    KdbxFile::save(
        &KeePassDatabase::default(),
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("disposable-password-value").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "ls",
            "--password",
            "disposable-password-value",
        ])
        .env("XDG_CONFIG_HOME", tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    assert!(
        !combined
            .windows(b"disposable-password-value".len())
            .any(|window| window == b"disposable-password-value")
    );
    assert!(
        !combined
            .windows(b"LOGIN".len())
            .any(|window| window == b"LOGIN")
    );
}
