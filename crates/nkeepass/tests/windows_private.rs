#![cfg(windows)]
//! Native Windows end-to-end private write coverage with synthetic data.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root)
        .env("NKEEPASS_CONFIG_DIR", root.join("config"))
        .env("NKEEPASS_DATA_DIR", root.join("data"))
        .env(
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
            "synthetic-windows-password",
        )
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn init_backup_context_mutation_and_no_clobber_are_private() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let args = [
        "init",
        "vault.kdbx",
        "--password-env",
        "NKEEPASS_WINDOWS_TEST_PASSWORD",
        "--size",
        "20",
        "--kdf",
        "argon2id",
        "--memory",
        "1024",
        "--iterations",
        "1",
    ];
    let init = run(root, &args);
    succeeded(&init);
    let report: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    let backup = report["password_backup"].as_str().unwrap();
    for path in [
        root.join("vault.kdbx"),
        root.join("config/config.json"),
        root.join("config/init-password.agekey"),
        backup.into(),
    ] {
        windows_private_file::verify(&File::open(path).unwrap()).unwrap();
    }
    let original = std::fs::read(root.join("vault.kdbx")).unwrap();
    assert!(!run(root, &args).status.success());
    assert_eq!(original, std::fs::read(root.join("vault.kdbx")).unwrap());
    let edit = run(
        root,
        &[
            "secrets",
            "set",
            "--key",
            "generated",
            "--notes",
            "synthetic note",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
        ],
    );
    succeeded(&edit);
    windows_private_file::verify(&File::open(root.join("vault.kdbx")).unwrap()).unwrap();
    let show = run(
        root,
        &[
            "secrets",
            "show",
            "--key",
            "generated",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
        ],
    );
    succeeded(&show);
}
