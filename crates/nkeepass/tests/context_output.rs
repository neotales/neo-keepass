//! Process-level context output coverage with isolated synthetic vaults.

use std::process::{Command, Output, Stdio};

fn run(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root)
        .env("NKEEPASS_CONFIG_DIR", root.join("config"))
        .env("NKEEPASS_DATA_DIR", root.join("data"))
        .env("NKEEPASS_CONTEXT_TEST_PASSWORD", "synthetic-test-password")
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .env_remove("NKEEPASS_PASSWORD")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn direct_default_and_aliases_are_listed_once_with_current_status() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("default vault.kdbx");
    let path = path.to_str().unwrap();
    assert!(
        run(root.path(), &["config", "set", "default_vault", path])
            .status
            .success()
    );
    let text = run(root.path(), &["context", "list"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("(default)"));
    let listed = run(root.path(), &["context", "ls", "--json"]);
    let record: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(record["path"], path);
    assert_eq!(record["source"], "default");
    assert_eq!(record["current"], false);
    assert!(
        run(root.path(), &["context", "set", "work", path])
            .status
            .success()
    );
    assert!(
        run(root.path(), &["context", "use", "work"])
            .status
            .success()
    );
    let listed = run(root.path(), &["context", "list", "--json"]);
    let records: Vec<serde_json::Value> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["alias"], "work");
    assert_eq!(records[0]["current"], true);
    assert!(
        run(root.path(), &["config", "set", "current", path])
            .status
            .success()
    );
    let listed = run(root.path(), &["context", "ls", "--json"]);
    let records: Vec<serde_json::Value> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["current"], true);
}

#[test]
fn generated_master_is_recoverable_without_output_disclosure() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let result = run(
        root.path(),
        &[
            "init",
            "--json",
            "--generate-master-password",
            "--iterations",
            "64",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["master_password_generated"], true);
    assert_eq!(report["age_identity_created"], true);
    let key = std::fs::read_to_string(report["age_identity"].as_str().unwrap()).unwrap();
    let identity = neotales_age::AgeIdentity::from_private_key(key.trim()).unwrap();
    let ciphertext = std::fs::read_to_string(report["password_backup"].as_str().unwrap()).unwrap();
    let password = zeroize::Zeroizing::new(
        neotales_age::AgeFile::decrypt_armored(&ciphertext, &[identity]).unwrap(),
    );
    assert_eq!(password.len(), 32);
    assert!(password.iter().all(u8::is_ascii_alphanumeric));
    for channel in [&result.stdout, &result.stderr] {
        assert!(
            !channel
                .windows(password.len())
                .any(|part| part == password.as_slice())
        );
        assert!(
            !channel
                .windows(key.trim().len())
                .any(|part| part == key.trim().as_bytes())
        );
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root.path())
        .env("NKEEPASS_CONFIG_DIR", root.path().join("config"))
        .env("NKEEPASS_DATA_DIR", root.path().join("data"))
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args(["secrets", "ls", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&password).unwrap();
    drop(child.stdin.take());
    assert!(child.wait_with_output().unwrap().status.success());

    let second = run(
        root.path(),
        &[
            "init",
            "second.kdbx",
            "--generate-master-password",
            "--iterations",
            "64",
        ],
    );
    assert!(second.status.success());
    let text = String::from_utf8_lossy(&second.stdout);
    assert!(text.contains("Database:"));
    assert!(text.contains("Encrypted password backup:"));
    assert!(text.contains("Age identity reused:"));
    assert!(!text.contains(key.trim()));
    let collision = run(
        root.path(),
        &[
            "init",
            "second.kdbx",
            "--json",
            "--generate-master-password",
            "--iterations",
            "64",
        ],
    );
    assert!(!collision.status.success());
    let recovery: serde_json::Value = serde_json::from_slice(&collision.stdout).unwrap();
    assert_eq!(recovery["operation"], "init-recovery");
    let collision_backup =
        std::fs::read_to_string(recovery["password_backup"].as_str().unwrap()).unwrap();
    let identity = neotales_age::AgeIdentity::from_private_key(key.trim()).unwrap();
    let recovered = zeroize::Zeroizing::new(
        neotales_age::AgeFile::decrypt_armored(&collision_backup, &[identity]).unwrap(),
    );
    for channel in [&collision.stdout, &collision.stderr] {
        assert!(
            !channel
                .windows(recovered.len())
                .any(|bytes| bytes == recovered.as_slice())
        );
        assert!(
            !channel
                .windows(key.trim().len())
                .any(|bytes| bytes == key.trim().as_bytes())
        );
    }
}

#[test]
fn generated_master_requires_backup_and_rejects_other_credentials() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("data"), b"not a directory").unwrap();
    let out = run(
        root.path(),
        &[
            "init",
            "vault.kdbx",
            "--generate-master-password",
            "--iterations",
            "64",
        ],
    );
    assert!(!out.status.success());
    assert!(!root.path().join("vault.kdbx").exists());
    let out = run(
        root.path(),
        &[
            "init",
            "vault.kdbx",
            "--generate-master-password",
            "--password-env",
            "NKEEPASS_CONTEXT_TEST_PASSWORD",
        ],
    );
    assert!(!out.status.success());
    assert!(!root.path().join("vault.kdbx").exists());
}

#[test]
fn init_text_reports_backup_identity_creation_and_reuse() {
    let root = tempfile::tempdir().unwrap();
    for (name, status) in [("one.kdbx", "created"), ("two.kdbx", "reused")] {
        let output = run(
            root.path(),
            &[
                "init",
                name,
                "--iterations",
                "64",
                "--password-env",
                "NKEEPASS_CONTEXT_TEST_PASSWORD",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Database:"));
        assert!(text.contains(name));
        assert!(text.contains("Encrypted password backup:"));
        assert!(text.contains(&format!("Age identity {status}:")));
        assert!(!text.contains("synthetic-test-password"));
        assert!(!text.starts_with('{'));
    }
}

#[test]
fn initialized_contexts_are_visible_as_text_and_json() {
    for explicit in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("named.kdbx");
        let mut args = vec!["init", "--json"];
        if explicit {
            args.push(vault.to_str().unwrap());
        }
        args.extend([
            "--iterations",
            "64",
            "--password-env",
            "NKEEPASS_CONTEXT_TEST_PASSWORD",
        ]);
        let created = run(root.path(), &args);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
        let path = value["path"].as_str().unwrap();
        for action in ["ls", "list", "show"] {
            let text = run(root.path(), &["context", action]);
            assert!(text.status.success());
            let text = String::from_utf8(text.stdout).unwrap();
            assert!(text.contains(path));
            assert!(text.contains(if explicit {
                if action == "show" {
                    "(unnamed)"
                } else {
                    "(current)"
                }
            } else {
                "default"
            }));
            let json = run(root.path(), &["context", action, "--json"]);
            assert!(json.status.success());
            let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
            assert_eq!(json["path"], path);
        }
        let opened = run(
            root.path(),
            &[
                "secrets",
                "ls",
                "--password-env",
                "NKEEPASS_CONTEXT_TEST_PASSWORD",
            ],
        );
        assert!(
            opened.status.success(),
            "{}",
            String::from_utf8_lossy(&opened.stderr)
        );
    }
}
