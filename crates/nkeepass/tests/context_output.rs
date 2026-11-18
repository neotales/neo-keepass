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

fn opens_with(root: &std::path::Path, vault: &str, password: &[u8]) -> bool {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root)
        .env("NKEEPASS_CONFIG_DIR", root.join("config"))
        .env("NKEEPASS_DATA_DIR", root.join("data"))
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args(["--vault", vault, "secrets", "ls", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(password).unwrap();
    drop(child.stdin.take());
    child.wait().unwrap().success()
}

fn decrypt_candidate(record: &serde_json::Value) -> zeroize::Zeroizing<Vec<u8>> {
    let key = zeroize::Zeroizing::new(
        std::fs::read_to_string(record["age_identity"].as_str().unwrap()).unwrap(),
    );
    let identity = neotales_age::AgeIdentity::from_private_key(key.trim()).unwrap();
    let encrypted = std::fs::read_to_string(record["password_backup"].as_str().unwrap()).unwrap();
    zeroize::Zeroizing::new(
        neotales_age::AgeFile::decrypt_armored(&encrypted, &[identity]).unwrap(),
    )
}

fn candidates(root: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_dir(root.join("data"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
        .collect()
}

#[test]
fn human_context_list_shows_unaliased_paths_but_json_preserves_alias_only_contract() {
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
    assert!(listed.status.success());
    assert!(listed.stdout.is_empty());
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
    assert_eq!(records[0]["path"], path);
    assert!(records[0].get("current").is_none());
    assert_eq!(records[0].as_object().unwrap().len(), 2);
    let text = run(root.path(), &["context", "ls"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("(current)"));
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
    assert!(records[0].get("current").is_none());
    assert_eq!(records[0].as_object().unwrap().len(), 2);
    let current_text = run(root.path(), &["context", "ls"]);
    assert!(String::from_utf8_lossy(&current_text.stdout).contains("(current)"));

    let direct_current = root.path().join("current-only.kdbx");
    let separate_default = root.path().join("default-only.kdbx");
    assert!(
        run(
            root.path(),
            &["config", "set", "current", direct_current.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert!(
        run(
            root.path(),
            &[
                "config",
                "set",
                "default_vault",
                separate_default.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    let listed = run(root.path(), &["context", "ls", "--json"]);
    let records: Vec<serde_json::Value> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["alias"], "work");
    let text = run(root.path(), &["context", "list"]);
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("(current)"));
    assert!(text.contains("(default)"));
}

#[test]
fn context_show_keeps_alias_name_for_explicit_and_environment_selection() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("vault.kdbx");
    assert!(
        run(
            root.path(),
            &["context", "set", "work", path.to_str().unwrap()]
        )
        .status
        .success()
    );
    let output = run(
        root.path(),
        &["--vault", "work", "context", "show", "--json"],
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["alias"].is_null());
    assert_eq!(result["source"], "argument");
    let text = run(root.path(), &["--vault", "work", "context", "show"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("Name: work"));
    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .env("NKEEPASS_CONFIG_DIR", root.path().join("config"))
        .env("NKEEPASS_DATA_DIR", root.path().join("data"))
        .env("NKEEPASS_VAULT", "work")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args(["context", "show"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Name: work"));
    assert!(text.contains("Source: environment"));
    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .env("NKEEPASS_CONFIG_DIR", root.path().join("config"))
        .env("NKEEPASS_DATA_DIR", root.path().join("data"))
        .env("NKEEPASS_VAULT", "work")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args(["context", "show", "--json"])
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["alias"].is_null());
    assert_eq!(result["source"], "environment");
    assert!(
        run(root.path(), &["config", "set", "default_vault", "work"])
            .status
            .success()
    );
    let text = run(root.path(), &["context", "show"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("Name: work"));
    assert!(text.contains("Source: default"));
    let json = run(root.path(), &["context", "show", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["source"], "default");
    assert!(json["alias"].is_null());
}

#[cfg(windows)]
#[test]
fn windows_context_paths_preserve_case_distinct_candidates() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("MixedCase.kdbx");
    let original = path.to_str().unwrap();
    let alternate = original.to_ascii_uppercase().replace('\\', "/");
    assert!(
        run(root.path(), &["context", "set", "work", original])
            .status
            .success()
    );
    assert!(
        run(root.path(), &["config", "set", "current", &alternate])
            .status
            .success()
    );
    assert!(
        run(root.path(), &["config", "set", "default_vault", &alternate])
            .status
            .success()
    );
    let output = run(root.path(), &["context", "ls", "--json"]);
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["alias"], "work");
    assert_eq!(rows[0]["path"], original.replace('/', "\\"));
    let text = run(root.path(), &["context", "ls"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("(current)"));
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
    assert_eq!(report["ancestor_durability"], "unconfirmed");
    let association: serde_json::Value = serde_json::from_slice(
        &std::fs::read(report["recovery_association"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(association["ancestor_durability"], "unconfirmed");
    assert_eq!(
        report["directory_sync_policy"],
        if cfg!(unix) {
            "required"
        } else {
            "unconfirmed"
        }
    );
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

    {
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
        assert!(text.contains("Recovery directory ancestry durability: unconfirmed"));
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
        assert_eq!(recovery["operation"], "init-unused-backup");
        assert_eq!(recovery["vault_installed"], false);
        assert!(recovery["path"].as_str().unwrap().ends_with("second.kdbx"));
        let collision_backup =
            std::fs::read_to_string(recovery["password_backup"].as_str().unwrap()).unwrap();
        let identity = neotales_age::AgeIdentity::from_private_key(key.trim()).unwrap();
        let recovered = zeroize::Zeroizing::new(
            neotales_age::AgeFile::decrypt_armored(&collision_backup, &[identity]).unwrap(),
        );
        assert!(!opens_with(
            root.path(),
            recovery["path"].as_str().unwrap(),
            &recovered
        ));
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
        let text_collision = run(
            root.path(),
            &[
                "init",
                "second.kdbx",
                "--generate-master-password",
                "--iterations",
                "64",
            ],
        );
        assert!(!text_collision.status.success());
        let text = String::from_utf8_lossy(&text_collision.stdout);
        assert!(text.contains("Vault not created; unused backup"));
        assert!(text.contains("second.kdbx"));
    }
}

#[cfg(unix)]
#[test]
fn closed_output_recovers_from_multiple_private_candidate_records() {
    let root = tempfile::tempdir().unwrap();
    for name in ["first.kdbx", "second.kdbx"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .args([
                "init",
                name,
                "--generate-master-password",
                "--iterations",
                "64",
            ])
            .current_dir(root.path())
            .env("NKEEPASS_CONFIG_DIR", root.path().join("config"))
            .env("NKEEPASS_DATA_DIR", root.path().join("data"))
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        drop(child.stderr.take());
        let output = child.wait().unwrap();
        assert!(!output.success());
        assert!(root.path().join(name).is_file());
    }
    let records = candidates(root.path());
    assert_eq!(records.len(), 2);
    for name in ["first.kdbx", "second.kdbx"] {
        let target = root.path().join(name);
        let record = records
            .iter()
            .find(|record| record["vault"] == target.to_str().unwrap())
            .unwrap();
        assert_eq!(record["status"], "candidate");
        let password = decrypt_candidate(record);
        assert!(opens_with(root.path(), target.to_str().unwrap(), &password));
        let association = format!("{}.json", record["password_backup"].as_str().unwrap());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(association).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn concurrent_generated_init_keeps_winner_and_unused_backup_distinct() {
    let root = tempfile::tempdir().unwrap();
    let args = [
        "init",
        "same.kdbx",
        "--json",
        "--generate-master-password",
        "--iterations",
        "64",
    ];
    let (first, second) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| run(root.path(), &args));
        (run(root.path(), &args), worker.join().unwrap())
    });
    assert_ne!(first.status.success(), second.status.success());
    let (winner, loser) = if first.status.success() {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let win: serde_json::Value = serde_json::from_slice(&winner.stdout).unwrap();
    let lose: serde_json::Value = serde_json::from_slice(&loser.stdout).unwrap();
    assert_eq!(lose["operation"], "init-unused-backup");
    assert_eq!(lose["vault_installed"], false);
    let records = candidates(root.path());
    assert_eq!(records.len(), 2);
    for (report, expected) in [(&win, true), (&lose, false)] {
        let record = records
            .iter()
            .find(|record| record["password_backup"] == report["password_backup"])
            .unwrap();
        let password = decrypt_candidate(record);
        assert_eq!(
            opens_with(root.path(), win["path"].as_str().unwrap(), &password),
            expected
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

#[cfg(unix)]
#[test]
fn identity_reuse_does_not_require_reading_traversable_ancestors() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let restricted = root.path().join("traverse-only");
    std::fs::create_dir(&restricted).unwrap();
    let config = restricted.join("config");
    let data = restricted.join("data");
    let invoke = |name: &str| {
        Command::new(env!("CARGO_BIN_EXE_nkp"))
            .current_dir(root.path())
            .env("NKEEPASS_CONFIG_DIR", &config)
            .env("NKEEPASS_DATA_DIR", &data)
            .env("NKEEPASS_CONTEXT_TEST_PASSWORD", "synthetic-test-password")
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .env_remove("NKEEPASS_PASSWORD")
            .args([
                "init",
                name,
                "--json",
                "--password-env",
                "NKEEPASS_CONTEXT_TEST_PASSWORD",
                "--iterations",
                "64",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    assert!(invoke("first.kdbx").status.success());
    std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o111)).unwrap();
    if std::fs::read_dir(&restricted).is_ok() {
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("SKIP execute-only ancestor: test user can read mode 0111 directories");
        return;
    }
    let second = invoke("second.kdbx");
    std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(root.path().join("second.kdbx").is_file());
    let report: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(report["age_identity_created"], false);
}

#[test]
fn collision_with_closed_stdout_preserves_original_failure() {
    let root = tempfile::tempdir().unwrap();
    let first = run(
        root.path(),
        &[
            "init",
            "existing.kdbx",
            "--password-env",
            "NKEEPASS_CONTEXT_TEST_PASSWORD",
            "--iterations",
            "64",
        ],
    );
    assert!(first.status.success());
    let path = root.path().join("existing.kdbx");
    let original = std::fs::read(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root.path())
        .env("NKEEPASS_CONFIG_DIR", root.path().join("config"))
        .env("NKEEPASS_DATA_DIR", root.path().join("data"))
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .args([
            "init",
            "existing.kdbx",
            "--generate-master-password",
            "--iterations",
            "64",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("vault already exists or cannot be created"),
        "{stderr}"
    );
    assert!(
        stderr.contains("recovery report could not be written"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn generated_init_refuses_invalid_existing_identity_without_clobber() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir(&config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    nkeepass::private_file::set_owner_only(&config, "cannot secure synthetic directory").unwrap();
    let identity = config.join("init-password.agekey");
    nkeepass::private_file::write_private_noclobber(&identity, b"synthetic-invalid-key").unwrap();
    let result = run(
        root.path(),
        &[
            "init",
            "vault.kdbx",
            "--generate-master-password",
            "--iterations",
            "64",
        ],
    );
    assert!(!result.status.success());
    assert!(!root.path().join("vault.kdbx").exists());
    assert_eq!(std::fs::read(identity).unwrap(), b"synthetic-invalid-key");
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
            if action == "show" {
                let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
                assert_eq!(json["path"], path);
            } else if explicit {
                assert!(
                    json.stdout.is_empty(),
                    "unaliased context leaked into alias-only JSON output"
                );
            } else {
                let records: Vec<serde_json::Value> = String::from_utf8_lossy(&json.stdout)
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0]["alias"], "default");
                assert_eq!(records[0]["path"], path);
            }
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
