#![cfg(windows)]
//! Native Windows end-to-end private write coverage with synthetic data.

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::fs::File;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn independently_assert_private(path: &Path) {
    // Windows PowerShell's .NET ACL inspection is independent of the
    // production GetSecurityInfo/ACE verifier.
    let script = r#"
$a = Get-Acl -LiteralPath $env:NKEEPASS_TEST_ACL_PATH
$u = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (!$a.AreAccessRulesProtected -or @($a.Access).Count -ne 1) { exit 1 }
$r = @($a.Access)[0]
if ($r.IsInherited -or $r.AccessControlType -ne 'Allow' -or
    $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $u -or
    $r.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { exit 2 }
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("NKEEPASS_TEST_ACL_PATH", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent ACL inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn acl_sddl(path: &Path) -> Vec<u8> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Acl -LiteralPath $env:NKEEPASS_TEST_ACL_PATH).Sddl",
        ])
        .env("NKEEPASS_TEST_ACL_PATH", path)
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

#[test]
fn secure_directory_rejects_regular_file_without_changing_acl() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("ordinary");
    std::fs::write(&file, b"synthetic").unwrap();
    let before = acl_sddl(&file);
    assert_eq!(
        nkeepass::private_file::set_owner_only(&file, "not a private directory"),
        Err("not a private directory")
    );
    assert_eq!(acl_sddl(&file), before);
    assert_eq!(std::fs::read(&file).unwrap(), b"synthetic");
}

fn command(root: &Path, args: &[&str]) -> Command {
    Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
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
}

fn run(root: &Path, args: &[&str]) -> Output {
    command(root, args).output().unwrap()
}

#[test]
fn mixed_case_environment_aliases_follow_precedence_and_cli_vault_wins() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let selected = root.join("selected.kdbx");
    let lower = root.join("lower.kdbx");
    let output = command(root, &["context", "show"])
        .env("nEo_KeEpAsS_vAuLt", &selected)
        .env("NKP_VAULT", &lower)
        .env("NKEEPASS_VAULT", &lower)
        .output()
        .unwrap();
    succeeded(&output);
    let context: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(context["path"], selected.to_string_lossy().as_ref());
    assert_eq!(context["source"], "environment");

    let explicit = root.join("explicit.kdbx");
    let output = command(
        root,
        &["--vault", explicit.to_str().unwrap(), "context", "show"],
    )
    .env("nEo_KeEpAsS_vAuLt", "")
    .env("NKP_VAULT", &lower)
    .output()
    .unwrap();
    succeeded(&output);
    let context: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(context["path"], explicit.to_string_lossy().as_ref());
    assert_eq!(context["source"], "argument");
}

#[test]
fn mixed_case_password_alias_unlocks_and_exec_reserves_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let initialized = run(
        root,
        &[
            "init",
            "vault.kdbx",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
            "--iterations",
            "64",
        ],
    );
    succeeded(&initialized);

    let listed = command(root, &["--vault", "vault.kdbx", "secrets", "ls"])
        .env("nEo_KeEpAsS_pAsSwOrD", "synthetic-windows-password")
        .env("NKP_PASSWORD", "incorrect-lower-priority")
        .env("NKEEPASS_PASSWORD", "incorrect-legacy")
        .output()
        .unwrap();
    succeeded(&listed);

    let explicitly_selected = command(
        root,
        &[
            "--vault",
            "vault.kdbx",
            "secrets",
            "ls",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
        ],
    )
    .env("nEo_KeEpAsS_pAsSwOrD", "incorrect-default")
    .output()
    .unwrap();
    succeeded(&explicitly_selected);

    for name in [
        "NEO_KEEPASS_PASSWORD",
        "NKP_PASSWORD",
        "NKEEPASS_PASSWORD",
        "nEo_KeEpAsS_pAsSwOrD",
    ] {
        let output = command(
            root,
            &[
                "exec",
                "--key",
                "generated",
                "--env",
                name,
                "--",
                "cmd.exe",
                "/c",
                "exit 0",
            ],
        )
        .output()
        .unwrap();
        assert!(!output.status.success(), "exec accepted reserved {name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reserved for the master password")
        );
    }
}

#[test]
fn mixed_case_config_and_data_aliases_beat_short_and_legacy_names() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let selected_config = root.join("selected-config");
    let selected_data = root.join("selected-data");
    let ignored_config = root.join("ignored-config");
    let ignored_data = root.join("ignored-data");
    let output = command(
        root,
        &[
            "init",
            "vault.kdbx",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
            "--iterations",
            "64",
        ],
    )
    .env("nEo_KeEpAsS_cOnFiG_dIr", &selected_config)
    .env("NEO_KEEPASS_DATA_DIR", &selected_data)
    .env("NKP_CONFIG_DIR", &ignored_config)
    .env("NKP_DATA_DIR", &ignored_data)
    .output()
    .unwrap();
    succeeded(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let backup = Path::new(report["password_backup"].as_str().unwrap());
    assert_eq!(backup.parent(), Some(selected_data.as_path()));
    assert!(selected_config.join("init-password.agekey").is_file());
    assert!(!ignored_config.exists());
    assert!(!ignored_data.exists());
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
    for bytes in [&init.stdout, &init.stderr] {
        assert!(
            !bytes
                .windows(b"synthetic-windows-password".len())
                .any(|v| v == b"synthetic-windows-password")
        );
    }
    let report: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    let backup = report["password_backup"].as_str().unwrap();
    let identity_text = std::fs::read_to_string(root.join("config/init-password.agekey")).unwrap();
    let identity = neotales_age::AgeIdentity::from_private_key(identity_text.trim()).unwrap();
    let encrypted = std::fs::read_to_string(backup).unwrap();
    assert_eq!(
        neotales_age::AgeFile::decrypt_armored(&encrypted, &[identity]).unwrap(),
        b"synthetic-windows-password"
    );
    for path in [
        root.join("vault.kdbx"),
        root.join("config/config.json"),
        root.join("config/init-password.agekey"),
        backup.into(),
    ] {
        independently_assert_private(&path);
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
    independently_assert_private(&root.join("vault.kdbx"));
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
    let path = root.join("vault.kdbx");
    let text = path.to_str().unwrap();
    succeeded(&run(root, &["config", "set", "current", text]));
    independently_assert_private(&root.join("config/config.json"));
    succeeded(&run(root, &["config", "rm", "current"]));
    independently_assert_private(&root.join("config/config.json"));
}

#[test]
fn backup_failure_reports_partial_success_without_disclosing_password() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("data"), b"not a directory").unwrap();
    let output = run(
        temp.path(),
        &[
            "init",
            "vault.kdbx",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
            "--kdf",
            "argon2id",
            "--memory",
            "1024",
            "--iterations",
            "1",
        ],
    );
    assert!(!output.status.success());
    assert!(temp.path().join("vault.kdbx").is_file());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("vault created"));
    assert!(diagnostic.contains("cannot prepare password backup directory"));
    assert!(temp.path().join("config/config.json").is_file());
    assert!(!temp.path().join("config/init-password.agekey").exists());
    assert_eq!(
        std::fs::read(temp.path().join("data")).unwrap(),
        b"not a directory"
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !bytes
                .windows(b"synthetic-windows-password".len())
                .any(|v| v == b"synthetic-windows-password")
        );
    }
}

#[test]
fn config_replacement_failure_preserves_existing_data() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let vault = root.join("vault.kdbx");
    succeeded(&run(
        root,
        &["config", "set", "current", vault.to_str().unwrap()],
    ));
    let config = root.join("config/config.json");
    let before = std::fs::read(&config).unwrap();
    let mut permissions = std::fs::metadata(&config).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&config, permissions).unwrap();
    let output = run(root, &["config", "rm", "current"]);
    let mut permissions = std::fs::metadata(&config).unwrap().permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(&config, permissions).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot save configuration"));
    assert_eq!(std::fs::read(&config).unwrap(), before);
    independently_assert_private(&config);
}

#[test]
fn existing_junction_target_is_not_replaced_or_followed() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("existing-dir");
    let link = temp.path().join("vault.kdbx");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("marker"), b"unchanged").unwrap();
    let result = Command::new("cmd.exe")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "creating synthetic junction failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let before_link = acl_sddl(&link);
    let before_target = acl_sddl(&target);
    assert_eq!(
        nkeepass::private_file::set_owner_only(&link, "not a private directory"),
        Err("not a private directory")
    );
    assert_eq!(acl_sddl(&link), before_link);
    assert_eq!(acl_sddl(&target), before_target);
    let output = run(
        temp.path(),
        &[
            "init",
            "vault.kdbx",
            "--password-env",
            "NKEEPASS_WINDOWS_TEST_PASSWORD",
            "--kdf",
            "argon2id",
            "--memory",
            "1024",
            "--iterations",
            "1",
        ],
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("vault already exists or cannot be created")
    );
    assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"unchanged");
    assert!(!temp.path().join("config").exists());
    assert!(!temp.path().join("data").exists());
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    assert_ne!(
        std::fs::symlink_metadata(&link).unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
}

#[test]
fn concurrent_init_has_one_winner_without_clobber() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let args = [
        "init",
        "race.kdbx",
        "--password-env",
        "NKEEPASS_WINDOWS_TEST_PASSWORD",
        "--kdf",
        "argon2id",
        "--memory",
        "1024",
        "--iterations",
        "1",
    ];
    let (first, second) = std::thread::scope(|scope| {
        let other = scope.spawn(|| run(root, &args));
        (run(root, &args), other.join().unwrap())
    });
    assert_eq!(
        usize::from(first.status.success()) + usize::from(second.status.success()),
        1
    );
    let loser = if first.status.success() {
        &second
    } else {
        &first
    };
    assert!(
        String::from_utf8_lossy(&loser.stderr)
            .contains("vault already exists or cannot be created")
    );
    independently_assert_private(&root.join("race.kdbx"));
}
