#![cfg(windows)]
//! Native Windows end-to-end private write coverage with synthetic data.

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
    assert!(String::from_utf8_lossy(&output.stderr).contains("vault created"));
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
    assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"unchanged");
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    assert_ne!(
        std::fs::symlink_metadata(&link).unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
}
