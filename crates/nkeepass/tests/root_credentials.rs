#![cfg(unix)]

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use neotales_keepass::{
    Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    ProtectedValue,
};

fn vault(home: &Path) -> PathBuf {
    let path = home.join("credentials.kdbx");
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("login");
    entry.password = ProtectedValue::from_text("app-secret");
    database.root.add_entry(entry);
    KdbxFile::save(
        &database,
        std::fs::File::create(&path).unwrap(),
        &mut KdbxCredentials::password("vault-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    path
}

fn command(home: &Path, vault: &Path, args: &[&str]) -> Command {
    let command = Command::new(env!("CARGO_BIN_EXE_nkp"));
    let mut command = command.isolate_application_environment();
    command
        .args(["--vault", vault.to_str().unwrap()])
        .args(args)
        .env("XDG_CONFIG_HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("NEO_KEEPASS_CONFIG_DIR")
        .env_remove("NKP_CONFIG_DIR")
        .env_remove("NEO_KEEPASS_DATA_DIR")
        .env_remove("NKP_DATA_DIR")
        .env_remove("XDG_CONFIG_DIR")
        .env_remove("NEO_KEEPASS_VAULT")
        .env_remove("NKP_VAULT")
        .env_remove("NEO_KEEPASS_VAULT_PATH")
        .env_remove("NKP_VAULT_PATH")
        .env_remove("NEO_KEEPASS_PASSWORD")
        .env_remove("NKP_PASSWORD")
        .env_remove("NEO_KEEPASS_COMPLETE_PASSWORD_ENV")
        .env_remove("NKP_COMPLETE_PASSWORD_ENV")
        .env_remove("NKEEPASS_SECRET")
        .stdin(Stdio::null());
    command
}

#[test]
fn default_password_environment_names_follow_documented_precedence() {
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for (variables, expected_success) in [
        (vec![("NEO_KEEPASS_PASSWORD", "vault-password")], true),
        (vec![("NKP_PASSWORD", "vault-password")], true),
        (vec![("NKEEPASS_PASSWORD", "vault-password")], false),
        (
            vec![
                ("NKEEPASS_PASSWORD", "wrong"),
                ("NKP_PASSWORD", "vault-password"),
            ],
            true,
        ),
        (
            vec![
                ("NEO_KEEPASS_PASSWORD", "wrong"),
                ("NKP_PASSWORD", "vault-password"),
            ],
            false,
        ),
        (
            vec![
                ("NKEEPASS_PASSWORD", "vault-password"),
                ("NKP_PASSWORD", "wrong"),
            ],
            false,
        ),
        (
            vec![
                ("NKP_PASSWORD", "wrong"),
                ("NEO_KEEPASS_PASSWORD", "vault-password"),
            ],
            true,
        ),
        (
            vec![
                ("NEO_KEEPASS_PASSWORD", "vault-password"),
                ("NKEEPASS_PASSWORD", "wrong"),
            ],
            true,
        ),
        (
            vec![
                ("NKP_PASSWORD", "vault-password"),
                ("NEO_KEEPASS_PASSWORD", ""),
            ],
            false,
        ),
    ] {
        let mut command = command(temp.path(), &vault, &["get", "--key", "login"]);
        for &(name, value) in &variables {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.success(),
            expected_success,
            "unexpected result with environment names: {:?}; stdout: {}; stderr: {}",
            variables.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn legacy_password_environment_name_is_ignored_when_set_alone() {
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    let output = command(temp.path(), &vault, &["get", "--key", "login"])
        .env("NKEEPASS_PASSWORD", "vault-password")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "legacy password variable alone unlocked the vault"
    );
    assert!(
        !output
            .stdout
            .windows(b"vault-password".len())
            .any(|window| window == b"vault-password")
    );
    assert!(
        !output
            .stderr
            .windows(b"vault-password".len())
            .any(|window| window == b"vault-password")
    );
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn root_credentials_reach_shared_vault_commands_and_explicit_sources_override_default() {
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for args in [
        vec![
            "--password-env",
            "EXPLICIT_PASSWORD",
            "get",
            "--key",
            "login",
        ],
        vec![
            "get",
            "--password-env",
            "EXPLICIT_PASSWORD",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "EXPLICIT_PASSWORD",
            "secrets",
            "get",
            "--key",
            "login",
        ],
    ] {
        let output = command(temp.path(), &vault, &args)
            .env("EXPLICIT_PASSWORD", "vault-password")
            .env("NEO_KEEPASS_PASSWORD", "wrong-password")
            .output()
            .unwrap();
        success(&output);
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("app-secret")
        );
    }
    success(
        &command(temp.path(), &vault, &["group", "ls"])
            .env("NEO_KEEPASS_PASSWORD", "vault-password")
            .output()
            .unwrap(),
    );
}

#[test]
fn stdin_password_works_at_root_or_command_and_overrides_the_default() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for args in [
        vec!["--password-stdin", "secrets", "get", "--key", "login"],
        vec!["secrets", "get", "--password-stdin", "--key", "login"],
    ] {
        let mut command = command(temp.path(), &vault, &args);
        command.env("NEO_KEEPASS_PASSWORD", "wrong-password");
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"vault-password\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        success(&output);
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("app-secret")
        );
    }
}

#[test]
fn global_credential_help_and_static_completions_show_both_sources() {
    let help = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .arg("--help")
        .output()
        .unwrap();
    success(&help);
    let help = String::from_utf8(help.stdout).unwrap();
    let globals = help.split_once("GLOBAL OPTIONS:").unwrap().1;
    assert!(globals.contains("--password-env NAME"));
    assert!(globals.contains("--password-stdin"));
    assert!(help.contains("NEO_KEEPASS_PASSWORD"));
    for shell in ["bash", "sh", "zsh", "fish", "powershell", "nushell"] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(["completion", shell])
            .output()
            .unwrap();
        success(&output);
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(script.contains("--password-env") || script.contains("-l password-env"));
        assert!(script.contains("--password-stdin") || script.contains("-l password-stdin"));
    }
}

#[test]
fn credential_duplicates_and_conflicts_across_positions_fail_before_vault_input() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("does-not-exist.kdbx");
    for args in [
        vec![
            "--password-env",
            "P",
            "--password-stdin",
            "get",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "P",
            "--password-env",
            "P",
            "get",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "P",
            "get",
            "--password-env",
            "P",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "P",
            "secrets",
            "get",
            "--password-stdin",
            "--key",
            "login",
        ],
        vec![
            "--password-stdin",
            "--password-stdin",
            "get",
            "--key",
            "login",
        ],
        vec![
            "--password-stdin",
            "get",
            "--password-stdin",
            "--key",
            "login",
        ],
        vec![
            "--password-stdin",
            "get",
            "--password-env",
            "P",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "P",
            "get",
            "--password",
            "literal",
            "--key",
            "login",
        ],
        vec![
            "--password-stdin",
            "get",
            "--password-file",
            "absent",
            "--key",
            "login",
        ],
        vec![
            "--password-env",
            "P",
            "exec",
            "--password-stdin",
            "--key",
            "login",
            "--env",
            "APP_PASSWORD",
            "--",
            "unused",
        ],
    ] {
        let output = command(temp.path(), &vault, &args).output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("option") || error.contains("select exactly one credential source"),
            "{error}"
        );
        assert!(!error.contains("cannot open vault"));
    }
}

#[test]
fn absent_and_empty_password_variables_fail_without_default_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for value in [None, Some("")] {
        let mut cli = command(
            temp.path(),
            &vault,
            &[
                "--password-env",
                "EXPLICIT_PASSWORD",
                "get",
                "--key",
                "login",
            ],
        );
        cli.env_remove("EXPLICIT_PASSWORD")
            .env("NEO_KEEPASS_PASSWORD", "vault-password");
        if let Some(value) = value {
            cli.env("EXPLICIT_PASSWORD", value);
        }
        let output = cli.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("password environment variable unavailable")
        );
    }
    let output = command(temp.path(), &vault, &["get", "--key", "login"])
        .env("NEO_KEEPASS_PASSWORD", "")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("password environment variable unavailable")
    );
    let output = command(temp.path(), &vault, &["get", "--key", "login"])
        .env("NKEEPASS_SECRET", "vault-password")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("password source required")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_password_variables_fail_without_disclosure() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for name in [
        "EXPLICIT_PASSWORD",
        "NEO_KEEPASS_PASSWORD",
        "NKP_PASSWORD",
        "NEO_KEEPASS_PASSWORD",
    ] {
        let mut args = Vec::new();
        if name == "EXPLICIT_PASSWORD" {
            args.extend(["--password-env", name]);
        }
        args.extend(["get", "--key", "login"]);
        let output = command(temp.path(), &vault, &args)
            .env(name, OsString::from_vec(vec![0xff]))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("password environment variable unavailable")
        );
    }
}

#[cfg(unix)]
#[test]
fn exec_preserves_child_options_and_removes_default_and_explicit_password_variables() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    let child = [
        "--key",
        "login",
        "--env",
        "APP_PASSWORD",
        "--",
        "/bin/sh",
        "-c",
        "test \"$APP_PASSWORD\" = app-secret && test \"${NEO_KEEPASS_PASSWORD+x}\" != x && test \"${EXPLICIT_PASSWORD+x}\" != x && test \"$1\" = --password-env && test \"$2\" = child-source && test \"$3\" = --password-stdin",
        "child",
        "--password-env",
        "child-source",
        "--password-stdin",
    ];
    for source in [
        vec!["--password-env", "EXPLICIT_PASSWORD", "exec"],
        vec!["exec", "--password-env", "EXPLICIT_PASSWORD"],
        vec!["--password-stdin", "exec"],
        vec!["exec", "--password-stdin"],
        vec!["exec"],
    ] {
        let stdin = source.contains(&"--password-stdin");
        let fallback = source == ["exec"];
        let mut args = source;
        args.extend(child);
        let mut cli = command(temp.path(), &vault, &args);
        cli.env("EXPLICIT_PASSWORD", "vault-password")
            .env(
                "NEO_KEEPASS_PASSWORD",
                if fallback {
                    "vault-password"
                } else {
                    "wrong-password"
                },
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = if stdin {
            cli.stdin(Stdio::piped());
            let mut child = cli.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"vault-password\n")
                .unwrap();
            child.wait_with_output().unwrap()
        } else {
            cli.output().unwrap()
        };
        success(&output);
    }
    let output = command(
        temp.path(),
        &vault,
        &[
            "--password-env",
            "PATH",
            "exec",
            "--key",
            "login",
            "--env",
            "APP_PASSWORD",
            "--",
            "/usr/bin/env",
        ],
    )
    .env("PATH", "vault-password")
    .env("NEO_KEEPASS_PASSWORD", "wrong-password")
    .output()
    .unwrap();
    success(&output);
    let environment = String::from_utf8(output.stdout).unwrap();
    assert!(
        !environment
            .lines()
            .any(|line| line.starts_with("PATH=") || line.starts_with("NEO_KEEPASS_PASSWORD="))
    );
    assert!(
        environment
            .lines()
            .any(|line| line == "APP_PASSWORD=app-secret")
    );
}

#[test]
fn exec_rejects_every_default_password_alias_as_a_child_binding() {
    let temp = tempfile::tempdir().unwrap();
    let vault = vault(temp.path());
    for name in [
        "NEO_KEEPASS_PASSWORD",
        "NKP_PASSWORD",
        "NEO_KEEPASS_PASSWORD",
    ] {
        let output = command(
            temp.path(),
            &vault,
            &["exec", "--key", "login", "--env", name, "--", "/bin/true"],
        )
        .output()
        .unwrap();
        assert!(!output.status.success(), "exec accepted reserved {name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reserved for the master password")
        );
    }
}
