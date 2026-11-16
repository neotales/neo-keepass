use std::path::Path;
use std::process::{Command, Output};

fn cli(home: &Path, vault: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args(["--vault", vault.to_str().unwrap()])
        .args(args)
        .args(["--password-env", "GROUP_TEST_PASSWORD"])
        .env("GROUP_TEST_PASSWORD", "test-password")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_creates_nested_groups_and_entry_parents_without_overwrites() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("groups.kdbx");
    success(&cli(temp.path(), &vault, &["init", "--iterations", "64"]));
    success(&cli(
        temp.path(),
        &vault,
        &["group", "add", "--key", "team/service/prod"],
    ));
    let saved = std::fs::read(&vault).unwrap();
    success(&cli(
        temp.path(),
        &vault,
        &["groups", "ensure", "--key", "TEAM/service/prod"],
    ));
    assert_eq!(std::fs::read(&vault).unwrap(), saved);
    success(&cli(
        temp.path(),
        &vault,
        &[
            "secrets",
            "ensure",
            "--key",
            "team/new/deep/login",
            "--size",
            "24",
        ],
    ));
    let output = cli(temp.path(), &vault, &["group", "list"]);
    success(&output);
    let groups = String::from_utf8(output.stdout).unwrap();
    assert!(groups.contains("Root/team/service/prod\n"));
    assert!(groups.contains("Root/team/new/deep\n"));
    assert_eq!(
        groups.lines().filter(|path| *path == "Root/team").count(),
        1
    );
    let password = cli(
        temp.path(),
        &vault,
        &["get", "--key", "team/new/deep/login"],
    );
    success(&password);
    let saved = std::fs::read(&vault).unwrap();
    success(&cli(
        temp.path(),
        &vault,
        &["ensure", "--key", "TEAM/new/deep/LOGIN", "--size", "48"],
    ));
    assert_eq!(std::fs::read(&vault).unwrap(), saved);
    assert_eq!(
        cli(
            temp.path(),
            &vault,
            &["get", "--key", "team/new/deep/login"]
        )
        .stdout,
        password.stdout
    );
}

#[test]
fn cli_dry_runs_invalid_paths_and_delete_guards_keep_vault_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("groups.kdbx");
    success(&cli(temp.path(), &vault, &["init", "--iterations", "64"]));
    success(&cli(
        temp.path(),
        &vault,
        &["group", "create", "--key", "team/service"],
    ));
    let saved = std::fs::read(&vault).unwrap();
    for args in [
        vec!["group", "add", "--key", "missing/child", "--dry-run"],
        vec![
            "ensure",
            "--key",
            "missing/child/login",
            "--size",
            "24",
            "--dry-run",
        ],
        vec!["group", "rm", "--key", "team", "--dry-run"],
    ] {
        success(&cli(temp.path(), &vault, &args));
        assert_eq!(std::fs::read(&vault).unwrap(), saved);
    }
    for key in [
        "",
        "new//child",
        "new/./child",
        "new/../child",
        "new/\nchild",
        "/new",
    ] {
        for action in ["add", "rm"] {
            let output = cli(
                temp.path(),
                &vault,
                &["group", action, "--key", key, "--dry-run"],
            );
            assert!(!output.status.success());
            assert_eq!(std::fs::read(&vault).unwrap(), saved);
        }
    }
    for args in [
        vec!["group", "rm", "--key", "team"],
        vec!["group", "rm", "--key", "Root", "--yes"],
        vec!["group", "rm", "--key", "Root", "--dry-run"],
    ] {
        assert!(!cli(temp.path(), &vault, &args).status.success());
        assert_eq!(std::fs::read(&vault).unwrap(), saved);
    }
    success(&cli(
        temp.path(),
        &vault,
        &["groups", "remove", "--key", "team", "--yes"],
    ));
    let output = cli(temp.path(), &vault, &["group", "ls"]);
    success(&output);
    assert!(!String::from_utf8(output.stdout).unwrap().contains("team"));
}

#[test]
fn group_help_and_all_static_completions_include_subcommands() {
    for group in ["group", "groups"] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .args([group, "add", "--help"])
            .output()
            .unwrap();
        success(&output);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--dry-run"));
        assert!(help.contains("--key PATH"));
        assert!(help.contains("--password-env"));
    }
    for shell in ["bash", "sh", "zsh", "fish", "powershell", "nushell"] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .args(["completion", shell])
            .output()
            .unwrap();
        success(&output);
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(script.contains("group"));
        assert!(script.contains("create"));
        assert!(script.contains("--dry-run") || script.contains("-l dry-run"));
    }
}
