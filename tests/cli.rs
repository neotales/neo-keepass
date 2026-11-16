#[allow(
    dead_code,
    clippy::unused_self,
    reason = "shared fixture exposes optional scenarios to other CLI adapters"
)]
#[path = "support/cli_support.rs"]
mod nkeepass_cli;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn help_program() -> String {
    Path::new(env!("CARGO_BIN_EXE_nkeepass"))
        .file_name()
        .expect("Cargo binary path has a basename")
        .to_string_lossy()
        .into_owned()
}

fn expected_help(text: &str) -> String {
    text.replace("nkeepass", &help_program())
}

fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args(args)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap()
}

#[test]
fn context_alias_persistence_and_precedence() {
    let tmp = tempfile::tempdir().unwrap();
    // Use the platform's temporary directory so the target is absolute on every OS.
    let vault = tmp.path().join("nkeepass-test.kdbx");
    let vault = vault.to_str().unwrap();
    assert!(
        cli(tmp.path(), &["context", "set", "work", vault])
            .status
            .success(),
        "context set refused an absolute path on this platform"
    );
    assert!(
        cli(tmp.path(), &["context", "use", "work"])
            .status
            .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let config = tmp.path().join("nkeepass/config.json");
        assert_eq!(
            std::fs::metadata(config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        cli(
            tmp.path(),
            &["alias", "set", "work", vault, "--kind", "vault"]
        )
        .status
        .success()
    );
    assert!(
        cli(
            tmp.path(),
            &["alias", "set", "mail", "Root/Email", "--field", "UserName"]
        )
        .status
        .success()
    );
    let output = cli(tmp.path(), &["context", "show"]);
    assert!(output.status.success());
    let show: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(show["path"], vault);
    assert_eq!(show["source"], "context");
    assert_eq!(show["alias"], "work");
    let output = cli(tmp.path(), &["context", "ls"]);
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["alias"], "work");
    assert_eq!(listed["path"], vault);
    let completion = cli(tmp.path(), &["__complete", "vault-aliases", "w"]);
    assert_eq!(completion.stdout, b"work\n");
    let output = cli(tmp.path(), &["--vault", "work", "context", "show"]);
    let show: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(show["source"], "argument");
    assert!(show["alias"].is_null());
    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args(["context", "show"])
        .env("XDG_CONFIG_HOME", tmp.path())
        .env("NKEEPASS_VAULT", vault)
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap();
    assert!(output.status.success());
    let show: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(show["source"], "environment");
    assert!(show["alias"].is_null());
    let output = cli(tmp.path(), &["alias", "resolve", "mail"]);
    let alias: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(alias["target"], "Root/Email");
    assert_eq!(alias["field"], "UserName");
    assert!(
        !cli(tmp.path(), &["alias", "set", "escape", "../Private"])
            .status
            .success()
    );
    assert!(!cli(tmp.path(), &["context", "use", vault]).status.success());
    assert!(
        cli(tmp.path(), &["alias", "remove", "mail"])
            .status
            .success()
    );
    assert!(
        !cli(tmp.path(), &["alias", "resolve", "mail"])
            .status
            .success()
    );
    assert!(cli(tmp.path(), &["context", "rm", "work"]).status.success());
}

#[test]
fn alias_mutations_clear_the_selected_context() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("work.kdbx");
    let vault = vault.to_str().unwrap();

    assert!(
        cli(tmp.path(), &["context", "set", "work", vault])
            .status
            .success()
    );
    assert!(
        cli(tmp.path(), &["context", "use", "work"])
            .status
            .success()
    );
    assert!(cli(tmp.path(), &["alias", "rm", "work"]).status.success());
    let output = cli(tmp.path(), &["context", "show"]);
    assert!(output.status.success());
    let show: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(show["source"], "context");
    assert!(show["alias"].is_null());

    assert!(
        cli(tmp.path(), &["context", "set", "work", vault])
            .status
            .success()
    );
    assert!(
        cli(tmp.path(), &["context", "use", "work"])
            .status
            .success()
    );
    assert!(
        cli(
            tmp.path(),
            &["alias", "set", "work", "Root/Email", "--kind", "entry"]
        )
        .status
        .success()
    );
    let output = cli(tmp.path(), &["context", "show"]);
    assert!(output.status.success());
    let show: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(show["source"], "context");
    assert!(show["alias"].is_null());
}

#[cfg(unix)]
#[test]
fn configuration_and_non_utf8_inputs_fail_closed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    let tmp = tempfile::tempdir().unwrap();
    let relative = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .current_dir(tmp.path())
        .args(["alias", "list"])
        .env("XDG_CONFIG_HOME", "relative-config")
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap();
    assert!(!relative.status.success());
    assert!(!tmp.path().join("relative-config").exists());

    let config_home = tmp.path().join("config-home");
    let config_dir = config_home.join("nkeepass");
    std::fs::create_dir_all(&config_dir).unwrap();
    let external = tmp.path().join("external.json");
    std::fs::write(&external, b"{}").unwrap();
    symlink(&external, config_dir.join("config.json")).unwrap();
    let linked = cli(&config_home, &["alias", "list"]);
    assert!(!linked.status.success());
    assert_eq!(std::fs::read(&external).unwrap(), b"{}");

    let oversized_home = tmp.path().join("oversized-home");
    let oversized_dir = oversized_home.join("nkeepass");
    std::fs::create_dir_all(&oversized_dir).unwrap();
    let oversized = oversized_dir.join("config.json");
    std::fs::write(&oversized, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let mut permissions = std::fs::metadata(&oversized).unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&oversized, permissions).unwrap();
    assert!(!cli(&oversized_home, &["alias", "list"]).status.success());

    let env_home = tmp.path().join("env-home");
    let invalid_env = OsString::from_vec(vec![0xff]);
    let environment = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args(["context", "show"])
        .env("XDG_CONFIG_HOME", &env_home)
        .env("NKEEPASS_VAULT", invalid_env)
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap();
    assert!(!environment.status.success());
    assert!(!String::from_utf8_lossy(&environment.stderr).contains("panicked"));

    let invalid_arg = OsString::from_vec(vec![0xfe]);
    let argument = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .arg(invalid_arg)
        .env("XDG_CONFIG_HOME", env_home)
        .output()
        .unwrap();
    assert!(!argument.status.success());
    assert!(!String::from_utf8_lossy(&argument.stderr).contains("panicked"));
}

#[test]
fn metadata_listing_never_prints_password_or_values() {
    use nkeepass_cli::{CliFixture, MASTER_PASSWORD, assert_no_secrets};

    // A vault built in process, with a real entry carrying a real password, a
    // username, notes, a protected custom field, an OTP seed and an attachment.
    //
    // This test used to read `tests/fixtures/keepassxc-minimal.kdbx`, which is a
    // KDBX 3 *minimal* fixture whose root group is empty. `secrets ls` therefore
    // wrote zero bytes to stdout, `text.lines()` yielded nothing, and the loop
    // below never ran once. The `assert!(!text.contains("fixture-password"))` that
    // followed was trivially true of an empty string.
    //
    // It would have passed unchanged if the listing printed the password, or
    // printed the title and nothing else, or printed nothing at all -- and it is
    // named for exactly the surface that carries the hostile-metadata finding in
    // #7. A test that cannot fail on the vulnerability it is named for reads as
    // coverage, which is worse than no test.
    //
    // The first assertion is therefore the one that matters: that the listing is
    // non-empty. Without it the rest is decoration.
    let fixture = CliFixture::new(false);
    let vault = fixture.vault();
    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "ls",
            "--password-env",
            "FIXTURE_PASSWORD",
        ])
        .env("XDG_CONFIG_HOME", fixture.directory())
        .env("FIXTURE_PASSWORD", MASTER_PASSWORD)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "the fixture vault listed nothing, so every assertion below is vacuous -- \
         this is the failure this test was reported for"
    );

    for line in &lines {
        let item: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("listing line is not JSON: {line:?} ({error})"));
        assert!(item.get("path").is_some(), "no path in {line:?}");
        assert!(item.get("title").is_some(), "no title in {line:?}");
        for forbidden in ["password", "value", "notes", "username"] {
            assert!(
                item.get(forbidden).is_none(),
                "{forbidden} disclosed in a metadata listing: {line:?}"
            );
        }
    }

    // The structural checks above would pass on a listing that leaked a value in
    // some other shape, so the bytes are checked against every marker the fixture
    // planted: the entry password, the username, the notes, the protected custom
    // field, the OTP seed and URI, the attachment and the key file.
    assert_no_secrets(&output);

    // A wrong password must still fail, and must not fall back to printing
    // something. Kept from the original test, and now meaningful because the vault
    // has contents to withhold.
    let tmp = tempfile::tempdir().unwrap();
    let failure = cli(
        tmp.path(),
        &[
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "ls",
            "--password-env",
            "MISSING_PASSWORD",
        ],
    );
    assert!(!failure.status.success());
    assert!(
        failure.stdout.is_empty(),
        "a failed listing wrote to stdout"
    );
}

/// A child program that exits zero only if it was given `SCRIPT_VALUE`, and the
/// arguments needed to reach it.
///
/// `sh` is not on PATH on Windows, and this file's runner clears the environment,
/// so nothing inherited rescues it. Naming `sh` unconditionally failed the run with
/// "cannot run child command" -- a diagnostic about the wrong component entirely,
/// when the thing under test is whether `exec` injects the value into the child.
#[cfg(unix)]
fn child_reporting_script_value() -> (&'static str, Vec<String>) {
    (
        "sh",
        vec!["-c".to_owned(), "test -n \"$SCRIPT_VALUE\"".to_owned()],
    )
}

#[cfg(windows)]
fn child_reporting_script_value() -> (&'static str, Vec<String>) {
    (
        "cmd",
        vec![
            "/C".to_owned(),
            "if not \"%SCRIPT_VALUE%\"==\"\" (exit 0) else (exit 1)".to_owned(),
        ],
    )
}

#[test]
fn explicit_password_is_a_documented_scripting_compatibility_mode() {
    use nkeepass_cli::{
        CliFixture, ENTRY_TITLE, MASTER_PASSWORD, assert_no_secrets, command, run_with_stdin,
    };

    let fixture = CliFixture::new(false);
    let binary = Path::new(env!("CARGO_BIN_EXE_nkeepass"));
    let vault = fixture.vault().to_str().unwrap();
    let run = |args: &[&str]| {
        let mut child = command(binary, &fixture);
        child
            .env(
                "XDG_CONFIG_HOME",
                fixture.directory().join("compatibility-config"),
            )
            .args(args);
        run_with_stdin(&mut child, b"input-not-consumed-by-static-validation\n")
    };

    let help = run(&["--help"]);
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("WARNING: --password VALUE is exposed in process listings"));
    assert!(help_text.contains("shell history."));

    let listed = run(&[
        "--vault",
        vault,
        "secrets",
        "ls",
        "--password",
        MASTER_PASSWORD,
    ]);
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains(ENTRY_TITLE));
    assert_no_secrets(&listed);

    let (child, child_args) = child_reporting_script_value();
    let mut executed_args: Vec<&str> = vec![
        "--vault",
        vault,
        "x",
        "--key",
        ENTRY_TITLE,
        "--env",
        "SCRIPT_VALUE",
        "--password",
        MASTER_PASSWORD,
        "--",
        child,
    ];
    executed_args.extend(child_args.iter().map(String::as_str));
    let executed = run(&executed_args);
    assert!(executed.status.success());
    assert_no_secrets(&executed);

    for (args, diagnostic) in [
        (
            vec![
                "secrets",
                "ls",
                "--password",
                MASTER_PASSWORD,
                "--password-env",
                "UNUSED",
            ],
            "select exactly one credential source",
        ),
        (
            vec![
                "field",
                "set",
                "--key",
                ENTRY_TITLE,
                "--field",
                "Token",
                "--stdin",
                "--password-stdin",
            ],
            "stdin cannot carry both password and value",
        ),
    ] {
        let failure = run(&args);
        assert!(!failure.status.success());
        assert_eq!(
            failure.stderr,
            format!("nkeepass: {diagnostic}\n").as_bytes()
        );
        assert_no_secrets(&failure);
    }
}

#[test]
fn attachment_metadata_and_explicit_export_use_service_alias_selection() {
    use nkeepass_cli::{
        ATTACHMENT, CliFixture, ENTRY_TITLE, MASTER_PASSWORD, command, run_with_stdin,
    };

    let fixture = CliFixture::new(false);
    let binary = Path::new(env!("CARGO_BIN_EXE_nkeepass"));
    let vault = fixture.vault().to_str().unwrap();
    let run = |args: &[&str]| {
        let mut child = command(binary, &fixture);
        child.env("XDG_CONFIG_HOME", fixture.directory()).args(args);
        run_with_stdin(&mut child, b"")
    };
    let alias = run(&["alias", "set", "attachment-entry", ENTRY_TITLE]);
    assert!(
        alias.status.success(),
        "{}",
        String::from_utf8_lossy(&alias.stderr)
    );

    let listed = run(&[
        "--vault",
        vault,
        "attachment",
        "ls",
        "--key",
        "attachment-entry",
        "--password",
        MASTER_PASSWORD,
    ]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let row: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(
        row,
        serde_json::json!({"name":"file.txt", "bytes": ATTACHMENT.len(), "protected": true})
    );

    let output = fixture.directory().join("exported-attachment.bin");
    let output_text = output.to_str().unwrap();
    let exported = run(&[
        "--vault",
        vault,
        "attachment",
        "get",
        "--key",
        "attachment-entry",
        "--field",
        "file.txt",
        "--output",
        output_text,
        "--password",
        MASTER_PASSWORD,
    ]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(
        exported.stdout.is_empty(),
        "attachment bytes must not enter metadata output"
    );
    assert_eq!(std::fs::read(output).unwrap(), ATTACHMENT);
}

#[test]
fn completion_scripts_are_static_for_every_advertised_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = "completion-environment-SENTINEL-39ac71";
    let mut scripts = std::collections::BTreeMap::new();
    for shell in ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "nushell"] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .current_dir(tmp.path())
            .env_clear()
            .env("NKEEPASS_COMPLETE_PASSWORD_ENV", "COMPLETION_PASSWORD")
            .env("COMPLETION_PASSWORD", marker)
            .env("NKEEPASS_VAULT", marker)
            .env("XDG_CONFIG_HOME", "relative-config-must-not-be-read")
            .args(["completion", shell])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{shell} completion failed");
        assert!(
            output.stderr.is_empty(),
            "{shell} completion wrote diagnostics"
        );
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(
            !script.contains(marker),
            "{shell} completion leaked a secret"
        );
        assert!(
            script.contains("__complete"),
            "{shell} omitted dynamic metadata"
        );
        assert!(
            script.contains(if shell == "fish" { "-l key" } else { "--key" }),
            "{shell} omitted operation options"
        );
        assert!(
            !script.contains("--value"),
            "{shell} advertised a secret argv option"
        );
        scripts.insert(shell, script);
    }
    assert_eq!(scripts["powershell"], scripts["pwsh"]);
    assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());

    // The scripts are checked by handing them to a real parser, which is the only
    // way to know they parse. Where the parser is not installed the check is
    // *reported as skipped* rather than passed quietly: a gate that cannot run and
    // says nothing is indistinguishable from a gate that ran and found nothing.
    //
    // This is the Windows runner's situation. It clears the environment, and the
    // shell it would need is not on a cleared PATH, so `bash -n` failed with
    // "bash completion is not valid syntax" -- naming a syntax error in a script
    // that had not been parsed at all.
    for (shell, parser) in [("bash", "bash"), ("sh", "sh")] {
        let available = Command::new(parser).arg("-c").arg("exit 0").output();
        if !matches!(&available, Ok(output) if output.status.success()) {
            println!(
                "skipping the {shell} syntax check: no {parser} on PATH here, so the \
                 script was generated and inspected but not parsed"
            );
            continue;
        }
        let script = tmp.path().join(format!("nkeepass-{shell}.completion"));
        std::fs::write(&script, &scripts[shell]).unwrap();
        let syntax = Command::new(parser).arg("-n").arg(script).output().unwrap();
        assert!(
            syntax.status.success(),
            "{shell} completion is not valid syntax"
        );
        assert!(syntax.stderr.is_empty());
    }
}

#[test]
fn completion_rejects_unsupported_shells_without_echoing_input() {
    let marker = "unsupported-shell-SENTINEL-827d1a";
    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env_clear()
        .args(["completion", "csh", marker])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"nkeepass: unsupported completion shell\n".as_slice()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end matrix covers every completion disclosure boundary"
)]
fn completion_protocol_covers_static_and_authenticated_metadata_safely() {
    use nkeepass_cli::{CliFixture, assert_no_secrets, command};

    let fixture = CliFixture::new(false);
    let binary = Path::new(env!("CARGO_BIN_EXE_nkeepass"));
    let vault = fixture.vault().to_str().unwrap();

    let locked = command(binary, &fixture)
        .env("XDG_CONFIG_HOME", "relative-config-must-not-be-read")
        .env("NKEEPASS_VAULT", vault)
        .args(["__complete", "entries", "fixture"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(locked.status.success());
    assert!(
        locked.stdout.is_empty(),
        "entry completion unlocked without opt-in"
    );
    assert_no_secrets(&locked);

    let config_home = fixture.directory().join("completion-config");
    let configured = command(binary, &fixture)
        .env("XDG_CONFIG_HOME", &config_home)
        .args([
            "alias",
            "set",
            "mail",
            "Root/fixture-login",
            "--kind",
            "entry",
        ])
        .output()
        .unwrap();
    assert!(configured.status.success());

    let aliases = command(binary, &fixture)
        .env("XDG_CONFIG_HOME", &config_home)
        .args(["__complete", "aliases", "m"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(aliases.status.success());
    assert_eq!(aliases.stdout, b"mail\n");

    let nested = fixture.directory().join("child");
    std::fs::create_dir(&nested).unwrap();
    let nested_vault = nested.join("nested-vault.kdbx");
    std::fs::write(&nested_vault, b"not read by completion").unwrap();
    std::fs::write(fixture.directory().join("root-vault.kdbx"), b"not read").unwrap();
    let files = command(binary, &fixture)
        .env_clear()
        .args(["__complete", "vault-files", "nested"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(files.status.success());
    // The completion emits *canonical* paths, and the expectation is canonicalised
    // to match rather than the emitted path being loosened to match the fixture.
    //
    // `vault_file_candidates` canonicalises the working directory before walking
    // it, which is what lets it compute a candidate's path relative to the root.
    // The emitted path is therefore built from the canonical root, not from the
    // root as spelled. That is deliberate -- a completion a shell will insert has
    // to be unambiguous about which file it names, and `/var/folders/...` and
    // `/private/var/folders/...` are the same file only on macOS.
    //
    // This assertion failed on the macOS runner and nowhere else, for exactly
    // that reason: `TempDir::new()` returns `/var/folders/...`, `/var` is a
    // symlink to `/private/var`, and the two spellings differ. Canonicalising
    // here is the honest form of the expectation. Loosening the comparison to
    // accept either spelling would have hidden the same class of bug anywhere
    // else it appeared.
    let canonical_nested_vault = nested_vault.canonicalize().unwrap();
    assert_eq!(
        files.stdout,
        format!("{}\n", canonical_nested_vault.display()).as_bytes()
    );
    assert!(!String::from_utf8_lossy(&files.stdout).contains("root-vault.kdbx"));

    let authenticated = |kind: &str, prefix: &str| {
        command(binary, &fixture)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("NKEEPASS_VAULT", vault)
            .env(
                "NKEEPASS_COMPLETE_PASSWORD_ENV",
                "NKEEPASS_COMPLETE_TEST_PASSWORD",
            )
            .env(
                "NKEEPASS_COMPLETE_TEST_PASSWORD",
                nkeepass_cli::MASTER_PASSWORD,
            )
            .args(["__complete", kind, prefix])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let entries = authenticated("entries", "Root/fixture");
    assert!(entries.status.success());
    assert_eq!(entries.stdout, b"Root/fixture-login\n");
    assert_no_secrets(&entries);
    let groups = authenticated("groups", "Root");
    assert!(groups.status.success());
    assert_eq!(groups.stdout, b"Root\n");
    assert_no_secrets(&groups);
    let keys = authenticated("keys", "m");
    assert!(keys.status.success());
    assert_eq!(keys.stdout, b"mail\n");
    assert_no_secrets(&keys);

    // The shell protocol must honor the same explicit global vault as the
    // command being completed; an environment fallback must not win.
    let forwarded = command(binary, &fixture)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NKEEPASS_VAULT", "/path/that/must/not/be-used.kdbx")
        .env(
            "NKEEPASS_COMPLETE_PASSWORD_ENV",
            "NKEEPASS_COMPLETE_TEST_PASSWORD",
        )
        .env(
            "NKEEPASS_COMPLETE_TEST_PASSWORD",
            nkeepass_cli::MASTER_PASSWORD,
        )
        .args(["--vault", vault, "__complete", "keys", "m"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(forwarded.status.success());
    assert_eq!(forwarded.stdout, b"mail\n");
    assert_no_secrets(&forwarded);

    let wrong = command(binary, &fixture)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("NKEEPASS_VAULT", vault)
        .env(
            "NKEEPASS_COMPLETE_PASSWORD_ENV",
            "NKEEPASS_COMPLETE_TEST_PASSWORD",
        )
        .env(
            "NKEEPASS_COMPLETE_TEST_PASSWORD",
            nkeepass_cli::WRONG_PASSWORD,
        )
        .args(["__complete", "entries", "fixture"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert_no_secrets(&wrong);

    let rejected_secret = command(binary, &fixture)
        .env_clear()
        .args([
            "__complete",
            "entries",
            "fixture",
            nkeepass_cli::MASTER_PASSWORD,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!rejected_secret.status.success());
    assert!(rejected_secret.stdout.is_empty());
    assert!(
        !String::from_utf8_lossy(&rejected_secret.stderr).contains(nkeepass_cli::MASTER_PASSWORD)
    );
}

#[test]
fn completion_protocol_omits_ambiguous_entry_and_group_paths() {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
        ProtectedValue,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("ambiguous.kdbx");
    let mut database = KeePassDatabase::default();
    database.root.add_entry(Entry::new("Shared"));
    database.root.add_entry(Entry::new("shared"));
    database.root.groups.push(Group::new("GroupOnly"));
    let mut foo = Group::new("Foo");
    foo.add_entry(Entry::new("first"));
    database.root.add_group(foo);
    let mut lower_foo = Group::new("foo");
    lower_foo.add_entry(Entry::new("second"));
    database.root.add_group(lower_foo);
    let mut duplicate = Entry::new("GroupOnly");
    duplicate.password = ProtectedValue::from_text("must-not-be-printed-SENTINEL");
    database.root.add_entry(duplicate);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("completion-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    for (kind, prefix) in [
        ("entries", "Root/Shared"),
        ("entries", "Root/GroupOnly"),
        ("groups", "Root/GroupOnly"),
        ("entries", "Root/Foo/"),
        ("groups", "Root/Foo"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env("NKEEPASS_VAULT", &vault)
            .env("NKEEPASS_COMPLETE_PASSWORD_ENV", "COMPLETION_TEST_PASSWORD")
            .env("COMPLETION_TEST_PASSWORD", "completion-test-password")
            .args(["__complete", kind, prefix])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            output.stdout.is_empty(),
            "ambiguous {kind} path was completed"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-be-printed-SENTINEL"));
    }
}

#[test]
fn public_and_diagnostic_surfaces_do_not_leak_fixture_markers() {
    use nkeepass_cli::{CliFixture, Scenario, assert_public_surfaces, command, run_with_stdin};

    let fixture = CliFixture::new(false);
    let binary = Path::new(env!("CARGO_BIN_EXE_nkeepass"));
    assert_public_surfaces(&fixture, |scenario, fixture| {
        let vault = fixture.vault().to_str().unwrap();
        let corrupt = fixture.corrupt_vault();
        let corrupt = corrupt.to_str().unwrap();
        let (args, input): (Vec<&str>, &[u8]) = match scenario {
            Scenario::Help => (vec!["--help"], b""),
            Scenario::List => (
                vec!["--vault", vault, "secrets", "ls", "--password-stdin"],
                b"cli-master-SENTINEL-5a8c91\n",
            ),
            Scenario::Context => (vec!["context", "set", "work", vault], b""),
            Scenario::Alias => (
                vec![
                    "alias",
                    "set",
                    "mail",
                    nkeepass_cli::ENTRY_TITLE,
                    "--field",
                    "UserName",
                ],
                b"",
            ),
            Scenario::MissingEntry => (
                vec![
                    "--vault",
                    vault,
                    "get",
                    "--key",
                    fixture.missing_path(),
                    "--password-stdin",
                ],
                b"cli-master-SENTINEL-5a8c91\n",
            ),
            Scenario::WrongPassword => (
                vec![
                    "--vault",
                    vault,
                    "get",
                    "--key",
                    nkeepass_cli::ENTRY_TITLE,
                    "--password-stdin",
                ],
                b"cli-wrong-SENTINEL-c29a81\n",
            ),
            Scenario::CorruptVault => (
                vec!["--vault", corrupt, "secrets", "ls", "--password-stdin"],
                b"cli-master-SENTINEL-5a8c91\n",
            ),
        };
        let mut child = command(binary, fixture);
        child
            .env("XDG_CONFIG_HOME", fixture.directory().join("public-config"))
            .args(args);
        run_with_stdin(&mut child, input)
    });
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "end-to-end vault mutation and redaction regression"
)]
fn shortcuts_fields_attachments_and_exec() {
    use std::io::Write;

    use neotales_keepass::{
        Attachment, Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
        KeePassDatabase, ProtectedValue,
    };
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("test.kdbx");
    let mut db = KeePassDatabase::default();
    let mut entry = Entry::new("LOGIN");
    entry.password = ProtectedValue::from_text("hidden-sentinel");
    for data in [
        b"first-duplicate".as_slice(),
        b"second-duplicate".as_slice(),
    ] {
        let reference = db.binary_pool.add(data.to_vec(), true);
        entry.attachments.push(Attachment {
            name: "duplicate.txt".to_owned(),
            reference,
        });
    }
    db.add_entry(entry);
    let mut target = Entry::new("TARGET");
    target.password = ProtectedValue::from_text("target-sentinel");
    db.add_entry(target);
    db.add_entry(Entry::new("Collision"));
    db.add_entry(Entry::new("collision"));
    KdbxFile::save(
        &db,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 10,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let loaded = KdbxFile::load(
        std::fs::File::open(&vault).unwrap(),
        &mut KdbxCredentials::password("test-password").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert!(
        loaded.can_save_losslessly,
        "fixture cannot be saved losslessly"
    );
    let vault = vault.to_str().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .args(["--vault", vault])
            .args(args)
            .env("XDG_CONFIG_HOME", tmp.path())
            .env("TEST_VAULT_PASSWORD", "test-password")
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .output()
            .unwrap()
    };
    let value_file = tmp.path().join("value.txt");
    let auth = ["--password-env", "TEST_VAULT_PASSWORD"];
    let out = run(&["ls", auth[0], auth[1]]);
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("hidden-sentinel"));
    let out = run(&["get", "--key", "LOGIN", auth[0], auth[1]]);
    assert_eq!(out.stdout, b"hidden-sentinel");
    let out = run(&["getx", "--key", "LOGIN", auth[0], auth[1]]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["value"], "hidden-sentinel");
    let out = run(&["rm", "--key", "LOGIN", auth[0], auth[1]]);
    assert!(!out.status.success());
    std::fs::write(&value_file, "field-sentinel").unwrap();
    let out = run(&[
        "field",
        "set",
        "--key",
        "LOGIN",
        "--field",
        "Token",
        "--file",
        value_file.to_str().unwrap(),
        auth[0],
        auth[1],
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(&[
        "field", "get", "--key", "LOGIN", "--field", "Token", auth[0], auth[1],
    ]);
    assert_eq!(out.stdout, b"field-sentinel");
    assert!(
        run(&["alias", "set", "token", "LOGIN", "--field", "Token"])
            .status
            .success()
    );
    assert_eq!(
        run(&["get", "--key", "token", auth[0], auth[1]]).stdout,
        b"field-sentinel"
    );
    assert_eq!(
        run(&[
            "custom-field",
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            auth[0],
            auth[1]
        ])
        .stdout,
        b"field-sentinel"
    );
    assert!(
        run(&[
            "field", "rm", "--key", "LOGIN", "--field", "Token", "--yes", auth[0], auth[1]
        ])
        .status
        .success()
    );
    std::fs::write(&value_file, "attachment-sentinel").unwrap();
    assert!(
        run(&[
            "attachment",
            "add",
            "--key",
            "LOGIN",
            "--field",
            "file.txt",
            "--file",
            value_file.to_str().unwrap(),
            auth[0],
            auth[1]
        ])
        .status
        .success()
    );
    let file = tmp.path().join("output.txt");
    let attachment_get = run(&[
        "attachment",
        "get",
        "--key",
        "LOGIN",
        "--field",
        "file.txt",
        "--output",
        file.to_str().unwrap(),
        auth[0],
        auth[1],
    ]);
    assert!(
        attachment_get.status.success(),
        "{}",
        String::from_utf8_lossy(&attachment_get.stderr)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"attachment-sentinel");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let overwrite = run(&[
        "attachment",
        "get",
        "--key",
        "LOGIN",
        "--field",
        "file.txt",
        "--output",
        file.to_str().unwrap(),
        auth[0],
        auth[1],
    ]);
    assert!(!overwrite.status.success());
    assert_eq!(std::fs::read(&file).unwrap(), b"attachment-sentinel");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = tmp.path().join("not-an-attachment");
        std::fs::write(&target, b"unchanged").unwrap();
        let link = tmp.path().join("attachment-link");
        symlink(&target, &link).unwrap();
        let linked = run(&[
            "attachment",
            "get",
            "--key",
            "LOGIN",
            "--field",
            "file.txt",
            "--output",
            link.to_str().unwrap(),
            auth[0],
            auth[1],
        ]);
        assert!(!linked.status.success());
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }
    let duplicate_output = tmp.path().join("duplicate-output.txt");
    let duplicate = run(&[
        "attachment",
        "get",
        "--key",
        "LOGIN",
        "--field",
        "duplicate.txt",
        "--output",
        duplicate_output.to_str().unwrap(),
        auth[0],
        auth[1],
    ]);
    assert!(!duplicate.status.success());
    assert!(!duplicate_output.exists());
    assert!(
        run(&[
            "attachment",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "file.txt",
            "--yes",
            auth[0],
            auth[1]
        ])
        .status
        .success()
    );
    // Child returns a status based on the injected value without printing it.
    let reopened = KdbxFile::load(
        std::fs::File::open(vault).unwrap(),
        &mut KdbxCredentials::password("test-password").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert_eq!(reopened.binary_pool.records().len(), 2);
    let implicit_name = run(&[
        "x", "--key", "LOGIN", auth[0], auth[1], "--", "sh", "-c", "exit 0",
    ]);
    assert!(!implicit_name.status.success());
    for alias in ["x", "exec"] {
        let out = run(&[
            alias,
            "--key",
            "LOGIN",
            "--env",
            "LOGIN",
            auth[0],
            auth[1],
            "--",
            "sh",
            "-c",
            "test \"$LOGIN\" = hidden-sentinel && test -z \"$TEST_VAULT_PASSWORD\"",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
    }
    let mut isolated_stdin = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args([
            "--vault",
            vault,
            "x",
            "--key",
            "LOGIN",
            "--env",
            "LOGIN",
            "--password-stdin",
            "--",
            "sh",
            "-c",
            "IFS= read -r line; test \"$line\" = child-input-SENTINEL",
        ])
        .env("XDG_CONFIG_HOME", tmp.path())
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    isolated_stdin
        .stdin
        .take()
        .unwrap()
        .write_all(b"test-password\nchild-input-SENTINEL\n")
        .unwrap();
    let isolated_output = isolated_stdin.wait_with_output().unwrap();
    assert_eq!(isolated_output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&isolated_output.stderr).contains("child-input-SENTINEL"));

    let out = run(&[
        "x", "--key", "LOGIN", "--env", "LOGIN", auth[0], auth[1], "--", "sh", "-c", "exit 7",
    ]);
    assert_eq!(out.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("hidden-sentinel"));
    let argv_secret = run(&[
        "set",
        "--key",
        "LOGIN",
        "--value",
        "argv-password-SENTINEL",
        auth[0],
        auth[1],
    ]);
    assert!(!argv_secret.status.success());
    assert!(!String::from_utf8_lossy(&argv_secret.stderr).contains("argv-password-SENTINEL"));
    std::fs::write(&value_file, "changed").unwrap();
    assert!(
        run(&[
            "set",
            "--key",
            "LOGIN",
            "--file",
            value_file.to_str().unwrap(),
            auth[0],
            auth[1],
        ])
        .status
        .success()
    );
    assert_eq!(
        run(&["get", "--key", "LOGIN", auth[0], auth[1]]).stdout,
        b"changed"
    );
    assert!(run(&["alias", "set", "LOGIN", "TARGET"]).status.success());
    let ambiguous_alias = run(&["get", "--key", "LOGIN", auth[0], auth[1]]);
    assert!(!ambiguous_alias.status.success());
    assert!(ambiguous_alias.stdout.is_empty());
    assert!(run(&["alias", "remove", "LOGIN"]).status.success());
    let duplicate_path = run(&["get", "--key", "collision", auth[0], auth[1]]);
    assert!(!duplicate_path.status.success());
    assert!(duplicate_path.stdout.is_empty());
    assert!(
        run(&["ensure", "--key", "New", auth[0], auth[1]])
            .status
            .success()
    );
    assert!(
        run(&["rm", "--key", "New", "--yes", auth[0], auth[1]])
            .status
            .success()
    );
}

/// U+009B is 8-bit CSI, U+009D is OSC, U+009C is ST, U+007F is DEL. No ESC:
/// the point is that the bytes a naive `is_ascii_control`-style check misses are
/// exactly the ones an xterm acts on in UTF-8 mode.
const HOSTILE_PAYLOAD: &str = "evil\u{9b}31mRED\u{9b}0m\u{9d}0;window-title=PWNED\u{9c}del\u{7f}";

/// Builds a vault whose *metadata* is hostile while its *secrets* are ordinary.
///
/// Three shapes, because each reaches a different rendering surface:
/// - a hostile entry title, which `secrets ls` and `secrets search` emit;
/// - a hostile field name and attachment name on an otherwise benign entry,
///   which `field ls` and `attachment ls` emit under a clean `--key` -- a
///   selector cannot mask a value it was never asked about;
/// - a fully clean entry declared *after* the tainted ones, so a listing that
///   stopped at the first bad record cannot pass.
fn hostile_metadata_vault(dir: &Path) -> PathBuf {
    use neotales_keepass::{
        Attachment, Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
        KeePassDatabase, ProtectedValue,
    };

    let vault = dir.join("hostile.kdbx");
    let mut database = KeePassDatabase::default();
    let attachment = database
        .binary_pool
        .add(b"attachment-bytes-SENTINEL".to_vec(), true);

    let mut titled = Entry::new(HOSTILE_PAYLOAD);
    titled.password = ProtectedValue::from_text("hostile-password-SENTINEL");

    let mut tainted = Entry::new("benign-entry");
    tainted.password = ProtectedValue::from_text("benign-password-SENTINEL");
    tainted
        .fields
        .push(Field::new(HOSTILE_PAYLOAD, "field-value-SENTINEL"));
    tainted.attachments.push(Attachment {
        name: HOSTILE_PAYLOAD.to_owned(),
        reference: attachment,
    });

    let mut survivor = Entry::new("benign-survivor");
    survivor.password = ProtectedValue::from_text("survivor-password-SENTINEL");
    survivor
        .fields
        .push(Field::new("API_TOKEN", "survivor-token-SENTINEL"));

    database.root.add_entry(titled);
    database.root.add_entry(tainted);
    database.root.add_entry(survivor);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    vault
}

/// Runs the CLI against a vault with an isolated config directory. The
/// credential option goes *after* the subcommand: this CLI takes it as a
/// per-command option, and in front of the subcommand it is an "unknown
/// command" error rather than a global flag.
fn run_against(vault: &Path, config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env("XDG_CONFIG_HOME", config)
        .env("NKEEPASS_VAULT", vault)
        .env("HOSTILE_TEST_PASSWORD", "hostile-test-password")
        .args(args)
        .args(["--password-env", "HOSTILE_TEST_PASSWORD"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A vault is untrusted input: anyone can hand you a `.kdbx`. `serde_json`
/// escapes the C0 range but emits `U+007F` and the entire C1 block raw, and
/// `U+009B` is 8-bit CSI. Before this was fixed, a title carrying those bytes
/// reached stdout verbatim and the terminal acted on them -- a hostile vault
/// could repaint the screen, rewrite the window title, or reach the clipboard.
///
/// The assertion is deliberately on the raw output *bytes* rather than on an
/// error, because the requirement is the narrower one: no control byte may
/// reach stdout at all, whether the CLI refuses the record or escapes it.
#[test]
fn hostile_vault_metadata_never_reaches_stdout_as_control_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = hostile_metadata_vault(tmp.path());
    let config = tmp.path().join("config");

    // Every surface that renders vault-supplied metadata. `secrets ls` covers
    // the title, `field ls` the field name, `attachment ls` the attachment
    // name, and `secrets show` all three plus the resolved path.
    for args in [
        vec!["secrets", "ls"],
        vec!["secrets", "search", "evil"],
        vec!["secrets", "show", "--key", "Root/benign-entry"],
        vec!["field", "ls", "--key", "Root/benign-entry"],
        vec!["attachment", "ls", "--key", "Root/benign-entry"],
    ] {
        let output = run_against(&vault, &config, &args);
        // Both outcomes are acceptable -- refuse, or render safely -- but the
        // bytes on stdout are not negotiable. A line feed is the one exception:
        // it is the NDJSON record separator, so it is part of the format
        // rather than injected content. Everything else, including DEL and the
        // whole C1 block, is exactly what a naive C0-only check would miss.
        for &byte in &output.stdout {
            assert!(
                !byte.is_ascii_control() || byte == b'\n',
                "{} emitted a raw control byte 0x{byte:02X} on stdout",
                args.join(" "),
            );
        }
        // And the payload never survives in any form that a terminal or a log
        // pipeline would act on.
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !text.contains('\u{9b}') && !text.contains('\u{9d}') && !text.contains('\u{7f}'),
            "{} emitted a C1 or DEL control character",
            args.join(" "),
        );
    }
}

/// Withholding a hostile record must not cost the caller the rest of the vault.
///
/// This is the other half of the fix and the reason it is not simply "reject
/// the vault". A vault is a collection: one entry an attacker wrote must not
/// make every other entry unreadable, and a listing must not stop at the first
/// bad record and silently look like a short vault. The benign entry here is
/// declared *after* the tainted one, so a walk that stopped early fails.
#[test]
fn hostile_vault_record_is_withheld_without_hiding_the_rest_of_the_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = hostile_metadata_vault(tmp.path());
    let config = tmp.path().join("config");

    let listing = run_against(&vault, &config, &["secrets", "ls"]);
    let text = String::from_utf8_lossy(&listing.stdout);
    assert!(
        listing.status.success(),
        "a hostile record must not fail the whole listing, got: {}",
        String::from_utf8_lossy(&listing.stderr),
    );
    assert!(
        !text.contains("benign-entry"),
        "the entry carrying a hostile attachment and field name is withheld",
    );
    assert!(
        text.contains("benign-survivor"),
        "a benign entry must still be listed after a hostile one, got: {text}",
    );
    assert!(
        !text.contains("RED") && !text.contains("window-title"),
        "no part of the payload may survive on stdout",
    );

    // The hostile *field* name is dropped from the record; the rest of that
    // entry's fields are not, so a selective drop is distinguishable from
    // discarding the whole entry.
    let fields = run_against(
        &vault,
        &config,
        &["field", "ls", "--key", "Root/benign-survivor"],
    );
    let field_text = String::from_utf8_lossy(&fields.stdout);
    assert!(
        fields.status.success(),
        "listing a benign entry's fields must succeed, got: {field_text}",
    );
    assert!(
        field_text.contains("\"name\":\"API_TOKEN\""),
        "a benign custom field must still be listed, got: {field_text}",
    );

    // The single-entry commands refuse rather than filter. Returning a
    // complete-looking entry with one field quietly missing would be
    // concealment by a trusted tool: the user cannot see the field, so cannot
    // ask for it by name, while `field get` still returns its value. An
    // attacker who can write one byte into a field name gets to hide it that
    // way, which is worse than the loud failure it replaced.
    for args in [
        vec!["secrets", "show", "--key", "Root/benign-entry"],
        vec!["field", "ls", "--key", "Root/benign-entry"],
        vec!["attachment", "ls", "--key", "Root/benign-entry"],
    ] {
        let output = run_against(&vault, &config, &args);
        assert!(
            !output.status.success(),
            "{} must refuse an entry with hostile metadata rather than filter it",
            args.join(" "),
        );
        assert!(
            output.stdout.is_empty(),
            "{} wrote a record while refusing",
            args.join(" "),
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !text.contains("API_TOKEN") && !text.contains("RED"),
            "{} leaked metadata while refusing, got: {text}",
            args.join(" "),
        );
    }
}

#[test]
fn search_withholds_control_bytes_in_group_paths_and_keeps_benign_matches() {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("hostile-group-path.kdbx");
    let mut database = KeePassDatabase::default();
    // Most C0 characters cannot be represented in XML 1.0, so they are tested
    // at the predicate layer. This reader normalizes U+0085 to LF; omit it and
    // verify below that every selected DEL/C1 character survives the round-trip.
    let representable_controls = (0x80..=0x84)
        .chain(0x86..=0x9f)
        .chain(std::iter::once(0x7f))
        .filter_map(char::from_u32)
        .collect::<String>();
    let mut group = Group::new(format!("needle{representable_controls}group"));
    group.add_entry(Entry::new("ordinary"));
    database.root.add_group(group);
    database.root.add_entry(Entry::new("needle-benign"));
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    // Prove the fixture actually round-trips each character before treating
    // this as end-to-end CLI coverage.
    let loaded = KdbxFile::load(
        std::fs::File::open(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap();
    assert_eq!(
        loaded.root.groups[0].name,
        format!("needle{representable_controls}group")
    );

    let output = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "search", "needle"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output
            .stdout
            .windows(b"needle-benign".len())
            .any(|window| window == b"needle-benign"),
        "the later benign match must remain visible: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    for &byte in &output.stdout {
        assert!(
            !byte.is_ascii_control() || byte == b'\n',
            "search emitted a raw control byte 0x{byte:02X} on stdout",
        );
    }
    let text = std::str::from_utf8(&output.stdout).expect("search stdout must be valid UTF-8");
    assert!(
        !text
            .chars()
            .any(|character| { character.is_control() && character != '\n' }),
        "search emitted a control character: {text:?}",
    );
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "hostile paths must be withheld");
    let record: serde_json::Value = serde_json::from_slice(records[0]).unwrap();
    assert_eq!(record["title"], "needle-benign");
    assert_eq!(record["path"], "Root/needle-benign");
    assert!(
        records[0]
            .windows(b"needle".len())
            .any(|window| window == b"needle"),
        "the NDJSON survivor record should contain the benign result",
    );
}

#[test]
fn root_prefixed_selectors_survive_unaddressable_siblings() {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
        ProtectedValue,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("unaddressable-sibling.kdbx");
    let mut database = KeePassDatabase::default();
    let mut unaddressable = Group::new("bad/group");
    let mut hidden = Group::new("hidden");
    hidden.add_entry(Entry::new("secret"));
    unaddressable.add_group(hidden);
    database.root.groups.push(unaddressable);
    let mut valid = Group::new("Valid");
    let mut slash_entry = Entry::new("bad/entry");
    slash_entry.password = ProtectedValue::from_text("wrong-raw-slash-entry");
    valid.add_entry(slash_entry);
    valid.add_entry(Entry::new("survivor"));
    let mut bad = Group::new("bad");
    let mut entry = Entry::new("entry");
    entry.password = ProtectedValue::from_text("actual-child-entry");
    bad.add_entry(entry);
    valid.add_group(bad);
    database.root.groups.push(valid);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let config = tmp.path().join("config");
    for key in ["Root/Valid/survivor", "Valid/survivor"] {
        let output = run_against(&vault, &config, &["secrets", "show", "--key", key]);
        assert!(
            output.status.success(),
            "valid selector {key:?} failed despite unrelated slash-containing siblings: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
    for key in ["Root/Valid/new-entry", "Valid/another-entry"] {
        let output = run_against(&vault, &config, &["ensure", "--key", key]);
        assert!(
            output.status.success(),
            "valid group selector {key:?} failed despite an unrelated slash-containing group sibling: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let selected = run_against(&vault, &config, &["get", "--key", "Root/Valid/bad/entry"]);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(selected.stdout, b"actual-child-entry");

    let candidates = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env("XDG_CONFIG_HOME", &config)
        .env("NKEEPASS_VAULT", &vault)
        .env("HOSTILE_TEST_PASSWORD", "hostile-test-password")
        .env("NKEEPASS_COMPLETE_PASSWORD_ENV", "HOSTILE_TEST_PASSWORD")
        .args(["__complete", "entries", "Root/Valid/bad/"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(candidates.status.success());
    assert_eq!(candidates.stdout, b"Root/Valid/bad/entry\n");
    let hidden = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env("XDG_CONFIG_HOME", &config)
        .env("NKEEPASS_VAULT", &vault)
        .env("HOSTILE_TEST_PASSWORD", "hostile-test-password")
        .env("NKEEPASS_COMPLETE_PASSWORD_ENV", "HOSTILE_TEST_PASSWORD")
        .args(["__complete", "entries", "Root/bad/group/"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(hidden.status.success());
    assert!(hidden.stdout.is_empty());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers root-path selection and ensure parity"
)]
fn renamed_root_and_personal_child_selectors_resolve_without_aliasing() {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
        ProtectedValue,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("renamed-root.kdbx");
    let mut database = KeePassDatabase::default();
    database.root.name = "Work Vault".into();
    let mut root_mail = Entry::new("Mail");
    root_mail.password = ProtectedValue::from_text("root-secret");
    database.root.add_entry(root_mail);
    let mut personal = Group::new("Personal");
    let mut mail = Entry::new("Mail");
    mail.password = ProtectedValue::from_text("child-secret");
    personal.add_entry(mail);
    database.root.add_group(personal);
    let mut colliding_root_name = Group::new("Work Vault");
    let mut collision_mail = Entry::new("Mail");
    collision_mail.password = ProtectedValue::from_text("collision-secret");
    colliding_root_name.add_entry(collision_mail);
    let mut nested_only = Entry::new("NestedOnly");
    nested_only.password = ProtectedValue::from_text("nested-only-secret");
    colliding_root_name.add_entry(nested_only);
    database.root.add_group(colliding_root_name);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let config = tmp.path().join("config");
    for key in ["Personal/Mail", "Work Vault/Personal/Mail"] {
        let output = run_against(&vault, &config, &["get", "--key", key]);
        assert!(
            output.status.success(),
            "{key:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout, b"child-secret",
            "{key:?} resolved to the wrong entry"
        );
    }
    assert_eq!(
        run_against(&vault, &config, &["get", "--key", "Mail"]).stdout,
        b"root-secret"
    );
    let ambiguous = run_against(&vault, &config, &["get", "--key", "Work Vault/Mail"]);
    assert!(
        !ambiguous.status.success(),
        "root/child name collision selected a credential"
    );
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous"));
    assert_eq!(
        run_against(
            &vault,
            &config,
            &["get", "--key", "Work Vault/Work Vault/Mail"]
        )
        .stdout,
        b"collision-secret"
    );
    for key in ["Work Vault/NestedOnly", "Work Vault/Work Vault/NestedOnly"] {
        let output = run_against(&vault, &config, &["get", "--key", key]);
        assert!(
            output.status.success(),
            "{key:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"nested-only-secret", "{key:?}");
    }
    for key in ["Work Vault/NestedOnly", "Work Vault/Work Vault/NestedOnly"] {
        let output = run_against(&vault, &config, &["ensure", "--key", key]);
        assert!(
            output.status.success(),
            "ensure {key:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let ambiguous_ensure = run_against(&vault, &config, &["ensure", "--key", "Work Vault/created"]);
    assert!(
        !ambiguous_ensure.status.success(),
        "ensure chose the root rather than the colliding child group"
    );
    let missing = run_against(&vault, &config, &["get", "--key", "Work Vault/NoSuchEntry"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("entry not found"));
    assert!(!String::from_utf8_lossy(&missing.stderr).contains("no group named \"Work Vault\""));

    for key in ["Personal/Created", "Work Vault/Personal/AlsoCreated"] {
        let output = run_against(&vault, &config, &["ensure", "--key", key]);
        assert!(
            output.status.success(),
            "{key:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let listing = run_against(&vault, &config, &["secrets", "ls", "Work Vault/Personal/*"]);
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Work Vault/Personal/Created"));
    assert!(listing.contains("Work Vault/Personal/AlsoCreated"));
}

#[test]
fn complete_root_prefixed_paths_ignore_unresolvable_duplicate_branches() {
    use neotales_keepass::{
        Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
        ProtectedValue,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("complete-path-candidates.kdbx");
    let mut database = KeePassDatabase::default();
    database.root.name = "Work Vault".into();

    let mut nested = Group::new("Work Vault");
    let mut first_x = Group::new("X");
    let mut nested_duplicate = Entry::new("Duplicate");
    nested_duplicate.password = ProtectedValue::from_text("nested-first-secret");
    first_x.add_entry(nested_duplicate);
    first_x.add_entry(Entry::new("NestedOnly"));
    let mut second_x = Group::new("X");
    let mut nested_duplicate = Entry::new("Duplicate");
    nested_duplicate.password = ProtectedValue::from_text("nested-second-secret");
    second_x.add_entry(nested_duplicate);
    nested.add_group(first_x);
    nested.add_group(second_x);
    database.root.add_group(nested);

    let mut root_x = Group::new("X");
    let mut mail = Entry::new("Mail");
    mail.password = ProtectedValue::from_text("root-x-mail-secret");
    root_x.add_entry(mail);
    let mut root_duplicate = Entry::new("Duplicate");
    root_duplicate.password = ProtectedValue::from_text("root-x-duplicate-secret");
    root_x.add_entry(root_duplicate);
    database.root.add_group(root_x);

    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let config = tmp.path().join("config");
    let mail = run_against(&vault, &config, &["get", "--key", "Work Vault/X/Mail"]);
    assert!(
        mail.status.success(),
        "{}",
        String::from_utf8_lossy(&mail.stderr)
    );
    assert_eq!(mail.stdout, b"root-x-mail-secret");

    let genuinely_ambiguous =
        run_against(&vault, &config, &["get", "--key", "Work Vault/X/Duplicate"]);
    assert!(!genuinely_ambiguous.status.success());
    assert!(String::from_utf8_lossy(&genuinely_ambiguous.stderr).contains("ambiguous"));

    let missing = run_against(&vault, &config, &["get", "--key", "Work Vault/X/Missing"]);
    assert!(!missing.status.success());
    let missing_stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing_stderr.contains("entry not found"),
        "{missing_stderr}"
    );
    assert!(!missing_stderr.contains("ambiguous"), "{missing_stderr}");
    let missing_after_duplicate_prefix = run_against(
        &vault,
        &config,
        &["get", "--key", "Work Vault/Work Vault/X/Missing/Mail"],
    );
    assert!(!missing_after_duplicate_prefix.status.success());
    let stderr = String::from_utf8_lossy(&missing_after_duplicate_prefix.stderr);
    assert!(stderr.contains("entry not found"), "{stderr}");
    assert!(!stderr.contains("ambiguous"), "{stderr}");

    let ambiguous_ensure = run_against(
        &vault,
        &config,
        &["ensure", "--key", "Work Vault/X/Created"],
    );
    assert!(!ambiguous_ensure.status.success());
    assert!(String::from_utf8_lossy(&ambiguous_ensure.stderr).contains("ambiguous"));

    // Reopen via the CLI after the failed mutation and verify no candidate got
    // the requested title.
    let listing = run_against(&vault, &config, &["secrets", "ls"]);
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    assert!(!String::from_utf8_lossy(&listing.stdout).contains("Created"));
}

#[test]
fn service_backed_search_preserves_ndjson_projection_and_order() {
    use neotales_keepass::{
        Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("search-parity.kdbx");
    let mut database = KeePassDatabase::default();
    let mut first = Entry::new("first");
    first.username = "alice".into();
    first.tags.push("work".into());
    first.fields.push(Field::new("token", "secret-value"));
    database.root.add_entry(first);
    let mut second = Entry::new("second");
    second.username = "alice".into();
    database.root.add_entry(second);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "search", "alice"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        concat!(
            "{\"fields\":[\"Title\",\"UserName\",\"token\"],\"path\":\"Root/first\",\"tags\":[],\"title\":\"first\"}\n",
            "{\"fields\":[\"Title\",\"UserName\"],\"path\":\"Root/second\",\"tags\":[],\"title\":\"second\"}\n",
        )
        .as_bytes(),
    );
    assert!(
        !output
            .stdout
            .windows(b"secret-value".len())
            .any(|window| window == b"secret-value")
    );
}

#[test]
fn search_keeps_matching_rules_duplicates_order_and_thousand_result_cap() {
    use neotales_keepass::{
        Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
        KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("search-contract.kdbx");
    let mut database = KeePassDatabase::default();
    let mut group = Group::new("group-needle");
    let mut duplicate_a = Entry::new("duplicate");
    duplicate_a.tags.push("needle-tag".into());
    group.add_entry(duplicate_a);
    let mut duplicate_b = Entry::new("duplicate");
    duplicate_b.url = "https://needle.example".into();
    group.add_entry(duplicate_b);
    for index in 0..1_001 {
        let mut entry = Entry::new(format!("needle-{index:04}"));
        entry.username = "needle-user".into();
        group.add_entry(entry);
    }
    let mut excluded = Entry::new("not-a-match");
    excluded.notes = "needle must not match notes".into();
    excluded
        .fields
        .push(Field::new("custom", "needle must not match fields"));
    group.add_entry(excluded);
    database.root.add_group(group);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "search", "needle"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1_000);
    assert_eq!(records[0]["path"], "Root/group-needle/duplicate");
    assert_eq!(records[1]["path"], "Root/group-needle/duplicate");
    assert_eq!(records[2]["path"], "Root/group-needle/needle-0000");
    assert_eq!(records[999]["path"], "Root/group-needle/needle-0997");
    assert!(records.iter().all(|record| {
        record
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["fields", "path", "tags", "title"]
    }));

    for query in ["", &"q".repeat(4_097)] {
        let invalid = run_against(
            &vault,
            &tmp.path().join("config"),
            &["secrets", "search", query],
        );
        assert_eq!(invalid.status.code(), Some(2));
        assert_eq!(invalid.stderr, b"nkeepass: invalid search query\n");
        assert!(invalid.stdout.is_empty());
    }
    let max_query = "q".repeat(4_096);
    let accepted = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "search", &max_query],
    );
    assert!(accepted.status.success());
    assert!(accepted.stdout.is_empty());
}

#[test]
fn cli_search_continues_past_more_than_ten_thousand_hostile_matches() {
    use neotales_keepass::{
        Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("search-hostile-continuation.kdbx");
    let mut database = KeePassDatabase::default();
    for _ in 0..10_005 {
        database.root.add_entry(Entry::new("needle\u{1b}"));
    }
    database.root.add_entry(Entry::new("needle-benign"));
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "search", "needle"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    let row: serde_json::Value = serde_json::from_slice(rows[0]).unwrap();
    assert_eq!(row["title"], "needle-benign");
}

#[test]
fn service_backed_ls_keeps_unfiltered_schema_and_vault_order() {
    use neotales_keepass::{
        Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("list-contract.kdbx");
    let mut database = KeePassDatabase::default();
    let mut first = Entry::new("first");
    first
        .fields
        .push(Field::new("custom", "must-not-be-output"));
    database.root.add_entry(first);
    let mut nested = neotales_keepass::Group::new("nested");
    nested.add_entry(Entry::new("third"));
    database.root.add_group(nested);
    database.root.add_entry(Entry::new("second"));
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = run_against(&vault, &tmp.path().join("config"), &["secrets", "ls"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        concat!(
            "{\"fields\":[\"Title\",\"custom\"],\"path\":\"Root/first\",\"tags\":[],\"title\":\"first\"}\n",
            "{\"fields\":[\"Title\"],\"path\":\"Root/second\",\"tags\":[],\"title\":\"second\"}\n",
            "{\"fields\":[\"Title\"],\"path\":\"Root/nested/third\",\"tags\":[],\"title\":\"third\"}\n",
        )
        .as_bytes(),
    );
    assert!(
        !output
            .stdout
            .windows(b"must-not-be-output".len())
            .any(|w| w == b"must-not-be-output")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end fixture verifies both service routes and selector safety"
)]
fn show_and_field_ls_resolve_through_service_without_changing_json_schemas() {
    use neotales_keepass::{
        Attachment, Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits,
        KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("selected-entry-contract.kdbx");
    let mut database = KeePassDatabase::default();
    database.root.groups.push(Group::new("bad/group"));
    database.root.add_entry(Entry::new("Login"));
    let mut folder = Group::new("Folder");
    folder.add_entry(Entry::new("bad/entry"));
    folder.add_entry(Entry::new("DUPLICATE"));
    folder.add_entry(Entry::new("duplicate"));
    let mut entry = Entry::new("Login");
    entry.tags.push("work".into());
    entry.fields.push(Field {
        key: "API_TOKEN".into(),
        value: neotales_keepass::ProtectedValue::from_text("never-output"),
        protected: true,
        protect_in_memory: true,
    });
    entry.fields.push(Field {
        key: "otp".into(),
        value: neotales_keepass::ProtectedValue::from_text("not-an-otp-uri"),
        protected: true,
        protect_in_memory: false,
    });
    entry.fields.push(Field {
        key: "Password".into(),
        value: neotales_keepass::ProtectedValue::from_text("password-value"),
        protected: true,
        protect_in_memory: false,
    });
    let attachment = database
        .binary_pool
        .add(b"attachment-secret".to_vec(), true);
    entry.attachments.push(Attachment {
        name: "attached.txt".into(),
        reference: attachment,
    });
    folder.add_entry(entry);
    database.root.add_group(folder);
    database.root.add_group(Group::new("DuplicateGroup"));
    database.root.add_group(Group::new("duplicategroup"));
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let config = tmp.path().join("config");

    let shown = run_against(
        &vault,
        &config,
        &["secrets", "show", "--key", "rOoT/fOlDeR/lOgIn"],
    );
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "attachments",
            "auto_type",
            "fields",
            "has_otp",
            "path",
            "tags",
            "title"
        ]
    );
    assert_eq!(value["path"], "rOoT/fOlDeR/lOgIn");
    assert_eq!(value["title"], "Login");
    assert_eq!(value["tags"], serde_json::json!([]));
    assert_eq!(
        value["attachments"],
        serde_json::json!([{ "name": "attached.txt" }])
    );
    assert_eq!(value["has_otp"], true);
    assert_eq!(
        value["auto_type"],
        serde_json::json!({"enabled": false, "associations": 0})
    );
    assert!(value["fields"].as_array().unwrap().iter().any(|field| {
        field["name"] == "API_TOKEN"
            && field["protected"] == true
            && field["protect_in_memory"] == true
    }));
    assert!(value["fields"].as_array().unwrap().iter().any(|field| {
        field["name"] == "Password"
            && field["protected"] == true
            && field["protect_in_memory"] == false
    }));
    assert!(!String::from_utf8_lossy(&shown.stdout).contains("never-output"));

    let fields = run_against(&vault, &config, &["field", "ls", "--key", "Folder/Login"]);
    assert!(
        fields.status.success(),
        "{}",
        String::from_utf8_lossy(&fields.stderr)
    );
    let rows = fields
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(rows.iter().any(|field| {
        field["name"] == "API_TOKEN"
            && field["protected"] == true
            && field["protect_in_memory"] == true
    }));
    assert!(rows.iter().any(|field| {
        field["name"] == "Password"
            && field["protected"] == true
            && field["protect_in_memory"] == false
    }));
    assert!(rows.iter().all(|field| {
        field
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["name", "protect_in_memory", "protected"]
    }));
    assert!(!String::from_utf8_lossy(&fields.stdout).contains("never-output"));

    let run_alias = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nkeepass"))
            .env("XDG_CONFIG_HOME", &config)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let alias_set = run_alias(&["alias", "set", "account", "Folder/Login"]);
    assert!(
        alias_set.status.success(),
        "{}",
        String::from_utf8_lossy(&alias_set.stderr)
    );
    let alias_show = run_against(&vault, &config, &["secrets", "show", "--key", "account"]);
    assert!(alias_show.status.success());
    let alias_value: serde_json::Value = serde_json::from_slice(&alias_show.stdout).unwrap();
    assert_eq!(alias_value["path"], "Folder/Login");

    let collision_set = run_alias(&["alias", "set", "Login", "Folder/Login"]);
    assert!(collision_set.status.success());
    let collision = run_against(&vault, &config, &["secrets", "show", "--key", "Login"]);
    assert!(!collision.status.success());
    assert!(collision.stdout.is_empty());

    for key in ["Folder/duplicate", "duplicategroup/Login"] {
        let ambiguous = run_against(&vault, &config, &["secrets", "show", "--key", key]);
        assert!(!ambiguous.status.success(), "{key:?} must be ambiguous");
        assert!(ambiguous.stdout.is_empty());
    }
}

#[test]
fn field_ls_ignores_unrelated_unsafe_metadata_but_rejects_unsafe_field_names() {
    use neotales_keepass::{
        Attachment, Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
        KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("field-list-hostile.kdbx");
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("target");
    entry.tags.push("bad\u{1b}tag".into());
    entry.fields.push(Field {
        key: "safe-field".into(),
        value: neotales_keepass::ProtectedValue::from_text("not-output"),
        protected: true,
        protect_in_memory: false,
    });
    let attachment = database.binary_pool.add(b"bytes".to_vec(), true);
    entry.attachments.push(Attachment {
        name: "bad\u{1b}attachment".into(),
        reference: attachment,
    });
    database.root.add_entry(entry);
    let mut unsafe_field = Entry::new("unsafe-field");
    unsafe_field.fields.push(Field {
        key: "bad\u{1b}field".into(),
        value: neotales_keepass::ProtectedValue::from_text("secret"),
        protected: false,
        protect_in_memory: false,
    });
    database.root.add_entry(unsafe_field);
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let config = tmp.path().join("config");
    let fields = run_against(&vault, &config, &["field", "ls", "--key", "target"]);
    assert!(
        fields.status.success(),
        "{}",
        String::from_utf8_lossy(&fields.stderr)
    );
    let rows: Vec<serde_json::Value> = fields
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let safe = rows.iter().find(|row| row["name"] == "safe-field").unwrap();
    assert_eq!(safe["protected"], true);
    assert_eq!(safe["protect_in_memory"], false);
    assert!(!String::from_utf8_lossy(&fields.stdout).contains("bad"));

    let rejected = run_against(&vault, &config, &["field", "ls", "--key", "unsafe-field"]);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
}

#[test]
fn ls_glob_withholds_only_matching_hostile_rows() {
    use neotales_keepass::{
        Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("list-glob-hostile.kdbx");
    let mut database = KeePassDatabase::default();
    database.root.add_entry(Entry::new("needle\u{1b}"));
    database.root.add_entry(Entry::new("needle-visible"));
    database.root.add_entry(Entry::new("other\u{1b}"));
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env("NKEEPASS_VAULT", &vault)
        .env("HOSTILE_TEST_PASSWORD", "hostile-test-password")
        .args([
            "secrets",
            "ls",
            "--password-env",
            "HOSTILE_TEST_PASSWORD",
            "--",
            "Root/needle*",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"{\"fields\":[\"Title\"],\"path\":\"Root/needle-visible\",\"tags\":[],\"title\":\"needle-visible\"}\n"
    );
    assert_eq!(
        output.stderr,
        b"nkeepass: 1 record(s) withheld: vault metadata contains terminal-control bytes\n"
    );

    let no_match = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "ls", "Root/absent*"],
    );
    assert!(no_match.status.success());
    assert!(no_match.stdout.is_empty());
    assert!(
        no_match.stderr.is_empty(),
        "non-matching hostile entries are not withheld results"
    );
}

#[test]
fn ls_continues_across_pages_without_the_search_result_cap() {
    use neotales_keepass::{
        Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("list-pages.kdbx");
    let mut database = KeePassDatabase::default();
    for index in 0..2_005 {
        database
            .root
            .add_entry(Entry::new(format!("entry-{index:04}")));
    }
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = run_against(&vault, &tmp.path().join("config"), &["secrets", "ls"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| serde_json::from_slice::<serde_json::Value>(row).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2_005);
    assert_eq!(rows[0]["path"], "Root/entry-0000");
    assert_eq!(rows[1_000]["path"], "Root/entry-1000");
    assert_eq!(rows[2_004]["path"], "Root/entry-2004");
    assert!(rows.iter().all(|row| {
        row.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["fields", "path", "tags", "title"]
    }));
}

#[test]
fn ls_rejects_globs_over_the_byte_limit_before_unlocking_the_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("missing.kdbx");
    let oversized = "x".repeat(1_025);
    let output = run_against(
        &vault,
        &tmp.path().join("config"),
        &["secrets", "ls", &oversized],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stderr,
        b"nkeepass: glob pattern is 1025 bytes; the limit is 1024\n"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn ls_propagates_a_closed_stdout_pipe() {
    use neotales_keepass::{
        Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    };

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("closed-pipe.kdbx");
    let mut database = KeePassDatabase::default();
    for index in 0..2_000 {
        database
            .root
            .add_entry(Entry::new(format!("entry-{index:04}")));
    }
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("hostile-test-password").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..Default::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env("NKEEPASS_VAULT", &vault)
        .env("HOSTILE_TEST_PASSWORD", "hostile-test-password")
        .args(["secrets", "ls", "--password-env", "HOSTILE_TEST_PASSWORD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stderr, b"nkeepass: cannot write output\n");
}

/// Every root command and shortcut answers `--help` with its own route.
#[test]
fn help_is_answered_at_every_command_depth() {
    let tmp = tempfile::tempdir().unwrap();
    let words = [
        "init",
        "context",
        "alias",
        "secrets",
        "automation",
        "get",
        "getx",
        "list",
        "ls",
        "search",
        "show",
        "set",
        "rm",
        "remove",
        "ensure",
        "otp",
        "setx",
        "import",
        "export",
        "sync",
        "env",
        "attachment",
        "attachments",
        "field",
        "custom-field",
        "config",
        "exec",
        "x",
        "completion",
        "version",
    ];
    for word in words {
        let output = cli(tmp.path(), &[word, "--help"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "`{word} --help` exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(word),
            "`{word} --help` succeeded but never mentioned `{word}`:\n{stdout}"
        );
        assert!(!stdout.trim().is_empty(), "`{word} --help` printed nothing");
    }
}

/// Root help is an overview, not the full manual. Check the built binary's real
/// output so spacing drift and an accidental return of the detailed prose are
/// visible without pinning the whole help text as a snapshot.
#[test]
fn root_help_is_aligned_scannable_and_points_to_details() {
    const DESCRIPTION_COLUMN: usize = 26;

    let tmp = tempfile::tempdir().unwrap();
    let output = cli(tmp.path(), &["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();

    let command_rows = help_section(&help, "COMMANDS");
    let labels: Vec<_> = command_rows
        .iter()
        .map(|row| row[..DESCRIPTION_COLUMN].trim())
        .collect();
    assert_eq!(
        labels,
        [
            "tui",
            "init",
            "context",
            "alias",
            "secrets",
            "automation",
            "attachment|attachments",
            "group|groups",
            "field|custom-field",
            "config",
            "exec|x",
            "completion",
            "version",
            "get",
            "getx",
            "list|ls",
            "search",
            "show",
            "set",
            "rm|remove",
            "ensure",
            "otp",
            "setx",
            "import",
            "export",
            "sync",
            "env",
        ],
        "root commands and accepted shortcuts should match the dispatcher:\n{help}"
    );
    for row in command_rows {
        assert!(
            row.len() > DESCRIPTION_COLUMN,
            "command row has no description: {row:?}"
        );
        assert!(
            row.starts_with("  "),
            "command row is not indented: {row:?}"
        );
        assert!(
            !row[..DESCRIPTION_COLUMN].trim().is_empty()
                && row[..DESCRIPTION_COLUMN].ends_with(' ')
                && !row[DESCRIPTION_COLUMN..].starts_with(' '),
            "description is not at column {DESCRIPTION_COLUMN}: {row:?}"
        );
    }
    for (number, line) in help.lines().enumerate() {
        assert!(
            line.len() <= 100,
            "help line {} is too wide ({} columns): {line}",
            number + 1,
            line.len()
        );
    }

    assert!(help.contains("WARNING: --password VALUE is exposed in process listings"));
    assert!(help.contains("credentials are prompted without echo"));
    let normalized_help = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_help.contains("init never overwrites or prints a password"));
    assert!(help.contains("Selected values are explicit disclosures"));
    assert!(help.contains("-h, --help"));
    assert!(help.contains("README"));
    assert!(help.contains("Glob syntax"));
    assert!(help.contains("Automation and interchange"));
    for obsolete_detail in [
        "NKEEPASS_VAULT_PATH",
        "timestamp is read ONCE",
        "passwords_pending",
        "MAXIMUM 64 KiB",
    ] {
        assert!(
            !help.contains(obsolete_detail),
            "root help contains detailed-manual prose {obsolete_detail:?}"
        );
    }
}

fn help_section<'a>(help: &'a str, section: &str) -> Vec<&'a str> {
    let marker = format!("{section}:");
    let Some(start) = help.lines().position(|line| line == marker) else {
        return Vec::new();
    };
    help.lines()
        .skip(start + 1)
        .take_while(|line| line.is_empty() || line.starts_with(' '))
        .filter(|line| !line.is_empty())
        .collect()
}

fn help_row_labels(rows: &[&str]) -> Vec<String> {
    rows.iter()
        .map(|row| row.split_whitespace().next().unwrap().to_owned())
        .collect()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven integration test keeps the full command-help matrix auditable"
)]
fn every_command_tier_has_its_own_help_and_direct_children() {
    let tmp = tempfile::tempdir().unwrap();
    let groups: &[(&[&str], &[&str])] = &[
        (&["context"], &["ls", "show", "use", "rm", "set"]),
        (&["alias"], &["ls|list", "set", "rm|remove", "resolve"]),
        (
            &["secrets"],
            &[
                "ls|list",
                "search",
                "env|environment",
                "show",
                "get",
                "getx",
                "set",
                "rm|remove",
                "ensure",
                "otp",
                "setx",
                "import",
                "export",
                "sync",
            ],
        ),
        (&["automation"], &["setx", "import", "export", "sync"]),
        (
            &["attachment"],
            &["ls|list", "add|import", "get|export", "rm|remove"],
        ),
        (
            &["field"],
            &["ls|list", "get|reveal", "set|edit", "rm|remove"],
        ),
        (&["config"], &["ls|list", "get|show", "set", "rm|remove"]),
    ];
    for (path, expected) in groups {
        for flag in ["--help", "-h"] {
            let output = cli(tmp.path(), &[path[0], flag]);
            assert!(output.status.success(), "{path:?} {flag} failed");
            let help = String::from_utf8(output.stdout).unwrap();
            let commands = help_row_labels(&help_section(&help, "COMMANDS"));
            let options = help_section(&help, "OPTIONS").join("\n");
            let global_options = help_section(&help, "GLOBAL OPTIONS").join("\n");
            assert_eq!(
                commands, *expected,
                "wrong direct children for {path:?}:\n{help}"
            );
            assert!(!options.contains("--vault PATH"));
            assert!(global_options.contains("--vault PATH"));
            assert!(options.contains("--help"));
            assert!(
                !options.contains("--password-env"),
                "group {path:?} advertises leaf credential options:\n{help}"
            );
            assert!(help.contains(&format!("Usage: {} {} <COMMAND>", help_program(), path[0])));
            for listed in *expected {
                for alias in listed.split('|') {
                    let output = cli(tmp.path(), &[path[0], alias, "--help"]);
                    assert!(
                        output.status.success(),
                        "nested alias {} {alias} did not answer help",
                        path[0]
                    );
                    let nested = String::from_utf8_lossy(&output.stdout);
                    assert!(
                        nested.contains(&format!("Usage: {} {} {alias}", help_program(), path[0])),
                        "help did not route to {} {alias}:\n{nested}",
                        path[0]
                    );
                }
            }
        }
    }

    let leaves: &[(&[&str], &str)] = &[
        (&["context", "show"], "Usage: nkeepass context show"),
        (
            &["context", "set"],
            "Usage: nkeepass context set ALIAS PATH",
        ),
        (&["context", "use"], "Usage: nkeepass context use ALIAS"),
        (&["context", "rm"], "Usage: nkeepass context rm ALIAS"),
        (&["context", "ls"], "Usage: nkeepass context ls"),
        (&["alias", "ls"], "Usage: nkeepass alias ls"),
        (&["alias", "set"], "--kind vault|entry"),
        (&["alias", "rm"], "Usage: nkeepass alias rm NAME"),
        (&["alias", "resolve"], "Usage: nkeepass alias resolve NAME"),
        (&["secrets", "ls"], "--password-env NAME"),
        (
            &["secrets", "search"],
            "Usage: nkeepass secrets search [--] QUERY",
        ),
        (&["secrets", "env"], "--name NAME"),
        (
            &["secrets", "show"],
            "Usage: nkeepass secrets show --key PATH",
        ),
        (&["secrets", "get"], "--format FORMAT"),
        (&["secrets", "getx"], "--key PATH"),
        (&["secrets", "set"], "--stdin"),
        (&["secrets", "rm"], "--yes"),
        (&["secrets", "ensure"], "--size N"),
        (&["secrets", "otp"], "--is-output"),
        (&["secrets", "setx"], "--dry-run"),
        (&["secrets", "import"], "--replace"),
        (&["secrets", "export"], "--output PATH"),
        (&["secrets", "sync"], "--strategy newest|source"),
        (&["automation", "setx"], "--file PATH"),
        (&["automation", "import"], "--replace"),
        (&["automation", "export"], "--output PATH"),
        (&["automation", "sync"], "--strategy newest|source"),
        (&["attachment", "ls"], "--key PATH"),
        (&["attachment", "add"], "--field FIELD"),
        (&["attachment", "get"], "--output PATH"),
        (&["attachment", "rm"], "--yes"),
        (&["field", "ls"], "Usage: nkeepass field ls --key PATH"),
        (&["field", "get"], "--field FIELD"),
        (&["field", "set"], "--stdin"),
        (&["field", "rm"], "--yes"),
        (&["config", "ls"], "--json"),
        (&["config", "get"], "Usage: nkeepass config get KEY"),
        (&["config", "set"], "Usage: nkeepass config set KEY VALUE"),
        (&["config", "rm"], "Usage: nkeepass config rm KEY"),
    ];
    for (path, expected) in leaves {
        for flag in ["--help", "-h"] {
            let mut args = path.to_vec();
            args.push(flag);
            let output = cli(tmp.path(), &args);
            assert!(
                output.status.success(),
                "{args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let help = String::from_utf8(output.stdout).unwrap();
            assert!(
                help.contains(&expected_help(expected)),
                "{args:?} omitted {expected:?}:\n{help}"
            );
            assert!(help.contains("OPTIONS:"), "{args:?} has no OPTIONS section");
            assert!(
                help.contains("--vault PATH"),
                "{args:?} omitted global options"
            );
            assert!(
                !help.contains("COMMANDS:"),
                "leaf {args:?} lists sibling commands"
            );
        }
    }
}

#[test]
fn help_flags_respect_global_options_values_and_exec_separator() {
    let tmp = tempfile::tempdir().unwrap();
    for flag in ["--help", "-h"] {
        let output = cli(tmp.path(), &[flag]);
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("COMMANDS:"));
    }
    for args in [
        vec!["--vault", "chosen.kdbx", "--help"],
        vec!["--help", "--vault", "chosen.kdbx"],
    ] {
        let output = cli(tmp.path(), &args);
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).starts_with(&format!("{} -", help_program()))
        );
    }
    for args in [
        vec!["secrets", "get", "--key", "ENTRY", "--help"],
        vec!["secrets", "get", "--help", "--key", "ENTRY"],
        vec!["--vault", "chosen.kdbx", "secrets", "ls", "-h"],
    ] {
        let output = cli(tmp.path(), &args);
        assert!(output.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("Usage: {} secrets", help_program()))
        );
    }

    // A help-looking argument consumed as an option value is not a help flag.
    let value = cli(tmp.path(), &["secrets", "get", "--key", "--help"]);
    assert!(!value.status.success());
    assert!(value.stdout.is_empty());
    let env_value = cli(tmp.path(), &["exec", "--env", "--help", "--"]);
    assert!(!env_value.status.success());
    assert!(env_value.stdout.is_empty());
}

#[test]
fn help_shows_only_options_allowed_by_the_selected_command() {
    let tmp = tempfile::tempdir().unwrap();
    for (args, expected_option, forbidden_option) in [
        (
            ["secrets", "ls", "--help"].as_slice(),
            "--password-env NAME",
            "--key PATH",
        ),
        (
            ["secrets", "get", "--help"].as_slice(),
            "--format FORMAT",
            "--stdin",
        ),
        (
            ["secrets", "env", "--help"].as_slice(),
            "--name NAME",
            "--dry-run",
        ),
        (
            ["config", "ls", "--help"].as_slice(),
            "--json",
            "--password-env",
        ),
        (
            ["alias", "set", "--help"].as_slice(),
            "--kind vault|entry",
            "--password-env",
        ),
        (
            ["init", "--help"].as_slice(),
            "--kdf aes|argon2d|argon2id",
            "--dry-run",
        ),
    ] {
        let output = cli(tmp.path(), args);
        assert!(output.status.success(), "{args:?}");
        let help = String::from_utf8(output.stdout).unwrap();
        let options = help_section(&help, "OPTIONS").join("\n");
        assert!(options.contains(expected_option), "{args:?}:\n{help}");
        assert!(
            !options.contains(forbidden_option),
            "{args:?} advertised unsupported option {forbidden_option}:\n{help}"
        );
    }

    let exec = cli(tmp.path(), &["exec", "--help"]);
    let exec_help = String::from_utf8(exec.stdout).unwrap();
    let exec_options = help_section(&exec_help, "OPTIONS").join("\n");
    let normalized_exec_help = exec_help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_exec_help.contains(
        &expected_help(
            "Usage: nkeepass exec [--key PATH [--field FIELD] --env NAME]... [OPTIONS] -- COMMAND [ARG ...]"
        )
    ));
    for option in ["--key PATH", "--field FIELD", "--env NAME"] {
        assert!(
            exec_options.contains(option),
            "exec help omitted {option}:\n{exec_help}"
        );
    }
    assert!(!exec_options.contains("--dry-run"));
}

#[test]
fn rendered_command_help_aligns_wrapped_option_descriptions() {
    let tmp = tempfile::tempdir().unwrap();
    let output = cli(tmp.path(), &["secrets", "ls", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let options = help_section(&help, "OPTIONS");
    let password_row = options
        .iter()
        .position(|row| row.contains("--password VALUE"))
        .expect("rendered help should contain the password option");
    let description_column = options[password_row]
        .find("Unsafe compatibility mode")
        .expect("password option description should be rendered");
    let continuation = options[password_row + 1];
    assert_eq!(
        description_column, 24,
        "unexpected rendered column:\n{help}"
    );
    assert!(
        continuation.starts_with(&" ".repeat(description_column)),
        "wrapped description should align below the first description:\n{help}"
    );
    assert!(continuation.trim_start().starts_with("history."));
}

#[test]
fn accepted_root_and_nested_aliases_route_to_their_own_help() {
    let tmp = tempfile::tempdir().unwrap();
    for (args, usage) in [
        (&["x", "--help"][..], "Usage: nkeepass x [--key PATH"),
        (
            &["attachments", "ls", "--help"][..],
            "Usage: nkeepass attachments ls --key PATH",
        ),
        (
            &["custom-field", "get", "--help"][..],
            "Usage: nkeepass custom-field get --key PATH --field FIELD [OPTIONS]",
        ),
        (
            &["secrets", "list", "--help"][..],
            "Usage: nkeepass secrets list [--] [GLOB]",
        ),
        (
            &["secrets", "environment", "--help"][..],
            "Usage: nkeepass secrets environment [--key PATH",
        ),
        (
            &["config", "show", "--help"][..],
            "Usage: nkeepass config show KEY",
        ),
        (&["get", "--help"][..], "Usage: nkeepass get [OPTIONS]"),
    ] {
        for flag in ["--help", "-h"] {
            let mut with_flag = args.to_vec();
            with_flag.push(flag);
            let output = cli(tmp.path(), &with_flag);
            assert!(output.status.success(), "{with_flag:?}");
            let help = String::from_utf8(output.stdout).unwrap();
            assert!(
                help.contains(&expected_help(usage)),
                "{with_flag:?}:\n{help}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn help_uses_the_argv0_basename_including_executable_extension() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;

    let tmp = tempfile::tempdir().unwrap();
    for (argv0, expected) in [
        (OsString::from("/opt/nkeepass"), "nkeepass"),
        (OsString::from("nkp"), "nkp"),
        (OsString::from("/opt/tools/nkp.exe"), "nkp.exe"),
        (OsString::from("/opt/tools/工具"), "工具"),
        (OsString::from_vec(b"/opt/tools/nkp-\xff".to_vec()), "nkp-�"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nkeepass"));
        command
            .arg0(argv0)
            .arg("secrets")
            .arg("get")
            .arg("--help")
            .env("XDG_CONFIG_HOME", tmp.path())
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH");
        let output = command.output().unwrap();
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(help.starts_with(&format!("{expected} secrets get\n")));
        assert!(help.contains(&format!("Usage: {expected} secrets get")));
        assert!(!help.contains("/opt/"));
    }
}

/// Nested help preserves the complete command path in its title and usage.
#[test]
fn help_names_the_group_and_the_subcommand_together() {
    let tmp = tempfile::tempdir().unwrap();
    for (args, expected) in [
        (["secrets", "ensure", "--help"], "secrets ensure"),
        (["secrets", "ls", "--help"], "secrets ls"),
        (["config", "ls", "--help"], "config ls"),
        (["field", "get", "--help"], "field get"),
    ] {
        let output = cli(tmp.path(), &args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{args:?} exited non-zero");
        assert!(
            stdout.contains(expected),
            "{args:?} did not name `{expected}`:\n{stdout}"
        );
    }
}

/// `-h` is the same request for both command-specific help and root groups.
#[test]
fn short_help_flag_and_group_help_work() {
    let tmp = tempfile::tempdir().unwrap();
    for word in ["init", "config"] {
        for flag in ["--help", "-h"] {
            let output = cli(tmp.path(), &[word, flag]);
            assert!(
                output.status.success(),
                "`{word} {flag}` exited {:?}",
                output.status.code()
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.starts_with(&format!("{} {word}", help_program())),
                "`{word} {flag}` lost its command-specific usage:\n{stdout}"
            );
        }
    }
}

/// A child's own `--help` belongs to the child.
///
/// `exec` runs a program, and that program's arguments live after a bare `--`.
/// Scanning for `--help` past that separator would make `nkeepass exec -- myapp
/// --help` print this CLI's reference instead of running `myapp --help`, which
/// would be a command unable to launch anything that takes a flag.
#[test]
fn exec_passes_help_through_to_the_child_rather_than_answering_it() {
    let tmp = tempfile::tempdir().unwrap();

    // A child that reports its own arguments, so a `--help` that reached it is
    // visible rather than merely inferred from the exit status.
    let child = tmp.path().join("child.sh");
    std::fs::write(
        &child,
        "#!/bin/sh\nfor a in \"$@\"; do echo \"arg:$a\"; done\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args([
            "exec",
            "--key",
            "nothing",
            "--env",
            "X",
            "--",
            "sh",
            child.to_str().unwrap(),
            "--help",
        ])
        .env("XDG_CONFIG_HOME", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Whatever this CLI decides about the missing key, the child's own output
    // must not be replaced by this CLI's help text.
    assert!(
        !stdout.contains("nkeepass - headless KeePass CLI"),
        "exec answered --help itself instead of passing it on:\n{stdout}"
    );
}

/// The reason an entry path could not be resolved, not one message for four causes.
///
/// `lookup_entry` answered `ambiguous or invalid entry path` for all of these:
///
///   1. a group in the path that this vault does not have;
///   2. a group or entry whose own name contains `/`, so no path can address it;
///   3. two names differing only in case, where the path is genuinely ambiguous;
///   4. a path naming the root group rather than an entry.
///
/// Only (1) is something a user hits by accident, and it is the one the old
/// message was worst at: nothing in `secrets ensure --key prod/db` mentions an
/// alias, a group, or a case collision, so the message described none of the three
/// things that could be wrong. Each now names its own cause, and (1) -- the only
/// one with a next step -- names it too.
#[test]
fn an_unresolvable_entry_path_says_which_of_the_reasons_it_is() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("v.kdbx");
    let vault = vault.to_str().unwrap();

    // The master password arrives on stdin, through `--password-stdin`, rather
    // than through an environment variable. Both are documented sources and both
    // work; stdin is the one a caller reaches for when the password must not sit
    // in the process environment, and it is a path worth having a test on.
    let run = |args: &[&str]| -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nkeepass"));
        child
            .args(args)
            .env("XDG_CONFIG_HOME", tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = child.spawn().expect("nkeepass should start");
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(b"pw-for-this-test\n")
            .expect("the password should reach the child");
        child.wait_with_output().expect("nkeepass should finish")
    };

    // A vault with no groups. Built through the CLI rather than from a checked-in
    // fixture, so the test does not depend on a binary file and the shape of the
    // vault is whatever this version of `init` produces.
    let created = run(&["init", vault, "--password-stdin", "--iterations", "64"]);
    assert!(
        created.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let ask = |key: &str| -> String {
        let output = run(&[
            "--vault",
            vault,
            "secrets",
            "get",
            "--key",
            key,
            "--password-stdin",
        ]);
        assert!(!output.status.success(), "{key} unexpectedly resolved");
        String::from_utf8_lossy(&output.stderr).trim().to_owned()
    };

    // (1) the missing group, with the way out.
    let missing = ask("prod/db");
    assert!(
        missing.contains("no group named \"prod\""),
        "a missing group did not name itself: {missing}"
    );
    assert!(
        missing.contains("group add") && missing.contains("secrets ensure"),
        "a missing group did not name a command that creates it: {missing}"
    );
    assert!(
        !missing.contains("ambiguous"),
        "a missing group was still called ambiguous: {missing}"
    );

    // (4) the root group, which is not an entry.
    let root = ask("Root");
    assert!(
        root.contains("root group"),
        "naming the root was not explained: {root}"
    );

    // A well-formed path that simply is not there keeps its own message, because
    // that is a different answer to a different question.
    let absent = ask("nothing-here");
    assert_eq!(absent, "nkeepass: entry not found");
}

/// A command with a home directory, so it gets as far as the vault.
///
/// `cli_support::command` clears the environment on purpose, which is right for
/// proving that nothing is inherited -- but this CLI resolves a configuration and
/// data directory before it opens anything, so with neither set every command here
/// failed with `home directory unavailable`.
///
/// That failure mode is worth naming, because it is the dangerous one: the three
/// cases in this file that *expect* a refusal were passing for the wrong reason,
/// before this helper existed. A test that cannot distinguish "the key file was
/// rejected" from "the process could not start" is not testing the key file.
fn key_file_command(fixture: &nkeepass_cli::CliFixture) -> std::process::Command {
    let mut child = nkeepass_cli::command(Path::new(env!("CARGO_BIN_EXE_nkeepass")), fixture);
    child
        .env("XDG_CONFIG_HOME", fixture.directory().join("config"))
        .env("XDG_DATA_HOME", fixture.directory().join("data"))
        .env("HOME", fixture.directory());
    child
}

/// A child that prints how many `NKEEPASS_*` variables it can see, and the
/// arguments needed to reach it.
///
/// Split by platform for the same reason as [`child_reporting_script_value`]: this
/// file's runner clears the environment, and `sh` is not on a Windows PATH, so
/// naming it unconditionally fails with "cannot run child command" -- which says
/// nothing about whether the allowlist leaked, the thing under test.
#[cfg(unix)]
fn child_counting_nkeepass_variables() -> (&'static str, Vec<String>) {
    (
        "sh",
        vec![
            "-c".to_owned(),
            "env | grep -c '^NKEEPASS_' || true".to_owned(),
        ],
    )
}

#[cfg(windows)]
fn child_counting_nkeepass_variables() -> (&'static str, Vec<String>) {
    // `set NKEEPASS_` alone is not usable: with no match, cmd writes
    // "Environment variable NKEEPASS_ not defined" to stderr and exits non-zero,
    // which is indistinguishable from the child having run and failed. A trailing
    // `& echo` makes the exit status the echo's, and the marker is what the
    // assertion looks for -- so "nothing leaked" is a clean line and a leak is
    // text before the marker.
    (
        "cmd",
        vec![
            "/C".to_owned(),
            "set NKEEPASS_ & echo nkeepass-no-leak-marker".to_owned(),
        ],
    )
}

/// A key file is a first-class credential component, and it had no tests at all.
///
/// `--key-file` is documented in `--help`, takes a separate code path through the
/// credential builder, and includes the branch that matters most: a key file on its
/// own must skip the password prompt entirely. An untested credential path in a
/// secrets tool is one that has never been shown to work and never been shown to
/// fail safely, and the prompt-skipping branch is the dangerous one — if it is
/// wrong, a key-file user gets a silent authentication result rather than an error.
///
/// Every case here runs the real binary against a real vault built with a real key
/// file, so the composite credential is exercised rather than mocked.
#[test]
fn a_key_file_alone_opens_the_vault_and_skips_the_password_prompt() {
    use nkeepass_cli::{CliFixture, ENTRY_TITLE, MASTER_PASSWORD, run_with_stdin};

    let fixture = CliFixture::key_file_only();
    let mut child = key_file_command(&fixture);
    child.args([
        "--vault",
        fixture.vault().to_str().unwrap(),
        "secrets",
        "ls",
        "--key-file",
        fixture.key_file().to_str().unwrap(),
    ]);
    // stdin is a pipe carrying nothing, so any prompt would read EOF rather than
    // block. A prompt that is skipped proves itself by the command succeeding; a
    // prompt that is not skipped cannot succeed here at all.
    let output = run_with_stdin(&mut child, b"");
    assert!(
        output.status.success(),
        "a key file alone did not open the vault: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(ENTRY_TITLE),
        "the listing did not include the entry: {stdout}"
    );
    // The master password is set in the environment, so a command that consulted
    // it would still have worked. This asserts the key file was sufficient.
    let _ = MASTER_PASSWORD;
}

#[test]
fn a_key_file_and_a_password_together_open_the_same_vault() {
    use nkeepass_cli::{CliFixture, ENTRY_TITLE, MASTER_PASSWORD};

    let fixture = CliFixture::new(true);
    let output = key_file_command(&fixture)
        .args([
            "--vault",
            fixture.vault().to_str().unwrap(),
            "secrets",
            "ls",
            "--key-file",
            fixture.key_file().to_str().unwrap(),
            "--password-env",
            "PW",
        ])
        .env("PW", MASTER_PASSWORD)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the composite credential did not open the vault: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(ENTRY_TITLE));
}

/// A wrong key file must fail, and must say so without echoing the path.
///
/// A key file is not a secret in the way a password is, but the path to one names
/// the vault it opens, and an error that quotes the path turns a failed
/// authentication into a disclosure in whatever log captured it.
#[test]
fn a_wrong_key_file_fails_with_a_static_diagnostic_and_no_path() {
    use nkeepass_cli::{CliFixture, assert_no_secrets};

    let fixture = CliFixture::new(true);
    let wrong = fixture.directory().join("not-the-key");
    // 32 bytes, so it parses as a key file and fails on the value rather than on
    // the shape. Otherwise this would test the parser and not the credential.
    std::fs::write(&wrong, b"wrong-key-file-contents-0000000").unwrap();

    let output = key_file_command(&fixture)
        .args([
            "--vault",
            fixture.vault().to_str().unwrap(),
            "secrets",
            "ls",
            "--key-file",
            wrong.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a wrong key file opened the vault"
    );
    assert!(output.stdout.is_empty(), "a failure wrote to stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(wrong.to_str().unwrap()),
        "the diagnostic quoted the key file's path: {stderr}"
    );
    assert_no_secrets(&output);
}

#[test]
fn a_missing_key_file_fails_with_a_static_diagnostic() {
    use nkeepass_cli::CliFixture;

    let fixture = CliFixture::new(true);
    let absent = fixture.directory().join("absent.key");
    let output = key_file_command(&fixture)
        .args([
            "--vault",
            fixture.vault().to_str().unwrap(),
            "secrets",
            "ls",
            "--key-file",
            absent.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a missing key file opened the vault"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("absent.key"),
        "the diagnostic quoted the missing path: {stderr}"
    );
}

#[test]
fn a_key_file_that_is_a_directory_is_refused() {
    use nkeepass_cli::CliFixture;

    let fixture = CliFixture::new(true);
    let output = key_file_command(&fixture)
        .args([
            "--vault",
            fixture.vault().to_str().unwrap(),
            "secrets",
            "ls",
            "--key-file",
            fixture.directory().to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a directory was accepted as a key file"
    );
    assert!(output.stdout.is_empty());
}

/// No vault-related variable reaches a child, whichever credential opened the vault.
///
/// The allowlist in `child_environment` already excludes `NKEEPASS_*`, and
/// `exec_does_not_pass_the_parent_environment_to_the_child` covers a
/// password-only vault. This is the key-file half of the same claim: a key file is
/// passed by *path*, so the path is exactly the thing most likely to leak, and it
/// travels in argv rather than in the environment.
#[test]
fn exec_with_a_key_file_passes_no_nkeepass_variable_to_the_child() {
    use nkeepass_cli::{CliFixture, ENTRY_TITLE, MASTER_PASSWORD, assert_no_secrets};

    let fixture = CliFixture::new(true);
    let (child, child_args) = child_counting_nkeepass_variables();
    let mut args: Vec<&str> = vec![
        "--vault",
        fixture.vault().to_str().unwrap(),
        "exec",
        "--key",
        ENTRY_TITLE,
        "--env",
        "INJECTED",
        "--key-file",
        fixture.key_file().to_str().unwrap(),
        "--password-env",
        "PW",
        "--",
        child,
    ];
    args.extend(child_args.iter().map(String::as_str));
    let output = key_file_command(&fixture)
        .args(args)
        .env("PW", MASTER_PASSWORD)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exec with a key file did not run the child: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if cfg!(windows) {
        assert_eq!(
            stdout.trim(),
            "nkeepass-no-leak-marker",
            "a NKEEPASS_ variable reached the child: {stdout}"
        );
    } else {
        assert_eq!(
            stdout.trim(),
            "0",
            "a NKEEPASS_ variable reached the child: {stdout}"
        );
    }
    assert_no_secrets(&output);
}
