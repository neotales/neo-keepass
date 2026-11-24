//! End-to-end integration tests for `nkp inject`, `nkp x --env-file`,
//! `nkp trust` / `nkp untrust`, `nkp shell` subcommands, `nkp __hook`, and a
//! real `/usr/bin/bash` direnv-style lifecycle.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "end-to-end integration test assertions"
)]

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use neotales_keepass::{
    Entry, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    ProtectedValue,
};
use tempfile::TempDir;

const MASTER_PASSWORD: &str = "shell-inject-master-disposable-9a4f";
const WORK_PASSWORD: &str = "shell-inject-master-disposable-9a4f";
const STRIPE_SECRET: &str = "sk_live_disposable_5184";
const PG_SECRET: &str = "pg_pass'\"quote_disposable";
const WORK_SECRET: &str = "work_api_secret_disposable_72c1";
const MULTILINE_SECRET: &str = "line1\nline2#hash";

struct TestFixture {
    dir: TempDir,
    vault: PathBuf,
    work_vault: PathBuf,
    config_dir: PathBuf,
    data_dir: PathBuf,
}

impl TestFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let data_dir = dir.path().join("data");

        let mut db = KeePassDatabase::default();
        let mut projects = Group::new("projects");
        let mut myapp = Group::new("myapp");

        let mut stripe = Entry::new("stripe");
        stripe.password = ProtectedValue::from_text(STRIPE_SECRET);
        myapp.entries.push(stripe);

        let mut postgres = Entry::new("postgres");
        postgres.username = "pg_user".into();
        postgres.password = ProtectedValue::from_text(PG_SECRET);
        myapp.entries.push(postgres);

        projects.groups.push(myapp);
        db.root.groups.push(projects);

        let mut services = Group::new("services");
        let mut recursive = Entry::new("recursive");
        recursive.password = ProtectedValue::from_text("nkp://projects/myapp/stripe");
        services.entries.push(recursive);

        let mut multiline = Entry::new("multiline");
        multiline.password = ProtectedValue::from_text(MULTILINE_SECRET);
        services.entries.push(multiline);

        let mut unsafe_ctrl = Entry::new("unsafe_ctrl");
        unsafe_ctrl.password = ProtectedValue::from_text("bad\u{001b}[31msecret");
        services.entries.push(unsafe_ctrl);
        db.root.groups.push(services);

        let vault = dir.path().join("primary.kdbx");
        KdbxFile::save(
            &db,
            fs::File::create(&vault).unwrap(),
            &mut KdbxCredentials::password(MASTER_PASSWORD).unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).unwrap();

        let mut work_db = KeePassDatabase::default();
        let mut api = Group::new("api");
        let mut key = Entry::new("key");
        key.password = ProtectedValue::from_text(WORK_SECRET);
        api.entries.push(key);
        work_db.root.groups.push(api);

        let work_vault = dir.path().join("work.kdbx");
        KdbxFile::save(
            &work_db,
            fs::File::create(&work_vault).unwrap(),
            &mut KdbxCredentials::password(WORK_PASSWORD).unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        fs::set_permissions(&work_vault, fs::Permissions::from_mode(0o600)).unwrap();

        Self {
            dir,
            vault,
            work_vault,
            config_dir,
            data_dir,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
        cmd.env("HOME", self.dir.path())
            .env("XDG_CONFIG_HOME", &self.config_dir)
            .env("XDG_DATA_HOME", &self.data_dir)
            .stdin(Stdio::null());
        cmd
    }

    fn cmd_with_pw(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.env("NKEEPASS_TEST_PW", MASTER_PASSWORD);
        cmd
    }

    fn register_work_alias(&self) {
        let out = self
            .cmd()
            .args([
                "alias",
                "set",
                "work",
                self.work_vault.to_str().unwrap(),
                "--kind",
                "vault",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "alias set failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn write_private(path: &Path, content: &str) {
    fs::write(path, content.as_bytes()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn inject_raw_dotenv_check_output_alias_literal_only_and_non_recursive() {
    let fx = TestFixture::new();
    fx.register_work_alias();

    // 1. Raw template with bare nkp://, braced {{nkp://...}}, @work/ alias, and non-recursive ref.
    let tmpl_path = fx.dir.path().join("app.tmpl");
    fs::write(
        &tmpl_path,
        "stripe=nkp://projects/myapp/stripe\n\
         dsn=postgres://{{nkp://projects/myapp/postgres#UserName}}:{{nkp://projects/myapp/postgres}}@db.internal:5432/app\n\
         work=nkp://@work/api/key\n\
         nonrec=nkp://services/recursive\n",
    )
    .unwrap();

    for input_args in [
        vec![tmpl_path.to_str().unwrap()],
        vec!["--", tmpl_path.to_str().unwrap()],
        vec!["-f", tmpl_path.to_str().unwrap()],
    ] {
        let mut args = vec![
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            "--password-env",
            "NKEEPASS_TEST_PW",
        ];
        args.extend(input_args);
        let out = fx.cmd_with_pw().args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "inject failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stderr.is_empty());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(
            stdout,
            format!(
                "stripe={STRIPE_SECRET}\n\
                 dsn=postgres://pg_user:{PG_SECRET}@db.internal:5432/app\n\
                 work={WORK_SECRET}\n\
                 nonrec=nkp://projects/myapp/stripe\n"
            )
        );
    }

    // 2. --stdin + -o private no-clobber output
    let out_file = fx.dir.path().join("rendered.txt");
    let mut child = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            "--stdin",
            "-o",
            out_file.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"token={{nkp://projects/myapp/stripe}}\n")
        .unwrap();
    let stdin_out = child.wait_with_output().unwrap();
    assert!(
        stdin_out.status.success(),
        "inject --stdin -o failed: {}",
        String::from_utf8_lossy(&stdin_out.stderr)
    );
    assert!(stdin_out.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(&out_file).unwrap(),
        format!("token={STRIPE_SECRET}\n")
    );
    let mode = fs::metadata(&out_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // No-clobber refuses overwriting existing file
    let clobber = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            tmpl_path.to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .output()
        .unwrap();
    assert!(!clobber.status.success());

    // 3. --format dotenv
    let env_tmpl = fx.dir.path().join("secret.env");
    fs::write(
        &env_tmpl,
        "export API_KEY=nkp://projects/myapp/stripe # prod\n\
         PLAIN=actualValue # literal\n\
         MULTI=nkp://services/multiline\n\
         WORK=nkp://@work/api/key\n",
    )
    .unwrap();
    let dotenv_out = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            "-f",
            env_tmpl.to_str().unwrap(),
            "--format",
            "dotenv",
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .output()
        .unwrap();
    assert!(
        dotenv_out.status.success(),
        "inject --format dotenv failed: {}",
        String::from_utf8_lossy(&dotenv_out.stderr)
    );
    let dotenv_text = String::from_utf8(dotenv_out.stdout).unwrap();
    assert_eq!(
        dotenv_text,
        format!(
            "API_KEY=\"{STRIPE_SECRET}\"\n\
             PLAIN=\"actualValue\"\n\
             MULTI=\"line1\\nline2#hash\"\n\
             WORK=\"{WORK_SECRET}\"\n"
        )
    );

    // 4. --check emits zero secrets and fails on missing ref; conflicts with -o
    let check_ok = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            tmpl_path.to_str().unwrap(),
            "--check",
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .output()
        .unwrap();
    assert!(check_ok.status.success());
    assert!(check_ok.stdout.is_empty());

    let missing_tmpl = fx.dir.path().join("missing_ref.tmpl");
    fs::write(
        &missing_tmpl,
        "ok=nkp://projects/myapp/stripe\nmissing=nkp://no/such/entry\n",
    )
    .unwrap();
    let atomic_out = fx.dir.path().join("should_not_exist.txt");
    let missing_fail = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            missing_tmpl.to_str().unwrap(),
            "-o",
            atomic_out.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .output()
        .unwrap();
    assert!(!missing_fail.status.success());
    assert!(missing_fail.stdout.is_empty());
    assert!(!atomic_out.exists());

    let check_missing = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "inject",
            missing_tmpl.to_str().unwrap(),
            "--check",
            "--password-env",
            "NKEEPASS_TEST_PW",
        ])
        .output()
        .unwrap();
    assert!(!check_missing.status.success());
    assert!(check_missing.stdout.is_empty());

    let check_output_conflict = fx
        .cmd_with_pw()
        .args([
            "inject",
            tmpl_path.to_str().unwrap(),
            "--check",
            "-o",
            atomic_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!check_output_conflict.status.success());

    // 5. Literal-only input succeeds without vault or password!
    let literal_tmpl = fx.dir.path().join("literal.tmpl");
    fs::write(&literal_tmpl, "HELLO=world\nLITERAL_BRACES={{not_nkp}}\n").unwrap();
    let lit_out = fx
        .cmd()
        .args(["inject", literal_tmpl.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        lit_out.status.success(),
        "literal-only inject failed: {}",
        String::from_utf8_lossy(&lit_out.stderr)
    );
    assert_eq!(
        String::from_utf8(lit_out.stdout).unwrap(),
        "HELLO=world\nLITERAL_BRACES={{not_nkp}}\n"
    );

    // 6. Conflicting inputs and non-regular-file rejection
    for bad in [
        vec![tmpl_path.to_str().unwrap(), "--stdin"],
        vec![
            tmpl_path.to_str().unwrap(),
            "-f",
            tmpl_path.to_str().unwrap(),
        ],
        vec!["--stdin", "--password-stdin"],
        vec![fx.dir.path().to_str().unwrap()],
    ] {
        let mut args = vec!["inject"];
        args.extend(bad);
        let res = fx.cmd().args(&args).output().unwrap();
        assert!(!res.status.success(), "unexpectedly accepted {args:?}");
    }
}

#[test]
fn exec_env_file_resolves_secrets_literals_and_enforces_isolation() {
    let fx = TestFixture::new();
    fx.register_work_alias();

    let env_file = fx.dir.path().join("exec.env");
    fs::write(
        &env_file,
        "export STRIPE_KEY=nkp://projects/myapp/stripe\n\
         export PLAIN=actualValue\n\
         WORK_KEY=nkp://@work/api/key\n",
    )
    .unwrap();

    let out = fx
        .cmd_with_pw()
        .env("UNRELATED_SECRET", "must-not-leak")
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "x",
            "--env-file",
            env_file.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s|%s|%s|%s|%s|%s' \"$STRIPE_KEY\" \"$PLAIN\" \"$WORK_KEY\" \"${UNRELATED_SECRET:-absent}\" \"${NKEEPASS_TEST_PW:-absent}\" \"$1\"",
            "sh",
            "--help",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "nkp x --env-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{STRIPE_SECRET}|actualValue|{WORK_SECRET}|absent|absent|--help")
    );

    // Literal-only --env-file works without vault or password!
    let lit_env = fx.dir.path().join("literal.env");
    fs::write(&lit_env, "PLAIN_ONLY=hello_literal\n").unwrap();
    let lit_out = fx
        .cmd()
        .args([
            "x",
            "--env-file",
            lit_env.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$PLAIN_ONLY\"",
        ])
        .output()
        .unwrap();
    assert!(lit_out.status.success());
    assert_eq!(lit_out.stdout, b"hello_literal");

    // Combined --env-file + -B and collision rejection across sources
    let second_env = fx.dir.path().join("second.env");
    fs::write(&second_env, "EXTRA=from_second\n").unwrap();
    let combined_out = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "x",
            "-B",
            "BOUND=projects/myapp/stripe",
            "--env-file",
            lit_env.to_str().unwrap(),
            "--env-file",
            second_env.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s|%s|%s' \"$BOUND\" \"$PLAIN_ONLY\" \"$EXTRA\"",
        ])
        .output()
        .unwrap();
    assert!(combined_out.status.success());
    assert_eq!(
        String::from_utf8(combined_out.stdout).unwrap(),
        format!("{STRIPE_SECRET}|hello_literal|from_second")
    );

    // Collision between --bind and --env-file must fail closed
    let collide = fx
        .cmd_with_pw()
        .args([
            "-V",
            fx.vault.to_str().unwrap(),
            "x",
            "-B",
            "PLAIN_ONLY=projects/myapp/stripe",
            "--env-file",
            lit_env.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PW",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!collide.status.success());

    // Reserved var in --env-file must fail closed
    let reserved_env = fx.dir.path().join("reserved.env");
    fs::write(&reserved_env, "LD_PRELOAD=/tmp/evil.so\n").unwrap();
    let reserved = fx
        .cmd()
        .args([
            "x",
            "--env-file",
            reserved_env.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!reserved.status.success());
}

#[test]
fn trust_untrust_list_prune_and_tamper_detection() {
    let fx = TestFixture::new();
    let proj = fx.dir.path().join("proj");
    fs::create_dir(&proj).unwrap();

    // Non-vault route rejects -V and credential options
    for bad in [
        vec![
            "-V",
            fx.vault.to_str().unwrap(),
            "trust",
            proj.to_str().unwrap(),
        ],
        vec!["trust", "--password-env", "NKEEPASS_TEST_PW"],
        vec!["trust", "--password-stdin"],
        vec!["-V", fx.vault.to_str().unwrap(), "untrust", "--all"],
        vec!["untrust", "--password-env", "NKEEPASS_TEST_PW"],
    ] {
        let out = fx.cmd_with_pw().args(&bad).output().unwrap();
        assert!(!out.status.success(), "unexpectedly accepted {bad:?}");
    }

    let manifest = proj.join(".nkp.toml");
    let dot_env = proj.join(".env");
    write_private(
        &manifest,
        &format!(
            "version = 1\nvault = \"{}\"\nenv_file = \".env\"\n\n[env]\nAPI = \"projects/myapp/stripe\"\n",
            fx.vault.to_str().unwrap()
        ),
    );
    write_private(&dot_env, "PLAIN=initial\n");

    // Untrusted initially in status
    let status_untrusted = fx
        .cmd()
        .current_dir(&proj)
        .args(["shell", "status", "--json"])
        .output()
        .unwrap();
    assert!(status_untrusted.status.success());
    let json_untrusted: serde_json::Value =
        serde_json::from_slice(&status_untrusted.stdout).unwrap();
    assert_eq!(json_untrusted["trust"], "untrusted");

    // Trust directory
    let trust_out = fx
        .cmd()
        .current_dir(&proj)
        .args(["trust"])
        .output()
        .unwrap();
    assert!(
        trust_out.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trust_out.stderr)
    );
    assert!(trust_out.stdout.is_empty());

    // Trust --list --json shows both .nkp.toml and .env
    let list_out = fx
        .cmd()
        .args(["trust", "--list", "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_text = String::from_utf8(list_out.stdout).unwrap();
    assert_eq!(list_text.lines().count(), 2, "{list_text}");
    assert!(list_text.contains(".nkp.toml"));
    assert!(list_text.contains(".env"));

    // Status is now trusted
    let status_trusted = fx
        .cmd()
        .current_dir(&proj)
        .args(["shell", "status", "--json"])
        .output()
        .unwrap();
    let json_trusted: serde_json::Value = serde_json::from_slice(&status_trusted.stdout).unwrap();
    assert_eq!(json_trusted["trust"], "trusted");

    // Tampering with .env invalidates trust immediately
    write_private(&dot_env, "PLAIN=tampered\n");
    let status_mod = fx
        .cmd()
        .current_dir(&proj)
        .args(["shell", "status", "--json"])
        .output()
        .unwrap();
    let json_mod: serde_json::Value = serde_json::from_slice(&status_mod.stdout).unwrap();
    assert_eq!(json_mod["trust"], "modified");

    // Untrust directory removes its entries; prune cleans deleted files
    let untrust_out = fx
        .cmd()
        .current_dir(&proj)
        .args(["untrust"])
        .output()
        .unwrap();
    assert!(untrust_out.status.success());
    let list_empty = fx.cmd().args(["trust", "--list"]).output().unwrap();
    assert!(list_empty.status.success());
    assert!(list_empty.stdout.is_empty());

    // Trust explicit .env, delete it, then prune
    let standalone_env = fx.dir.path().join("standalone.env");
    write_private(&standalone_env, "ONLY_PLAIN=ok\n");
    assert!(
        fx.cmd()
            .args(["trust", standalone_env.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::remove_file(&standalone_env).unwrap();
    assert!(
        fx.cmd()
            .args(["trust", "--prune"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        fx.cmd()
            .args(["trust", "--list"])
            .output()
            .unwrap()
            .stdout
            .is_empty()
    );

    // untrust --all
    write_private(&standalone_env, "ONLY_PLAIN=ok\n");
    assert!(
        fx.cmd()
            .args(["trust", standalone_env.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        fx.cmd()
            .args(["untrust", "--all"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        fx.cmd()
            .args(["trust", "--list"])
            .output()
            .unwrap()
            .stdout
            .is_empty()
    );
}

#[test]
fn shell_init_completions_status_and_help_cover_all_shells() {
    let fx = TestFixture::new();

    for shell in ["bash", "zsh", "fish", "pwsh", "powershell", "nushell"] {
        let init_out = fx.cmd().args(["shell", "init", shell]).output().unwrap();
        assert!(
            init_out.status.success(),
            "shell init {shell} failed: {}",
            String::from_utf8_lossy(&init_out.stderr)
        );
        let script = String::from_utf8(init_out.stdout).unwrap();
        assert!(!script.is_empty());
        assert!(!script.contains("\r\n"), "{shell} init emitted CRLF");

        let comp_new = fx
            .cmd()
            .args(["shell", "completions", shell])
            .output()
            .unwrap();
        let comp_legacy = fx.cmd().args(["completion", shell]).output().unwrap();
        assert!(comp_new.status.success());
        assert_eq!(comp_new.stdout, comp_legacy.stdout);
    }

    // sh is refused for shell init (exit 2) while completions sh works
    let sh_init = fx.cmd().args(["shell", "init", "sh"]).output().unwrap();
    assert_eq!(sh_init.status.code(), Some(2));
    assert!(
        fx.cmd()
            .args(["shell", "completions", "sh"])
            .output()
            .unwrap()
            .status
            .success()
    );

    // --no-completion + --no-env rejected
    let both_disabled = fx
        .cmd()
        .args(["shell", "init", "bash", "--no-completion", "--no-env"])
        .output()
        .unwrap();
    assert_eq!(both_disabled.status.code(), Some(2));

    // -V rejected on shell init and shell completions
    assert!(
        !fx.cmd()
            .args(["-V", fx.vault.to_str().unwrap(), "shell", "init", "bash"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !fx.cmd()
            .args([
                "-V",
                fx.vault.to_str().unwrap(),
                "shell",
                "completions",
                "bash",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Help works at every depth
    for help_args in [
        vec!["inject", "--help"],
        vec!["trust", "--help"],
        vec!["untrust", "--help"],
        vec!["shell", "--help"],
        vec!["shell", "init", "--help"],
        vec!["shell", "completions", "--help"],
        vec!["shell", "load", "--help"],
        vec!["shell", "unload", "--help"],
        vec!["shell", "status", "--help"],
    ] {
        let out = fx.cmd().args(&help_args).output().unwrap();
        assert!(out.status.success(), "help failed for {help_args:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("Usage:"));
    }

    // __hook suppresses --help interception
    let hook_help = fx
        .cmd()
        .args(["__hook", "bash", "--help"])
        .output()
        .unwrap();
    assert!(!hook_help.status.success());
    assert!(hook_help.stdout.is_empty());
}

#[test]
fn real_bash_end_to_end_direnv_lifecycle() {
    let fx = TestFixture::new();
    let proj = fx.dir.path().join("project");
    let outside = fx.dir.path().join("outside");
    fs::create_dir(&proj).unwrap();
    fs::create_dir(&outside).unwrap();

    write_private(
        &proj.join(".nkp.toml"),
        &format!(
            "version = 1\nvault = \"{}\"\nenv_file = \".env\"\n\n[env]\nAPI_KEY = \"projects/myapp/stripe\"\n",
            fx.vault.to_str().unwrap()
        ),
    );
    write_private(
        &proj.join(".env"),
        "LITERAL_VAR=from_dotenv\nEXISTING=overwritten\n",
    );

    let trust_out = fx
        .cmd()
        .current_dir(&proj)
        .args(["trust"])
        .output()
        .unwrap();
    assert!(
        trust_out.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trust_out.stderr)
    );

    let bash_bin = if Path::new("/usr/bin/bash").exists() {
        "/usr/bin/bash"
    } else {
        "bash"
    };

    let script = format!(
        r#"
set -euo pipefail
export EXISTING=before
eval "$("$NKP_BIN" shell init bash)"

tick_prompt() {{
  if declare -p PROMPT_COMMAND 2>/dev/null | grep -q '^declare -a '; then
    local fn
    for fn in "${{PROMPT_COMMAND[@]}}"; do
      true
      "$fn"
    done
  else
    true
    eval "${{PROMPT_COMMAND:-}}"
  fi
}}

cd "$PROJ_DIR"
tick_prompt

[ "$API_KEY" = "{STRIPE_SECRET}" ]
[ "$LITERAL_VAR" = "from_dotenv" ]
[ "$EXISTING" = "overwritten" ]

# __NKP_ENV_STATE must NOT be exported to child processes
if env | grep -q '^__NKP_ENV_STATE='; then
  echo "LEAKED __NKP_ENV_STATE to child env" >&2
  exit 9
fi

# Verify non-disclosing shell status directly through the `nkp` shell wrapper
status_json="$(nkp shell status --json)"
printf '%s\n' "$status_json" | grep -q '"status":"active"'
printf '%s\n' "$status_json" | grep -q '"API_KEY"'
printf '%s\n' "$status_json" | grep -q '"LITERAL_VAR"'
printf '%s\n' "$status_json" | grep -q '"EXISTING"'
if printf '%s\n' "$status_json" | grep -q '{STRIPE_SECRET}'; then
  echo "SECRET leaked in shell status" >&2
  exit 9
fi

# Manual edit is preserved when leaving directory, while secret and prior are reverted
export LITERAL_VAR=manual_edit
cd "$OUTSIDE_DIR"
tick_prompt

[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]
[ "$LITERAL_VAR" = "manual_edit" ]

# Re-enter project dir -> activates again
unset LITERAL_VAR
cd "$PROJ_DIR"
tick_prompt
[ "$API_KEY" = "{STRIPE_SECRET}" ]
[ "$LITERAL_VAR" = "from_dotenv" ]
[ "$EXISTING" = "overwritten" ]

# Explicit unload stays unloaded across subsequent prompt ticks
nkp shell unload
[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "${{LITERAL_VAR:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]

tick_prompt
[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]

# Explicit reload activates again
nkp shell load
[ "$API_KEY" = "{STRIPE_SECRET}" ]
[ "$LITERAL_VAR" = "from_dotenv" ]
[ "$EXISTING" = "overwritten" ]

# Tampering with .env reverts active vars immediately on next prompt tick
printf 'LITERAL_VAR=tampered\nEXISTING=overwritten\n' > "$PROJ_DIR/.env"
chmod 600 "$PROJ_DIR/.env"
tick_prompt
[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]
"#,
    );

    let bash_out = Command::new(bash_bin)
        .isolate_application_environment()
        .args(["--norc", "--noprofile", "-c", &script])
        .env("HOME", fx.dir.path())
        .env("XDG_CONFIG_HOME", &fx.config_dir)
        .env("XDG_DATA_HOME", &fx.data_dir)
        .env("NKP_PASSWORD", MASTER_PASSWORD)
        .env("NKP_BIN", env!("CARGO_BIN_EXE_nkp"))
        .env("PROJ_DIR", &proj)
        .env("OUTSIDE_DIR", &outside)
        .current_dir(&outside)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        bash_out.status.success(),
        "real bash lifecycle failed (code {:?}):\nstdout:\n{}\nstderr:\n{}",
        bash_out.status.code(),
        String::from_utf8_lossy(&bash_out.stdout),
        String::from_utf8_lossy(&bash_out.stderr),
    );
}

#[test]
fn real_bash_reverts_secrets_when_trust_store_fails_or_is_corrupt() {
    let fx = TestFixture::new();
    let proj = fx.dir.path().join("project");
    let outside = fx.dir.path().join("outside");
    fs::create_dir(&proj).unwrap();
    fs::create_dir(&outside).unwrap();

    write_private(
        &proj.join(".nkp.toml"),
        &format!(
            "version = 1\nvault = \"{}\"\nenv_file = \".env\"\n\n[env]\nAPI_KEY = \"projects/myapp/stripe\"\n",
            fx.vault.to_str().unwrap()
        ),
    );
    write_private(
        &proj.join(".env"),
        "LITERAL_VAR=from_dotenv\nEXISTING=overwritten\n",
    );

    let trust_out = fx
        .cmd()
        .current_dir(&proj)
        .args(["trust"])
        .output()
        .unwrap();
    assert!(trust_out.status.success());

    let trust_json = fx.data_dir.join("nkeepass").join("trust.json");
    assert!(trust_json.is_file());

    let bash_bin = if Path::new("/usr/bin/bash").exists() {
        "/usr/bin/bash"
    } else {
        "bash"
    };

    let script = format!(
        r#"
set -euo pipefail
export EXISTING=before
eval "$("$NKP_BIN" shell init bash)"

tick_prompt() {{
  if declare -p PROMPT_COMMAND 2>/dev/null | grep -q '^declare -a '; then
    local fn
    for fn in "${{PROMPT_COMMAND[@]}}"; do
      true
      "$fn"
    done
  else
    true
    eval "${{PROMPT_COMMAND:-}}"
  fi
}}

cd "$PROJ_DIR"
tick_prompt
[ "$API_KEY" = "{STRIPE_SECRET}" ]
[ "$LITERAL_VAR" = "from_dotenv" ]
[ "$EXISTING" = "overwritten" ]

# 1. Unsafe permissions on trust.json (chmod 644) while leaving dir must revert secrets!
chmod 644 "$TRUST_JSON"
cd "$OUTSIDE_DIR"
tick_prompt
[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "${{LITERAL_VAR:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]

# Restore permissions, re-enter and re-activate
chmod 600 "$TRUST_JSON"
cd "$PROJ_DIR"
tick_prompt
[ "$API_KEY" = "{STRIPE_SECRET}" ]
[ "$EXISTING" = "overwritten" ]

# 2. Corrupt trust.json on disk must also revert active secrets!
printf 'not-valid-json\n' > "$TRUST_JSON"
chmod 600 "$TRUST_JSON"
cd "$OUTSIDE_DIR"
tick_prompt
[ "${{API_KEY:-__UNSET__}}" = "__UNSET__" ]
[ "${{LITERAL_VAR:-__UNSET__}}" = "__UNSET__" ]
[ "$EXISTING" = "before" ]
"#,
    );

    let bash_out = Command::new(bash_bin)
        .isolate_application_environment()
        .args(["--norc", "--noprofile", "-c", &script])
        .env("HOME", fx.dir.path())
        .env("XDG_CONFIG_HOME", &fx.config_dir)
        .env("XDG_DATA_HOME", &fx.data_dir)
        .env("NKP_PASSWORD", MASTER_PASSWORD)
        .env("NKP_BIN", env!("CARGO_BIN_EXE_nkp"))
        .env("PROJ_DIR", &proj)
        .env("OUTSIDE_DIR", &outside)
        .env("TRUST_JSON", &trust_json)
        .current_dir(&outside)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        bash_out.status.success(),
        "trust-store fail-closed revert test failed (code {:?}):\nstdout:\n{}\nstderr:\n{}",
        bash_out.status.code(),
        String::from_utf8_lossy(&bash_out.stdout),
        String::from_utf8_lossy(&bash_out.stderr),
    );
}
