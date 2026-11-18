#![cfg(unix)]

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use neotales_keepass::{
    Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxUuid, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use tempfile::TempDir;

const PASSWORD: &str = "hardening-master-disposable-4c7e";
const MAX_PASSWORD_STDIN_BYTES: usize = 64 * 1024;

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new(database: &KeePassDatabase, password: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("hardening.kdbx");
        KdbxFile::save(
            database,
            fs::File::create(&vault).unwrap(),
            &mut KdbxCredentials::password(password).unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        Self { directory, vault }
    }

    fn path(&self) -> &Path {
        &self.vault
    }
}

fn run(fixture: &Fixture, args: &[&str]) -> Output {
    // `PW` is what the tests below name explicitly, and `run` already sets
    // `NKEEPASS_TEST_PASSWORD` for the rest; both are the same value, so neither
    // test has to know which spelling the helper prefers.

    Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args(["--vault", fixture.vault.to_str().unwrap()])
        .args(args)
        .env("XDG_CONFIG_HOME", fixture.directory.path().join("config"))
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .env("PW", PASSWORD)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_with_input(fixture: &Fixture, args: &[&str], input: &[u8]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
    command
        .args(["--vault", fixture.vault.to_str().unwrap()])
        .args(args)
        .env("XDG_CONFIG_HOME", fixture.directory.path().join("config"))
        .env_remove("NKEEPASS_TEST_PASSWORD")
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_static_failure(output: &Output, diagnostic: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, format!("nkp: {diagnostic}\n").as_bytes());
}

fn database_with_entries(entries: impl IntoIterator<Item = Entry>) -> KeePassDatabase {
    let mut database = KeePassDatabase::default();
    database.root.entries.extend(entries);
    database
}

fn password_auth() -> [&'static str; 2] {
    ["--password-env", "NKEEPASS_TEST_PASSWORD"]
}

#[test]
fn duplicate_entry_uuid_cannot_redirect_a_mutation() {
    let mut first = Entry::new("First");
    let mut target = Entry::new("Target");
    target.id = KdbxUuid::from_bytes([2; 16]);
    first.id = target.id;
    let fixture = Fixture::new(&database_with_entries([first, target]), PASSWORD);
    let before = fs::read(fixture.path()).unwrap();
    let value_file = fixture.directory.path().join("value.txt");
    fs::write(&value_file, "replacement-value").unwrap();
    let auth = password_auth();
    let output = run(
        &fixture,
        &[
            "set",
            "--key",
            "Target",
            "--file",
            value_file.to_str().unwrap(),
            auth[0],
            auth[1],
        ],
    );
    assert_static_failure(&output, "vault contains duplicate object UUIDs");
    assert_eq!(fs::read(fixture.path()).unwrap(), before);

    let output = run(
        &fixture,
        &["rm", "--key", "Target", "--yes", auth[0], auth[1]],
    );
    assert_static_failure(&output, "vault contains duplicate object UUIDs");
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn duplicate_group_uuid_cannot_redirect_ensure() {
    let mut first = Group::new("First");
    let mut target = Group::new("Target");
    target.id = KdbxUuid::from_bytes([3; 16]);
    first.id = target.id;
    target.add_entry(Entry::new("Existing"));
    let mut database = KeePassDatabase::default();
    database.root.groups.extend([first, target]);
    let fixture = Fixture::new(&database, PASSWORD);
    let before = fs::read(fixture.path()).unwrap();
    let auth = password_auth();
    let output = run(
        &fixture,
        &[
            "ensure",
            "--key",
            "Root/Target/New",
            "--size",
            "12",
            auth[0],
            auth[1],
        ],
    );
    assert_static_failure(&output, "vault contains duplicate object UUIDs");
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn public_routes_reject_internal_actions_before_vault_access() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.kdbx");
    for args in [
        vec![
            "secrets",
            "field-get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--password-env",
            "MISSING_PASSWORD",
        ],
        vec![
            "secrets",
            "field-set",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--file",
            "/does/not/matter",
            "--password-env",
            "MISSING_PASSWORD",
        ],
        vec![
            "secrets",
            "attachment-ls",
            "--key",
            "LOGIN",
            "--password-env",
            "MISSING_PASSWORD",
        ],
        vec![
            "secrets",
            "attachment-rm",
            "--key",
            "LOGIN",
            "--field",
            "file.bin",
            "--yes",
            "--password-env",
            "MISSING_PASSWORD",
        ],
        vec!["automation", "field-get", "--key", "LOGIN"],
        vec!["automation", "attachment-ls", "--key", "LOGIN"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(["--vault", missing.to_str().unwrap()])
            .args(&args)
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env_remove("MISSING_PASSWORD")
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_static_failure(&output, "unknown operation; see --help");
    }
}

#[test]
fn generic_dry_run_is_rejected_by_non_dry_run_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.kdbx");
    let cases = [
        vec!["secrets", "ls", "--dry-run"],
        vec!["secrets", "search", "query", "--dry-run"],
        vec!["secrets", "show", "--key", "LOGIN", "--dry-run"],
        vec!["secrets", "get", "--key", "LOGIN", "--dry-run"],
        vec!["secrets", "getx", "--key", "LOGIN", "--dry-run"],
        vec!["secrets", "set", "--key", "LOGIN", "--dry-run"],
        vec!["secrets", "rm", "--key", "LOGIN", "--yes", "--dry-run"],
        vec!["secrets", "otp", "--key", "LOGIN", "--dry-run"],
        vec![
            "field",
            "set",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--dry-run",
        ],
        vec![
            "field",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--yes",
            "--dry-run",
        ],
        vec![
            "attachment",
            "add",
            "--key",
            "LOGIN",
            "--field",
            "file",
            "--dry-run",
        ],
        vec![
            "attachment",
            "get",
            "--key",
            "LOGIN",
            "--field",
            "file",
            "--output",
            "/tmp/out",
            "--dry-run",
        ],
        vec![
            "attachment",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "file",
            "--yes",
            "--dry-run",
        ],
    ];
    for args in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(["--vault", missing.to_str().unwrap()])
            .args(&args)
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_static_failure(&output, "invalid operation option");
    }
}

#[test]
fn duplicate_global_vault_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first.kdbx");
    let second = tmp.path().join("second.kdbx");
    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            first.to_str().unwrap(),
            "--vault",
            second.to_str().unwrap(),
            "context",
            "show",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_static_failure(&output, "invalid or duplicate option");
}

#[test]
fn secrets_list_and_search_accept_a_positional_terminator() {
    let mut entry = Entry::new("LOGIN");
    entry.password = ProtectedValue::from_text("terminator-secret");
    let fixture = Fixture::new(&database_with_entries([entry]), PASSWORD);
    let auth = password_auth();
    for args in [
        vec!["secrets", "ls", auth[0], auth[1], "--", "*LOGIN"],
        vec!["secrets", "search", auth[0], auth[1], "--", "LOGIN"],
    ] {
        let output = run(&fixture, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("LOGIN"));
    }
}

/// The glob syntax `secrets ls` grew, exercised through the binary.
///
/// The unit tests cover the matcher; this covers the wiring -- that the
/// pattern is compiled once before the walk, that a path is one string with
/// `/` in it, and that the length limit is reported rather than applied
/// silently.
#[test]
fn secrets_ls_matches_the_glob_syntax_it_documents() {
    let mut prod = Group::new("prod");
    prod.add_entry(Entry::new("admin"));
    prod.add_entry(Entry::new("report"));
    let mut staging = Group::new("staging");
    staging.add_entry(Entry::new("admin"));
    let mut dev = Group::new("dev");
    dev.add_entry(Entry::new("admin"));
    let mut deep = Group::new("one");
    let mut deeper = Group::new("two");
    deeper.add_entry(Entry::new("admin"));
    deep.groups.push(deeper);
    prod.groups.push(deep);
    let mut database = KeePassDatabase::default();
    database.root.groups.push(prod);
    database.root.groups.push(staging);
    database.root.groups.push(dev);
    let fixture = Fixture::new(&database, PASSWORD);
    let auth = password_auth();

    for (pattern, expected) in [
        ("Root/prod/admin", "Root/prod/admin"),
        (
            "Root/{prod,staging}/*",
            "Root/prod/admin Root/prod/report Root/prod/one/two/admin Root/staging/admin",
        ),
        (
            "Root/**/admin",
            "Root/prod/admin Root/staging/admin Root/dev/admin Root/prod/one/two/admin",
        ),
        (
            "Root/*/[a]dmin",
            "Root/dev/admin Root/prod/admin Root/prod/one/two/admin Root/staging/admin",
        ),
        (
            "Root/[ps]*",
            "Root/prod/admin Root/prod/report Root/prod/one/two/admin Root/staging/admin",
        ),
        // The old syntax, unchanged: `*` still crosses a `/`.
        (
            "Root/*admin",
            "Root/dev/admin Root/prod/admin Root/prod/one/two/admin Root/staging/admin",
        ),
        (
            "Root/*",
            "Root/prod/admin Root/prod/report Root/prod/one/two/admin Root/staging/admin \
             Root/dev/admin",
        ),
        (
            "Root/**",
            "Root/prod/admin Root/prod/report Root/prod/one/two/admin Root/staging/admin \
             Root/dev/admin",
        ),
    ] {
        let output = run(
            &fixture,
            &["secrets", "ls", auth[0], auth[1], "--", pattern],
        );
        assert!(
            output.status.success(),
            "{pattern}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing = String::from_utf8_lossy(&output.stdout);
        let mut paths: Vec<&str> = listing
            .lines()
            .map(|line| {
                let start = line.find("\"path\":\"").expect("a path field") + 8;
                let end = start + line[start..].find('"').expect("a closing quote");
                &line[start..end]
            })
            .collect();
        paths.sort_unstable();
        let mut wanted: Vec<&str> = expected.split_whitespace().collect();
        wanted.sort_unstable();
        assert_eq!(paths, wanted, "pattern {pattern}");
    }
}

#[test]
fn an_oversized_glob_names_the_limit_and_the_length() {
    let fixture = Fixture::new(&database_with_entries([Entry::new("LOGIN")]), PASSWORD);
    let auth = password_auth();
    let output = run(
        &fixture,
        &["secrets", "ls", auth[0], auth[1], "--", &"a".repeat(1025)],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "nkp: glob pattern is 1025 bytes; the limit is 1024\n"
    );
}

#[cfg(unix)]
#[test]
fn exec_child_signal_returns_a_normal_result_and_preserves_status() {
    let fixture = Fixture::new(&database_with_entries([Entry::new("LOGIN")]), PASSWORD);
    let auth = password_auth();
    let output = run(
        &fixture,
        &[
            "x",
            "--key",
            "LOGIN",
            "--env",
            "LOGIN",
            auth[0],
            auth[1],
            "--",
            "sh",
            "-c",
            "kill -TERM $$",
        ],
    );
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(143));
    assert_eq!(output.stderr, b"nkp: child command failed\n");
}

#[test]
fn secrets_env_rejects_unrelated_options_before_credentials_or_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let missing_vault = tmp.path().join("does-not-exist.kdbx");
    let auth = ["--password-env", "MISSING_PASSWORD"];
    let unrelated = [
        vec!["--file", "unused-value"],
        vec!["--output", "unused-output"],
        vec!["--yes"],
        vec!["--dry-run"],
        vec!["--replace"],
        vec!["--size", "12"],
        vec!["--strategy", "newest"],
        vec!["--stdin"],
    ];
    for extra in unrelated {
        let mut args = vec![
            "--vault",
            missing_vault.to_str().unwrap(),
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "VALUE",
        ];
        args.extend(extra);
        args.extend(auth);
        let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(&args)
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env_remove("MISSING_PASSWORD")
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_static_failure(&output, "invalid operation option");
    }
}

#[test]
fn hotp_is_rejected_without_saving_a_counter() {
    let mut entry = Entry::new("LOGIN");
    entry.fields.push(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text(
            "otpauth://hotp/Fixture?secret=JBSWY3DPEHPK3PXP&counter=0",
        ),
        protected: true,
        protect_in_memory: true,
    });
    let fixture = Fixture::new(&database_with_entries([entry]), PASSWORD);
    let before = fs::read(fixture.path()).unwrap();
    let auth = password_auth();
    let output = run(&fixture, &["otp", "--key", "LOGIN", auth[0], auth[1]]);
    assert_static_failure(&output, "HOTP requires atomic counter persistence");
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn otp_service_errors_keep_the_existing_cli_diagnostics() {
    let auth = password_auth();
    let mut entry = Entry::new("LOGIN");
    entry.fields.push(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text("not-an-otp-uri"),
        protected: true,
        protect_in_memory: true,
    });
    let fixture = Fixture::new(&database_with_entries([entry]), PASSWORD);
    let output = run(&fixture, &["otp", "--key", "LOGIN", auth[0], auth[1]]);
    assert_static_failure(&output, "invalid OTP field");
}

#[test]
fn otp_selector_diagnostics_preserve_path_categories_and_aliases() {
    let mut login = Entry::new("LOGIN");
    login.fields.push(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text(
            "otpauth://totp/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
        ),
        protected: true,
        protect_in_memory: true,
    });
    let mut two = Group::new("two");
    two.add_entry(login);
    let mut one = Group::new("one");
    one.groups.push(two);
    let mut nested_ambiguity = Group::new("ambiguous");
    let mut first_two = Group::new("two");
    first_two.add_entry(Entry::new("LOGIN"));
    let mut second_two = Group::new("TWO");
    second_two.add_entry(Entry::new("LOGIN"));
    nested_ambiguity.groups.extend([first_two, second_two]);
    one.groups.push(nested_ambiguity);
    let mut prod = Group::new("prod");
    prod.groups.push(one);
    let mut database = KeePassDatabase::default();
    database
        .root
        .groups
        .extend([prod, Group::new("dup"), Group::new("DUP")]);
    database
        .root
        .entries
        .extend([Entry::new("mail"), Entry::new("Twin"), Entry::new("twin")]);
    let fixture = Fixture::new(&database, PASSWORD);
    let auth = password_auth();

    for (selector, diagnostic) in [
        ("/bad", "invalid entry path"),
        ("Root", "that path names the root group, not an entry"),
        ("DUP/key", "entry not found"),
        (
            "Root/prod/one/ambiguous/TWO/LOGIN",
            r#"this vault holds more than one group matching "TWO" ignoring case, so the path is ambiguous"#,
        ),
        (
            "Twin",
            r#"this vault holds more than one entry matching "Twin" ignoring case, so the path is ambiguous"#,
        ),
        (
            "Root/prod/no-such/deeper/LOGIN",
            r#"this vault has no group named "no-such" at "prod/no-such"; Use `group add --key PATH` to create groups, or `secrets ensure --key PATH` to create an entry and its parent groups."#,
        ),
        ("Root/prod/one/two/missing", "entry not found"),
    ] {
        let output = run(&fixture, &["otp", "--key", selector, auth[0], auth[1]]);
        assert_static_failure(&output, diagnostic);
    }

    let configured = run(
        &fixture,
        &[
            "alias",
            "set",
            "otp-mail",
            "Root/prod/one/two/LOGIN",
            "--kind",
            "entry",
        ],
    );
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let aliased = run(&fixture, &["otp", "--key", "otp-mail", auth[0], auth[1]]);
    assert!(
        aliased.status.success(),
        "{}",
        String::from_utf8_lossy(&aliased.stderr)
    );
    assert_eq!(aliased.stdout.len(), 6);

    let collision = run(
        &fixture,
        &[
            "alias",
            "set",
            "mail",
            "Root/prod/one/two/LOGIN",
            "--kind",
            "entry",
        ],
    );
    assert!(
        collision.status.success(),
        "{}",
        String::from_utf8_lossy(&collision.stderr)
    );
    let collided = run(&fixture, &["otp", "--key", "mail", auth[0], auth[1]]);
    assert_static_failure(&collided, "ambiguous entry selector");
}

#[test]
fn env_and_exec_keep_selector_error_categories_after_service_migration() {
    let mut prod = Group::new("prod");
    prod.groups.push(Group::new("one"));
    let mut database = KeePassDatabase::default();
    database.root.groups.push(prod);
    let fixture = Fixture::new(&database, PASSWORD);
    let auth = password_auth();
    let expected = "this vault has no group named \"missing\" at \"prod/missing\"; Use `group add --key PATH` to create groups, or `secrets ensure --key PATH` to create an entry and its parent groups.";

    let env = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "Root/prod/missing/LOGIN",
            "--field",
            "Password",
            "--name",
            "PW",
            auth[0],
            auth[1],
        ],
    );
    assert_static_failure(&env, expected);

    let exec = run(
        &fixture,
        &[
            "exec",
            "--key",
            "Root/prod/missing/LOGIN",
            "--env",
            "BINDING_VALUE",
            auth[0],
            auth[1],
            "--",
            "sh",
            "-c",
            "true",
        ],
    );
    assert_static_failure(&exec, expected);
}

#[test]
fn password_stdin_has_a_bounded_line_contract() {
    let password = "x".repeat(MAX_PASSWORD_STDIN_BYTES);
    let fixture = Fixture::new(&KeePassDatabase::default(), &password);
    let authless = ["secrets", "ls", "--password-stdin"];

    let boundary = vec![b'x'; MAX_PASSWORD_STDIN_BYTES];
    let output = run_with_input(&fixture, &authless, &boundary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let mut boundary_with_newline = boundary.clone();
    boundary_with_newline.push(b'\n');
    let output = run_with_input(&fixture, &authless, &boundary_with_newline);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let mut boundary_with_crlf = boundary;
    boundary_with_crlf.extend_from_slice(b"\r\n");
    let output = run_with_input(&fixture, &authless, &boundary_with_crlf);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let empty = run_with_input(&fixture, &authless, b"");
    assert_static_failure(&empty, "password must not be empty");
    let newline_only = run_with_input(&fixture, &authless, b"\n");
    assert_static_failure(&newline_only, "password must not be empty");

    let oversized = vec![b'x'; MAX_PASSWORD_STDIN_BYTES + 1];
    let output = run_with_input(&fixture, &authless, &oversized);
    assert_static_failure(&output, "password exceeds size limit");
}

#[cfg(unix)]
#[test]
fn config_directory_permissions_are_checked_on_read() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let config_home = tmp.path().join("config-home");
    let config_dir = config_home.join("nkeepass");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("config.json"), b"{}").unwrap();
    fs::set_permissions(
        config_dir.join("config.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let command = || {
        Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(["alias", "list"])
            .env("XDG_CONFIG_HOME", &config_home)
            .env_remove("NKEEPASS_VAULT")
            .env_remove("NKEEPASS_VAULT_PATH")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let insecure = command();
    assert!(!insecure.status.success());
    assert_eq!(
        insecure.stderr,
        b"nkp: unsafe configuration directory permissions\n".as_slice()
    );
    assert!(insecure.stdout.is_empty());

    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let secure = command();
    assert!(secure.status.success());
    assert!(secure.stderr.is_empty());
}

/// `exec` must not hand the child the caller's whole environment.
///
/// The default for `std::process::Command` is to inherit every parent variable,
/// which passes cloud tokens, CI credentials and unrelated `*_TOKEN`s to a
/// program whose provenance the user may not control. Removing only the one
/// password variable leaves that wide open, so the environment is an allowlist.
///
/// This is the same finding as ticket #140 in the sibling .NET implementation,
/// rated P0 there. The Rust port reimplemented the behaviour from scratch and
/// did not carry the fix across, which is the point worth remembering: a port
/// has to re-earn every security property rather than inheriting it.
#[test]
fn exec_does_not_pass_the_parent_environment_to_the_child() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("exec-env");
    entry.password = ProtectedValue::from_text("child-password-SENTINEL");
    database.root.add_entry(entry);

    let fixture = Fixture::new(&database, PASSWORD);
    let vault = fixture.vault.to_str().unwrap().to_owned();

    // A sentinel in the parent that the allowlist must not carry. It is named
    // so that nothing else in the process legitimately sets it.
    let sentinel = "NKEEPASS_EXEC_LEAK_SENTINEL";
    let value = "must-not-reach-the-child";

    // The sentinel name is interpolated into the shell script so the child
    // reports the variable by its real name. `format!` with an inline capture
    // rather than a positional argument, which is what clippy asks for.
    let script = format!(
        "printf 'LEAK=[%s]\\n' \"${sentinel}\"; printf 'PATH=[%s]\\n' \"${{PATH:+set}}\"; \
         printf 'INJECTED=[%s]\\n' \"$INJECTED\""
    );

    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            &vault,
            "exec",
            "--key",
            "exec-env",
            "--env",
            "INJECTED",
            "--password-env",
            "HARDENING_PASSWORD",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("XDG_CONFIG_HOME", fixture.directory.path().join("config"))
        .env("HARDENING_PASSWORD", PASSWORD)
        .env(sentinel, value)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "exec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    // The whole point: the parent's secret never arrives.
    assert!(
        !stdout.contains(value),
        "exec passed a parent environment variable to the child: {stdout}"
    );
    assert!(
        stdout.contains("LEAK=[]"),
        "the sentinel should be absent, not merely renamed: {stdout}"
    );

    // And the allowlist did not break the child in the other direction: the
    // selected value arrives and PATH is present, or every exec would fail and
    // the fix would be indistinguishable from "exec is broken".
    assert!(
        stdout.contains("PATH=[set]"),
        "PATH must be passed or no command can be resolved: {stdout}"
    );
    assert!(
        stdout.contains("INJECTED=[child-password-SENTINEL]"),
        "the selected value must reach the child: {stdout}"
    );

    // The vault password variable itself must not survive, which the existing
    // code already did and which this must not regress.
    assert!(
        !stdout.contains("HARDENING_PASSWORD="),
        "the credential variable leaked into the child environment: {stdout}"
    );
}

/// A directory that genuinely grants `BUILTIN\Users` read access, and the file
/// created inside it therefore genuinely inherits it.
///
/// Split out because the test that uses it is about the *consequence* of that
/// inheritance, and a 105-line test that also builds the premise is a test where
/// the premise is easy to break without noticing.
///
/// The `(OI)(CI)` flags are the whole subtlety. `icacls /grant BUILTIN\Users:(RX)`
/// adds an entry to the directory and nothing created inside it inherits it, so the
/// first version of this grant made the file stay private -- and the test then
/// passed with the protection disabled, because the directory listing showed the
/// grant while the file it was written to did not have it. A premise satisfied by
/// the wrong object is worse than no premise, and this is the second time in this
/// file that an assertion looked right while checking nothing.
#[cfg(windows)]
fn make_a_deliberately_shared_directory(parent: &Path) -> PathBuf {
    let shared = parent.join("shared");
    fs::create_dir(&shared).unwrap();
    let granted = Command::new("icacls")
        .arg(&shared)
        .arg("/grant")
        .arg("BUILTIN\\Users:(OI)(CI)(RX)")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("icacls ships with Windows");
    assert!(
        granted.success(),
        "could not make the directory permissive, so the test would not exercise \
         the inheritance it is about"
    );
    let listing = Command::new("icacls")
        .arg(&shared)
        .output()
        .expect("icacls");
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(
        listing.contains("BUILTIN\\Users"),
        "the shared directory does not grant BUILTIN\\Users, so the premise is not \
         established:\n{listing}"
    );
    shared
}

/// On Unix the temporary directory is already private to its owner, so the
/// inheritance the test is about does not arise and no setup is needed. The
/// Unix half of the assertion checks the mode directly.
#[cfg(not(windows))]
fn make_a_deliberately_shared_directory(parent: &Path) -> PathBuf {
    parent.to_path_buf()
}

/// A plaintext output must be readable by its owner and by nobody else.
///
/// On Unix this is a `mode & 0o777 == 0o600` assertion, and it has always been
/// there. On Windows it is the check that was missing, and the gap was not
/// cosmetic. A file this CLI wrote holding a decrypted entry password inherited its
/// parent directory's ACL, which on this fleet's runner was:
///
///     NT AUTHORITY\SYSTEM       FullControl
///     BUILTIN\Administrators    FullControl
///     BUILTIN\Users             ReadAndExecute
///
/// so every account on the machine could read it. The staging file is created in the
/// *target's* directory, so `secrets get --output` into a shared folder puts a
/// decrypted credential somewhere world-readable.
///
/// The Windows half reads the ACL back and requires that the only account named is
/// the one running the test. It asserts on the *absence* of `BUILTIN\Users`,
/// `Everyone`, `BUILTIN\Guest` and the authenticated-users group specifically,
/// because those are the entries that make a file public and none of them is the
/// caller's own name -- so a grant that widened to the world is caught even if
/// something else appears alongside it.
#[test]
fn a_plaintext_output_denies_every_other_account() {
    let mut database = KeePassDatabase::default();
    database.root.add_entry({
        let mut entry = neotales_keepass::Entry::new("acl-probe-entry");
        entry.password = neotales_keepass::ProtectedValue::from_text("a-decrypted-value-4f2b");
        entry
    });
    let fixture = Fixture::new(&database, PASSWORD);

    // The output directory is made **deliberately permissive** first, and this is
    // the part that makes the test worth anything.
    //
    // The obvious version of this test -- write into the fixture's own temporary
    // directory and check the mode -- passes whether or not the protection works,
    // because a directory under `%TEMP%` already grants only its owner. It was
    // written that way first, and it passed with `set_owner_only` stubbed out to do
    // nothing at all. A gate whose premise is supplied by the environment rather
    // than by the test is a gate that cannot fail.
    //
    // So the directory is given an explicit grant to `BUILTIN\Users` before the
    // file is written. Now the inheritance is genuinely permissive, the exposure is
    // real, and whether the file comes out owner-only is entirely down to this CLI.
    let shared = make_a_deliberately_shared_directory(fixture.directory.path());

    let out = shared.join("plaintext.out");
    let out_text = out.to_str().unwrap();
    // `secrets export --output`, because that is the command that has an
    // `--output` option, and it writes the larger of the two secrets: the whole
    // decrypted vault rather than one value. A snapshot in a shared directory is
    // the worse accident of the two, so it is the one worth asserting on.
    let result = run(
        &fixture,
        &[
            "secrets",
            "export",
            "--output",
            out_text,
            "--password-env",
            "PW",
        ],
    );
    assert!(
        result.status.success(),
        "writing a plaintext output failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(out.exists(), "no output file was written");
    // The secret really is in there, so the assertions below are about permissions
    // rather than about an empty file. An empty or absent file satisfies every
    // mode and ACL check and proves nothing at all.
    let written = fs::read_to_string(&out).unwrap();
    assert!(
        written.contains("acl-probe-entry"),
        "the snapshot does not contain the entry, so there is no secret to protect"
    );
    // The password is base64 in the document; decoding it is what proves the file
    // holds the plaintext rather than a reference to it.
    assert!(
        written.contains("YS1kZWNyeXB0ZWQtdmFsdWUtNGYyYg=="),
        "the snapshot does not carry the entry's password"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a plaintext output is not owner-only: mode {:o}",
            mode & 0o777
        );
    }

    #[cfg(windows)]
    {
        let listed = Command::new("icacls")
            .arg(&out)
            .output()
            .expect("icacls ships with Windows");
        assert!(
            listed.status.success(),
            "icacls could not read the ACL: {}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let acl = String::from_utf8_lossy(&listed.stdout).into_owned();
        for forbidden in [
            "BUILTIN\\Users",
            "Everyone",
            "BUILTIN\\Guest",
            "NT AUTHORITY\\Authenticated",
        ] {
            assert!(
                !acl.contains(forbidden),
                "the output's ACL grants access to {forbidden}, so a decrypted \
                 secret is readable by accounts other than its owner:\n{acl}"
            );
        }
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let identity = Command::new(Path::new(&system_root).join("System32").join("whoami.exe"))
            .env_clear()
            .env("SystemRoot", &system_root)
            .output()
            .expect("whoami ships with Windows");
        assert!(
            identity.status.success(),
            "whoami failed: status={:?}, stderr={}",
            identity.status,
            String::from_utf8_lossy(&identity.stderr)
        );
        let owner = String::from_utf8_lossy(&identity.stdout).trim().to_owned();
        assert!(
            acl.to_lowercase().contains(&owner.to_lowercase()),
            "the output's ACL does not name its own owner {owner:?}, so the \
             owner-only grant was never applied:\n{acl}"
        );
    }
}

#[cfg(windows)]
#[test]
fn config_write_uses_the_authenticated_account_when_username_is_forged() {
    let fixture = Fixture::new(&KeePassDatabase::default(), PASSWORD);
    let config_home = fixture.directory.path().join("spoofed-config-home");
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args(["config", "set", "current", fixture.vault.to_str().unwrap()])
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("USERNAME", "forged-fixture-account")
        .env("XDG_CONFIG_HOME", &config_home)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "config write failed: status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let config = config_home.join("nkeepass").join("config.json");
    assert!(config.is_file(), "the configuration file was not installed");
    let icacls = Path::new(&system_root).join("System32").join("icacls.exe");
    let listed = Command::new(icacls)
        .arg(&config)
        .output()
        .expect("icacls ships with Windows");
    assert!(
        listed.status.success(),
        "icacls failed: status={:?}, stderr={}",
        listed.status,
        String::from_utf8_lossy(&listed.stderr)
    );
    let acl = String::from_utf8_lossy(&listed.stdout).to_lowercase();
    let identity = Command::new(Path::new(&system_root).join("System32").join("whoami.exe"))
        .env_clear()
        .env("SystemRoot", &system_root)
        .output()
        .expect("whoami ships with Windows");
    assert!(
        identity.status.success(),
        "whoami failed: status={:?}, stderr={}",
        identity.status,
        String::from_utf8_lossy(&identity.stderr)
    );
    let account = String::from_utf8_lossy(&identity.stdout)
        .trim()
        .to_lowercase();
    assert!(
        acl.contains(&account),
        "config ACL omitted the authenticated account: {acl}"
    );
    assert!(
        !acl.contains("forged-fixture-account"),
        "config ACL trusted the caller-controlled USERNAME variable"
    );
}
