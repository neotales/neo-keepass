// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

//! Live KeePassXC-to-`nkp` interoperability integration tests.

#[path = "support/application_environment.rs"]
mod application_environment;

use application_environment::IsolatedApplicationEnvironment;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MASTER_PASSWORD: &str = "keepassxc-interop-master-disposable-9f3a";
const ENTRY_PASSWORD: &str = "keepassxc-interop-entry-disposable-4c81";
const UPDATED_PASSWORD: &str = "keepassxc-interop-updated-disposable-7e2d";
const ENTRY_USER: &str = "interop-service-user";
const ENTRY_URL: &str = "https://interop.example.test/login";
const ENTRY_NOTES: &str = "interop-notes-disposable-6b14";
const CUSTOM_FIELD_NAME: &str = "Environment";
const CUSTOM_FIELD_VALUE: &str = "staging-interop";
const GROUP_NAME: &str = "Work";
const ENTRY_TITLE: &str = "ServiceLogin";
const ENTRY_PATH: &str = "Work/ServiceLogin";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;

#[allow(
    clippy::panic,
    clippy::print_stdout,
    reason = "missing external tool must fail loudly in the interop lane and report tool version"
)]
fn require_keepassxc_cli() {
    // No skip path. If this lane was invoked then it is supposed to prove something,
    // and a missing tool is a lane that could not run, which the support matrix
    // records as an exclusion rather than as a pass. Returning quietly would let a
    // green run stand for a claim that was never tested.
    let tool = match Command::new("keepassxc-cli").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "the KeePassXC interoperation lane cannot run: keepassxc-cli is not installed. \
             Install it and re-run, or record this lane as an exclusion. It is \
             currently verified on Linux and Windows, not macOS."
        ),
        Err(error) => panic!("cannot launch keepassxc-cli: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "keepassxc-cli --version failed");
            output
        }
    };
    println!(
        "keepassxc-cli {}",
        String::from_utf8_lossy(&tool.stdout).trim()
    );
}

#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test helper fails immediately on subprocess setup or timeout errors"
)]
fn run_with_stdin_timeout(command: &mut Command, input: &[u8], timeout: Duration) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn subprocess");

    let stdout_pipe = child.stdout.take().expect("capture stdout");
    let stderr_pipe = child.stderr.take().expect("capture stderr");

    let stdout_thread = thread::spawn(move || {
        let mut buffer = Vec::new();
        stdout_pipe
            .take(MAX_CAPTURE_BYTES)
            .read_to_end(&mut buffer)
            .expect("read stdout");
        buffer
    });
    let stderr_thread = thread::spawn(move || {
        let mut buffer = Vec::new();
        stderr_pipe
            .take(MAX_CAPTURE_BYTES)
            .read_to_end(&mut buffer)
            .expect("read stderr");
        buffer
    });

    if let Some(mut stdin_pipe) = child.stdin.take() {
        if let Err(error) = stdin_pipe.write_all(input) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "write subprocess stdin: {error}"
            );
        }
        drop(stdin_pipe);
    }

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll subprocess status") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            panic!("subprocess timed out after {timeout:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = stdout_thread.join().expect("join stdout reader");
    let stderr = stderr_thread.join().expect("join stderr reader");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn run_keepassxc(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut command = Command::new("keepassxc-cli");
    command.args(args);
    run_with_stdin_timeout(&mut command, stdin_bytes, COMMAND_TIMEOUT)
}

#[allow(
    clippy::expect_used,
    reason = "test path must be valid UTF-8 for CLI invocation"
)]
fn run_nkp(dir: &Path, vault: &Path, args: &[&str], stdin_bytes: &[u8]) -> Output {
    let home = dir.join("home");
    let xdg_config = dir.join("xdg-config");
    let xdg_data = dir.join("xdg-data");
    let nkp_config = dir.join("nkp-config");
    let nkp_data = dir.join("nkp-data");
    let vault_str = vault.to_str().expect("vault path is valid UTF-8");

    let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
    command
        .current_dir(dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("NKP_CONFIG_DIR", &nkp_config)
        .env("NKP_DATA_DIR", &nkp_data)
        .arg("--vault")
        .arg(vault_str)
        .args(args);
    run_with_stdin_timeout(&mut command, stdin_bytes, COMMAND_TIMEOUT)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_no_secret_bytes(output: &Output, secrets: &[&str]) {
    for secret in secrets {
        let needle = secret.as_bytes();
        assert!(
            !contains_bytes(&output.stdout, needle),
            "stdout leaked secret material"
        );
        assert!(
            !contains_bytes(&output.stderr, needle),
            "stderr leaked secret material"
        );
    }
}

fn assert_nkp_get_field(
    dir: &Path,
    vault: &Path,
    entry_path: &str,
    field: Option<&str>,
    keyfile: Option<&str>,
    master_password: &str,
    expected: &[u8],
) {
    let mut args = vec!["get", entry_path];
    if let Some(field_name) = field {
        args.extend(["-F", field_name]);
    }
    if let Some(keyfile_path) = keyfile {
        args.extend(["--key-file", keyfile_path]);
    }
    args.push("--password-stdin");
    let stdin_bytes = format!("{master_password}\n");
    let output = run_nkp(dir, vault, &args, stdin_bytes.as_bytes());
    let label = field.unwrap_or("Password");
    assert!(
        output.status.success(),
        "nkp get {label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected, "nkp get {label} mismatch");
}

fn keepassxc_add_supports_notes() -> bool {
    let mut command = Command::new("keepassxc-cli");
    command.args(["add", "--help"]);
    let output = run_with_stdin_timeout(&mut command, b"", COMMAND_TIMEOUT);
    let help = String::from_utf8_lossy(&output.stdout);
    let err_help = String::from_utf8_lossy(&output.stderr);
    help.contains("--notes") || err_help.contains("--notes")
}

#[allow(
    clippy::expect_used,
    reason = "integration test fails loudly if setup or subprocess I/O fails"
)]
fn create_keepassxc_test_vault(vault: &Path) -> bool {
    let vault_str = vault.to_str().expect("vault path is valid UTF-8");
    let master_twice = format!("{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n");
    let master_once = format!("{MASTER_PASSWORD}\n");

    let create = run_keepassxc(
        &["db-create", "--set-password", vault_str],
        master_twice.as_bytes(),
    );
    assert!(
        create.status.success(),
        "keepassxc-cli db-create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let mkdir = run_keepassxc(&["mkdir", vault_str, GROUP_NAME], master_once.as_bytes());
    assert!(
        mkdir.status.success(),
        "keepassxc-cli mkdir failed: {}",
        String::from_utf8_lossy(&mkdir.stderr)
    );

    let supports_notes = keepassxc_add_supports_notes();
    let add_stdin = format!("{MASTER_PASSWORD}\n{ENTRY_PASSWORD}\n");
    let mut add_args = vec!["add", "--username", ENTRY_USER, "--url", ENTRY_URL];
    if supports_notes {
        add_args.extend(["--notes", ENTRY_NOTES]);
    }
    add_args.extend(["-p", vault_str, ENTRY_PATH]);
    let add = run_keepassxc(&add_args, add_stdin.as_bytes());
    assert!(
        add.status.success(),
        "keepassxc-cli add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    supports_notes
}

#[allow(
    clippy::expect_used,
    reason = "integration test fails loudly if CLI output is invalid"
)]
fn assert_nkp_metadata_views(dir: &Path, vault: &Path) {
    let master_once = format!("{MASTER_PASSWORD}\n");

    let ls = run_nkp(
        dir,
        vault,
        &["ls", "--password-stdin"],
        master_once.as_bytes(),
    );
    assert!(
        ls.status.success(),
        "nkp ls failed: {}",
        String::from_utf8_lossy(&ls.stderr)
    );
    assert_no_secret_bytes(&ls, &[MASTER_PASSWORD, ENTRY_PASSWORD]);
    let ls_stdout = String::from_utf8(ls.stdout).expect("nkp ls stdout is valid UTF-8");
    let listed = ls_stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("ls line is JSON"))
        .any(|record| {
            record["title"] == ENTRY_TITLE
                && record["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(ENTRY_PATH))
        });
    assert!(listed, "nkp ls did not list {ENTRY_PATH}: {ls_stdout}");

    let show = run_nkp(
        dir,
        vault,
        &["show", "-k", ENTRY_PATH, "--password-stdin"],
        master_once.as_bytes(),
    );
    assert!(
        show.status.success(),
        "nkp show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert_no_secret_bytes(&show, &[MASTER_PASSWORD, ENTRY_PASSWORD]);
    let show_json: serde_json::Value =
        serde_json::from_slice(&show.stdout).expect("nkp show output is valid JSON");
    assert_eq!(show_json["title"], ENTRY_TITLE);
    assert_eq!(show_json["path"], ENTRY_PATH);
    let fields = show_json["fields"]
        .as_array()
        .expect("show JSON includes fields array");
    for required_field in ["Title", "UserName", "Password", "URL"] {
        assert!(
            fields.iter().any(|field| field["name"] == required_field),
            "show JSON missing field {required_field}: {show_json}"
        );
    }
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
#[allow(
    clippy::expect_used,
    reason = "integration test fails loudly if setup or subprocess I/O fails"
)]
fn keepassxc_created_database_opens_and_reads_in_nkp() {
    require_keepassxc_cli();

    let directory = tempfile::tempdir().expect("create temporary directory");
    let vault = directory.path().join("interop.kdbx");
    let vault_str = vault.to_str().expect("vault path is valid UTF-8");
    let master_once = format!("{MASTER_PASSWORD}\n");

    let supports_notes = create_keepassxc_test_vault(&vault);
    assert_nkp_metadata_views(directory.path(), &vault);

    assert_nkp_get_field(
        directory.path(),
        &vault,
        ENTRY_PATH,
        None,
        None,
        MASTER_PASSWORD,
        ENTRY_PASSWORD.as_bytes(),
    );
    assert_nkp_get_field(
        directory.path(),
        &vault,
        ENTRY_PATH,
        Some("UserName"),
        None,
        MASTER_PASSWORD,
        ENTRY_USER.as_bytes(),
    );
    assert_nkp_get_field(
        directory.path(),
        &vault,
        ENTRY_PATH,
        Some("URL"),
        None,
        MASTER_PASSWORD,
        ENTRY_URL.as_bytes(),
    );
    if supports_notes {
        assert_nkp_get_field(
            directory.path(),
            &vault,
            ENTRY_PATH,
            Some("Notes"),
            None,
            MASTER_PASSWORD,
            ENTRY_NOTES.as_bytes(),
        );
    }

    let password_assignment = format!("Password={UPDATED_PASSWORD}");
    let custom_assignment = format!("{CUSTOM_FIELD_NAME}={CUSTOM_FIELD_VALUE}");
    let set = run_nkp(
        directory.path(),
        &vault,
        &[
            "set",
            ENTRY_PATH,
            "-F",
            &password_assignment,
            "-F",
            &custom_assignment,
            "--password-stdin",
        ],
        master_once.as_bytes(),
    );
    assert!(
        set.status.success(),
        "nkp set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert!(set.stdout.is_empty(), "nkp set wrote unexpected stdout");

    let xc_show_password = run_keepassxc(
        &["show", "-s", "-a", "Password", vault_str, ENTRY_PATH],
        master_once.as_bytes(),
    );
    assert!(
        xc_show_password.status.success(),
        "keepassxc-cli show Password after nkp set failed: {}",
        String::from_utf8_lossy(&xc_show_password.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&xc_show_password.stdout).trim_end_matches(['\r', '\n']),
        UPDATED_PASSWORD
    );

    let xc_show_custom = run_keepassxc(
        &["show", "-s", "-a", CUSTOM_FIELD_NAME, vault_str, ENTRY_PATH],
        master_once.as_bytes(),
    );
    assert!(
        xc_show_custom.status.success(),
        "keepassxc-cli show custom attribute after nkp set failed: {}",
        String::from_utf8_lossy(&xc_show_custom.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&xc_show_custom.stdout).trim_end_matches(['\r', '\n']),
        CUSTOM_FIELD_VALUE
    );
}

#[test]
#[ignore = "requires keepassxc-cli; run in the interoperation lane"]
#[allow(
    clippy::expect_used,
    reason = "integration test fails loudly if setup or subprocess I/O fails"
)]
fn keepassxc_created_keyfile_database_opens_in_nkp() {
    require_keepassxc_cli();

    let directory = tempfile::tempdir().expect("create temporary directory");
    let vault = directory.path().join("keyfile-interop.kdbx");
    let keyfile = directory.path().join("interop.key");
    let vault_str = vault.to_str().expect("vault path is valid UTF-8");
    let keyfile_str = keyfile.to_str().expect("keyfile path is valid UTF-8");
    let master_twice = format!("{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n");
    let master_once = format!("{MASTER_PASSWORD}\n");

    let create = run_keepassxc(
        &["db-create", "-k", keyfile_str, "--set-password", vault_str],
        master_twice.as_bytes(),
    );
    assert!(
        create.status.success(),
        "keepassxc-cli db-create with keyfile failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(keyfile.is_file(), "keepassxc-cli did not generate keyfile");

    let add_stdin = format!("{MASTER_PASSWORD}\n{ENTRY_PASSWORD}\n");
    let add = run_keepassxc(
        &[
            "add",
            "-k",
            keyfile_str,
            "--username",
            ENTRY_USER,
            "-p",
            vault_str,
            ENTRY_TITLE,
        ],
        add_stdin.as_bytes(),
    );
    assert!(
        add.status.success(),
        "keepassxc-cli add with keyfile failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let without_keyfile = run_nkp(
        directory.path(),
        &vault,
        &["get", ENTRY_TITLE, "--password-stdin"],
        master_once.as_bytes(),
    );
    assert!(
        !without_keyfile.status.success(),
        "nkp unexpectedly opened a keyfile-protected vault without --key-file"
    );
    assert_no_secret_bytes(&without_keyfile, &[MASTER_PASSWORD, ENTRY_PASSWORD]);

    let ls = run_nkp(
        directory.path(),
        &vault,
        &["ls", "--key-file", keyfile_str, "--password-stdin"],
        master_once.as_bytes(),
    );
    assert!(
        ls.status.success(),
        "nkp ls with --key-file failed: {}",
        String::from_utf8_lossy(&ls.stderr)
    );
    assert_no_secret_bytes(&ls, &[MASTER_PASSWORD, ENTRY_PASSWORD]);
    let ls_stdout = String::from_utf8(ls.stdout).expect("nkp ls stdout is valid UTF-8");
    assert!(
        ls_stdout.contains(ENTRY_TITLE),
        "nkp ls did not include {ENTRY_TITLE}: {ls_stdout}"
    );

    assert_nkp_get_field(
        directory.path(),
        &vault,
        ENTRY_TITLE,
        None,
        Some(keyfile_str),
        MASTER_PASSWORD,
        ENTRY_PASSWORD.as_bytes(),
    );
    assert_nkp_get_field(
        directory.path(),
        &vault,
        ENTRY_TITLE,
        Some("UserName"),
        Some(keyfile_str),
        MASTER_PASSWORD,
        ENTRY_USER.as_bytes(),
    );
}
