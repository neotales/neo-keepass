#![cfg(unix)]

//! Binding a TOTP code to a child environment or a process.
//!
//! The behaviour under test is mostly about what does *not* come out. The OTP
//! field's stored value is an `otpauth://` URI whose query string carries
//! `secret=`, and the seed inside it derives every code the entry will ever
//! produce. A code is safe to hand to a child process; the seed is not, and it is
//! the thing this suite asserts is absent from every output.

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use neotales_keepass::{
    Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
    ProtectedValue,
};
use tempfile::TempDir;

const PASSWORD: &str = "totp-binding-master-disposable-4e17";
/// The seed, kept as a named constant because it is the value the whole suite is
/// asserting never appears in output.
#[allow(dead_code, reason = "the sentinel below is what asserts on it")]
const OTP_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// A TOTP field. The `period` is stated because the library rejects a TOTP
/// URI without one, even though RFC 6238 section 4 defaults it to 30.
const TOTP_URI: &str =
    "otpauth://totp/LOGIN?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Fixture&period=30";

/// A HOTP field, which must stay refused: emitting a code without persisting the
/// counter first burns it, and every later code in the sequence is then wrong.
const HOTP_URI: &str = "otpauth://hotp/LOGIN?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0";

/// What must never appear in any output of any command in this file.
const FORBIDDEN: [&str; 3] = [OTP_SEED, "otpauth://", "secret="];

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new(otp: &str) -> Self {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("LOGIN");
        entry.password = ProtectedValue::from_text("entry-password-disposable-7c3b");
        entry.set_field(Field {
            key: "otp".into(),
            value: ProtectedValue::from_text(otp),
            protected: true,
            protect_in_memory: true,
        });
        database.add_entry(entry);

        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("totp-binding.kdbx");
        KdbxFile::save(
            &database,
            std::fs::File::create(&vault).unwrap(),
            &mut KdbxCredentials::password(PASSWORD).unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        Self { directory, vault }
    }
}

fn nkp() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_nkp"))
}

fn auth() -> [&'static str; 2] {
    ["--password-env", "NKEEPASS_TOTP_TEST_PASSWORD"]
}

/// Run a command with the fixture's credential.
///
/// The credential flags are spliced in **before** the `--` terminator when there
/// is one, because everything after `--` is the child command line. Appending
/// them at the end looks equivalent and is not: `exec` then sees no credential
/// source at all and refuses with "password source required for non-interactive
/// input", which reads like a credential problem rather than an argument-order
/// one.
fn run(fixture: &Fixture, args: &[&str]) -> Output {
    let mut command = Vec::new();
    if let Some(at) = args.iter().position(|arg| *arg == "--") {
        command.extend_from_slice(&args[..at]);
        command.extend_from_slice(&auth());
        command.extend_from_slice(&args[at..]);
    } else {
        command.extend_from_slice(args);
        command.extend_from_slice(&auth());
    }
    Command::new(nkp())
        .isolate_application_environment()
        .current_dir(fixture.directory.path())
        .env("NKEEPASS_VAULT", &fixture.vault)
        .env("NKEEPASS_TOTP_TEST_PASSWORD", PASSWORD)
        .args(&command)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn error_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Assert nothing that can reconstruct a future code reached any stream.
fn assert_no_seed(output: &Output) {
    let combined = format!("{}{}", text(output), error_text(output));
    for forbidden in FORBIDDEN {
        assert!(
            !combined.contains(forbidden),
            "output disclosed {forbidden:?}, which reconstructs every future code:\n{combined}"
        );
    }
}

/// The value a `--name BINDING` line carries, from any of the named formats.
fn bound_value(stdout: &str, name: &str) -> String {
    let quoted = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix(&format!("export {name}='"))?;
            rest.strip_suffix("';")
        })
        .unwrap_or_else(|| panic!("no binding for {name} in:\n{stdout}"));
    quoted.to_owned()
}

fn is_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[test]
fn secrets_env_field_otp_emits_a_code_and_never_the_uri() {
    let fixture = Fixture::new(TOTP_URI);
    let output = run(
        &fixture,
        &[
            "secrets", "env", "--key", "LOGIN", "--field", "otp", "--name", "CODE",
        ],
    );
    assert!(output.status.success(), "{}", error_text(&output));
    assert_no_seed(&output);
    let code = bound_value(&text(&output), "CODE");
    assert!(is_code(&code), "expected a 6-digit code, got {code:?}");
}

#[test]
fn exec_field_otp_binds_a_code_to_the_child() {
    let fixture = Fixture::new(TOTP_URI);
    // The child writes what it received to stdout, so the assertion is on what
    // actually crossed the process boundary rather than on what the parent held.
    let output = run(
        &fixture,
        &[
            "exec",
            "--key",
            "LOGIN",
            "--field",
            "otp",
            "--env",
            "CODE",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$CODE\"",
        ],
    );
    assert!(output.status.success(), "{}", error_text(&output));
    assert_no_seed(&output);
    let code = text(&output);
    assert!(is_code(&code), "expected a 6-digit code, got {code:?}");
}

#[test]
fn exec_binds_the_password_by_default_and_a_field_on_request() {
    let fixture = Fixture::new(TOTP_URI);
    let output = run(
        &fixture,
        &[
            "exec",
            "--key",
            "LOGIN",
            "--env",
            "PW",
            "--key",
            "LOGIN",
            "--field",
            "otp",
            "--env",
            "CODE",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$PW\" \"$CODE\"",
        ],
    );
    assert!(output.status.success(), "{}", error_text(&output));
    assert_no_seed(&output);
    let bound = text(&output);
    let (password, code) = bound.split_once('|').expect("two bindings");
    assert_eq!(password, "entry-password-disposable-7c3b");
    assert!(is_code(code), "expected a 6-digit code, got {code:?}");
}

#[test]
fn codes_bound_in_one_invocation_agree() {
    let fixture = Fixture::new(TOTP_URI);
    let output = run(
        &fixture,
        &[
            "secrets", "env", "--key", "LOGIN", "--field", "otp", "--name", "FIRST", "--key",
            "LOGIN", "--field", "otp", "--name", "SECOND", "--key", "LOGIN", "--field", "otp",
            "--name", "THIRD",
        ],
    );
    assert!(output.status.success(), "{}", error_text(&output));
    assert_no_seed(&output);
    let stdout = text(&output);
    let first = bound_value(&stdout, "FIRST");
    assert_eq!(
        first,
        bound_value(&stdout, "SECOND"),
        "two codes in one invocation must come from one pinned timestamp"
    );
    assert_eq!(first, bound_value(&stdout, "THIRD"));
    assert!(is_code(&first), "expected a 6-digit code, got {first:?}");
}

#[test]
fn hotp_stays_refused_in_both_bindings() {
    // Not a regression guard for a bug: a deliberate refusal that a future
    // "just generate it" change would silently undo. Emitting an HOTP code
    // without persisting the counter burns it.
    let fixture = Fixture::new(HOTP_URI);
    for args in [
        vec![
            "secrets", "env", "--key", "LOGIN", "--field", "otp", "--name", "CODE",
        ],
        vec![
            "exec", "--key", "LOGIN", "--field", "otp", "--env", "CODE", "--", "sh", "-c", "true",
        ],
    ] {
        let output = run(&fixture, &args);
        assert!(!output.status.success(), "HOTP must be refused: {args:?}");
        assert!(
            error_text(&output).contains("HOTP"),
            "expected an HOTP-specific diagnostic, got {:?}",
            error_text(&output)
        );
        assert_no_seed(&output);
    }
}

#[test]
fn exec_field_without_a_key_is_rejected() {
    let fixture = Fixture::new(TOTP_URI);
    let command = [
        "exec", "--field", "otp", "--env", "CODE", "--", "sh", "-c", "true",
    ];
    let output = run(&fixture, &command);
    assert!(!output.status.success());
    assert!(
        error_text(&output).contains("--key required before --field"),
        "{}",
        error_text(&output)
    );
}

#[test]
fn exec_rejects_a_repeated_field_for_one_key() {
    let fixture = Fixture::new(TOTP_URI);
    let output = run(
        &fixture,
        &[
            "exec", "--key", "LOGIN", "--field", "otp", "--field", "Password", "--env", "CODE",
            "--", "sh", "-c", "true",
        ],
    );
    assert!(!output.status.success());
    assert!(
        error_text(&output).contains("invalid or duplicate option"),
        "{}",
        error_text(&output)
    );
}

#[test]
fn exec_refuses_an_existing_binding_name_before_starting_the_child() {
    let fixture = Fixture::new(TOTP_URI);
    let output = Command::new(nkp())
        .isolate_application_environment()
        .current_dir(fixture.directory.path())
        .env("NKEEPASS_VAULT", &fixture.vault)
        .env("NKEEPASS_TOTP_TEST_PASSWORD", PASSWORD)
        .env("COLLISION", "caller-value")
        .args([
            "exec",
            "--key",
            "LOGIN",
            "--env",
            "COLLISION",
            "--password-env",
            "NKEEPASS_TOTP_TEST_PASSWORD",
            "--",
            "sh",
            "-c",
            "printf child-started",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(text(&output).is_empty(), "child must not have started");
    assert!(
        error_text(&output).contains("exec environment name already exists"),
        "{}",
        error_text(&output)
    );
    assert_no_seed(&output);
}

#[test]
fn the_expiry_warning_names_the_binding_and_never_the_code() {
    let fixture = Fixture::new(TOTP_URI);
    // Run until the clock is inside the warning window, so the assertion does not
    // depend on when the suite happens to execute. Bounded so a broken warning
    // fails the test rather than hanging it.
    let mut warned = None;
    for _ in 0..40 {
        let output = run(
            &fixture,
            &[
                "secrets", "env", "--key", "LOGIN", "--field", "otp", "--name", "CODE",
            ],
        );
        assert!(output.status.success(), "{}", error_text(&output));
        assert_no_seed(&output);
        let stderr = error_text(&output);
        if stderr.contains("expires in") {
            let code = bound_value(&text(&output), "CODE");
            assert!(
                !stderr.contains(&code),
                "the warning must not repeat the code"
            );
            assert!(stderr.contains("CODE"), "the warning must name the binding");
            warned = Some(stderr);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    let stderr = warned.expect("no expiry warning appeared within 40 seconds");
    assert!(
        stderr.starts_with("nkp: warning:"),
        "the warning belongs on stderr and is labelled: {stderr:?}"
    );
}
