//! Disposable CLI fixtures and byte-level secret-leak checks.
//! Include this file from a downstream command-line front end's `tests/`
//! directory to run the same scenarios against its own executable.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use neotales_keepass::{
    Attachment, Entry, Field, KdbxCredentials, KdbxFile, KdbxKeyFile, KdbxReadLimits,
    KdbxWriteOptions, KeePassDatabase, ProtectedValue,
};
use tempfile::TempDir;

pub const MASTER_PASSWORD: &str = "cli-master-SENTINEL-5a8c91";
pub const WRONG_PASSWORD: &str = "cli-wrong-SENTINEL-c29a81";
pub const ENTRY_PASSWORD: &str = "cli-entry-SENTINEL-619c4f";
pub const USERNAME: &str = "cli-user-SENTINEL-1178bc";
pub const NOTES: &str = "cli-notes-SENTINEL-39e12a";
pub const CUSTOM_FIELD: &str = "cli-custom-SENTINEL-a271fc";
pub const OTP_SEED: &str = "JBSWY3DPEHPK3PXP";
pub const ATTACHMENT: &[u8] = b"cli-attachment-SENTINEL-dcae32";
pub const KEY_FILE: &[u8; 32] = b"cli-key-file-SENTINEL-0123456789";
pub const ENTRY_TITLE: &str = "fixture-login";
/// A *valid* TOTP field value.
///
/// The `period` parameter is present because the library rejects a TOTP URI
/// without one (`TOTP URI period must be positive`), even though RFC 6238 section
/// 4 fixes the time step at 30 seconds and `period` only overrides it. Without it
/// this fixture's OTP field was unparseable, and every command that reads it
/// failed with "invalid OTP field" -- which meant **no test could exercise
/// `secrets otp` against the shared fixture at all**, and the one OTP test that
/// did exist had to build its own entry to get around it.
pub const OTP_URI: &str =
    "otpauth://totp/fixture-login?secret=JBSWY3DPEHPK3PXP&issuer=fixture&period=30";

/// A temporary KDBX4 vault; all file paths die with this value.
pub struct CliFixture {
    directory: TempDir,
    vault: PathBuf,
    key_file: PathBuf,
}

impl CliFixture {
    /// Create a password-only vault, or a password-and-key-file vault.
    pub fn new(with_key_file: bool) -> Self {
        Self::build(with_key_file, true)
    }

    /// Create a vault whose *only* credential is a key file.
    ///
    /// Separate from `new(true)` because that one always includes the master
    /// password, and a vault that needs both cannot show that `--key-file` alone
    /// skips the password prompt: the prompt would be satisfied by the password
    /// anyway, so the test would pass whether or not the key file was
    /// sufficient. That is the branch the coverage is for, so the fixture has to
    /// isolate it.
    pub fn key_file_only() -> Self {
        Self::build(true, false)
    }

    fn build(with_key_file: bool, with_password: bool) -> Self {
        let directory = TempDir::new().expect("temporary directory");
        let vault = directory.path().join("fixture.kdbx");
        let key_file = directory.path().join("fixture.key");
        fs::write(&key_file, KEY_FILE).expect("write key file");

        let mut database = KeePassDatabase::default();
        let reference = database.binary_pool.add(ATTACHMENT.to_vec(), true);
        let mut entry = Entry::new(ENTRY_TITLE);
        entry.username = USERNAME.into();
        entry.notes = NOTES.into();
        entry.password = ProtectedValue::from_text(ENTRY_PASSWORD);
        entry.set_field(Field {
            key: "Private custom field".into(),
            value: ProtectedValue::from_text(CUSTOM_FIELD),
            protected: true,
            protect_in_memory: true,
        });
        entry.set_field(Field {
            key: "otp".into(),
            value: ProtectedValue::from_text(OTP_URI),
            protected: true,
            protect_in_memory: true,
        });
        entry.attachments.push(Attachment {
            name: "file.txt".into(),
            reference,
        });
        database.root.add_entry(entry);

        let mut credentials = match (with_key_file, with_password) {
            (true, true) => KdbxCredentials::with_provider(
                Some(MASTER_PASSWORD),
                Box::new(KdbxKeyFile::parse(KEY_FILE).expect("key file parses")),
            ),
            (true, false) => KdbxCredentials::with_provider(
                None,
                Box::new(KdbxKeyFile::parse(KEY_FILE).expect("key file parses")),
            ),
            (false, _) => KdbxCredentials::password(MASTER_PASSWORD),
        }
        .expect("credentials");
        let mut output = fs::File::create(&vault).expect("create vault");
        KdbxFile::save(
            &database,
            &mut output,
            &mut credentials,
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .expect("save fixture vault");

        Self {
            directory,
            vault,
            key_file,
        }
    }

    pub fn vault(&self) -> &Path {
        &self.vault
    }

    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Put the path sentinel in a request, without putting it inside the vault.
    pub fn missing_path(&self) -> &'static str {
        "missing-entry-SENTINEL-2d5c83"
    }

    /// A second disposable file for the malformed-file error path.
    pub fn corrupt_vault(&self) -> PathBuf {
        let path = self.directory.path().join("corrupt.kdbx");
        let mut contents = fs::read(&self.vault).expect("read vault");
        contents[20] ^= 1;
        fs::write(&path, contents).expect("write corrupted vault");
        path
    }
}

/// A marker identifier only, never the marker's plaintext.
#[derive(Debug, Eq, PartialEq)]
pub struct Leak {
    pub channel: &'static str,
    pub marker: &'static str,
}

const MARKERS: &[(&str, &[u8])] = &[
    ("master password", MASTER_PASSWORD.as_bytes()),
    ("wrong password", WRONG_PASSWORD.as_bytes()),
    ("entry password", ENTRY_PASSWORD.as_bytes()),
    ("username", USERNAME.as_bytes()),
    ("notes", NOTES.as_bytes()),
    ("custom field", CUSTOM_FIELD.as_bytes()),
    ("otp seed", OTP_SEED.as_bytes()),
    ("otp uri", OTP_URI.as_bytes()),
    ("attachment", ATTACHMENT),
    ("key file", KEY_FILE),
    ("missing path", b"missing-entry-SENTINEL-2d5c83"),
];

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Scan raw stdout and stderr (including invalid UTF-8) without displaying secrets.
pub fn find_leak(output: &Output) -> Option<Leak> {
    for (channel, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        for &(marker, value) in MARKERS {
            if contains_bytes(bytes, value) {
                return Some(Leak { channel, marker });
            }
        }
        if contains_bytes(bytes, b"otpauth://") || contains_bytes(bytes, b"secret=") {
            return Some(Leak {
                channel,
                marker: "otp uri fragment",
            });
        }
    }
    None
}

/// Assert a metadata/diagnostic command is secret-free; never print `Output` on failure.
pub fn assert_no_secrets(output: &Output) {
    assert_eq!(find_leak(output), None, "CLI leaked a fixture marker");
}

/// Start with a sanitized process environment and isolate all filesystem activity.
/// The app test must supply its own CLI arguments and credential source.
///
/// Windows receives a deliberately forged `USERNAME` value. It is ordinary
/// caller-controlled environment data and must not determine which account gets
/// access to a secret file; the ACL implementation resolves the account from the
/// operating system instead. Keeping this fixture catches regressions to trusting
/// `USERNAME` without exposing any fixture secrets to the child.
pub fn command(binary: &Path, fixture: &CliFixture) -> Command {
    let mut command = Command::new(binary);
    command.current_dir(fixture.directory()).env_clear();
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        // File ACL hardening invokes absolute System32 utilities with a cleared
        // environment. Keep this OS path while retaining the forged USERNAME
        // value below to verify that ACL ownership does not trust it.
        command.env("SystemRoot", system_root);
    }
    #[cfg(windows)]
    command.env("USERNAME", "forged-fixture-account");
    command
}

/// Run a command with piped stdin; the caller owns any credential bytes in `input`.
pub fn run_with_stdin(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    let write_result = child.stdin.take().expect("stdin pipe").write_all(input);
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "write CLI stdin: {error}"
        );
    }
    child.wait_with_output().expect("wait for CLI")
}

/// Required public CLI surfaces. The adapter translates these into app-specific argv.
#[derive(Clone, Copy, Debug)]
pub enum Scenario {
    Help,
    List,
    Context,
    Alias,
    MissingEntry,
    WrongPassword,
    CorruptVault,
}

/// Run every public/diagnostic path through the same byte-level disclosure gate.
/// The adapter must authenticate using stdin or a temporary password file, not argv.
pub fn assert_public_surfaces(
    fixture: &CliFixture,
    mut run: impl FnMut(Scenario, &CliFixture) -> Output,
) {
    for scenario in [
        Scenario::Help,
        Scenario::List,
        Scenario::Context,
        Scenario::Alias,
        Scenario::MissingEntry,
        Scenario::WrongPassword,
        Scenario::CorruptVault,
    ] {
        let output = run(scenario, fixture);
        assert_no_secrets(&output);
        let should_succeed = matches!(
            scenario,
            Scenario::Help | Scenario::List | Scenario::Context | Scenario::Alias
        );
        assert_eq!(
            output.status.success(),
            should_succeed,
            "unexpected CLI status for {scenario:?}"
        );
        if matches!(scenario, Scenario::List) {
            assert!(
                contains_bytes(&output.stdout, ENTRY_TITLE.as_bytes()),
                "list did not display the fixture entry"
            );
        }
    }
}
