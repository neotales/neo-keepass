#![cfg(unix)]

//! Integration coverage for `nkp init`.
//!
//! The properties asserted here are security properties, not conveniences: a
//! create path that silently overwrites, briefly exposes, or prints a secret is
//! worse than a missing feature, because the user has no way to tell it
//! happened.

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Length requested from `init --size`.
///
/// The disclosure check below asks that no alphanumeric run as long as this
/// reaches stdout or stderr. The result document's longest such run is
/// `generated_password`, at 17, so the report cannot satisfy the check and only
/// a printed secret can.
const GENERATED: usize = 32;

const PASSWORD: &str = "init-master-disposable-9b41";
const OTHER_PASSWORD: &str = "init-master-disposable-0000";
const PASSWORD_ENV: &str = "NKEEPASS_INIT_TEST_PASSWORD";

/// The `$UUID` `VariantDictionary` entry inside the outer header's KDF field: a
/// field-type byte, then a 4-byte length and the name, then a 4-byte length and
/// the 16-byte UUID. Pinning that whole prefix is what makes the assertion about
/// the *header* rather than about a coincidental 16-byte run somewhere in the
/// encrypted payload.
const UUID_FIELD: &[u8] = b"\x42\x05\x00\x00\x00$UUID\x10\x00\x00\x00";
const ARGON2ID: &[u8] = &[
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];
const ARGON2D: &[u8] = &[
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const AES_KDF: &[u8] = &[
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    /// Configuration and data live in separate directories so a test can tell
    /// "the context was adopted" from "the context happened to already exist".
    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
    }

    fn data_home(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn vault(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn default_vault(&self) -> PathBuf {
        self.data_home().join("nkeepass").join("default.kdbx")
    }
}

fn command(fixture: &Fixture, password: &str) -> Command {
    let child = Command::new(env!("CARGO_BIN_EXE_nkp"));
    let mut child = child.isolate_application_environment();
    child
        .current_dir(fixture.root.path())
        .env("HOME", fixture.root.path())
        .env_remove("NKEEPASS_CONFIG_DIR")
        .env_remove("NEO_KEEPASS_CONFIG_DIR")
        .env_remove("NKP_CONFIG_DIR")
        .env_remove("NKEEPASS_DATA_DIR")
        .env_remove("NEO_KEEPASS_DATA_DIR")
        .env_remove("NKP_DATA_DIR")
        .env_remove("XDG_CONFIG_DIR")
        .env_remove("XDG_DATA_DIR")
        .env("XDG_CONFIG_HOME", fixture.config_home())
        .env("XDG_DATA_HOME", fixture.data_home())
        .env(PASSWORD_ENV, password)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NEO_KEEPASS_VAULT")
        .env_remove("NKP_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .env_remove("NEO_KEEPASS_VAULT_PATH")
        .env_remove("NKP_VAULT_PATH")
        .env_remove("NKEEPASS_PASSWORD")
        .env_remove("NEO_KEEPASS_PASSWORD")
        .env_remove("NKP_PASSWORD")
        .env_remove("NKEEPASS_COMPLETE_PASSWORD_ENV")
        .env_remove("NEO_KEEPASS_COMPLETE_PASSWORD_ENV")
        .env_remove("NKP_COMPLETE_PASSWORD_ENV")
        .stdin(Stdio::null());
    child
}

#[test]
fn password_backup_uses_app_specific_directory_overrides() {
    let fixture = Fixture::new();
    let vault = fixture.vault("override.kdbx");
    let config = fixture.root.path().join("override-config");
    let data = fixture.root.path().join("override-data");
    let output = command(&fixture, PASSWORD)
        .env("NKEEPASS_CONFIG_DIR", &config)
        .env("NKEEPASS_DATA_DIR", &data)
        .args(with_password(&["init", vault.to_str().unwrap()]))
        .output()
        .unwrap();
    let result = created(&output);
    let backup = PathBuf::from(result["password_backup"].as_str().unwrap());
    assert_eq!(backup.parent(), Some(data.as_path()));
    assert!(config.join("init-password.agekey").is_file());

    let xdg_config = fixture.root.path().join("xdg-config");
    let xdg_data = fixture.root.path().join("xdg-data");
    let xdg_vault = fixture.vault("xdg-override.kdbx");
    let xdg_output = command(&fixture, PASSWORD)
        .env("XDG_CONFIG_DIR", &xdg_config)
        .env("XDG_DATA_DIR", &xdg_data)
        .args(with_password(&["init", xdg_vault.to_str().unwrap()]))
        .output()
        .unwrap();
    let xdg_result = created(&xdg_output);
    let xdg_backup = PathBuf::from(xdg_result["password_backup"].as_str().unwrap());
    assert_eq!(
        xdg_backup.parent(),
        Some(xdg_data.join("nkeepass").as_path())
    );
    assert!(xdg_config.join("nkeepass/init-password.agekey").is_file());

    for (index, (config_name, data_name, fallback_name)) in [
        ("NEO_KEEPASS_CONFIG_DIR", "NEO_KEEPASS_DATA_DIR", "NKP"),
        ("NKP_CONFIG_DIR", "NKP_DATA_DIR", "NKEEPASS"),
    ]
    .into_iter()
    .enumerate()
    {
        let selected_config = fixture.root.path().join(format!("alias-config-{index}"));
        let selected_data = fixture.root.path().join(format!("alias-data-{index}"));
        let ignored_config = fixture.root.path().join(format!("ignored-config-{index}"));
        let ignored_data = fixture.root.path().join(format!("ignored-data-{index}"));
        let alias_vault = fixture.vault(&format!("alias-{index}.kdbx"));
        let output = command(&fixture, PASSWORD)
            .env(config_name, &selected_config)
            .env(data_name, &selected_data)
            .env(format!("{fallback_name}_CONFIG_DIR"), &ignored_config)
            .env(format!("{fallback_name}_DATA_DIR"), &ignored_data)
            .args(with_password(&["init", alias_vault.to_str().unwrap()]))
            .output()
            .unwrap();
        let result = created(&output);
        let backup = PathBuf::from(result["password_backup"].as_str().unwrap());
        assert_eq!(backup.parent(), Some(selected_data.as_path()));
        assert!(selected_config.join("init-password.agekey").is_file());
        assert!(!ignored_config.exists());
        assert!(!ignored_data.exists());
    }
}

#[test]
fn empty_config_alias_does_not_fall_through_to_lower_priority_directory() {
    let fixture = Fixture::new();
    let selected_config = fixture.root.path().join("empty-fallback-config");
    let empty_output = command(&fixture, PASSWORD)
        .env("NEO_KEEPASS_CONFIG_DIR", "")
        .env("NKP_CONFIG_DIR", &selected_config)
        .args(with_password(&[
            "init",
            fixture.vault("empty-config-dir.kdbx").to_str().unwrap(),
        ]))
        .output()
        .unwrap();
    assert!(!empty_output.status.success());
    assert!(!selected_config.exists());
}

#[test]
fn empty_data_alias_does_not_fall_through_to_lower_priority_directory() {
    let fixture = Fixture::new();
    let selected_data = fixture.root.path().join("empty-fallback-data");
    let empty_output = command(&fixture, PASSWORD)
        .env("NEO_KEEPASS_DATA_DIR", "")
        .env("NKP_DATA_DIR", &selected_data)
        .args(with_password(&[
            "init",
            fixture.vault("empty-data-dir.kdbx").to_str().unwrap(),
        ]))
        .output()
        .unwrap();
    assert!(!empty_output.status.success());
    assert!(!selected_data.exists());
}

#[test]
fn app_directory_alias_handles_nonunicode_paths_according_to_filesystem_capability() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let config = PathBuf::from(std::ffi::OsString::from_vec(
        fixture
            .root
            .path()
            .join("config-")
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .copied()
            .chain([0xff])
            .collect(),
    ));
    // Test the same parent and filename bytes the CLI will use. An unrelated
    // permissions or I/O error must not masquerade as lack of byte support.
    let control = fixture.root.path().join("config-control");
    std::fs::create_dir(&control).expect("create ASCII control directory");
    std::fs::remove_dir(&control).expect("remove ASCII control directory");
    let supports_nonunicode = match std::fs::create_dir(&config) {
        Ok(()) => {
            std::fs::remove_dir(&config).expect("remove non-Unicode probe directory");
            true
        }
        Err(error) => {
            let invalid_name = error.kind() == std::io::ErrorKind::InvalidInput
                || error.kind() == std::io::ErrorKind::InvalidData
                || cfg!(target_os = "macos") && error.raw_os_error() == Some(92)
                || cfg!(target_os = "linux") && error.raw_os_error() == Some(84);
            assert!(
                invalid_name,
                "unexpected non-Unicode mkdir error: {error:?}"
            );
            eprintln!("filesystem rejected non-Unicode mkdir: {error:?}");
            false
        }
    };

    let output = command(&fixture, PASSWORD)
        .env("NEO_KEEPASS_CONFIG_DIR", &config)
        .env("NKP_CONFIG_DIR", fixture.root.path().join("short-fallback"))
        .env(
            "NKEEPASS_CONFIG_DIR",
            fixture.root.path().join("legacy-fallback"),
        )
        .args([
            "context",
            "set",
            "native",
            fixture.vault("native.kdbx").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    if supports_nonunicode {
        assert!(
            output.status.success(),
            "OS-native directory paths should work: {}",
            stderr(&output)
        );
        assert!(config.join("config.json").is_file());
    } else {
        assert!(
            !output.status.success(),
            "unsupported filename was accepted"
        );
        assert!(
            stderr(&output).contains("cannot create configuration directory"),
            "{}",
            stderr(&output)
        );
        assert!(!fixture.config_home().join("nkeepass/config.json").exists());
        assert!(!fixture.data_home().exists());
        assert!(!fixture.vault("native.kdbx").exists());
        assert_no_password(&output);
    }
    assert!(!fixture.root.path().join("short-fallback").exists());
    assert!(!fixture.root.path().join("legacy-fallback").exists());
}

#[test]
fn unsafe_backup_roots_stop_password_only_creation_before_any_vault() {
    use std::os::unix::ffi::OsStringExt;

    for suffix in ["CONFIG_DIR", "DATA_DIR"] {
        for prefix in ["NEO_KEEPASS", "NKP", "NKEEPASS"] {
            for bad_byte in [0xff, b'\n'] {
                for generated in [false, true] {
                    for json in [false, true] {
                        let fixture = Fixture::new();
                        let vault = fixture.vault("not-created.kdbx");
                        let bad_root = PathBuf::from(std::ffi::OsString::from_vec(
                            fixture
                                .root
                                .path()
                                .join("unsafe-")
                                .as_os_str()
                                .as_encoded_bytes()
                                .iter()
                                .copied()
                                .chain([bad_byte])
                                .collect(),
                        ));
                        let mut child = command(&fixture, PASSWORD);
                        child
                            .env(format!("{prefix}_{suffix}"), bad_root)
                            .args(["init", vault.to_str().unwrap()]);
                        if generated {
                            child.arg("--generate-master-password");
                        } else {
                            child.args(["--password-env", PASSWORD_ENV]);
                        }
                        if json {
                            child.arg("--json");
                        }
                        let output = child.output().unwrap();
                        assert!(!output.status.success(), "{prefix}_{suffix}");
                        assert!(!vault.exists(), "{prefix}_{suffix}");
                        assert!(
                            stderr(&output).contains("vault creation did not start"),
                            "{}",
                            stderr(&output)
                        );
                        assert!(
                            stderr(&output)
                                .contains("password backup directory is not safe to report")
                        );
                        assert_no_password(&output);
                    }
                }
            }
        }
    }
}

#[test]
fn key_file_only_init_does_not_require_reportable_backup_roots() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let vault = fixture.vault("key-only.kdbx");
    let key = fixture.root.path().join("keyfile");
    std::fs::write(&key, [42_u8; 32]).unwrap();
    let unsafe_data = PathBuf::from(std::ffi::OsString::from_vec(
        fixture
            .root
            .path()
            .join("data-")
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .copied()
            .chain([0xff])
            .collect(),
    ));
    let output = command(&fixture, PASSWORD)
        .env("NEO_KEEPASS_DATA_DIR", unsafe_data)
        .args([
            "init",
            vault.to_str().unwrap(),
            "--key-file",
            key.to_str().unwrap(),
            "--json",
            "--iterations",
            "64",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(vault.is_file());
    assert_no_password(&output);
}

#[cfg(unix)]
#[test]
fn backup_failure_reports_cause_and_leaves_created_vault() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let vault = fixture.vault("partial.kdbx");
    let data = fixture.root.path().join("backup-data");
    std::fs::create_dir(&data).unwrap();
    let target = fixture.root.path().join("do-not-touch");
    std::fs::create_dir(&target).unwrap();
    symlink(&target, data.join("nkeepass")).unwrap();
    let output = command(&fixture, PASSWORD)
        .env("NKEEPASS_DATA_DIR", data.join("nkeepass"))
        .args(with_password(&["init", vault.to_str().unwrap()]))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(vault.is_file(), "vault creation is not rolled back");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("vault created"));
    assert!(diagnostic.contains("must not be a symlink or non-directory"));
}

fn run(fixture: &Fixture, args: &[&str]) -> Output {
    command(fixture, PASSWORD).args(args).output().unwrap()
}

fn run_as(fixture: &Fixture, args: &[&str], password: &str) -> Output {
    command(fixture, password).args(args).output().unwrap()
}

fn assert_reported_path(value: &serde_json::Value, expected: &Path) {
    let reported = Path::new(value.as_str().expect("reported path is a string"));
    fn normalized(path: &Path) -> PathBuf {
        if let Ok(path) = path.canonicalize() {
            return path;
        }
        let parent = path.parent().expect("reported path has a parent");
        parent
            .canonicalize()
            .unwrap()
            .join(path.file_name().expect("reported path has a filename"))
    }

    assert_eq!(normalized(reported), normalized(expected));
}

/// Appends the one credential source this file uses everywhere.
///
/// `--password-env` rather than `--password VALUE` so the master password never
/// reaches the test's own argv either, and the assertions below then cover
/// exactly the channels the tool itself writes.
fn with_password<'a>(args: &'a [&'a str]) -> Vec<&'a str> {
    args.iter()
        .copied()
        .chain(args.contains(&"init").then_some("--json"))
        .chain(["--password-env", PASSWORD_ENV])
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn created(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "init failed: {}", stderr(output));
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Asserts the master password reached no channel the tool writes to.
///
/// A secret in stdout is capturable by terminal scrollback, redirected files,
/// logs and pipelines, so "we printed it" is indistinguishable downstream from
/// "we leaked it".
fn assert_no_password(output: &Output) {
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    for secret in [PASSWORD, OTHER_PASSWORD] {
        assert!(
            !combined
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "init disclosed the master password"
        );
    }
}

/// Asserts no maximal run of alphanumeric bytes in the output reaches `length`.
///
/// A generated password is exactly such a run, so this catches a disclosure
/// from any source rather than only one that happens to equal the value read
/// back from the vault. `length` is chosen well above the longest key or value
/// the result document can contain, so the check cannot be satisfied by the
/// report itself.
fn assert_no_alphanumeric_run(output: &Output, length: usize, secret: &str) {
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    let mut run = 0;
    let mut longest = 0;
    for byte in &combined {
        if byte.is_ascii_alphanumeric() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(
        longest < length,
        "init disclosed {secret}: a {longest}-character alphanumeric run reached stdout or stderr"
    );
}

fn header_carries(bytes: &[u8], uuid: &[u8]) -> bool {
    let mut field = UUID_FIELD.to_vec();
    field.extend_from_slice(uuid);
    bytes.windows(field.len()).any(|window| window == field)
}

#[test]
fn creates_a_vault_that_reopens_with_the_same_password() {
    let fixture = Fixture::new();
    let vault = fixture.vault("round-trip.kdbx");
    let result = created(&run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap()]),
    ));
    assert_eq!(result["operation"], "init");
    assert_reported_path(&result["path"], &vault);
    assert_eq!(result["source"], "argument");
    assert_eq!(result["kdf"], "aes");
    assert_eq!(result["generated_password"], false);
    let backup = PathBuf::from(
        result["password_backup"]
            .as_str()
            .expect("reported backup path"),
    );
    assert_eq!(
        backup.parent(),
        Some(fixture.data_home().join("nkeepass").as_path())
    );
    assert!(
        backup
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("init-password-") && name.ends_with(".age"))
    );
    assert!(backup.is_file());
    assert!(
        fixture
            .config_home()
            .join("nkeepass/init-password.agekey")
            .is_file()
    );
    // Nothing had chosen a vault yet, so the new one becomes the context.
    assert_eq!(result["context_set"], true);
    assert!(std::fs::metadata(&vault).unwrap().len() > 0);

    let shown = run(&fixture, &["context", "show", "--json"]);
    let context: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_reported_path(&context["path"], &vault);
    assert_eq!(context["source"], "context");

    let opened = run(
        &fixture,
        &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
    );
    assert!(
        opened.status.success(),
        "the created vault did not reopen: {}",
        stderr(&opened)
    );
    assert!(opened.stdout.is_empty());

    // The library, not the CLI, is what proves the file is a real database.
    let file = std::fs::File::open(&vault).unwrap();
    let db = neotales_keepass::KdbxFile::open(file, PASSWORD).unwrap();
    assert_eq!(db.root.name, "Root");
    assert!(db.root.entries.is_empty());
}

#[test]
fn the_master_password_is_never_echoed() {
    let fixture = Fixture::new();
    let vault = fixture.vault("quiet.kdbx");
    let output = run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap(), "--iterations", "64"]),
    );
    created(&output);
    assert_no_password(&output);
}

#[test]
fn refuses_to_overwrite_and_leaves_the_original_unchanged() {
    let fixture = Fixture::new();
    let vault = fixture.vault("existing.kdbx");
    let original = b"an existing vault that must survive".to_vec();
    std::fs::write(&vault, &original).unwrap();

    let output = run(&fixture, &with_password(&["init", vault.to_str().unwrap()]));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("vault already exists or cannot be created"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(&vault).unwrap(), original);

    // And it stays refused: the guarantee is the create itself, not a one-shot
    // warning a second run walks past.
    let again = run(&fixture, &with_password(&["init", vault.to_str().unwrap()]));
    assert!(!again.status.success());
    assert_eq!(std::fs::read(&vault).unwrap(), original);
    assert_no_password(&output);
    assert_no_password(&again);
}

#[cfg(target_os = "linux")]
#[test]
fn staging_failure_keeps_the_target_absent_and_reports_the_init_diagnostic() {
    let fixture = Fixture::new();
    let vault = Path::new("/proc").join(format!("nkeepass-init-{}.kdbx", std::process::id()));
    let output = run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap(), "--iterations", "64"]),
    );
    assert!(!output.status.success());
    assert_eq!(
        stderr(&output).trim(),
        "nkp: cannot create vault temporary file"
    );
    assert!(!vault.exists());
}

#[test]
fn the_requested_argon2_variant_replaces_the_aes_kdf_in_the_header() {
    for (kdf, expected) in [("argon2id", ARGON2ID), ("argon2d", ARGON2D)] {
        let fixture = Fixture::new();
        let vault = fixture.vault(&format!("{kdf}.kdbx"));
        let result = created(&run(
            &fixture,
            &with_password(&[
                "init",
                vault.to_str().unwrap(),
                "--kdf",
                kdf,
                "--memory",
                "1024",
                "--iterations",
                "1",
                "--parallelism",
                "1",
            ]),
        ));
        assert_eq!(result["kdf"], kdf);
        assert_eq!(result["kdf_parameters"]["memory_kib"], 1024);
        assert_eq!(result["kdf_parameters"]["iterations"], 1);
        assert_eq!(result["kdf_parameters"]["parallelism"], 1);

        let bytes = std::fs::read(&vault).unwrap();
        assert!(
            header_carries(&bytes, expected),
            "{kdf} header does not carry its KDF UUID"
        );
        assert!(
            !header_carries(&bytes, AES_KDF),
            "{kdf} header still carries the AES-KDF UUID"
        );

        // The parameters were written, not merely reported: a vault that will
        // not reopen is not a hardened vault.
        let opened = run(
            &fixture,
            &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
        );
        assert!(
            opened.status.success(),
            "{kdf} vault did not reopen: {}",
            stderr(&opened)
        );
    }
}

#[test]
fn the_default_kdf_records_the_aes_kdf_in_the_header() {
    let fixture = Fixture::new();
    let vault = fixture.vault("default-kdf.kdbx");
    let result = created(&run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap(), "--iterations", "64"]),
    ));
    assert_eq!(result["kdf"], "aes");
    assert_eq!(result["kdf_parameters"]["aes_kdf_rounds"], 64);

    let bytes = std::fs::read(&vault).unwrap();
    assert!(header_carries(&bytes, AES_KDF));
    for argon2 in [ARGON2ID, ARGON2D] {
        assert!(!header_carries(&bytes, argon2));
    }
}

#[cfg(unix)]
#[test]
fn the_created_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    for (name, kdf) in [("plain.kdbx", false), ("argon.kdbx", true)] {
        let vault = fixture.vault(name);
        let mut base = vec!["init", vault.to_str().unwrap()];
        if kdf {
            base.extend_from_slice(&["--kdf", "argon2id", "--memory", "1024", "--iterations", "1"]);
        } else {
            base.extend_from_slice(&["--iterations", "64"]);
        }
        created(&run(&fixture, &with_password(&base)));
        assert_eq!(
            std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
            0o600,
            "{name} is not owner-only"
        );
    }
}

/// An absolute path whose last component is `name`, on this platform.
///
/// Not a literal `/tmp/...`. The CLI validates the vault path before it looks at
/// anything else, and `Path::is_absolute` is platform-defined, so on Windows
/// `/tmp/bell\u{7}.kdbx` was refused as "must be absolute and normalized" rather
/// than as the control-byte violation the test is about -- failing on the right
/// outcome for the wrong reason, which is the worst way to fail.
fn absolute_named(name: &str) -> String {
    std::env::temp_dir()
        .join(name)
        .to_str()
        .expect("a temporary directory with a UTF-8 path")
        .to_owned()
}

#[test]
fn a_control_character_in_the_path_is_rejected_and_creates_nothing() {
    let fixture = Fixture::new();
    for hostile in [
        "bell\u{7}.kdbx",
        "escape\u{1b}[31m.kdbx",
        "delete\u{7f}.kdbx",
        "c1\u{9b}0m.kdbx",
    ] {
        let target = fixture.vault(hostile);
        let absolute = absolute_named(hostile);
        let output = run(&fixture, &with_password(&["init", &absolute]));
        assert!(!output.status.success(), "accepted {hostile:?}");
        assert!(
            stderr(&output).contains("vault path cannot contain terminal-control bytes"),
            "{hostile:?}: {}",
            stderr(&output)
        );
        assert!(!target.exists(), "{hostile:?} was created anyway");
    }

    // The same predicate guards the global --vault, so a hostile path cannot
    // arrive by the other route either.
    let output = run_as(
        &fixture,
        &[
            "--vault",
            &absolute_named("bell\u{7}.kdbx"),
            "secrets",
            "ls",
        ],
        PASSWORD,
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("terminal-control bytes"));
}

#[test]
fn init_help_succeeds_and_documents_its_flags() {
    let fixture = Fixture::new();
    for flag in ["--help", "-h"] {
        let output = run(&fixture, &["init", flag]);
        assert!(output.status.success(), "init {flag} failed");
        let text = String::from_utf8_lossy(&output.stdout);
        for expected in [
            "--password-env",
            "--password-stdin",
            "--password-file",
            "--key-file",
            "--kdf",
            "aes",
            "argon2d",
            "argon2id",
            "--memory",
            "--iterations",
            "--parallelism",
            "--size",
            "Password persistence",
            "age-encrypted",
            "Partial failure",
            "Windows private files",
            "owner-only ACLs",
        ] {
            assert!(text.contains(expected), "init {flag} omits {expected}");
        }
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains(
            "Supplied password-only: backup follows successful vault creation; backup failure leaves the vault installed."
        ));
        assert!(normalized.contains(
            "Generated master: backup and association precede vault creation; their failure stops creation."
        ));
    }

    let help = run(&fixture, &["--help"]);
    assert!(help.status.success());
    let root_help = String::from_utf8_lossy(&help.stdout);
    assert!(root_help.contains("COMMANDS:"));
    assert!(root_help.lines().any(|line| line.starts_with("  init ")));
}

#[test]
fn initialization_docs_distinguish_backup_failure_ordering() {
    let readme = include_str!("../../../README.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(readme.contains(
        "master password and installs its encrypted backup and recovery association before attempting vault creation; a failure in either stops vault creation."
    ));
    assert!(readme.contains(
        "If that supplied-password backup fails, init reports the sanitized cause and leaves the already-created vault in place."
    ));
    let reference = include_str!("../../../docs/reference/vault.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(reference.contains(
        "With a supplied password and no key file, init attempts the age-encrypted backup after successful vault creation. A failure of that backup leaves the created vault in place."
    ));
    assert!(reference.contains(
        "With a generated master password, backup and recovery association are attempted before vault creation; a failure in either stops vault creation."
    ));
}

#[test]
fn a_wrong_password_does_not_open_the_created_vault() {
    let fixture = Fixture::new();
    let vault = fixture.vault("locked.kdbx");
    created(&run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap(), "--iterations", "64"]),
    ));

    let refused = run_as(
        &fixture,
        &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
        OTHER_PASSWORD,
    );
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("cannot unlock vault"));
    assert!(refused.stdout.is_empty());

    // The right password still works, so the failure above is the credential
    // and not a vault that was written broken.
    let opened = run(
        &fixture,
        &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
    );
    assert!(opened.status.success());
}

#[test]
fn a_bare_init_creates_the_resolved_default_and_adopts_the_context() {
    let fixture = Fixture::new();
    assert!(!fixture.default_vault().parent().unwrap().exists());
    let result = created(&run(&fixture, &with_password(&["init"])));
    assert_reported_path(&result["path"], &fixture.default_vault());
    assert_eq!(result["source"], "data-directory");
    assert_eq!(result["context_set"], true);
    assert!(fixture.default_vault().is_file());
    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.config_home().join("nkeepass/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(config["current"], "default");
    assert_eq!(config["aliases"]["default"]["kind"], "vault");
    assert_eq!(config["aliases"]["default"]["target"], result["path"]);

    let shown = run(&fixture, &["context", "show", "--json"]);
    assert!(shown.status.success());
    let context: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_reported_path(&context["path"], &fixture.default_vault());
    assert_eq!(context["source"], "context");
    assert_eq!(context["alias"], "default");

    let listed = run(&fixture, &["context", "ls", "--json"]);
    assert!(listed.status.success());
    let alias: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(alias["alias"], "default");
    assert_reported_path(&alias["path"], &fixture.default_vault());

    // The selected value is the alias, and it can be selected again after
    // clearing current independently of the alias record.
    assert!(run(&fixture, &["config", "rm", "current"]).status.success());
    assert!(
        run(&fixture, &["context", "use", "default"])
            .status
            .success()
    );
    let selected = run(&fixture, &["context", "show", "--json"]);
    let selected: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(selected["source"], "context");
    assert_eq!(selected["alias"], "default");
    assert_reported_path(&selected["path"], &fixture.default_vault());

    // The next command works with no --vault at all: the create path being
    // usable immediately is the whole reason the context is adopted.
    let ensured = run(
        &fixture,
        &with_password(&["secrets", "ensure", "--key", "LOGIN", "--size", "16"]),
    );
    assert!(
        ensured.status.success(),
        "secrets ensure after init failed: {}",
        stderr(&ensured)
    );
    let got = run(
        &fixture,
        &with_password(&["secrets", "get", "--key", "LOGIN"]),
    );
    assert!(got.status.success());
    assert_eq!(got.stdout.len(), 16);
}

#[test]
fn bare_init_does_not_replace_a_user_selected_context() {
    let fixture = Fixture::new();
    let selected = fixture.vault("selected.kdbx");
    assert!(
        run(
            &fixture,
            &["context", "set", "chosen", selected.to_str().unwrap(),],
        )
        .status
        .success()
    );
    assert!(
        run(&fixture, &["context", "use", "chosen"])
            .status
            .success()
    );

    let result = created(&run(&fixture, &with_password(&["init"])));
    assert_reported_path(&result["path"], &selected);
    assert_eq!(result["source"], "context");
    assert_eq!(result["context_set"], false);
    assert!(selected.is_file());
    assert!(!fixture.default_vault().exists());

    let shown = run(&fixture, &["context", "show", "--json"]);
    let context: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(context["source"], "context");
    assert_eq!(context["alias"], "chosen");
    assert_reported_path(&context["path"], &selected);
}

#[test]
fn bare_init_preserves_a_colliding_default_alias() {
    let fixture = Fixture::new();
    let prior = fixture.vault("prior-default-alias.kdbx");
    assert!(
        run(
            &fixture,
            &["context", "set", "default", prior.to_str().unwrap(),],
        )
        .status
        .success()
    );

    let result = created(&run(&fixture, &with_password(&["init"])));
    assert_reported_path(&result["path"], &fixture.default_vault());
    assert_eq!(result["context_set"], true);
    assert!(fixture.default_vault().is_file());

    let listed = run(&fixture, &["context", "ls", "--json"]);
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let alias = rows.iter().find(|row| row["alias"] == "default").unwrap();
    assert_reported_path(&alias["path"], &prior);
    assert!(rows.iter().any(|row| row["alias"] == "default-1"));

    let shown = run(&fixture, &["context", "show", "--json"]);
    let context: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(context["source"], "context");
    assert_eq!(context["alias"], "default-1");
    assert_reported_path(&context["path"], &fixture.default_vault());
}

#[cfg(windows)]
#[test]
fn bare_init_works_without_home_with_explicit_app_directories() {
    let fixture = Fixture::new();
    let output = command(&fixture, PASSWORD)
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("APPDATA")
        .env_remove("LOCALAPPDATA")
        .env("NKEEPASS_CONFIG_DIR", fixture.config_home())
        .env("NKEEPASS_DATA_DIR", fixture.data_home())
        .args(with_password(&["init"]))
        .output()
        .unwrap();
    let result = created(&output);
    // NKEEPASS_DATA_DIR is already the app-specific directory; unlike XDG data
    // homes, it must not gain an additional `nkeepass` component.
    let expected = fixture.data_home().join("default.kdbx");
    assert_reported_path(&result["path"], &expected);
    assert!(expected.is_file());
    assert!(!fixture.data_home().join("nkeepass").exists());
}

#[test]
fn an_explicit_path_beats_the_context_but_an_existing_context_is_never_replaced() {
    let fixture = Fixture::new();
    let existing = fixture.vault("already-chosen.kdbx");
    assert!(
        run(
            &fixture,
            &["context", "set", "existing", existing.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert!(
        run(&fixture, &["context", "use", "existing"])
            .status
            .success()
    );

    let other = fixture.vault("other.kdbx");
    let result = created(&run(
        &fixture,
        &with_password(&["init", other.to_str().unwrap(), "--iterations", "64"]),
    ));
    assert_eq!(result["source"], "argument");
    assert_eq!(result["context_set"], false);

    let shown = run(&fixture, &["context", "show", "--json"]);
    let context: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_reported_path(&context["path"], &existing);
    assert!(other.is_file());
}

#[test]
fn a_generated_password_is_stored_in_the_vault_and_never_printed() {
    let fixture = Fixture::new();
    let vault = fixture.vault("sized.kdbx");
    let output = run(
        &fixture,
        &with_password(&[
            "init",
            vault.to_str().unwrap(),
            "--size",
            &GENERATED.to_string(),
            "--iterations",
            "64",
        ]),
    );
    assert_eq!(created(&output)["generated_password"], true);
    assert_no_password(&output);

    let listed = run(
        &fixture,
        &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
    );
    assert!(listed.status.success());
    let record: serde_json::Value = serde_json::from_slice(&listed.stdout)
        .unwrap_or_else(|_| panic!("expected one listing record: {}", stderr(&listed)));
    assert_eq!(record["path"], "Root/generated");

    // The value really is in the vault, at the requested length, and it is not
    // the master key: the vault still opens with the supplied master password.
    let got = run(
        &fixture,
        &with_password(&[
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "get",
            "--key",
            "Root/generated",
        ]),
    );
    assert!(got.status.success(), "{}", stderr(&got));
    let generated = got.stdout.clone();
    let generated = String::from_utf8(generated).unwrap();
    assert_eq!(generated.len(), GENERATED);
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_ne!(generated, PASSWORD);
    assert!(
        !output
            .stdout
            .windows(generated.len())
            .any(|window| window == generated.as_bytes()),
        "init printed the generated password"
    );
    // The other direction: a leak from any source, and on stderr as well as
    // stdout.
    assert_no_alphanumeric_run(&output, GENERATED, "the generated password");
    assert_no_alphanumeric_run(&output, GENERATED, "the master password");

    // Two vaults get two different values, or --size is a constant.
    let second = fixture.vault("sized-2.kdbx");
    created(&run(
        &fixture,
        &with_password(&[
            "init",
            second.to_str().unwrap(),
            "--size",
            &GENERATED.to_string(),
            "--iterations",
            "64",
        ]),
    ));
    let other = run(
        &fixture,
        &with_password(&[
            "--vault",
            second.to_str().unwrap(),
            "secrets",
            "get",
            "--key",
            "Root/generated",
        ]),
    );
    assert!(other.status.success());
    assert_ne!(other.stdout, got.stdout);
}

#[test]
fn kdf_options_are_refused_where_they_cannot_be_honoured() {
    let fixture = Fixture::new();
    let vault = fixture.vault("policy.kdbx");
    created(&run(
        &fixture,
        &with_password(&["init", vault.to_str().unwrap(), "--iterations", "64"]),
    ));
    let target = vault.to_str().unwrap();

    // Silently ignoring --kdf would leave the caller believing they had
    // hardened a vault written with something else, so a command that cannot
    // honour it has to say so.
    let cases: Vec<Vec<&str>> = vec![
        vec!["--vault", target, "secrets", "ls", "--kdf", "argon2id"],
        vec![
            "--vault", target, "secrets", "get", "--key", "LOGIN", "--memory", "1024",
        ],
        vec![
            "--vault",
            target,
            "secrets",
            "export",
            "--output",
            "/dev/null",
            "--parallelism",
            "2",
        ],
        vec![
            "--vault",
            target,
            "secrets",
            "ensure",
            "--key",
            "LOGIN",
            "--iterations",
            "2",
        ],
    ];
    for case in cases {
        let output = run(&fixture, &with_password(&case));
        assert!(
            !output.status.success(),
            "accepted KDF options on {}",
            case.join(" ")
        );
        assert!(
            stderr(&output).contains("invalid operation option"),
            "{}: {}",
            case.join(" "),
            stderr(&output)
        );
    }
}

#[test]
fn init_rejects_options_it_has_no_meaning_for_and_unsafe_kdf_combinations() {
    let fixture = Fixture::new();
    let vault = fixture.vault("rejected.kdbx");
    let target = vault.to_str().unwrap();
    let ambiguous = fixture.vault("ambiguous.kdbx");
    let cases: Vec<Vec<&str>> = vec![
        // An Argon2 knob under the AES KDF is discarded by the format, so
        // accepting it would misreport what was written.
        vec!["init", target, "--kdf", "aes", "--memory", "1024"],
        vec!["init", target, "--kdf", "aes", "--parallelism", "2"],
        vec!["init", target, "--memory", "1024"],
        // Beyond the read limits this CLI enforces, so init could write a file
        // its own reader would refuse to open.
        vec!["init", target, "--kdf", "argon2id", "--memory", "99999999"],
        vec!["init", target, "--kdf", "argon2id", "--iterations", "11"],
        vec!["init", target, "--kdf", "argon2id", "--parallelism", "17"],
        vec!["init", target, "--kdf", "argon2id", "--memory", "0"],
        vec!["init", target, "--kdf", "argon2id", "--parallelism", "0"],
        vec!["init", target, "--kdf", "argon2id", "--iterations", "0"],
        vec!["init", target, "--kdf", "bcrypt"],
        // The option surface init has no meaning for.
        vec!["init", target, "--key", "LOGIN"],
        vec!["init", target, "--output", "/tmp/x"],
        vec!["init", target, "--replace"],
        vec!["init", target, "--dry-run"],
        vec!["init", target, "--format", "json"],
        vec!["init", target, "--size", "0"],
        vec!["init", target, "--size", "4097"],
        // Two targets are ambiguous, not ordered.
        vec!["--vault", target, "init", ambiguous.to_str().unwrap()],
    ];
    // Bound before the list, because a `vec!` of `&str` cannot hold a borrow of a
    // temporary.
    let escaping = absolute_named("../escape.kdbx");
    let mut cases = cases;
    cases.push(vec!["init", &escaping]);
    for case in cases {
        let output = run(&fixture, &with_password(&case));
        assert!(!output.status.success(), "accepted {}", case.join(" "));
        assert!(!vault.exists(), "created a vault for {}", case.join(" "));
    }
}

#[test]
fn relative_init_path_is_resolved_from_the_invocation_directory() {
    let fixture = Fixture::new();
    let output = run(&fixture, &with_password(&["init", "./db.kdbx"]));
    let result = created(&output);
    assert_reported_path(&result["path"], &fixture.vault("db.kdbx"));
    assert!(fixture.vault("db.kdbx").is_file());

    let overwrite = run(&fixture, &with_password(&["init", "./db.kdbx"]));
    assert!(!overwrite.status.success());
    assert!(fixture.vault("db.kdbx").is_file());

    let traversal = run(&fixture, &with_password(&["init", "../escape.kdbx"]));
    assert!(!traversal.status.success());
    assert!(stderr(&traversal).contains("parent components"));
    assert!(
        !fixture
            .root
            .path()
            .parent()
            .unwrap()
            .join("escape.kdbx")
            .exists()
    );
}

#[test]
fn the_password_stdin_source_creates_a_usable_vault_without_echoing() {
    let fixture = Fixture::new();
    let vault = fixture.vault("stdin.kdbx");
    let mut command = command(&fixture, PASSWORD);
    command
        .args([
            "init",
            vault.to_str().unwrap(),
            "--password-stdin",
            "--iterations",
            "64",
        ])
        .env_remove(PASSWORD_ENV);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_no_password(&output);

    let listed = run(
        &fixture,
        &with_password(&["--vault", vault.to_str().unwrap(), "secrets", "ls"]),
    );
    assert!(listed.status.success());
}

#[test]
fn no_credential_source_is_a_refusal_that_creates_nothing() {
    let fixture = Fixture::new();
    let vault = fixture.vault("no-credential.kdbx");
    let output = run_as(&fixture, &["init", vault.to_str().unwrap()], "");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("password source required"));
    assert!(!vault.exists());
    assert!(!Path::new(&vault).exists());
}
