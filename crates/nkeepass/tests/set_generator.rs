#[allow(dead_code, reason = "shared synthetic fixture")]
#[path = "support/cli_support.rs"]
mod fixture;

use fixture::{CliFixture, ENTRY_TITLE, MASTER_PASSWORD, command, run_with_stdin};
use std::path::Path;
use std::process::Output;

fn run(fixture: &CliFixture, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut cmd = command(Path::new(env!("CARGO_BIN_EXE_nkp")), fixture);
    cmd.args(["--vault", fixture.vault().to_str().unwrap()])
        .args(args)
        .env("NEO_KEEPASS_CONFIG_DIR", fixture.directory().join("config"))
        .env("TEST_UNLOCK", MASTER_PASSWORD);
    if let Some(input) = input {
        run_with_stdin(&mut cmd, input)
    } else {
        cmd.output().unwrap()
    }
}

fn get(fixture: &CliFixture, key: &str, field: &str) -> Vec<u8> {
    let output = run(
        fixture,
        &[
            "get",
            key,
            "--field",
            field,
            "--password-env",
            "TEST_UNLOCK",
        ],
        None,
    );
    assert!(
        output.status.success(),
        "get diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn value_sources_assignments_empty_values_and_legacy_selector() {
    let fixture = CliFixture::new(false);
    let file = fixture.directory().join("value.txt");
    std::fs::write(&file, b"file-value\n").unwrap();
    for (args, stdin, expected) in [
        (
            vec!["--value", "argv-value"],
            None,
            b"argv-value".as_slice(),
        ),
        (
            vec!["--value-stdin"],
            Some(b"stdin-value\n".as_slice()),
            b"stdin-value\n".as_slice(),
        ),
        (
            vec!["--value-file", file.to_str().unwrap()],
            None,
            b"file-value\n".as_slice(),
        ),
        (vec!["--value", ""], None, b"".as_slice()),
    ] {
        let mut options = vec!["set", ENTRY_TITLE, "--password-env", "TEST_UNLOCK"];
        options.extend(args);
        let output = run(&fixture, &options, stdin);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert_eq!(get(&fixture, ENTRY_TITLE, "Password"), expected);
    }
    let mut cmd = command(Path::new(env!("CARGO_BIN_EXE_nkp")), &fixture);
    let output = cmd
        .args([
            "--vault",
            fixture.vault().to_str().unwrap(),
            "set",
            ENTRY_TITLE,
            "--password-env",
            "TEST_UNLOCK",
            "--value-env",
            "TEST_FIELD",
        ])
        .env("NEO_KEEPASS_CONFIG_DIR", fixture.directory().join("config"))
        .env("TEST_UNLOCK", MASTER_PASSWORD)
        .env("TEST_FIELD", "env-value")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(get(&fixture, ENTRY_TITLE, "Password"), b"env-value");
    let output = run(
        &fixture,
        &[
            "set",
            ENTRY_TITLE,
            "--password-env",
            "TEST_UNLOCK",
            "--field",
            "Custom=one=two",
            "--field",
            "Notes=",
            "--field",
            "UserName",
            "--value",
            "legacy-user",
        ],
        None,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(get(&fixture, ENTRY_TITLE, "Custom"), b"one=two");
    assert_eq!(get(&fixture, ENTRY_TITLE, "Notes"), b"");
    assert_eq!(get(&fixture, ENTRY_TITLE, "UserName"), b"legacy-user");
}

#[test]
fn invalid_updates_do_not_mutate_or_disclose_and_noninteractive_prompt_fails() {
    let fixture = CliFixture::new(false);
    let before = std::fs::read(fixture.vault()).unwrap();
    for extra in [
        vec!["--value", "new-secret", "--value-stdin"],
        vec!["--field", "Password=new-secret", "--value", "other-secret"],
        vec!["--field", "Notes=one", "--field", "Notes=two"],
        vec!["--field", "Notes", "--field", "Custom=value"],
        vec!["--value-env", "MISSING"],
        vec!["--generate", "--value", "new-secret"],
        vec!["--upper"],
        vec!["--size", "16"],
        vec!["--generate", "-c", "3"],
        vec!["--age-decrypt", "--generate"],
        vec![],
    ] {
        let mut args = vec!["set", ENTRY_TITLE, "--password-env", "TEST_UNLOCK"];
        args.extend(extra);
        let started = std::time::Instant::now();
        let output = run(&fixture, &args, None);
        assert!(!output.status.success());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("new-secret"));
        assert_eq!(std::fs::read(fixture.vault()).unwrap(), before);
    }
}

#[test]
fn ensure_defaults_classes_aliases_existing_and_dry_run() {
    let fixture = CliFixture::new(false);
    for (path, extra, size, digits_only) in [
        ("new-default", vec![], 16, false),
        ("new-digits", vec!["-D", "-c", "9"], 9, true),
        ("new-uppercase", vec!["--upper", "--chars", "1"], 1, false),
    ] {
        let mut args = vec!["ensure", "--key", path, "--password-env", "TEST_UNLOCK"];
        args.extend(extra);
        let output = run(&fixture, &args, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = get(&fixture, path, "Password");
        assert_eq!(value.len(), size);
        if digits_only {
            assert!(value.iter().all(u8::is_ascii_digit));
        }
        if size == 16 {
            assert!(value.iter().any(u8::is_ascii_uppercase));
            assert!(value.iter().any(u8::is_ascii_lowercase));
            assert!(value.iter().any(u8::is_ascii_digit));
            assert!(value.iter().any(u8::is_ascii_punctuation));
        }
        let output = run(
            &fixture,
            &[
                "ensure",
                "--key",
                path,
                "-D",
                "--password-env",
                "TEST_UNLOCK",
            ],
            None,
        );
        assert!(output.status.success());
        assert_eq!(get(&fixture, path, "Password"), value);
    }
    let before = std::fs::read(fixture.vault()).unwrap();
    let output = run(
        &fixture,
        &[
            "ensure",
            "--key",
            "dry",
            "--dry-run",
            "--password-env",
            "TEST_UNLOCK",
        ],
        None,
    );
    assert!(output.status.success());
    assert_eq!(std::fs::read(fixture.vault()).unwrap(), before);
    for path in ["new-default", "impossible-missing"] {
        let output = run(
            &fixture,
            &[
                "ensure",
                "--key",
                path,
                "--chars",
                "3",
                "--password-env",
                "TEST_UNLOCK",
            ],
            None,
        );
        assert!(
            !output.status.success(),
            "impossible policies must fail even for existing entries"
        );
        assert_eq!(std::fs::read(fixture.vault()).unwrap(), before);
    }
    let output = run(
        &fixture,
        &[
            "set",
            ENTRY_TITLE,
            "--generate",
            "-L",
            "-c",
            "12",
            "--password-env",
            "TEST_UNLOCK",
        ],
        None,
    );
    assert!(output.status.success());
    let value = get(&fixture, ENTRY_TITLE, "Password");
    assert_eq!(value.len(), 12);
    assert!(value.iter().all(u8::is_ascii_lowercase));
}

#[test]
fn age_discovery_and_explicit_identity_precedence() {
    use neotales_age::{AgeFile, AgeIdentity};
    use zeroize::Zeroizing;
    let fixture = CliFixture::new(false);
    let generated = neotales_age::AgeKey::generate().unwrap();
    let identity = AgeIdentity::from_private_key(&generated.private_key).unwrap();
    let recipient = identity.recipient().unwrap();
    let key = Zeroizing::new(identity.to_private_key().unwrap());
    let root = fixture.directory().join("config");
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    nkeepass::private_file::set_owner_only(&root, "test private directory").unwrap();
    std::fs::write(root.join("init-password.agekey"), key.as_bytes()).unwrap();
    let ciphertext = AgeFile::encrypt(b"decrypted-test-value", &[recipient]).unwrap();
    let mut cmd = command(Path::new(env!("CARGO_BIN_EXE_nkp")), &fixture);
    cmd.args([
        "--vault",
        fixture.vault().to_str().unwrap(),
        "set",
        ENTRY_TITLE,
        "--password-env",
        "TEST_UNLOCK",
        "--age-decrypt",
        "--value-stdin",
    ])
    .env("TEST_UNLOCK", MASTER_PASSWORD)
    .env("NEO_KEEPASS_CONFIG_DIR", &root);
    let output = run_with_stdin(&mut cmd, &ciphertext);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        get(&fixture, ENTRY_TITLE, "Password"),
        b"decrypted-test-value"
    );
    let mut cmd = command(Path::new(env!("CARGO_BIN_EXE_nkp")), &fixture);
    cmd.args([
        "--vault",
        fixture.vault().to_str().unwrap(),
        "set",
        ENTRY_TITLE,
        "--password-env",
        "TEST_UNLOCK",
        "--age-decrypt",
        "--value-stdin",
        "-i",
        "missing-identity",
    ])
    .env("TEST_UNLOCK", MASTER_PASSWORD)
    .env("NEO_KEEPASS_CONFIG_DIR", &root);
    let output = run_with_stdin(&mut cmd, &ciphertext);
    assert!(
        !output.status.success(),
        "explicit identity must never fall back"
    );
    assert!(output.stdout.is_empty());
}
