//! Ordered, atomic bundle disclosure against synthetic vaults only.
use neotales_keepass::{
    Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const MASTER: &str = "synthetic-bundle-master";
const FIRST: &str = "first-bundle-SENTINEL";
const SECOND: &str = "second-bundle-SENTINEL";

struct Fixture {
    directory: tempfile::TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("many.kdbx");
        let mut database = KeePassDatabase::default();
        for (title, password) in [
            ("A", FIRST),
            ("B", SECOND),
            ("many", "entry-named-many"),
            ("-odd", "leading-dash"),
            ("G_Path", "underscore-value"),
        ] {
            let mut entry = Entry::new(title);
            entry.password = ProtectedValue::from_text(password);
            entry.notes = if title == "B" {
                "second 'quote'\nline"
            } else {
                "first $`\\\" text"
            }
            .into();
            entry.set_field(Field::new("many", format!("field-many-{title}")));
            if title == "A" {
                entry.set_field(Field::new("OnlyA", "only-a-secret"));
            }
            for (key, value) in [
                (
                    "BadNul",
                    if title == "B" {
                        "hidden\0nul"
                    } else {
                        "ordinary"
                    },
                ),
                (
                    "BadControl",
                    if title == "B" {
                        "hidden\u{1b}[31m"
                    } else {
                        "ordinary"
                    },
                ),
            ] {
                entry.set_field(Field {
                    key: key.into(),
                    value: ProtectedValue::from_text(value),
                    protected: true,
                    protect_in_memory: true,
                });
            }
            database.root.add_entry(entry);
        }
        let mut group = Group::new("G");
        let mut entry = Entry::new("Path");
        entry.password = ProtectedValue::from_text("slash-value");
        group.add_entry(entry);
        database.root.add_group(group);
        KdbxFile::save(
            &database,
            std::fs::File::create(&vault).unwrap(),
            &mut KdbxCredentials::password(MASTER).unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        Self { directory, vault }
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nkp"));
        cmd.env_clear()
            .current_dir(self.directory.path())
            .env(
                "NEO_KEEPASS_CONFIG_DIR",
                self.directory.path().join("config"),
            )
            .env("NEO_KEEPASS_PASSWORD", MASTER)
            .args(["--vault", self.vault.to_str().unwrap()])
            .args(args)
            .stdin(Stdio::null());
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
        cmd.output().unwrap()
    }
    fn success(&self, args: &[&str]) -> Vec<u8> {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        output.stdout
    }
    fn refused(&self, args: &[&str]) {
        let output = self.run(args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty(), "partial plaintext was disclosed");
        for secret in [MASTER, FIRST, SECOND, "only-a-secret", "hidden"] {
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(secret),
                "diagnostic leaked a value"
            );
        }
    }
}

#[test]
fn ordered_text_null_json_and_common_field() {
    let fixture = Fixture::new();
    for route in [
        vec![
            "--password-env",
            "NEO_KEEPASS_PASSWORD",
            "get",
            "many",
            "B",
            "A",
        ],
        vec![
            "--password-env",
            "NEO_KEEPASS_PASSWORD",
            "secrets",
            "get",
            "many",
            "B",
            "A",
        ],
    ] {
        assert_eq!(
            fixture.success(&route),
            format!("{SECOND},{FIRST}").as_bytes()
        );
    }
    assert_eq!(
        fixture.success(&["get", "many", "B", "A"]),
        format!("{SECOND},{FIRST}").as_bytes()
    );
    assert_eq!(
        fixture.success(&["secrets", "get", "many", "B", "A", "--format", "null"]),
        format!("{SECOND}\0{FIRST}\0").as_bytes()
    );
    assert_eq!(
        fixture.success(&["get", "many", "B", "A", "--format", "json"]),
        format!("{{\"B\":\"{SECOND}\",\"A\":\"{FIRST}\"}}\n").as_bytes()
    );
    assert_eq!(
        fixture.success(&["get", "many", "B", "--field", "many", "A"]),
        b"field-many-B,field-many-A"
    );
    assert_eq!(
        fixture.success(&["get", "many", "G/Path", "G_Path", "--format", "json"]),
        b"{\"G/Path\":\"slash-value\",\"G_Path\":\"underscore-value\"}\n"
    );
}

#[test]
fn named_bundle_formats_reuse_single_value_conventions() {
    let fixture = Fixture::new();
    for format in [
        "dotenv",
        "shell",
        "pwsh",
        "powershell",
        "github-actions",
        "azure-devops",
    ] {
        let field = if format == "azure-devops" {
            "Password"
        } else {
            "Notes"
        };
        let mut expected = fixture.success(&[
            "get", "B", "--field", field, "--format", format, "--name", "B",
        ]);
        expected.extend(fixture.success(&[
            "get", "A", "--field", field, "--format", format, "--name", "A",
        ]));
        assert_eq!(
            fixture.success(&[
                "get", "many", "B", "A", "--field", field, "--format", format
            ]),
            expected,
            "{format}"
        );
    }
    let output = fixture.success(&[
        "get",
        "many",
        "B",
        "A",
        "--format",
        "azure-devops",
        "--is-output",
    ]);
    assert_eq!(
        String::from_utf8(output)
            .unwrap()
            .matches(";isOutput=true")
            .count(),
        2
    );
}

#[test]
fn request_and_format_failures_are_atomic_and_redacted() {
    let fixture = Fixture::new();
    for args in [
        vec!["get", "many"],
        vec!["get", "many", "A", "A"],
        vec!["get", "many", "A", "missing"],
        vec!["get", "many", "A", "B", "--field", "OnlyA"],
        vec!["get", "many", "A", "G/Path", "--format", "shell"],
        vec![
            "get", "many", "A", "B", "--field", "BadNul", "--format", "null",
        ],
        vec![
            "get",
            "many",
            "A",
            "B",
            "--field",
            "BadControl",
            "--format",
            "dotenv",
        ],
        vec![
            "get",
            "many",
            "A",
            "B",
            "--field",
            "Notes",
            "--format",
            "azure-devops",
        ],
        vec!["get", "many", "A", "--name", "X"],
        vec!["get", "many", "--key", "A"],
        vec!["get", "many", "A", "--clipboard"],
        vec!["get", "many", "A", "--format", "unknown"],
        vec!["get", "many", "A", "--is-output"],
        vec!["get", "many", "A", "--age-encrypt"],
        vec!["get", "many", "A", "--age-encrypt", "-r", "invalid"],
    ] {
        fixture.refused(&args);
    }
    let mut too_many = vec!["get", "many"];
    too_many.extend(std::iter::repeat_n("A", 257));
    fixture.refused(&too_many);
    // Windows rejects this at CreateProcess's command-line length limit; the
    // platform-independent unit test covers the CLI budget without spawning.
    #[cfg(unix)]
    {
        let too_long = "A".repeat(64 * 1024 + 1);
        fixture.refused(&["get", "many", &too_long]);
    }
}

#[test]
fn reserved_many_leading_dash_paths_aliases_and_collisions() {
    let fixture = Fixture::new();
    assert_eq!(fixture.success(&["get", "--", "many"]), b"entry-named-many");
    assert_eq!(
        fixture.success(&["get", "--key", "many"]),
        b"entry-named-many"
    );
    assert_eq!(
        fixture.success(&["get", "--field", "many", "A"]),
        b"field-many-A"
    );
    assert_eq!(
        fixture.success(&["get", "many", "many", "A"]),
        format!("entry-named-many,{FIRST}").as_bytes()
    );
    assert_eq!(
        fixture.success(&["get", "many", "--", "-odd", "A"]),
        format!("leading-dash,{FIRST}").as_bytes()
    );
    fixture.success(&["alias", "set", "ALIAS1", "A", "--field", "Notes"]);
    fixture.success(&["alias", "set", "ALIAS2", "A"]);
    assert_eq!(
        fixture.success(&["get", "many", "ALIAS1", "ALIAS2"]),
        format!("{FIRST},{FIRST}").as_bytes(),
        "bundle default ignores alias field override"
    );
    fixture.success(&["alias", "set", "B", "A"]);
    fixture.refused(&["get", "many", "A", "B"]);
}

#[test]
fn age_encrypts_one_complete_bundle_for_each_format_and_private_output() {
    use neotales_age::{AgeFile, AgeIdentity, AgeKey};
    use zeroize::Zeroizing;
    let fixture = Fixture::new();
    let key = AgeKey::generate().unwrap();
    let private = Zeroizing::new(key.private_key);
    let identity = AgeIdentity::from_private_key(private.as_str()).unwrap();
    for format in [
        "text",
        "null",
        "json",
        "dotenv",
        "shell",
        "pwsh",
        "github-actions",
        "azure-devops",
    ] {
        let expected = fixture.success(&["get", "many", "B", "A", "--format", format]);
        let output = fixture.success(&[
            "get",
            "many",
            "B",
            "A",
            "--format",
            format,
            "--age-encrypt",
            "-r",
            &key.public_key,
        ]);
        let armor = std::str::from_utf8(&output).unwrap();
        assert_eq!(
            armor.matches("-----BEGIN AGE ENCRYPTED FILE-----").count(),
            1
        );
        assert!(!armor.contains(FIRST) && !armor.contains(SECOND));
        let plaintext = Zeroizing::new(
            AgeFile::decrypt_armored(armor, std::slice::from_ref(&identity)).unwrap(),
        );
        assert_eq!(&*plaintext, &expected);
    }
    let path = fixture.directory.path().join("bundle.age");
    assert!(
        fixture
            .success(&[
                "get",
                "many",
                "B",
                "A",
                "--format",
                "json",
                "--age-encrypt",
                "-r",
                &key.public_key,
                "--output",
                path.to_str().unwrap()
            ])
            .is_empty()
    );
    let ciphertext = std::fs::read(&path).unwrap();
    let decrypted = Zeroizing::new(
        AgeFile::decrypt_armored(std::str::from_utf8(&ciphertext).unwrap(), &[identity]).unwrap(),
    );
    assert_eq!(
        &*decrypted,
        &fixture.success(&["get", "many", "B", "A", "--format", "json"])
    );
    fixture.refused(&[
        "get",
        "many",
        "B",
        "A",
        "--age-encrypt",
        "-r",
        &key.public_key,
        "--output",
        path.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&path).unwrap(), ciphertext);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn removed_routes_are_rejected_and_not_advertised() {
    let fixture = Fixture::new();
    for route in [
        vec!["getx"],
        vec!["secrets", "getx"],
        vec!["setx"],
        vec!["secrets", "setx"],
        vec!["automation", "setx"],
    ] {
        fixture.refused(&route);
        let mut help = route.clone();
        help.push("--help");
        fixture.refused(&help);
    }
    for route in [
        vec!["--help"],
        vec!["secrets", "--help"],
        vec!["automation", "--help"],
    ] {
        let output = fixture.success(&route);
        let help = String::from_utf8(output).unwrap();
        assert!(!help.contains("getx") && !help.contains("setx"));
    }
    for shell in ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "nushell"] {
        let output = fixture.success(&["completion", shell]);
        let script = String::from_utf8(output).unwrap();
        assert!(!script.contains("getx") && !script.contains("setx"));
        assert!(script.contains("many"));
    }
    for route in [vec!["get", "--help"], vec!["secrets", "get", "--help"]] {
        let help = String::from_utf8(fixture.success(&route)).unwrap();
        assert!(help.contains("COMMANDS:") && help.contains("many"));
        assert!(help.contains("--password-env"));
    }
    for route in [
        vec!["get", "many", "--help"],
        vec!["secrets", "get", "many", "--help"],
    ] {
        let help = String::from_utf8(fixture.success(&route)).unwrap();
        assert!(
            help.contains("--field")
                && help.contains("--age-encrypt")
                && help.contains("--password-env")
        );
        assert!(!help.contains("--clipboard"));
    }
}
