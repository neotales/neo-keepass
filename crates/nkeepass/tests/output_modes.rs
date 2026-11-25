#![cfg(unix)]

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use neotales_keepass::{
    Attachment, Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use tempfile::TempDir;

const PASSWORD: &str = "output-mode-master-disposable-b712";
const FIELD_SECRET: &str = "quote ' dollar $ semicolon ; newline\nsnowman-☃";
const CONTROL_VALUE: &str = "control\u{1b}[31m\u{7}end";
const OTP_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// An entry title that is an injection payload if anything ever treats it as a
/// variable name. No output path may do that.
const HOSTILE_TITLE: &str = "$env:NKEEPASS_PWNED";
const HOSTILE_SECRET: &str = "hostile-title-secret-disposable-31c4";

/// Every character a quoting rule has to get right, and none of the ones that
/// would need an escape to be worth trusting a format with: no line feed, so
/// this value is renderable by all three new formats and the round trip can be
/// asserted byte for byte.
const QUOTED_SECRET: &str = "single' double\" dollar $ backtick` backslash \\ percent % vso]";

/// The delimiter the github-actions format writes, and the one it refuses.
const GITHUB_EOF: &str = "NKP_EOF";

/// Every format that needs a `--name`, whether or not it also needs an escape.
const NAMED_FORMATS: [&str; 6] = [
    "dotenv",
    "shell",
    "pwsh",
    "powershell",
    "github-actions",
    "azure-devops",
];

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("LOGIN");
        entry.password = ProtectedValue::from_text(FIELD_SECRET);
        entry.username = "fixture-user".into();
        entry.url = "https://example.test/login".into();
        entry.notes = "fixture notes".into();
        entry.set_field(Field::new("Notes", "fixture notes"));
        entry.set_field(Field {
            key: "Token".into(),
            value: ProtectedValue::from_text("token-output-disposable-d490"),
            protected: true,
            protect_in_memory: true,
        });
        entry.set_field(Field {
            key: "Quoted".into(),
            value: ProtectedValue::from_text(QUOTED_SECRET),
            protected: true,
            protect_in_memory: true,
        });
        // A line that is exactly the heredoc delimiter would close the
        // github-actions block early and hand the rest of the value to the
        // runner as workflow commands, so it has to be refusable.
        entry.set_field(Field {
            key: "Heredoc".into(),
            value: ProtectedValue::from_text(format!("before\n{GITHUB_EOF}\nafter")),
            protected: true,
            protect_in_memory: true,
        });
        entry.set_field(Field {
            key: "otp".into(),
            value: ProtectedValue::from_text(format!(
                "otpauth://totp/Fixture?secret={OTP_SEED}&issuer=Fixture&period=30"
            )),
            protected: true,
            protect_in_memory: false,
        });
        entry.set_field(Field {
            key: "Control".into(),
            value: ProtectedValue::from_text(CONTROL_VALUE),
            protected: true,
            protect_in_memory: true,
        });
        let reference = database
            .binary_pool
            .add(b"attachment-output-disposable-85ac".to_vec(), true);
        entry.attachments.push(Attachment {
            name: "report.bin".into(),
            reference,
        });
        database.add_entry(entry);
        let mut hostile = Entry::new(HOSTILE_TITLE);
        hostile.password = ProtectedValue::from_text(HOSTILE_SECRET);
        database.add_entry(hostile);
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join("output-modes.kdbx");
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

fn run(fixture: &Fixture, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
    if args.first() != Some(&"alias") {
        command.args(["--vault", fixture.vault.to_str().unwrap()]);
    }
    command
        .args(args)
        .env("XDG_CONFIG_HOME", fixture.directory.path().join("config"))
        .env("XDG_DATA_HOME", fixture.directory.path().join("data"))
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .env_remove("NEO_KEEPASS_VAULT")
        .env_remove("NEO_KEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn success(output: &Output) -> &[u8] {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    &output.stdout
}

fn assert_markers_absent(output: &Output) {
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    for marker in [
        PASSWORD.as_bytes(),
        FIELD_SECRET.as_bytes(),
        CONTROL_VALUE.as_bytes(),
        OTP_SEED.as_bytes(),
        b"token-output-disposable-d490",
        b"attachment-output-disposable-85ac",
        HOSTILE_SECRET.as_bytes(),
        b"secret=",
    ] {
        assert!(
            !combined
                .windows(marker.len())
                .any(|window| window == marker),
            "non-disclosure surface contained a secret marker"
        );
    }
}

#[test]
fn unsupported_age_options_fail_before_disclosure_or_init_side_effects() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.vault).unwrap();
    for flag in [
        vec!["--age-encrypt"],
        vec!["--age-decrypt"],
        vec!["-r", "unused-recipient"],
        vec!["-i", "unused-identity"],
    ] {
        for route in [vec!["env"], vec!["secrets", "env"]] {
            let mut args = route;
            args.extend(["--key", "LOGIN", "--field", "Password", "--name", "DEMO"]);
            args.extend(["--password-env", "NKEEPASS_TEST_PASSWORD"]);
            args.extend(flag.iter().copied());
            let output = run(&fixture, &args);
            assert!(!output.status.success(), "unsupported age option succeeded");
            assert!(
                output.stdout.is_empty(),
                "unsupported age option wrote stdout"
            );
            assert_markers_absent(&output);
            assert!(String::from_utf8_lossy(&output.stderr).contains("age options"));
        }
        let destination = fixture.directory.path().join("new.kdbx");
        let mut args = vec![
            "init",
            destination.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ];
        args.extend(flag.iter().copied());
        let output = run(&fixture, &args);
        assert!(
            !output.status.success(),
            "unsupported init age option succeeded"
        );
        assert!(output.stdout.is_empty());
        assert_markers_absent(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("age options"));
        assert!(!destination.exists());
        assert!(!fixture.directory.path().join("config").exists());
        assert!(!fixture.directory.path().join("data").exists());
        assert!(std::fs::read(&fixture.vault).unwrap() == before);
    }
}

#[test]
#[allow(clippy::too_many_lines, reason = "output parity cases stay together")]
fn get_formats_are_explicit_bounded_and_shell_safe() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    let sentinel = fixture.directory.path().join("shell-injection-marker");

    let text = run(&fixture, &["get", "--key", "LOGIN", auth[0], auth[1]]);
    assert_eq!(success(&text), FIELD_SECRET.as_bytes());

    for (field, expected) in [
        ("Title", b"LOGIN".as_slice()),
        ("UserName", b"fixture-user".as_slice()),
        ("URL", b"https://example.test/login".as_slice()),
        ("Notes", b"fixture notes".as_slice()),
        ("Token", b"token-output-disposable-d490".as_slice()),
    ] {
        let output = run(
            &fixture,
            &["get", "--key", "LOGIN", "--field", field, auth[0], auth[1]],
        );
        assert_eq!(success(&output), expected);
    }
    let null = run(
        &fixture,
        &[
            "get", "--key", "LOGIN", "--format", "null", auth[0], auth[1],
        ],
    );
    let expected_null = [FIELD_SECRET.as_bytes(), &[0]].concat();
    assert_eq!(success(&null), expected_null);

    let dotenv = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--name",
            "LOGIN_PASSWORD",
            "--format",
            "dotenv",
            auth[0],
            auth[1],
        ],
    );
    let dotenv_text = String::from_utf8(success(&dotenv).to_vec()).unwrap();
    assert!(dotenv_text.starts_with("LOGIN_PASSWORD=\""));
    assert!(dotenv_text.ends_with("\"\n"));
    assert!(dotenv_text.contains("\\n"));
    assert!(dotenv_text.contains("☃"));

    let shell = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--name",
            "LOGIN_PASSWORD",
            "--format",
            "shell",
            auth[0],
            auth[1],
        ],
    );
    let shell_text = String::from_utf8(success(&shell).to_vec()).unwrap();
    assert!(shell_text.starts_with("export LOGIN_PASSWORD='"));
    assert!(shell_text.ends_with("';\n"));
    assert!(shell_text.contains("'\\''"));
    assert!(!sentinel.exists());

    let script = format!("{shell_text}printf '%s' \"$LOGIN_PASSWORD\"\n");
    let evaluated = Command::new("sh").arg("-c").arg(script).output().unwrap();
    assert!(evaluated.status.success());
    assert_eq!(evaluated.stdout, FIELD_SECRET.as_bytes());
    assert!(!sentinel.exists());

    for args in [
        vec![
            "get", "--key", "LOGIN", "--format", "dotenv", auth[0], auth[1],
        ],
        vec![
            "get",
            "--key",
            "LOGIN",
            "--name",
            "INVALID-NAME",
            "--format",
            "shell",
            auth[0],
            auth[1],
        ],
    ] {
        let failure = run(&fixture, &args);
        assert!(!failure.status.success());
        assert!(failure.stdout.is_empty());
        assert_markers_absent(&failure);
    }
}

#[test]
fn formatted_output_rejects_terminal_controls_before_writing() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    for format in NAMED_FORMATS {
        let output = run(
            &fixture,
            &[
                "get",
                "--key",
                "LOGIN",
                "--field",
                "Control",
                "--name",
                "CONTROL_VALUE",
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"nkp: formatted output cannot contain terminal-control bytes\n".as_slice(),
            "{format} wrote a terminal-control byte"
        );
        assert_markers_absent(&output);
    }

    let text = run(
        &fixture,
        &[
            "get", "--key", "LOGIN", "--field", "Control", auth[0], auth[1],
        ],
    );
    assert_eq!(success(&text), CONTROL_VALUE.as_bytes());
    let null = run(
        &fixture,
        &[
            "get", "--key", "LOGIN", "--field", "Control", "--format", "null", auth[0], auth[1],
        ],
    );
    assert_eq!(success(&null), [CONTROL_VALUE.as_bytes(), &[0]].concat());

    for format in NAMED_FORMATS {
        let env = run(
            &fixture,
            &[
                "secrets",
                "env",
                "--key",
                "LOGIN",
                "--field",
                "Control",
                "--name",
                "CONTROL_VALUE",
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        assert!(!env.status.success());
        assert!(env.stdout.is_empty());
        assert_eq!(
            env.stderr,
            b"nkp: formatted output cannot contain terminal-control bytes\n".as_slice(),
            "{format} wrote a terminal-control byte from a binding"
        );
        assert_markers_absent(&env);
    }
}

#[test]
fn ci_shell_formats_render_known_values_exactly() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    for format in NAMED_FORMATS {
        let output = run(
            &fixture,
            &[
                "get",
                "--key",
                "LOGIN",
                "--field",
                "Token",
                "--name",
                "LOGIN_TOKEN",
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        let text = String::from_utf8(success(&output).to_vec()).unwrap();
        let expected: &str = match format {
            // A backslash is not an escape character in a dotenv double-quoted
            // string, and a percent is not an escape character anywhere.
            "dotenv" => "LOGIN_TOKEN=\"token-output-disposable-d490\"\n",
            "shell" => "export LOGIN_TOKEN='token-output-disposable-d490';\n",
            "pwsh" | "powershell" => "$env:LOGIN_TOKEN = 'token-output-disposable-d490'\n",
            "github-actions" => "LOGIN_TOKEN<<NKP_EOF\ntoken-output-disposable-d490\nNKP_EOF\n",
            "azure-devops" => {
                "##vso[task.setvariable variable=LOGIN_TOKEN]token-output-disposable-d490\n"
            }
            other => panic!("unlisted format {other}"),
        };
        assert_eq!(text, expected, "{format} rendered unexpectedly");
    }

    // `pwsh` is a spelling of `powershell`, not a second format with its own
    // rules, so both must render the same bytes.
    let short = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "pwsh",
            auth[0],
            auth[1],
        ],
    );
    let long = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "powershell",
            auth[0],
            auth[1],
        ],
    );
    assert_eq!(short.stdout, long.stdout);
}

#[test]
fn ci_shell_formats_round_trip_quotes_dollar_backtick_and_backslash() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    let expected: [&str; 3] = [
        // The single-quoted literal needs no `$` or backtick escape, and a
        // single quote is doubled rather than backslash-escaped.
        "$env:LOGIN_QUOTED = 'single'' double\" dollar $ backtick` backslash \\ percent % vso]'\n",
        // Nothing is quoted, so the value is the block body verbatim.
        "LOGIN_QUOTED<<NKP_EOF\nsingle' double\" dollar $ backtick` backslash \\ percent % vso]\nNKP_EOF\n",
        // The value follows the property list untouched.
        "##vso[task.setvariable variable=LOGIN_QUOTED]single' double\" dollar $ backtick` backslash \\ percent % vso]\n",
    ];
    for (format, expected) in ["pwsh", "github-actions", "azure-devops"]
        .into_iter()
        .zip(expected)
    {
        let output = run(
            &fixture,
            &[
                "get",
                "--key",
                "LOGIN",
                "--field",
                "Quoted",
                "--name",
                "LOGIN_QUOTED",
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        assert_eq!(
            String::from_utf8(success(&output).to_vec()).unwrap(),
            expected,
            "{format} did not round trip the value"
        );
    }
}

#[test]
fn line_feeds_are_data_except_where_the_consumer_cannot_carry_one() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    // A single-quoted PowerShell literal and a heredoc body both hold a line
    // feed as data, so the value comes back whole.
    for format in ["pwsh", "github-actions"] {
        let output = run(
            &fixture,
            &[
                "get",
                "--key",
                "LOGIN",
                "--name",
                "LOGIN_PASSWORD",
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        let text = String::from_utf8(success(&output).to_vec()).unwrap();
        assert!(
            text.contains("newline\nsnowman-☃"),
            "{format} lost the line feed"
        );
    }

    // The Azure DevOps agent reads one logging command per line, so a line feed
    // would set the variable to the fragment before the break. Refusing is the
    // only answer that cannot silently deliver a different secret.
    let azure = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--name",
            "LOGIN_PASSWORD",
            "--format",
            "azure-devops",
            auth[0],
            auth[1],
        ],
    );
    assert!(!azure.status.success());
    assert!(azure.stdout.is_empty());
    assert_eq!(
        azure.stderr,
        b"nkp: azure-devops output cannot contain a line feed\n".as_slice()
    );
    assert_markers_absent(&azure);
}

#[test]
fn a_heredoc_delimiter_in_the_value_is_refused() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    let output = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Heredoc",
            "--name",
            "LOGIN_HEREDOC",
            "--format",
            "github-actions",
            auth[0],
            auth[1],
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"nkp: github-actions output cannot contain the heredoc delimiter\n".as_slice()
    );
    assert_markers_absent(&output);

    // The other formats have no delimiter to collide with; azure-devops still
    // refuses this one, for the line feed in it rather than the delimiter.
    let pwsh = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Heredoc",
            "--name",
            "LOGIN_HEREDOC",
            "--format",
            "pwsh",
            auth[0],
            auth[1],
        ],
    );
    let pwsh = String::from_utf8(success(&pwsh).to_vec()).unwrap();
    assert_eq!(pwsh, "$env:LOGIN_HEREDOC = 'before\nNKP_EOF\nafter'\n");

    let azure = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Heredoc",
            "--name",
            "LOGIN_HEREDOC",
            "--format",
            "azure-devops",
            auth[0],
            auth[1],
        ],
    );
    assert!(!azure.status.success());
    assert_eq!(
        azure.stderr,
        b"nkp: azure-devops output cannot contain a line feed\n".as_slice()
    );
    assert_markers_absent(&azure);
}

#[test]
fn named_formats_require_a_caller_supplied_identifier() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    for format in NAMED_FORMATS {
        // No `--name`: the name is never inferred from the entry title, because
        // `$env:` and loader names are an injection class.
        let unnamed = run(
            &fixture,
            &[
                "get", "--key", "LOGIN", "--format", format, auth[0], auth[1],
            ],
        );
        assert!(!unnamed.status.success(), "{format} accepted no --name");
        assert!(unnamed.stdout.is_empty());
        assert_eq!(
            unnamed.stderr,
            b"nkp: --name required for formatted output\n".as_slice(),
            "{format} gave the wrong diagnostic"
        );
        assert_markers_absent(&unnamed);

        // A loader name like `LD_PRELOAD` is a syntactically valid identifier and
        // a caller is free to type it; the property under test is that nothing
        // but the caller's own `--name` reaches the output.
        for name in [
            "INVALID-NAME",
            "${LOGIN_TOKEN}",
            "$env:LOGIN_TOKEN",
            "LOGIN TOKEN",
            "LOGIN.TOKEN",
            // `;` and `]` are the two characters that would end or extend the
            // azure-devops property list, and `>` would end the heredoc header.
            "LOGIN;TOKEN",
            "LOGIN]TOKEN",
            "LOGIN>TOKEN",
            "1LOGIN_TOKEN",
            "",
        ] {
            let unsafe_name = run(
                &fixture,
                &[
                    "get", "--key", "LOGIN", "--name", name, "--format", format, auth[0], auth[1],
                ],
            );
            assert!(
                !unsafe_name.status.success(),
                "{format} accepted the name {name:?}"
            );
            assert!(unsafe_name.stdout.is_empty());
            assert_markers_absent(&unsafe_name);
        }

        // An entry title is vault-controlled data, so it is never the variable
        // name -- however much it looks like one.
        let titled = run(
            &fixture,
            &[
                "get",
                "--key",
                HOSTILE_TITLE,
                "--format",
                format,
                auth[0],
                auth[1],
            ],
        );
        assert!(
            !titled.status.success(),
            "{format} named a variable from a title"
        );
        assert!(titled.stdout.is_empty());
        assert_markers_absent(&titled);
    }
}

#[test]
fn is_output_is_the_azure_devops_form_and_nothing_else() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    let plain = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "azure-devops",
            auth[0],
            auth[1],
        ],
    );
    let plain = String::from_utf8(success(&plain).to_vec()).unwrap();
    assert!(!plain.contains("isOutput"), "{plain}");

    let output = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "azure-devops",
            "--is-output",
            auth[0],
            auth[1],
        ],
    );
    assert_eq!(
        String::from_utf8(success(&output).to_vec()).unwrap(),
        "##vso[task.setvariable variable=LOGIN_TOKEN;isOutput=true]token-output-disposable-d490\n"
    );

    // An output variable is read back differently from a plain one, so the flag
    // is refused where it would silently change the scope a variable lands in.
    for args in [
        vec![
            "get",
            "--key",
            "LOGIN",
            "--name",
            "LOGIN_PASSWORD",
            "--format",
            "pwsh",
            "--is-output",
            auth[0],
            auth[1],
        ],
        vec!["get", "--key", "LOGIN", "--is-output", auth[0], auth[1]],
    ] {
        let refused = run(&fixture, &args);
        assert!(!refused.status.success(), "accepted {args:?}");
        assert!(refused.stdout.is_empty());
        assert_eq!(
            refused.stderr,
            b"nkp: --is-output requires the azure-devops format\n".as_slice()
        );
        assert_markers_absent(&refused);
    }
}

#[test]
fn secrets_env_renders_every_binding_in_order() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    let pwsh = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "LOGIN_PASSWORD",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "pwsh",
            auth[0],
            auth[1],
        ],
    );
    let pwsh = String::from_utf8(success(&pwsh).to_vec()).unwrap();
    assert_eq!(pwsh.matches("$env:LOGIN_").count(), 2, "{pwsh}");
    assert!(pwsh.contains("$env:LOGIN_PASSWORD = 'quote '' "), "{pwsh}");
    assert!(
        pwsh.contains("$env:LOGIN_TOKEN = 'token-output-disposable-d490'"),
        "{pwsh}"
    );

    // One unrenderable binding refuses the whole command: a refusal after the
    // first record is written would leave a truncated set that looks complete.
    let truncated = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "LOGIN_PASSWORD",
            "--format",
            "azure-devops",
            auth[0],
            auth[1],
        ],
    );
    assert!(!truncated.status.success());
    assert!(truncated.stdout.is_empty());
    assert_eq!(
        truncated.stderr,
        b"nkp: azure-devops output cannot contain a line feed\n".as_slice()
    );
    assert_markers_absent(&truncated);
}

#[test]
fn secrets_env_renders_the_ci_logging_formats() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    let github = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "github-actions",
            auth[0],
            auth[1],
        ],
    );
    assert_eq!(
        String::from_utf8(success(&github).to_vec()).unwrap(),
        "LOGIN_TOKEN<<NKP_EOF\ntoken-output-disposable-d490\nNKP_EOF\n"
    );

    let azure = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "azure-devops",
            "--is-output",
            auth[0],
            auth[1],
        ],
    );
    assert_eq!(
        String::from_utf8(success(&azure).to_vec()).unwrap(),
        "##vso[task.setvariable variable=LOGIN_TOKEN;isOutput=true]token-output-disposable-d490\n"
    );
}

#[test]
fn secrets_env_refuses_a_format_it_cannot_render() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    for args in [
        vec![
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "json",
            "--is-output",
            auth[0],
            auth[1],
        ],
        vec![
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--name",
            "LOGIN_TOKEN",
            "--format",
            "no-such-format",
            auth[0],
            auth[1],
        ],
    ] {
        let refused = run(&fixture, &args);
        assert!(!refused.status.success(), "accepted {args:?}");
        assert!(refused.stdout.is_empty());
        assert_markers_absent(&refused);
    }
}

#[test]
fn env_binds_aliases_and_emits_all_machine_formats() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    let configured = run(
        &fixture,
        &[
            "alias", "set", "mail", "LOGIN", "--kind", "entry", "--field", "Token",
        ],
    );
    success(&configured);

    let json = run(
        &fixture,
        &[
            "secrets",
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "LOGIN_PASSWORD",
            "--key",
            "mail",
            "--name",
            "MAIL_TOKEN",
            "--format",
            "json",
            auth[0],
            auth[1],
        ],
    );
    let values: serde_json::Value = serde_json::from_slice(success(&json)).unwrap();
    assert_eq!(values["LOGIN_PASSWORD"], FIELD_SECRET);
    assert_eq!(values["MAIL_TOKEN"], "token-output-disposable-d490");

    let null = run(
        &fixture,
        &[
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "LOGIN_PASSWORD",
            "--key",
            "mail",
            "--name",
            "MAIL_TOKEN",
            "--format",
            "null",
            auth[0],
            auth[1],
        ],
    );
    let mut records = success(&null).split(|byte| *byte == 0);
    assert_eq!(records.next(), Some(b"LOGIN_PASSWORD".as_slice()));
    assert_eq!(records.next(), Some(FIELD_SECRET.as_bytes()));
    assert_eq!(records.next(), Some(b"MAIL_TOKEN".as_slice()));
    assert_eq!(
        records.next(),
        Some(b"token-output-disposable-d490".as_slice())
    );
    assert_eq!(records.next(), Some(b"".as_slice()));
    assert_eq!(records.next(), None);

    let duplicate = run(
        &fixture,
        &[
            "env",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "DUPLICATE",
            "--key",
            "LOGIN",
            "--field",
            "Password",
            "--name",
            "DUPLICATE",
            auth[0],
            auth[1],
        ],
    );
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    assert_markers_absent(&duplicate);
}

#[test]
fn entry_notes_scalar_and_standard_field_round_trip_through_output_bindings() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("LOGIN");
    entry.notes = "serialized-notes".into();
    entry.set_field(Field::new("Notes", "serialized-notes"));
    database.add_entry(entry);
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        vault: directory.path().join("projection-mismatch.kdbx"),
        directory,
    };
    KdbxFile::save(
        &database,
        std::fs::File::create(&fixture.vault).unwrap(),
        &mut KdbxCredentials::password(PASSWORD).unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    let env = run(
        &fixture,
        &[
            "secrets", "env", "--key", "LOGIN", "--field", "Notes", "--name", "NOTES", auth[0],
            auth[1],
        ],
    );
    assert_eq!(success(&env), b"export NOTES='serialized-notes';\n");

    let exec = run(
        &fixture,
        &[
            "exec",
            "--key",
            "LOGIN",
            "--field",
            "Notes",
            "--env",
            "BOUND_NOTES",
            auth[0],
            auth[1],
            "--",
            "sh",
            "-c",
            "printf '%s' \"$BOUND_NOTES\"",
        ],
    );
    assert_eq!(success(&exec), b"serialized-notes");
}

#[test]
fn metadata_subcommands_aliases_and_otp_are_non_disclosing_except_otp() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    for args in [
        vec!["search", "LOGIN", auth[0], auth[1]],
        vec!["show", "--key", "LOGIN", auth[0], auth[1]],
        vec!["show", "LOGIN", auth[0], auth[1]],
        vec!["show", auth[0], auth[1], "--", "LOGIN"],
        vec!["secrets", "show", "LOGIN", auth[0], auth[1]],
        vec!["secrets", "list", auth[0], auth[1]],
        vec!["field", "ls", "--key", "LOGIN", auth[0], auth[1]],
        vec!["attachment", "list", "--key", "LOGIN", auth[0], auth[1]],
    ] {
        let metadata = run(&fixture, &args);
        success(&metadata);
        assert_markers_absent(&metadata);
    }

    let duplicate_selector = run(
        &fixture,
        &["show", "LOGIN", "--key", "LOGIN", auth[0], auth[1]],
    );
    assert!(!duplicate_selector.status.success());
    assert_eq!(
        duplicate_selector.stderr,
        b"nkp: entry key specified more than once; use either a positional key or --key\n"
    );

    let ensured = run(&fixture, &["ensure", "LOGIN", auth[0], auth[1]]);
    success(&ensured);
    assert!(ensured.stdout.is_empty());
    assert!(ensured.stderr.is_empty());
    let nested_ensured = run(&fixture, &["secrets", "ensure", "LOGIN", auth[0], auth[1]]);
    success(&nested_ensured);
    assert!(nested_ensured.stdout.is_empty());
    assert!(nested_ensured.stderr.is_empty());

    let otp = run(
        &fixture,
        &["secrets", "otp", "--key", "LOGIN", auth[0], auth[1]],
    );
    let otp_code = success(&otp);
    assert_eq!(otp_code.len(), 6);
    assert!(otp_code.iter().all(u8::is_ascii_digit));
    let json_otp = run(
        &fixture,
        &[
            "secrets", "otp", "--key", "LOGIN", "--format", "json", auth[0], auth[1],
        ],
    );
    let json_otp: serde_json::Value = serde_json::from_slice(&json_otp.stdout).unwrap();
    assert_eq!(json_otp["value"].as_str().unwrap().as_bytes(), otp_code);
    let combined = [otp.stdout.as_slice(), otp.stderr.as_slice()].concat();
    assert!(
        !combined
            .windows(OTP_SEED.len())
            .any(|window| window == OTP_SEED.as_bytes())
    );
    let positional_otp = run(&fixture, &["otp", "LOGIN", auth[0], auth[1]]);
    let positional_otp_code = success(&positional_otp);
    assert_eq!(positional_otp_code.len(), 6);
    assert!(positional_otp_code.iter().all(u8::is_ascii_digit));
    let nested_positional_otp = run(&fixture, &["secrets", "otp", "LOGIN", auth[0], auth[1]]);
    let nested_positional_otp_code = success(&nested_positional_otp);
    assert_eq!(nested_positional_otp_code.len(), 6);
    assert!(nested_positional_otp_code.iter().all(u8::is_ascii_digit));
    assert!(
        !combined
            .windows(b"secret=".len())
            .any(|window| window == b"secret=")
    );
}

#[test]
fn missing_noninteractive_password_and_unrelated_options_fail_with_static_redaction() {
    let fixture = Fixture::new();
    let no_password = run(&fixture, &["secrets", "ls"]);
    assert!(!no_password.status.success());
    assert_eq!(
        no_password.stderr,
        b"nkp: password source required for non-interactive input\n".as_slice()
    );
    assert_markers_absent(&no_password);

    let irrelevant = run(
        &fixture,
        &[
            "get",
            "--key",
            "LOGIN",
            "--size",
            "99",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!irrelevant.status.success());
    assert_eq!(
        irrelevant.stderr,
        b"nkp: invalid operation option\n".as_slice()
    );
    assert_markers_absent(&irrelevant);
}

#[test]
fn password_file_is_safe_for_automation_output_commands() {
    let fixture = Fixture::new();
    let password_file = fixture.directory.path().join("master.password");
    std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            fixture.vault.to_str().unwrap(),
            "secrets",
            "search",
            "LOGIN",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .env(
            "XDG_CONFIG_HOME",
            fixture.directory.path().join("file-config"),
        )
        .env_remove("NEO_KEEPASS_VAULT")
        .env_remove("NEO_KEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    success(&output);
    assert_markers_absent(&output);

    let snapshot = fixture.directory.path().join("snapshot.json");
    let exported = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            fixture.vault.to_str().unwrap(),
            "secrets",
            "export",
            "--output",
            snapshot.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .env(
            "XDG_CONFIG_HOME",
            fixture.directory.path().join("export-config"),
        )
        .env_remove("NEO_KEEPASS_VAULT")
        .env_remove("NEO_KEEPASS_VAULT_PATH")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    success(&exported);
    assert_markers_absent(&exported);
    assert!(snapshot.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        std::fs::read_to_string(password_file).unwrap(),
        format!("{PASSWORD}\n")
    );
    assert!(
        !Path::new(&fixture.vault)
            .with_file_name("master.password.tmp")
            .exists()
    );
}

#[test]
fn env_accepts_switch_like_password_value_without_splitting_bindings() {
    let mut database = KeePassDatabase::default();
    let mut group = Group::new("Demo");
    let mut entry = Entry::new("mail");
    entry.username = "demo-user".into();
    entry.password = ProtectedValue::from_text("demo-pw");
    group.entries.push(entry);
    database.root.groups.push(group);

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("switch-pw.kdbx");
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault).unwrap(),
        &mut KdbxCredentials::password("--key").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "env",
            "-k",
            "Demo/mail",
            "-F",
            "UserName",
            "--name",
            "DEMO",
            "--password",
            "--key",
        ])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(success(&output), b"export DEMO='demo-user';\n");

    let env_named_key = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "env",
            "-k",
            "Demo/mail",
            "-F",
            "UserName",
            "--name",
            "DEMO",
            "--password-env",
            "--key",
        ])
        .env("--key", "--key")
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(success(&env_named_key), b"export DEMO='demo-user';\n");
}

#[cfg(target_os = "linux")]
#[test]
fn tty_protects_raw_and_json_while_pipes_preserve_exact_bytes() {
    let mut database = KeePassDatabase::default();
    let c1_and_del = "c1-\u{009b}31m-\u{007f}-secret-SENTINEL";
    let esc_value = "esc-\u{001b}[31m-secret-SENTINEL";
    let safe_multiline = "safe\tline1\nline2";

    let mut c1_entry = Entry::new("C1Entry");
    c1_entry.password = ProtectedValue::from_text(c1_and_del);
    database.add_entry(c1_entry);

    let mut esc_entry = Entry::new("EscEntry");
    esc_entry.password = ProtectedValue::from_text(esc_value);
    database.add_entry(esc_entry);

    let mut safe_entry = Entry::new("SafeMultiline");
    safe_entry.password = ProtectedValue::from_text(safe_multiline);
    database.add_entry(safe_entry);

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("tty-raw.kdbx");
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

    // 1) Piped stdout preserves exact raw and wire JSON bytes (including C0/C1/DEL).
    let piped_raw = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "get",
            "C1Entry",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ])
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(success(&piped_raw), c1_and_del.as_bytes());

    let piped_json = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "get",
            "C1Entry",
            "--format",
            "json",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ])
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let piped_json_bytes = success(&piped_json);
    assert!(piped_json_bytes.windows(2).any(|w| w == [0xc2, 0x9b]));
    assert!(piped_json_bytes.contains(&0x7f));

    // 2) Real PTY stdout checks raw refusal, safe multiline/null preservation,
    // and TTY-safe JSON escaping.
    const PTY_DRIVER: &str = r#"
import errno, json, os, pty, select, subprocess, sys, time

binary, vault, mode = sys.argv[1:]
master, slave = pty.openpty()
base_args = [binary, "--vault", vault]
if mode == "raw_c1_refused":
    args = base_args + ["--color=always", "get", "C1Entry", "--password-env", "NKEEPASS_TEST_PASSWORD"]
elif mode == "null_esc_refused":
    args = base_args + ["get", "EscEntry", "--format", "null", "--password-env", "NKEEPASS_TEST_PASSWORD"]
elif mode == "many_partial_refused":
    args = base_args + ["get", "many", "SafeMultiline", "C1Entry", "--password-env", "NKEEPASS_TEST_PASSWORD"]
elif mode == "safe_null_ok":
    args = base_args + ["get", "SafeMultiline", "--format", "null", "--password-env", "NKEEPASS_TEST_PASSWORD"]
elif mode == "json_c1_safe":
    args = base_args + ["get", "C1Entry", "--format", "json", "--password-env", "NKEEPASS_TEST_PASSWORD"]
elif mode == "env_json_c1_safe":
    args = base_args + ["env", "-k", "C1Entry", "-F", "Password", "--name", "VAL", "--format", "json", "--password-env", "NKEEPASS_TEST_PASSWORD"]
else:
    raise SystemExit(2)

child = subprocess.Popen(args, stdout=slave, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
os.close(slave)
pty_bytes = bytearray()
deadline = time.monotonic() + 20
while True:
    remaining = deadline - time.monotonic()
    assert remaining > 0, "PTY deadline"
    assert select.select([master], [], [], remaining)[0], "PTY read timeout"
    try:
        chunk = os.read(master, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not chunk:
        break
    pty_bytes.extend(chunk)
_, stderr = child.communicate(timeout=20)
os.close(master)

if mode in ("raw_c1_refused", "null_esc_refused", "many_partial_refused"):
    assert child.returncode != 0, (mode, child.returncode)
    assert pty_bytes == b"", (mode, pty_bytes)
    assert b"SENTINEL" not in stderr, (mode, stderr)
    assert b"redirect stdout to a file or pipe" in stderr, (mode, stderr)
elif mode == "safe_null_ok":
    assert child.returncode == 0, (mode, stderr)
    # PTY ONLCR may translate \n to \r\n; assert the NUL delimiter itself is intact.
    assert b"\x00" in pty_bytes and b"safe\tline1" in pty_bytes and b"line2\x00" in pty_bytes, pty_bytes
elif mode in ("json_c1_safe", "env_json_c1_safe"):
    assert child.returncode == 0, (mode, stderr)
    assert b"\xc2\x9b" not in pty_bytes and b"\x7f" not in pty_bytes, pty_bytes
    assert b"\\u009b" in pty_bytes and b"\\u007f" in pty_bytes, pty_bytes
    decoded = json.loads(pty_bytes.decode("utf-8"))
    val = decoded["value"] if mode == "json_c1_safe" else decoded["VAL"]
    assert val == "c1-\u009b31m-\u007f-secret-SENTINEL", val
"#;

    for mode in [
        "raw_c1_refused",
        "null_esc_refused",
        "many_partial_refused",
        "safe_null_ok",
        "json_c1_safe",
        "env_json_c1_safe",
    ] {
        let status = Command::new("timeout")
            .args(["--kill-after=2s", "25s", "python3"])
            .args([
                "-c",
                PTY_DRIVER,
                env!("CARGO_BIN_EXE_nkp"),
                vault.to_str().unwrap(),
                mode,
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir.path())
            .env("NKP_CONFIG_DIR", dir.path().join("config"))
            .env("NKP_DATA_DIR", dir.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
            .env("TERM", "xterm")
            .stdin(Stdio::null())
            .status()
            .expect("run PTY driver");
        assert!(status.success(), "PTY mode {mode} failed");
    }
}

#[test]
fn powershell_output_neutralizes_unicode_curly_single_quotes() {
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("CurlyEntry");
    let payload = "a\u{2018}; Invoke-Expression calc;\u{2019}\u{201A}\u{201B}'b";
    entry.password = ProtectedValue::from_text(payload);
    database.add_entry(entry);

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("curly.kdbx");
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

    for format in ["pwsh", "powershell"] {
        let get_out = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args([
                "--vault",
                vault.to_str().unwrap(),
                "get",
                "CurlyEntry",
                "--name",
                "CURLY",
                "--format",
                format,
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ])
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8(success(&get_out).to_vec()).unwrap();
        assert_eq!(
            text,
            "$env:CURLY = ('a' + [char]0x2018 + '; Invoke-Expression calc;' + [char]0x2019 + '' + [char]0x201A + '' + [char]0x201B + '''b')\n"
        );
        for curly in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            assert!(
                !text.contains(curly),
                "raw curly quote U+{:04X} leaked into {format} output: {text}",
                u32::from(curly)
            );
        }
    }

    let env_out = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .isolate_application_environment()
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "secrets",
            "env",
            "--key",
            "CurlyEntry",
            "--field",
            "Password",
            "--name",
            "CURLY",
            "--format",
            "pwsh",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ])
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let env_text = String::from_utf8(success(&env_out).to_vec()).unwrap();
    assert_eq!(
        env_text,
        "$env:CURLY = ('a' + [char]0x2018 + '; Invoke-Expression calc;' + [char]0x2019 + '' + [char]0x201A + '' + [char]0x201B + '''b')\n"
    );
}

fn strip_sgr_bytes(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index..].starts_with(b"\x1b[") {
            index += 2;
            while index < input.len() && input[index] != b'm' {
                index += 1;
            }
            if index < input.len() {
                index += 1;
            }
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    output
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers all six human-format metadata routes together"
)]
fn human_format_works_across_all_six_metadata_routes_without_leaking_secrets() {
    let fixture = Fixture::new();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];
    let run_colored = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
        if !args.iter().any(|arg| *arg == "alias") {
            command.args(["--vault", fixture.vault.to_str().unwrap()]);
        }
        command
            .args(args)
            .env("XDG_CONFIG_HOME", fixture.directory.path().join("config"))
            .env("XDG_DATA_HOME", fixture.directory.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
            .env("TERM", "xterm")
            .env_remove("NO_COLOR")
            .env_remove("FORCE_COLOR")
            .env_remove("COLORTERM")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    // Set up an alias so `alias ls` has data in both JSON and human modes.
    let alias_set = run_colored(&["alias", "set", "mail", "LOGIN"]);
    success(&alias_set);

    let metadata_routes: Vec<Vec<&str>> = vec![
        vec!["ls", auth[0], auth[1]],
        vec!["secrets", "ls", auth[0], auth[1]],
        vec!["search", "LOGIN", auth[0], auth[1]],
        vec!["secrets", "search", "LOGIN", auth[0], auth[1]],
        vec!["show", "LOGIN", auth[0], auth[1]],
        vec!["secrets", "show", "LOGIN", auth[0], auth[1]],
        vec!["files", "ls", "LOGIN", auth[0], auth[1]],
        vec!["field", "ls", "LOGIN", auth[0], auth[1]],
        vec!["alias", "ls"],
    ];

    for base_args in &metadata_routes {
        // Default == explicit `--format json`, even under `--color=always`.
        let default_out = run_colored(base_args);
        let default_bytes = success(&default_out).to_vec();

        let mut json_args = vec!["--color=always"];
        json_args.extend(base_args.iter().copied());
        json_args.extend(["--format", "json"]);
        let json_out = run_colored(&json_args);
        assert_eq!(
            success(&json_out),
            default_bytes.as_slice(),
            "{base_args:?}"
        );
        assert!(!json_out.stdout.contains(&0x1b), "{base_args:?}");

        // `--format human` with `--color=never` vs `--color=always`.
        let mut human_plain_args = vec!["--color=never"];
        human_plain_args.extend(base_args.iter().copied());
        human_plain_args.extend(["--format", "human"]);
        let human_plain = run_colored(&human_plain_args);
        assert_markers_absent(&human_plain);
        let plain_bytes = success(&human_plain).to_vec();
        assert!(!plain_bytes.contains(&0x1b), "{base_args:?}");

        let mut human_color_args = vec!["--color=always"];
        human_color_args.extend(base_args.iter().copied());
        human_color_args.extend(["--format", "human"]);
        let human_color = run_colored(&human_color_args);
        assert_markers_absent(&human_color);
        let color_bytes = success(&human_color).to_vec();
        assert!(
            color_bytes.windows(2).any(|w| w == b"\x1b["),
            "expected SGR styling for {base_args:?}"
        );
        assert_eq!(
            strip_sgr_bytes(&color_bytes),
            plain_bytes,
            "color altered plain layout for {base_args:?}"
        );
    }

    let ls_human =
        String::from_utf8(run(&fixture, &["ls", "--format", "human", auth[0], auth[1]]).stdout)
            .unwrap();
    assert!(ls_human.contains("PATH") && ls_human.contains("LOGIN"));
    assert!(ls_human.contains("[otp]"));

    let search_human = String::from_utf8(
        run(
            &fixture,
            &["search", "LOGIN", "--format", "human", auth[0], auth[1]],
        )
        .stdout,
    )
    .unwrap();
    assert!(search_human.contains("PATH") && search_human.contains("LOGIN"));
    assert!(search_human.contains("[otp]"));

    let show_human = String::from_utf8(
        run(
            &fixture,
            &["show", "LOGIN", "--format", "human", auth[0], auth[1]],
        )
        .stdout,
    )
    .unwrap();
    assert!(show_human.contains("Entry: LOGIN"));
    assert!(show_human.contains("OTP: [otp] configured"));
    assert!(show_human.contains("[protected]"));
    assert!(show_human.contains("report.bin"));

    let files_human = String::from_utf8(
        run(
            &fixture,
            &[
                "files", "ls", "LOGIN", "--format", "human", auth[0], auth[1],
            ],
        )
        .stdout,
    )
    .unwrap();
    assert!(files_human.contains("NAME") && files_human.contains("report.bin"));
    assert!(files_human.contains("[protected]"));

    let field_human = String::from_utf8(
        run(
            &fixture,
            &[
                "field", "ls", "LOGIN", "--format", "human", auth[0], auth[1],
            ],
        )
        .stdout,
    )
    .unwrap();
    assert!(field_human.contains("NAME") && field_human.contains("Token"));
    assert!(field_human.contains("[protected]"));
    assert!(field_human.contains("[otp]"));

    let alias_human =
        String::from_utf8(run(&fixture, &["alias", "ls", "--format", "human"]).stdout).unwrap();
    assert!(alias_human.contains("NAME") && alias_human.contains("mail"));
    assert!(alias_human.contains("[entry]") && alias_human.contains("LOGIN"));

    // Empty states for search, files ls, and a clean alias store.
    let empty_search = String::from_utf8(
        success(&run(
            &fixture,
            &[
                "search",
                "no-such-match-xyz",
                "--format",
                "human",
                auth[0],
                auth[1],
            ],
        ))
        .to_vec(),
    )
    .unwrap();
    assert_eq!(empty_search, "(no matches)\n");

    let empty_files = String::from_utf8(
        success(&run(
            &fixture,
            &[
                "files",
                "ls",
                HOSTILE_TITLE,
                "--format",
                "human",
                auth[0],
                auth[1],
            ],
        ))
        .to_vec(),
    )
    .unwrap();
    assert_eq!(empty_files, "(no attachments)\n");
}

#[test]
fn human_format_sanitizes_bidi_and_truncates_wide_unicode_metadata() {
    let mut database = KeePassDatabase::default();
    let long_title = format!(
        "prefix\u{202E}SPOOF\u{2066}{}",
        "日本語の長いタイトル".repeat(12)
    );
    let mut entry = Entry::new(&long_title);
    entry.password = ProtectedValue::from_text("secret-value-never-shown");
    entry.tags = vec!["tag-\u{202E}bidi".to_owned(), "second".to_owned()];
    let long_field = format!("Custom\u{202E}Field_{}", "幅広文字".repeat(25));
    entry.set_field(Field {
        key: long_field.clone(),
        value: ProtectedValue::from_text("custom-secret-never-shown"),
        protected: true,
        protect_in_memory: true,
    });
    let reference = database.binary_pool.add(b"attachment-bytes".to_vec(), true);
    let long_attachment = format!("attach\u{202E}_{}.bin", "あいうえお".repeat(20));
    entry.attachments.push(Attachment {
        name: long_attachment,
        reference,
    });
    database.add_entry(entry);

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("unicode-human.kdbx");
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

    let run_vault = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .args(["--color=never", "--vault", vault.to_str().unwrap()])
            .args(args)
            .args(["--password-env", "NKEEPASS_TEST_PASSWORD"])
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    for args in [
        vec!["ls", "--format", "human"],
        vec!["search", "SPOOF", "--format", "human"],
        vec!["show", &long_title, "--format", "human"],
        vec!["files", "ls", &long_title, "--format", "human"],
        vec!["field", "ls", &long_title, "--format", "human"],
    ] {
        let output = run_vault(&args);
        let text = String::from_utf8(success(&output).to_vec()).unwrap();
        assert!(!text.contains("secret-value-never-shown"), "{args:?}");
        assert!(!text.contains("custom-secret-never-shown"), "{args:?}");
        for forbidden in ['\u{202E}', '\u{2066}', '\u{200E}', '\u{001B}', '\u{009B}'] {
            assert!(
                !text.contains(forbidden),
                "raw unsafe char U+{:04X} reached stdout in {args:?}: {text:?}",
                u32::from(forbidden)
            );
        }
        assert!(
            text.contains('…'),
            "expected truncation marker in {args:?}: {text}"
        );
        assert!(
            text.contains("\\u{202e}"),
            "expected escaped BiDi marker in {args:?}: {text}"
        );
    }
}

#[test]
fn human_format_is_rejected_on_secret_and_interchange_routes() {
    let fixture = Fixture::new();
    let template = fixture.directory.path().join("tmpl.txt");
    std::fs::write(&template, "KEY={{nkp://LOGIN#Password}}\n").unwrap();
    let export_dest = fixture.directory.path().join("export.json");
    let import_src = fixture.directory.path().join("import.json");
    std::fs::write(&import_src, "{}").unwrap();
    let auth = ["--password-env", "NKEEPASS_TEST_PASSWORD"];

    for args in [
        vec!["get", "LOGIN", "--format", "human", auth[0], auth[1]],
        vec![
            "get", "many", "LOGIN", "--format", "human", auth[0], auth[1],
        ],
        vec!["otp", "LOGIN", "--format", "human", auth[0], auth[1]],
        vec![
            "field", "get", "LOGIN", "Token", "--format", "human", auth[0], auth[1],
        ],
        vec![
            "env", "-k", "LOGIN", "-F", "Password", "-n", "PW", "--format", "human", auth[0],
            auth[1],
        ],
        vec![
            "secrets", "env", "-k", "LOGIN", "-F", "Password", "-n", "PW", "--format", "human",
            auth[0], auth[1],
        ],
        vec![
            "inject",
            "-f",
            template.to_str().unwrap(),
            "--format",
            "human",
            auth[0],
            auth[1],
        ],
        vec![
            "export",
            "-o",
            export_dest.to_str().unwrap(),
            "--format",
            "human",
            auth[0],
            auth[1],
        ],
        vec![
            "import",
            "-f",
            import_src.to_str().unwrap(),
            "--format",
            "human",
            auth[0],
            auth[1],
        ],
    ] {
        let output = run(&fixture, &args);
        assert!(
            !output.status.success(),
            "route unexpectedly accepted --format human: {args:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "rejected --format human wrote stdout: {args:?}"
        );
        assert_markers_absent(&output);
    }
    assert!(!export_dest.exists());
}

#[test]
fn broken_pipe_never_panics_on_help_version_completion_and_listings() {
    use std::io::Read;

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("pipe-test.kdbx");
    let mut database = KeePassDatabase::default();
    for index in 0..2_000 {
        database
            .root
            .add_entry(Entry::new(format!("entry-{index:04}")));
    }
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

    let cases: &[(&[&str], bool)] = &[
        (&["--help"], false),
        (&["version"], false),
        (&["--version"], false),
        (&["completion", "bash"], false),
        (&["shell", "init", "bash"], false),
        (&["shell", "completions", "bash"], false),
        (&["ls", "--password-env", "NKEEPASS_TEST_PASSWORD"], true),
        (
            &[
                "ls",
                "--format",
                "human",
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ],
            true,
        ),
    ];

    for (args, needs_vault) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
        command
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env("XDG_DATA_HOME", tmp.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD);
        if *needs_vault {
            command.args(["--vault", vault.to_str().unwrap()]);
        }
        command.args(*args);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Close read end immediately to trigger BrokenPipe on stdout writes.
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr_text.contains("panicked at")
                && !stderr_text.contains("Broken pipe")
                && !stderr_text.contains("RUST_BACKTRACE"),
            "broken pipe panicked for {args:?}: {stderr_text:?}"
        );
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr_text:?}");
        assert_eq!(
            output.stderr, b"nkp: cannot write output\n",
            "{args:?}: {stderr_text:?}"
        );
    }

    // Also close the pipe partway through a multi-line listing (>64 KiB pipe buffer).
    for args in [
        vec![
            "--vault",
            vault.to_str().unwrap(),
            "ls",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
        vec![
            "--vault",
            vault.to_str().unwrap(),
            "ls",
            "--format",
            "human",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nkp"))
            .isolate_application_environment()
            .env("XDG_CONFIG_HOME", tmp.path().join("config"))
            .env("XDG_DATA_HOME", tmp.path().join("data"))
            .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut prefix = [0_u8; 16];
        stdout.read_exact(&mut prefix).unwrap();
        drop(stdout);
        let output = child.wait_with_output().unwrap();
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr_text.contains("panicked at"),
            "{args:?}: {stderr_text:?}"
        );
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr_text:?}");
        assert_eq!(output.stderr, b"nkp: cannot write output\n");
    }
}
