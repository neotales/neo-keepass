#![cfg(unix)]

use std::process::{Command, Output};

#[allow(dead_code, clippy::unused_self)]
#[path = "support/cli_support.rs"]
mod cli_support;

fn nkp(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let directory = tempfile::tempdir().expect("isolated CLI profile");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nkp"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", directory.path())
        .env("NKP_CONFIG_DIR", directory.path().join("config"))
        .env("NKP_DATA_DIR", directory.path().join("data"))
        .stdin(std::process::Stdio::null())
        .args(args)
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR");
    command.env_remove("COLORTERM").env("TERM", "xterm");
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().expect("run nkp")
}

fn fixture_run(fixture: &cli_support::CliFixture, color: &str, args: &[&str]) -> Output {
    let mut command =
        cli_support::command(std::path::Path::new(env!("CARGO_BIN_EXE_nkp")), fixture);
    command
        .args(["--color", color, "--vault"])
        .arg(fixture.vault())
        .args(["--password-env", "NKP_TEST_MASTER"])
        .args(args)
        .env("NKP_TEST_MASTER", cli_support::MASTER_PASSWORD)
        .env("HOME", fixture.directory())
        .env("XDG_CONFIG_HOME", fixture.directory().join("config"))
        .env("XDG_DATA_HOME", fixture.directory().join("data"))
        .env("TERM", "xterm")
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("COLORTERM");
    if color == "truecolor" {
        command.env("COLORTERM", "truecolor");
    }
    command.output().expect("run fixture CLI")
}

#[test]
fn color_environment_and_explicit_options_only_style_human_help_and_diagnostics() {
    let auto = nkp(
        &["--color=auto", "--help"],
        &[("FORCE_COLOR", "3"), ("NO_COLOR", "1")],
    );
    assert!(auto.status.success());
    assert!(!auto.stdout.windows(2).any(|bytes| bytes == b"\x1b["));

    let no_color_wins = nkp(&["--help"], &[("FORCE_COLOR", "1"), ("NO_COLOR", "1")]);
    assert!(no_color_wins.status.success());
    assert!(
        !no_color_wins
            .stdout
            .windows(2)
            .any(|bytes| bytes == b"\x1b[")
    );

    let forced = nkp(&["--color=always", "--help"], &[("NO_COLOR", "1")]);
    assert!(forced.status.success());
    assert!(forced.stdout.windows(2).any(|bytes| bytes == b"\x1b["));

    let empty_no_color = nkp(&["--help"], &[("NO_COLOR", ""), ("FORCE_COLOR", "3")]);
    assert!(empty_no_color.status.success());
    assert!(
        empty_no_color
            .stdout
            .windows(2)
            .any(|bytes| bytes == b"\x1b[")
    );
    let forced_depth = nkp(&["--help"], &[("FORCE_COLOR", "3"), ("COLORTERM", "24bit")]);
    assert!(
        forced_depth
            .stdout
            .windows(b"\x1b[1;38;2;80;190;255m".len())
            .any(|bytes| bytes == b"\x1b[1;38;2;80;190;255m")
    );

    let force_off = nkp(&["--help"], &[("FORCE_COLOR", "0")]);
    assert!(force_off.status.success());
    assert!(!force_off.stdout.windows(2).any(|bytes| bytes == b"\x1b["));

    let basic = nkp(&["--color=basic", "--help"], &[]);
    let truecolor = nkp(
        &["--color=truecolor", "--help"],
        &[("COLORTERM", "truecolor")],
    );
    assert!(basic.stdout.windows(2).any(|bytes| bytes == b"\x1b["));
    assert!(truecolor.stdout.windows(2).any(|bytes| bytes == b"\x1b["));
    assert!(
        basic
            .stdout
            .windows(b"\x1b[1;36m".len())
            .any(|bytes| bytes == b"\x1b[1;36m")
    );
    assert!(
        truecolor
            .stdout
            .windows(b"\x1b[1;38;2;80;190;255m".len())
            .any(|bytes| bytes == b"\x1b[1;38;2;80;190;255m")
    );
    assert_eq!(strip_sgr(&basic.stdout), strip_sgr(&truecolor.stdout));

    let disabled = nkp(&["--no-color", "--help"], &[("FORCE_COLOR", "3")]);
    assert!(disabled.status.success());
    assert!(!disabled.stdout.windows(2).any(|bytes| bytes == b"\x1b["));

    let completion = nkp(&["--color=always", "completion", "bash"], &[]);
    let plain_completion = nkp(&["completion", "bash"], &[]);
    assert!(completion.status.success());
    assert_eq!(completion.stdout, plain_completion.stdout);
    assert!(!completion.stdout.windows(2).any(|bytes| bytes == b"\x1b["));

    let diagnostic = nkp(&["--color=always", "unknown-command"], &[]);
    assert!(!diagnostic.status.success());
    assert!(diagnostic.stderr.windows(2).any(|bytes| bytes == b"\x1b["));
    let completion_prefix = nkp(&["__complete", "entries", "--color=bogus"], &[]);
    assert!(!String::from_utf8_lossy(&completion_prefix.stderr).contains("invalid --color"));

    let help = nkp(
        &[
            "--color=always",
            "get",
            "--field",
            "Password",
            "many",
            "--help",
        ],
        &[],
    );
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&strip_sgr(&help.stdout)).contains("Usage: nkp get [PATH]"));
    let plain_help = nkp(
        &["--no-color", "get", "--field", "Password", "many", "--help"],
        &[],
    );
    assert_eq!(strip_sgr(&help.stdout), plain_help.stdout);
    let group_help = nkp(&["--color=never", "group", "add", "--help"], &[]);
    assert!(group_help.status.success());
    let synopsis = String::from_utf8_lossy(&group_help.stdout);
    assert!(synopsis.contains("Usage: nkp group add (PATH | --key PATH)"));
    assert!(!synopsis.contains("add [PATH]"));
}

fn strip_sgr(input: &[u8]) -> Vec<u8> {
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

#[cfg(target_os = "linux")]
#[test]
fn auto_styles_help_only_when_stdout_is_a_tty() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new("timeout")
        .args(["--kill-after=2s", "25s", "script"])
        .args([
            "-q",
            "-e",
            "-c",
            &format!("{} --color=auto --help", env!("CARGO_BIN_EXE_nkp")),
            "/dev/null",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", directory.path())
        .env("NKP_CONFIG_DIR", directory.path().join("config"))
        .env("NKP_DATA_DIR", directory.path().join("data"))
        .stdin(std::process::Stdio::null())
        .env("TERM", "xterm")
        .output()
        .expect("run nkp in a PTY");
    assert!(output.status.success());
    assert!(output.stdout.windows(2).any(|bytes| bytes == b"\x1b["));
}

#[cfg(target_os = "linux")]
#[test]
fn auto_evaluates_stdout_and_stderr_tty_independently() {
    const DRIVER: &str = r#"
import errno, os, pty, subprocess, sys, select, time
binary, stream = sys.argv[1:]
master, slave = pty.openpty()
if stream == "stdout":
    child = subprocess.Popen([binary, "--color=auto", "--help"], stdout=slave, stderr=subprocess.PIPE)
else:
    child = subprocess.Popen([binary, "--color=auto", "unknown-command"], stdout=subprocess.PIPE, stderr=slave)
os.close(slave)
terminal = bytearray()
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
    terminal.extend(chunk)
stdout, stderr = child.communicate(timeout=20)
os.close(master)
assert b"\x1b[" in terminal, (stream, terminal)
assert b";38;2;" in terminal, (stream, terminal)
other = stderr if stream == "stdout" else stdout
assert b"\x1b[" not in other, (stream, other)
"#;
    for stream in ["stdout", "stderr"] {
        let directory = tempfile::tempdir().unwrap();
        let status = Command::new("timeout")
            .args(["--kill-after=2s", "25s", "python3"])
            .args(["-c", DRIVER, env!("CARGO_BIN_EXE_nkp"), stream])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", directory.path())
            .env("NKP_CONFIG_DIR", directory.path().join("config"))
            .env("NKP_DATA_DIR", directory.path().join("data"))
            .stdin(std::process::Stdio::null())
            .env("TERM", "xterm")
            .env("COLORTERM", "truecolor")
            .status()
            .expect("run per-stream PTY driver");
        assert!(status.success(), "per-stream TTY check failed for {stream}");
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_no_color_is_still_a_disable_signal() {
    use std::os::unix::ffi::OsStringExt;

    let output = Command::new(env!("CARGO_BIN_EXE_nkp"))
        .arg("--help")
        .env("TERM", "xterm")
        .env("FORCE_COLOR", "3")
        .env("NO_COLOR", std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .expect("run with non-Unicode NO_COLOR");
    assert!(output.status.success());
    assert!(!output.stdout.windows(2).any(|bytes| bytes == b"\x1b["));
}

#[test]
fn forced_color_never_changes_data_or_file_bytes() {
    let fixture = cli_support::CliFixture::new(false);
    for (args, expected) in [
        (
            vec!["get", "fixture-login"],
            cli_support::ENTRY_PASSWORD.as_bytes().to_vec(),
        ),
        (
            vec!["get", "fixture-login", "--format", "null"],
            format!("{}\0", cli_support::ENTRY_PASSWORD).into_bytes(),
        ),
        (
            vec!["get", "fixture-login", "--format", "json"],
            format!("{{\"value\":\"{}\"}}\n", cli_support::ENTRY_PASSWORD).into_bytes(),
        ),
        (
            vec![
                "get",
                "fixture-login",
                "--format",
                "shell",
                "--name",
                "FIXTURE_PASSWORD",
            ],
            format!(
                "export FIXTURE_PASSWORD='{}';\n",
                cli_support::ENTRY_PASSWORD
            )
            .into_bytes(),
        ),
        (
            vec!["files", "ls", "fixture-login"],
            format!(
                "{{\"bytes\":{},\"name\":\"file.txt\",\"protected\":true}}\n",
                cli_support::ATTACHMENT.len()
            )
            .into_bytes(),
        ),
    ] {
        let plain = fixture_run(&fixture, "never", &args);
        let always = fixture_run(&fixture, "always", &args);
        let basic = fixture_run(&fixture, "basic", &args);
        let truecolor = fixture_run(&fixture, "truecolor", &args);
        for output in [&plain, &always, &basic, &truecolor] {
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, expected, "{args:?}");
            assert!(!output.stderr.contains(&0x1b), "{args:?}");
        }
        assert_eq!(plain.status, basic.status, "basic route {args:?}");
        assert_eq!(plain.status, truecolor.status, "truecolor route {args:?}");
        assert_eq!(plain.stdout, basic.stdout, "basic route {args:?}");
        assert_eq!(plain.stdout, truecolor.stdout, "truecolor route {args:?}");
        assert!(!plain.stdout.windows(2).any(|bytes| bytes == b"\x1b["));
    }
}

#[test]
fn forced_color_never_changes_attachment_file_bytes() {
    let fixture = cli_support::CliFixture::new(false);
    let plain_path = fixture.directory().join("attachment-plain.bin");
    let color_path = fixture.directory().join("attachment-color.bin");
    let plain = fixture_run(
        &fixture,
        "never",
        &[
            "files",
            "get",
            "fixture-login",
            "--field",
            "file.txt",
            "--output",
            plain_path.to_str().unwrap(),
        ],
    );
    let colored = fixture_run(
        &fixture,
        "truecolor",
        &[
            "files",
            "get",
            "fixture-login",
            "--field",
            "file.txt",
            "--output",
            color_path.to_str().unwrap(),
        ],
    );
    assert!(
        plain.status.success(),
        "plain attachment export failed: {}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(
        colored.status.success(),
        "colored attachment export failed: {}",
        String::from_utf8_lossy(&colored.stderr)
    );
    assert_eq!(plain.status, colored.status);
    assert_eq!(std::fs::read(plain_path).unwrap(), cli_support::ATTACHMENT);
    assert_eq!(std::fs::read(color_path).unwrap(), cli_support::ATTACHMENT);
    assert!(plain.stdout.is_empty() && colored.stdout.is_empty());
    for color in ["always", "basic"] {
        let path = fixture.directory().join(format!("attachment-{color}.bin"));
        let output = fixture_run(
            &fixture,
            color,
            &[
                "attachments",
                "export",
                "fixture-login",
                "--field",
                "file.txt",
                "--output",
                path.to_str().unwrap(),
            ],
        );
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(std::fs::read(path).unwrap(), cli_support::ATTACHMENT);
    }
}

#[test]
fn forced_color_never_changes_child_bytes_or_arguments() {
    let fixture = cli_support::CliFixture::new(false);
    let child_args = [
        "exec",
        "--key",
        "fixture-login",
        "--env",
        "FIXTURE_CHILD_VALUE",
        "--",
        "/bin/sh",
        "-c",
        "printf '%s' \"$FIXTURE_CHILD_VALUE\"",
    ];
    let plain = fixture_run(&fixture, "never", &child_args);
    let colored = fixture_run(&fixture, "truecolor", &child_args);
    assert!(plain.status.success() && colored.status.success());
    assert_eq!(plain.status, colored.status);
    assert_eq!(plain.stdout, colored.stdout);
    assert_eq!(plain.stdout, cli_support::ENTRY_PASSWORD.as_bytes());

    for literal in ["--no-color", "-k", "-F", "--color=always"] {
        let child_literal_args = [
            "exec",
            "--key",
            "fixture-login",
            "--env",
            "FIXTURE_CHILD_VALUE",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$1\"",
            "child",
            literal,
        ];
        for color in ["never", "always", "basic", "truecolor"] {
            let output = fixture_run(&fixture, color, &child_literal_args);
            assert!(output.status.success());
            assert_eq!(output.stdout, literal.as_bytes());
            assert_eq!(output.stderr, b"");
        }
    }
}

#[test]
fn machine_route_alias_errors_never_acquire_ansi() {
    let fixture = cli_support::CliFixture::new(false);
    for route in [
        vec!["__complete", "invalid"],
        vec!["completion", "invalid"],
        vec!["--version", "invalid"],
        vec!["show"],
        vec!["otp"],
        vec!["import"],
        vec!["sync"],
        vec!["get"],
        vec!["secrets", "show"],
        vec!["secrets", "otp"],
        vec!["secrets", "env"],
        vec!["secrets", "environment"],
        vec!["secrets", "import"],
        vec!["secrets", "sync"],
        vec!["automation", "import"],
        vec!["automation", "sync"],
    ] {
        for color in ["always", "basic", "truecolor"] {
            let output = fixture_run(&fixture, color, &route);
            assert!(!output.status.success(), "{route:?}");
            assert!(output.stdout.is_empty(), "{route:?}");
            assert!(
                !output.stderr.contains(&0x1b),
                "{route:?}: {:?}",
                output.stderr
            );
        }
    }
}

#[test]
fn successful_metadata_and_interchange_reports_are_color_invariant() {
    let fixture = cli_support::CliFixture::new(false);
    let snapshot = fixture.directory().join("snapshot.json");
    let export = fixture_run(
        &fixture,
        "always",
        &["export", "--output", snapshot.to_str().unwrap()],
    );
    assert!(export.status.success());
    assert!(!export.stdout.contains(&0x1b));
    serde_json::from_slice::<serde_json::Value>(&export.stdout).unwrap();
    // Sync deliberately refuses UUID collisions, including a self-export.
    // Use an independent source rather than comparing two identical failures.
    let source = cli_support::CliFixture::new(false);
    let sync_snapshot = source.directory().join("source.json");
    let source_export = fixture_run(
        &source,
        "never",
        &["export", "--output", sync_snapshot.to_str().unwrap()],
    );
    assert!(source_export.status.success());
    for args in [
        vec!["ls"],
        vec!["secrets", "list"],
        vec!["show", "fixture-login"],
        vec!["secrets", "show", "fixture-login"],
        vec![
            "import",
            "--file",
            snapshot.to_str().unwrap(),
            "--replace",
            "--dry-run",
        ],
        vec![
            "secrets",
            "import",
            "--file",
            snapshot.to_str().unwrap(),
            "--replace",
            "--dry-run",
        ],
        vec![
            "automation",
            "import",
            "--file",
            snapshot.to_str().unwrap(),
            "--replace",
            "--dry-run",
        ],
        vec![
            "sync",
            "--file",
            sync_snapshot.to_str().unwrap(),
            "--dry-run",
        ],
        vec![
            "secrets",
            "sync",
            "--file",
            sync_snapshot.to_str().unwrap(),
            "--dry-run",
        ],
        vec![
            "automation",
            "sync",
            "--file",
            sync_snapshot.to_str().unwrap(),
            "--dry-run",
        ],
    ] {
        let plain = fixture_run(&fixture, "never", &args);
        assert!(plain.status.success(), "{args:?}: {:?}", plain.stderr);
        assert!(plain.stdout.ends_with(b"\n"));
        // Exactly one JSON/NDJSON record, not an error or an empty listing.
        serde_json::from_slice::<serde_json::Value>(&plain.stdout).unwrap();
        for color in ["always", "basic", "truecolor"] {
            let output = fixture_run(&fixture, color, &args);
            assert!(output.status.success(), "{args:?}: {:?}", output.stderr);
            assert_eq!(output.stdout, plain.stdout, "{args:?}");
            assert!(!output.stdout.contains(&0x1b));
            assert!(!output.stderr.contains(&0x1b));
        }
    }
}

#[test]
fn exec_missing_values_cannot_consume_separator_or_child_options() {
    for flag in [
        "--key",
        "--env",
        "--field",
        "--password-env",
        "--password-file",
        "--key-file",
    ] {
        let output = nkp(
            &[
                "--color=always",
                "x",
                "--key",
                "fixture-login",
                "--env",
                "FIXTURE_CHILD_VALUE",
                flag,
                "--",
                "/bin/echo",
                "-k",
            ],
            &[],
        );
        assert!(!output.status.success(), "{flag}");
        assert!(output.stdout.is_empty(), "{flag}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("missing argument"),
            "{flag}: {:?}",
            output.stderr
        );
    }
}
