//! Disposable PTY coverage of UI behavior, not terminal admission or signal safety.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "disposable fixture setup"
)]

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;
use neotales_keepass::{
    Attachment, Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid, getsid};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct DriverRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    capture_overflow: bool,
}

fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("owned child status must be readable")
        {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop_owned_driver(child: &mut Child) -> ExitStatus {
    // The caller has NOT reaped this child. Its PID pins any verified session
    // and group ID through signaling; never signal a cached/reaped PID/group.
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
    let owns_session = getsid(Some(pid)) == Ok(pid) && getpgid(Some(pid)) == Ok(pid);
    if owns_session {
        // Let a stopped driver run its finally block and reap its own child.
        // TERM precedes CONT so a stopped app cannot resume normal execution.
        let _ = killpg(pid, Signal::SIGTERM);
        let _ = killpg(pid, Signal::SIGCONT);
        if let Some(status) = wait_until(child, Instant::now() + Duration::from_secs(1)) {
            return status; // Already reaped: no further signaling is allowed.
        }
        let _ = killpg(pid, Signal::SIGKILL);
    }
    // Before session setup there cannot be an app child. Never target the
    // inherited process group (which could include the Rust test runner).
    let _ = child.kill();
    wait_until(child, Instant::now() + Duration::from_secs(2))
        .expect("owned driver did not terminate within cleanup deadline")
}

fn capture(file: &mut std::fs::File) -> (Vec<u8>, bool) {
    const LIMIT: u64 = 64 * 1024;
    let overflow = file.metadata().unwrap().len() > LIMIT;
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.take(LIMIT).read_to_end(&mut bytes).unwrap();
    (bytes, overflow)
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.kdbx");
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("Example");
    entry.username = "disposable-user".into();
    entry.url = "https://example.invalid".into();
    entry.notes = "disposable-notes".into();
    entry.password = ProtectedValue::from_text("disposable-reveal-marker");
    for (suffix, value) in [
        ("FIRST-FIELD", "first-field-marker"),
        ("SECOND-FIELD", "second-field-marker"),
    ] {
        let mut field = Field::new(format!("{}{suffix}", "shared-field-".repeat(40)), value);
        field.protected = true;
        entry.fields.push(field);
    }
    for (suffix, bytes) in [("FIRST.bin", b"first"), ("SECOND.bin", b"other")] {
        let reference = database.binary_pool.add(bytes.to_vec(), true);
        entry.attachments.push(Attachment {
            name: format!("{}{suffix}", "shared-name-".repeat(16)),
            reference,
        });
    }
    database.add_entry(entry);
    database.add_entry(Entry::new(format!("{}TAIL", "entry-".repeat(40))));
    KdbxFile::save(
        &database,
        std::fs::File::create(&path).unwrap(),
        &mut KdbxCredentials::password("disposable-tui-fixture").unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
    (directory, path)
}

fn run_driver(directory: &Path, path: &Path, case: &str) -> DriverRun {
    run_driver_bounded(directory, path, case, Duration::from_secs(45))
}

fn run_driver_bounded(directory: &Path, path: &Path, case: &str, budget: Duration) -> DriverRun {
    // Regular files avoid an unbounded pipe drain even if a descendant keeps
    // an inherited output descriptor open. Retention is separately capped.
    let mut stdout = tempfile::tempfile_in(directory).unwrap();
    let mut stderr = tempfile::tempfile_in(directory).unwrap();
    let mut child = Command::new("python3")
        .isolate_application_environment()
        .args(["-c", include_str!("support/tui_ui_pty.py")])
        .arg(env!("CARGO_BIN_EXE_nkp"))
        .arg(path)
        .arg(case)
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .env("XDG_DATA_HOME", directory.join("data"))
        // No real clipboard/display access, even if a key-routing bug occurs.
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .spawn()
        .expect("python3 is required for Unix TUI PTY tests");
    let status = wait_until(&mut child, Instant::now() + budget);
    let timed_out = status.is_none();
    let status = status.unwrap_or_else(|| stop_owned_driver(&mut child));
    let (stdout, stdout_overflow) = capture(&mut stdout);
    let (stderr, stderr_overflow) = capture(&mut stderr);
    DriverRun {
        status,
        stdout,
        stderr,
        timed_out,
        capture_overflow: stdout_overflow || stderr_overflow,
    }
}

fn drive(directory: &Path, path: &Path, case: &str) {
    let output = run_driver(directory, path, case);
    assert!(
        !output.timed_out && !output.capture_overflow && output.status.success(),
        "TUI UI PTY checks failed (timeout={}, capture_overflow={}): {}",
        output.timed_out,
        output.capture_overflow,
        String::from_utf8_lossy(&output.stderr)
    );
    // Assert only on the predicate, never expose captured data on failure.
    let no_output = output.stdout.is_empty();
    assert!(no_output, "unexpected PTY driver output");
}

fn assert_unchanged(path: &Path, before: &[u8]) {
    let unchanged = std::fs::read(path).unwrap() == before;
    assert!(unchanged, "UI unexpectedly persisted changes");
}

struct Bystander(Child);

impl Drop for Bystander {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = wait_until(&mut self.0, Instant::now() + Duration::from_secs(2));
        }
    }
}

#[test]
fn stopped_pty_reader_and_driver_fail_bounded_without_harming_bystander() {
    let mut bystander = Bystander(
        Command::new("python3")
            .isolate_application_environment()
            .args(["-c", "import time; time.sleep(60)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for case in [
        "stopped-key-writes",
        "stopped-cursor-writes",
        "stopped-driver",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let output = run_driver_bounded(
            directory.path(),
            &directory.path().join("unused.kdbx"),
            case,
            Duration::from_secs(3),
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "watchdog exceeded cleanup budget"
        );
        let pid: i32 = std::fs::read_to_string(directory.path().join("stopped-child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        // Signal 0 observes absence only. Never send a terminating signal to a
        // reaped PID (which could have been reused by an unrelated process).
        assert_eq!(
            nix::sys::signal::kill(Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
        assert!(
            bystander.0.try_wait().unwrap().is_none(),
            "cleanup harmed unrelated bystander"
        );
        assert!(!output.status.success());
        assert!(!output.capture_overflow);
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        if case == "stopped-driver" {
            assert!(output.timed_out);
            assert!(diagnostic.contains("PTY driver watchdog termination"));
        } else {
            assert!(
                !output.timed_out,
                "PTY write blocked until the outer watchdog"
            );
            assert!(diagnostic.contains("PTY write deadline exceeded"));
        }
    }
}

#[test]
fn pty_driver_retains_terminal_lifetime_and_rejects_unrestored_attributes() {
    let directory = tempfile::tempdir().unwrap();
    let unused = directory.path().join("unused.kdbx");
    drive(directory.path(), &unused, "terminal-lifetime");
    let output = run_driver(directory.path(), &unused, "terminal-lifetime-unrestored");
    assert!(!output.status.success(), "unrestored terminal was accepted");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("terminal attributes not restored (changed: lflag)"));
    let no_output = output.stdout.is_empty();
    assert!(no_output, "unexpected PTY driver output");
    let output = run_driver(directory.path(), &unused, "terminal-lifetime-ioctl-error");
    assert!(
        !output.status.success(),
        "invalid terminal descriptor was accepted"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("PTY terminal operation failed: read restored attributes / errno=")
    );
    assert!(!diagnostic.contains("Traceback"));
    let no_output = output.stdout.is_empty();
    assert!(no_output, "unexpected PTY driver output");
}

#[test]
fn long_colliding_field_names_are_inspectable_before_reveal_consent() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "long-field-targets");
    assert_unchanged(&path, &before);
}

#[test]
fn compact_field_navigation_identifies_the_target_before_consent() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "field-identity");
    assert_unchanged(&path, &before);
}

#[test]
fn reveal_owns_focus_and_one_escape_hides_it_after_help_key() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "reveal");
    assert_unchanged(&path, &before);
}

#[test]
fn generation_confirmation_and_cancellation_reach_the_event_loop() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "generation-cancel");
    assert_unchanged(&path, &before);
    drive(directory.path(), &path, "generation-confirm");
    let mut service = nkeepass::VaultService::default();
    let session = service
        .open(
            &path,
            &mut KdbxCredentials::password("disposable-tui-fixture").unwrap(),
            &nkeepass::KDBX_LIMITS,
        )
        .unwrap();
    let page = service.list_page(session, None, None).unwrap();
    let bytes = service
        .reveal_field(&page.hits[0].reference(), "Password")
        .unwrap();
    assert_eq!(bytes.len(), 32);
    assert!(bytes.as_slice() != b"disposable-reveal-marker");
}

#[test]
fn colliding_target_suffixes_are_inspectable_before_export_and_delete() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "targets");
    assert_unchanged(&path, &before);
    let selected_bytes_match =
        std::fs::read(directory.path().join("selected.bin")).unwrap() == b"other";
    assert!(
        selected_bytes_match,
        "export did not match the inspected target"
    );
}

#[test]
fn attachment_removal_confirmation_removes_only_the_selected_target() {
    let (directory, path) = fixture();
    drive(directory.path(), &path, "remove-confirm");
    let mut service = nkeepass::VaultService::default();
    let session = service
        .open(
            &path,
            &mut KdbxCredentials::password("disposable-tui-fixture").unwrap(),
            &nkeepass::KDBX_LIMITS,
        )
        .unwrap();
    let page = service.list_page(session, None, None).unwrap();
    let attachments = service
        .attachment_metadata(&page.hits[0].reference())
        .unwrap();
    assert_eq!(attachments.len(), 1);
    assert!(attachments[0].name().ends_with("FIRST.bin"));
}

#[test]
fn failed_save_keeps_the_unsaved_decision_actionable() {
    let (directory, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    drive(directory.path(), &path, "save-failure");
    assert_unchanged(&path, &before);
}
