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
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, getpgid, getsid, kill_process_group, test_kill_process,
    test_kill_process_group, waitid,
};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum DriverEvent {
    SessionVerified,
    SpawnPermitted,
    AppSpawnAttempted,
    StartupPaused,
    LeaderExitedBeforeGroupKill,
    ResistantAppOutlivedLeader,
    GroupKillAttempted,
    LeaderReaped,
    CleanupComplete,
}

struct DriverRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    capture_overflow: bool,
    events: Vec<DriverEvent>,
}

impl DriverRun {
    fn observed(&self, event: DriverEvent) -> bool {
        self.events.contains(&event)
    }
}

fn wait_until(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn exited_unreaped(child: &Child) -> rustix::io::Result<bool> {
    // rustix supports Darwin waitid/WNOWAIT (nix's waitid API does not).
    waitid(
        WaitId::Pid(Pid::from_child(child)),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map(|status| status.is_some())
}

struct OwnedDriver {
    child: Child,
    session_verified: bool,
    reaped: bool,
}

impl Drop for OwnedDriver {
    fn drop(&mut self) {
        // Panic/error cleanup also honors the ownership pin. An ECHILD error
        // means ownership is lost: do not signal a potentially reused ID.
        if !self.reaped && exited_unreaped(&self.child).is_ok() {
            if self.session_verified {
                let _ = kill_process_group(Pid::from_child(&self.child), Signal::KILL);
            }
            let _ = self.child.kill();
            let _ = wait_until(&mut self.child, Instant::now() + Duration::from_secs(2));
        }
    }
}

fn signal_pinned_group(driver: &OwnedDriver, signal: Signal) {
    assert!(driver.session_verified && !driver.reaped);
    // Recheck waitability WITHOUT reaping before every terminating signal.
    exited_unreaped(&driver.child).expect("driver ownership pin was lost");
    let result = kill_process_group(Pid::from_child(&driver.child), signal);
    // Darwin can report EPERM for a zombie-only group. This is not taken as
    // absence: after the final kill/reap we separately require ESRCH.
    assert!(matches!(
        result,
        Ok(()) | Err(rustix::io::Errno::SRCH | rustix::io::Errno::PERM)
    ));
}

fn finish_driver(
    driver: &mut OwnedDriver,
    timed_out: bool,
    resistant_app: Option<Pid>,
) -> (ExitStatus, Vec<DriverEvent>) {
    let mut events = Vec::new();
    let pid = Pid::from_child(&driver.child);
    if driver.session_verified && timed_out {
        signal_pinned_group(driver, Signal::TERM);
        signal_pinned_group(driver, Signal::CONT);
        let grace = Instant::now() + Duration::from_secs(1);
        while !exited_unreaped(&driver.child).unwrap() && Instant::now() < grace {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let exited_before_kill = exited_unreaped(&driver.child).unwrap();
    let resistant_outlived =
        exited_before_kill && resistant_app.is_some_and(|app| test_kill_process(app).is_ok());
    if exited_before_kill {
        events.push(DriverEvent::LeaderExitedBeforeGroupKill);
    }
    if resistant_outlived {
        events.push(DriverEvent::ResistantAppOutlivedLeader);
    }
    if driver.session_verified {
        // Required even if TERM already exited the leader: the unreaped PID
        // pins this exact verified group until its remaining members are killed.
        signal_pinned_group(driver, Signal::KILL);
        events.push(DriverEvent::GroupKillAttempted);
    } else {
        // No permit was issued, so no app can race this direct-child-only kill,
        // even if the driver establishes a session concurrently with timeout.
        let _ = driver.child.kill();
    }
    let status = wait_until(&mut driver.child, Instant::now() + Duration::from_secs(2))
        .unwrap()
        .expect("driver cleanup/reap deadline exceeded");
    driver.reaped = true;
    events.push(DriverEvent::LeaderReaped);
    let absence_deadline = Instant::now() + Duration::from_secs(2);
    let mut absent = !driver.session_verified;
    while !absent && Instant::now() < absence_deadline {
        absent = test_kill_process_group(pid) == Err(rustix::io::Errno::SRCH);
        if !absent {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // Observation only after reap: never send a terminating signal here.
    if absent {
        events.push(DriverEvent::CleanupComplete);
    }
    (status, events)
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
    let protocol = tempfile::tempdir_in(directory).unwrap();
    let child = Command::new("python3")
        .isolate_application_environment()
        .args(["-c", include_str!("support/tui_ui_pty.py")])
        .arg(env!("CARGO_BIN_EXE_nkp"))
        .arg(path)
        .arg(case)
        .arg(protocol.path())
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
    let mut driver = OwnedDriver {
        child,
        session_verified: false,
        reaped: false,
    };
    let deadline = Instant::now() + budget;
    let mut events = Vec::new();
    let timed_out = loop {
        if exited_unreaped(&driver.child).unwrap() {
            break false;
        }
        if Instant::now() >= deadline {
            break true;
        }
        let ready = protocol.path().join("ready");
        if !driver.session_verified && ready.exists() {
            let pid = Pid::from_child(&driver.child);
            assert_eq!(
                std::fs::read_to_string(ready).unwrap(),
                driver.child.id().to_string()
            );
            assert_eq!(getsid(Some(pid)), Ok(pid));
            assert_eq!(getpgid(Some(pid)), Ok(pid));
            // Set this BEFORE publishing the permit: after this point every
            // exit/error path performs pinned group cleanup, never driver-only.
            driver.session_verified = true;
            events.push(DriverEvent::SessionVerified);
            if case != "startup-after-session" {
                std::fs::write(
                    protocol.path().join("permit.tmp"),
                    driver.child.id().to_string(),
                )
                .unwrap();
                std::fs::rename(
                    protocol.path().join("permit.tmp"),
                    protocol.path().join("permit"),
                )
                .unwrap();
                events.push(DriverEvent::SpawnPermitted);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let resistant_app = (case == "term-resistant-app").then(|| {
        let pid: i32 = std::fs::read_to_string(directory.join("stopped-child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        Pid::from_raw(pid).unwrap()
    });
    if protocol.path().join("startup-paused").exists() {
        events.push(DriverEvent::StartupPaused);
    }
    if protocol.path().join("app-spawn-attempt").exists() {
        events.push(DriverEvent::AppSpawnAttempted);
    }
    let (status, cleanup_events) = finish_driver(&mut driver, timed_out, resistant_app);
    events.extend(cleanup_events);
    let (stdout, stdout_overflow) = capture(&mut stdout);
    let (stderr, stderr_overflow) = capture(&mut stderr);
    DriverRun {
        status,
        stdout,
        stderr,
        timed_out,
        capture_overflow: stdout_overflow || stderr_overflow,
        events,
    }
}

fn drive(directory: &Path, path: &Path, case: &str) {
    let output = run_driver(directory, path, case);
    assert!(
        !output.timed_out
            && !output.capture_overflow
            && output.observed(DriverEvent::CleanupComplete)
            && output.status.success(),
        "TUI UI PTY checks failed (timeout={}, capture_overflow={}, cleanup_complete={}): {}",
        output.timed_out,
        output.capture_overflow,
        output.observed(DriverEvent::CleanupComplete),
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

fn bystander() -> Bystander {
    Bystander(
        Command::new("python3")
            .isolate_application_environment()
            .args(["-c", "import time; time.sleep(60)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

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
    let mut bystander = bystander();
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
            test_kill_process(Pid::from_raw(pid).unwrap()),
            Err(rustix::io::Errno::SRCH)
        );
        assert!(
            bystander.0.try_wait().unwrap().is_none(),
            "cleanup harmed unrelated bystander"
        );
        assert!(!output.status.success());
        assert!(!output.capture_overflow);
        assert!(output.observed(DriverEvent::CleanupComplete));
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
fn startup_permission_and_unreaped_leader_close_watchdog_cleanup_races() {
    let mut bystander = bystander();
    for case in [
        "startup-before-session",
        "startup-after-session",
        "term-resistant-app",
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
            started.elapsed() < Duration::from_secs(10),
            "cleanup exceeded bounded allowance"
        );
        assert!(output.timed_out);
        assert!(!output.status.success());
        assert!(output.observed(DriverEvent::CleanupComplete));
        assert!(
            bystander.0.try_wait().unwrap().is_none(),
            "cleanup harmed bystander"
        );
        if case.starts_with("startup-") {
            assert!(output.observed(DriverEvent::StartupPaused));
            assert!(!output.observed(DriverEvent::SpawnPermitted));
            assert!(!output.observed(DriverEvent::AppSpawnAttempted));
            assert_eq!(
                output.observed(DriverEvent::SessionVerified),
                case == "startup-after-session"
            );
            assert_eq!(
                output.observed(DriverEvent::GroupKillAttempted),
                case == "startup-after-session"
            );
            assert!(!directory.path().join("stopped-child.pid").exists());
        } else {
            assert!(output.observed(DriverEvent::SessionVerified));
            assert!(output.observed(DriverEvent::SpawnPermitted));
            assert!(output.observed(DriverEvent::AppSpawnAttempted));
            // Actual observation before group KILL: the leader has exited,
            // yet its TERM/HUP-resistant app still exists. Reap must wait.
            assert!(output.observed(DriverEvent::LeaderExitedBeforeGroupKill));
            assert!(output.observed(DriverEvent::ResistantAppOutlivedLeader));
            let killed = output
                .events
                .iter()
                .position(|event| *event == DriverEvent::GroupKillAttempted)
                .unwrap();
            let reaped = output
                .events
                .iter()
                .position(|event| *event == DriverEvent::LeaderReaped)
                .unwrap();
            assert!(
                killed < reaped,
                "verified group must be killed before leader reap"
            );
            let pid: i32 = std::fs::read_to_string(directory.path().join("stopped-child.pid"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                test_kill_process(Pid::from_raw(pid).unwrap()),
                Err(rustix::io::Errno::SRCH)
            );
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
