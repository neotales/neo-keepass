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
    Attachment, Entry, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions,
    KeePassDatabase, ProtectedValue,
};
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.kdbx");
    let mut database = KeePassDatabase::default();
    let mut entry = Entry::new("Example");
    entry.password = ProtectedValue::from_text("disposable-reveal-marker");
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

fn drive(directory: &Path, path: &Path, case: &str) {
    let output = Command::new("python3")
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
        .output()
        .expect("python3 is required for Unix TUI PTY tests");
    assert!(
        output.status.success(),
        "TUI UI PTY checks failed: {}",
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
