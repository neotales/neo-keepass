//! Owner-only permissions for files that may contain secrets.
//!
//! Unix permissions are restricted directly. Windows staging files are
//! created with a protected user-only DACL, then verified before use.
//! As on Unix, callers must not use a parent directory controlled by an
//! adversary who can replace paths during staging or publication.

use std::path::Path;

/// Restricts a still-empty Unix file or a Windows directory to its owner.
///
/// On Windows this operation is only supported for directories; private files
/// must instead be created with [`new_private_temp`].
///
/// # Errors
///
/// Returns the caller's diagnostic when the platform permission update fails.
pub fn set_owner_only(path: &Path, error: &'static str) -> Result<(), &'static str> {
    set_owner_only_platform(path, error)
}

/// Creates a private empty staging file in `parent`.
///
/// On Windows the DACL is applied at creation and verified before returning.
/// The containing directory must not be controlled by an adversary.
///
/// # Errors
///
/// Returns an I/O error if staging or permission verification fails.
pub fn new_private_temp(parent: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    #[cfg(windows)]
    {
        tempfile::Builder::new().make_in(parent, windows_private_file::create_new)
    }
    #[cfg(not(windows))]
    {
        let file = tempfile::NamedTempFile::new_in(parent)?;
        set_owner_only(file.path(), "cannot restrict temporary file")
            .map_err(std::io::Error::other)?;
        Ok(file)
    }
}

/// Writes sensitive bytes to a new owner-only file without replacing a target.
/// The empty staging inode is restricted before any bytes are written.
///
/// # Errors
///
/// Returns a fixed diagnostic if staging, permission restriction, writing,
/// syncing, or no-clobber installation fails.
pub fn write_private_noclobber(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    write_private_noclobber_with(path, bytes, sync_parent_directory)
}

fn write_private_noclobber_with(
    path: &Path,
    bytes: &[u8],
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), &'static str> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = new_private_temp(parent).map_err(|error| {
        if error.kind() == std::io::ErrorKind::Unsupported {
            "filesystem cannot verify persistent owner-only ACL support"
        } else if error.kind() == std::io::ErrorKind::PermissionDenied {
            "cannot restrict output permissions"
        } else {
            "cannot stage output"
        }
    })?;
    staging
        .write_all(bytes)
        .map_err(|_| "cannot write output")?;
    staging
        .as_file()
        .sync_all()
        .map_err(|_| "cannot sync output")?;
    staging.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            "output exists"
        } else {
            "cannot install output"
        }
    })?;
    sync_parent(parent).map_err(|_| "output installed but directory durability is unconfirmed")?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_platform(path: &Path, error: &'static str) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| error)
}

#[cfg(windows)]
fn set_owner_only_platform(path: &Path, error: &'static str) -> Result<(), &'static str> {
    windows_private_file::secure_directory(path).map_err(|cause| {
        if cause.kind() == std::io::ErrorKind::Unsupported {
            "filesystem cannot verify persistent owner-only ACL support"
        } else {
            error
        }
    })
}

#[cfg(any(windows, test))]
const MAX_WHOAMI_OUTPUT_BYTES: usize = 1024;

#[cfg(windows)]
const CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(windows, test))]
fn wait_for_child(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                terminate_and_reap(child)?;
                return Err(error);
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            // Reap the child before returning so a timeout leaves no live
            // process behind.
            terminate_and_reap(child)?;
            return Ok(None);
        }
        std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(10)));
    }
}

#[cfg(any(windows, test))]
fn terminate_and_reap(child: &mut std::process::Child) -> std::io::Result<()> {
    // `kill` reports an error when the process has already exited on some
    // platforms. Check first, and check again after a failed kill so that
    // this normal race is not reported as a cleanup failure.
    let mut last_error = match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => None,
        Err(error) => Some(error),
    };
    if let Err(error) = child.kill() {
        last_error = Some(error);
    }

    // Never call `wait` here: if termination failed, `wait` could block
    // forever. Retry briefly to handle transient platform/process races, but
    // keep cleanup bounded even if the OS refuses to terminate the process.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        if std::time::Instant::now() >= deadline {
            return Err(last_error.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "child process remained alive after termination",
                )
            }));
        }
        if let Err(error) = child.kill() {
            // A failed retry may indicate that the process exited between
            // `try_wait` and `kill`; the next iteration checks that race.
            last_error = Some(error);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(any(windows, test))]
fn join_reader_if_finished(reader: std::thread::JoinHandle<()>) {
    if reader.is_finished() {
        let _ = reader.join();
    } else {
        // Dropping a JoinHandle detaches the reader. In particular, a
        // descendant may still hold stdout open after the direct child exits.
        drop(reader);
    }
}

#[cfg(any(windows, test))]
fn bounded_command_output(
    command: &mut std::process::Command,
    max_bytes: usize,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    use std::io::Read;

    // A reader thread retains at most max_bytes + 1 bytes. It stops as soon as
    // it observes the extra byte, allowing the parent to kill a child that
    // otherwise could fill a temporary file or block forever on a pipe.
    let (output_sender, output_receiver) = std::sync::mpsc::sync_channel(1);
    let mut child = command.stdout(std::process::Stdio::piped()).spawn().ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let Some(read_limit) = max_bytes.checked_add(1) else {
            let _ = output_sender.send(None);
            return;
        };
        let mut bytes = Vec::with_capacity(read_limit);
        let result = stdout
            .take(read_limit as u64)
            .read_to_end(&mut bytes)
            .ok()
            .filter(|_| bytes.len() <= max_bytes)
            .map(|_| bytes);
        let _ = output_sender.send(result);
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut captured = None;
    let status = loop {
        match output_receiver.try_recv() {
            Ok(Some(output)) => captured = Some(output),
            Ok(None) => {
                let _ = terminate_and_reap(&mut child);
                join_reader_if_finished(reader);
                return None;
            }
            Err(
                std::sync::mpsc::TryRecvError::Empty | std::sync::mpsc::TryRecvError::Disconnected,
            ) => {}
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                let _ = terminate_and_reap(&mut child);
                join_reader_if_finished(reader);
                return None;
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            let _ = terminate_and_reap(&mut child);
            // Killing the direct child closes its pipe writer. Do not wait
            // indefinitely for EOF from a descendant that inherited stdout.
            match output_receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    join_reader_if_finished(reader);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // A descendant may still own the pipe writer. The reader
                    // cannot be synchronously canceled with std, so dropping
                    // its handle keeps this timeout path bounded.
                    drop(reader);
                }
            }
            return None;
        }
        std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(10)));
    };
    if !status.success() {
        join_reader_if_finished(reader);
        return None;
    }
    let output = if let Some(output) = captured {
        output
    } else {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        output_receiver.recv_timeout(remaining).ok()??
    };
    join_reader_if_finished(reader);
    (output.len() <= max_bytes).then_some(output)
}

#[cfg(any(windows, test))]
fn run_command_with_timeout(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let mut child = command.spawn().ok()?;
    wait_for_child(&mut child, timeout).ok()?
}

#[cfg(windows)]
fn whoami_command(executable: &Path, system_root: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(executable);
    command
        .env_clear()
        .env("SystemRoot", system_root)
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

#[cfg(any(windows, test))]
fn windows_tool_paths(
    system_directory: &Path,
) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    if !system_directory.is_absolute() {
        return None;
    }
    let system_root = system_directory.parent()?.to_path_buf();
    Some((
        system_root,
        system_directory.join("whoami.exe"),
        system_directory.join("icacls.exe"),
    ))
}

#[cfg(any(windows, test))]
fn windows_sid_from_whoami_csv(output: &str) -> Option<String> {
    if output.len() > MAX_WHOAMI_OUTPUT_BYTES {
        return None;
    }
    let record = output.strip_suffix("\r\n").unwrap_or(output);
    if record.contains('\r') || record.contains('\n') {
        return None;
    }
    let bytes = record.as_bytes();
    let mut position = 0;
    let account = parse_whoami_csv_field(bytes, &mut position)?;
    if account.is_empty() || bytes.get(position) != Some(&b',') {
        return None;
    }
    position += 1;
    let sid = parse_whoami_csv_field(bytes, &mut position)?;
    if position != bytes.len() || !is_windows_sid(&sid) {
        return None;
    }
    Some(sid)
}

#[cfg(any(windows, test))]
fn parse_whoami_csv_field(bytes: &[u8], position: &mut usize) -> Option<String> {
    if bytes.get(*position) != Some(&b'"') {
        return None;
    }
    *position += 1;
    let mut field = Vec::new();
    loop {
        match bytes.get(*position) {
            Some(b'"') if bytes.get(*position + 1) == Some(&b'"') => {
                if field.len() >= 512 {
                    return None;
                }
                field.push(b'"');
                *position += 2;
            }
            Some(b'"') => {
                *position += 1;
                return String::from_utf8(field).ok();
            }
            Some(byte) => {
                if field.len() >= 512 {
                    return None;
                }
                field.push(*byte);
                *position += 1;
            }
            None => return None,
        }
    }
}

#[cfg(any(windows, test))]
fn is_windows_sid(candidate: &str) -> bool {
    // A SID has at most 15 32-bit subauthorities; its textual form is bounded
    // as well. Reject oversized utility output before retaining it as a grant.
    if candidate.len() > 184 {
        return false;
    }
    let Some(subauthorities) = candidate.strip_prefix("S-1-") else {
        return false;
    };
    let mut parts = subauthorities.split('-');
    let Some(authority) = parts.next() else {
        return false;
    };
    if authority.is_empty() || !authority.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(authority) = authority.parse::<u64>() else {
        return false;
    };
    if authority > 0x0000_ffff_ffff_ffff {
        return false;
    }
    let parts: Vec<_> = parts.collect();
    !parts.is_empty()
        && parts.len() <= 15
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

#[cfg(any(windows, test))]
fn icacls_command(
    executable: &Path,
    system_root: &Path,
    path: &Path,
    sid: &str,
) -> std::process::Command {
    let mut command = std::process::Command::new(executable);
    command
        .env_clear()
        .env("SystemRoot", system_root)
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("*{sid}:(F)"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

#[cfg(not(any(unix, windows)))]
fn set_owner_only_platform(_path: &Path, _error: &'static str) -> Result<(), &'static str> {
    Err("owner-only permissions are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;

    use super::{set_owner_only, write_private_noclobber, write_private_noclobber_with};

    #[test]
    #[cfg(unix)]
    fn private_output_is_owner_only_and_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sensitive.bin");
        write_private_noclobber(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(write_private_noclobber(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn post_install_sync_failure_reports_installed_file_and_uncertain_durability() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("installed.bin");
        let result = write_private_noclobber_with(&path, b"complete", |_| {
            Err(std::io::Error::other("injected sync failure"))
        });
        assert_eq!(
            result,
            Err("output installed but directory durability is unconfirmed")
        );
        assert_eq!(std::fs::read(path).unwrap(), b"complete");
    }

    #[test]
    #[cfg(unix)]
    fn no_clobber_reports_destination_collision_separately_from_install_errors() {
        let directory = tempfile::tempdir().unwrap();
        let occupied = directory.path().join("occupied.bin");
        std::fs::write(&occupied, b"keep").unwrap();
        assert_eq!(
            write_private_noclobber(&occupied, b"replacement"),
            Err("output exists")
        );
        let missing_parent = directory.path().join("missing").join("output.bin");
        assert_eq!(
            write_private_noclobber(&missing_parent, b"new"),
            Err("cannot stage output")
        );
        assert_eq!(std::fs::read(occupied).unwrap(), b"keep");
    }

    #[test]
    #[cfg(unix)]
    fn restricts_the_empty_staging_file_before_first_byte() {
        let temp = tempfile::tempdir().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        set_owner_only(file.path(), "permissions").unwrap();
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                file.as_file().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        file.write_all(b"secret").unwrap();
        assert_eq!(file.as_file().metadata().unwrap().len(), 6);
    }

    #[test]
    fn icacls_command_receives_only_its_minimal_environment_and_selected_identity() {
        let command = super::icacls_command(
            Path::new("C:\\Windows\\System32\\icacls.exe"),
            Path::new("C:\\Windows"),
            Path::new("vault.kdbx"),
            "S-1-5-21-123-456-789-1001",
        );
        let envs: Vec<_> = command.get_envs().collect();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "SystemRoot");
        assert_eq!(envs[0].1, Some(std::ffi::OsStr::new("C:\\Windows")));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], "vault.kdbx");
        assert_eq!(args[1], "/inheritance:r");
        assert_eq!(args[2], "/grant:r");
        assert_eq!(args[3], "*S-1-5-21-123-456-789-1001:(F)");
    }

    #[test]
    fn whoami_csv_parser_selects_only_the_sid_column() {
        assert_eq!(
            super::windows_sid_from_whoami_csv("\"CONTOSO\\alice\",\"S-1-5-21-1-2-3-1000\"\r\n"),
            Some("S-1-5-21-1-2-3-1000".into())
        );
        // An account name that is itself a valid SID must never shadow column 2.
        assert_eq!(
            super::windows_sid_from_whoami_csv("\"S-1-5-18\",\"S-1-5-21-1-2-3-1000\"\r\n"),
            Some("S-1-5-21-1-2-3-1000".into())
        );
        for malformed in [
            "\"S-1-5-18\",\"not-a-sid\"",
            "\"account\",\"S-1-5-18\",\"S-1-5-19\"",
            "account,\"S-1-5-18\"",
            "\"account\",S-1-5-18",
            "\"account\",\"S-1-5-18\"\r\n\"second\",\"S-1-5-19\"",
        ] {
            assert_eq!(
                super::windows_sid_from_whoami_csv(malformed),
                None,
                "accepted malformed whoami CSV {malformed:?}"
            );
        }
        assert_eq!(
            super::windows_sid_from_whoami_csv(&format!("\"{}\",\"S-1-5-18\"", "a".repeat(513))),
            None
        );
        assert_eq!(
            super::windows_sid_from_whoami_csv(&format!("\"account\",\"{}\"", "x".repeat(1025))),
            None
        );
        assert_eq!(
            super::windows_sid_from_whoami_csv(&format!("\"account\",\"{}\"", "x".repeat(513))),
            None
        );
    }

    #[test]
    fn windows_tools_are_selected_only_under_the_resolved_system_directory() {
        let system_directory = std::env::temp_dir().join("trusted-system-directory");
        let (root, whoami, icacls) =
            super::windows_tool_paths(&system_directory).expect("absolute system directory");
        assert_eq!(root, system_directory.parent().unwrap());
        assert_eq!(whoami, system_directory.join("whoami.exe"));
        assert_eq!(icacls, system_directory.join("icacls.exe"));
        assert!(super::windows_tool_paths(Path::new("System32")).is_none());
    }

    #[test]
    fn bounded_output_times_out_when_a_nested_child_keeps_running() {
        const PROBE: &str = "NKEEPASS_TIMEOUT_OUTPUT_PROBE";
        if std::env::var_os(PROBE).is_some() {
            use std::io::Write;

            std::io::stdout().write_all(b"child started\n").unwrap();
            std::io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(60));
            return;
        }

        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "private_file::tests::bounded_output_times_out_when_a_nested_child_keeps_running",
                "--nocapture",
            ])
            .env(PROBE, "child")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let start = std::time::Instant::now();
        let output = super::bounded_command_output(
            &mut command,
            1024,
            std::time::Duration::from_millis(250),
        );
        assert!(output.is_none(), "a still-running child must time out");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "bounded output waited for EOF instead of enforcing its timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_output_does_not_wait_for_descendant_after_nonzero_exit() {
        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "sleep 1 & exit 7"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let start = std::time::Instant::now();
        let output =
            super::bounded_command_output(&mut command, 1024, std::time::Duration::from_secs(3));

        assert!(output.is_none(), "a nonzero child must fail closed");
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "bounded output waited for stdout inherited by a descendant"
        );
        // The inherited writer is a deliberately short-lived `sleep`; it
        // closes stdout after one second even if the assertion above fails.
    }

    #[test]
    fn timed_out_nested_child_is_killed_and_reaped() {
        const PROBE: &str = "NKEEPASS_TIMEOUT_REAP_PROBE";
        if std::env::var_os(PROBE).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(60));
            return;
        }

        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "private_file::tests::timed_out_nested_child_is_killed_and_reaped",
                "--nocapture",
            ])
            .env(PROBE, "child")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        let status =
            super::wait_for_child(&mut child, std::time::Duration::from_millis(250)).unwrap();
        assert!(
            status.is_none(),
            "the nested child should exceed its deadline"
        );
        assert!(
            child.try_wait().unwrap().is_some(),
            "timed-out child was not reaped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_output_stops_and_terminates_a_child_that_exceeds_the_limit() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("oversized-output");
        std::fs::write(
            &executable,
            b"#!/bin/sh\nwhile :; do printf '%4096s' x; done\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = std::process::Command::new(executable);
        command
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let start = std::time::Instant::now();
        let result =
            super::bounded_command_output(&mut command, 32, std::time::Duration::from_secs(2));
        assert!(result.is_none(), "oversized output must fail closed");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "oversized output was not stopped promptly"
        );
    }

    #[test]
    fn termination_reaps_a_child_that_already_exited() {
        let mut command = if cfg!(windows) {
            let mut command = std::process::Command::new("cmd");
            command.args(["/c", "exit", "0"]);
            command
        } else {
            std::process::Command::new("true")
        };
        let mut child = command.spawn().unwrap();
        let _ = child.wait();
        assert!(super::terminate_and_reap(&mut child).is_ok());
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn command_status_times_out_for_a_hung_nested_child() {
        const PROBE: &str = "NKEEPASS_TIMEOUT_STATUS_PROBE";
        if std::env::var_os(PROBE).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(60));
            return;
        }

        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "private_file::tests::command_status_times_out_for_a_hung_nested_child",
                "--nocapture",
            ])
            .env(PROBE, "child")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let start = std::time::Instant::now();
        let status =
            super::run_command_with_timeout(&mut command, std::time::Duration::from_millis(250));
        assert!(status.is_none(), "a still-running command must time out");
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[cfg(windows)]
    #[test]
    fn private_staging_is_verified_by_handle() {
        let temp = tempfile::tempdir().unwrap();
        let file = super::new_private_temp(temp.path()).unwrap();
        windows_private_file::verify(file.as_file()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn private_staging_rejects_inherited_everyone_access() {
        let system_directory =
            known_folders::get_known_folder_path(known_folders::KnownFolder::System)
                .expect("Windows system directory");
        let (system_root, _, icacls_path) =
            super::windows_tool_paths(&system_directory).expect("absolute system directory");
        let temp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(icacls_path)
            .env_clear()
            .env("SystemRoot", system_root)
            .arg(temp.path())
            .args(["/grant", "*S-1-1-0:(OI)(CI)(F)"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "grant inheritable Everyone ACE");
        let private = super::new_private_temp(temp.path()).unwrap();
        windows_private_file::verify(private.as_file()).unwrap();
        let inherited = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        assert!(windows_private_file::verify(inherited.as_file()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn explicit_other_principal_grant_is_not_mistaken_for_owner_only() {
        let system_directory =
            known_folders::get_known_folder_path(known_folders::KnownFolder::System)
                .expect("Windows system directory");
        let (system_root, _, icacls_path) =
            super::windows_tool_paths(&system_directory).expect("absolute system directory");
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut grant = std::process::Command::new(&icacls_path);
        grant
            .env_clear()
            .env("SystemRoot", &system_root)
            .arg(temp.path())
            .arg("/grant")
            .arg("*S-1-1-0:(F)")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        assert!(
            grant.status().unwrap().success(),
            "grant explicit Everyone ACE"
        );
        let inspect_acl = || {
            std::process::Command::new(&icacls_path)
                .env_clear()
                .env("SystemRoot", &system_root)
                .arg(temp.path())
                .output()
                .unwrap()
        };
        let before = inspect_acl();
        assert!(before.status.success());

        assert!(windows_private_file::verify(temp.as_file()).is_err());
        let after = inspect_acl();
        assert!(after.status.success());
        assert_eq!(
            after.stdout, before.stdout,
            "refusal must leave the explicit other-principal ACE untouched"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_secret_output_is_private_and_refuses_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret.bin");
        super::write_private_noclobber(&path, b"secret").unwrap();
        windows_private_file::verify(&std::fs::File::open(&path).unwrap()).unwrap();
        assert!(super::write_private_noclobber(&path, b"other").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"secret");
    }

    #[cfg(unix)]
    fn environment_probe_command(directory: &Path, sid: &str) -> std::process::Command {
        let path = std::env::var_os("PATH").expect("PATH is required for the environment probe");
        let interpreter = std::env::split_paths(&path)
            .map(|directory| directory.join("python3"))
            .find(|path| path.is_file())
            .expect("an existing Python interpreter is required for the environment probe");
        let source = "import os, sys\nsys.stdout.buffer.write(b''.join(k+b'='+v+b'\\0' for k,v in os.environb.items()))\n";
        let mut script = tempfile::NamedTempFile::new_in(directory).unwrap();
        script.write_all(source.as_bytes()).unwrap();
        let script_path = directory.join("environment-probe.py");
        // Close and atomically publish the complete script, but read it as data:
        // executing a newly written inode can race with filesystem observers.
        script.into_temp_path().persist(&script_path).unwrap();
        // Python reads the builder's file argument as its script and ignores
        // the harmless icacls arguments. The actual builder still clears env.
        super::icacls_command(&interpreter, Path::new("C:\\Windows"), &script_path, sid)
    }

    #[cfg(unix)]
    #[test]
    fn icacls_child_does_not_inherit_the_callers_environment() {
        let temp = tempfile::tempdir().unwrap();
        let output = environment_probe_command(temp.path(), "selected-user")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "environment probe failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let entries: Vec<_> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .collect();
        // Rust may add LC_CTYPE on Unix; macOS also adds SDK lookup defaults.
        // A separate nested-process probe injects distinct arbitrary caller
        // markers and verifies those are not propagated.
        assert!(entries.contains(&b"SystemRoot=C:\\Windows".as_slice()));
        for entry in entries {
            let name = entry.split(|byte| *byte == b'=').next().unwrap_or_default();
            let allowed = name == b"SystemRoot"
                || name == b"LC_CTYPE"
                || cfg!(target_os = "macos")
                    && matches!(
                        name,
                        b"__CF_USER_TEXT_ENCODING"
                            | b"SDKROOT"
                            | b"CPATH"
                            | b"LIBRARY_PATH"
                            | b"MANPATH"
                    );
            assert!(
                allowed,
                "unexpected child environment entry: {}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn icacls_child_omits_a_distinct_secret_marker_from_its_parent() {
        const PROBE: &str = "NKEEPASS_ICACLS_ENV_PROBE";
        const MARKER: &str = "icacls-parent-secret-SENTINEL-72dc";
        if std::env::var_os(PROBE).is_some() {
            let temp = tempfile::tempdir().unwrap();
            let output = environment_probe_command(temp.path(), "S-1-5-21-1-2-3-4")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fake icacls failed: status={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let child_env = output.stdout;
            assert!(
                !child_env
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()),
                "the caller's secret marker reached the child environment"
            );
            assert!(
                !child_env
                    .windows(b"NKEEPASS_TEST_CANARY_SOURCE".len())
                    .any(|window| window == b"NKEEPASS_TEST_CANARY_SOURCE"),
                "the caller's canary variable name reached the child environment"
            );
            return;
        }

        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_file::tests::icacls_child_omits_a_distinct_secret_marker_from_its_parent",
                "--nocapture",
            ])
            .env(PROBE, "child")
            .env("NKEEPASS_TEST_SECRET_MARKER", MARKER)
            .env("NKEEPASS_TEST_CANARY_SOURCE", "caller-only")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "environment probe child failed: status={:?}, stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_sid_parser_rejects_malformed_and_unbounded_values() {
        assert!(super::is_windows_sid("S-1-5-21-123-456-789-1001"));
        assert!(super::is_windows_sid(&format!(
            "S-1-5-{}",
            vec!["1"; 15].join("-")
        )));
        for malformed in [
            "S-2-5-21",
            "S-1--5",
            "S-1-5-",
            "S-1-5-+1",
            "S-1-5--1",
            "S-1-281474976710656-1",
            "S-1-5-4294967296",
            &format!("S-1-5-{}", vec!["1"; 16].join("-")),
            &format!("S-1-5-{}", "1".repeat(185)),
        ] {
            assert!(!super::is_windows_sid(malformed), "accepted {malformed:?}");
        }
    }
}
