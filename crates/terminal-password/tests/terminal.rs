#![cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::pty::openpty;
use nix::sys::termios::{LocalFlags, SetArg, SpecialCharacterIndices, tcgetattr, tcsetattr};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Drain while the worker is alive: a failing termios assertion/backtrace can
/// itself fill a PTY and otherwise look like a blocked input reader.
#[derive(Default)]
struct Transcript {
    tail: Vec<u8>,
    scan: Vec<u8>,
    total: usize,
    echoed: bool,
}

impl Transcript {
    fn drain(&mut self, master: &mut std::fs::File) {
        let mut bytes = [0; 8192];
        // Bound each drain as well as retention; a noisy child must not starve
        // the parent deadline. Keep scanning for echo after retention overflows.
        for _ in 0..16 {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    let chunk = &bytes[..count];
                    self.total += count;
                    self.scan.extend_from_slice(chunk);
                    self.echoed |= self.scan.windows(6).any(|part| part == b"S\xc3\xabcre");
                    let discard = self.scan.len().saturating_sub(5);
                    self.scan.drain(..discard);
                    const LIMIT: usize = 64 * 1024;
                    let discard = (self.tail.len() + count).saturating_sub(LIMIT);
                    self.tail.drain(..discard);
                    self.tail.extend_from_slice(chunk);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("cannot drain worker PTY: {error}"),
            }
        }
    }

    fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.tail)
    }
}

struct Worker(std::process::Child);
impl std::ops::Deref for Worker {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Worker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

#[test]
fn worker() {
    let Ok(scenario) = std::env::var("TERMINAL_PASSWORD_TEST") else {
        return;
    };
    let stdin = std::io::stdin();
    let original = tcgetattr(&stdin).unwrap();
    let mut prior_actions = Vec::new();
    if scenario == "prior" {
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGUSR1);
        let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::SA_RESTART, mask);
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ] {
            // SAFETY: isolated child test; SIG_IGN contains no callback.
            prior_actions.push((signal, unsafe { sigaction(signal, &ignored).unwrap() }));
        }
    }
    // Signal readiness only after the input mode was set: the parent observes
    // the slave's flags before sending anything, so no typed secret can echo.
    eprintln!("ready");
    let result = terminal_password::read(Duration::from_millis(300));
    eprintln!(
        "read returned: {}",
        if result.is_ok() { "success" } else { "error" }
    );
    let mut restored = tcgetattr(&stdin).unwrap();
    if scenario == "diagnostic" {
        // Model a BSD-style pending-input bit mismatch. The complete termios
        // assertion plus backtrace can exceed a PTY's output capacity.
        restored.local_flags.toggle(LocalFlags::PENDIN);
        std::io::stderr().write_all(&[b'.'; 128 * 1024]).unwrap();
    }
    assert_eq!(restored, original, "restore every termios bit");
    match scenario.as_str() {
        "enter" | "post-enter" | "enter-tail" | "raw-enter" | "pendin-enter" => {
            assert_eq!(&*result.unwrap(), "Sëcret")
        }
        "cancel" | "escape" | "eof" | "signal" | "post-cancel" | "cancel-tail" => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted)
        }
        "timeout" | "post-timeout" | "prior" | "partial-timeout" => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut)
        }
        "invalid-utf8" => assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Other),
        _ => panic!("unknown scenario"),
    }
    for (signal, original) in prior_actions {
        use nix::sys::signal::{SaFlags, SigHandler, Signal, sigaction};
        // SAFETY: restore the saved action in this isolated child.
        let restored = unsafe { sigaction(signal, &original).unwrap() };
        assert_eq!(restored.handler(), SigHandler::SigIgn);
        assert!(restored.flags().contains(SaFlags::SA_RESTART));
        assert!(restored.mask().contains(Signal::SIGUSR1));
    }
    if scenario.starts_with("post-") {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
        panic!("SIGTERM was swallowed after read returned");
    }
}

#[test]
fn submission_cancellation_and_timeout_restore_exact_modes_without_echo() {
    for (scenario, input) in [
        ("enter", "SëcreX\u{7f}t\n".as_bytes()),
        ("cancel", b"\x03".as_slice()),
        ("escape", b"\x1b".as_slice()),
        ("eof", b"\x04".as_slice()),
        ("signal", b"".as_slice()),
        ("timeout", b"".as_slice()),
        ("post-enter", "SëcreX\u{7f}t\n".as_bytes()),
        ("post-cancel", b"\x03".as_slice()),
        ("post-timeout", b"".as_slice()),
        ("prior", b"".as_slice()),
        ("enter-tail", "Sëcret\nAFTER-ENTER-SENTINEL\n".as_bytes()),
        ("cancel-tail", b"\x03AFTER-CANCEL-SENTINEL\n".as_slice()),
        ("partial-timeout", b"partial".as_slice()),
        ("invalid-utf8", b"\xff\n".as_slice()),
        ("raw-enter", "Sëcret\n".as_bytes()),
        ("pendin-enter", "Sëcret\n".as_bytes()),
        ("diagnostic", "SëcreX\u{7f}t\n".as_bytes()),
    ] {
        let pty = openpty(None, None).unwrap();
        let mut mode = tcgetattr(&pty.slave).unwrap();
        mode.local_flags
            .insert(LocalFlags::ECHO | LocalFlags::ICANON);
        if scenario == "raw-enter" {
            mode.local_flags.remove(LocalFlags::ICANON);
            mode.control_chars[SpecialCharacterIndices::VMIN as usize] = 7;
            mode.control_chars[SpecialCharacterIndices::VTIME as usize] = 2;
        } else if scenario == "pendin-enter" {
            mode.local_flags.insert(LocalFlags::PENDIN);
        }
        tcsetattr(&pty.slave, SetArg::TCSANOW, &mode).unwrap();
        let original_flags = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
        for fd in [&pty.master, &pty.slave] {
            let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap());
            fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC)).unwrap();
        }
        let flags = OFlag::from_bits_retain(fcntl(&pty.master, FcntlArg::F_GETFL).unwrap());
        fcntl(&pty.master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        let mut master = std::fs::File::from(pty.master);
        let mut child = Worker(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "worker", "--nocapture"])
                .env("TERMINAL_PASSWORD_TEST", scenario)
                .env(
                    "RUST_BACKTRACE",
                    if scenario == "diagnostic" {
                        "full"
                    } else {
                        "0"
                    },
                )
                .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
                .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
                .stderr(Stdio::from(pty.slave.try_clone().unwrap()))
                .spawn()
                .unwrap(),
        );
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        let mut transcript = Transcript::default();
        while tcgetattr(&pty.slave)
            .unwrap()
            .local_flags
            .contains(LocalFlags::ECHO)
        {
            transcript.drain(&mut master);
            if let Some(status) = child.try_wait().unwrap() {
                transcript.drain(&mut master);
                panic!(
                    "worker exited before no-echo mode: scenario={scenario}, status={status}, transcript={}",
                    transcript.text()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                transcript.drain(&mut master);
                panic!(
                    "worker did not enter no-echo mode: scenario={scenario}, elapsed={:?}, transcript={}",
                    started.elapsed(),
                    transcript.text()
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let active_mode = tcgetattr(&pty.slave).unwrap();
        master.write_all(input).unwrap();
        if scenario == "signal" {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
        }
        let status = loop {
            transcript.drain(&mut master);
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                transcript.drain(&mut master);
                panic!(
                    "worker leaked or stalled: scenario={scenario}, pid={}, elapsed={:?}, mode={:?}, parent_pgrp={}, tty_pgrp={:?}, captured_bytes={}, transcript={}",
                    child.id(),
                    started.elapsed(),
                    tcgetattr(&pty.slave),
                    nix::unistd::getpgrp(),
                    nix::unistd::tcgetpgrp(&pty.slave),
                    transcript.total,
                    transcript.text()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        transcript.drain(&mut master);
        assert_eq!(
            tcgetattr(&pty.slave).unwrap(),
            mode,
            "scenario={scenario}, transcript={}",
            transcript.text()
        );
        assert_eq!(
            fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap(),
            original_flags,
            "reader changed shared descriptor flags: scenario={scenario}"
        );
        assert_eq!(
            active_mode.control_chars[SpecialCharacterIndices::VMIN as usize],
            0,
            "read itself could block despite poll: scenario={scenario}"
        );
        assert_eq!(
            active_mode.control_chars[SpecialCharacterIndices::VTIME as usize],
            0
        );
        if matches!(scenario, "enter-tail" | "cancel-tail") {
            let flags = OFlag::from_bits_retain(fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap());
            fcntl(&pty.slave, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
            let mut unread = [0];
            assert!(
                matches!(
                    nix::unistd::read(&pty.slave, &mut unread),
                    Err(nix::errno::Errno::EAGAIN)
                ),
                "hidden typeahead was left for the next reader: scenario={scenario}"
            );
        }
        drop(pty.slave);
        transcript.drain(&mut master);
        assert!(
            if scenario == "diagnostic" {
                status.code() == Some(101)
            } else if scenario.starts_with("post-") {
                status.signal() == Some(15)
            } else {
                status.success()
            },
            "worker {scenario}: {}",
            transcript.text()
        );
        assert!(!transcript.echoed, "secret echoed: scenario={scenario}");
        if scenario == "diagnostic" {
            assert!(
                transcript.total > 128 * 1024,
                "large panic output was not drained"
            );
            assert!(
                transcript.text().contains("restore every termios bit"),
                "lost the worker's original failure diagnostic"
            );
        }
    }
}
