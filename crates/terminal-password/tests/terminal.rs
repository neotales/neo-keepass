#![cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::pty::openpty;
use nix::sys::termios::{LocalFlags, SetArg, SpecialCharacterIndices, tcgetattr, tcsetattr};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ECHO_MARKERS: &[&[u8]] = &[
    b"S\xc3\xabcre",
    b"AFTER-ENTER-SENTINEL",
    b"AFTER-CANCEL-SENTINEL",
];

#[test]
fn frontend_quiet_snapshot_restores_exact_modes_without_hidden_replay() {
    use nix::sys::termios::{InputFlags, cfmakeraw};
    use std::os::fd::AsRawFd;
    for (canonical, pending, explicit) in [
        (true, false, true),
        (true, true, true),
        (false, false, true),
        (true, false, false),
    ] {
        let pty = openpty(None, None).unwrap();
        let mut original = tcgetattr(&pty.slave).unwrap();
        original.local_flags.set(LocalFlags::ICANON, canonical);
        original.local_flags.set(LocalFlags::PENDIN, pending);
        original
            .local_flags
            .insert(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ISIG);
        original.input_flags.insert(InputFlags::IXON);
        tcsetattr(&pty.slave, SetArg::TCSANOW, &original).unwrap();
        let original = tcgetattr(&pty.slave).unwrap();
        let mut guard = terminal_password::QuietTerminal::new(std::fs::File::from(
            pty.slave.try_clone().unwrap(),
        ))
        .unwrap();
        let snapshot = tcgetattr(&pty.slave).unwrap();
        assert!(
            !snapshot.local_flags.intersects(
                LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ISIG | LocalFlags::IEXTEN,
            ),
            "backend snapshot must never re-enable input side effects"
        );
        let mut raw = snapshot.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&pty.slave, SetArg::TCSANOW, &raw).unwrap();
        let mut master = std::fs::File::from(pty.master);
        master.write_all(b"HIDDEN-EXIT-TAIL\n\x03\n").unwrap();
        // Acknowledge queued bytes before teardown; also forces Darwin replay.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let mut count: nix::libc::c_int = 0;
            // SAFETY: live PTY descriptor and correctly sized writable integer.
            assert_eq!(
                unsafe { nix::libc::ioctl(pty.slave.as_raw_fd(), nix::libc::FIONREAD, &mut count) },
                0
            );
            if count == 19 {
                break;
            }
            assert!(Instant::now() < deadline, "hidden bytes not queued");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Simulate the backend's ordinary restore, before the guard's handoff.
        tcsetattr(&pty.slave, SetArg::TCSANOW, &snapshot).unwrap();
        if explicit {
            guard.restore().unwrap();
        }
        drop(guard);
        assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
        let mut count: nix::libc::c_int = -1;
        // SAFETY: same live descriptor and output integer as above.
        assert_eq!(
            unsafe { nix::libc::ioctl(pty.slave.as_raw_fd(), nix::libc::FIONREAD, &mut count) },
            0
        );
        assert_eq!(count, 0, "hidden typeahead survived the ownership handoff");
        let flags = OFlag::from_bits_retain(fcntl(&master, FcntlArg::F_GETFL).unwrap());
        fcntl(&master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        let mut byte = [0];
        assert_eq!(
            master.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "hidden typeahead was echoed"
        );
    }
}

#[test]
fn restored_frontend_guard_does_not_flush_the_next_owners_input() {
    let pty = openpty(None, None).unwrap();
    let mut guard =
        terminal_password::QuietTerminal::new(std::fs::File::from(pty.slave.try_clone().unwrap()))
            .unwrap();
    guard.restore().unwrap();
    let mut master = std::fs::File::from(pty.master);
    master.write_all(b"next-owner\n").unwrap();
    // Repeated explicit restoration and Drop are no-ops after handoff.
    guard.restore().unwrap();
    drop(guard);
    use nix::poll::{PollFd, PollFlags, poll};
    use std::os::fd::AsFd;
    let mut fds = [PollFd::new(pty.slave.as_fd(), PollFlags::POLLIN)];
    assert_eq!(
        poll(&mut fds, 500u16).unwrap(),
        1,
        "next owner's input was discarded"
    );
    let mut slave = std::fs::File::from(pty.slave);
    let flags = OFlag::from_bits_retain(fcntl(&slave, FcntlArg::F_GETFL).unwrap());
    fcntl(&slave, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
    let mut bytes = [0; 11];
    assert_eq!(slave.read(&mut bytes).unwrap(), bytes.len());
    assert_eq!(&bytes, b"next-owner\n");
}

fn worker_output(slave: &OwnedFd) -> OwnedFd {
    // dup/try_clone shares status flags and Darwin's FWASWRITTEN history.
    // Reopen this same PTY instead: termios and captured output remain shared,
    // but harness writes cannot contaminate the reader's file description.
    nix::fcntl::open(
        &nix::unistd::ttyname(slave).unwrap(),
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap()
}

#[test]
fn worker_output_has_independent_status_flags_but_the_same_terminal() {
    let pty = openpty(None, None).unwrap();
    let output = worker_output(&pty.slave);
    let input_flags = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
    let output_flags = fcntl(&output, FcntlArg::F_GETFL).unwrap();
    fcntl(
        &output,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(output_flags) | OFlag::O_NONBLOCK),
    )
    .unwrap();
    nix::unistd::write(&output, b"harness diagnostic\n").unwrap();
    assert_eq!(
        fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap(),
        input_flags,
        "output writes/status changes contaminated the input description"
    );
    let mut mode = tcgetattr(&pty.slave).unwrap();
    mode.local_flags.toggle(LocalFlags::ECHO);
    tcsetattr(&pty.slave, SetArg::TCSANOW, &mode).unwrap();
    assert_eq!(tcgetattr(&output).unwrap(), mode);
    let mut master = std::fs::File::from(pty.master);
    // A missing output route must fail within a deadline, not block this test.
    let flags = OFlag::from_bits_retain(fcntl(&master, FcntlArg::F_GETFL).unwrap());
    fcntl(&master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut transcript = Transcript::default();
    while !transcript.text().contains("harness diagnostic") {
        transcript.drain(&mut master);
        assert!(
            Instant::now() < deadline,
            "output did not reach the PTY master"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_duplicate_output_write_changes_input_write_history_without_a_reader() {
    // XNU bsd/sys/fcntl.h: kernel-only FWASWRITTEN, not a settable O_* flag.
    const FWASWRITTEN: i32 = 0x0001_0000;
    let pty = openpty(None, None).unwrap();
    let output = pty.slave.try_clone().unwrap();
    let before = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
    assert_eq!(before & FWASWRITTEN, 0);
    nix::unistd::write(&output, b"diagnostic without terminal_password::read\n").unwrap();
    let after = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
    assert_eq!(
        after,
        before | FWASWRITTEN,
        "before={before:#x}, after={after:#x}"
    );
}

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
    fn record(&mut self, chunk: &[u8]) {
        self.total += chunk.len();
        self.scan.extend_from_slice(chunk);
        self.echoed |= ECHO_MARKERS
            .iter()
            .any(|marker| self.scan.windows(marker.len()).any(|part| part == *marker));
        let keep = ECHO_MARKERS
            .iter()
            .map(|marker| marker.len())
            .max()
            .unwrap()
            - 1;
        let discard = self.scan.len().saturating_sub(keep);
        self.scan.drain(..discard);
        const LIMIT: usize = 64 * 1024;
        if chunk.len() >= LIMIT {
            self.tail.clear();
            self.tail.extend_from_slice(&chunk[chunk.len() - LIMIT..]);
        } else {
            let discard = (self.tail.len() + chunk.len()).saturating_sub(LIMIT);
            self.tail.drain(..discard);
            self.tail.extend_from_slice(chunk);
        }
    }

    fn drain(&mut self, master: &mut std::fs::File) {
        let mut bytes = [0; 8192];
        // Bound each drain as well as retention; a noisy child must not starve
        // the parent deadline. Keep scanning for echo after retention overflows.
        for _ in 0..16 {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    self.record(&bytes[..count]);
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

#[test]
fn echo_scanning_covers_split_typeahead_markers_and_retention_overflow() {
    for marker in ECHO_MARKERS {
        for split in 1..marker.len() {
            let mut transcript = Transcript::default();
            transcript.record(&marker[..split]);
            transcript.record(&marker[split..]);
            for _ in 0..20 {
                transcript.record(&[b'.'; 8192]);
            }
            assert!(
                transcript.echoed,
                "marker crossing a read boundary was lost"
            );
            assert_eq!(transcript.tail.len(), 64 * 1024);
            assert!(
                !transcript
                    .tail
                    .windows(marker.len())
                    .any(|part| part == *marker)
            );
        }
    }
}

fn set_cloexec(fd: &impl std::os::fd::AsFd) {
    let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap());
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC)).unwrap();
}

fn drain_nonblocking(reader: &mut impl Read, buf: &mut Vec<u8>, max_chunks: usize) {
    let mut chunk = [0u8; 4096];
    for _ in 0..max_chunks {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => buf.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("cannot drain worker pipe: {error}"),
        }
    }
}

struct Worker {
    child: std::process::Child,
    pty_master: Option<OwnedFd>,
}

impl Worker {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            pty_master: None,
        }
    }

    fn with_pty_master(child: std::process::Child, pty_master: OwnedFd) -> Self {
        Self {
            child,
            pty_master: Some(pty_master),
        }
    }

    fn close_pty_master(&mut self) {
        self.pty_master.take();
    }

    fn reap_bounded(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        }
    }
}

impl std::ops::Deref for Worker {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for Worker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        // Release the PTY master BEFORE reaping so an XNU session leader with a
        // saturated output queue cannot block in Es (ttywait) during wait().
        self.pty_master.take();
        let _ = self.reap_bounded(Duration::from_secs(2));
    }
}

#[test]
fn stalled_prompt_worker() {
    let Ok(scenario) = std::env::var("TERMINAL_PASSWORD_STALLED_PROMPT") else {
        return;
    };
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let stdin = std::io::stdin();
    nix::unistd::setsid().unwrap();
    // SAFETY: isolated child, live PTY stdin; acquire it as controlling terminal.
    assert_eq!(
        unsafe { nix::libc::ioctl(stdin.as_raw_fd(), nix::libc::TIOCSCTTY as _, 0,) },
        0
    );
    let original = tcgetattr(&stdin).unwrap();
    let input_flags = fcntl(&stdin, FcntlArg::F_GETFL).unwrap();
    let stdout_flags = fcntl(std::io::stdout(), FcntlArg::F_GETFL).unwrap();
    // Saturate output before calling the public API. The parent NEVER drains
    // the master; diagnostics use a separate pipe, not this blocked terminal.
    let output = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open("/dev/tty")
        .unwrap();
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "could not saturate PTY output"
        );
        match nix::unistd::write(&output, &[b'.'; 4096]) {
            Ok(count) => assert!(count > 0),
            Err(nix::errno::Errno::EAGAIN) => break,
            Err(error) => panic!("prefill PTY failed: {error}"),
        }
    }
    drop(output);
    let timeout = if scenario == "cancel" {
        Duration::from_secs(3)
    } else {
        Duration::from_millis(300)
    };
    let started = Instant::now();
    let result = terminal_password::read_controlling(&".".repeat(8 * 1024 * 1024), timeout);
    let elapsed = started.elapsed();
    assert_eq!(
        tcgetattr(&stdin).unwrap(),
        original,
        "stalled prompt must restore every mode"
    );
    assert_eq!(fcntl(&stdin, FcntlArg::F_GETFL).unwrap(), input_flags);
    assert_eq!(
        fcntl(std::io::stdout(), FcntlArg::F_GETFL).unwrap(),
        stdout_flags,
        "prompt changed inherited stdout OFD"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        if scenario == "cancel" {
            std::io::ErrorKind::Interrupted
        } else {
            assert!(elapsed >= Duration::from_millis(250));
            std::io::ErrorKind::TimedOut
        }
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "prompt exceeded bounded return: {elapsed:?}"
    );
    println!("STALLED_PROMPT_DONE");
    let _ = std::io::stdout().flush();
}

#[test]
fn stalled_prompt_timeout_and_signal_cancel_restore_exact_modes_without_writer_threads() {
    for scenario in ["timeout", "cancel"] {
        let pty = openpty(None, None).unwrap();
        set_cloexec(&pty.master);
        set_cloexec(&pty.slave);
        let mut child = Worker::with_pty_master(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "stalled_prompt_worker", "--nocapture"])
                .env("TERMINAL_PASSWORD_STALLED_PROMPT", scenario)
                .env("RUST_BACKTRACE", "0")
                .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
            pty.master,
        );
        let mut pty_slave = Some(pty.slave);
        let deadline = Instant::now() + Duration::from_secs(5);
        if scenario == "cancel" {
            while tcgetattr(pty_slave.as_ref().unwrap())
                .unwrap()
                .local_flags
                .contains(LocalFlags::ECHO)
            {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "prompt exited before cancellation"
                );
                assert!(Instant::now() < deadline, "prompt never entered quiet mode");
                std::thread::sleep(Duration::from_millis(1));
            }
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
        }
        let mut stdout = child.stdout.take().unwrap();
        let stdout_flags = OFlag::from_bits_retain(fcntl(&stdout, FcntlArg::F_GETFL).unwrap());
        fcntl(&stdout, FcntlArg::F_SETFL(stdout_flags | OFlag::O_NONBLOCK)).unwrap();
        let mut stdout_buf = Vec::new();
        let mut early_status = None;
        let mut timed_out = false;
        loop {
            drain_nonblocking(&mut stdout, &mut stdout_buf, 16);
            if String::from_utf8_lossy(&stdout_buf).contains("STALLED_PROMPT_DONE") {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                drain_nonblocking(&mut stdout, &mut stdout_buf, usize::MAX);
                early_status = Some(status);
                break;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Release the PTY master (and slave) BEFORE reaping the session-leader
        // worker: on XNU, exit1() -> ptsclose -> ttywflush -> ttywait blocks in
        // unkillable Es while the master remains open on a saturated output queue.
        child.close_pty_master();
        pty_slave.take();
        let mut status = early_status;
        if !timed_out && status.is_none() {
            loop {
                if let Some(exited) = child.try_wait().unwrap() {
                    status = Some(exited);
                    break;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if timed_out {
            let _ = child.kill();
            let _ = child.reap_bounded(Duration::from_secs(2));
            drain_nonblocking(&mut stdout, &mut stdout_buf, usize::MAX);
            let mut diagnostic = String::from_utf8_lossy(&stdout_buf).into_owned();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut diagnostic);
            }
            panic!("stalled prompt {scenario} exceeded outer bound: {diagnostic}");
        }
        let status = status.unwrap();
        drain_nonblocking(&mut stdout, &mut stdout_buf, usize::MAX);
        let mut diagnostic = String::from_utf8_lossy(&stdout_buf).into_owned();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut diagnostic)
            .unwrap();
        assert!(status.success(), "stalled prompt {scenario}: {diagnostic}");
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
    // Snapshot immediately around the product call, before any diagnostic
    // writes. Keep raw bits (including unknown kernel flags), not an OFlag
    // truncation that could hide a regression.
    let input_flags = fcntl(&stdin, FcntlArg::F_GETFL).unwrap();
    let descriptor_flags = fcntl(&stdin, FcntlArg::F_GETFD).unwrap();
    let result = terminal_password::read(Duration::from_millis(300));
    let returned_flags = fcntl(&stdin, FcntlArg::F_GETFL).unwrap();
    let returned_descriptor_flags = fcntl(&stdin, FcntlArg::F_GETFD).unwrap();
    assert_eq!(
        returned_flags,
        input_flags,
        "product changed input status flags: scenario={scenario}, before={input_flags:#x}, after={returned_flags:#x}, delta={:#x}",
        input_flags ^ returned_flags
    );
    assert_eq!(
        returned_descriptor_flags, descriptor_flags,
        "product changed input descriptor flags: scenario={scenario}"
    );
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
        "enter" | "post-enter" | "enter-tail" | "raw-enter" | "pendin-enter"
        | "nonblocking-enter" => {
            assert_eq!(&*result.unwrap(), "Sëcret")
        }
        "cancel" | "escape" | "eof" | "signal" | "post-cancel" | "cancel-tail" => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted)
        }
        "timeout" | "post-timeout" | "prior" | "partial-timeout" | "nonblocking-timeout" => {
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
        ("nonblocking-enter", "Sëcret\n".as_bytes()),
        ("nonblocking-timeout", b"".as_slice()),
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
        if scenario.starts_with("nonblocking-") {
            let flags = OFlag::from_bits_retain(fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap());
            fcntl(&pty.slave, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        }
        let original_flags = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
        set_cloexec(&pty.master);
        set_cloexec(&pty.slave);
        let original_descriptor_flags = fcntl(&pty.slave, FcntlArg::F_GETFD).unwrap();
        let output = worker_output(&pty.slave);
        let flags = OFlag::from_bits_retain(fcntl(&pty.master, FcntlArg::F_GETFL).unwrap());
        fcntl(&pty.master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        let mut child = Worker::new(
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
                .stdout(Stdio::from(output.try_clone().unwrap()))
                .stderr(Stdio::from(output))
                .spawn()
                .unwrap(),
        );
        // Declare master after child so an unwinding panic closes master before Worker::drop.
        let mut master = std::fs::File::from(pty.master);
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
                let _ = child.reap_bounded(Duration::from_secs(2));
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
        let active_flags = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
        assert_eq!(
            active_flags,
            original_flags,
            "input status flags changed while reading: scenario={scenario}, before={original_flags:#x}, active={active_flags:#x}, delta={:#x}",
            original_flags ^ active_flags
        );
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
                let _ = child.reap_bounded(Duration::from_secs(2));
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
        let restored_flags = fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap();
        assert_eq!(
            restored_flags,
            original_flags,
            "input status flags changed: scenario={scenario}, before={original_flags:#x}, active={active_flags:#x}, after={restored_flags:#x}, delta={:#x}",
            original_flags ^ restored_flags
        );
        assert_eq!(
            fcntl(&pty.slave, FcntlArg::F_GETFD).unwrap(),
            original_descriptor_flags,
            "parent descriptor flags changed: scenario={scenario}"
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
