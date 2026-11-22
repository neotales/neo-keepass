//! Synchronous secret input: no reader thread, no global event queue.
//! The saved terminal mode is restored on every normal return and unwind.
use std::io;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

static READER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read from the Unix controlling terminal, with the same ownership, deadline,
/// cancellation and quiet input-flush contract as [`read`]. This preserves
/// interactive callers' `/dev/tty` selection rather than consuming piped stdin.
/// The unbuffered prompt is written only after quiet mode and its restoration
/// guard are installed. Nonblocking writes share the input deadline and scoped
/// signal cancellation. No output drain/flush waits for the terminal consumer.
/// Prompt timeout, cancellation and I/O errors also restore the mode.
#[cfg(unix)]
pub fn read_controlling(prompt: &str, timeout: Duration) -> io::Result<Zeroizing<String>> {
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("invalid input timeout"))?;
    let _exclusive = READER
        .try_lock()
        .map_err(|_| io::Error::other("terminal input is already in use"))?;
    let terminal = std::fs::OpenOptions::new().read(true).open("/dev/tty")?;
    // Independent output description: writes must not contaminate the input
    // description's Darwin file-status history.
    let output = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open("/dev/tty")?;
    platform::read_from_ready(&terminal, deadline, || {
        platform::write_prompt(&output, prompt.as_bytes(), deadline)
    })
}

/// Exclusive Unix terminal-mode ownership around a raw-mode frontend.
///
/// Capture and quiet the supplied terminal BEFORE a backend snapshots modes.
/// That backend must finish restoring its snapshot before `restore` or Drop.
/// Its snapshot therefore cannot re-enable echo/signals during canonical
/// restoration. No signal handlers are installed here. Callers must exclude
/// other mode owners and readers; this guard does not serialize external code.
/// Restoration intentionally discards queued typeahead while quiet, then
/// restores every original mode bit. Later input belongs to the restored owner.
/// Preparation failures never enable echo/signals over unsettled input.
#[cfg(unix)]
pub struct QuietTerminal(platform::Restore<std::fs::File>);

#[cfg(unix)]
impl QuietTerminal {
    /// Takes ownership of the descriptor; Drop retries incomplete restoration.
    pub fn new(terminal: std::fs::File) -> io::Result<Self> {
        platform::Restore::quiet(terminal).map(Self)
    }

    /// Report restoration errors on normal exits; Drop is only a fallback.
    pub fn restore(&mut self) -> io::Result<()> {
        self.0.restore()
    }
}

/// Reads UTF-8 from terminal stdin without echo, bounded by an absolute deadline.
/// Redirected stdin is refused. Enter submits; Ctrl-C, Ctrl-D and Escape cancel.
/// Terminal state is restored before returning, including on timeout.
/// On Unix, restoration first settles the saved canonical/raw discipline with
/// echo and signal generation disabled, then flushes pending input before
/// reinstating the exact saved flags. That quiet flush is the input-ownership
/// handoff: bytes arriving later are not guaranteed to be discarded and obey
/// the restored flags (including an originally set PENDIN).
///
/// # Process-wide ownership
/// On Unix this call temporarily owns the process-wide SIGINT, SIGTERM, SIGHUP
/// and SIGQUIT actions. The caller must ensure that no other thread, component
/// or library concurrently changes those actions until this call returns.
/// Restoration reinstalls the saved actions and would overwrite concurrent
/// changes. The internal lock excludes other calls to this function only; it
/// does not coordinate external signal-action installers. Likewise, no other
/// consumer may read terminal stdin or change its terminal modes concurrently.
/// Submission is provisional until terminal modes and prior signal actions
/// have been restored. Cancellation recorded by the scoped handlers through
/// that handoff discards the value instead of returning a secret.
///
/// # Errors
/// Refuses nonterminal or concurrent input, cancellation, expired deadlines,
/// invalid Unicode, oversized values, and terminal I/O or restoration errors.
/// On Unix, failed preparation never enables echo or signals over unsettled
/// input; the guard retries the same staged sequence.
/// A persistent OS error can prevent complete restoration and is reported.
pub fn read(timeout: Duration) -> io::Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    let _exclusive = READER
        .try_lock()
        .map_err(|_| io::Error::other("terminal input is already in use"))?;
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(
            "value input requires a terminal or an explicit source",
        ));
    }
    platform::read(
        Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("invalid input timeout"))?,
    )
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "value input cancelled")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "value input timed out")
}

#[cfg(unix)]
mod platform {
    use super::*;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    use nix::sys::termios::{
        FlushArg, LocalFlags, SetArg, SpecialCharacterIndices, Termios, tcflush, tcgetattr,
        tcsetattr,
    };
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicBool, Ordering};

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    extern "C" fn interrupt(_: i32) {
        INTERRUPTED.store(true, Ordering::Relaxed);
    }

    fn remaining(deadline: Instant) -> io::Result<Duration> {
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(timed_out)
    }

    pub(super) fn write_prompt(
        output: &impl AsFd,
        mut bytes: &[u8],
        deadline: Instant,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            remaining(deadline)?;
            // The caller opens an independent O_NONBLOCK description. Readiness
            // alone cannot bound a write; no retry here may silently block or
            // restart EINTR without rechecking cancellation and the deadline.
            match nix::unistd::write(output, &bytes[..bytes.len().min(4096)]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "terminal prompt write made no progress",
                    ));
                }
                Ok(count) => {
                    bytes = &bytes[count..];
                    continue;
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EAGAIN) => {}
                Err(error) => return Err(error.into()),
            }
            let mut fds = [PollFd::new(output.as_fd(), PollFlags::POLLOUT)];
            let timeout =
                PollTimeout::try_from(remaining(deadline)?.min(Duration::from_millis(100)))
                    .unwrap_or(PollTimeout::MAX);
            match poll(&mut fds, timeout) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
                _ => {}
            }
            let events = fds[0]
                .revents()
                .ok_or_else(|| io::Error::other("invalid terminal output readiness event"))?;
            if events.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP | PollFlags::POLLERR) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "terminal prompt output failed",
                ));
            }
        }
        remaining(deadline).map(|_| ())
    }

    // sigaction saves/restores complete dispositions, including masks/flags.
    // Unregistering a signal-hook callback would leave its process-wide handler
    // installed and can swallow subsequent default-terminating signals.
    struct Signals(Vec<(Signal, SigAction)>);
    impl Signals {
        fn restore(&mut self) -> io::Result<()> {
            while let Some((signal, previous)) = self.0.last() {
                // SAFETY: previous was returned by sigaction for this signal.
                // The installed handler only touches a static atomic. The
                // public reader lock excludes concurrent readers in this crate.
                unsafe {
                    sigaction(*signal, previous)?;
                }
                self.0.pop();
            }
            Ok(())
        }
    }
    impl Drop for Signals {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    enum RestoreOp<'a> {
        FlushInput,
        SetMode(&'a Termios),
    }

    fn quiet_mode(original: &Termios) -> Termios {
        let mut mode = original.clone();
        mode.local_flags.remove(
            LocalFlags::ECHO
                | LocalFlags::ECHONL
                | LocalFlags::ISIG
                | LocalFlags::IEXTEN
                | LocalFlags::PENDIN,
        );
        mode.input_flags.remove(nix::sys::termios::InputFlags::IXON);
        mode
    }

    fn restore_mode(
        original: &Termios,
        mut apply: impl FnMut(RestoreOp<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        // Enter the ORIGINAL canonical/raw discipline, but keep echo/signal
        // generation, extended input and start/stop handling disabled. Darwin can
        // generate PENDIN here and replay bytes arriving during the change;
        // neither that replay nor newly arriving bytes may expose input.
        let quiet = quiet_mode(original);
        apply(RestoreOp::SetMode(&quiet))?;
        // Clear queued input AND kernel-generated PENDIN while still quiet.
        // TCIFLUSH never waits for output. Preparation failure must not fall
        // through to enabling the original flags; Drop retries this sequence.
        apply(RestoreOp::FlushInput)?;
        // Canonical mode no longer changes, so this does not generate PENDIN.
        // Restore all original bits, including an originally set PENDIN.
        // Input arriving after the quiet flush belongs to the restored owner.
        apply(RestoreOp::SetMode(original))
    }

    pub(super) struct Restore<F: AsFd> {
        stdin: F,
        original: Termios,
        restored: bool,
    }
    impl<F: AsFd> Restore<F> {
        pub(super) fn quiet(stdin: F) -> io::Result<Self> {
            let original = tcgetattr(&stdin)?;
            let mode = quiet_mode(&original);
            let restore = Self {
                stdin,
                original,
                restored: false,
            };
            tcsetattr(&restore.stdin, SetArg::TCSANOW, &mode)?;
            Ok(restore)
        }

        pub(super) fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            let result = restore_mode(&self.original, |operation| {
                match operation {
                    RestoreOp::FlushInput => tcflush(&self.stdin, FlushArg::TCIFLUSH),
                    RestoreOp::SetMode(mode) => tcsetattr(&self.stdin, SetArg::TCSANOW, mode),
                }
                .map_err(io::Error::from)
            });
            self.restored = result.is_ok();
            result
        }
    }
    impl<F: AsFd> Drop for Restore<F> {
        fn drop(&mut self) {
            if !self.restored {
                let _ = self.restore();
            }
        }
    }

    pub(super) fn read(deadline: Instant) -> io::Result<Zeroizing<String>> {
        let stdin = io::stdin();
        read_from(&stdin, deadline)
    }

    pub(super) fn read_from(stdin: &impl AsFd, deadline: Instant) -> io::Result<Zeroizing<String>> {
        read_from_ready(stdin, deadline, || Ok(()))
    }

    pub(super) fn read_from_ready(
        stdin: &impl AsFd,
        deadline: Instant,
        ready: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Zeroizing<String>> {
        read_from_handoff(stdin, deadline, ready, || Ok(()))
    }

    // Private deterministic handoff seam; production supplies a no-op. Keeping
    // this after mode restoration exercises signals in the actual late window,
    // not merely a signal already observed by the input loop.
    fn read_from_handoff(
        stdin: &impl AsFd,
        deadline: Instant,
        ready: impl FnOnce() -> io::Result<()>,
        before_signal_restore: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Zeroizing<String>> {
        INTERRUPTED.store(false, Ordering::Relaxed);
        let mut signals = Signals(Vec::new());
        let handler = SigAction::new(
            SigHandler::Handler(interrupt),
            SaFlags::empty(),
            SigSet::empty(),
        );
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ] {
            // SAFETY: interrupt is an async-signal-safe static atomic store.
            // Save the exact prior action before any terminal mutation.
            let previous = unsafe { sigaction(signal, &handler)? };
            signals.0.push((signal, previous));
        }
        let original = tcgetattr(stdin)?;
        let mut mode = quiet_mode(&original);
        mode.local_flags.remove(LocalFlags::ICANON);
        // Poll is readiness, not a guarantee that a subsequent blocking read
        // cannot stall. MIN=TIME=0 makes every read itself nonblocking without
        // changing shared descriptor flags or leaving an input thread behind.
        mode.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        mode.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        let mut restore = Restore {
            stdin,
            original,
            restored: false,
        };
        tcsetattr(stdin, SetArg::TCSANOW, &mode)?;
        let outcome = (|| {
            remaining(deadline)?;
            ready()?;
            let mut bytes = Zeroizing::new(Vec::new());
            loop {
                let remaining = remaining(deadline)?;
                let mut fds = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
                let timeout = PollTimeout::try_from(remaining.min(Duration::from_millis(100)))
                    .unwrap_or(PollTimeout::MAX);
                match poll(&mut fds, timeout) {
                    Ok(0) => continue,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(error) => return Err(error.into()),
                    _ => {}
                }
                let events = fds[0]
                    .revents()
                    .ok_or_else(|| io::Error::other("invalid terminal readiness event"))?;
                if events.contains(PollFlags::POLLNVAL) {
                    return Err(io::Error::other("invalid terminal input descriptor"));
                }
                if !events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
                    continue;
                }
                let mut byte = [0];
                match nix::unistd::read(stdin, &mut byte) {
                    Ok(0) if events.contains(PollFlags::POLLHUP) => return Err(cancelled()),
                    Ok(0) if events.contains(PollFlags::POLLERR) => {
                        return Err(io::Error::other("terminal input failed"));
                    }
                    Ok(0) => continue, // Empty nonblocking read, not EOF.
                    Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
                    Err(error) => return Err(error.into()),
                    Ok(_) => {}
                }
                match byte[0] {
                    b'\r' | b'\n' => {
                        return std::str::from_utf8(&bytes)
                            .map(|text| Zeroizing::new(text.to_owned()))
                            .map_err(|_| io::Error::other("value requires UTF-8"));
                    }
                    3 | 4 | 27 => return Err(cancelled()),
                    8 | 127 => {
                        // Delete one complete UTF-8 character, not just its last byte.
                        while bytes.pop().is_some_and(|byte| byte & 0xc0 == 0x80) {}
                    }
                    byte => {
                        if bytes.len() >= 64 * 1024 {
                            return Err(io::Error::other("value exceeds input limit"));
                        }
                        bytes.push(byte);
                    }
                }
            }
        })();
        restore.restore()?;
        before_signal_restore()?;
        signals.restore()?;
        let value = outcome?;
        // The last read/Enter is not the cancellation handoff. A scoped handler
        // can run during terminal cleanup or signal-action restoration. Check
        // AFTER all prior actions are back, while the public reader lock is
        // still held; a competing reader cannot clear this cancellation flag.
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Err(cancelled()); // value is zeroized on this path.
        }
        Ok(value)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use nix::pty::openpty;
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, OwnedFd};

        // Private readiness/error branch: verify prompt publication is inside
        // the real quiet-mode guard and a failed prompt restores exact modes.
        #[test]
        fn prompt_readiness_is_quiet_and_prompt_error_restores_modes() {
            let _exclusive = READER.lock().unwrap();
            let pty = openpty(None, None).unwrap();
            let original = tcgetattr(&pty.slave).unwrap();
            let read_only = std::fs::OpenOptions::new()
                .read(true)
                .open(nix::unistd::ttyname(&pty.slave).unwrap())
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let outcome = read_from_ready(&pty.slave, deadline, || {
                let active = tcgetattr(&pty.slave)?;
                assert!(
                    !active.local_flags.intersects(
                        LocalFlags::ECHO
                            | LocalFlags::ECHONL
                            | LocalFlags::ISIG
                            | LocalFlags::ICANON
                    ),
                    "prompt published before quiet mode"
                );
                write_prompt(&read_only, b"synthetic prompt", deadline)
            });
            assert_eq!(outcome.unwrap_err().raw_os_error(), Some(nix::libc::EBADF));
            assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
        }

        // Private late-handoff branch is otherwise timing-dependent. Deliver
        // a real signal after Enter/cleanup and exercise the public lock too.
        #[test]
        fn accepted_enter_cannot_return_a_secret_after_handoff_cancellation() {
            use std::sync::atomic::AtomicUsize;
            static PREVIOUS_CALLS: AtomicUsize = AtomicUsize::new(0);
            extern "C" fn previous_handler(_: i32) {
                PREVIOUS_CALLS.fetch_add(1, Ordering::Relaxed);
            }
            let _exclusive = READER.lock().unwrap();
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGUSR1);
            let previous = SigAction::new(
                SigHandler::Handler(previous_handler),
                SaFlags::SA_RESTART,
                mask,
            );
            // SAFETY: reader lock serializes this test with other in-process
            // signal owners in this module. Handler only updates an atomic.
            let saved = unsafe { sigaction(Signal::SIGTERM, &previous).unwrap() };
            let _restore_previous = Signals(vec![(Signal::SIGTERM, saved)]);
            for late_signal in [false, true] {
                PREVIOUS_CALLS.store(0, Ordering::Relaxed);
                let pty = openpty(None, None).unwrap();
                let original = tcgetattr(&pty.slave).unwrap();
                let mut master = std::fs::File::from(pty.master);
                let result = read_from_handoff(
                    &pty.slave,
                    Instant::now() + Duration::from_secs(1),
                    || master.write_all(b"synthetic-value\n"),
                    || {
                        assert_eq!(tcgetattr(&pty.slave)?, original);
                        if late_signal {
                            nix::sys::signal::raise(Signal::SIGTERM)?;
                            assert!(INTERRUPTED.load(Ordering::Relaxed));
                        }
                        // A concurrent API call must refuse before resetting the
                        // flag or changing the currently installed dispositions.
                        let competing = std::thread::spawn(|| {
                            [
                                crate::read(Duration::ZERO),
                                crate::read_controlling("", Duration::ZERO),
                            ]
                        })
                        .join()
                        .unwrap();
                        for refusal in competing {
                            assert_eq!(
                                refusal.unwrap_err().to_string(),
                                "terminal input is already in use"
                            );
                        }
                        assert_eq!(INTERRUPTED.load(Ordering::Relaxed), late_signal);
                        assert_eq!(PREVIOUS_CALLS.load(Ordering::Relaxed), 0);
                        Ok(())
                    },
                );
                if late_signal {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
                } else {
                    assert_eq!(&*result.unwrap(), "synthetic-value");
                }
                assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
                // Reinstalling the same action returns its complete current
                // disposition; verify handler, flags and mask, not just SIG_DFL.
                // SAFETY: same exclusive ownership and atomic handler as above.
                let restored = unsafe { sigaction(Signal::SIGTERM, &previous).unwrap() };
                assert_eq!(restored.handler(), previous.handler());
                assert_eq!(restored.flags(), previous.flags());
                assert_eq!(restored.mask(), previous.mask());
                nix::sys::signal::raise(Signal::SIGTERM).unwrap();
                assert_eq!(PREVIOUS_CALLS.load(Ordering::Relaxed), 1);
            }
        }

        fn available(fd: &OwnedFd) -> io::Result<usize> {
            let mut count: nix::libc::c_int = 0;
            // SAFETY: the owned PTY descriptor is live; FIONREAD writes one
            // c_int to this initialized local. It does not consume input.
            if unsafe { nix::libc::ioctl(fd.as_raw_fd(), nix::libc::FIONREAD, &mut count) } < 0 {
                return Err(io::Error::last_os_error());
            }
            usize::try_from(count).map_err(|_| io::Error::other("invalid queued-byte count"))
        }

        fn inject(master: &mut std::fs::File, slave: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
            // Querying readiness also forces Darwin's PENDIN replay. Linux
            // can defer PTY input processing, so acknowledge the entire burst,
            // not merely that a previous complete line is readable.
            let expected = available(slave)? + bytes.len();
            master.write_all(bytes)?;
            let deadline = Instant::now() + Duration::from_millis(500);
            while available(slave)? < expected {
                assert!(
                    Instant::now() < deadline,
                    "test input did not reach the terminal discipline"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }

        #[test]
        fn transition_arrivals_are_not_echoed_before_the_cleanup_flush() {
            for (canonical, pending) in [(true, false), (true, true), (false, false)] {
                let pty = openpty(None, None).unwrap();
                let mut original = tcgetattr(&pty.slave).unwrap();
                original.local_flags.set(LocalFlags::ICANON, canonical);
                original.local_flags.set(LocalFlags::PENDIN, pending);
                original
                    .local_flags
                    .insert(LocalFlags::ECHO | LocalFlags::ISIG);
                tcsetattr(&pty.slave, SetArg::TCSANOW, &original).unwrap();
                let original = tcgetattr(&pty.slave).unwrap();
                let mut active = original.clone();
                active.local_flags.remove(
                    LocalFlags::ECHO
                        | LocalFlags::ECHONL
                        | LocalFlags::ISIG
                        | LocalFlags::IEXTEN
                        | LocalFlags::ICANON
                        | LocalFlags::PENDIN,
                );
                tcsetattr(&pty.slave, SetArg::TCSANOW, &active).unwrap();
                let flags = OFlag::from_bits_retain(fcntl(&pty.master, FcntlArg::F_GETFL).unwrap());
                fcntl(&pty.master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
                let mut master = std::fs::File::from(pty.master);
                inject(&mut master, &pty.slave, b"AFTER-ENTER-SENTINEL\n").unwrap();
                let mut operations = 0;
                let mut modes = 0;
                let mut transition_flags = None;
                let mut transition_input_flags = None;
                restore_mode(&original, |operation| {
                    match operation {
                        RestoreOp::FlushInput => tcflush(&pty.slave, FlushArg::TCIFLUSH)?,
                        RestoreOp::SetMode(mode) => {
                            tcsetattr(&pty.slave, SetArg::TCSANOW, mode)?;
                            modes += 1;
                            if modes == 1 {
                                let attributes = tcgetattr(&pty.slave)?;
                                let flags = attributes.local_flags;
                                transition_flags = Some(flags);
                                transition_input_flags = Some(attributes.input_flags);
                                // This input also forces Darwin to replay any
                                // raw bytes retained under generated PENDIN.
                                inject(&mut master, &pty.slave, b"AFTER-CANCEL-SENTINEL\n")?;
                                if !flags.contains(LocalFlags::ISIG) {
                                    inject(&mut master, &pty.slave, b"\x03\n")?;
                                }
                            }
                        }
                    }
                    operations += 1;
                    if operations == 1 {
                        inject(&mut master, &pty.slave, b"AFTER-ENTER-SENTINEL\n")?;
                    }
                    Ok(())
                })
                .unwrap();
                let mut output = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    match master.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => {
                            output.extend_from_slice(&chunk[..count]);
                            assert!(output.len() <= 64 * 1024);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("cannot read transition transcript: {error}"),
                    }
                }
                for marker in [
                    b"AFTER-ENTER-SENTINEL".as_slice(),
                    b"AFTER-CANCEL-SENTINEL".as_slice(),
                ] {
                    assert!(
                        !output.windows(marker.len()).any(|part| part == marker),
                        "hidden transition input echoed: canonical={canonical}, pending={pending}"
                    );
                }
                assert!(!transition_flags.unwrap().intersects(
                    LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ISIG | LocalFlags::IEXTEN
                ));
                assert!(
                    !transition_input_flags
                        .unwrap()
                        .contains(nix::sys::termios::InputFlags::IXON)
                );
                assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
                let flags = OFlag::from_bits_retain(fcntl(&pty.slave, FcntlArg::F_GETFL).unwrap());
                fcntl(&pty.slave, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
                assert!(matches!(
                    nix::unistd::read(&pty.slave, &mut chunk),
                    Err(nix::errno::Errno::EAGAIN)
                ));
            }
        }

        #[test]
        fn preparation_errors_never_enable_original_echo_or_signals() {
            let pty = openpty(None, None).unwrap();
            let mut original = tcgetattr(&pty.slave).unwrap();
            original
                .local_flags
                .insert(LocalFlags::ECHO | LocalFlags::ISIG | LocalFlags::ICANON);
            for fail_at in [1, 2] {
                let mut operations = 0;
                let mut original_enabled = false;
                let result = restore_mode(&original, |operation| {
                    operations += 1;
                    if let RestoreOp::SetMode(mode) = operation {
                        original_enabled |= mode
                            .local_flags
                            .intersects(LocalFlags::ECHO | LocalFlags::ISIG);
                        assert_eq!(
                            mode.local_flags.contains(LocalFlags::ICANON),
                            original.local_flags.contains(LocalFlags::ICANON)
                        );
                    }
                    if operations == fail_at {
                        Err(io::Error::other("injected preparation failure"))
                    } else {
                        Ok(())
                    }
                });
                assert!(result.is_err());
                assert_eq!(
                    operations, fail_at,
                    "failed preparation fell through to restoration"
                );
                assert!(!original_enabled);
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
                GetStdHandle, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW, STD_INPUT_HANDLE,
                SetConsoleMode,
            },
            Threading::WaitForSingleObject,
        },
    };
    struct Restore(HANDLE, u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: console handle belongs to this process and remains open.
            unsafe {
                SetConsoleMode(self.0, self.1);
            }
        }
    }

    pub(super) fn read(deadline: Instant) -> io::Result<Zeroizing<String>> {
        // SAFETY: all pointers refer to initialized local values; handles are
        // checked before use. No async I/O or worker survives this function.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return Err(io::Error::last_os_error());
            }
            let restore = Restore(handle, mode);
            if SetConsoleMode(
                handle,
                mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let outcome = (|| {
                let mut units = Zeroizing::new(Vec::<u16>::new());
                loop {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(timed_out)?;
                    let millis =
                        u32::try_from(remaining.as_millis().max(1)).unwrap_or(u32::MAX - 1);
                    match WaitForSingleObject(handle, millis) {
                        WAIT_TIMEOUT => continue,
                        WAIT_OBJECT_0 => {}
                        _ => return Err(io::Error::last_os_error()),
                    }
                    let mut record: INPUT_RECORD = std::mem::zeroed();
                    let mut count = 0;
                    if ReadConsoleInputW(handle, &mut record, 1, &mut count) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if count == 0 || record.EventType != KEY_EVENT as u16 {
                        continue;
                    }
                    let key = record.Event.KeyEvent;
                    if key.bKeyDown == 0 {
                        continue;
                    }
                    let unit = key.uChar.UnicodeChar;
                    for _ in 0..key.wRepeatCount {
                        match unit {
                            13 | 10 => {
                                return String::from_utf16(&units)
                                    .map(Zeroizing::new)
                                    .map_err(|_| io::Error::other("value requires valid Unicode"));
                            }
                            3 | 4 | 27 => return Err(cancelled()),
                            8 => {
                                if units
                                    .pop()
                                    .is_some_and(|unit| (0xdc00..=0xdfff).contains(&unit))
                                {
                                    units.pop();
                                }
                            }
                            0 => {}
                            unit => {
                                if units.len() >= 64 * 1024 {
                                    return Err(io::Error::other("value exceeds input limit"));
                                }
                                units.push(unit);
                            }
                        }
                    }
                }
            })();
            if SetConsoleMode(handle, restore.1) == 0 {
                return Err(io::Error::last_os_error());
            }
            drop(restore);
            outcome
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) fn read(_: Instant) -> io::Result<Zeroizing<String>> {
        Err(io::Error::other(
            "terminal value input is unsupported on this platform",
        ))
    }
}
