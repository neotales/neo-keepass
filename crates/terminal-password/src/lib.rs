//! Synchronous secret input: no reader thread, no global event queue.
//! The saved terminal mode is restored on every normal return and unwind.
use std::io;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Reads UTF-8 from terminal stdin without echo, bounded by an absolute deadline.
/// Redirected stdin is refused. Enter submits; Ctrl-C, Ctrl-D and Escape cancel.
/// Terminal state is restored before returning, including on timeout.
/// On Unix, unconsumed terminal input is discarded when the prompt ends.
/// Hidden typeahead cannot be echoed or read as a command after restoration.
///
/// # Process-wide ownership
/// On Unix this call temporarily owns the process-wide SIGINT, SIGTERM, SIGHUP
/// and SIGQUIT actions. The caller must ensure that no other thread, component
/// or library concurrently changes those actions until this call returns.
/// Restoration reinstalls the saved actions and would overwrite concurrent
/// changes. The internal lock excludes other calls to this function only; it
/// does not coordinate external signal-action installers. Likewise, no other
/// consumer may read terminal stdin concurrently.
///
/// # Errors
/// Refuses nonterminal or concurrent input, cancellation, expired deadlines,
/// invalid Unicode, oversized values, and terminal I/O or restoration errors.
pub fn read(timeout: Duration) -> io::Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    static READER: std::sync::Mutex<()> = std::sync::Mutex::new(());
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

    struct Restore<'a> {
        stdin: &'a io::Stdin,
        original: Termios,
        restored: bool,
    }
    impl Restore<'_> {
        fn restore(&mut self) -> io::Result<()> {
            // Do not replay unread secret typeahead with echo/signals enabled.
            // TCIFLUSH does not wait for output, unlike TCSAFLUSH/TCSADRAIN.
            let flushed = tcflush(self.stdin, FlushArg::TCIFLUSH);
            // A failed flush must not prevent the attempt to restore modes.
            let mode_restored = tcsetattr(self.stdin, SetArg::TCSANOW, &self.original);
            let settled = if mode_restored.is_ok()
                && self.original.local_flags.contains(LocalFlags::ICANON)
                && !self.original.local_flags.contains(LocalFlags::PENDIN)
            {
                // Darwin/BSD's TIOCSETA sets PENDIN on raw -> canonical even
                // with empty queues, and ORs it into the supplied mode. A
                // second tcsetattr cannot clear it. TCIFLUSH clears that
                // generated pending-input state without draining output or
                // replaying hidden bytes. Preserve PENDIN if originally set.
                tcflush(self.stdin, FlushArg::TCIFLUSH)
            } else {
                Ok(())
            };
            self.restored = flushed.is_ok() && mode_restored.is_ok() && settled.is_ok();
            mode_restored?;
            flushed?;
            settled?;
            Ok(())
        }
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            if !self.restored {
                let _ = self.restore();
            }
        }
    }

    pub(super) fn read(deadline: Instant) -> io::Result<Zeroizing<String>> {
        let stdin = io::stdin();
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
        let original = tcgetattr(&stdin)?;
        let mut mode = original.clone();
        mode.local_flags.remove(
            LocalFlags::ECHO
                | LocalFlags::ECHONL
                | LocalFlags::ICANON
                | LocalFlags::ISIG
                | LocalFlags::IEXTEN,
        );
        mode.input_flags.remove(nix::sys::termios::InputFlags::IXON);
        // Poll is readiness, not a guarantee that a subsequent blocking read
        // cannot stall. MIN=TIME=0 makes every read itself nonblocking without
        // changing shared descriptor flags or leaving an input thread behind.
        mode.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        mode.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        let mut restore = Restore {
            stdin: &stdin,
            original,
            restored: false,
        };
        tcsetattr(&stdin, SetArg::TCSANOW, &mode)?;
        let outcome = (|| {
            let mut bytes = Zeroizing::new(Vec::new());
            loop {
                if INTERRUPTED.load(Ordering::Relaxed) {
                    return Err(cancelled());
                }
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(timed_out)?;
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
                match nix::unistd::read(&stdin, &mut byte) {
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
        signals.restore()?;
        outcome
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
