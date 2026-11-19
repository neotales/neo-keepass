//! Synchronous secret input: no reader thread, no global event queue.
//! The saved terminal mode is restored on every normal return and unwind.
use std::io;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Reads UTF-8 from terminal stdin without echo, bounded by an absolute deadline.
/// Redirected stdin is refused. Enter submits; Ctrl-C, Ctrl-D and Escape cancel.
/// Terminal state is restored before returning, including on timeout.
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
        LocalFlags, SetArg, SpecialCharacterIndices, Termios, tcgetattr, tcsetattr,
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

    struct Restore<'a>(&'a io::Stdin, Termios);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = tcsetattr(self.0, SetArg::TCSANOW, &self.1);
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
        mode.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
        mode.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
        let restore = Restore(&stdin, original);
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
                let mut byte = [0];
                if nix::unistd::read(&stdin, &mut byte)? == 0 {
                    return Err(cancelled());
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
        tcsetattr(&stdin, SetArg::TCSANOW, &restore.1)?;
        drop(restore);
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
