# terminal-password

Small synchronous input boundary for `nkp set`'s hidden value prompt.

`rpassword`'s blocking reader cannot be safely abandoned on timeout. A worker
thread would retain a terminal reader after the caller returned. Crossterm's
shared event reader and Windows cooked-mode reconstruction are not an exact
saved-mode restoration boundary. This crate instead owns one synchronous
reader, waits against an absolute deadline, and restores the actual saved mode.
It does not replace the CLI's unrelated vault-password or TUI input paths.

- Unix: safe nix termios, poll and read calls; a restoration guard; temporary
  signal-hook cancellation flags for SIGINT/SIGTERM/SIGHUP/SIGQUIT. No signal
  thread. Input polling is capped at 100 ms to observe cancellation flags.
- Windows: a narrowly isolated unsafe Win32 boundary. Save `GetConsoleMode`,
  disable echo/line/processed input, then `WaitForSingleObject` and
  `ReadConsoleInputW`. Restore the exact saved bitmask, not guessed cooked-mode
  defaults. No crossterm event reader, overlapped read, or background thread.
- Enter submits; Ctrl-C, Ctrl-D and Escape cancel. Unicode backspace is
  supported; input is bounded and held in zeroizing buffers.
- A process-wide try-lock refuses concurrent calls. Callers must not run an
  independent input consumer at the same time.
- OS restoration failures are errors; drop retries restoration. Uncatchable
  process termination, including SIGKILL and forced Windows process termination,
  cannot run cleanup.

`cargo test -p terminal-password` runs bounded Unix PTY tests. Windows builds
run `tests/windows_console.rs`, using disposable child consoles for submission,
cancellation, timeout and exact-mode restoration. These Windows tests have
been added but were **not compiled or executed on the Linux implementation
host**. Native Windows validation is a release gate, not an inferred pass.

The short-duration tests exercise the same deadline loop as the CLI's fixed
60-second timeout without making every test wait a minute.
