"""UI-only PTY checks. Never print captured terminal data or OS error details."""
import codecs
import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time


class Screen:
    """Cursor/erase CSI subset emitted by the pinned Crossterm backend."""
    def __init__(self, reply):
        self.cells = [[" "] * 40 for _ in range(12)]
        self.x = self.y = 0
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.reply = reply

    def feed(self, chunk):
        self.pending += self.decoder.decode(chunk)
        while self.pending:
            if self.pending.startswith("\x1b"):
                match = re.match(r"\x1b\[([0-9;?]*)([@-~])", self.pending)
                if not match:
                    return
                parameters, command = match.groups()
                self.pending = self.pending[match.end():]
                values = [int(v) if v else 1 for v in parameters.lstrip("?").split(";")]
                if command in ("H", "f"):
                    self.y = max(0, min(11, values[0] - 1))
                    self.x = max(0, min(39, (values[1] if len(values) > 1 else 1) - 1))
                elif command == "J" or (command == "h" and parameters == "?1049"):
                    self.cells = [[" "] * 40 for _ in range(12)]
                elif command == "K":
                    self.cells[self.y][self.x:] = [" "] * (40 - self.x)
                elif command == "n" and parameters == "6":
                    self.reply(("\x1b[%d;%dR" % (self.y + 1, self.x + 1)).encode("ascii"))
                continue
            character = self.pending[0]
            self.pending = self.pending[1:]
            if character == "\r":
                self.x = 0
            elif character == "\n":
                self.y = min(11, self.y + 1)
            elif character >= " ":
                self.cells[self.y][self.x] = character
                self.x = min(39, self.x + 1)

    def text(self):
        return "\n".join("".join(row) for row in self.cells)


def check(value, label):
    if not value:
        raise AssertionError(label)


def terminal_operation(stage, operation, *args):
    try:
        return operation(*args)
    except (OSError, termios.error) as error:
        number = error.args[0] if error.args and isinstance(error.args[0], int) else "unknown"
        raise AssertionError("PTY terminal operation failed: " + stage + " / errno=" + str(number)) from None


def check_restored(slave, initial_attributes):
    restored = terminal_operation("read restored attributes", termios.tcgetattr, slave)
    names = ("iflag", "oflag", "cflag", "lflag", "ispeed", "ospeed", "cc")
    changed = [name for name, before, after in zip(names, initial_attributes, restored) if before != after]
    # Compare every termios component, including control characters and speeds.
    # Report names only, never terminal contents or raw OS exception messages.
    check(restored == initial_attributes, "terminal attributes not restored (changed: " + (",".join(changed) or "shape") + ")")


def write_pty(master, data, deadline):
    pending = memoryview(data)
    while pending:
        remaining = deadline - time.monotonic()
        check(remaining > 0, "PTY write deadline exceeded")
        try:
            if not select.select([], [master], [], min(remaining, 0.03))[1]:
                continue
            written = os.write(master, pending[:65536])
            check(written > 0, "PTY write made no progress")
            pending = pending[written:]
        except (BlockingIOError, InterruptedError):
            continue


def run(binary, vault, mode):
    master, slave = pty.openpty()
    process = None
    def own_terminal():
        # The DRIVER must outlive the app as the controlling session leader.
        # Darwin revokes the controlling terminal when its leader exits, so
        # making the app the leader invalidates our post-exit tcgetattr check.
        terminal_operation("create driver session", os.setsid)
        terminal_operation("acquire driver terminal", fcntl.ioctl, slave, termios.TIOCSCTTY, 0)
        check(os.getsid(0) == os.getpid(), "driver session ownership not established")
        foreground = terminal_operation("read foreground group", os.tcgetpgrp, slave)
        check(foreground == os.getpgrp(), "driver terminal is not foreground")

    transcript = bytearray()
    screen = Screen(lambda response: send(response))
    deadline = time.monotonic() + 20
    state = "startup"

    def pump():
        check(time.monotonic() < deadline, "PTY deadline: " + mode + " / " + state)
        if select.select([master], [], [], 0.03)[0]:
            try:
                chunk = os.read(master, 65536)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            transcript.extend(chunk)
            screen.feed(chunk)

    def wait_for(text, absent=False, within=None):
        nonlocal state
        state = ("hide " if absent else "show ") + text
        local_deadline = deadline if within is None else time.monotonic() + within
        while (text in screen.text()) == absent:
            check(time.monotonic() < local_deadline, "UI response deadline: " + mode + " / " + state)
            check(process.poll() is None, "PTY exited: " + mode + " / " + state)
            pump()

    def send(keys):
        write_pty(master, keys, deadline)

    def watchdog_termination(_signal, _frame):
        raise AssertionError("PTY driver watchdog termination")

    try:
        signal.signal(signal.SIGTERM, watchdog_termination)
        terminal_operation("make PTY master nonblocking", os.set_blocking, master, False)
        terminal_operation("set window size", fcntl.ioctl, slave, termios.TIOCSWINSZ, struct.pack("HHHH", 12, 40, 0, 0))
        initial_attributes = terminal_operation("read initial attributes", termios.tcgetattr, slave)
        own_terminal()
        command = [binary, "tui", vault]
        if mode.startswith("stopped-"):
            command = [sys.executable, "-c", """
import os, signal, tty
tty.setraw(0)
os.kill(os.getpid(), signal.SIGSTOP)
"""]
        if mode.startswith("terminal-lifetime"):
            # A fast disposable child proves the harness owns the living
            # controlling session. A second probe deliberately leaves ECHO
            # changed, so restoration checks must reject it on every Unix.
            command = [sys.executable, "-c", """
import os, sys, termios
if os.getsid(0) != os.getppid():
    sys.exit(77)
if sys.argv[1] == "terminal-lifetime-unrestored":
    attributes = termios.tcgetattr(0)
    attributes[3] ^= termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, attributes)
""", mode]
        process = subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=slave,
            env=dict(os.environ, TERM="xterm-256color"),
            close_fds=True, cwd=os.path.dirname(vault),
        )
        if mode.startswith("stopped-"):
            with open(os.path.join(os.path.dirname(vault), "stopped-child.pid"), "w") as marker:
                marker.write(str(process.pid))
            stop_deadline = time.monotonic() + 1
            while True:
                waited, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
                if waited == process.pid:
                    check(os.WIFSTOPPED(status), "negative-control child exited instead of stopping")
                    break
                check(time.monotonic() < stop_deadline, "negative-control child did not stop")
                time.sleep(0.01)
            if mode == "stopped-driver":
                os.kill(os.getpid(), signal.SIGSTOP)
                raise AssertionError("stopped driver resumed without watchdog termination")
            deadline = time.monotonic() + 0.4
            if mode == "stopped-key-writes":
                send(b"x" * (8 * 1024 * 1024))
            else:
                for _ in range(1_000_000):
                    screen.feed(b"\x1b[6n")
            raise AssertionError("stopped child unexpectedly accepted all PTY input")
        if mode.startswith("terminal-lifetime"):
            state = "terminal lifetime probe exit"
            while process.poll() is None:
                pump()
            check(process.returncode == 0, "PTY child did not inherit the living driver session")
            if mode == "terminal-lifetime-ioctl-error":
                read_end, write_end = os.pipe()
                try:
                    check_restored(read_end, initial_attributes)
                finally:
                    os.close(read_end)
                    os.close(write_end)
            check_restored(slave, initial_attributes)
            return
        wait_for("Vault password: ")
        while terminal_operation("read password-prompt attributes", termios.tcgetattr, slave)[3] & termios.ECHO:
            pump()
        send(b"disposable-tui-fixture\n")
        wait_for("Example")
        if mode == "save-failure":
            send(b"e")
            wait_for("New entry title")
            send(b"Temporary\r")
            wait_for("Entry added in memory")
            send(b"q")
            wait_for("Unsaved changes")
            backup = vault + ".saved"
            os.rename(vault, backup)
            os.mkdir(vault)
            try:
                send(b"s")
                wait_for("Save failed:")
                wait_for("s save")
                wait_for("c cancel")
            finally:
                os.rmdir(vault)
                os.rename(backup, vault)
            send(b"d")
        else:
            send(b"\r")
            wait_for("Title: Example")
            if mode == "field-identity":
                wait_for("> Title", within=2)
                # Traverse beyond the compact viewport, then move back.
                for _ in range(4):
                    send(b"j")
                wait_for("> Notes", within=2)
                send(b"k")
                wait_for("> Password", within=2)
                send(b"v")
                wait_for("Reveal field: Password", within=2)
                wait_for("Type YES", within=2)
                check("REVEALED" not in screen.text(), "field disclosed before consent")
                check("disposable-reveal-marker" not in screen.text(), "field value shown before consent")
                send(b"\x1b")
                wait_for("> Password", within=2)
            elif mode == "long-field-targets":
                for _ in range(5):
                    send(b"j")
                for index, suffix in [(6, "FIRST-FIELD"), (7, "SECOND-FIELD")]:
                    send(b"v")
                    wait_for("Type YES", within=2)
                    wait_for("WARNING:", within=2)
                    wait_for("screenshots may persist.", within=2)
                    wait_for("F2 inspect full target", within=2)
                    send(b"\x1b[12~")
                    wait_for("Inspect target", within=2)
                    wait_for("Field %d/7" % index, within=2)
                    send(b"\x1b[F")
                    wait_for(suffix, within=2)
                    check("first-field-marker" not in screen.text(), "first field disclosed before consent")
                    check("second-field-marker" not in screen.text(), "second field disclosed before consent")
                    send(b"\x1b")
                    wait_for("Type YES", within=2)
                    if index == 6:
                        send(b"\x1b")
                        wait_for("Entry detail", within=2)
                        send(b"j")
                    else:
                        send(b"YES\r")
                        wait_for("second-field-marker", within=2)
                        check("first-field-marker" not in screen.text(), "wrong field revealed")
                        send(b"\x1b")
                        wait_for("second-field-marker", absent=True, within=2)
            elif mode == "reveal":
                send(b"r")
                wait_for("Type YES.")
                send(b"YES\r")
                wait_for("disposable-reveal-marker")
                send(b"?")
                pump()
                send(b"\x1b")
                # Must hide because of this Escape, not the 15-second TTL.
                wait_for("disposable-reveal-marker", absent=True, within=2)
                wait_for("REVEALED", absent=True, within=2)
            elif mode.startswith("generation-"):
                send(b"g")
                wait_for("password length")
                send(b"32\r")
                wait_for("This replaces the current password.")
                wait_for("Enter submit")
                send(b"NO\r" if mode.endswith("cancel") else b"YES\r")
                if mode.endswith("cancel"):
                    wait_for("Password generation cancelled")
                else:
                    wait_for("Password replaced in memory")
                    send(b"s")
                    wait_for("Saved")
            elif mode == "remove-confirm":
                send(b"n")
                wait_for("Selected attachment 2/2")
                send(b"d")
                wait_for("Attachment 2/2")
                wait_for("Type YES")
                send(b"\x1b[12~")
                wait_for("Inspect target")
                send(b"\x1b[F")
                wait_for("SECOND.bin")
                send(b"\x1b")
                wait_for("Remove this attachment?")
                send(b"YES\r")
                wait_for("Attachment removed")
                send(b"s")
                wait_for("Saved")
            elif mode == "targets":
                send(b"n")
                wait_for("Selected attachment 2/2")
                send(b"x")
                wait_for("Attachment 2/2")
                wait_for("F2 inspect full target")
                send(b"\x1b[12~")
                wait_for("Inspect target")
                send(b"\x1b[F")
                wait_for("SECOND.bin")
                send(b"\x1b")
                wait_for("Destination")
                send(b"selected.bin\r")
                wait_for("Attachment exported")
                send(b"d")
                wait_for("Attachment 2/2")
                wait_for("Type YES")
                send(b"\x1b[12~")
                wait_for("Inspect target")
                send(b"\x1b[F")
                wait_for("SECOND.bin")
                send(b"\x1b")
                wait_for("Remove this attachment?")
                send(b"NO\r")
                wait_for("Attachment removal cancelled")
                send(b"\x1b")
                wait_for("Title:", absent=True)
                send(b"j")
                send(b"x")
                wait_for("Entry row 2/2")
                wait_for("Type YES")
                send(b"\x1b[F")
                wait_for("TAIL")
                wait_for("Entry row 2/2")
                send(b"\x1b")
                wait_for("Confirm deletion", absent=True)
            send(b"q")
        state = "exit"
        while process.poll() is None:
            pump()
        for _ in range(3):
            pump()
        check(process.returncode == 0, "interactive TUI failed")
        check(b"disposable-tui-fixture" not in transcript, "credential echoed")
        check(b"\x1b[?1049l" in transcript, "alternate screen not restored")
        check_restored(slave, initial_attributes)
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    raise AssertionError("PTY child cleanup deadline exceeded") from None
        finally:
            # Closing our own controlling PTY can send us SIGHUP. Ignore it
            # only in final cleanup, never before spawning the app: the app
            # never inherits this disposition.
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            os.close(slave)
            os.close(master)


try:
    run(*sys.argv[1:])
except (AssertionError, OSError) as error:
    label = str(error) if isinstance(error, AssertionError) else "PTY operating-system failure"
    sys.stderr.write(label + "\n")
    sys.exit(1)
