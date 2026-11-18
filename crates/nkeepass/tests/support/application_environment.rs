//! Test-only isolation for the application's environment configuration.

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const OUTPUT_READER_JOIN_TIMEOUT: Duration = Duration::from_millis(100);

/// Owns a child command and its disposable home directory until the command
/// has completed and the fixture is dropped.
pub struct IsolatedCommand {
    command: Command,
    home: Option<tempfile::TempDir>,
    stdin_set: bool,
    stdout_set: bool,
    stderr_set: bool,
}

#[allow(
    dead_code,
    reason = "shared subprocess fixture APIs are used by different integration binaries"
)]
impl IsolatedCommand {
    /// Removes inherited application inputs and directs home/XDG paths into an
    /// owned temporary directory whose lifetime covers the command fixture.
    #[must_use]
    pub fn new(mut command: Command) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        for name in [
            "NEO_KEEPASS_PASSWORD",
            "NKP_PASSWORD",
            "NKEEPASS_PASSWORD",
            "NEO_KEEPASS_VAULT",
            "NKP_VAULT",
            "NKEEPASS_VAULT",
            "NEO_KEEPASS_VAULT_PATH",
            "NKP_VAULT_PATH",
            "NKEEPASS_VAULT_PATH",
            "NEO_KEEPASS_CONFIG_DIR",
            "NKP_CONFIG_DIR",
            "NKEEPASS_CONFIG_DIR",
            "NEO_KEEPASS_DATA_DIR",
            "NKP_DATA_DIR",
            "NKEEPASS_DATA_DIR",
            "NEO_KEEPASS_COMPLETE_PASSWORD_ENV",
            "NKP_COMPLETE_PASSWORD_ENV",
            "NKEEPASS_COMPLETE_PASSWORD_ENV",
            "XDG_CONFIG_DIR",
            "XDG_DATA_DIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "HOME",
        ] {
            command.env_remove(name);
        }
        let home = tempfile::Builder::new()
            .prefix("neo-keepass-test-")
            .tempdir()
            .expect("create isolated command home");
        command
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"));
        Self {
            command,
            home: Some(home),
            stdin_set: false,
            stdout_set: false,
            stderr_set: false,
        }
    }

    /// Returns the temporary home that backs this command's sanitized defaults.
    #[must_use]
    pub fn home(&self) -> &Path {
        self.home
            .as_ref()
            .expect("isolated home has moved into the child guard")
            .path()
    }

    /// Adds a single argument.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.command.arg(arg);
        self
    }

    /// Adds command arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(args);
        self
    }

    /// Sets one child environment variable.
    pub fn env<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.command.env(key, value);
        self
    }

    /// Removes one child environment variable.
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.command.env_remove(key);
        self
    }

    /// Clears the child environment.
    pub fn env_clear(&mut self) -> &mut Self {
        self.command.env_clear();
        self
    }

    /// Sets the child's current directory.
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.command.current_dir(dir);
        self
    }

    /// Configures the child's standard input.
    pub fn stdin(&mut self, cfg: std::process::Stdio) -> &mut Self {
        self.command.stdin(cfg);
        self.stdin_set = true;
        self
    }

    /// Configures the child's standard output.
    pub fn stdout(&mut self, cfg: std::process::Stdio) -> &mut Self {
        self.command.stdout(cfg);
        self.stdout_set = true;
        self
    }

    /// Configures the child's standard error.
    pub fn stderr(&mut self, cfg: std::process::Stdio) -> &mut Self {
        self.command.stderr(cfg);
        self.stderr_set = true;
        self
    }

    /// Runs to completion and collects output while retaining the isolated home.
    pub fn output(&mut self) -> io::Result<Output> {
        if !self.stdin_set {
            self.command.stdin(Stdio::null());
        }
        if !self.stdout_set {
            self.command.stdout(Stdio::piped());
        }
        if !self.stderr_set {
            self.command.stderr(Stdio::piped());
        }
        self.spawn()?.wait_with_output()
    }

    /// Runs to completion and returns the child's exit status.
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        if !self.stdin_set {
            self.command.stdin(Stdio::null());
        }
        self.spawn()?.wait()
    }

    /// Sets `argv[0]` on Unix.
    #[cfg(unix)]
    pub fn arg0<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        use std::os::unix::process::CommandExt;

        self.command.arg0(arg);
        self
    }

    /// Starts the subprocess and transfers ownership of its temporary home to
    /// a child guard that kills and reaps the process if dropped unfinished.
    pub fn spawn(&mut self) -> io::Result<IsolatedChild> {
        let Some(home) = self.home.take() else {
            return Err(io::Error::other(
                "isolated command can only be spawned once",
            ));
        };
        let child = match self.command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.home = Some(home);
                return Err(error);
            }
        };
        let process_group = child.id();
        Ok(IsolatedChild {
            child: Some(child),
            _home: home,
            process_group,
            reaped: false,
        })
    }
}

/// A spawned child that keeps its isolated home alive until the child is
/// reaped, and kills/reaps it if the guard is dropped early.
pub struct IsolatedChild {
    child: Option<Child>,
    _home: tempfile::TempDir,
    process_group: u32,
    reaped: bool,
}

#[allow(
    dead_code,
    reason = "shared subprocess fixture APIs are used by different integration binaries"
)]
impl IsolatedChild {
    /// Returns the temporary home inherited by the child process.
    #[must_use]
    pub fn home(&self) -> &Path {
        self._home.path()
    }

    /// Returns the child's process identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.as_ref().expect("child is present").id()
    }

    /// Takes the child's piped standard input, if present.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut().expect("child is present").stdin.take()
    }

    /// Takes the child's piped standard output, if present.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut().expect("child is present").stdout.take()
    }

    /// Waits for the child, retaining its home until this guard is dropped.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.as_mut().expect("child is present").wait()?;
        self.reaped = true;
        Ok(status)
    }

    /// Collects piped output while keeping the home alive until the child is
    /// reaped. Dropping this guard during an error or unwind kills and reaps
    /// any still-running child.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        let child = self.child.as_mut().expect("child is present");
        drop(child.stdin.take());
        let process_group = self.process_group;
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let status = match self.wait() {
            Ok(status) => status,
            Err(error) => {
                self.kill_and_reap();
                let _ = collect_output(stdout, stderr, process_group);
                return Err(error);
            }
        };
        let (stdout, stderr) = collect_output(stdout, stderr, process_group)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl IsolatedChild {
    fn kill_and_reap(&mut self) {
        terminate_process_group(self.process_group);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.reaped = true;
    }
}

impl Drop for IsolatedChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_and_reap();
        }
    }
}

type Drain = (Receiver<io::Result<Vec<u8>>>, thread::JoinHandle<()>);

fn drain<R: Read + Send + 'static>(reader: Option<R>) -> Option<Drain> {
    reader.map(|mut reader| {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = reader.read_to_end(&mut bytes).map(|_| bytes);
            let _ = sender.send(result);
        });
        (receiver, handle)
    })
}

fn collect(reader: Option<Drain>, process_group: u32) -> io::Result<Vec<u8>> {
    let Some((receiver, handle)) = reader else {
        return Ok(Vec::new());
    };
    let result = match receiver.recv_timeout(OUTPUT_DRAIN_TIMEOUT) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            terminate_process_group(process_group);
            if let Ok(result) = receiver.recv_timeout(OUTPUT_DRAIN_TIMEOUT) {
                // The reader sent its result, so joining it is immediate and
                // ensures no completed reader is left detached.
                let _ = result;
                let _ = join_finished(handle);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child output remained open after the child exited",
            ));
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err(io::Error::other("child output reader panicked"));
        }
    };
    join_finished(handle)?;
    result
}

fn join_finished(handle: thread::JoinHandle<()>) -> io::Result<()> {
    let deadline = Instant::now() + OUTPUT_READER_JOIN_TIMEOUT;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::park_timeout(Duration::from_millis(1));
    }
    if handle.is_finished() {
        handle
            .join()
            .map_err(|_| io::Error::other("child output reader panicked"))
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "child output reader did not finish promptly",
        ))
    }
}

fn collect_output(
    stdout: Option<Drain>,
    stderr: Option<Drain>,
    process_group: u32,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let stdout = collect(stdout, process_group);
    let stderr = collect(stderr, process_group);
    if stdout
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
    {
        return Err(stdout.unwrap_err());
    }
    if stderr
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
    {
        return Err(stderr.unwrap_err());
    }
    // Observe both readers before propagating a non-timeout stream error.
    Ok((stdout?, stderr?))
}

fn terminate_process_group(process_group: u32) {
    #[cfg(unix)]
    {
        let group = format!("-{process_group}");
        let _ = Command::new("kill")
            .args(["-KILL", "--", &group])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(unix))]
    let _ = process_group;
}

#[cfg(test)]
mod tests {
    use super::{Drain, collect_output};
    use std::io;
    use std::sync::mpsc;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;

    #[test]
    fn reader_failure_still_joins_the_other_stream() {
        let stderr_joined = Arc::new(AtomicBool::new(false));
        let stderr_joined_by_thread = Arc::clone(&stderr_joined);
        let stdout = Some(spawn_result(|| {
            Err(io::Error::other("injected reader failure"))
        }));
        let stderr = Some(spawn_result(move || {
            stderr_joined_by_thread.store(true, Ordering::SeqCst);
            Ok(vec![b'e'])
        }));

        assert!(collect_output(stdout, stderr, 0).is_err());
        assert!(stderr_joined.load(Ordering::SeqCst));
    }

    fn spawn_result<F>(read: F) -> Drain
    where
        F: FnOnce() -> io::Result<Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = sender.send(read());
        });
        (receiver, handle)
    }
}

/// Wraps a command with an owned, sanitized home/XDG environment.
pub trait IsolatedApplicationEnvironment {
    /// Returns a command fixture that owns its sanitized home directory.
    fn isolate_application_environment(self) -> IsolatedCommand;
}

impl IsolatedApplicationEnvironment for Command {
    fn isolate_application_environment(self) -> IsolatedCommand {
        IsolatedCommand::new(self)
    }
}
