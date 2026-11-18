//! Test-only isolation for the application's environment configuration.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};

/// Owns a child command and its disposable home directory until the command
/// has completed and the fixture is dropped.
pub struct IsolatedCommand {
    command: Command,
    stdin_set: bool,
    stdout_set: bool,
    stderr_set: bool,
    stdout_capture: Option<File>,
    stderr_capture: Option<File>,
    home: Option<tempfile::TempDir>,
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
            stdin_set: false,
            stdout_set: false,
            stderr_set: false,
            stdout_capture: None,
            stderr_capture: None,
            home: Some(home),
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
        self.stdout_capture = None;
        self.stdout_set = true;
        self
    }

    /// Configures the child's standard error.
    pub fn stderr(&mut self, cfg: std::process::Stdio) -> &mut Self {
        self.command.stderr(cfg);
        self.stderr_capture = None;
        self.stderr_set = true;
        self
    }

    /// Capture output in private temporary files, not pipes. This fixture
    /// waits only for the direct child: callers must not depend on output
    /// from descendants or leave descendants using the isolated home.
    pub fn capture_stdout(&mut self) -> &mut Self {
        let file = tempfile::tempfile_in(self.home()).expect("create private stdout capture");
        self.command
            .stdout(file.try_clone().expect("clone stdout capture"));
        self.stdout_set = true;
        self.stdout_capture = Some(file);
        self
    }

    /// Capture direct-child stderr in a private temporary file.
    pub fn capture_stderr(&mut self) -> &mut Self {
        let file = tempfile::tempfile_in(self.home()).expect("create private stderr capture");
        self.command
            .stderr(file.try_clone().expect("clone stderr capture"));
        self.stderr_set = true;
        self.stderr_capture = Some(file);
        self
    }

    /// Runs to completion and collects output while retaining the isolated home.
    pub fn output(&mut self) -> io::Result<Output> {
        if !self.stdin_set {
            self.command.stdin(Stdio::null());
        }
        if !self.stdout_set {
            self.capture_stdout();
        }
        if !self.stderr_set {
            self.capture_stderr();
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
        // Command retains configured handles after spawn. Release them before
        // the home is removed, particularly for delete-on-close on Windows.
        self.command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(IsolatedChild {
            child: Some(child),
            stdout_capture: self.stdout_capture.take(),
            stderr_capture: self.stderr_capture.take(),
            _home: home,
            reaped: false,
        })
    }
}

/// A spawned child that keeps its isolated home alive until the child is
/// reaped, and kills/reaps it if the guard is dropped early.
pub struct IsolatedChild {
    child: Option<Child>,
    stdout_capture: Option<File>,
    stderr_capture: Option<File>,
    _home: tempfile::TempDir,
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
        // The sole piped stdout use takes and closes the reader before this
        // call to exercise EPIPE. Never wait for EOF from an inherited pipe.
        if child.stdout.is_some() || child.stderr.is_some() {
            return Err(io::Error::other(
                "piped output must be taken before waiting",
            ));
        }
        let status = self.wait()?;
        let stdout = read_capture(self.stdout_capture.take())?;
        let stderr = read_capture(self.stderr_capture.take())?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl IsolatedChild {
    fn kill_and_reap(&mut self) {
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

fn read_capture(file: Option<File>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(mut file) = file {
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut bytes)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::IsolatedApplicationEnvironment;
    use std::process::Command;

    #[test]
    fn captured_output_and_home_are_cleaned_up() {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
        let home = command.home().to_path_buf();
        let output = command.arg("--help").output().unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
        assert!(!home.exists());
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
