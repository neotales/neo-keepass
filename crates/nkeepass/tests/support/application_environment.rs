//! Test-only isolation for the application's environment configuration.

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::Command;

/// Owns a child command and its disposable home directory until the command
/// has completed and the fixture is dropped.
pub struct IsolatedCommand {
    command: Command,
    _home: tempfile::TempDir,
}

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
            _home: home,
        }
    }

    /// Returns the temporary home that backs this command's sanitized defaults.
    #[must_use]
    pub fn home(&self) -> &Path {
        self._home.path()
    }
}

impl Deref for IsolatedCommand {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

impl DerefMut for IsolatedCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.command
    }
}

/// Wraps a command with an owned, sanitized home/XDG environment.
pub trait IsolatedApplicationEnvironment {
    fn isolate_application_environment(self) -> IsolatedCommand;
}

impl IsolatedApplicationEnvironment for Command {
    fn isolate_application_environment(self) -> IsolatedCommand {
        IsolatedCommand::new(self)
    }
}
