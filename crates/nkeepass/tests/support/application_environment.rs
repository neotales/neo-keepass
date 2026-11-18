//! Test-only isolation for the application's environment configuration.

use std::process::Command;
use std::sync::OnceLock;

static TEST_HOME: OnceLock<tempfile::TempDir> = OnceLock::new();

/// Removes all supported application configuration names from a child
/// process before a test adds the variables it intends to exercise.
pub trait IsolatedApplicationEnvironment {
    fn isolate_application_environment(&mut self) -> &mut Command;
}

impl IsolatedApplicationEnvironment for Command {
    fn isolate_application_environment(&mut self) -> &mut Command {
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
        ] {
            self.env_remove(name);
        }
        let home = TEST_HOME.get_or_init(|| {
            tempfile::Builder::new()
                .prefix("neo-keepass-test-")
                .tempdir()
                .unwrap()
        });
        self.env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"));
        self
    }
}
