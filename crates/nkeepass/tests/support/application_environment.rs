//! Remove ambient application overrides without changing subprocess semantics.
use std::process::Command;

pub trait IsolatedApplicationEnvironment {
    fn isolate_application_environment(self) -> Command;
}

impl IsolatedApplicationEnvironment for Command {
    fn isolate_application_environment(mut self) -> Command {
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
        self
    }
}

#[cfg(test)]
mod tests {
    use super::IsolatedApplicationEnvironment;
    use std::ffi::OsStr;
    use std::process::Command;

    #[test]
    fn removes_aliases_without_replacing_explicit_homes() {
        let mut command = Command::new("unused");
        for suffix in [
            "PASSWORD",
            "VAULT",
            "VAULT_PATH",
            "CONFIG_DIR",
            "DATA_DIR",
            "COMPLETE_PASSWORD_ENV",
        ] {
            for prefix in ["NEO_KEEPASS_", "NKP_", "NKEEPASS_"] {
                command.env(format!("{prefix}{suffix}"), "canary");
            }
        }
        command
            .env("XDG_CONFIG_DIR", "canary")
            .env("XDG_DATA_DIR", "canary")
            .env("HOME", "owned-home")
            .env("XDG_CONFIG_HOME", "owned-config")
            .env("XDG_DATA_HOME", "owned-data");
        let command = command.isolate_application_environment();
        let envs: Vec<_> = command.get_envs().collect();
        for suffix in [
            "PASSWORD",
            "VAULT",
            "VAULT_PATH",
            "CONFIG_DIR",
            "DATA_DIR",
            "COMPLETE_PASSWORD_ENV",
        ] {
            for prefix in ["NEO_KEEPASS_", "NKP_", "NKEEPASS_"] {
                let name = format!("{prefix}{suffix}");
                assert!(
                    envs.iter()
                        .any(|(key, value)| *key == OsStr::new(&name) && value.is_none()),
                    "{name}"
                );
            }
        }
        for (name, expected) in [
            ("HOME", "owned-home"),
            ("XDG_CONFIG_HOME", "owned-config"),
            ("XDG_DATA_HOME", "owned-data"),
        ] {
            assert!(envs.iter().any(
                |(key, value)| *key == OsStr::new(name) && *value == Some(OsStr::new(expected))
            ));
        }
        for name in ["XDG_CONFIG_DIR", "XDG_DATA_DIR"] {
            assert!(
                envs.iter()
                    .any(|(key, value)| *key == OsStr::new(name) && value.is_none())
            );
        }
    }
}
