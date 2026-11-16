#![allow(
    clippy::collapsible_match,
    clippy::items_after_statements,
    clippy::struct_excessive_bools,
    reason = "small command records keep their parser and dispatch cases together"
)]

mod clipboard;
mod completion;
#[allow(
    dead_code,
    reason = "also supplies the CLI's setx parser and format constants"
)]
mod interchange;
mod tui;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use neotales_age::{AgeFile, AgeIdentity, AgeRecipient};
use neotales_keepass::{KdbxCredentials, KdbxKdf, KdbxWriteOptions, SecretBytes, read_key_file};
use nkeepass::{
    KDBX_LIMITS, SearchHit,
    glob::Glob,
    service::{FieldUpdate, VaultService},
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use zeroize::Zeroizing;

const HELP_WIDTH: usize = 88;
const HELP_TITLE: &str = "headless KeePass CLI";

struct HelpOption {
    label: &'static str,
    summary: &'static str,
}

struct HelpCommand {
    names: &'static str,
    usage: &'static str,
    summary: &'static str,
    options: &'static [HelpOption],
    children: &'static [HelpCommand],
}

const fn help_command(
    names: &'static str,
    usage: &'static str,
    summary: &'static str,
    options: &'static [HelpOption],
    children: &'static [HelpCommand],
) -> HelpCommand {
    HelpCommand {
        names,
        usage,
        summary,
        options,
        children,
    }
}

const GLOBAL_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "-V, --vault PATH",
    summary: "Select a vault or configured alias before the command.",
}];
const GLOBAL_CREDENTIAL_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--password-env NAME",
        summary: "Read the master password from this variable; before or after a vault command.",
    },
    HelpOption {
        label: "--password-stdin",
        summary: "Read one master-password line from stdin; before or after a vault command.",
    },
];
const DEFAULT_PASSWORD_ENV: &str = "NKEEPASS_PASSWORD";
const ROOT_ONLY_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--version",
    summary: "Print version information.",
}];
const HELP_OPTION: HelpOption = HelpOption {
    label: "-h, --help",
    summary: "Show help for this command.",
};
const NO_OPTIONS: &[HelpOption] = &[];
const CREDENTIAL_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--password-env NAME",
        summary: "Read the master password from an environment variable.",
    },
    HelpOption {
        label: "--password-stdin",
        summary: "Read one password line from stdin.",
    },
    HelpOption {
        label: "--password-file PATH",
        summary: "Read one password line from a file.",
    },
    HelpOption {
        label: "--key-file PATH",
        summary: "Add a key-file credential component.",
    },
    HelpOption {
        label: "--password VALUE",
        summary: "Unsafe compatibility mode; visible in process listings and shell history.",
    },
];
const KEY_OPTION: HelpOption = HelpOption {
    label: "--key PATH",
    summary: "Select an entry by path or entry alias.",
};
const FIELD_OPTION: HelpOption = HelpOption {
    label: "--field FIELD",
    summary: "Select a field (defaults to Password where applicable).",
};
const FILE_OPTION: HelpOption = HelpOption {
    label: "--file PATH",
    summary: "Read input from a file.",
};
const STDIN_OPTION: HelpOption = HelpOption {
    label: "--stdin",
    summary: "Read input from stdin.",
};
const DRY_RUN_OPTION: HelpOption = HelpOption {
    label: "--dry-run",
    summary: "Validate and report without saving changes.",
};
const FORMAT_OPTION: HelpOption = HelpOption {
    label: "--format FORMAT",
    summary: "Choose text, JSON, null, or a supported named output format.",
};
const NAME_OPTION: HelpOption = HelpOption {
    label: "--name NAME",
    summary: "Name the output variable for a named format.",
};
const YES_OPTION: HelpOption = HelpOption {
    label: "--yes",
    summary: "Confirm a destructive operation without prompting.",
};

const CONTEXT_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls",
        "ls",
        "List configured vault aliases and paths.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "show",
        "show",
        "Show the selected vault and its source.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "use",
        "use ALIAS",
        "Select a configured vault alias.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm",
        "rm ALIAS",
        "Remove a vault alias.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set",
        "set ALIAS PATH",
        "Create or update a vault alias and its path.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
];
const ALIAS_SET_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--kind vault|entry",
        summary: "Set the alias target kind; inferred from the target by default.",
    },
    HelpOption {
        label: "--field FIELD",
        summary: "Bind an entry alias to a field.",
    },
];
const ALIAS_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls",
        "List configured aliases.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set",
        "set NAME TARGET [OPTIONS]",
        "Create or replace a validated vault or entry alias.",
        ALIAS_SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm NAME",
        "Remove an alias.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "resolve",
        "resolve NAME",
        "Show the target of an alias.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
];
const CONFIG_LS_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--json",
    summary: "Emit one JSON record per configuration key.",
}];
const CONFIG_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls [GLOB] [--json]",
        "List the closed configuration key set.",
        CONFIG_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "get|show",
        "get KEY",
        "Print one configured scalar value.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set",
        "set KEY VALUE",
        "Set a supported configuration value.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm KEY",
        "Clear a configured scalar value.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
];
const COMMON_LIST_OPTIONS: &[HelpOption] = &[];
const SEARCH_OPTIONS: &[HelpOption] = &[];
const SHOW_OPTIONS: &[HelpOption] = &[KEY_OPTION];
const GET_OPTIONS: &[HelpOption] = &[
    KEY_OPTION,
    FIELD_OPTION,
    FORMAT_OPTION,
    NAME_OPTION,
    HelpOption {
        label: "--is-output",
        summary: "Mark Azure DevOps output as an output variable.",
    },
    HelpOption {
        label: "--age-encrypt",
        summary: "Encrypt the selected value to one or more age recipients.",
    },
    HelpOption {
        label: "-r, --age-recipient KEY",
        summary: "Age/SSH key, @FILE, gh:USER, or HTTPS source; repeatable.",
    },
    HelpOption {
        label: "--output PATH",
        summary: "Write encrypted output to a private, no-clobber file.",
    },
];
const GETX_OPTIONS: &[HelpOption] = &[KEY_OPTION, FIELD_OPTION, FORMAT_OPTION];
const SET_OPTIONS: &[HelpOption] = &[
    KEY_OPTION,
    FIELD_OPTION,
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "--age-decrypt",
        summary: "Decrypt age-encrypted input before setting the field.",
    },
    HelpOption {
        label: "-i, --age-identity PATH",
        summary: "Read an age or unencrypted SSH identity from this file.",
    },
];
const RM_OPTIONS: &[HelpOption] = &[KEY_OPTION, FIELD_OPTION, YES_OPTION];
const ENSURE_OPTIONS: &[HelpOption] = &[
    KEY_OPTION,
    HelpOption {
        label: "--size N",
        summary: "Generate a password of N characters for a new entry only.",
    },
    DRY_RUN_OPTION,
];
const OTP_OPTIONS: &[HelpOption] = &[
    KEY_OPTION,
    FORMAT_OPTION,
    NAME_OPTION,
    HelpOption {
        label: "--is-output",
        summary: "Mark Azure DevOps output as an output variable.",
    },
];
const SETX_OPTIONS: &[HelpOption] = &[KEY_OPTION, FILE_OPTION, STDIN_OPTION, DRY_RUN_OPTION];
const IMPORT_OPTIONS: &[HelpOption] = &[
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "--replace",
        summary: "Allow replacing a non-empty vault.",
    },
    DRY_RUN_OPTION,
];
const EXPORT_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--output PATH",
    summary: "Write the interchange snapshot to this private output file.",
}];
const SYNC_OPTIONS: &[HelpOption] = &[
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "--strategy newest|source",
        summary: "Choose how snapshot data is synchronized.",
    },
    DRY_RUN_OPTION,
];
const ENV_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--key PATH",
        summary: "Start a value binding (repeatable).",
    },
    HelpOption {
        label: "--field FIELD",
        summary: "Select the field for the current binding; otp emits a code.",
    },
    HelpOption {
        label: "--name NAME",
        summary: "Finish a binding with its output variable name.",
    },
    FORMAT_OPTION,
    HelpOption {
        label: "--is-output",
        summary: "Mark Azure DevOps output as an output variable.",
    },
];
const ATTACHMENT_LS_OPTIONS: &[HelpOption] = &[KEY_OPTION];
const ATTACHMENT_ADD_OPTIONS: &[HelpOption] =
    &[KEY_OPTION, FIELD_OPTION, FILE_OPTION, STDIN_OPTION];
const ATTACHMENT_RM_OPTIONS: &[HelpOption] = &[KEY_OPTION, FIELD_OPTION, YES_OPTION];
const SECRETS_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls [--] [GLOB]",
        "List redacted entry metadata as JSON lines.",
        COMMON_LIST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "search",
        "search [--] QUERY",
        "Search bounded, allowlisted entry metadata.",
        SEARCH_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "env|environment",
        "env [--key PATH [--field FIELD] --name NAME]... [OPTIONS]",
        "Emit selected values in a named format.",
        ENV_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "show",
        "show --key PATH",
        "Show redacted descriptors for one entry.",
        SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "get",
        "get --key PATH [OPTIONS]",
        "Reveal one explicitly selected value.",
        GET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "getx",
        "getx --key PATH [OPTIONS]",
        "Reveal selected data as JSON.",
        GETX_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set",
        "set --key PATH [OPTIONS]",
        "Set an entry field from explicit input.",
        SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm --key PATH [OPTIONS]",
        "Remove an entry or selected field.",
        RM_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "ensure",
        "ensure --key PATH [OPTIONS]",
        "Create a missing entry and its parent groups; keep existing entries.",
        ENSURE_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "otp",
        "otp --key PATH [OPTIONS]",
        "Generate a TOTP code; never disclose the seed. HOTP is refused.",
        OTP_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "setx",
        "setx --key PATH (--file PATH|--stdin)",
        "Atomically set exact fields from bounded JSON.",
        SETX_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "import",
        "import (--file PATH|--stdin) [OPTIONS]",
        "Import a bounded interchange snapshot.",
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "export",
        "export --output PATH [OPTIONS]",
        "Write a private interchange snapshot.",
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "sync",
        "sync (--file PATH|--stdin) [OPTIONS]",
        "Synchronize a bounded interchange snapshot.",
        SYNC_OPTIONS,
        NO_COMMANDS,
    ),
];
const AUTOMATION_COMMANDS: &[HelpCommand] = &[
    help_command(
        "setx",
        "setx --key PATH (--file PATH|--stdin)",
        "Set exact fields from bounded JSON.",
        SETX_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "import",
        "import (--file PATH|--stdin) [OPTIONS]",
        "Import a bounded interchange snapshot.",
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "export",
        "export --output PATH [OPTIONS]",
        "Write a private interchange snapshot.",
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "sync",
        "sync (--file PATH|--stdin) [OPTIONS]",
        "Synchronize a bounded interchange snapshot.",
        SYNC_OPTIONS,
        NO_COMMANDS,
    ),
];
const ATTACHMENT_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls --key PATH",
        "List attachment metadata for one entry.",
        ATTACHMENT_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "add|import",
        "add --key PATH --field NAME [OPTIONS]",
        "Add an attachment from explicit input.",
        ATTACHMENT_ADD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "get|export",
        "get --key PATH --field NAME --output PATH",
        "Write one attachment to a private output file.",
        &[
            KEY_OPTION,
            FIELD_OPTION,
            HelpOption {
                label: "--output PATH",
                summary: "Private output destination; existing files are not overwritten.",
            },
        ],
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm --key PATH --field NAME --yes",
        "Remove one attachment.",
        ATTACHMENT_RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const FIELD_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls --key PATH",
        "List custom-field names for one entry.",
        SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "get|reveal",
        "get --key PATH --field FIELD [OPTIONS]",
        "Reveal one custom field.",
        GET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set|edit",
        "set --key PATH --field FIELD [OPTIONS]",
        "Set one custom field from explicit input.",
        SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm --key PATH --field FIELD",
        "Remove one custom field.",
        RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const INIT_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--size N",
        summary: "Store a generated N-character password in a new entry.",
    },
    HelpOption {
        label: "--kdf aes|argon2d|argon2id",
        summary: "Choose the key derivation function.",
    },
    HelpOption {
        label: "--memory KIB",
        summary: "Argon2 memory cost; requires an Argon2 KDF.",
    },
    HelpOption {
        label: "--iterations N",
        summary: "KDF transform rounds or time cost.",
    },
    HelpOption {
        label: "--parallelism N",
        summary: "Argon2 lanes; requires an Argon2 KDF.",
    },
];
const EXEC_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--key PATH",
        summary: "Entry to bind into the child environment (repeatable).",
    },
    HelpOption {
        label: "--field FIELD",
        summary: "Bind this field for the preceding --key; otp emits a code.",
    },
    HelpOption {
        label: "--env NAME",
        summary: "Child variable for the preceding --key (repeatable).",
    },
    HelpOption {
        label: "--password-env NAME",
        summary: "Read the master password from an environment variable.",
    },
    HelpOption {
        label: "--password-stdin",
        summary: "Read one password line from stdin.",
    },
    HelpOption {
        label: "--password-file PATH",
        summary: "Read one password line from a file.",
    },
    HelpOption {
        label: "--key-file PATH",
        summary: "Add a key-file credential component.",
    },
    HelpOption {
        label: "--password VALUE",
        summary: "Unsafe compatibility mode; visible in process listings and shell history.",
    },
];
const NO_COMMANDS: &[HelpCommand] = &[];
const GROUP_KEY_OPTION: HelpOption = HelpOption {
    label: "--key PATH",
    summary: "Select a group path, with or without the root name.",
};
const GROUP_ADD_OPTIONS: &[HelpOption] = &[GROUP_KEY_OPTION, DRY_RUN_OPTION];
const GROUP_RM_OPTIONS: &[HelpOption] = &[GROUP_KEY_OPTION, YES_OPTION, DRY_RUN_OPTION];
const GROUP_COMMANDS: &[HelpCommand] = &[
    help_command(
        "ls|list",
        "ls",
        "List group paths.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "add|create|ensure",
        "add --key PATH [--dry-run]",
        "Create missing groups; keep existing groups.",
        GROUP_ADD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm --key PATH --yes [--dry-run]",
        "Remove a group and its contents; never remove the root.",
        GROUP_RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const ROOT_COMMANDS: &[HelpCommand] = &[
    help_command(
        "tui",
        "tui PATH",
        "Open the interactive private-terminal browser.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "init",
        "init [PATH] [OPTIONS]",
        "Create a KDBX 4.1 vault; never overwrites.",
        INIT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "context",
        "context <COMMAND>",
        "Select or inspect the current vault.",
        NO_OPTIONS,
        CONTEXT_COMMANDS,
    ),
    help_command(
        "alias",
        "alias <COMMAND>",
        "Manage named vault and entry aliases.",
        NO_OPTIONS,
        ALIAS_COMMANDS,
    ),
    help_command(
        "secrets",
        "secrets <COMMAND>",
        "List, search, reveal, or manage vault data.",
        NO_OPTIONS,
        SECRETS_COMMANDS,
    ),
    help_command(
        "automation",
        "automation <COMMAND>",
        "Automation aliases for interchange operations.",
        NO_OPTIONS,
        AUTOMATION_COMMANDS,
    ),
    help_command(
        "attachment|attachments",
        "attachment <COMMAND>",
        "List or manage attachments.",
        NO_OPTIONS,
        ATTACHMENT_COMMANDS,
    ),
    help_command(
        "group|groups",
        "group <COMMAND>",
        "List, create, or remove vault groups.",
        NO_OPTIONS,
        GROUP_COMMANDS,
    ),
    help_command(
        "field|custom-field",
        "field <COMMAND>",
        "List or manage custom fields.",
        NO_OPTIONS,
        FIELD_COMMANDS,
    ),
    help_command(
        "config",
        "config <COMMAND>",
        "Inspect or change configuration.",
        NO_OPTIONS,
        CONFIG_COMMANDS,
    ),
    help_command(
        "exec|x",
        "exec [--key PATH [--field FIELD] --env NAME]... [OPTIONS] -- COMMAND [ARG ...]",
        "Run a child with selected values in its environment.",
        EXEC_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "completion",
        "completion SHELL",
        "Print static shell completion.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "version",
        "version",
        "Print version information.",
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "get",
        "get [OPTIONS]",
        "Shortcut for secrets get.",
        GET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "getx",
        "getx [OPTIONS]",
        "Shortcut for secrets getx.",
        GETX_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "list|ls",
        "ls [--] [GLOB] [OPTIONS]",
        "Shortcut for secrets ls.",
        COMMON_LIST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "search",
        "search [--] QUERY",
        "Shortcut for secrets search.",
        SEARCH_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "show",
        "show [OPTIONS]",
        "Shortcut for secrets show.",
        SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "set",
        "set [OPTIONS]",
        "Shortcut for secrets set.",
        SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "rm|remove",
        "rm [OPTIONS]",
        "Shortcut for secrets rm.",
        RM_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "ensure",
        "ensure [OPTIONS]",
        "Shortcut for secrets ensure.",
        ENSURE_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "otp",
        "otp [OPTIONS]",
        "Shortcut for secrets otp.",
        OTP_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "setx",
        "setx [OPTIONS]",
        "Shortcut for secrets setx.",
        SETX_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "import",
        "import [OPTIONS]",
        "Shortcut for secrets import.",
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "export",
        "export [OPTIONS]",
        "Shortcut for secrets export.",
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "sync",
        "sync [OPTIONS]",
        "Shortcut for secrets sync.",
        SYNC_OPTIONS,
        NO_COMMANDS,
    ),
    help_command(
        "env",
        "env [--key PATH [--field FIELD] --name NAME]... [OPTIONS]",
        "Emit selected values in a named format.",
        ENV_OPTIONS,
        NO_COMMANDS,
    ),
];

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_GLOB_PATTERN_BYTES: usize = 1024;

/// Maximum number of password bytes accepted from one `--password-stdin` line.
///
/// The terminating newline is not counted. The bound applies before UTF-8
/// decoding so oversized input cannot force an unbounded allocation.
const MAX_PASSWORD_STDIN_BYTES: usize = 64 * 1024;

/// Largest generated password `init --size` and `secrets ensure --size` accept.
///
/// A bound rather than a format limit: the value becomes a vault field, and
/// 4096 characters is far past any usable secret while still making an absurd
/// request an explicit error instead of an unbounded allocation.
const MAX_GENERATED_PASSWORD: usize = 4096;

#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    current: Option<String>,
    default_vault: Option<String>,
    aliases: BTreeMap<String, Alias>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    kind: Kind,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Vault,
    Entry,
}

/// An error, and the exit code to leave with.
///
/// The message is a `String` rather than a `&'static str` because two
/// diagnostics have to name a number -- the glob length and its limit -- and a
/// number is not attacker content. Every other message is still a literal, and
/// no diagnostic quotes its input.
#[derive(Debug)]
struct CliError(String, i32);
type Result<T> = std::result::Result<T, CliError>;

fn err(message: impl Into<String>) -> CliError {
    CliError(message.into(), 2)
}

fn validate_base_dir(path: PathBuf, unavailable: &'static str) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let namespace_component = path.components().any(|component| match component {
            Component::Prefix(prefix) => matches!(
                prefix.kind(),
                std::path::Prefix::Verbatim(_)
                    | std::path::Prefix::VerbatimUNC(_, _)
                    | std::path::Prefix::VerbatimDisk(_)
                    | std::path::Prefix::DeviceNS(_)
            ),
            _ => false,
        });
        let namespace_spelling = path
            .to_str()
            .is_some_and(|text| reject_windows_namespace_spelling(text).is_err());
        if namespace_component || namespace_spelling {
            return Err(err(unavailable));
        }
    }
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(err(unavailable));
    }
    Ok(path)
}

#[cfg(any(windows, test))]
fn first_valid_base_dir(
    candidates: impl IntoIterator<Item = PathBuf>,
    unavailable: &'static str,
) -> Result<PathBuf> {
    first_valid_candidate(candidates, |path| {
        validate_base_dir(path.to_path_buf(), unavailable).is_ok()
    })
    .ok_or_else(|| err(unavailable))
}

#[cfg(any(windows, test))]
fn first_valid_candidate(
    candidates: impl IntoIterator<Item = PathBuf>,
    mut is_valid: impl FnMut(&Path) -> bool,
) -> Option<PathBuf> {
    candidates.into_iter().find(|path| is_valid(path))
}

fn home_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let user_profile = env::var_os("USERPROFILE");
        let home_drive = env::var_os("HOMEDRIVE");
        let home_path = env::var_os("HOMEPATH");
        let candidates = windows_home_candidates(
            known_folders::get_known_folder_path(known_folders::KnownFolder::Profile),
            user_profile.as_deref(),
            home_drive.as_deref(),
            home_path.as_deref(),
        );
        first_valid_base_dir(candidates, "home directory unavailable")
    }
    #[cfg(not(windows))]
    {
        let path = env::var_os("HOME").ok_or_else(|| err("home directory unavailable"))?;
        validate_base_dir(PathBuf::from(path), "home directory unavailable")
    }
}

/// Orders Windows known-folder and environment candidates without accepting a
/// partial drive/path pair. Candidates are validated before use, so malformed
/// higher-priority values do not prevent a safe fallback.
#[cfg(any(windows, test))]
fn windows_home_candidates(
    known_profile: Option<PathBuf>,
    user_profile: Option<&std::ffi::OsStr>,
    home_drive: Option<&std::ffi::OsStr>,
    home_path: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(3);
    if let Some(path) = known_profile {
        candidates.push(path);
    }
    if let Some(path) = user_profile.filter(|path| !path.is_empty()) {
        candidates.push(PathBuf::from(path));
    }
    if let (Some(drive), Some(path)) = (home_drive, home_path)
        && !drive.is_empty()
        && !path.is_empty()
    {
        let mut combined = drive.to_os_string();
        combined.push(path);
        candidates.push(PathBuf::from(combined));
    }
    candidates
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsPathKind {
    DriveAbsolute,
    UncAbsolute,
    DriveRelative,
    RootedWithoutDrive,
    Relative,
    MalformedUnc,
    VerbatimDisk,
    VerbatimUnc,
    DeviceNamespace,
    OtherVerbatim,
}

#[cfg(any(windows, test))]
fn windows_namespace_kind(path: &str) -> Option<WindowsPathKind> {
    let bytes = path.as_bytes();
    let is_separator = |byte: u8| byte == b'\\' || byte == b'/';
    if bytes.len() < 4
        || !is_separator(bytes[0])
        || !is_separator(bytes[1])
        || !is_separator(bytes[3])
    {
        return None;
    }
    match bytes[2] {
        b'.' => Some(WindowsPathKind::DeviceNamespace),
        b'?' => {
            let remainder = &path[4..];
            if remainder.get(..4).is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case("UNC\\") || prefix.eq_ignore_ascii_case("UNC/")
            }) {
                Some(WindowsPathKind::VerbatimUnc)
            } else if remainder.len() >= 2
                && remainder.as_bytes()[0].is_ascii_alphabetic()
                && remainder.as_bytes()[1] == b':'
            {
                Some(WindowsPathKind::VerbatimDisk)
            } else {
                Some(WindowsPathKind::OtherVerbatim)
            }
        }
        _ => None,
    }
}

#[cfg(any(windows, test))]
fn reject_windows_namespace_spelling(path: &str) -> Result<()> {
    if windows_namespace_kind(path).is_some() {
        Err(err("vault path uses an unsupported Windows namespace"))
    } else {
        Ok(())
    }
}

/// Classifies Windows path spellings independently of the host OS so resolver
/// policy can be tested on Unix as well as Windows.
#[cfg(any(windows, test))]
fn windows_path_kind(path: &str) -> WindowsPathKind {
    let bytes = path.as_bytes();
    let is_separator = |byte: u8| byte == b'\\' || byte == b'/';
    if let Some(namespace) = windows_namespace_kind(path) {
        return namespace;
    }
    if bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1]) {
        if bytes[0] != bytes[1] {
            return WindowsPathKind::MalformedUnc;
        }
        let rest = &path[2..];
        let mut parts = rest.split(['\\', '/']);
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        return if !server.is_empty() && !share.is_empty() {
            WindowsPathKind::UncAbsolute
        } else {
            WindowsPathKind::MalformedUnc
        };
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return if bytes.get(2).is_some_and(|byte| is_separator(*byte)) {
            WindowsPathKind::DriveAbsolute
        } else {
            WindowsPathKind::DriveRelative
        };
    }
    if bytes.first().is_some_and(|byte| is_separator(*byte)) {
        WindowsPathKind::RootedWithoutDrive
    } else {
        WindowsPathKind::Relative
    }
}

#[cfg(test)]
fn valid_windows_absolute_base(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    reject_windows_namespace_spelling(text).is_ok()
        && matches!(
            windows_path_kind(text),
            WindowsPathKind::DriveAbsolute | WindowsPathKind::UncAbsolute
        )
        && !text
            .split(['\\', '/'])
            .any(|component| matches!(component, "." | ".."))
}

#[cfg(any(windows, test))]
fn validate_windows_init_spelling(path: &str) -> Result<()> {
    reject_windows_namespace_spelling(path)?;
    match windows_path_kind(path) {
        WindowsPathKind::DriveRelative => Err(err("vault path must not be drive-relative")),
        WindowsPathKind::RootedWithoutDrive => {
            Err(err("vault path must include a drive or UNC share"))
        }
        WindowsPathKind::MalformedUnc => Err(err("vault path has a malformed UNC root")),
        WindowsPathKind::VerbatimDisk
        | WindowsPathKind::VerbatimUnc
        | WindowsPathKind::DeviceNamespace
        | WindowsPathKind::OtherVerbatim => {
            Err(err("vault path uses an unsupported Windows namespace"))
        }
        _ => Ok(()),
    }
}

fn resolve_app_dir(
    app_override: Option<&std::ffi::OsStr>,
    xdg_override: Option<&std::ffi::OsStr>,
    standard_xdg_home: Option<&std::ffi::OsStr>,
    home: impl FnOnce() -> Result<PathBuf>,
    fallback_suffix: &str,
    unavailable: &'static str,
    validate: impl Fn(PathBuf, &'static str) -> Result<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = app_override {
        return validate(PathBuf::from(path), unavailable);
    }
    if let Some(path) = xdg_override {
        return Ok(validate(PathBuf::from(path), unavailable)?.join("nkeepass"));
    }
    if let Some(path) = standard_xdg_home {
        return Ok(validate(PathBuf::from(path), unavailable)?.join("nkeepass"));
    }
    Ok(validate(home()?, unavailable)?.join(fallback_suffix))
}

fn config_dir() -> Result<PathBuf> {
    let app_override = env::var_os("NKEEPASS_CONFIG_DIR");
    let xdg_override = env::var_os("XDG_CONFIG_DIR");
    let standard_xdg_home = env::var_os("XDG_CONFIG_HOME");
    resolve_app_dir(
        app_override.as_deref(),
        xdg_override.as_deref(),
        standard_xdg_home.as_deref(),
        home_dir,
        ".config/nkeepass",
        "configuration directory unavailable",
        validate_base_dir,
    )
}

fn data_dir() -> Result<PathBuf> {
    let app_override = env::var_os("NKEEPASS_DATA_DIR");
    let xdg_override = env::var_os("XDG_DATA_DIR");
    let standard_xdg_home = env::var_os("XDG_DATA_HOME");
    resolve_app_dir(
        app_override.as_deref(),
        xdg_override.as_deref(),
        standard_xdg_home.as_deref(),
        home_dir,
        ".local/share/nkeepass",
        "data directory unavailable",
        validate_base_dir,
    )
}

fn data_vault() -> Result<PathBuf> {
    Ok(data_dir()?.join("default.kdbx"))
}

fn load_config() -> Result<Config> {
    use std::io::Read;

    let dir = config_dir()?;
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(err("unsafe configuration directory permissions"));
                }
            }
        }
        Ok(_) => return Err(err("unsafe configuration directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(_) => return Err(err("cannot read configuration")),
    }
    let path = dir.join("config.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(_) => return Err(err("cannot read configuration")),
    };
    if !metadata.file_type().is_file() {
        return Err(err("unsafe configuration file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(err("unsafe configuration permissions"));
        }
    }
    let file = File::open(path).map_err(|_| err("cannot read configuration"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| err("cannot read configuration"))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(err("configuration exceeds size limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| err("invalid configuration"))
}

fn save_config(config: &Config) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).map_err(|_| err("cannot create configuration directory"))?;
    let metadata = fs::symlink_metadata(&dir).map_err(|_| err("cannot save configuration"))?;
    if !metadata.file_type().is_dir() {
        return Err(err("unsafe configuration directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| err("cannot save configuration"))?;
    }
    let bytes =
        serde_json::to_vec_pretty(config).map_err(|_| err("cannot encode configuration"))?;
    let mut temp = tempfile::NamedTempFile::new_in(&dir)
        .map_err(|_| err("cannot create configuration temporary file"))?;
    nkeepass::private_file::set_owner_only(
        temp.path(),
        "cannot create configuration temporary file",
    )
    .map_err(err)?;
    temp.write_all(&bytes)
        .map_err(|_| err("cannot write configuration"))?;
    temp.as_file()
        .sync_all()
        .map_err(|_| err("cannot sync configuration"))?;
    temp.persist(dir.join("config.json"))
        .map_err(|_| err("cannot save configuration"))?;
    #[cfg(unix)]
    File::open(&dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| err("configuration installed but directory durability is unconfirmed"))?;
    Ok(())
}

/// Every configuration key this CLI understands, in the order `config ls`
/// reports them.
///
/// The set is closed and written out here rather than derived from [`Config`]'s
/// fields. `deny_unknown_fields` already refuses an unrecognised key on *read*;
/// this is the same statement for *write*, so a field added to `Config` is not
/// reachable from the command line until someone adds it here deliberately. An
/// open-ended configuration is a place to put a secret, and this file's
/// owner-only permissions exist precisely so that it is not one.
const CONFIG_KEYS: [ConfigKey; 3] = [
    ConfigKey::Aliases,
    ConfigKey::Current,
    ConfigKey::DefaultVault,
];

/// The refusal for a key that is not in [`CONFIG_KEYS`].
///
/// Static, like every diagnostic in this CLI, so a caller-supplied key never
/// reaches stderr; the valid keys are the file's own field names rather than
/// anything sensitive, and naming them is what makes the message actionable.
/// A unit test keeps the list here and the names in [`ConfigKey::name`] from
/// drifting apart.
const UNKNOWN_CONFIG_KEY: &str =
    "unknown configuration key; valid keys are aliases, current, default_vault";

/// The refusal for the one key that is not a scalar.
///
/// `aliases` is a map of objects with its own commands. A `config set aliases
/// VALUE` that "worked" would have to either drop the map or flatten it to
/// text, and both outcomes put an unreviewed string into a file that is
/// supposed to hold paths. `alias set` and `alias rm` validate a target against
/// its alias kind, which is the check that makes a value safe to store.
const CONFIG_ALIASES_NOT_SCALAR: &str =
    "aliases is a map; use nkeepass alias set and nkeepass alias rm";

/// The refusal for a scalar key that holds nothing.
///
/// A removal that reports success while doing nothing is how a script comes to
/// believe a context was cleared when it was not, so this is an error, exactly
/// as `alias rm` is for a name that is not there.
const CONFIG_KEY_NOT_SET: &str = "configuration key is not set";

/// One configuration key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigKey {
    /// The alias map. Reported and cleared only by `alias ls|set|rm`.
    Aliases,
    /// The vault `context show` reports as the `context` precedence step.
    Current,
    /// The vault used as the `default` precedence step.
    DefaultVault,
}

impl ConfigKey {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "aliases" => Ok(Self::Aliases),
            "current" => Ok(Self::Current),
            "default_vault" => Ok(Self::DefaultVault),
            _ => Err(err(UNKNOWN_CONFIG_KEY)),
        }
    }

    /// The file's own spelling of the key, which is also what a glob matches.
    fn name(self) -> &'static str {
        match self {
            Self::Aliases => "aliases",
            Self::Current => "current",
            Self::DefaultVault => "default_vault",
        }
    }
}

impl Config {
    /// The stored value of a scalar key, or `None` when it is unset.
    ///
    /// [`ConfigKey::Aliases`] has no value here on purpose. It is a map, and
    /// reading it as one string is the first step towards turning this file into
    /// the key/value store it is deliberately not.
    fn value(&self, key: ConfigKey) -> Option<&String> {
        match key {
            ConfigKey::Current => self.current.as_ref(),
            ConfigKey::DefaultVault => self.default_vault.as_ref(),
            ConfigKey::Aliases => None,
        }
    }

    /// Stores a scalar key, or refuses the map-valued one.
    fn set_value(&mut self, key: ConfigKey, value: Option<String>) -> Result<()> {
        match key {
            ConfigKey::Current => self.current = value,
            ConfigKey::DefaultVault => self.default_vault = value,
            ConfigKey::Aliases => return Err(err(CONFIG_ALIASES_NOT_SCALAR)),
        }
        Ok(())
    }
}

/// The refusal for a stored configuration value carrying terminal-control
/// bytes.
const CONFIG_VALUE_UNSAFE: &str = "configuration values cannot contain terminal-control bytes";

/// Refuses to print a stored value carrying terminal-control bytes.
///
/// The configuration file is owner-only, so this is not the vault's
/// untrusted-input case -- but it is still a file a user may have hand-edited,
/// and every value this CLI prints lands in a terminal. `vault_path` already
/// applies the same predicate to a path on its way into a vault, so without
/// this check `config` would become the one command that renders what
/// `context show` refuses to.
fn check_config_value(value: &str) -> Result<()> {
    if safe_metadata(value) {
        Ok(())
    } else {
        Err(err(CONFIG_VALUE_UNSAFE))
    }
}

/// [`check_config_value`] over every string one alias record would print.
fn check_alias_metadata(name: &str, alias: &Alias) -> Result<()> {
    if safe_metadata(name)
        && safe_metadata(&alias.target)
        && alias.field.as_deref().is_none_or(safe_metadata)
    {
        Ok(())
    } else {
        Err(err(CONFIG_VALUE_UNSAFE))
    }
}

fn vault_path(target: &str) -> Result<PathBuf> {
    let path = Path::new(target);
    #[cfg(windows)]
    reject_windows_namespace_spelling(target)?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(err("vault path must be absolute and normalized"));
    }
    // A path is echoed back by `context show`, stored in the configuration
    // file, and passed straight back through this function on the next
    // command, so it carries attacker-influenced text into every one of those
    // channels. `safe_metadata` is the same predicate the read path applies to
    // vault metadata, and reusing it keeps one definition of "a byte no
    // terminal should act on".
    if !safe_metadata(target) {
        return Err(err("vault path cannot contain terminal-control bytes"));
    }
    Ok(path.to_path_buf())
}

/// Returns a stable textual path for configuration and machine-readable output.
/// Windows accepts mixed separators, but those spellings should not leak into
/// config JSON or context JSON once the path has crossed validation.
fn normalized_vault_text(path: &Path) -> String {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    let looks_like_windows_path = (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || (bytes.len() >= 2 && matches!(bytes[0], b'\\' | b'/') && bytes[0] == bytes[1]);
    if looks_like_windows_path {
        text.replace('/', "\\")
    } else {
        text.into_owned()
    }
}

/// Resolves an explicit `init` target to an absolute, lexically normalized
/// path. `.` components are harmless and removed; `..` is rejected rather than
/// allowed to escape the invocation directory or masquerade as a normalized
/// path. The terminal-control check applies to the original spelling.
fn init_target_path(target: &str) -> Result<PathBuf> {
    if target.is_empty() || !safe_metadata(target) {
        return Err(err("vault path cannot contain terminal-control bytes"));
    }
    let input = Path::new(target);
    #[cfg(windows)]
    validate_windows_init_spelling(target)?;
    if input
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(err("vault path must not contain parent components"));
    }
    let joined;
    let input = if input.is_absolute() {
        input
    } else {
        joined = env::current_dir()
            .map_err(|_| err("current directory unavailable"))?
            .join(input);
        &joined
    };
    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(err("vault path must not contain parent components"));
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    if !normalized.is_absolute() {
        return Err(err("vault path must be absolute and normalized"));
    }
    Ok(normalized)
}

fn entry_path(target: &str) -> Result<()> {
    if target.is_empty()
        || target.chars().any(char::is_control)
        || target
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || target.starts_with('/')
    {
        return Err(err("invalid entry path"));
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn resolve_vault(target: &str, config: &Config) -> Result<PathBuf> {
    if Path::new(target).is_absolute() {
        return vault_path(target);
    }
    match config.aliases.get(target) {
        Some(Alias {
            kind: Kind::Vault,
            target,
            ..
        }) => vault_path(target),
        _ => Err(err("vault alias not found")),
    }
}

fn set_context_alias(config: &mut Config, name: &str, target: &str) -> Result<()> {
    if !valid_name(name) {
        return Err(err("invalid context alias name"));
    }
    let path = vault_path(target)?;
    config.aliases.insert(
        name.to_owned(),
        Alias {
            kind: Kind::Vault,
            target: normalized_vault_text(&path),
            field: None,
        },
    );
    Ok(())
}

fn use_context_alias(config: &mut Config, name: &str) -> Result<()> {
    match config.aliases.get(name) {
        Some(Alias {
            kind: Kind::Vault, ..
        }) => {
            config.current = Some(name.to_owned());
            Ok(())
        }
        _ => Err(err("vault alias not found")),
    }
}

fn remove_context_alias(config: &mut Config, name: &str) -> Result<()> {
    match config.aliases.get(name) {
        Some(Alias {
            kind: Kind::Vault, ..
        }) => {}
        _ => return Err(err("vault alias not found")),
    }
    config.aliases.remove(name);
    if config.current.as_deref() == Some(name) {
        config.current = None;
    }
    Ok(())
}

fn environment_vault(name: &str) -> Result<Option<String>> {
    let Some(path) = env::var_os(name).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    path.into_string()
        .map(Some)
        .map_err(|_| err("vault environment variable is not valid UTF-8"))
}

fn active_vault<'a>(
    explicit: Option<&'a str>,
    config: &'a Config,
) -> Result<(PathBuf, &'static str)> {
    if let Some(path) = explicit {
        return Ok((resolve_vault(path, config)?, "argument"));
    }
    if let Some(path) = environment_vault("NKEEPASS_VAULT")? {
        return Ok((resolve_vault(&path, config)?, "environment"));
    }
    if let Some(path) = environment_vault("NKEEPASS_VAULT_PATH")? {
        return Ok((resolve_vault(&path, config)?, "environment"));
    }
    if let Some(path) = &config.current {
        return Ok((resolve_vault(path, config)?, "context"));
    }
    if let Some(path) = &config.default_vault {
        return Ok((resolve_vault(path, config)?, "default"));
    }
    Ok((data_vault()?, "data-directory"))
}

fn json<T: Serialize>(value: &T) -> Result<()> {
    let mut text = serde_json::to_vec(value).map_err(|_| err("cannot encode output"))?;
    text.push(b'\n');
    io::stdout()
        .write_all(&text)
        .map_err(|_| err("cannot write output"))
}

#[derive(Serialize)]
struct SearchJsonRow<'a> {
    #[serde(rename = "fields")]
    field_names: &'a [String],
    path: &'a str,
    tags: &'a [String],
    title: &'a str,
}

fn write_search_hit(hit: &SearchHit) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &SearchJsonRow {
            field_names: hit.field_names(),
            path: hit.path(),
            tags: hit.tags(),
            title: hit.title(),
        },
    )
    .map_err(|_| err("cannot encode output"))?;
    stdout
        .write_all(b"\n")
        .map_err(|_| err("cannot write output"))
}

/// Writes one text line, reporting a failed write rather than panicking.
///
/// `println!` aborts on a write error, so a listing consumed by a pipeline that
/// closes early -- `nkeepass config ls | head -1` -- would die with a panic
/// message on stderr instead of stopping. `json` already returns the refusal
/// for a closed pipe, and this is the same contract for the text form.
fn print_line(line: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{line}").map_err(|_| err("cannot write output"))
}

fn take_arg(args: &[String], index: usize) -> Result<&str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| err("missing argument; see --help"))
}

const MAX_SEARCH_QUERY_BYTES: usize = 4 * 1024;

// Every byte this CLI writes to stdout is attacker-controlled, because a vault
// is untrusted input. `serde_json` escapes the C0 range but emits `U+007F` and
// the whole C1 block raw, and `U+009B` is 8-bit CSI: a title containing it
// repaints the terminal, `U+009D` renames the window, and OSC 52 can reach the
// clipboard on some terminals. So metadata is validated on the *read* path,
// before any record is written, for exactly the reason the write paths already
// validate: the tool protects vaults it wrote and must equally refuse to render
// the ones it exists to read.
//
// This is deliberately stricter than `validate_formatted_controls`, which allows
// a line feed because the dotenv and shell contracts treat one as data. A
// metadata record is a single NDJSON line, so a line feed is not data here, it
// is a record separator an attacker would use to forge a second record.
//
// The check is on the *record*, not the vault. A single hostile entry must not
// make an otherwise readable vault unreadable, and it must not truncate an
// NDJSON stream mid-file for whatever is consuming it, so an offending record is
// dropped and the run continues. The diagnostic is deliberately silent about
// which entry it was: naming the record would put the payload back on stderr.
fn safe_metadata(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// Walks the tree, emitting one record per matching entry and counting the ones
/// withheld for containing terminal-control bytes.
///
/// A silent omission is indistinguishable from an empty vault, so a caller that
/// sees fewer entries than it expected has no way to know that a record was
/// suppressed rather than absent. The count is reported on stderr, which names
/// no record -- naming it would put the payload back on the channel the
/// attacker chose.
/// Reports records suppressed for containing terminal-control bytes.
///
/// Static, category-only, and never naming a record: the whole point is that
/// the offending bytes do not reach a channel a terminal will act on, and a
/// message quoting the title would undo that.
fn report_withheld(withheld: usize) {
    if withheld > 0 {
        eprintln!(
            "nkeepass: {withheld} record(s) withheld: vault metadata contains \
             terminal-control bytes"
        );
    }
}

/// Compiles a configuration-listing glob after applying the CLI's byte bound.
fn compile_glob(pattern: &str) -> Result<Glob> {
    if pattern.len() > MAX_GLOB_PATTERN_BYTES {
        return Err(err(format!(
            "glob pattern is {} bytes; the limit is {MAX_GLOB_PATTERN_BYTES}",
            pattern.len()
        )));
    }
    Ok(Glob::new(pattern))
}

fn write_selected_fields(fields: &[nkeepass::FieldMetadata]) -> Result<()> {
    for field in fields {
        json(&serde_json::json!({
            "name": field.name(),
            "protected": field.protected(),
            "protect_in_memory": field.protect_in_memory(),
        }))?;
    }
    Ok(())
}

fn write_selected_entry(selected: &nkeepass::SelectedEntry, path: &str) -> Result<()> {
    if selected
        .fields()
        .iter()
        .filter(|field| field.name() == "otp")
        .count()
        > 1
    {
        return Err(err("ambiguous field name"));
    }
    let fields = selected
        .fields()
        .iter()
        .map(|field| {
            serde_json::json!({
                "name": field.name(),
                "protected": field.protected(),
                "protect_in_memory": field.protect_in_memory(),
            })
        })
        .collect::<Vec<_>>();
    let attachments = selected
        .attachments()
        .iter()
        .map(|attachment| serde_json::json!({"name": attachment.name()}))
        .collect::<Vec<_>>();
    let has_otp = selected
        .fields()
        .iter()
        .find(|field| field.name() == "otp")
        .is_some_and(nkeepass::FieldMetadata::protected);
    json(&serde_json::json!({
        "path": path,
        "title": selected.title(),
        "tags": selected.tags(),
        "fields": fields,
        "attachments": attachments,
        "has_otp": has_otp,
        "auto_type": {
            "enabled": selected.auto_type_enabled(),
            "associations": selected.auto_type_associations(),
        },
    }))
}

/// Whether a command accepts a bare positional word.
///
/// Every command shares one option parser, so the positional policy is a
/// parameter of it rather than a second parser. Naming the three cases keeps
/// the walk commands' `--`-terminated glob distinct from `init`'s target path;
/// folding them into one "allow a word" flag would have made the search glob
/// double as a file path, which is exactly the sort of silent meaning-shift
/// this CLI's precedence rules exist to prevent.
#[derive(Clone, Copy)]
enum Positional {
    /// No bare positional is accepted.
    Forbidden,
    /// One `secrets ls`/`secrets search` glob, taken after the `--` terminator.
    Glob,
    /// One bare target path, as `init PATH` takes.
    Path,
}

impl Positional {
    /// Only the two walk commands take a bare word, and only behind `--`.
    fn for_action(action: &str) -> Self {
        if matches!(action, "ls" | "search") {
            Self::Glob
        } else {
            Self::Forbidden
        }
    }
}

#[derive(Default)]
struct Options<'a> {
    key: Option<&'a str>,
    field: Option<&'a str>,
    name: Option<&'a str>,
    file: Option<&'a str>,
    output: Option<&'a str>,
    password: Option<&'a str>,
    password_env: Option<&'a str>,
    password_file: Option<&'a str>,
    key_file: Option<&'a str>,
    password_stdin: bool,
    stdin: bool,
    yes: bool,
    dry_run: bool,
    replace: bool,
    size: Option<usize>,
    glob: Option<&'a str>,
    format: Option<&'a str>,
    is_output: bool,
    strategy: Option<&'a str>,
    path: Option<&'a str>,
    kdf: Option<&'a str>,
    memory: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
    age_encrypt: bool,
    age_decrypt: bool,
    age_recipients: Vec<&'a str>,
    age_identity: Option<&'a str>,
}

fn options(args: &[String], positional: Positional) -> Result<Options<'_>> {
    let mut opts = Options::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(positional, Positional::Glob) && arg == "--" {
            i += 1;
            if i < args.len() {
                if opts.glob.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                opts.glob = Some(args[i].as_str());
                i += 1;
                if i < args.len() {
                    return Err(err("invalid or duplicate option"));
                }
            }
            continue;
        }
        let value = if matches!(
            arg,
            "--key"
                | "--field"
                | "--name"
                | "--file"
                | "--output"
                | "--password"
                | "--password-env"
                | "--password-file"
                | "--key-file"
                | "--size"
                | "--format"
                | "--strategy"
                | "--kdf"
                | "--memory"
                | "--iterations"
                | "--parallelism"
                | "--age-recipient"
                | "-r"
                | "--age-identity"
                | "-i"
        ) {
            i += 1;
            Some(take_arg(args, i)?)
        } else {
            None
        };
        match arg {
            "--key" if opts.key.is_none() => opts.key = value,
            "--field" if opts.field.is_none() => opts.field = value,
            "--name" if opts.name.is_none() => opts.name = value,
            "--file" if opts.file.is_none() => opts.file = value,
            "--output" if opts.output.is_none() => opts.output = value,
            "--password" if opts.password.is_none() => opts.password = value,
            "--password-env" if opts.password_env.is_none() => opts.password_env = value,
            "--password-file" if opts.password_file.is_none() => opts.password_file = value,
            "--key-file" if opts.key_file.is_none() => opts.key_file = value,
            "--password-stdin" if !opts.password_stdin => opts.password_stdin = true,
            "--stdin" if !opts.stdin => opts.stdin = true,
            "--yes" if !opts.yes => opts.yes = true,
            "--dry-run" if !opts.dry_run => opts.dry_run = true,
            "--replace" if !opts.replace => opts.replace = true,
            "--size" if opts.size.is_none() => opts.size = Some(count(value, "invalid size")?),
            "--format" if opts.format.is_none() => opts.format = value,
            "--is-output" if !opts.is_output => opts.is_output = true,
            "--strategy" if opts.strategy.is_none() => opts.strategy = value,
            "--kdf" if opts.kdf.is_none() => opts.kdf = value,
            "--memory" if opts.memory.is_none() => {
                opts.memory = Some(count(value, "invalid memory")?);
            }
            "--iterations" if opts.iterations.is_none() => {
                opts.iterations = Some(count(value, "invalid iterations")?);
            }
            "--parallelism" if opts.parallelism.is_none() => {
                opts.parallelism = Some(count(value, "invalid parallelism")?);
            }
            "--age-encrypt" if !opts.age_encrypt => opts.age_encrypt = true,
            "--age-decrypt" if !opts.age_decrypt => opts.age_decrypt = true,
            "--age-recipient" | "-r" => opts
                .age_recipients
                .push(value.ok_or_else(|| err("age recipient required"))?),
            "--age-identity" | "-i" if opts.age_identity.is_none() => {
                opts.age_identity = value;
            }
            word if !word.starts_with('-') => match positional {
                Positional::Glob if opts.glob.is_none() => opts.glob = Some(word),
                Positional::Path if opts.path.is_none() => opts.path = Some(word),
                _ => return Err(err("invalid or duplicate option")),
            },
            _ => return Err(err("invalid or duplicate option")),
        }
        i += 1;
    }
    validate_shared_options(&opts)?;
    Ok(opts)
}

/// Parses one numeric option value.
///
/// A missing, malformed or negative value is a refusal rather than a zero: a
/// silently substituted zero would change the shape of what was asked for, and
/// on the KDF counts that means a vault weaker than the caller requested.
fn count<T: std::str::FromStr>(value: Option<&str>, invalid: &'static str) -> Result<T> {
    value
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| err(invalid))
}

/// Checks the option conflicts every command shares, before the per-action
/// matrix gets a say.
fn validate_shared_options(opts: &Options<'_>) -> Result<()> {
    let password_sources = usize::from(opts.password.is_some())
        + usize::from(opts.password_env.is_some())
        + usize::from(opts.password_file.is_some())
        + usize::from(opts.password_stdin);
    if password_sources > 1 {
        return Err(err("select exactly one credential source"));
    }
    if opts.stdin && opts.password_stdin {
        return Err(err("stdin cannot carry both password and value"));
    }
    if opts.password_env.is_some_and(|name| !valid_name(name)) {
        return Err(err("invalid environment variable name"));
    }
    Ok(())
}

fn password(opts: &Options<'_>) -> Result<Option<Zeroizing<String>>> {
    if let Some(value) = opts.password {
        if value.is_empty() {
            return Err(err("password must not be empty"));
        }
        return Ok(Some(Zeroizing::new(value.to_owned())));
    }
    if let Some(name) = opts.password_env {
        return env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new)
            .map(Some)
            .ok_or_else(|| err("password environment variable unavailable"));
    }
    if let Some(path) = opts.password_file {
        let bytes = bounded_file(path, MAX_PASSWORD_STDIN_BYTES as u64)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| err("invalid password file"))?;
        let line = text.split_once(['\n', '\r']).map_or(text, |(line, _)| line);
        if line.is_empty() {
            return Err(err("password must not be empty"));
        }
        return Ok(Some(Zeroizing::new(line.to_owned())));
    }
    if opts.password_stdin {
        return read_password_stdin(io::stdin().lock()).map(Some);
    }
    if opts.key_file.is_some() {
        return Ok(None);
    }
    match env::var(DEFAULT_PASSWORD_ENV) {
        Ok(value) if !value.is_empty() => return Ok(Some(Zeroizing::new(value))),
        Err(env::VarError::NotPresent) => {}
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            return Err(err("password environment variable unavailable"));
        }
    }
    if !io::stdin().is_terminal() {
        return Err(err("password source required for non-interactive input"));
    }
    eprint!("Master password: ");
    io::stderr()
        .flush()
        .map_err(|_| err("cannot start password prompt"))?;
    let value = rpassword::read_password().map_err(|_| err("cannot read password"))?;
    eprintln!();
    if value.is_empty() {
        return Err(err("password must not be empty"));
    }
    Ok(Some(Zeroizing::new(value)))
}

fn read_password_stdin(mut input: impl Read) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_STDIN_BYTES + 1));
    loop {
        let mut next = [0_u8; 1];
        let read = input
            .read(&mut next)
            .map_err(|_| err("cannot read password"))?;
        if read == 0 {
            break;
        }
        let byte = next[0];
        if byte == b'\n' {
            break;
        }
        if bytes.len() >= MAX_PASSWORD_STDIN_BYTES {
            if byte == b'\r' {
                let mut next = [0_u8; 1];
                let read = input
                    .read(&mut next)
                    .map_err(|_| err("cannot read password"))?;
                if read == 0 || next[0] == b'\n' {
                    break;
                }
            }
            return Err(err("password exceeds size limit"));
        }
        bytes.push(byte);
    }
    while bytes.ends_with(b"\r") {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(err("password must not be empty"));
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| err("cannot read password"))?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn credentials(opts: &Options<'_>) -> Result<KdbxCredentials> {
    let password = password(opts)?;
    let key_file = opts
        .key_file
        .map(|path| {
            File::open(path)
                .map_err(|_| err("cannot open key file"))
                .and_then(|file| read_key_file(file).map_err(|_| err("invalid key file")))
        })
        .transpose()?;
    let providers = key_file
        .map(|provider| {
            vec![Box::new(provider) as Box<dyn neotales_keepass::CredentialProvider + Send>]
        })
        .unwrap_or_default();
    KdbxCredentials::from_parts(password.as_ref().map(|value| value.as_bytes()), providers)
        .map_err(|_| err("invalid credentials"))
}

fn bounded_file(path: &str, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path).map_err(|_| err("cannot open input file"))?;
    let bytes = read_bounded(file, max, "cannot read input file")?;
    if bytes.len() as u64 > max {
        return Err(err("input exceeds size limit"));
    }
    Ok(bytes)
}

/// Parses inline native or SSH public keys and explicit `@PATH` key files.
fn age_recipients(values: &[&str]) -> Result<Vec<AgeRecipient>> {
    let mut recipients = Vec::new();
    for value in values {
        let key = if value.starts_with("gh:") || value.starts_with("https://") {
            fetch_recipient_source(value)?
        } else if let Some(path) = value.strip_prefix('@') {
            if path.is_empty() {
                return Err(err("invalid age recipient file"));
            }
            let bytes =
                bounded_file(path, 64 * 1024).map_err(|_| err("cannot read age recipient file"))?;
            String::from_utf8(bytes.to_vec()).map_err(|_| err("invalid age recipient file"))?
        } else {
            (*value).to_owned()
        };
        for line in key
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            recipients.push(
                AgeRecipient::from_public_key(line)
                    .or_else(|_| AgeRecipient::from_ssh_public_key(line))
                    .map_err(|_| err("invalid age recipient"))?,
            );
        }
    }
    if recipients.is_empty() {
        return Err(err("age recipient required"));
    }
    Ok(recipients)
}

/// Resolves an explicitly requested GitHub or HTTPS recipient source.
fn fetch_recipient_source(source: &str) -> Result<String> {
    let url = if let Some(username) = source.strip_prefix("gh:") {
        if username.is_empty()
            || username.len() > 39
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(err("invalid GitHub recipient name"));
        }
        format!("https://github.com/{username}.keys")
    } else {
        validate_https_url(source)?;
        source.to_owned()
    };

    fetch_recipient_url(&url, RecipientTransport::Https)
}

#[derive(Clone, Copy)]
enum RecipientTransport {
    Https,
    #[cfg(test)]
    HttpFixture,
}

impl RecipientTransport {
    fn curl_protocol(self) -> &'static str {
        match self {
            Self::Https => "=https",
            #[cfg(test)]
            Self::HttpFixture => "=http",
        }
    }
}

/// Fetches a recipient document while checking the HTTP status independently
/// of curl's process exit code. The HTTP transport exists only in unit tests.
fn fetch_recipient_url(url: &str, transport: RecipientTransport) -> Result<String> {
    let mut command = std::process::Command::new("curl");
    command
        .args([
            "--disable",
            "--globoff",
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--max-filesize",
            "65536",
            "--max-redirs",
            "0",
            "--proto",
            transport.curl_protocol(),
            "--url",
        ])
        .arg(url)
        .args(["--write-out", "\n%{http_code}"])
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| err("HTTPS recipient lookup unavailable"))?;
    let Some(mut output) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err("HTTPS recipient lookup failed"));
    };
    const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
    const MAX_RESPONSE_WITH_STATUS: u64 = MAX_RESPONSE_BYTES + 4;
    let bytes = match read_bounded(
        &mut output,
        MAX_RESPONSE_WITH_STATUS,
        "HTTPS recipient lookup failed",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if bytes.len() as u64 > MAX_RESPONSE_WITH_STATUS {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err("HTTPS recipient response exceeds size limit"));
    }
    let status = child
        .wait()
        .map_err(|_| err("HTTPS recipient lookup failed"))?;
    if !status.success() {
        return Err(err("HTTPS recipient lookup failed"));
    }
    let status_start = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| err("HTTPS recipient lookup failed"))?;
    let suffix = &bytes[status_start..];
    if suffix[0] != b'\n' || !suffix[1..].iter().all(u8::is_ascii_digit) {
        return Err(err("HTTPS recipient lookup failed"));
    }
    let code = std::str::from_utf8(&suffix[1..])
        .ok()
        .and_then(|text| text.parse::<u16>().ok())
        .ok_or_else(|| err("HTTPS recipient lookup failed"))?;
    if code < 200 || code >= 300 {
        return Err(err("HTTPS recipient lookup failed"));
    }
    let body = &bytes[..status_start];
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(err("HTTPS recipient response exceeds size limit"));
    }
    String::from_utf8(body.to_vec()).map_err(|_| err("invalid HTTPS recipient response"))
}

/// Restricts discovery URLs to a simple HTTPS authority and path.
fn validate_https_url(url: &str) -> Result<()> {
    let Some(authority_and_path) = url.strip_prefix("https://") else {
        return Err(err("recipient URL must use HTTPS"));
    };
    if url.len() > 2048
        || authority_and_path.is_empty()
        || authority_and_path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || authority_and_path.contains(['?', '#', '@'])
    {
        return Err(err("invalid HTTPS recipient URL"));
    }
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(err("invalid HTTPS recipient URL"));
    }
    if let Some(port) = authority
        .strip_prefix(host)
        .and_then(|rest| rest.strip_prefix(':'))
        && port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
    {
        return Err(err("invalid HTTPS recipient URL"));
    }
    Ok(())
}

/// Loads bounded native age identities or unencrypted SSH private keys.
fn age_identities(path: &str) -> Result<Vec<AgeIdentity>> {
    let bytes = bounded_file(path, 1 << 20).map_err(|_| err("cannot read age identity file"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| err("invalid age identity file"))?;
    if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        || text.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || text.starts_with("-----BEGIN PRIVATE KEY-----")
    {
        return AgeIdentity::from_ssh_private_key(text)
            .map(|identity| vec![identity])
            .map_err(|_| err("invalid age identity"));
    }
    let mut identities = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        identities.push(
            AgeIdentity::from_private_key(line)
                .or_else(|_| AgeIdentity::from_ssh_private_key(line))
                .map_err(|_| err("invalid age identity"))?,
        );
    }
    if identities.is_empty() {
        return Err(err("age identity required"));
    }
    Ok(identities)
}

/// Decrypts either strict age ASCII armor or the binary age file format.
fn decrypt_age_input(input: &[u8], identities: &[AgeIdentity]) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = if input.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        let armored = std::str::from_utf8(input).map_err(|_| err("invalid encrypted input"))?;
        AgeFile::decrypt_armored(armored, identities)
    } else {
        AgeFile::decrypt(input, identities)
    }
    .map_err(|_| err("age decryption failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn read_bounded(mut input: impl Read, max: u64, error: &'static str) -> Result<Zeroizing<Vec<u8>>> {
    let capacity =
        usize::try_from(max.saturating_add(1)).map_err(|_| err("input exceeds size limit"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    input
        .by_ref()
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| err(error))?;
    Ok(bytes)
}

fn input_value(opts: &Options<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let count = usize::from(opts.file.is_some()) + usize::from(opts.stdin);
    if count != 1 {
        return Err(err("select exactly one non-argv value source"));
    }
    if let Some(file) = opts.file {
        return bounded_file(file, 16 * 1024 * 1024);
    }
    let bytes = read_bounded(io::stdin(), 16 * 1024 * 1024, "cannot read value")?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(err("input exceeds size limit"));
    }
    Ok(bytes)
}

fn read_stdin(max: usize, error: &'static str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = read_bounded(io::stdin(), max as u64, error)?;
    if bytes.len() > max {
        return Err(err("input exceeds size limit"));
    }
    Ok(bytes)
}

fn automation_input(opts: &Options<'_>, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let count = usize::from(opts.file.is_some()) + usize::from(opts.stdin);
    if count != 1 {
        return Err(err("select exactly one interchange input source"));
    }
    if let Some(file) = opts.file {
        return bounded_file(
            file,
            u64::try_from(max).map_err(|_| err("input exceeds size limit"))?,
        );
    }
    read_stdin(max, "cannot read interchange input")
}

///
/// Unix only, and the gate is the point rather than tidiness: with `save_vault`
/// converted to `confirm_durable`, this function's only production caller is the
/// `#[cfg(unix)]` half of that pair, so on Windows it has no caller and a
/// *release* build warned
///
///     warning: function `sync_installed_directory` is never used
///
/// The test build did not warn, because a test calls it directly -- so the warning
/// only appeared in the one configuration nobody builds locally, which is the
/// configuration the release matrix now compiles on every run.
#[cfg(unix)]
fn sync_installed_directory(parent: &Path, error: &'static str) -> Result<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| err(error))
}

/// Confirms the directory entry that names an installed file is itself durable.
///
/// Split by platform rather than guarded at the call site so the `parent` and
/// `durable` fields are used on every build and Windows does not warn about them.
///
/// On Windows this is a no-op, and so the `durable` message is never shown
/// there. That is the honest outcome rather than a gap: opening a directory as
/// a file and flushing it is a Unix operation, and reporting a durability
/// guarantee this platform cannot actually make would be worse than not
/// claiming one.
#[cfg(unix)]
fn confirm_durable(parent: &Path, error: &'static str) -> Result<()> {
    sync_installed_directory(parent, error)
}

#[cfg(not(unix))]
fn confirm_durable() {}

/// The five diagnostics a private install can report.
///
/// They travel as one value rather than as positional arguments so that a
/// second caller of [`StagedFile`] cannot adopt a half of another's wording and
/// leave a security-relevant failure described in the wrong terms.
struct InstallDiagnostics {
    staging: &'static str,
    permissions: &'static str,
    write: &'static str,
    exists: &'static str,
    durable: &'static str,
}

/// A private staging file beside a target, for an install that must never
/// overwrite an existing file and must never be readable by another user.
///
/// Two properties are load-bearing, and are the reason this is one shared type
/// rather than a shape each caller reimplements:
///
/// * **The mode is applied to the empty file, before a caller writes a byte.**
///   A `chmod` after the write leaves a window in which the secret exists under
///   whatever the process umask allows.
/// * **The install never clobbers.** `persist_noclobber` is a kernel
///   `RENAME_NOREPLACE` on Linux, so the refusal is enforced by the filesystem.
///   A `stat` followed by a rename is a race another process wins between the
///   two calls, and for a vault that race overwrites the only copy.
struct StagedFile {
    file: tempfile::NamedTempFile,
    target: PathBuf,
    parent: PathBuf,
    diagnostics: InstallDiagnostics,
}

impl StagedFile {
    fn new(target: &Path, diagnostics: InstallDiagnostics) -> Result<Self> {
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file =
            tempfile::NamedTempFile::new_in(&parent).map_err(|_| err(diagnostics.staging))?;
        nkeepass::private_file::set_owner_only(file.path(), diagnostics.permissions)
            .map_err(err)?;
        Ok(Self {
            file,
            target: target.to_path_buf(),
            parent,
            diagnostics,
        })
    }

    /// The staging sink, handed out empty and owner-only.
    fn writer(&mut self) -> &mut dyn Write {
        &mut self.file
    }

    /// Flushes, installs without clobbering, and confirms directory durability.
    fn install(self) -> Result<()> {
        self.file
            .as_file()
            .sync_all()
            .map_err(|_| err(self.diagnostics.write))?;
        self.file
            .persist_noclobber(&self.target)
            .map_err(|_| err(self.diagnostics.exists))?;
        #[cfg(unix)]
        confirm_durable(&self.parent, self.diagnostics.durable)?;
        #[cfg(not(unix))]
        {
            // Keep these fields used on platforms where durability is a no-op.
            let _ = (&self.parent, self.diagnostics.durable);
            confirm_durable();
        }
        Ok(())
    }
}

fn write_private_output(path: &str, bytes: &[u8]) -> Result<()> {
    let mut staged = StagedFile::new(
        Path::new(path),
        InstallDiagnostics {
            staging: "cannot create output temporary file",
            permissions: "cannot set output permissions",
            write: "cannot write output file",
            exists: "output already exists or cannot be created",
            durable: "plaintext output installed but directory durability is unconfirmed",
        },
    )?;
    staged
        .writer()
        .write_all(bytes)
        .map_err(|_| err("cannot write output file"))?;
    staged.install()
}

/// Two names in the vault differing only in case.
///
/// Lookup is case-insensitive, so which of them a path means is genuinely
/// undecidable, and picking one would be a guess about which credential a caller
/// meant to read.
fn ambiguous(kind: &str, name: &str) -> CliError {
    err(format!(
        "this vault holds more than one {kind} matching {name:?} ignoring case, so the path is ambiguous"
    ))
}

fn entry_not_found(service: &VaultService, session: nkeepass::SessionId, path: &str) -> CliError {
    match service.resolve_entry_for_otp(session, path) {
        Ok(_) => err("entry not found"),
        Err(error) => otp_selector_error(path, error),
    }
}

fn otp_selector_error(path: &str, error: nkeepass::SelectorError) -> CliError {
    use nkeepass::SelectorError;

    let segments = path.split('/').collect::<Vec<_>>();
    match error {
        SelectorError::MalformedPath => err("invalid entry path"),
        SelectorError::RootGroup => err("that path names the root group, not an entry"),
        SelectorError::AmbiguousGroup { segment_index } => segments.get(segment_index).map_or_else(
            || err("ambiguous entry path"),
            |name| ambiguous("group", name),
        ),
        SelectorError::AmbiguousEntry { segment_index } => segments.get(segment_index).map_or_else(
            || err("ambiguous entry path"),
            |name| ambiguous("entry", name),
        ),
        SelectorError::MissingGroup {
            segment_index,
            walked_start_index,
        } => {
            let Some(segment) = segments.get(segment_index) else {
                return err("ambiguous entry path");
            };
            let walked = segments
                .get(walked_start_index..=segment_index)
                .map_or_else(|| (*segment).to_owned(), |parts| parts.join("/"));
            err(format!(
                "this vault has no group named {segment:?} at {walked:?}; \
                 Use `group add --key PATH` to create groups, or \
                 `secrets ensure --key PATH` to create an entry and its parent groups."
            ))
        }
        SelectorError::NotFound => err("entry not found"),
        SelectorError::Service(error) => err(error.message()),
    }
}

/// Resolves CLI aliases without letting a model entry cross the service boundary.
fn resolve_service_selector(
    service: &VaultService,
    session: nkeepass::SessionId,
    selector: &str,
    config: &Config,
) -> Result<nkeepass::ResolvedEntry> {
    let path = if let Some(alias) = config.aliases.get(selector) {
        if alias.kind != Kind::Entry {
            return Err(err("entry alias required"));
        }
        entry_path(&alias.target)?;
        if alias.target != selector {
            match service.resolve_entry_for_otp(session, selector) {
                Ok(_) => return Err(err("ambiguous entry selector")),
                Err(nkeepass::SelectorError::NotFound) => {}
                Err(error) => return Err(otp_selector_error(selector, error)),
            }
        }
        alias.target.as_str()
    } else {
        selector
    };
    service
        .resolve_entry_for_otp(session, path)
        .map_err(|error| otp_selector_error(path, error))
}

fn reveal_service_field(
    service: &VaultService,
    entry: &nkeepass::ResolvedEntry,
    field: &str,
) -> Result<SecretBytes> {
    service
        .reveal_field(&entry.reference(), field)
        .map_err(|error| match error {
            nkeepass::ServiceError::Ambiguous => err("ambiguous field name"),
            nkeepass::ServiceError::NotFound => err("field not found"),
            _ => err("cannot reveal value"),
        })
}

#[cfg(test)]
const PASSWORD_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// Largest multiple of the 62-character alphabet that fits in one byte.
#[cfg(test)]
const PASSWORD_BYTE_LIMIT: u8 = 248;

#[cfg(test)]
fn password_index(byte: u8) -> Option<usize> {
    (byte < PASSWORD_BYTE_LIMIT).then(|| usize::from(byte) % PASSWORD_CHARS.len())
}

fn write_stdout(bytes: &[u8], error: &'static str) -> Result<()> {
    io::stdout().write_all(bytes).map_err(|_| err(error))
}

// Formatted output is commonly redirected to a terminal or evaluated by a
// shell. Permit line feeds because the established dotenv/shell contract
// treats them as escaped/quoted data, but reject every other Unicode control
// character (including ESC, BEL, DEL, and C1 controls) before writing bytes.
fn validate_formatted_controls(value: &str) -> Result<()> {
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return Err(err(
            "formatted output cannot contain terminal-control bytes",
        ));
    }
    Ok(())
}

/// The heredoc delimiter GitHub Actions looks for on a line of its own.
///
/// Chosen by us, not derived from anything in the vault: the value is refused
/// rather than escaped if it contains this line (see [`validate_named_value`]).
const GITHUB_EOF: &str = "NKEEPASS_EOF";

/// Whether `--format` names a variable the caller has to supply with `--name`.
///
/// Every format matched here writes a name and then a value, so every one of them
/// needs the caller to say which variable it is. The name is never derived from
/// vault-controlled metadata: a title that becomes `$env:NAME`, `${...}`, or a
/// loader name like `LD_PRELOAD` is an injection class, so the name is always an
/// identifier the caller typed.
fn is_named_format(format: &str) -> bool {
    matches!(
        format,
        "dotenv" | "shell" | "pwsh" | "powershell" | "github-actions" | "azure-devops"
    )
}

/// The name and text every named format is rendered from.
///
/// All four refusals live in one function on purpose. A format added later that
/// reaches for the name and the value without passing through here would skip the
/// terminal-control check, and that check is the disclosure contract, not a
/// formatting detail.
fn named_text<'a>(
    format: &str,
    name: Option<&'a str>,
    value: &'a [u8],
) -> Result<(&'a str, &'a str)> {
    let name = name.ok_or_else(|| err("--name required for named output"))?;
    if !valid_env_name(name) {
        return Err(err("invalid output name"));
    }
    let text = std::str::from_utf8(value).map_err(|_| err("value is not UTF-8"))?;
    if text.contains('\0') {
        return Err(err("formatted output cannot contain NUL"));
    }
    validate_formatted_controls(text)?;
    validate_named_value(format, text)?;
    Ok((name, text))
}

/// The per-format value rules that go beyond the shared control-byte contract.
///
/// `secrets env` runs this over every binding before writing the first one, so a
/// value a format cannot render refuses the whole command rather than truncating
/// the record stream partway through it.
fn validate_named_value(format: &str, value: &str) -> Result<()> {
    match format {
        // A line that is exactly the delimiter ends the block early, and the
        // remainder of the value would then be read as workflow commands. There
        // is no escape for it in the heredoc form, so the value is refused.
        "github-actions" if value.lines().any(|line| line == GITHUB_EOF) => Err(err(
            "github-actions output cannot contain the heredoc delimiter",
        )),
        // The agent reads one logging command per line, so a value carrying a
        // line feed would set the variable to the fragment before the break and
        // print the rest as log lines. Percent-encoding is not the answer: the
        // agent only decodes the message when DECODE_PERCENTS is set, so the
        // escape would silently deliver a different secret. A carriage return is
        // already refused by `validate_formatted_controls` above.
        "azure-devops" if value.contains('\n') => {
            Err(err("azure-devops output cannot contain a line feed"))
        }
        _ => Ok(()),
    }
}

/// Quoting only. The value has already been through [`named_text`].
///
/// Embedded single quotes use the standard `'\''` sequence, so metacharacters,
/// command substitutions, and newlines stay data.
fn emit_shell_value(name: &str, value: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write!(output, "export {name}='").map_err(|_| err("cannot write value"))?;
    for (index, part) in value.split('\'').enumerate() {
        if index > 0 {
            output
                .write_all(b"'\\''")
                .map_err(|_| err("cannot write value"))?;
        }
        output
            .write_all(part.as_bytes())
            .map_err(|_| err("cannot write value"))?;
    }
    output
        .write_all(b"';\n")
        .map_err(|_| err("cannot write value"))
}

/// `$env:NAME = 'value'`, for `pwsh` and its `powershell` spelling.
///
/// A single-quoted PowerShell literal is the right shape for a secret because `$`
/// and the backtick are ordinary characters inside one, so neither needs an
/// escape. The single quote is the only character that can end the literal, and
/// doubling it is PowerShell's own escape.
fn emit_powershell_value(name: &str, value: &str) -> Result<()> {
    write_stdout(
        format!("$env:{name} = '{}'\n", value.replace('\'', "''")).as_bytes(),
        "cannot write value",
    )
}

/// `NAME<<NKEEPASS_EOF` / value / `NKEEPASS_EOF`, the `$GITHUB_OUTPUT` form.
///
/// Nothing is quoted, so there is no value that can break out of the block and no
/// escape to get wrong. That is the reason to prefer it over the deprecated
/// `::set-output name=value` workflow command, which is a quoted string the
/// runner has to parse, and which GitHub has scheduled for removal.
fn emit_github_actions_value(name: &str, value: &str) -> Result<()> {
    write_stdout(
        format!("{name}<<{GITHUB_EOF}\n{value}\n{GITHUB_EOF}\n").as_bytes(),
        "cannot write value",
    )
}

/// `##vso[task.setvariable variable=NAME]value`.
///
/// `isOutput=true` is appended only where the caller asked for it with
/// `--is-output`: an output variable is read back differently from a plain one
/// (`$(name)` in the same job against `$(step.outputs.NAME)` in a later one), so
/// choosing a scope for the caller would hand them a variable their YAML does not
/// reference.
///
/// The value is written verbatim, with no percent-escaping. The agent's escape
/// table (`;` → `%3B`, `]` → `%5D`, `%` → `%AZP25`) exists to protect the
/// *property* list, and this format writes a name that cannot contain any of
/// those characters, so the value lands in the message where none of them are
/// structural. Escaping it anyway would corrupt the common case: the agent only
/// decodes a message when `DECODE_PERCENTS` is set, so a `;` would reach the
/// pipeline as the four characters `%3B`. The one documented consequence is that
/// a value containing a literal `%0D` or `%0A` is decoded to a line ending by a
/// pipeline that enables `DECODE_PERCENTS`, which is that pipeline's choice to
/// turn decoding on, not something this format can encode around.
fn emit_azure_devops_value(name: &str, value: &str, is_output: bool) -> Result<()> {
    let is_output = if is_output { ";isOutput=true" } else { "" };
    write_stdout(
        format!("##vso[task.setvariable variable={name}{is_output}]{value}\n").as_bytes(),
        "cannot write value",
    )
}

fn emit_value(value: &[u8], format: &str, name: Option<&str>, is_output: bool) -> Result<()> {
    if is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    match format {
        "text" => write_stdout(value, "cannot write value"),
        "null" => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            output
                .write_all(value)
                .and_then(|()| output.write_all(b"\0"))
                .map_err(|_| err("cannot write value"))
        }
        "json" => {
            let text = std::str::from_utf8(value).map_err(|_| err("value is not UTF-8"))?;
            json(&serde_json::json!({"value": text}))
        }
        "dotenv" => {
            let (name, text) = named_text(format, name, value)?;
            let encoded = serde_json::to_string(text).map_err(|_| err("cannot encode value"))?;
            write_stdout(
                format!("{name}={encoded}\n").as_bytes(),
                "cannot write value",
            )
        }
        "shell" => {
            let (name, text) = named_text(format, name, value)?;
            emit_shell_value(name, text)
        }
        "pwsh" | "powershell" => {
            let (name, text) = named_text(format, name, value)?;
            emit_powershell_value(name, text)
        }
        "github-actions" => {
            let (name, text) = named_text(format, name, value)?;
            emit_github_actions_value(name, text)
        }
        "azure-devops" => {
            let (name, text) = named_text(format, name, value)?;
            emit_azure_devops_value(name, text, is_output)
        }
        _ => Err(err("invalid output format")),
    }
}

fn reveal_native_service_field(
    service: &VaultService,
    entry: &nkeepass::ResolvedEntry,
    field: &str,
) -> Result<SecretBytes> {
    service
        .reveal_native_field(&entry.reference(), field)
        .map_err(|error| match error {
            nkeepass::ServiceError::Ambiguous => err("ambiguous field name"),
            nkeepass::ServiceError::NotFound => err("field not found"),
            _ => err("cannot reveal value"),
        })
}

fn interchange_error(error: interchange::InterchangeError) -> CliError {
    err(error.message())
}

#[allow(
    clippy::too_many_lines,
    reason = "the small operation dispatcher keeps CLI output schemas explicit"
)]
fn service_automation_operation(
    action: &str,
    opts: &Options<'_>,
    path: &Path,
    credentials: &mut KdbxCredentials,
) -> Result<()> {
    let mut service = VaultService::default();
    let session = service
        .open(path, credentials, &KDBX_LIMITS)
        .map_err(|error| err(error.message()))?;
    let outcome = (|| {
        let (result, changed) = match action {
            "import" => {
                let input = automation_input(opts, interchange::VAULT_LIMITS.max_bytes)?;
                let report = service
                    .import_snapshot(
                        &input,
                        nkeepass::ImportOptions {
                            replace: opts.replace,
                            dry_run: opts.dry_run,
                        },
                    )
                    .map_err(|error| err(error.message()))?;
                (
                    serde_json::json!({
                        "operation": "import",
                        "dry_run": report.dry_run,
                        "replaced": report.replaced,
                        "groups": report.groups,
                        "entries": report.entries,
                        "history_entries": report.history_entries,
                        "fields": report.fields,
                        "attachments": report.attachments,
                        "protected_values": report.protected_values,
                        "binary_records": report.binary_records,
                        "binary_bytes": report.binary_bytes,
                        "passwords_generated": report.passwords_generated,
                        "passwords_kept": report.passwords_kept,
                        "passwords_pending": report.passwords_pending,
                    }),
                    !opts.dry_run,
                )
            }
            "export" => {
                let snapshot = service
                    .export_snapshot()
                    .map_err(|error| err(error.message()))?;
                write_private_output(
                    opts.output.ok_or_else(|| err("--output required"))?,
                    snapshot.bytes(),
                )?;
                (
                    serde_json::json!({
                        "operation": "export",
                        "format": interchange::FORMAT,
                        "version": interchange::VERSION,
                        "bytes": snapshot.bytes().len(),
                    }),
                    false,
                )
            }
            "sync" => {
                let input = automation_input(opts, interchange::VAULT_LIMITS.max_bytes)?;
                let strategy = nkeepass::SyncStrategy::parse(opts.strategy.unwrap_or("newest"))
                    .map_err(|error| err(error.message()))?;
                let report = service
                    .sync_snapshot(
                        &input,
                        nkeepass::SyncOptions {
                            strategy,
                            dry_run: opts.dry_run,
                        },
                    )
                    .map_err(|error| err(error.message()))?;
                let changed = !opts.dry_run
                    && (report.groups_added > 0
                        || report.groups_updated > 0
                        || report.entries_added > 0
                        || report.entries_updated > 0
                        || report.passwords_generated > 0);
                (
                    serde_json::json!({
                        "operation": "sync",
                        "dry_run": report.dry_run,
                        "strategy": opts.strategy.unwrap_or("newest"),
                        "groups_added": report.groups_added,
                        "groups_updated": report.groups_updated,
                        "entries_added": report.entries_added,
                        "entries_updated": report.entries_updated,
                        "passwords_generated": report.passwords_generated,
                        "passwords_kept": report.passwords_kept,
                        "passwords_pending": report.passwords_pending,
                    }),
                    changed,
                )
            }
            _ => return Err(err("unknown operation")),
        };
        if changed {
            service
                .save(path, credentials)
                .map_err(|error| err(error.message()))?;
        }
        json(&result)
    })();
    let locked = service.lock(session).map_err(|error| err(error.message()));
    outcome?;
    locked?;
    Ok(())
}

/// Reports whether the caller supplied an option that only means something
/// when a *new* vault is being written.
///
/// `init` is the only command that creates a vault, so it is the only command
/// where `--kdf` and the Argon2 shape flags select anything at all. Every other
/// action must reject them rather than ignore them: a silently dropped
/// `--kdf argon2id` would leave the caller believing they had hardened a vault
/// that was written with whatever the existing pinned policy happens to be.
fn vault_creation_options(opts: &Options<'_>) -> bool {
    opts.kdf.is_some()
        || opts.memory.is_some()
        || opts.iterations.is_some()
        || opts.parallelism.is_some()
}

#[allow(
    clippy::too_many_lines,
    reason = "the explicit per-action option matrix is easier to audit in one place"
)]
fn validate_regular_options(action: &str, opts: &Options<'_>) -> Result<()> {
    let value_input = opts.file.is_some() || opts.stdin;
    let has_age_options = opts.age_encrypt
        || opts.age_decrypt
        || !opts.age_recipients.is_empty()
        || opts.age_identity.is_some();
    if has_age_options && !matches!(action, "get" | "set") {
        return Err(err("age options are only valid for get and set"));
    }
    let invalid = match action {
        "ls" | "search" | "group-ls" => {
            opts.key.is_some()
                || opts.field.is_some()
                || opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
        }
        "show" => {
            opts.key.is_none()
                || opts.field.is_some()
                || opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
        }
        "get" | "getx" | "field-get" => {
            opts.file.is_some()
                || (opts.output.is_some() && !opts.age_encrypt)
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.strategy.is_some()
                || opts.stdin
                || opts.age_decrypt
                || opts.age_identity.is_some()
                || (!opts.age_encrypt && !opts.age_recipients.is_empty())
                || (opts.age_encrypt && opts.age_recipients.is_empty())
                // `getx` is the JSON interchange read: there is no variable to
                // name and no output scope to declare.
                || (action == "getx" && (opts.name.is_some() || opts.is_output))
        }
        "set" | "field-set" | "attachment-add" => {
            opts.key.is_none()
                || opts.name.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || !value_input
                || opts.age_encrypt
                || !opts.age_recipients.is_empty()
                || (opts.age_decrypt != opts.age_identity.is_some())
                || (opts.age_identity.is_some() && action != "set")
        }
        "rm" | "field-rm" | "attachment-rm" => {
            opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
                || (action == "rm" && opts.field.is_some())
        }
        "ensure" => {
            opts.field.is_some()
                || opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.replace
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
        }
        "group-add" | "group-rm" => {
            opts.key.is_none()
                || opts.field.is_some()
                || opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
                || (action == "group-add" && opts.yes)
        }
        "field-ls" | "attachment-ls" => {
            opts.field.is_some()
                || opts.name.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
        }
        "attachment-get" => {
            opts.file.is_some()
                || opts.name.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.is_output
                || opts.strategy.is_some()
                || opts.stdin
        }
        "otp" => {
            opts.field.is_some()
                || opts.file.is_some()
                || opts.output.is_some()
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.strategy.is_some()
                || opts.stdin
        }
        _ => return Err(err("unknown operation")),
    };
    if invalid || vault_creation_options(opts) {
        return Err(err("invalid operation option"));
    }
    Ok(())
}

fn validate_automation_options(action: &str, opts: &Options<'_>) -> Result<()> {
    let unexpected = opts.field.is_some()
        || opts.name.is_some()
        || opts.output.is_some()
        || opts.yes
        || opts.size.is_some()
        || opts.glob.is_some()
        || opts.format.is_some()
        || opts.is_output;
    match action {
        "setx" => {
            if opts.key.is_none()
                || unexpected
                || opts.replace
                || opts.strategy.is_some()
                || usize::from(opts.file.is_some()) + usize::from(opts.stdin) != 1
            {
                return Err(err("invalid setx option"));
            }
        }
        "import" => {
            if opts.key.is_some()
                || unexpected
                || opts.strategy.is_some()
                || usize::from(opts.file.is_some()) + usize::from(opts.stdin) != 1
            {
                return Err(err("invalid import option"));
            }
        }
        "export" => {
            if opts.output.is_none()
                || opts.key.is_some()
                || opts.field.is_some()
                || opts.file.is_some()
                || opts.stdin
                || opts.yes
                || opts.dry_run
                || opts.replace
                || opts.size.is_some()
                || opts.glob.is_some()
                || opts.format.is_some()
                || opts.strategy.is_some()
                || opts.is_output
            {
                return Err(err("invalid export option"));
            }
        }
        "sync" => {
            if opts.key.is_some()
                || unexpected
                || opts.replace
                || usize::from(opts.file.is_some()) + usize::from(opts.stdin) != 1
            {
                return Err(err("invalid sync option"));
            }
        }
        _ => {}
    }
    if vault_creation_options(opts) {
        return Err(err("invalid operation option"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "shared command handler keeps nested and shortcut operations identical"
)]
fn operation(action: &str, args: &[String], vault: Option<&str>, config: &Config) -> Result<()> {
    if !matches!(
        action,
        "ls" | "search"
            | "show"
            | "field-ls"
            | "get"
            | "getx"
            | "field-get"
            | "attachment-ls"
            | "attachment-get"
            | "set"
            | "field-set"
            | "setx"
            | "ensure"
            | "rm"
            | "field-rm"
            | "attachment-add"
            | "attachment-rm"
            | "otp"
            | "import"
            | "export"
            | "sync"
            | "group-ls"
            | "group-add"
            | "group-rm"
    ) {
        return Err(err("unknown operation"));
    }
    let mut opts = options(args, Positional::for_action(action))?;
    if matches!(action, "import" | "export" | "sync" | "setx") {
        validate_automation_options(action, &opts)?;
    } else {
        validate_regular_options(action, &opts)?;
    }
    if matches!(action, "get" | "getx" | "set") && opts.field.is_none() {
        opts.field = opts
            .key
            .and_then(|name| config.aliases.get(name))
            .and_then(|alias| alias.field.as_deref());
    }
    let requires_key = !matches!(
        action,
        "ls" | "search" | "import" | "export" | "sync" | "group-ls"
    );
    let selector = if requires_key {
        Some(opts.key.ok_or_else(|| err("--key required"))?)
    } else {
        None
    };
    let (path, _) = active_vault(vault, config)?;
    let mut credentials = credentials(&opts)?;
    if matches!(action, "group-ls" | "group-add" | "group-rm") {
        return group_operation(action, &opts, &path, &mut credentials);
    }
    if matches!(action, "import" | "export" | "sync") {
        return service_automation_operation(action, &opts, &path, &mut credentials);
    }
    if action == "search" {
        if opts.key.is_some() || opts.field.is_some() || opts.name.is_some() {
            return Err(err("invalid search option"));
        }
        let query = opts
            .glob
            .as_ref()
            .ok_or_else(|| err("search query required"))?;
        if query.is_empty() || query.len() > MAX_SEARCH_QUERY_BYTES {
            return Err(err("invalid search query"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let mut cursor = None;
        let mut emitted = 0usize;
        let mut withheld = 0usize;
        loop {
            let page = service
                .search_page(session, query, cursor)
                .map_err(|error| err(error.message()))?;
            withheld = withheld.saturating_add(page.withheld);
            for hit in page.hits {
                write_search_hit(&hit)?;
                emitted += 1;
                if emitted == 1_000 {
                    break;
                }
            }
            if emitted == 1_000 {
                break;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        report_withheld(withheld);
        service
            .lock(session)
            .map_err(|error| err(error.message()))?;
        return Ok(());
    }
    if action == "ls" {
        if opts.key.is_some() || opts.field.is_some() || opts.name.is_some() {
            return Err(err("invalid list option"));
        }
        if opts
            .glob
            .is_some_and(|pattern| pattern.len() > nkeepass::MAX_LIST_PATTERN_BYTES)
        {
            return Err(err(format!(
                "glob pattern is {} bytes; the limit is {}",
                opts.glob.map_or(0, str::len),
                nkeepass::MAX_LIST_PATTERN_BYTES
            )));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let mut cursor = None;
        let mut withheld = 0usize;
        loop {
            let page = service
                .list_page(session, opts.glob, cursor)
                .map_err(|error| err(error.message()))?;
            withheld = withheld.saturating_add(page.withheld);
            for hit in &page.hits {
                write_search_hit(hit)?;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        report_withheld(withheld);
        service
            .lock(session)
            .map_err(|error| err(error.message()))?;
        return Ok(());
    }
    if matches!(action, "show" | "field-ls") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        if action == "field-ls"
            && (opts.field.is_some() || opts.name.is_some() || opts.file.is_some() || opts.stdin)
        {
            return Err(err("invalid field list option"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let (resolved_selector, output_path) = if let Some(alias) = config.aliases.get(selector)
            {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                (alias.target.as_str(), alias.target.as_str())
            } else {
                (selector, selector)
            };
            let resolved = service
                .resolve_entry(session, resolved_selector)
                .map_err(|error| err(error.message()))?;
            if action == "show" {
                let selected = service
                    .selected_entry(&resolved.reference())
                    .map_err(|error| err(error.message()))?;
                write_selected_entry(&selected, output_path)
            } else {
                let fields = service
                    .field_metadata(&resolved.reference())
                    .map_err(|error| err(error.message()))?;
                write_selected_fields(&fields)
            }
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "get" | "getx" | "field-get") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let format = opts
            .format
            .unwrap_or(if action == "getx" { "json" } else { "text" });
        if action == "getx" && format != "json" {
            return Err(err("getx requires JSON format"));
        }
        if opts.age_encrypt
            && (action != "get"
                || !matches!(format, "text")
                || opts.name.is_some()
                || opts.is_output)
        {
            return Err(err("age encryption requires plain get output"));
        }
        if is_named_format(format) && opts.name.is_none() {
            return Err(err("--name required for formatted output"));
        }
        if !is_named_format(format) && opts.name.is_some() {
            return Err(err("--name requires a named output format"));
        }
        if opts.is_output && format != "azure-devops" {
            return Err(err("--is-output requires the azure-devops format"));
        }
        let field = if action == "field-get" {
            Some(opts.field.ok_or_else(|| err("--field required"))?)
        } else {
            opts.field
        };
        if action == "field-get"
            && matches!(
                field,
                Some("Password" | "Title" | "UserName" | "URL" | "Notes")
            )
        {
            return Err(err("custom field required"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            let value = service
                .reveal_field(&resolved.reference(), field.unwrap_or("Password"))
                .map_err(|error| match error {
                    nkeepass::ServiceError::Ambiguous => err("ambiguous field name"),
                    nkeepass::ServiceError::NotFound => err("field not found"),
                    error => err(error.message()),
                })?;
            if opts.age_encrypt {
                let recipients = age_recipients(&opts.age_recipients)?;
                let encrypted = AgeFile::encrypt_armored(value.as_slice(), &recipients)
                    .map_err(|_| err("age encryption failed"))?;
                if let Some(path) = opts.output {
                    write_private_output(path, encrypted.as_bytes())
                } else {
                    io::stdout()
                        .write_all(encrypted.as_bytes())
                        .and_then(|()| io::stdout().write_all(b"\n"))
                        .map_err(|_| err("cannot write encrypted output"))
                }
            } else {
                emit_value(value.as_slice(), format, opts.name, opts.is_output)
            }
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "attachment-ls" | "attachment-get") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        if action == "attachment-ls"
            && (opts.field.is_some() || opts.name.is_some() || opts.file.is_some() || opts.stdin)
        {
            return Err(err("invalid attachment list option"));
        }
        let name = if action == "attachment-get" {
            Some(
                opts.field
                    .ok_or_else(|| err("--field attachment name required"))?,
            )
        } else {
            None
        };
        let output = if action == "attachment-get" {
            Some(opts.output.ok_or_else(|| err("--output required"))?)
        } else {
            None
        };
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            if action == "attachment-ls" {
                let attachments = service.attachment_metadata(&resolved.reference()).map_err(
                    |error| match error {
                        nkeepass::ServiceError::Ambiguous => err("ambiguous attachment name"),
                        nkeepass::ServiceError::InvalidInput => {
                            err("vault metadata cannot contain terminal-control bytes")
                        }
                        nkeepass::ServiceError::NotFound => err("attachment unavailable"),
                        error => err(error.message()),
                    },
                )?;
                for attachment in attachments {
                    json(&serde_json::json!({
                        "name": attachment.name(),
                        "bytes": attachment.size(),
                        "protected": attachment.protected(),
                    }))?;
                }
            } else {
                let name = name.expect("attachment-get selector validated above");
                let attachment = service
                    .attachment_metadata_for(&resolved.reference(), name)
                    .map_err(|error| match error {
                        nkeepass::ServiceError::Ambiguous => err("ambiguous attachment name"),
                        nkeepass::ServiceError::InvalidInput => {
                            err("vault metadata cannot contain terminal-control bytes")
                        }
                        nkeepass::ServiceError::NotFound => err("attachment not found"),
                        error => err(error.message()),
                    })?;
                let bytes = service.reveal_attachment(&attachment.reference()).map_err(
                    |error| match error {
                        nkeepass::ServiceError::Ambiguous => err("ambiguous attachment name"),
                        nkeepass::ServiceError::NotFound => err("attachment unavailable"),
                        error => err(error.message()),
                    },
                )?;
                write_private_output(
                    output.expect("attachment-get output validated above"),
                    bytes.as_slice(),
                )?;
            }
            Ok(())
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "set" | "field-set") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let name = opts.field.unwrap_or("Password");
        if action == "field-set"
            && (opts.field.is_none()
                || matches!(name, "Password" | "Title" | "UserName" | "URL" | "Notes"))
        {
            return Err(err("custom field required"));
        }
        let bytes = input_value(&opts)?;
        let bytes = if opts.age_decrypt {
            let identities = age_identities(
                opts.age_identity
                    .ok_or_else(|| err("age identity required"))?,
            )?;
            decrypt_age_input(&bytes, &identities)?
        } else {
            bytes
        };
        let value = Zeroizing::new(
            String::from_utf8(bytes.to_vec()).map_err(|_| err("field requires UTF-8"))?,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            let reference = resolved.reference();
            let mutation = if action == "field-set" {
                service.set_custom_field(&reference, name, value.as_str())
            } else {
                service.set_field(&reference, name, value.as_str())
            };
            mutation.map_err(|error| match error {
                nkeepass::ServiceError::DuplicateIds => {
                    err("vault contains duplicate object UUIDs")
                }
                nkeepass::ServiceError::DuplicateFields => err("entry contains duplicate fields"),
                nkeepass::ServiceError::AmbiguousField => err("ambiguous field name"),
                nkeepass::ServiceError::InvalidFieldName => err("invalid field name"),
                nkeepass::ServiceError::FieldConflict => err("title cannot be changed through set"),
                error => err(error.message()),
            })?;
            if !opts.dry_run {
                service
                    .save(&path, &mut credentials)
                    .map_err(|error| err(error.message()))?;
            }
            Ok(())
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if action == "setx" {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let input = automation_input(&opts, interchange::SETX_LIMITS.max_bytes)?;
        let updates = interchange::decode_setx(&input).map_err(interchange_error)?;
        let updates = updates
            .into_iter()
            .map(|update| FieldUpdate {
                key: update.key,
                value: update.value,
                protected: update.protected,
                protect_in_memory: update.protect_in_memory,
            })
            .collect();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            let field_count = service.set_fields(&resolved.reference(), updates).map_err(
                |error| match error {
                    nkeepass::ServiceError::DuplicateIds => {
                        err("vault contains duplicate object UUIDs")
                    }
                    nkeepass::ServiceError::DuplicateFields => {
                        err("entry contains duplicate fields")
                    }
                    nkeepass::ServiceError::InvalidFieldName => err("invalid setx field"),
                    error => err(error.message()),
                },
            )?;
            if !opts.dry_run {
                service
                    .save(&path, &mut credentials)
                    .map_err(|error| err(error.message()))?;
            }
            json(&serde_json::json!({
                "operation": "setx",
                "dry_run": opts.dry_run,
                "fields_updated": field_count,
            }))
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if action == "ensure" {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let created = service
                .ensure_entry(session, entry_selector, opts.size, opts.dry_run)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    nkeepass::ServiceError::RootGroup => {
                        err("that path names the root group, not an entry")
                    }
                    nkeepass::ServiceError::InvalidInput => err("invalid entry path"),
                    nkeepass::ServiceError::InvalidSize => err("invalid size"),
                    nkeepass::ServiceError::Ambiguous => err("ambiguous entry path"),
                    error => err(error.message()),
                })?;
            if created && !opts.dry_run {
                service
                    .save(&path, &mut credentials)
                    .map_err(|error| err(error.message()))?;
            }
            Ok(())
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "rm" | "field-rm") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let name = if action == "field-rm" {
            let name = opts.field.ok_or_else(|| err("--field required"))?;
            if matches!(name, "Password" | "Title" | "UserName" | "URL" | "Notes") {
                return Err(err("custom field required"));
            }
            Some(name)
        } else {
            None
        };
        if !opts.yes {
            return Err(err("removal requires --yes"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            let reference = resolved.reference();
            let mutation = if let Some(name) = name {
                service.remove_custom_field(&reference, name)
            } else {
                service.remove_entry(&reference)
            };
            mutation.map_err(|error| match error {
                nkeepass::ServiceError::DuplicateIds => {
                    err("vault contains duplicate object UUIDs")
                }
                nkeepass::ServiceError::DuplicateFields => err("entry contains duplicate fields"),
                nkeepass::ServiceError::Ambiguous => err("ambiguous field name"),
                nkeepass::ServiceError::NotFound => err("field not found"),
                nkeepass::ServiceError::FieldConflict => err("custom field required"),
                error => err(error.message()),
            })?;
            service
                .save(&path, &mut credentials)
                .map_err(|error| err(error.message()))
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "attachment-add" | "attachment-rm") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let name = opts
            .field
            .ok_or_else(|| err("--field attachment name required"))?;
        if action == "attachment-add"
            && (name.is_empty() || name.contains('/') || name.chars().any(char::is_control))
        {
            return Err(err("invalid attachment name"));
        }
        if action == "attachment-rm" && !opts.yes {
            return Err(err("removal requires --yes"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry(session, entry_selector)
                .map_err(|error| match error {
                    nkeepass::ServiceError::NotFound => {
                        entry_not_found(&service, session, entry_selector)
                    }
                    error => err(error.message()),
                })?;
            let reference = resolved.reference();
            if action == "attachment-add" {
                let data = input_value(&opts)?;
                service.add_attachment(&reference, name, data)
            } else {
                service.remove_attachment(&reference, name)
            }
            .map_err(|error| match error {
                nkeepass::ServiceError::InvalidInput => err("invalid attachment name"),
                nkeepass::ServiceError::AttachmentExists => err("attachment already exists"),
                nkeepass::ServiceError::Ambiguous => err("ambiguous attachment name"),
                nkeepass::ServiceError::NotFound => err("attachment not found"),
                nkeepass::ServiceError::InvalidAttachmentReference => {
                    err("invalid attachment reference")
                }
                error => err(error.message()),
            })?;
            service
                .save(&path, &mut credentials)
                .map_err(|error| err(error.message()))?;
            Ok(())
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if action == "otp" {
        let format = opts.format.unwrap_or("text");
        if is_named_format(format) && opts.name.is_none() {
            return Err(err("--name required for formatted output"));
        }
        if !is_named_format(format) && opts.name.is_some() {
            return Err(err("--name requires a named output format"));
        }
        if opts.is_output && format != "azure-devops" {
            return Err(err("--is-output requires the azure-devops format"));
        }
        if !opts.name.is_none_or(valid_env_name) {
            return Err(err("invalid output name"));
        }
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials, &KDBX_LIMITS)
            .map_err(|error| err(error.message()))?;
        let result = (|| {
            let selector = selector.ok_or_else(|| err("--key required"))?;
            let entry_selector = if let Some(alias) = config.aliases.get(selector) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != selector {
                    match service.resolve_entry_for_otp(session, selector) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::SelectorError::NotFound) => {}
                        Err(error) => return Err(otp_selector_error(selector, error)),
                    }
                }
                alias.target.as_str()
            } else {
                selector
            };
            let resolved = service
                .resolve_entry_for_otp(session, entry_selector)
                .map_err(|error| otp_selector_error(entry_selector, error))?;
            let timestamp = otp_now()?;
            let code = service
                .otp_code(&resolved.reference(), timestamp)
                .map_err(|error| err(error.message()))?;
            emit_value(code.as_bytes(), format, opts.name, opts.is_output)
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    Err(err("unsupported operation"))
}

fn group_operation(
    action: &str,
    opts: &Options<'_>,
    path: &Path,
    credentials: &mut KdbxCredentials,
) -> Result<()> {
    if action == "group-rm" && !opts.yes && !opts.dry_run {
        return Err(err("removal requires --yes"));
    }
    let mut service = VaultService::default();
    let session = service
        .open(path, credentials, &KDBX_LIMITS)
        .map_err(|error| err(error.message()))?;
    let result = (|| {
        let changed = match action {
            "group-ls" => {
                let metadata = service
                    .completion_metadata()
                    .map_err(|error| err(error.message()))?;
                for group in metadata.groups {
                    print_line(&group)?;
                }
                false
            }
            "group-add" => {
                service
                    .ensure_group(
                        session,
                        opts.key.ok_or_else(|| err("--key required"))?,
                        opts.dry_run,
                    )
                    .map_err(|error| err(error.message()))?
                    > 0
            }
            "group-rm" => {
                let reference = service
                    .resolve_group(session, opts.key.ok_or_else(|| err("--key required"))?)
                    .map_err(|error| err(error.message()))?;
                if reference
                    == service
                        .root_group(session)
                        .map_err(|error| err(error.message()))?
                {
                    return Err(err("the root group cannot be removed"));
                }
                if !opts.dry_run {
                    service
                        .remove_group(&reference)
                        .map_err(|error| err(error.message()))?;
                }
                true
            }
            _ => return Err(err("unknown group operation")),
        };
        if changed && !opts.dry_run {
            service
                .save(path, credentials)
                .map_err(|error| err(error.message()))?;
        }
        Ok(())
    })();
    let locked = service.lock(session).map_err(|error| err(error.message()));
    result?;
    locked
}

struct EnvBinding<'a> {
    key: &'a str,
    field: Option<&'a str>,
    name: &'a str,
}

struct EnvOptions<'a> {
    bindings: Vec<EnvBinding<'a>>,
    format: String,
    common: Vec<String>,
}

fn parse_env_options(args: &[String]) -> Result<EnvOptions<'_>> {
    let mut bindings = Vec::new();
    let mut current: Option<(&str, Option<&str>)> = None;
    let mut common = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                if current.is_some() {
                    return Err(err("--key must start a value binding"));
                }
                i += 1;
                current = Some((take_arg(args, i)?, None));
            }
            "--field" if current.is_none() => return Err(err("--key required before --field")),
            "--name" if current.is_none() => return Err(err("--name requires a value binding")),
            "--field" if current.is_some() => {
                i += 1;
                let (key, field) = current.ok_or_else(|| err("--key required before --field"))?;
                if field.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                current = Some((key, Some(take_arg(args, i)?)));
            }
            "--name" if current.is_some() => {
                i += 1;
                let name = take_arg(args, i)?;
                let (key, field) = current.take().ok_or_else(|| err("invalid value binding"))?;
                bindings.push(EnvBinding { key, field, name });
            }
            _ => {
                common.push(args[i].clone());
            }
        }
        i += 1;
    }
    if current.is_some() {
        return Err(err("incomplete value binding"));
    }
    if bindings.is_empty() {
        return Err(err(
            "secrets env requires at least one --key/--field/--name binding",
        ));
    }
    let common_options = options(&common, Positional::Forbidden)?;
    // `secrets env` has no value-file, mutation, or interchange options. Check
    // this allowlist before resolving a vault or reading credentials.
    if common_options.key.is_some()
        || common_options.field.is_some()
        || common_options.name.is_some()
        || common_options.file.is_some()
        || common_options.output.is_some()
        || common_options.yes
        || common_options.dry_run
        || common_options.replace
        || common_options.size.is_some()
        || common_options.glob.is_some()
        || common_options.stdin
        || common_options.strategy.is_some()
        || vault_creation_options(&common_options)
    {
        return Err(err("invalid operation option"));
    }
    let common_refs = common.iter().map(String::as_str).collect::<Vec<_>>();
    let format = match common_refs
        .iter()
        .position(|argument| *argument == "--format")
    {
        Some(index) => common_refs
            .get(index + 1)
            .copied()
            .ok_or_else(|| err("--format requires a value"))?
            .to_owned(),
        None => "shell".to_owned(),
    };
    if !is_named_format(&format) && !matches!(format.as_str(), "json" | "null") {
        return Err(err("invalid output format"));
    }
    if common_options.is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    Ok(EnvOptions {
        bindings,
        format,
        common,
    })
}

fn emit_environment(
    bindings: &[(String, SecretBytes)],
    format: &str,
    is_output: bool,
) -> Result<()> {
    if is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    if is_named_format(format) {
        // Every binding goes through the same validation `emit_value` does, and
        // it happens before the first record is written: a refusal after a
        // disclosure would leave the caller with a truncated set that looks
        // complete.
        for (name, value) in bindings {
            named_text(format, Some(name), value.as_slice())?;
        }
    } else {
        match format {
            "json" => {
                for (_, value) in bindings {
                    std::str::from_utf8(value.as_slice()).map_err(|_| err("value is not UTF-8"))?;
                }
            }
            "null" => {
                for (name, value) in bindings {
                    if name.as_bytes().contains(&0) || value.as_slice().contains(&0) {
                        return Err(err("null output cannot contain NUL in names or values"));
                    }
                }
            }
            _ => return Err(err("invalid output format")),
        }
    }
    if is_named_format(format) {
        for (name, value) in bindings {
            emit_value(value.as_slice(), format, Some(name), is_output)?;
        }
        return Ok(());
    }
    match format {
        "null" => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            for (name, value) in bindings {
                output
                    .write_all(name.as_bytes())
                    .and_then(|()| output.write_all(b"\0"))
                    .and_then(|()| output.write_all(value.as_slice()))
                    .and_then(|()| output.write_all(b"\0"))
                    .map_err(|_| err("cannot write value"))?;
            }
            Ok(())
        }
        "json" => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            let mut serializer = serde_json::Serializer::new(&mut output);
            let mut map = serializer
                .serialize_map(Some(bindings.len()))
                .map_err(|_| err("cannot encode output"))?;
            for (name, value) in bindings {
                let text =
                    std::str::from_utf8(value.as_slice()).map_err(|_| err("value is not UTF-8"))?;
                map.serialize_entry(name, text)
                    .map_err(|_| err("cannot encode output"))?;
            }
            map.end().map_err(|_| err("cannot encode output"))?;
            output
                .write_all(b"\n")
                .map_err(|_| err("cannot write output"))
        }
        _ => Err(err("invalid output format")),
    }
}

/// Rejects the option surface `init` does not have.
///
/// The allowlist is written out rather than derived, so a newly added option
/// defaults to *rejected* here. A silently ignored flag is how a caller comes to
/// believe a vault was hardened or written when it was not.
fn validate_init_options(opts: &Options<'_>) -> Result<()> {
    if opts.key.is_some()
        || opts.field.is_some()
        || opts.name.is_some()
        || opts.file.is_some()
        || opts.output.is_some()
        || opts.yes
        || opts.dry_run
        || opts.replace
        || opts.glob.is_some()
        || opts.format.is_some()
        || opts.is_output
        || opts.strategy.is_some()
        || opts.stdin
    {
        return Err(err("invalid operation option"));
    }
    if opts
        .size
        .is_some_and(|size| size == 0 || size > MAX_GENERATED_PASSWORD)
    {
        return Err(err("invalid size"));
    }
    Ok(())
}

fn bounded_kdf_count(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| err("value exceeds the pinned KDF limit"))
}

/// The writer policy a new vault is created with.
///
/// The defaults are the library's, which is the pinned policy every other
/// `nkeepass` save already uses, and every override is bounded by the same
/// [`KDBX_LIMITS`] the reader enforces. That is deliberate in both directions:
/// `init` does not write a file the rest of the CLI reads under different
/// assumptions, and it cannot write a file this CLI would then refuse to open.
fn init_write_options(opts: &Options<'_>) -> Result<KdbxWriteOptions> {
    let kdf = match opts.kdf.unwrap_or("aes") {
        "aes" => KdbxKdf::Aes,
        "argon2d" => KdbxKdf::Argon2d,
        "argon2id" => KdbxKdf::Argon2id,
        _ => return Err(err("invalid kdf")),
    };
    let argon2 = !matches!(kdf, KdbxKdf::Aes);
    if !argon2 && (opts.memory.is_some() || opts.parallelism.is_some()) {
        return Err(err("--memory and --parallelism require an Argon2 KDF"));
    }
    let mut write = KdbxWriteOptions {
        kdf,
        ..KdbxWriteOptions::default()
    };
    if let Some(count) = opts.iterations {
        let limit = if argon2 {
            u64::from(KDBX_LIMITS.max_argon2_time)
        } else {
            KDBX_LIMITS.max_aes_kdf_rounds
        };
        if count == 0 || count > limit {
            return Err(err("iterations exceed the pinned KDF limit"));
        }
        if argon2 {
            write.argon2_time = bounded_kdf_count(count)?;
        } else {
            write.aes_kdf_rounds = count;
        }
    }
    if let Some(memory) = opts.memory {
        if memory == 0 || memory > u64::from(KDBX_LIMITS.max_argon2_memory_kib) {
            return Err(err("memory exceeds the pinned KDF limit"));
        }
        write.argon2_memory_kib = bounded_kdf_count(memory)?;
    }
    if let Some(lanes) = opts.parallelism {
        if lanes == 0 || lanes > u64::from(KDBX_LIMITS.max_argon2_lanes) {
            return Err(err("parallelism exceeds the pinned KDF limit"));
        }
        write.argon2_lanes = bounded_kdf_count(lanes)?;
    }
    Ok(write)
}

fn kdf_name(kdf: KdbxKdf) -> &'static str {
    match kdf {
        KdbxKdf::Aes => "aes",
        KdbxKdf::Argon2d => "argon2d",
        KdbxKdf::Argon2id => "argon2id",
    }
}

/// Reports the KDF settings the new file's header will carry, so a caller can
/// confirm what it got without parsing the header itself.
fn kdf_parameters(write: &KdbxWriteOptions) -> serde_json::Value {
    match write.kdf {
        KdbxKdf::Aes => serde_json::json!({"aes_kdf_rounds": write.aes_kdf_rounds}),
        KdbxKdf::Argon2d | KdbxKdf::Argon2id => serde_json::json!({
            "memory_kib": write.argon2_memory_kib,
            "iterations": write.argon2_time,
            "parallelism": write.argon2_lanes,
        }),
    }
}

/// Creates a new vault at the resolved path.
///
/// The order is the security property. Every check that can fail runs before
/// the target is touched; the encrypted bytes are staged in an owner-only file
/// beside it; and the staging file is installed with create-if-absent
/// semantics. So a rejected request, a failed prompt, or a lost race all leave
/// the target path exactly as it was, and none of them can have replaced a file
/// that was already there.
#[allow(
    clippy::too_many_lines,
    reason = "the create-then-adopt ordering is the point, so it stays in one place"
)]
fn init_command(args: &[String], vault: Option<&str>, config: &mut Config) -> Result<()> {
    let opts = options(args, Positional::Path)?;
    validate_init_options(&opts)?;
    let write = init_write_options(&opts)?;

    // An explicit target wins over the ambient precedence. Supplying both a
    // positional PATH and the global --vault is not ordered but ambiguous, and
    // this CLI's standing rule is that an ambiguous selection is an error.
    let explicit = match (opts.path, vault) {
        (Some(_), Some(_)) => return Err(err("init accepts one target path")),
        (Some(path), None) | (None, Some(path)) => Some(path),
        (None, None) => None,
    };
    let use_default_alias = explicit.is_none();
    let (path, source) = match explicit {
        // `init` takes a filesystem path, never an alias. Relative targets are
        // anchored to the process working directory and normalized before the
        // create-if-absent transaction starts.
        Some(target) => (init_target_path(target)?, "argument"),
        None => active_vault(None, config)?,
    };
    // The resolved path is echoed in the result and stored in a JSON
    // configuration file, so it has to round-trip as text. Checking here, before
    // anything is created, keeps a non-UTF-8 default target from producing a
    // vault and then failing to report it.
    if path.to_str().is_none() {
        return Err(err("vault path is not valid UTF-8"));
    }
    let path_text = normalized_vault_text(&path);

    let mut credentials = credentials(&opts)?;
    let service = VaultService::default();
    // `init` exists so the next command works, and the context is what makes
    // that true with no extra step. Replacing a context the user chose is a
    // different matter: silently retargeting someone's selection at a vault
    // they did not ask for is the kind of surprise this CLI refuses elsewhere,
    // so an existing context is left alone and `nkeepass context use` remains
    // the way to change it. The flag is reported because "usable immediately"
    // and "did not touch your configuration" must not look identical.
    let context_set = adopt_after_init_create(
        config,
        &path_text,
        use_default_alias,
        service.create(&path, &mut credentials, write, opts.size),
        save_config,
    )?;

    json(&serde_json::json!({
        "operation": "init",
        "path": path_text,
        "source": source,
        "context_set": context_set,
        "kdf": kdf_name(write.kdf),
        "kdf_parameters": kdf_parameters(&write),
        "generated_password": opts.size.is_some(),
    }))
}

fn adopt_after_init_create(
    config: &mut Config,
    path: &str,
    use_default_alias: bool,
    create_result: std::result::Result<(), nkeepass::ServiceError>,
    persist: impl FnOnce(&Config) -> Result<()>,
) -> Result<bool> {
    match create_result {
        Ok(()) => adopt_init_context_with(config, path, use_default_alias, persist),
        Err(nkeepass::ServiceError::CreateDurability) => {
            // Installation already happened. Keep the new vault reachable from
            // the CLI context before reporting the durability warning/error.
            match adopt_init_context_with(config, path, use_default_alias, persist) {
                Ok(_) => Err(err(nkeepass::ServiceError::CreateDurability.message())),
                Err(context_error) => Err(err(format!(
                    "{}; {}",
                    nkeepass::ServiceError::CreateDurability.message(),
                    context_error.0
                ))),
            }
        }
        Err(error) => Err(err(error.message())),
    }
}

fn adopt_init_context_with(
    config: &mut Config,
    path: &str,
    use_default_alias: bool,
    persist: impl FnOnce(&Config) -> Result<()>,
) -> Result<bool> {
    if config.current.is_some() {
        return Ok(false);
    }
    let current = if use_default_alias {
        match config.aliases.get("default") {
            Some(alias) if alias.kind == Kind::Vault && alias.target == path => "default",
            Some(_) => return Ok(false),
            None => {
                config.aliases.insert(
                    "default".to_owned(),
                    Alias {
                        kind: Kind::Vault,
                        target: path.to_owned(),
                        field: None,
                    },
                );
                "default"
            }
        }
    } else {
        path
    };
    config.current = Some(current.to_owned());
    persist(config)?;
    Ok(true)
}

/// The seconds of wall-clock time an invocation pins its TOTP codes to.
///
/// A TOTP code is a function of time with a 30-second period, so two codes
/// generated microseconds apart can straddle a period boundary and disagree.
/// A consumer holding two codes for what it believes is one moment has no way to
/// tell that one of them is already stale -- it just sees a rejection and blames
/// the wrong thing.
///
/// So the timestamp is taken **once per invocation** and every code in that
/// invocation is derived from it. Two codes bound in one `secrets env` are
/// therefore always consistent, even across a period boundary, and the cost is
/// that a single invocation spanning a boundary emits two codes from the earlier
/// window -- where both are still valid, because the earlier window has not
/// ended. The alternative, generating per binding, silently produces mismatched
/// pairs that look like user error.
///
/// This is a decision, not an implementation detail, and it is stated in `--help`
/// so a user reading the contract learns it rather than inferring it from a
/// mysterious failure.
fn otp_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| err("system clock unavailable"))
}

/// The remaining seconds in a TOTP code's validity window, or `None` if unknown.
///
/// A code generated at `timestamp` is valid for the rest of the period it landed
/// in, so this is the number of seconds during which a consumer that starts using
/// the code at the last moment can still be refused by a server that began its
/// own window earlier. Servers commonly allow a one-period skew, which is what
/// makes the last few seconds worth warning about.
fn otp_seconds_remaining(timestamp: u64, period: u64) -> Option<u64> {
    (period > 0).then(|| period - (timestamp % period))
}

/// Warn that a bound TOTP code is close to expiry.
///
/// On **stderr only**, and naming the binding and the seconds left -- never the
/// code. A code printed twice is a code in two places: the intended destination
/// and a log.
fn warn_otp_expiring(name: &str, timestamp: u64, period: u64) {
    if let Some(remaining) = otp_seconds_remaining(timestamp, period)
        && remaining <= OTP_EXPIRY_WARNING_SECONDS
    {
        eprintln!(
            "nkeepass: warning: the code bound to {name} expires in {remaining}s; \
             a server that started its window early may already reject it"
        );
    }
}

/// How close to expiry a bound code must be before it is worth a warning.
const OTP_EXPIRY_WARNING_SECONDS: u64 = 10;

/// Resolve what a binding should emit.
///
/// `otp` is **not** a field name here, it is a selector. The distinction is the
/// whole fix for #22: the entry's field named `otp` holds the URI, so a
/// selector that meant "the field called otp" would emit the seed. A user who
/// writes `--field otp` means a one-time code, and that is what they get.
///
/// Every other name is an ordinary field read, unchanged.
enum Bound<'a> {
    Field(&'a str),
    Otp,
}

impl<'a> Bound<'a> {
    fn from_field(field: &'a str) -> Self {
        if field == "otp" {
            Self::Otp
        } else {
            Self::Field(field)
        }
    }
}

/// Runs the `config` group.
///
/// There is deliberately no private read or write of the configuration file
/// here. `run` has already loaded it through [`load_config`] -- so every
/// permission, symlink, size, and unknown-field check applies to every command
/// in this group by construction -- and every mutation below goes back out
/// through [`save_config`], the one writer that stages an owner-only file,
/// syncs it, installs it atomically, and confirms directory durability. A
/// second path that skipped either would be a way to write the file that the
/// existing checks do not cover, which is the one thing this group must not
/// become.
///
/// The group takes no vault, credential, or option surface, so it also has no
/// shared option parser to reuse: like `context` and `alias`, it parses its own
/// small closed argument list and refuses everything else rather than ignoring
/// a flag it does not understand.
fn config_command(args: &[String], config: &mut Config) -> Result<()> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| err("invalid config command; see --help"))?;
    let rest = &args[1..];
    match action {
        "list" | "ls" => {
            let (glob, as_json) = config_list_arguments(rest)?;
            config_list(config, glob.as_deref(), as_json)
        }
        "get" | "show" if rest.len() == 1 => config_get(config, ConfigKey::parse(&rest[0])?),
        "set" if rest.len() == 2 => config_set(config, ConfigKey::parse(&rest[0])?, &rest[1]),
        "rm" | "remove" if rest.len() == 1 => config_remove(config, ConfigKey::parse(&rest[0])?),
        _ => Err(err("invalid config command; see --help")),
    }
}

/// `config ls`'s arguments: one optional GLOB and one optional `--json`.
///
/// `--` is accepted before the glob as it is for `secrets ls`, so a pattern
/// beginning with `-` has a spelling. Anything else is refused: this group has
/// no other options, and silently ignoring one is how a script comes to believe
/// it asked for a filtered listing and received all of them.
fn config_list_arguments(args: &[String]) -> Result<(Option<String>, bool)> {
    let (mut glob, mut as_json, mut terminated) = (None, false, false);
    for arg in args {
        if terminated {
            if glob.is_none() {
                glob = Some(arg.clone());
                continue;
            }
            return Err(err("invalid config option"));
        }
        match arg.as_str() {
            "--" => terminated = true,
            "--json" if !as_json => as_json = true,
            _ if !arg.starts_with('-') && glob.is_none() => glob = Some(arg.clone()),
            _ => return Err(err("invalid config option")),
        }
    }
    Ok((glob, as_json))
}

/// The JSON value `config ls --json` reports for one key.
fn config_json_value(config: &Config, key: ConfigKey) -> Result<serde_json::Value> {
    if key == ConfigKey::Aliases {
        let mut map = serde_json::Map::new();
        for (name, alias) in &config.aliases {
            check_alias_metadata(name, alias)?;
            let value = serde_json::to_value(alias).map_err(|_| err("cannot encode output"))?;
            map.insert(name.clone(), value);
        }
        return Ok(serde_json::Value::Object(map));
    }
    let stored = config.value(key);
    if let Some(value) = stored {
        check_config_value(value)?;
    }
    Ok(match stored {
        Some(value) => serde_json::Value::String(value.clone()),
        None => serde_json::Value::Null,
    })
}

/// One line of `config ls` output, rendered before any of it is written.
enum ConfigRow {
    /// A JSON record, written by `json` so the encoding stays in one place.
    Record(serde_json::Value),
    /// A `KEY<TAB>VALUE` text row.
    Text(String),
}

/// Every line a listing will print, built before the first one is written.
///
/// The order is the point. A listing is the one command here whose output is
/// read by a script, so a listing that printed `aliases` and *then* refused a
/// hostile `current` would be indistinguishable from a complete one with keys
/// missing from it. Rendering everything first means a refusal leaves stdout
/// empty, which is the same contract `list_fields` and `list_attachments` keep
/// for the same reason.
fn config_listing(config: &Config, glob: Option<&str>, as_json: bool) -> Result<Vec<ConfigRow>> {
    // Compiled once rather than per key, and through the same `compile_glob` the
    // walk commands use, so `config ls` and `secrets ls` agree on what a pattern
    // means. A pattern that does not compile is refused here, before any row is
    // rendered, for the same reason the whole listing is rendered first: a
    // partial listing looks like a complete one.
    let glob = glob.map(compile_glob).transpose()?;
    CONFIG_KEYS
        .iter()
        .copied()
        .filter(|key| {
            glob.as_ref()
                .is_none_or(|pattern| pattern.is_match(key.name()))
        })
        .map(|key| {
            if as_json {
                return Ok(ConfigRow::Record(serde_json::json!({
                    "key": key.name(),
                    "value": config_json_value(config, key)?,
                })));
            }
            config_list_row(config, key).map(ConfigRow::Text)
        })
        .collect()
}

/// The text form of one key's row.
///
/// A map-valued key reports its size rather than becoming one enormous row, and
/// an unset scalar prints as the key alone, so a row that carries a value and a
/// row that does not are told apart without a placeholder word a script would
/// have to strip.
fn config_list_row(config: &Config, key: ConfigKey) -> Result<String> {
    if key == ConfigKey::Aliases {
        return Ok(format!("{}\t{}", key.name(), config.aliases.len()));
    }
    let stored = config.value(key);
    if let Some(value) = stored {
        check_config_value(value)?;
        return Ok(format!("{}\t{value}", key.name()));
    }
    Ok(key.name().to_owned())
}

/// `config ls` -- the key inventory, optionally filtered.
fn config_list(config: &Config, glob: Option<&str>, as_json: bool) -> Result<()> {
    for row in config_listing(config, glob, as_json)? {
        match row {
            ConfigRow::Record(record) => json(&record)?,
            ConfigRow::Text(line) => print_line(&line)?,
        }
    }
    Ok(())
}

/// `config get` -- one key's value, in the shape a caller can use it in.
fn config_get(config: &Config, key: ConfigKey) -> Result<()> {
    if key == ConfigKey::Aliases {
        // Built for the same reason as a listing: one hostile record must not
        // leave the benign ones already on stdout.
        let records = config
            .aliases
            .iter()
            .map(|(name, alias)| {
                check_alias_metadata(name, alias)?;
                Ok(serde_json::json!({
                    "name": name,
                    "kind": alias.kind,
                    "target": alias.target,
                    "field": alias.field,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        for record in records {
            json(&record)?;
        }
        return Ok(());
    }
    let value = config.value(key).ok_or_else(|| err(CONFIG_KEY_NOT_SET))?;
    check_config_value(value)?;
    // The bare value, not a JSON document, so `$(nkeepass config get current)`
    // is the path. A caller that wants a record has `config ls --json`.
    print_line(value)
}

/// `config set` -- validate first, then store, then save through the one writer.
fn config_set(config: &mut Config, key: ConfigKey, value: &str) -> Result<()> {
    if key == ConfigKey::Aliases {
        return Err(err(CONFIG_ALIASES_NOT_SCALAR));
    }
    if value.is_empty() {
        return Err(err("configuration value must not be empty"));
    }
    // Resolve before writing: a value the active-vault resolver would refuse
    // later is refused now, so the file cannot hold an unusable selector. Keep
    // the selector spelling so a configured alias can still be changed later.
    resolve_vault(value, config)?;
    check_config_value(value)?;
    config.set_value(key, Some(value.to_owned()))?;
    save_config(config)
}

/// `config rm` -- clear a scalar key, refusing the map-valued one.
fn config_remove(config: &mut Config, key: ConfigKey) -> Result<()> {
    if key == ConfigKey::Aliases {
        return Err(err(CONFIG_ALIASES_NOT_SCALAR));
    }
    if config.value(key).is_none() {
        return Err(err(CONFIG_KEY_NOT_SET));
    }
    config.set_value(key, None)?;
    save_config(config)
}

fn env_command(args: &[String], vault: Option<&str>, config: &Config) -> Result<()> {
    let opts = parse_env_options(args)?;
    let mut names = BTreeSet::new();
    for binding in &opts.bindings {
        if !valid_env_name(binding.name) || !names.insert(binding.name) {
            return Err(err("invalid or duplicate output name"));
        }
        if binding.field.is_none()
            && config
                .aliases
                .get(binding.key)
                .and_then(|alias| alias.field.as_deref())
                .is_none()
        {
            return Err(err("--field required"));
        }
    }
    let (path, _) = active_vault(vault, config)?;
    let credential_options = options(&opts.common, Positional::Forbidden)?;
    let is_output = credential_options.is_output;
    let mut credentials = credentials(&credential_options)?;
    let mut service = VaultService::default();
    let session = service
        .open(&path, &mut credentials, &KDBX_LIMITS)
        .map_err(|error| match error {
            nkeepass::ServiceError::Io => err("cannot open vault"),
            _ => err("cannot unlock vault"),
        })?;
    let mut values = Vec::with_capacity(opts.bindings.len());
    // Pinned once, for every binding in this invocation. See `otp_now`.
    let timestamp = otp_now()?;
    for binding in opts.bindings {
        let entry = resolve_service_selector(&service, session, binding.key, config)?;
        let alias_field = config
            .aliases
            .get(binding.key)
            .and_then(|alias| alias.field.as_deref());
        let field = binding
            .field
            .or(alias_field)
            .ok_or_else(|| err("--field required"))?;
        let bound = Bound::from_field(field);
        let value = match bound {
            Bound::Field(name) => reveal_native_service_field(&service, &entry, name)?,
            Bound::Otp => {
                let result = service
                    .totp_code_with_period(&entry.reference(), timestamp)
                    .map_err(|error| match error {
                        nkeepass::ServiceError::HotpUnsupported => {
                            err("HOTP requires atomic counter persistence")
                        }
                        nkeepass::ServiceError::AmbiguousField => err("ambiguous field name"),
                        _ => err("invalid OTP field"),
                    })?;
                warn_otp_expiring(binding.name, timestamp, result.period());
                SecretBytes::from_vec(result.code().as_bytes().to_vec())
            }
        };
        values.push((binding.name.to_owned(), value));
    }
    emit_environment(&values, &opts.format, is_output)
}

#[allow(
    clippy::too_many_lines,
    reason = "credential parsing and child-process isolation stay together"
)]
fn exec_command(args: &[String], vault: Option<&str>, config: &Config) -> Result<()> {
    let sep = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| err("exec requires -- COMMAND"))?;
    let command = args
        .get(sep + 1)
        .ok_or_else(|| err("exec requires a command"))?;
    let mut keys = Vec::new();
    let mut fields: Vec<Option<&str>> = Vec::new();
    let mut env_names = Vec::new();
    let mut password_arg = None;
    let mut password_env = None;
    let mut password_file = None;
    let mut key_file = None;
    let mut password_stdin = false;
    let mut i = 0;
    while i < sep {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                keys.push(take_arg(args, i)?.to_owned());
                // Every key has a field slot, so `--key/--field/--env` stay
                // positionally paired. Pushing `None` here rather than only when
                // `--field` is present is what keeps the two vectors the same
                // length; the alternative, a parallel `Vec<Option<&str>>` filled
                // out of band, is a length check waiting to be wrong.
                fields.push(None);
            }
            // `--field` applies to the `--key` before it, exactly as in
            // `secrets env`. Reusing that shape is deliberate: two commands that
            // bind the same values should not spell the binding differently.
            "--field" => {
                i += 1;
                let slot = fields
                    .last_mut()
                    .ok_or_else(|| err("--key required before --field"))?;
                if slot.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                *slot = Some(take_arg(args, i)?);
            }
            "--env" => {
                i += 1;
                env_names.push(take_arg(args, i)?.to_owned());
            }
            "--password" if password_arg.is_none() => {
                i += 1;
                password_arg = Some(take_arg(args, i)?);
            }
            "--password-env" if password_env.is_none() => {
                i += 1;
                password_env = Some(take_arg(args, i)?);
            }
            "--password-file" if password_file.is_none() => {
                i += 1;
                password_file = Some(take_arg(args, i)?);
            }
            "--key-file" if key_file.is_none() => {
                i += 1;
                key_file = Some(take_arg(args, i)?);
            }
            "--password-stdin" if !password_stdin => password_stdin = true,
            _ => return Err(err("invalid exec option")),
        }
        i += 1;
    }
    if keys.is_empty() {
        return Err(err("exec requires at least one --key"));
    }
    if keys.len() != env_names.len() {
        return Err(err("exec requires one --env name for each --key"));
    }
    let mut seen = BTreeSet::new();
    for name in &env_names {
        if name == DEFAULT_PASSWORD_ENV || password_env == Some(name.as_str()) {
            return Err(err(
                "exec environment name is reserved for the master password",
            ));
        }
        if !valid_env_name(name) || !seen.insert(name.clone()) {
            return Err(err("invalid or duplicate exec environment name"));
        }
    }
    let opts = Options {
        password: password_arg,
        password_env,
        password_file,
        key_file,
        password_stdin,
        ..Options::default()
    };
    validate_shared_options(&opts)?;
    let (path, _) = active_vault(vault, config)?;
    let mut credentials = credentials(&opts)?;
    let mut service = VaultService::default();
    let session = service
        .open(&path, &mut credentials, &KDBX_LIMITS)
        .map_err(|error| match error {
            nkeepass::ServiceError::Io => err("cannot open vault"),
            _ => err("cannot unlock vault"),
        })?;
    let mut values: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    // Pinned once for the whole invocation; see `otp_now`.
    let timestamp = otp_now()?;
    for ((key, field), name) in keys.iter().zip(&fields).zip(&env_names) {
        if env::var_os(name).is_some() {
            return Err(err("exec environment name already exists"));
        }
        let entry = resolve_service_selector(&service, session, key, config)?;
        let value: Zeroizing<String> = match field {
            // `exec` binds the password by default. A named field, and the `otp`
            // selector, are opt-in per binding.
            None => {
                let value = service
                    .reveal_password(&entry.reference())
                    .map_err(|_| err("cannot reveal value"))?;
                Zeroizing::new(
                    std::str::from_utf8(value.as_slice())
                        .map_err(|_| err("cannot reveal value"))?
                        .to_owned(),
                )
            }
            Some(field) => {
                let bound = Bound::from_field(field);
                match bound {
                    Bound::Field(field) => {
                        let value = reveal_service_field(&service, &entry, field)?;
                        Zeroizing::new(
                            std::str::from_utf8(value.as_slice())
                                .map_err(|_| err("cannot reveal value"))?
                                .to_owned(),
                        )
                    }
                    Bound::Otp => {
                        let result = service
                            .totp_code_with_period(&entry.reference(), timestamp)
                            .map_err(|error| match error {
                                nkeepass::ServiceError::HotpUnsupported => {
                                    err("HOTP requires atomic counter persistence")
                                }
                                nkeepass::ServiceError::AmbiguousField => {
                                    err("ambiguous field name")
                                }
                                _ => err("invalid OTP field"),
                            })?;
                        warn_otp_expiring(name, timestamp, result.period());
                        Zeroizing::new(result.code().to_owned())
                    }
                }
            }
        };
        values.insert(name.clone(), value);
    }

    // The child receives only explicitly selected, zeroizing values. Do not
    // keep the unlocked database or its credentials alive while it runs.
    service
        .lock(session)
        .map_err(|_| err("cannot unlock vault"))?;
    drop(service);
    drop(credentials);

    let status = {
        // `env_clear` first, then an allowlist. The default for
        // `std::process::Command` is to inherit the entire parent environment,
        // which hands every variable the user happens to hold -- cloud tokens,
        // CI credentials, unrelated `*_TOKEN`s -- to a program whose
        // provenance the user may not control. Removing only the one password
        // variable leaves that entirely open.
        //
        // This is the same finding as ticket #140 in the sibling .NET
        // implementation, rated P0 there and fixed with an allowlist. The
        // behaviour was reimplemented from scratch when the CLI was ported, so
        // a finding closed in one implementation did not automatically close in
        // the other. That is the pattern worth remembering: a port has to
        // re-earn every security property, it does not inherit them.
        let mut child = std::process::Command::new(command);
        child.env_clear();
        for (name, value) in child_environment() {
            child.env(name, value);
        }
        child.args(&args[sep + 2..]);
        for (name, value) in &values {
            child.env(name, value.as_str());
        }
        if let Some(name) = password_env {
            child.env_remove(name);
        }
        child.env_remove(DEFAULT_PASSWORD_ENV);
        if password_stdin {
            child.stdin(std::process::Stdio::null());
        }
        child
            .status()
            .map_err(|_| err("cannot run child command"))?
    };
    drop(values);

    if status.success() {
        Ok(())
    } else {
        Err(child_status_error(status))
    }
}

/// The variables `exec` passes through to the child.
///
/// An allowlist, not a denylist. A denylist has to enumerate every variable
/// that must NOT be passed, and the next one to be added upstream would be
/// passed by default; an allowlist fails closed, so a new variable is invisible
/// until somebody decides it should be visible.
///
/// `PATH` is required or no child can be found at all. The rest are the
/// variables a process genuinely needs to behave, and none of them carries a
/// credential. `NKEEPASS_*` is deliberately absent, so a future option that
/// stores something in the environment cannot leak by default.
fn child_environment() -> Vec<(String, String)> {
    const PASSTHROUGH: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        // Windows needs these to run at all, and they name the console rather
        // than carrying a secret.
        "SystemRoot",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        // The Rust test harness sets these so a child can find its own
        // fixtures; without them the acceptance run's `exec` steps break.
        "CARGO_MANIFEST_DIR",
    ];

    let mut out = Vec::new();
    for name in PASSTHROUGH {
        if let Some(value) = env::var_os(name) {
            let name = (*name).to_owned();
            if !name.starts_with("NKEEPASS_") {
                out.push((name, value.to_string_lossy().into_owned()));
            }
        }
    }
    out
}

fn child_status_error(status: std::process::ExitStatus) -> CliError {
    #[cfg(unix)]
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |signal| 128 + signal)
    });
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(1);
    CliError("child command failed".to_owned(), code)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn public_secrets_action(action: &str) -> Option<&str> {
    match action {
        "list" => Some("ls"),
        "remove" => Some("rm"),
        "environment" => Some("env"),
        "get" | "getx" | "ls" | "search" | "show" | "env" | "set" | "rm" | "ensure" | "otp"
        | "setx" | "import" | "export" | "sync" => Some(action),
        _ => None,
    }
}

fn public_automation_action(action: &str) -> Option<&str> {
    match action {
        "setx" | "import" | "export" | "sync" => Some(action),
        _ => None,
    }
}

/// Whether these arguments are asking for help rather than doing anything.
///
/// Stops at a bare `--`, because past that separator the arguments belong to a
/// child process. `nkeepass exec --key K --env V -- myapp --help` has to run
/// `myapp --help`; printing this CLI's reference instead would be a command that
/// cannot launch a program whose name starts with a hyphen.
fn aliases(names: &str) -> impl Iterator<Item = &str> {
    names.split('|')
}

fn find_help_command<'a>(commands: &'a [HelpCommand], name: &str) -> Option<&'a HelpCommand> {
    commands
        .iter()
        .find(|command| aliases(command.names).any(|alias| alias == name))
}

/// Returns the command route for a help request, without mistaking option
/// values for switches or scanning into an exec child's argument list.
fn help_request(args: &[String]) -> Option<Vec<String>> {
    let mut i = 0;
    let mut route_tokens = Vec::new();
    let mut expecting_value = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            break;
        }
        if expecting_value {
            expecting_value = false;
            i += 1;
            continue;
        }
        if matches!(arg, "-V" | "--vault") {
            expecting_value = true;
            i += 1;
            continue;
        }
        if matches!(arg, "--help" | "-h") {
            if route_tokens
                .first()
                .is_some_and(|word| word == "__complete")
            {
                return None;
            }
            return Some(resolve_help_route(&route_tokens));
        }
        if takes_option_value(arg) {
            expecting_value = true;
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        route_tokens.push(args[i].clone());
        i += 1;
    }
    None
}

fn takes_option_value(option: &str) -> bool {
    matches!(
        option,
        "--key"
            | "--field"
            | "--name"
            | "--file"
            | "--output"
            | "--password"
            | "--password-env"
            | "--password-file"
            | "--key-file"
            | "--age-recipient"
            | "-r"
            | "--age-identity"
            | "-i"
            | "--size"
            | "--format"
            | "--strategy"
            | "--kdf"
            | "--memory"
            | "--iterations"
            | "--parallelism"
            | "--kind"
            | "--env"
    )
}

fn resolve_help_route(tokens: &[String]) -> Vec<String> {
    let mut route = Vec::new();
    let mut commands = ROOT_COMMANDS;
    for token in tokens {
        let Some(command) = find_help_command(commands, token) else {
            break;
        };
        route.push(token.clone());
        commands = command.children;
    }
    route
}

fn program_basename(argv0: &OsStr) -> String {
    Path::new(argv0)
        .file_name()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| OsStr::new("nkeepass"))
        .to_string_lossy()
        .into_owned()
}

fn command_path<'a>(commands: &'a [HelpCommand], route: &[String]) -> Option<&'a HelpCommand> {
    let mut current = None;
    let mut children = commands;
    for part in route {
        let command = find_help_command(children, part)?;
        current = Some(command);
        children = command.children;
    }
    current
}

fn uses_credentials(route: &[String]) -> bool {
    match route {
        [command] => matches!(
            command.as_str(),
            "init"
                | "exec"
                | "x"
                | "get"
                | "getx"
                | "list"
                | "ls"
                | "search"
                | "show"
                | "set"
                | "rm"
                | "remove"
                | "ensure"
                | "otp"
                | "setx"
                | "import"
                | "export"
                | "sync"
                | "env"
        ),
        [group, action] => {
            matches!(
                group.as_str(),
                "secrets"
                    | "automation"
                    | "attachment"
                    | "attachments"
                    | "field"
                    | "custom-field"
                    | "group"
                    | "groups"
            ) && !matches!(action.as_str(), "")
        }
        _ => false,
    }
}

fn render_help(program: &str, route: &[String], width: usize) -> String {
    let mut output = String::new();
    let command = command_path(ROOT_COMMANDS, route);
    if route.is_empty() {
        let _ = writeln!(output, "{program} - {HELP_TITLE}");
        write_paragraph(
            &mut output,
            &format!("Usage: {program} [GLOBAL OPTIONS] COMMAND"),
            width,
            "",
        );
        write_paragraph(
            &mut output,
            &format!("       {program} --help | --version"),
            width,
            "",
        );
        output.push('\n');
    } else if let Some(command) = command {
        let usage_tail = command.usage.split_once(' ').map_or("", |(_, tail)| tail);
        let usage = if command.children.is_empty() && route.len() == 1 {
            let first = command.usage.split_whitespace().next().unwrap_or("");
            command.usage.replacen(first, &route[0], 1)
        } else if usage_tail.is_empty() {
            route.join(" ")
        } else {
            format!("{} {usage_tail}", route.join(" "))
        };
        let _ = writeln!(output, "{program} {}", route.join(" "));
        write_paragraph(&mut output, &format!("Usage: {program} {usage}"), width, "");
        output.push('\n');
        write_paragraph(&mut output, command.summary, width, "");
        output.push('\n');
    }

    let children = command.map_or(ROOT_COMMANDS, |node| node.children);
    if !children.is_empty() {
        output.push_str("COMMANDS:\n");
        let col = aligned_column(children.iter().map(|item| item.names), width);
        for item in children {
            write_help_row(&mut output, item.names, item.summary, col, width);
        }
        output.push('\n');
    }

    write_help_options(&mut output, command, route, width);
    if route.is_empty() || uses_credentials(route) {
        write_paragraph(
            &mut output,
            "Without an explicit credential source, use NKEEPASS_PASSWORD when set. Explicit sources override it; NKEEPASS_SECRET is not an alias.",
            width,
            "",
        );
    }
    write_paragraph(
        &mut output,
        "Safety: credentials are prompted without echo; init never overwrites or prints a password.",
        width,
        "",
    );
    write_paragraph(
        &mut output,
        "WARNING: --password VALUE is exposed in process listings and shell history.",
        width,
        "",
    );
    write_paragraph(
        &mut output,
        "Selected values are explicit disclosures; stdout may be captured in logs or files.",
        width,
        "",
    );
    write_paragraph(
        &mut output,
        "Use -h/--help for command-specific usage and options.",
        width,
        "",
    );
    write_paragraph(
        &mut output,
        "See the README: “Creating a vault”, “Explicit value output”, “Glob syntax”, and “Automation and interchange”.",
        width,
        "",
    );
    output
}

fn write_help_options(
    output: &mut String,
    command: Option<&HelpCommand>,
    route: &[String],
    width: usize,
) {
    output.push_str("OPTIONS:\n");
    let mut options = Vec::new();
    options.push(&HELP_OPTION);
    if route.is_empty() {
        options.extend(ROOT_ONLY_OPTIONS.iter());
    }
    if uses_credentials(route) {
        options.extend(CREDENTIAL_OPTIONS.iter());
    }
    if let Some(command) = command {
        options.extend(command.options.iter());
    }
    let col = aligned_column(options.iter().map(|option| option.label), width);
    for option in options {
        write_help_row(output, option.label, option.summary, col, width);
    }
    output.push('\n');
    output.push_str("GLOBAL OPTIONS:\n");
    let mut globals = GLOBAL_OPTIONS.iter().collect::<Vec<_>>();
    if route.is_empty() || uses_credentials(route) {
        globals.extend(GLOBAL_CREDENTIAL_OPTIONS.iter());
    }
    let col = aligned_column(globals.iter().map(|option| option.label), width);
    for option in globals {
        write_help_row(output, option.label, option.summary, col, width);
    }
    output.push('\n');
}

fn aligned_column<'a>(labels: impl Iterator<Item = &'a str>, width: usize) -> usize {
    let max_label = labels.map(str::len).max().unwrap_or(0);
    max_label
        .saturating_add(4)
        .min(width.saturating_sub(12).max(8))
}

fn write_help_row(output: &mut String, label: &str, summary: &str, col: usize, width: usize) {
    let desc_width = width.saturating_sub(col).max(8);
    if label.len() + 2 >= col {
        output.push_str("  ");
        output.push_str(label);
        output.push('\n');
        for line in wrap_help(summary, desc_width) {
            output.push_str(&" ".repeat(col));
            output.push_str(&line);
            output.push('\n');
        }
        return;
    }
    output.push_str("  ");
    output.push_str(label);
    output.push_str(&" ".repeat(col - label.len() - 2));
    let mut lines = wrap_help(summary, desc_width).into_iter();
    if let Some(line) = lines.next() {
        output.push_str(&line);
        output.push('\n');
    }
    for line in lines {
        output.push_str(&" ".repeat(col));
        output.push_str(&line);
        output.push('\n');
    }
}

fn wrap_help(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn write_paragraph(output: &mut String, text: &str, width: usize, indent: &str) {
    let width = width.saturating_sub(indent.chars().count()).max(8);
    for line in wrap_help(text, width) {
        output.push_str(indent);
        output.push_str(&line);
        output.push('\n');
    }
}

fn print_help(program: &str, route: &[String]) {
    print!("{}", render_help(program, route, HELP_WIDTH));
}

fn with_root_credentials<'a>(
    command: &str,
    rest: &'a [String],
    credentials: &[String],
) -> Result<Cow<'a, [String]>> {
    if credentials.is_empty() {
        return Ok(Cow::Borrowed(rest));
    }
    let command_help = find_help_command(ROOT_COMMANDS, command);
    let nested = command_help.is_some_and(|help| !help.children.is_empty());
    let mut route = vec![command.to_owned()];
    if nested {
        route.push(
            rest.first()
                .ok_or_else(|| err("subcommand required"))?
                .clone(),
        );
    }
    if !uses_credentials(&route) {
        return Err(err("this command does not accept root credential options"));
    }
    let offset = usize::from(nested);
    let mut merged = Vec::with_capacity(rest.len() + credentials.len());
    merged.extend_from_slice(&rest[..offset]);
    merged.extend_from_slice(credentials);
    merged.extend_from_slice(&rest[offset..]);
    Ok(Cow::Owned(merged))
}

#[allow(
    clippy::too_many_lines,
    reason = "dispatch for the small initial command surface"
)]
fn run(args: &[String], program: &str) -> Result<()> {
    if let Some(route) = help_request(args) {
        print_help(program, &route);
        return Ok(());
    }
    if args.is_empty() {
        print_help(program, &[]);
        return Ok(());
    }
    if args == ["--version"] || args == ["version"] {
        println!("nkeepass {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut vault = None;
    let mut root_credentials = Vec::new();
    let mut at = 0;
    while let Some(option) = args.get(at).map(String::as_str) {
        match option {
            "--vault" | "-V" => {
                if vault.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                vault = Some(take_arg(args, at + 1)?);
                at += 2;
            }
            "--password-env" => {
                root_credentials.push(option.to_owned());
                root_credentials.push(take_arg(args, at + 1)?.to_owned());
                at += 2;
            }
            "--password-stdin" => {
                root_credentials.push(option.to_owned());
                at += 1;
            }
            _ => break,
        }
    }
    options(&root_credentials, Positional::Forbidden)?;
    let command = take_arg(args, at)?;
    let command_args = with_root_credentials(command, &args[at + 1..], &root_credentials)?;
    let rest = command_args.as_ref();
    // The help request is resolved before dispatch and configuration loading.
    // Its command tree supplies the route and the per-command option inventory;
    // it skips option values, honors the `--` boundary, and exempts the private
    // `__complete` protocol.
    if command == "tui" {
        let [path] = rest else {
            return Err(err("usage: nkeepass tui PATH"));
        };
        let aliases = load_config()?
            .aliases
            .iter()
            .map(|(name, alias)| {
                check_alias_metadata(name, alias)?;
                let kind = match alias.kind {
                    Kind::Vault => "vault",
                    Kind::Entry => "entry",
                };
                Ok(format!(
                    "{name} [{kind}] → {}{}",
                    alias.target,
                    alias
                        .field
                        .as_deref()
                        .map_or_else(String::new, |field| format!(" · {field}"))
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        return tui::launch(Path::new(path), aliases).map_err(|_| err("TUI operation failed"));
    }
    match command {
        "completion" => {
            let [shell] = rest else {
                return Err(err("unsupported completion shell"));
            };
            print!("{}", completion::generate(shell)?);
            return Ok(());
        }
        "__complete" => return completion::candidates(rest, vault),
        _ => {}
    }
    let mut config = load_config()?;
    match command {
        "init" => init_command(rest, vault, &mut config),
        "context" => match rest.first().map(String::as_str) {
            Some("ls") if rest.len() == 1 => {
                for (name, alias) in &config.aliases {
                    if alias.kind == Kind::Vault {
                        check_alias_metadata(name, alias)?;
                        let path = normalized_vault_text(&vault_path(&alias.target)?);
                        json(&serde_json::json!({"alias": name, "path": path}))?;
                    }
                }
                Ok(())
            }
            Some("show") if rest.len() == 1 => {
                let (path, source) = active_vault(vault, &config)?;
                let path = normalized_vault_text(&path);
                let alias = (source == "context")
                    .then_some(config.current.as_deref())
                    .flatten()
                    .and_then(|current| {
                        config
                            .aliases
                            .get(current)
                            .filter(|alias| alias.kind == Kind::Vault)
                            .map(|_| current)
                    });
                json(&serde_json::json!({"path": path, "source": source, "alias": alias}))
            }
            Some("use") if rest.len() == 2 => {
                use_context_alias(&mut config, &rest[1])?;
                save_config(&config)
            }
            Some("rm") if rest.len() == 2 => {
                remove_context_alias(&mut config, &rest[1])?;
                save_config(&config)
            }
            Some("set") if rest.len() == 3 => {
                set_context_alias(&mut config, &rest[1], &rest[2])?;
                save_config(&config)
            }
            _ => Err(err("invalid context command; see --help")),
        },
        "alias" => match rest.first().map(String::as_str) {
            Some("list" | "ls") if rest.len() == 1 => {
                for (name, alias) in &config.aliases {
                    json(
                        &serde_json::json!({"name": name, "kind": alias.kind, "target": alias.target, "field": alias.field}),
                    )?;
                }
                Ok(())
            }
            Some("resolve") if rest.len() == 2 => {
                let alias = config
                    .aliases
                    .get(&rest[1])
                    .ok_or_else(|| err("alias not found"))?;
                json(
                    &serde_json::json!({"kind": alias.kind, "target": alias.target, "field": alias.field}),
                )
            }
            Some("remove" | "rm") if rest.len() == 2 => {
                if config.aliases.remove(&rest[1]).is_none() {
                    return Err(err("alias not found"));
                }
                if config.current.as_deref() == Some(rest[1].as_str()) {
                    config.current = None;
                }
                save_config(&config)
            }
            Some("set") => {
                if rest.len() < 3 || !valid_name(&rest[1]) {
                    return Err(err("invalid alias name or target"));
                }
                let mut kind = None;
                let mut field = None;
                let mut i = 3;
                while i < rest.len() {
                    match rest[i].as_str() {
                        "--kind" if kind.is_none() => {
                            kind = Some(match take_arg(rest, i + 1)? {
                                "vault" => Kind::Vault,
                                "entry" => Kind::Entry,
                                _ => return Err(err("invalid alias kind")),
                            });
                        }
                        "--field" if field.is_none() => {
                            field = Some(take_arg(rest, i + 1)?.to_owned());
                        }
                        _ => return Err(err("invalid alias option")),
                    }
                    i += 2;
                }
                let target = &rest[2];
                let kind = kind.unwrap_or(if Path::new(target).is_absolute() {
                    Kind::Vault
                } else {
                    Kind::Entry
                });
                match kind {
                    Kind::Vault => {
                        let path = vault_path(target)?;
                        if field.is_some() {
                            return Err(err("vault alias cannot have a field"));
                        }
                        config.aliases.insert(
                            rest[1].clone(),
                            Alias {
                                kind,
                                target: normalized_vault_text(&path),
                                field,
                            },
                        );
                        return save_config(&config);
                    }
                    Kind::Entry => {
                        entry_path(target)?;
                        if field
                            .as_ref()
                            .is_some_and(|f| f.is_empty() || f.chars().any(char::is_control))
                        {
                            return Err(err("invalid field name"));
                        }
                    }
                }
                if kind == Kind::Entry && config.current.as_deref() == Some(rest[1].as_str()) {
                    config.current = None;
                }
                config.aliases.insert(
                    rest[1].clone(),
                    Alias {
                        kind,
                        target: target.clone(),
                        field,
                    },
                );
                save_config(&config)
            }
            _ => Err(err("invalid alias command; see --help")),
        },
        "config" => config_command(rest, &mut config),
        "secrets" if !rest.is_empty() => {
            let action = public_secrets_action(&rest[0])
                .ok_or_else(|| err("unknown operation; see --help"))?;
            if action == "env" {
                env_command(&rest[1..], vault, &config)
            } else {
                operation(action, &rest[1..], vault, &config)
            }
        }
        "get" | "getx" | "list" | "ls" | "search" | "show" | "set" | "rm" | "remove" | "ensure"
        | "otp" | "setx" | "import" | "export" | "sync" => {
            let action = match command {
                "list" => "ls",
                "remove" => "rm",
                action => action,
            };
            operation(action, rest, vault, &config)
        }
        "env" => env_command(rest, vault, &config),
        "automation" if !rest.is_empty() => {
            let action = public_automation_action(&rest[0])
                .ok_or_else(|| err("unknown operation; see --help"))?;
            operation(action, &rest[1..], vault, &config)
        }

        "attachment" | "attachments" | "field" | "custom-field" | "group" | "groups"
            if !rest.is_empty() =>
        {
            let action = match (command, rest[0].as_str()) {
                ("group" | "groups", "list" | "ls") => "group-ls",
                ("group" | "groups", "add" | "create" | "ensure") => "group-add",
                ("group" | "groups", "remove" | "rm") => "group-rm",
                ("attachment" | "attachments", "list" | "ls") => "attachment-ls",
                ("attachment" | "attachments", "add" | "import") => "attachment-add",
                ("attachment" | "attachments", "get" | "export") => "attachment-get",
                ("attachment" | "attachments", "remove" | "rm") => "attachment-rm",
                ("field" | "custom-field", "list" | "ls") => "field-ls",
                ("field" | "custom-field", "get" | "reveal") => "field-get",
                ("field" | "custom-field", "set" | "edit") => "field-set",
                ("field" | "custom-field", "remove" | "rm") => "field-rm",
                _ => return Err(err("unknown operation")),
            };
            operation(action, &rest[1..], vault, &config)
        }
        "exec" | "x" => exec_command(rest, vault, &config),
        _ => Err(err("unknown command; see --help")),
    }
}

fn main() {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map_or_else(|| "nkeepass".to_owned(), |arg| program_basename(&arg));
    let command_args = arguments
        .map(std::ffi::OsString::into_string)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(command_args) = command_args else {
        eprintln!("nkeepass: arguments must be valid UTF-8");
        std::process::exit(2);
    };
    if let Err(error) = run(&command_args, &program) {
        eprintln!("nkeepass: {}", error.0);
        std::process::exit(error.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient_http_fixture(
        status: &'static str,
        body: &'static str,
        location: Option<&'static str>,
    ) -> (String, std::thread::JoinHandle<(usize, String)>) {
        use std::{
            net::TcpListener,
            sync::{Arc, Mutex},
            time::{Duration, Instant},
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
        listener
            .set_nonblocking(true)
            .expect("nonblocking HTTP fixture");
        let address = listener.local_addr().expect("fixture address");
        let observed = Arc::new(Mutex::new(String::new()));
        let observed_request = Arc::clone(&observed);
        let server = std::thread::spawn(move || {
            let mut requests = 0;
            // Allow slow CI scheduling for curl's first connection, then
            // observe for a short, separate interval to catch duplicate calls.
            let connection_deadline = Instant::now() + Duration::from_secs(10);
            let mut quiet_deadline = None;
            loop {
                let deadline = quiet_deadline.unwrap_or(connection_deadline);
                if Instant::now() >= deadline {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        requests += 1;
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("fixture read timeout");
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                            let count = stream.read(&mut chunk).expect("read HTTP request");
                            if count == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..count]);
                            if request.len() > 8192 {
                                break;
                            }
                        }
                        if requests == 1 {
                            *observed_request.lock().expect("request lock") =
                                String::from_utf8_lossy(&request).into_owned();
                        }
                        let location = location
                            .map_or_else(String::new, |value| format!("Location: {value}\r\n"));
                        let response = format!(
                            "HTTP/1.1 {status}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("write HTTP response");
                        if quiet_deadline.is_none() {
                            quiet_deadline = Some(Instant::now() + Duration::from_millis(300));
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("HTTP fixture accept failed: {error}"),
                }
            }
            (
                requests,
                observed_request.lock().expect("request lock").clone(),
            )
        });
        (format!("http://{address}/keys/{{one,two}}"), server)
    }

    #[test]
    fn recipient_fetch_disables_curl_globbing_and_issues_one_request() {
        let (url, server) = recipient_http_fixture("200 OK", "a valid key list\n", None);
        assert_eq!(
            fetch_recipient_url(&url, RecipientTransport::HttpFixture)
                .expect("controlled HTTP fetch"),
            "a valid key list\n"
        );
        let (requests, request) = server.join().expect("fixture thread");
        assert_eq!(requests, 1);
        assert!(
            request.starts_with("GET /keys/{one,two} HTTP/1.1\r\n"),
            "{request}"
        );
    }

    #[test]
    fn recipient_fetch_rejects_redirect_status_and_discards_its_body() {
        let (url, server) =
            recipient_http_fixture("302 Found", "redirect-body-canary", Some("/followed"));
        let error =
            fetch_recipient_url(&url, RecipientTransport::HttpFixture).expect_err("reject 302");
        assert!(!error.0.contains("redirect-body-canary"));
        let (requests, _) = server.join().expect("fixture thread");
        assert_eq!(requests, 1);
    }

    #[test]
    fn age_input_and_identity_helpers_round_trip_and_parse_recipient_files() {
        let key = neotales_age::AgeKey::generate().expect("age key");
        let recipient_path = tempfile::NamedTempFile::new().expect("recipient file");
        fs::write(recipient_path.path(), format!("{}\n", key.public_key)).expect("write recipient");
        let recipient_path = recipient_path.path().to_str().expect("UTF-8 temp path");
        let recipients = age_recipients(&[&format!("@{recipient_path}")]).expect("recipient file");
        let identity_path = tempfile::NamedTempFile::new().expect("identity file");
        fs::write(identity_path.path(), format!("{}\n", key.private_key)).expect("write identity");
        let identities = age_identities(identity_path.path().to_str().expect("UTF-8 temp path"))
            .expect("identity file");
        let ciphertext = AgeFile::encrypt(b"age CLI payload", &recipients).expect("encrypt");
        assert_eq!(
            decrypt_age_input(&ciphertext, &identities)
                .expect("decrypt")
                .as_slice(),
            b"age CLI payload"
        );
        let armored = AgeFile::encrypt_armored(b"armored CLI payload", &recipients).expect("armor");
        assert_eq!(
            decrypt_age_input(armored.as_bytes(), &identities)
                .expect("armored decrypt")
                .as_slice(),
            b"armored CLI payload"
        );
    }

    #[test]
    fn age_flags_parse_and_reject_duplicate_identity_options() {
        let args = [
            "--key".to_owned(),
            "service/account".to_owned(),
            "--age-encrypt".to_owned(),
            "-r".to_owned(),
            "age1example".to_owned(),
            "--age-recipient".to_owned(),
            "ssh-ed25519 AAAA".to_owned(),
        ];
        let parsed = options(&args, Positional::Forbidden).expect("age flags parse");
        assert!(parsed.age_encrypt);
        assert_eq!(parsed.age_recipients.len(), 2);
        assert!(
            options(
                &[
                    "--age-identity".to_owned(),
                    "one".to_owned(),
                    "-i".to_owned(),
                    "two".to_owned(),
                ],
                Positional::Forbidden,
            )
            .is_err()
        );
    }

    #[test]
    fn age_network_sources_are_strictly_https_and_bounded_by_contract() {
        assert!(validate_https_url("https://example.invalid/keys").is_ok());
        assert!(validate_https_url("http://example.invalid/keys").is_err());
        assert!(validate_https_url("https://user@example.invalid/keys").is_err());
        assert!(validate_https_url("https://example.invalid/keys?token=bad").is_err());
        assert!(validate_https_url("https://example.invalid:0/keys").is_err());
        assert!(fetch_recipient_source("gh:bad/name").is_err());
    }

    #[test]
    fn windows_home_candidates_prefer_known_folders_then_validated_env_fallbacks() {
        use std::ffi::OsStr;

        assert_eq!(
            windows_home_candidates(
                Some(PathBuf::from("known")),
                Some(OsStr::new("profile")),
                Some(OsStr::new("C:")),
                Some(OsStr::new("\\Users\\test")),
            ),
            vec![
                PathBuf::from("known"),
                PathBuf::from("profile"),
                PathBuf::from("C:\\Users\\test"),
            ]
        );
        assert_eq!(
            windows_home_candidates(
                None,
                Some(OsStr::new("C:\\Users\\profile")),
                Some(OsStr::new("C:")),
                Some(OsStr::new("\\Users\\test")),
            ),
            vec![
                PathBuf::from("C:\\Users\\profile"),
                PathBuf::from("C:\\Users\\test"),
            ]
        );
        assert!(windows_home_candidates(None, None, Some(OsStr::new("C:")), None).is_empty());
        assert!(
            windows_home_candidates(None, None, None, Some(OsStr::new("\\Users\\test"))).is_empty()
        );
    }

    #[test]
    fn windows_home_selection_uses_windows_validation_and_falls_back_safely() {
        use std::ffi::OsStr;

        let known = windows_home_candidates(
            Some(PathBuf::from(r"C:\Profiles\Known")),
            Some(OsStr::new(r"D:\Profiles\Environment")),
            Some(OsStr::new("E:")),
            Some(OsStr::new(r"\Users\Fallback")),
        );
        assert_eq!(
            first_valid_candidate(known, valid_windows_absolute_base),
            Some(PathBuf::from(r"C:\Profiles\Known")),
            "a valid Known Folders profile wins over valid environment values"
        );

        let from_user_profile = windows_home_candidates(
            Some(PathBuf::from(r"\\?\C:\InvalidKnownFolder")),
            Some(OsStr::new(r"D:\Profiles\Environment")),
            Some(OsStr::new("E:")),
            Some(OsStr::new(r"\Users\Fallback")),
        );
        assert_eq!(
            first_valid_candidate(from_user_profile, valid_windows_absolute_base),
            Some(PathBuf::from(r"D:\Profiles\Environment")),
            "an invalid known-folder result falls through to USERPROFILE"
        );

        let from_drive_pair = windows_home_candidates(
            Some(PathBuf::from(r"\\server")),
            Some(OsStr::new("relative-profile")),
            Some(OsStr::new("E:")),
            Some(OsStr::new(r"\Users\Fallback")),
        );
        assert_eq!(
            first_valid_candidate(from_drive_pair, valid_windows_absolute_base),
            Some(PathBuf::from(r"E:\Users\Fallback")),
            "invalid known-folder and USERPROFILE values fall through to HOMEDRIVE + HOMEPATH"
        );
    }

    #[test]
    fn windows_init_path_forms_are_explicitly_pinned() {
        assert_eq!(
            windows_path_kind(r"C:\db.kdbx"),
            WindowsPathKind::DriveAbsolute
        );
        assert_eq!(
            windows_path_kind(r"\\server\share\vault.kdbx"),
            WindowsPathKind::UncAbsolute
        );
        assert_eq!(
            windows_path_kind(r"\rooted"),
            WindowsPathKind::RootedWithoutDrive
        );
        assert_eq!(
            windows_path_kind("C:db.kdbx"),
            WindowsPathKind::DriveRelative
        );
        for malformed in [
            r"\\",
            r"\\server",
            r"\\server\",
            r"\\\share",
            r"\/server/share",
        ] {
            assert_eq!(
                windows_path_kind(malformed),
                WindowsPathKind::MalformedUnc,
                "unexpected classification for {malformed:?}"
            );
            assert!(validate_windows_init_spelling(malformed).is_err());
        }
        for (namespace, expected) in [
            (r"\\?\C:\dir\..\vault.kdbx", WindowsPathKind::VerbatimDisk),
            (r"\\?\C:\vault.kdbx", WindowsPathKind::VerbatimDisk),
            (
                r"\\?\UNC\server\share\vault.kdbx",
                WindowsPathKind::VerbatimUnc,
            ),
            (r"\\.\PhysicalDrive0", WindowsPathKind::DeviceNamespace),
            (r"/\?/C:/vault.kdbx", WindowsPathKind::VerbatimDisk),
            (r"\/./PhysicalDrive0", WindowsPathKind::DeviceNamespace),
        ] {
            assert_eq!(windows_path_kind(namespace), expected);
            assert!(reject_windows_namespace_spelling(namespace).is_err());
            assert!(validate_windows_init_spelling(namespace).is_err());
            assert!(!valid_windows_absolute_base(Path::new(namespace)));
        }
        assert_eq!(
            windows_path_kind(r"\\?x\share\vault.kdbx"),
            WindowsPathKind::UncAbsolute,
            "a server name beginning with '?' is ordinary UNC, not a namespace prefix"
        );
        assert_eq!(
            windows_path_kind(r"\\.x\share\vault.kdbx"),
            WindowsPathKind::UncAbsolute,
            "a server name beginning with '.' is ordinary UNC, not a device prefix"
        );
        assert_eq!(
            windows_path_kind(r"\\?\unc\server\share\vault.kdbx"),
            WindowsPathKind::VerbatimUnc,
            "the UNC namespace marker is case-insensitive"
        );
        assert!(validate_windows_init_spelling(r"\rooted").is_err());
        assert!(validate_windows_init_spelling("C:db.kdbx").is_err());
        assert!(validate_windows_init_spelling(r"\\server\share\vault.kdbx").is_ok());
    }

    fn validate_windows_path_for_resolver(
        path: PathBuf,
        unavailable: &'static str,
    ) -> Result<PathBuf> {
        if valid_windows_absolute_base(&path) {
            Ok(path)
        } else {
            Err(err(unavailable))
        }
    }

    #[test]
    fn help_formatter_wraps_at_requested_widths_with_aligned_continuations() {
        for width in [48, 64, 88, 120] {
            let route = vec!["secrets".to_owned()];
            let help = render_help("nkp", &route, width);
            for line in help.lines() {
                assert!(
                    line.chars().count() <= width,
                    "line exceeds {width} columns: {line:?}"
                );
            }
            let mut row = String::new();
            write_help_row(
                &mut row,
                "--example-option VALUE",
                "A deliberately long description that must wrap and keep every continuation aligned below its description column.",
                28,
                width,
            );
            let lines: Vec<_> = row.lines().collect();
            assert!(lines.len() > 1, "width {width} did not wrap the test row");
            assert!(lines[1].starts_with(&" ".repeat(28)));
            assert!(lines.iter().all(|line| line.chars().count() <= width));
        }
    }

    #[test]
    fn global_help_options_follow_command_options_in_their_own_section() {
        let help = render_help("nkeepass", &["get".to_owned()], HELP_WIDTH);
        let command_option = help.find("--key PATH").unwrap();
        let global_heading = help.find("GLOBAL OPTIONS:").unwrap();
        let global_option = help.find("-V, --vault PATH").unwrap();
        assert!(command_option < global_heading);
        assert!(global_heading < global_option);

        let context = render_help("nkeepass", &["context".to_owned()], HELP_WIDTH);
        for action in ["ls", "show", "use", "rm", "set"] {
            assert!(context.contains(action));
        }
    }

    #[test]
    fn global_credential_help_stays_scoped_and_after_command_options() {
        for route in [
            Vec::new(),
            vec!["exec".to_owned()],
            vec!["secrets".to_owned(), "get".to_owned()],
        ] {
            let help = render_help("nkeepass", &route, HELP_WIDTH);
            let options = help.find("OPTIONS:\n").unwrap();
            let globals = help.find("GLOBAL OPTIONS:\n").unwrap();
            assert!(options < globals);
            let global_options = &help[globals..];
            assert!(global_options.contains("--password-env NAME"));
            assert!(global_options.contains("--password-stdin"));
            assert!(global_options.contains("NKEEPASS_PASSWORD"));
            if !route.is_empty() {
                let command_options = &help[options..globals];
                assert!(command_options.contains("--key PATH"));
                assert!(command_options.contains("--password-env NAME"));
                assert!(command_options.contains("--password-stdin"));
            }
        }

        let context = render_help(
            "nkeepass",
            &["context".to_owned(), "show".to_owned()],
            HELP_WIDTH,
        );
        assert!(!context.contains("--password-env NAME"));
        assert!(!context.contains("--password-stdin"));
        assert!(!context.contains("NKEEPASS_PASSWORD"));
    }

    #[test]
    fn context_aliases_are_vault_only_normalized_and_clear_when_removed() {
        let mut config = Config::default();
        let path = env::current_dir().unwrap().join("context-test.kdbx");
        let path = normalized_vault_text(&path);
        set_context_alias(&mut config, "work", &path).unwrap();
        assert_eq!(
            config.aliases.get("work").unwrap().target,
            normalized_vault_text(Path::new(&path))
        );
        use_context_alias(&mut config, "work").unwrap();
        assert_eq!(config.current.as_deref(), Some("work"));

        config.aliases.insert(
            "entry".into(),
            Alias {
                kind: Kind::Entry,
                target: "Root/Entry".into(),
                field: None,
            },
        );
        assert!(use_context_alias(&mut config, "entry").is_err());
        assert!(remove_context_alias(&mut config, "entry").is_err());
        remove_context_alias(&mut config, "work").unwrap();
        assert!(config.current.is_none());
        assert!(!config.aliases.contains_key("work"));
    }

    #[test]
    fn context_path_text_normalizes_windows_mixed_separators() {
        let mixed = Path::new(r"C:\Users\dev\.local/share/nkeepass\default.kdbx");
        assert_eq!(
            normalized_vault_text(mixed),
            r"C:\Users\dev\.local\share\nkeepass\default.kdbx"
        );
    }

    #[test]
    fn app_directory_overrides_have_the_documented_precedence() {
        use std::ffi::OsStr;

        let app_dir = resolve_app_dir(
            Some(OsStr::new(r"C:\App\Nkeepass")),
            Some(OsStr::new(r"D:\Xdg\Nkeepass")),
            Some(OsStr::new(r"E:\XdgHome")),
            || panic!("home fallback must not run when an override is selected"),
            r"C:\Users\Test\.config\nkeepass",
            "configuration directory unavailable",
            validate_windows_path_for_resolver,
        )
        .unwrap();
        assert_eq!(app_dir, PathBuf::from(r"C:\App\Nkeepass"));

        let xdg_dir = resolve_app_dir(
            None,
            Some(OsStr::new(r"D:\Xdg")),
            Some(OsStr::new(r"E:\XdgHome")),
            || panic!("home fallback must not run when an override is selected"),
            r"C:\Users\Test\.config\nkeepass",
            "configuration directory unavailable",
            validate_windows_path_for_resolver,
        )
        .unwrap();
        assert_eq!(xdg_dir, PathBuf::from(r"D:\Xdg").join("nkeepass"));

        let standard_base = resolve_app_dir(
            None,
            None,
            Some(OsStr::new(r"E:\XdgHome")),
            || panic!("home fallback must not run when an XDG base is selected"),
            r"C:\Users\Test\.config\nkeepass",
            "configuration directory unavailable",
            validate_windows_path_for_resolver,
        )
        .unwrap();
        assert_eq!(standard_base, PathBuf::from(r"E:\XdgHome").join("nkeepass"));
    }

    #[test]
    fn invalid_app_directory_overrides_fail_without_falling_back() {
        use std::ffi::OsStr;

        for invalid in [
            "relative",
            r"C:drive-relative",
            r"\rooted",
            r"\\server",
            r"\\?\C:\verbatim\vault.kdbx",
            r"\\.\PhysicalDrive0",
            r"C:\Users\..\outside",
            r"C:\Users\.\child",
        ] {
            let result = resolve_app_dir(
                Some(OsStr::new(invalid)),
                Some(OsStr::new(r"D:\Valid\Nkeepass")),
                Some(OsStr::new(r"E:\Valid")),
                || Ok(PathBuf::from(r"C:\Users\Test")),
                r"C:\Users\Test\.config\nkeepass",
                "configuration directory unavailable",
                validate_windows_path_for_resolver,
            );
            assert!(
                result.is_err(),
                "accepted invalid selected value {invalid:?}"
            );
        }

        let invalid_xdg = resolve_app_dir(
            None,
            Some(OsStr::new("relative-xdg-base")),
            Some(OsStr::new(r"E:\Valid")),
            || Ok(PathBuf::from(r"C:\Users\Test")),
            ".config/nkeepass",
            "configuration directory unavailable",
            validate_windows_path_for_resolver,
        );
        assert!(invalid_xdg.is_err(), "invalid selected XDG_DIR fell back");
    }

    #[test]
    fn unset_app_directories_use_the_injected_windows_profile_defaults() {
        let profile = PathBuf::from(r"C:\Users\Test");
        let config_dir = resolve_app_dir(
            None,
            None,
            None,
            || Ok(profile.clone()),
            ".config/nkeepass",
            "configuration directory unavailable",
            validate_windows_path_for_resolver,
        )
        .unwrap();
        let data_dir = resolve_app_dir(
            None,
            None,
            None,
            || Ok(profile.clone()),
            ".local/share/nkeepass",
            "data directory unavailable",
            validate_windows_path_for_resolver,
        )
        .unwrap();
        assert_eq!(
            config_dir,
            PathBuf::from(r"C:\Users\Test").join(".config/nkeepass")
        );
        assert_eq!(
            data_dir,
            PathBuf::from(r"C:\Users\Test").join(".local/share/nkeepass")
        );
        assert_eq!(
            data_dir.join("default.kdbx"),
            PathBuf::from(r"C:\Users\Test").join(".local/share/nkeepass/default.kdbx")
        );
    }

    #[test]
    fn windows_home_resolution_skips_relative_candidates() {
        let valid = env::current_dir().unwrap();
        let resolved = first_valid_base_dir(
            [PathBuf::from("relative-profile"), valid.clone()],
            "home directory unavailable",
        )
        .unwrap();
        assert_eq!(resolved, valid);
        assert!(first_valid_base_dir([PathBuf::from("relative-profile")], "unavailable").is_err());
    }

    #[test]
    fn init_relative_path_normalizes_dot_and_rejects_parent_and_controls() {
        let expected = env::current_dir().unwrap().join("db.kdbx");
        assert_eq!(init_target_path("./db.kdbx").unwrap(), expected);
        assert!(init_target_path("../outside.kdbx").is_err());
        assert!(init_target_path("bell\u{7}.kdbx").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn init_applies_windows_root_and_unc_path_rules() {
        assert!(init_target_path("C:db.kdbx").is_err());
        assert!(init_target_path(r"\rooted").is_err());
        assert!(init_target_path(r"\\server").is_err());
        assert!(init_target_path(r"\\server\share\vault.kdbx").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_verbatim_paths_are_rejected_for_vaults_and_base_directories() {
        for path in [
            r"\\?\C:\dir\..\vault.kdbx",
            r"\\?\C:\vault.kdbx",
            r"\\?\UNC\server\share\vault.kdbx",
            r"\\.\PhysicalDrive0",
            r"/\?/C:/vault.kdbx",
            r"\/./PhysicalDrive0",
        ] {
            assert!(
                init_target_path(path).is_err(),
                "accepted vault path {path:?}"
            );
            assert!(
                validate_base_dir(PathBuf::from(path), "directory unavailable").is_err(),
                "accepted base directory {path:?}"
            );
            let path = PathBuf::from(path);
            assert!(
                resolve_app_dir(
                    Some(path.as_os_str()),
                    Some(std::ffi::OsStr::new(r"C:\Valid\Nkeepass")),
                    None,
                    || panic!("invalid app override must not fall through"),
                    "nkeepass",
                    "directory unavailable",
                    validate_base_dir,
                )
                .is_err(),
                "namespace app override fell through"
            );
        }

        assert!(validate_base_dir(PathBuf::from(r"C:\ordinary\vaults"), "unavailable").is_ok());
        assert!(validate_base_dir(PathBuf::from(r"\\server\share\vaults"), "unavailable").is_ok());
        assert!(init_target_path(r"C:\ordinary\vault.kdbx").is_ok());
        assert!(init_target_path(r"\\server\share\vault.kdbx").is_ok());
        assert!(vault_path(r"C:\ordinary\vault.kdbx").is_ok());
        assert!(vault_path(r"\\server\share\vault.kdbx").is_ok());

        let mut config = Config::default();
        for (index, path) in [
            r"\\?\C:\dir\..\vault.kdbx",
            r"\\?\C:\vault.kdbx",
            r"\\?\UNC\server\share\vault.kdbx",
            r"\\.\PhysicalDrive0",
        ]
        .into_iter()
        .enumerate()
        {
            config.aliases.insert(
                format!("alias{index}"),
                Alias {
                    kind: Kind::Vault,
                    target: path.to_owned(),
                    field: None,
                },
            );
            assert!(vault_path(path).is_err(), "accepted vault path {path:?}");
            assert!(resolve_vault(path, &config).is_err());
            assert!(resolve_vault(&format!("alias{index}"), &config).is_err());
            config.current = Some(path.to_owned());
            assert!(resolve_vault(config.current.as_deref().unwrap(), &config).is_err());
        }

        use std::os::windows::ffi::OsStringExt;
        let mut wide = r"\\?\C:\non-utf8".encode_utf16().collect::<Vec<_>>();
        wide.push(0xD800); // Unpaired surrogate: this OsStr is not valid UTF-8.
        let non_utf8_override = PathBuf::from(std::ffi::OsString::from_wide(&wide));
        assert!(validate_base_dir(non_utf8_override.clone(), "unavailable").is_err());
        assert!(
            resolve_app_dir(
                Some(non_utf8_override.as_os_str()),
                Some(std::ffi::OsStr::new(r"C:\Valid\Nkeepass")),
                None,
                || panic!("invalid app override must not fall through"),
                "nkeepass",
                "directory unavailable",
                validate_base_dir,
            )
            .is_err()
        );
    }

    #[test]
    fn help_routing_skips_values_and_preserves_completion_and_exec_boundaries() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            help_request(&args(&[
                "--vault",
                "selected.kdbx",
                "secrets",
                "get",
                "--help"
            ])),
            Some(args(&["secrets", "get"]))
        );
        assert_eq!(
            help_request(&args(&["secrets", "get", "--key", "--help"])),
            None
        );
        assert_eq!(
            help_request(&args(&["secrets", "get", "-r", "--help"])),
            None
        );
        assert_eq!(
            help_request(&args(&[
                "secrets",
                "get",
                "--age-recipient",
                "--help",
                "--help"
            ])),
            Some(args(&["secrets", "get"]))
        );
        assert_eq!(
            help_request(&args(&["secrets", "set", "-i", "--help", "--help"])),
            Some(args(&["secrets", "set"]))
        );
        assert_eq!(
            help_request(&args(&["exec", "--env", "--help", "--", "tool"])),
            None
        );
        assert_eq!(help_request(&args(&["__complete", "--help"])), None);
    }

    fn production_cli_source(source: &str) -> &str {
        let tokens = rust_code_token_spans(source);
        let mut brace_depth = 0_i32;
        for (index, (token, start, _)) in tokens.iter().enumerate() {
            if brace_depth == 0
                && index + 7 < tokens.len()
                && token == "#"
                && tokens[index + 1].0 == "["
                && tokens[index + 2].0 == "cfg"
                && tokens[index + 3].0 == "("
                && tokens[index + 4].0 == "test"
                && tokens[index + 5].0 == ")"
                && tokens[index + 6].0 == "]"
                && tokens[index + 7].0 == "mod"
                && tokens
                    .get(index + 8)
                    .is_some_and(|token| token.0 == "tests")
                && tokens.get(index + 9).is_some_and(|token| token.0 == "{")
            {
                // A test module is a safe trim point only when it is the final
                // lexical item. Otherwise scanning the prefix would silently
                // exempt production code appended after the tests.
                let mut module_depth = 0_i32;
                let mut close = None;
                for (at, (body_token, _, _)) in tokens.iter().enumerate().skip(index + 9) {
                    match body_token.as_str() {
                        "{" => module_depth += 1,
                        "}" => {
                            module_depth -= 1;
                            if module_depth == 0 {
                                close = Some(at);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if close == tokens.len().checked_sub(1) {
                    return &source[..*start];
                }
                return source;
            }
            match token.as_str() {
                "{" => brace_depth += 1,
                "}" => brace_depth -= 1,
                _ => {}
            }
        }
        source
    }

    fn is_macro_policy_violation(violation: &str) -> bool {
        violation.contains("unreviewed macro") || violation.contains("user-defined macro")
    }

    /// Tokenizes enough Rust syntax to recognize boundary violations while
    /// ignoring comments and string/character literals. This avoids treating
    /// examples in help text, diagnostics, or comments as executable access.
    fn rust_code_tokens(source: &str) -> Vec<String> {
        rust_code_token_spans(source)
            .into_iter()
            .map(|(token, _, _)| token)
            .collect()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the small Rust lexer stays together for auditability"
    )]
    fn rust_code_token_spans(source: &str) -> Vec<(String, usize, usize)> {
        let bytes = source.as_bytes();
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            if bytes[i..].starts_with(b"//") {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if bytes[i..].starts_with(b"/*") {
                i += 2;
                let mut depth = 1_u32;
                while i < bytes.len() && depth > 0 {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                continue;
            }

            let raw_start = if bytes[i..].starts_with(b"br") {
                Some(i + 1)
            } else if bytes[i] == b'r' {
                Some(i)
            } else {
                None
            };
            if let Some(start) = raw_start {
                let mut quote = start + 1;
                while quote < bytes.len() && bytes[quote] == b'#' {
                    quote += 1;
                }
                if quote < bytes.len() && bytes[quote] == b'"' {
                    let hashes = quote - start - 1;
                    i = quote + 1;
                    while i < bytes.len() {
                        if bytes[i] == b'"'
                            && bytes
                                .get(i + 1..i + 1 + hashes)
                                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                        {
                            i += hashes + 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
            }

            if bytes[i] == b'b' && bytes.get(i + 1) == Some(&b'"') {
                i += 2;
                skip_quoted_bytes(bytes, &mut i, b'"');
                continue;
            }
            if bytes[i] == b'"' {
                i += 1;
                skip_quoted_bytes(bytes, &mut i, b'"');
                continue;
            }
            if bytes[i] == b'\'' {
                if let Some(end) = char_literal_end(bytes, i) {
                    i = end;
                    continue;
                }
                tokens.push(("'".to_owned(), i, i + 1));
                i += 1;
                continue;
            }
            if bytes[i..].starts_with(b"r#")
                && bytes
                    .get(i + 2)
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                let start = i;
                i += 2;
                let name_start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                tokens.push((
                    String::from_utf8_lossy(&bytes[name_start..i]).into_owned(),
                    start,
                    i,
                ));
                continue;
            }
            if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                tokens.push((
                    String::from_utf8_lossy(&bytes[start..i]).into_owned(),
                    start,
                    i,
                ));
                continue;
            }
            if i + 1 < bytes.len()
                && matches!(
                    &bytes[i..i + 2],
                    b"::" | b"->" | b"+=" | b"-=" | b"*=" | b"/=" | b"==" | b"=>"
                )
            {
                tokens.push((
                    String::from_utf8_lossy(&bytes[i..i + 2]).into_owned(),
                    i,
                    i + 2,
                ));
                i += 2;
            } else {
                tokens.push((char::from(bytes[i]).to_string(), i, i + 1));
                i += 1;
            }
        }
        tokens
    }

    fn skip_quoted_bytes(bytes: &[u8], i: &mut usize, terminator: u8) {
        while *i < bytes.len() {
            if bytes[*i] == b'\\' {
                *i = (*i + 2).min(bytes.len());
            } else if bytes[*i] == terminator {
                *i += 1;
                break;
            } else {
                *i += 1;
            }
        }
    }

    fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut i = start + 1;
        if i >= bytes.len() || bytes[i] == b'\n' {
            return None;
        }
        if bytes[i] == b'\\' {
            i += 1;
            match *bytes.get(i)? {
                b'\\' | b'\'' | b'"' | b'n' | b'r' | b't' | b'0' => i += 1,
                b'x' => {
                    let digits = bytes.get(i + 1..i + 3)?;
                    if !digits.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    let value = u8::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
                    if value > 0x7f {
                        return None;
                    }
                    i += 3;
                }
                b'u' if bytes.get(i + 1) == Some(&b'{') => {
                    i += 2;
                    let digits_start = i;
                    while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'_') {
                        i += 1;
                    }
                    if i == digits_start || bytes.get(i) != Some(&b'}') {
                        return None;
                    }
                    let digits: String = bytes[digits_start..i]
                        .iter()
                        .copied()
                        .filter(|byte| *byte != b'_')
                        .map(char::from)
                        .collect();
                    let _ = u32::from_str_radix(&digits, 16)
                        .ok()
                        .and_then(char::from_u32)?;
                    i += 1;
                }
                _ => return None,
            }
        } else {
            let tail = std::str::from_utf8(bytes.get(i..)?).ok()?;
            let scalar = tail.chars().next()?;
            if scalar == '\n' || scalar == '\r' || scalar == '\'' {
                return None;
            }
            i += scalar.len_utf8();
        }
        (bytes.get(i) == Some(&b'\'')).then_some(i + 1)
    }

    fn cli_boundary_violations(source: &str) -> Vec<String> {
        cli_boundary_violations_with_completion_macro(source, false)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the production-only boundary checks stay together for auditability"
    )]
    fn cli_boundary_violations_with_completion_macro(
        source: &str,
        allow_completion_macro: bool,
    ) -> Vec<String> {
        let tokens = rust_code_tokens(source);
        let mut violations = Vec::new();
        const SAFE_MACROS: &[&str] = &[
            "assert",
            "assert_eq",
            "assert_ne",
            "cfg",
            "concat",
            "debug_assert",
            "debug_assert_eq",
            "eprint",
            "eprintln",
            "env",
            "format",
            "include_str",
            "matches",
            "option_env",
            "panic",
            "print",
            "println",
            // Review the exact qualified JSON constructor only; other
            // serde_json macros and unqualified aliases are not implicitly safe.
            "serde_json::json",
            "stringify",
            "todo",
            "unimplemented",
            "unreachable",
            "vec",
            "write",
            "writeln",
        ];
        // Attribute macros and derives can synthesize arbitrary code just like
        // function-like macros. Keep this list limited to attributes/derives
        // actually reviewed in the CLI; `serde` is the inert helper attribute
        // consumed by the reviewed serde derives above.
        const SAFE_ATTRIBUTES: &[&str] = &["allow", "cfg", "derive", "must_use", "serde", "test"];
        const SAFE_DERIVES: &[&str] = &[
            "Clone",
            "Copy",
            "Debug",
            "Default",
            "Deserialize",
            "Eq",
            "PartialEq",
            "Serialize",
        ];
        for (index, token) in tokens.iter().enumerate() {
            if token != "#" || tokens.get(index + 1).map(String::as_str) != Some("[") {
                continue;
            }
            let start = index + 2;
            let mut end = start;
            let mut depth = 1_i32;
            while end < tokens.len() && depth > 0 {
                match tokens[end].as_str() {
                    "[" => depth += 1,
                    "]" => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            if depth != 0 || start >= end - 1 {
                violations.push("malformed CLI attribute".to_owned());
                continue;
            }
            let content = &tokens[start..end - 1];
            let attr = content.first().map(String::as_str).unwrap_or_default();
            let qualified = content.get(1).map(String::as_str) == Some("::");
            if qualified || !SAFE_ATTRIBUTES.contains(&attr) {
                violations.push(format!("unreviewed CLI attribute {attr}"));
                continue;
            }
            if attr == "derive" {
                // Derive entries are comma-separated simple paths. Reject any
                // token that is not punctuation or a reviewed derive name,
                // including qualified paths and malformed nested syntax.
                let mut expect_name = true;
                for part in &content[2..] {
                    if part == "(" || part == ")" {
                        // Delimit the derive list without treating delimiters
                        // as derive paths.
                    } else if part == "," {
                        if expect_name {
                            violations.push("malformed CLI derive list".to_owned());
                        }
                        expect_name = true;
                    } else if expect_name && SAFE_DERIVES.contains(&part.as_str()) {
                        expect_name = false;
                    } else {
                        violations.push(format!("unreviewed CLI derive {part}"));
                        expect_name = false;
                    }
                }
                if expect_name && !content[2..].is_empty() {
                    violations.push("malformed CLI derive list".to_owned());
                }
            }
        }
        // A type imported under another spelling evades an identifier list.
        // CLI code only needs the credential/write primitives from the crate;
        // reject aliased imports and all model/OTP module imports outright.
        for (index, token) in tokens.iter().enumerate() {
            if token != "use" {
                continue;
            }
            let end = tokens[index..]
                .iter()
                .position(|part| part == ";")
                .map_or(tokens.len(), |offset| index + offset);
            let import = &tokens[index..end];
            let is_keepass_import = import.iter().any(|part| part == "neotales_keepass");
            let imports_model_module = is_keepass_import
                && import.iter().any(|part| {
                    matches!(
                        part.as_str(),
                        "model" | "otp" | "BinaryPool" | "Entry" | "Group" | "Field"
                    )
                });
            if imports_model_module || (is_keepass_import && import.iter().any(|part| part == "as"))
            {
                violations.push("aliased or direct KeePass model import".to_owned());
            }
            let canonical_env_module = import
                .windows(3)
                .any(|path| path[0] == "std" && path[1] == "::" && path[2] == "env");
            if import
                .iter()
                .any(|part| SAFE_MACROS.contains(&part.as_str()))
                && !canonical_env_module
            {
                violations.push(format!(
                    "macro import shadows a reviewed safe macro name: {}",
                    import.join("")
                ));
            }
        }
        for (index, token) in tokens.iter().enumerate() {
            if token == "macro_rules"
                && tokens.get(index + 1).is_some_and(|next| next == "!")
                && !(allow_completion_macro
                    && tokens.get(index + 2).map(String::as_str)
                        == Some("define_nushell_completion"))
            {
                violations.push("user-defined macro can synthesize production code".to_owned());
            }
            if token == "!"
                && tokens
                    .get(index + 1)
                    .is_some_and(|next| matches!(next.as_str(), "(" | "[" | "{"))
            {
                let Some(name) = index.checked_sub(1).and_then(|at| tokens.get(at)) else {
                    continue;
                };
                if !name
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                    || !name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    continue;
                }
                let mut path_start = index - 1;
                while path_start >= 2
                    && tokens[path_start - 1] == "::"
                    && tokens[path_start - 2]
                        .chars()
                        .next()
                        .is_some_and(|first| first.is_ascii_alphanumeric() || first == '_')
                {
                    path_start -= 2;
                }
                let mut qualified = tokens[path_start..index].join("");
                if path_start > 0 && tokens[path_start - 1] == "::" {
                    qualified.insert_str(0, "::");
                }
                if !(SAFE_MACROS.contains(&qualified.as_str())
                    || (allow_completion_macro && qualified == "define_nushell_completion"))
                {
                    violations.push(format!("unreviewed macro invocation {qualified}!"));
                }
            }
        }
        fn is_enum_variant(tokens: &[String], index: usize, enum_name: &str) -> bool {
            if index >= 2 && tokens[index - 2] == enum_name && tokens[index - 1] == "::" {
                return true;
            }
            let Some(start) = (0..index).rev().find(|at| {
                *at + 1 < index && tokens[*at] == "enum" && tokens[*at + 1] == enum_name
            }) else {
                return false;
            };
            let Some(open) = tokens[start + 2..index]
                .iter()
                .position(|token| token == "{")
                .map(|offset| start + 2 + offset)
            else {
                return false;
            };
            let mut depth = 0_i32;
            for token in &tokens[open..index] {
                match token.as_str() {
                    "{" => depth += 1,
                    "}" => depth -= 1,
                    _ => {}
                }
            }
            depth > 0
        }
        let model_types = [
            "KdbxFile",
            "KeePassDatabase",
            "Entry",
            "Group",
            "Field",
            "Attachment",
            "BinaryPool",
            "BinaryRecord",
            "ProtectedValue",
            "OtpUri",
            "KeePassXcOtp",
            "OtpKind",
            "OtpSecret",
            "TotpParameters",
            "Totp",
            "KeePassMeta",
            "KeePassTimes",
            "AutoType",
            "AutoTypeAssociation",
            "CustomIcon",
            "DeletedObject",
            "VariantValue",
            "VariantDictionary",
            "VariantDictionaryItem",
            "CustomData",
            "CustomDataItem",
            "KdbxUuid",
            "KdbxColor",
            "KdbxTimestamp",
            "OtpAlgorithm",
            "OtpDigits",
            "HotpParameters",
            "Hotp",
            "OtpKind",
            "MergeStrategy",
            "KeePassEntry",
            "KeePassGroup",
            "KeePassField",
            "KeePassAttachment",
        ];
        for (index, token) in tokens.iter().enumerate() {
            if !model_types.contains(&token.as_str()) {
                continue;
            }
            let is_variant = (token == "Entry"
                && (is_enum_variant(&tokens, index, "Kind")
                    || is_enum_variant(&tokens, index, "MetadataKind")
                    || is_enum_variant(&tokens, index, "CandidateKind")))
                || (token == "Group" && is_enum_variant(&tokens, index, "MetadataKind"))
                || (token == "Field"
                    && (is_enum_variant(&tokens, index, "Bound")
                        || (index >= 2
                            && tokens[index - 2] == "Self"
                            && tokens[index - 1] == "::")));
            if !is_variant {
                violations.push(format!("direct KeePass model/OTP type {token}"));
            }
        }
        for window in tokens.windows(3) {
            if window[0] == "KdbxFile"
                && window[1] == "::"
                && matches!(window[2].as_str(), "load" | "save")
            {
                violations.push(format!("direct KdbxFile::{}", window[2]));
            }
            if window[0] == "ProtectedValue" && window[1] == "::" && window[2].starts_with("reveal")
            {
                violations.push(format!("ProtectedValue::{}", window[2]));
            }
        }
        for (index, token) in tokens.iter().enumerate() {
            if token == "."
                && tokens
                    .get(index + 1)
                    .is_some_and(|method| method.starts_with("reveal"))
            {
                let method = &tokens[index + 1];
                let receiver = index.checked_sub(1).and_then(|at| tokens.get(at));
                let allowed_service_reveal = receiver.is_some_and(|name| name == "service")
                    && matches!(
                        method.as_str(),
                        "reveal_field"
                            | "reveal_native_field"
                            | "reveal_attachment"
                            | "reveal_password"
                    );
                if !allowed_service_reveal {
                    violations.push(format!("direct reveal method .{method}"));
                }
            }
            if token != "." {
                continue;
            }
            if let Some(method) = tokens.get(index + 1).map(String::as_str) {
                let receiver = index.checked_sub(1).and_then(|at| tokens.get(at));
                let direct_model_mutator = matches!(
                    method,
                    "set_field"
                        | "set_fields"
                        | "add_entry"
                        | "add_group"
                        | "add_attachment"
                        | "remove_entry"
                        | "remove_custom_field"
                        | "remove_attachment"
                        | "add"
                );
                if direct_model_mutator && receiver.is_none_or(|name| name != "service") {
                    violations.push(format!("direct model mutation method .{method}"));
                }
            }
            let Some(field) = tokens.get(index + 1).map(String::as_str) else {
                continue;
            };
            let Some(next) = tokens.get(index + 2).map(String::as_str) else {
                continue;
            };
            let receiver = index.checked_sub(1).and_then(|at| tokens.get(at));
            // These narrowly-scoped names are CLI/service DTO metadata, not
            // permission to access arbitrary model-shaped fields on either value.
            let safe_record = match receiver.map(String::as_str) {
                Some("opts") => matches!(field, "password" | "key" | "name"),
                Some("common_options") => matches!(field, "key" | "name"),
                Some("binding") => matches!(field, "key" | "name"),
                Some("update") => {
                    matches!(field, "key" | "value" | "protected" | "protect_in_memory")
                }
                Some("report") => {
                    matches!(field, "groups" | "entries" | "fields" | "attachments")
                }
                Some("metadata") => matches!(field, "groups" | "entries"),
                _ => false,
            };
            let model_fields = [
                // KeePass model field inventory from neotales-keepass's
                // public model structs. Keep names here even when they are
                // not currently read by the CLI: new direct reads or writes
                // must cross the service boundary too.
                "id",
                "name",
                "description",
                "default_username",
                "settings_changed",
                "database_name_changed",
                "database_description_changed",
                "default_username_changed",
                "master_key_changed",
                "maintenance_history_days",
                "color",
                "master_key_change_rec",
                "master_key_change_force",
                "master_key_change_force_once",
                "protect_password",
                "protect_title",
                "protect_username",
                "protect_url",
                "protect_notes",
                "times",
                "history_max_items",
                "history_max_size",
                "memory_protection",
                "recycle_bin_enabled",
                "recycle_bin_uuid",
                "recycle_bin_changed",
                "templates_uuid",
                "templates_changed",
                "selected_group_uuid",
                "top_visible_group_uuid",
                "custom_data",
                "legacy_binaries",
                "custom_icons",
                "root",
                "binary_pool",
                "deleted_objects",
                "public_custom_data",
                "typed_public_custom_data",
                "can_save_losslessly",
                "fields",
                "attachments",
                "password",
                "title",
                "username",
                "url",
                "notes",
                "history",
                "entries",
                "groups",
                "meta",
                "generator",
                "icon_id",
                "custom_icon_id",
                "is_expanded",
                "enable_auto_type",
                "enable_searching",
                "default_auto_type_sequence",
                "default_sequence",
                "last_top_visible_entry_id",
                "previous_parent_group_id",
                "tags",
                "foreground_color",
                "background_color",
                "quality_check",
                "auto_type",
                "key",
                "value",
                "protected",
                "protect_in_memory",
                "data",
                "reference",
                "window",
                "keystrokes",
                "enabled",
                "obfuscated",
                "associations",
                "uuid",
                "last_modification",
                "deleted_at",
                "expires",
                "expires_enabled",
                "created",
                "modified",
                "accessed",
                "usage_count",
                "location_changed",
            ];
            if model_fields.contains(&field) && !safe_record && next != "(" {
                violations.push(format!("direct model field access .{field}"));
            }
        }
        violations
    }

    #[test]
    fn init_context_persistence_failure_is_partial_success_and_retry_cannot_replace() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("installed.kdbx");
        let mut credentials = KdbxCredentials::password("init-context-test-password").unwrap();
        VaultService::default()
            .create(
                &path,
                &mut credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        let installed = fs::read(&path).unwrap();
        let mut config = Config::default();
        let error = adopt_init_context_with(&mut config, path.to_str().unwrap(), true, |_| {
            Err(err("injected configuration persistence failure"))
        });
        assert!(error.is_err());
        assert_eq!(config.current.as_deref(), Some("default"));
        assert_eq!(config.aliases["default"].target, path.to_str().unwrap());
        assert!(
            path.is_file(),
            "vault remains installed after context failure"
        );
        assert_eq!(fs::read(&path).unwrap(), installed);

        let retry = VaultService::default().create(
            &path,
            &mut KdbxCredentials::password("init-context-test-password").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            None,
        );
        assert_eq!(retry, Err(nkeepass::ServiceError::CreateExists));
        assert_eq!(fs::read(path).unwrap(), installed);
    }

    #[test]
    fn init_durability_failure_adopts_installed_vault_and_retry_cannot_replace() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("installed-after-durability-error.kdbx");
        let mut credentials = KdbxCredentials::password("init-durability-test-password").unwrap();
        VaultService::default()
            .create(
                &path,
                &mut credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        let installed = fs::read(&path).unwrap();
        let path_text = path.to_str().unwrap();
        let mut config = Config::default();

        let error = adopt_after_init_create(
            &mut config,
            path_text,
            true,
            Err(nkeepass::ServiceError::CreateDurability),
            |_| Ok(()),
        )
        .unwrap_err();

        assert_eq!(config.current.as_deref(), Some("default"));
        assert_eq!(config.aliases["default"].target, path_text);
        assert_eq!(error.0, nkeepass::ServiceError::CreateDurability.message());
        assert_eq!(fs::read(&path).unwrap(), installed);

        let retry = VaultService::default().create(
            &path,
            &mut KdbxCredentials::password("init-durability-test-password").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            None,
        );
        assert_eq!(retry, Err(nkeepass::ServiceError::CreateExists));
        assert_eq!(fs::read(path).unwrap(), installed);
    }

    #[test]
    fn init_durability_and_context_persistence_failures_are_both_reported() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("installed-with-config-error.kdbx");
        let mut credentials = KdbxCredentials::password("init-durability-test-password").unwrap();
        VaultService::default()
            .create(
                &path,
                &mut credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        let installed = fs::read(&path).unwrap();
        let path_text = path.to_str().unwrap();
        let mut config = Config::default();
        let error = adopt_after_init_create(
            &mut config,
            path_text,
            true,
            Err(nkeepass::ServiceError::CreateDurability),
            |_| Err(err("injected configuration persistence failure")),
        )
        .unwrap_err();

        assert!(
            error
                .0
                .contains(nkeepass::ServiceError::CreateDurability.message())
        );
        assert!(
            error
                .0
                .contains("injected configuration persistence failure")
        );
        assert_eq!(config.current.as_deref(), Some("default"));
        assert_eq!(config.aliases["default"].target, path_text);
        assert_eq!(fs::read(&path).unwrap(), installed);

        let retry = VaultService::default().create(
            &path,
            &mut KdbxCredentials::password("init-durability-test-password").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            None,
        );
        assert_eq!(retry, Err(nkeepass::ServiceError::CreateExists));
        assert_eq!(fs::read(path).unwrap(), installed);
    }

    #[test]
    fn init_durability_failure_does_not_replace_existing_context() {
        let mut config = Config {
            current: Some("chosen.kdbx".to_owned()),
            ..Default::default()
        };
        let error = adopt_after_init_create(
            &mut config,
            "/tmp/other.kdbx",
            true,
            Err(nkeepass::ServiceError::CreateDurability),
            |_| panic!("existing context must not be persisted or replaced"),
        )
        .unwrap_err();

        assert_eq!(error.0, nkeepass::ServiceError::CreateDurability.message());
        assert_eq!(config.current.as_deref(), Some("chosen.kdbx"));
        assert!(config.aliases.is_empty());
    }

    #[test]
    fn bounded_input_rejects_oversize_and_read_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversize.bin");
        fs::write(&path, b"four").unwrap();
        // The oversize path returns while `bounded_file` still owns its
        // Zeroizing allocation, so its partial contents are cleared on drop.
        assert!(bounded_file(path.to_str().unwrap(), 3).is_err());

        struct FailsAfterSecret(bool);
        impl Read for FailsAfterSecret {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("injected read failure"));
                }
                self.0 = true;
                let secret = b"sensitive";
                output[..secret.len()].copy_from_slice(secret);
                Ok(secret.len())
            }
        }

        // Force a partial plaintext read before the error; `read_bounded` owns
        // the Zeroizing buffer throughout, including this early return.
        assert!(read_bounded(FailsAfterSecret(false), 32, "read failed").is_err());
    }

    /// The three places the key set is written down must agree.
    ///
    /// The listing order, the name each key is reported and matched under, and
    /// the keys named in the refusal are three separate literals. The refusal
    /// is the only one a user ever sees for a typo, so if it fell behind the
    /// closed set it would tell someone the valid keys are a subset of the ones
    /// that actually work -- and if the set grew without the diagnostic, the
    /// message would advertise keys that do not exist.
    #[test]
    fn the_configuration_key_set_is_closed_and_every_spelling_agrees() {
        let names: Vec<&str> = CONFIG_KEYS.iter().map(|key| key.name()).collect();
        assert_eq!(names, ["aliases", "current", "default_vault"]);
        for name in &names {
            assert!(
                ConfigKey::parse(name).is_ok(),
                "{name} is listed but the parser refuses it"
            );
            assert!(
                UNKNOWN_CONFIG_KEY.contains(name),
                "the refusal for an unknown key does not name {name}: {UNKNOWN_CONFIG_KEY}"
            );
        }
        // Nothing outside the set parses, so a field the struct happens to grow
        // is not writable from the command line.
        for refused in [
            "",
            "Current",
            "default-vault",
            "alias",
            "context",
            "secrets",
        ] {
            let error = ConfigKey::parse(refused)
                .err()
                .unwrap_or_else(|| panic!("{refused} must not be a configuration key"));
            assert_eq!(
                error.0, UNKNOWN_CONFIG_KEY,
                "{refused} must be refused with the key list"
            );
        }
    }

    /// `aliases` cannot be read or written as one value.
    ///
    /// Both directions are asserted because either one alone leaves a hole: a
    /// `get` that flattened the map would print it as a string, and a `set`
    /// that replaced it would drop every alias the user has.
    #[test]
    fn the_alias_map_is_not_a_scalar_configuration_value() {
        let mut config = Config {
            current: Some("/abs/vault.kdbx".to_owned()),
            ..Config::default()
        };
        assert_eq!(config.value(ConfigKey::Aliases), None);
        assert_eq!(
            config
                .set_value(ConfigKey::Aliases, Some("anything".to_owned()))
                .unwrap_err()
                .0,
            CONFIG_ALIASES_NOT_SCALAR
        );
        assert!(config.aliases.is_empty());
        // The refusal is a redirect to the commands that do validate a target,
        // not a bare "no".
        assert!(CONFIG_ALIASES_NOT_SCALAR.contains("alias set"));
        assert!(CONFIG_ALIASES_NOT_SCALAR.contains("alias rm"));

        // A scalar write goes to its own field and leaves the other alone, so
        // `config set` cannot lose a key it was not asked about.
        config
            .set_value(
                ConfigKey::DefaultVault,
                Some("/abs/default.kdbx".to_owned()),
            )
            .unwrap();
        assert_eq!(config.current.as_deref(), Some("/abs/vault.kdbx"));
        assert_eq!(config.default_vault.as_deref(), Some("/abs/default.kdbx"));
    }

    #[test]
    fn the_child_environment_is_an_allowlist_that_carries_no_credential() {
        // `env::set_var` is `unsafe` in edition 2024 and this crate forbids
        // unsafe code, so the sentinel cannot be injected from a unit test.
        // Instead this asserts the property that is actually load-bearing: the
        // allowlist is a fixed list, and nothing outside it -- and nothing
        // matching NKEEPASS_* -- can ever be in the result. The end-to-end
        // behaviour, with a real sentinel in a real parent environment and a
        // real child, is covered by
        // `hardening::exec_does_not_pass_the_parent_environment_to_the_child`.
        let passed = child_environment();
        for (name, _) in &passed {
            assert!(
                !name.starts_with("NKEEPASS_"),
                "{name} is an NKEEPASS_* variable and must never reach the child"
            );
        }
        // Every returned name must be one this function is willing to return.
        // This is the assertion that fails if someone widens the allowlist
        // without thinking, because an unexpected name is not on the list.
        const KNOWN: &[&str] = &[
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TZ",
            "TERM",
            "SystemRoot",
            "SYSTEMROOT",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "HOMEDRIVE",
            "HOMEPATH",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "CARGO_MANIFEST_DIR",
        ];
        for (name, _) in &passed {
            assert!(
                KNOWN.contains(&name.as_str()),
                "{name} is not on the allowlist; add it deliberately and document why"
            );
        }
    }

    #[test]
    fn the_child_environment_carries_path_so_a_command_can_be_found() {
        // An allowlist that omits PATH produces an allowlist that breaks every
        // child, so this is asserted rather than assumed.
        if env::var_os("PATH").is_some() {
            assert!(
                child_environment().iter().any(|(name, _)| name == "PATH"),
                "PATH must be passed or no child command can be resolved"
            );
        }
    }

    #[test]
    fn cli_kdbx_policy_is_valid_and_pinned() {
        KDBX_LIMITS.validate().unwrap();
        assert_eq!(KDBX_LIMITS.max_input_bytes, 64 * 1024 * 1024);
        assert_eq!(KDBX_LIMITS.max_decompressed_bytes, 64 * 1024 * 1024);
        assert_eq!(KDBX_LIMITS.max_aes_kdf_rounds, 100_000_000);
        assert_eq!(KDBX_LIMITS.max_argon2_work_kib_passes, 64 * 1024 * 10);
    }

    /// Unix only, because the failure it demonstrates cannot occur elsewhere:
    /// opening a directory as a file and flushing it is the operation, and on
    /// Windows `File::open` on a directory fails before the flush is attempted --
    /// which is exactly why `confirm_durable` is a no-op there rather than a call
    /// to this.
    #[cfg(unix)]
    #[test]
    fn directory_sync_failures_are_reported_as_installed_durability_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let error = sync_installed_directory(
            &missing,
            "plaintext output installed but directory durability is unconfirmed",
        )
        .unwrap_err();
        assert_eq!(
            error.0,
            "plaintext output installed but directory durability is unconfirmed"
        );
    }

    #[test]
    fn formatted_controls_allow_line_feeds_but_reject_terminal_controls() {
        assert!(validate_formatted_controls("line one\nline two").is_ok());
        for value in ["escape\u{1b}[31m", "bell\u{7}", "delete\u{7f}", "c1\u{85}"] {
            assert_eq!(
                validate_formatted_controls(value).unwrap_err().0,
                "formatted output cannot contain terminal-control bytes"
            );
        }
    }

    #[test]
    fn safe_metadata_rejects_every_c0_del_and_c1_code_point() {
        for code in (0x00..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            assert!(
                !safe_metadata(&format!("group{control}name")),
                "U+{code:04X} must make CLI metadata unsafe",
            );
        }
        assert!(safe_metadata("ordinary group name"));
    }

    #[test]
    fn a_named_format_carries_its_own_value_rules() {
        // Everything with a name is a format that writes `NAME` then a value, so
        // each one has to be a name the caller typed.
        for format in [
            "dotenv",
            "shell",
            "pwsh",
            "powershell",
            "github-actions",
            "azure-devops",
        ] {
            assert!(is_named_format(format), "{format}");
            assert_eq!(
                named_text(format, None, b"value").unwrap_err().0,
                "--name required for named output"
            );
            assert_eq!(
                named_text(format, Some("LOGIN-PASSWORD"), b"value")
                    .unwrap_err()
                    .0,
                "invalid output name"
            );
            assert_eq!(
                named_text(format, Some("${LOGIN_PASSWORD}"), b"value")
                    .unwrap_err()
                    .0,
                "invalid output name"
            );
        }
        for format in ["text", "json", "null", "", "nope"] {
            assert!(!is_named_format(format), "{format}");
        }

        // A line feed is data everywhere except where the consumer reads one
        // line at a time, and the heredoc delimiter is data nowhere.
        assert!(validate_named_value("pwsh", "one\ntwo").is_ok());
        assert!(validate_named_value("pwsh", GITHUB_EOF).is_ok());
        assert!(validate_named_value("github-actions", "one\ntwo").is_ok());
        assert!(validate_named_value("github-actions", "NKEEPASS_EO").is_ok());
        assert!(validate_named_value("github-actions", "NKEEPASS_EOF extra").is_ok());
        assert_eq!(
            validate_named_value("github-actions", "NKEEPASS_EOF")
                .unwrap_err()
                .0,
            "github-actions output cannot contain the heredoc delimiter"
        );
        assert_eq!(
            validate_named_value("github-actions", "before\nNKEEPASS_EOF\nafter")
                .unwrap_err()
                .0,
            "github-actions output cannot contain the heredoc delimiter"
        );
        assert!(validate_named_value("azure-devops", "one line").is_ok());
        assert_eq!(
            validate_named_value("azure-devops", "one\ntwo")
                .unwrap_err()
                .0,
            "azure-devops output cannot contain a line feed"
        );
    }

    #[test]
    fn positional_terminator_preserves_leading_dash_queries() {
        let args = ["--".to_owned(), "-query".to_owned()];
        let opts = options(&args, Positional::Glob).unwrap();
        assert_eq!(opts.glob, Some("-query"));
        let extra = ["--".to_owned(), "-query".to_owned(), "extra".to_owned()];
        assert!(options(&extra, Positional::Glob).is_err());
    }

    #[test]
    fn a_bare_word_is_a_target_path_only_where_a_command_declares_one() {
        let args = ["/tmp/vault.kdbx".to_owned()];
        let opts = options(&args, Positional::Path).unwrap();
        assert_eq!(opts.path, Some("/tmp/vault.kdbx"));
        assert_eq!(opts.glob, None);
        // Only the walk commands take a bare word, so a stray positional is
        // refused everywhere else rather than silently dropped.
        assert!(options(&args, Positional::Forbidden).is_err());
        // A walk command's bare word is the glob, with or without the `--`
        // terminator, and it is never read as a path.
        let glob = options(&args, Positional::Glob).unwrap();
        assert_eq!(glob.glob, Some("/tmp/vault.kdbx"));
        assert_eq!(glob.path, None);
        let twice = ["/tmp/one.kdbx".to_owned(), "/tmp/two.kdbx".to_owned()];
        assert!(options(&twice, Positional::Path).is_err());
        assert!(options(&twice, Positional::Glob).is_err());
    }

    #[test]
    fn kdf_shape_options_are_rejected_by_every_command_except_init() {
        let args = ["--kdf".to_owned(), "argon2id".to_owned()];
        let opts = options(&args, Positional::Forbidden).unwrap();
        assert!(vault_creation_options(&opts));
        assert!(validate_regular_options("ls", &opts).is_err());
        assert!(validate_regular_options("get", &opts).is_err());
        assert!(validate_automation_options("sync", &opts).is_err());
        assert!(validate_init_options(&opts).is_ok());

        let bare = options(&[], Positional::Forbidden).unwrap();
        assert!(!vault_creation_options(&bare));
        assert!(validate_regular_options("ls", &bare).is_ok());
    }

    /// Parses `args` and hands the result to `check`, so an assertion can be
    /// written against the borrowed options without the closure outliving the
    /// vector they borrow from. Only for cases the parser must accept.
    fn parsed(args: &[&str], check: impl FnOnce(&Options<'_>)) {
        let owned: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
        let opts = options(&owned, Positional::Path)
            .unwrap_or_else(|error| panic!("{} refused: {}", args.join(" "), error.0));
        check(&opts);
    }

    /// Asserts a case is refused, whichever layer refuses it.
    ///
    /// Some of these are rejected by the parser -- a count that is not a number
    /// at all -- and some by the KDF policy, which only sees a parsed option
    /// set. Which layer refuses an invalid combination is not the property
    /// under test; refusing it is.
    fn assert_refused<T>(args: &[&str], policy: impl Fn(&Options<'_>) -> Result<T>) {
        let owned: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
        if let Ok(opts) = options(&owned, Positional::Path) {
            assert!(policy(&opts).is_err(), "accepted {}", args.join(" "));
        }
    }

    #[test]
    fn init_kdf_options_are_bounded_by_the_read_limits_they_must_satisfy() {
        parsed(&["--kdf", "aes", "--iterations", "600000"], |opts| {
            let write = init_write_options(opts).unwrap();
            assert_eq!(write.kdf, KdbxKdf::Aes);
            assert_eq!(write.aes_kdf_rounds, 600_000);
        });
        parsed(&["--kdf", "argon2id", "--memory", "65536"], |opts| {
            assert_eq!(init_write_options(opts).unwrap().kdf, KdbxKdf::Argon2id);
        });
        // The library default is the pinned policy, not an oversight.
        parsed(&[], |opts| {
            assert_eq!(
                init_write_options(opts).unwrap(),
                KdbxWriteOptions::default()
            );
        });

        // An Argon2 knob under the AES KDF would be silently discarded, which
        // is the failure mode this rejects: a caller would believe they had
        // hardened a vault that was written with AES-KDF. The rest sit beyond
        // the read limits this CLI enforces, so `init` must not be able to
        // write a file its own reader would refuse to open.
        let refused: Vec<Vec<&str>> = vec![
            vec!["--kdf", "aes", "--memory", "65536"],
            vec!["--kdf", "aes", "--parallelism", "4"],
            vec!["--memory", "65536"],
            vec!["--kdf", "argon2d", "--iterations", "0"],
            vec!["--kdf", "argon2d", "--memory", "0"],
            vec!["--kdf", "argon2d", "--parallelism", "0"],
            vec!["--kdf", "argon2d", "--memory", "99999999"],
            vec!["--kdf", "argon2d", "--parallelism", "17"],
            vec!["--kdf", "argon2d", "--iterations", "11"],
            vec!["--kdf", "argon2d", "--iterations", "99999999999999999999"],
            vec!["--kdf", "argon2"],
        ];
        for args in &refused {
            assert_refused(args, init_write_options);
        }
    }

    #[test]
    fn init_rejects_the_option_surface_it_has_no_meaning_for() {
        for args in [&[][..], &["--password-stdin"][..], &["--size", "32"][..]] {
            parsed(args, |opts| assert!(validate_init_options(opts).is_ok()));
        }
        let refused: Vec<Vec<&str>> = vec![
            vec!["--key", "LOGIN"],
            vec!["--field", "Password"],
            vec!["--name", "OUT"],
            vec!["--file", "/etc/hosts"],
            vec!["--output", "/tmp/out"],
            vec!["--yes"],
            vec!["--dry-run"],
            vec!["--replace"],
            vec!["--format", "json"],
            vec!["--strategy", "newest"],
            vec!["--stdin"],
            vec!["--size", "0"],
            vec!["--size", "4097"],
        ];
        for args in &refused {
            assert_refused(args, validate_init_options);
        }
    }

    #[test]
    fn vault_paths_reject_terminal_control_bytes() {
        // The accepted path is built from the platform's own temporary directory
        // rather than written as a literal `/tmp/...`.
        //
        // `Path::is_absolute` is platform-defined: on Windows a path needs a drive
        // prefix or a UNC share, and `/tmp/ok.kdbx` is neither -- it is a rooted
        // path *on the current drive*, which is not the same thing. So the literal
        // was refused as "must be absolute and normalized" and this test failed on
        // Windows while passing everywhere else.
        //
        // It failed for a long time without being noticed, because the Windows job
        // never reached the tests: it died earlier, on a `python3` shebang the
        // runner had no interpreter for. Two independent faults, stacked, with the
        // second one invisible until the first was fixed. A test that only ever ran
        // where its assumption holds is not a test of the assumption.
        let good = std::env::temp_dir().join("ok.kdbx");
        let good = good.to_str().unwrap();
        assert!(
            vault_path(good).is_ok(),
            "{good:?} should be an acceptable vault path on this platform"
        );

        // The control bytes are rejected whatever the prefix, so the same suffix is
        // appended to a path that is absolute here.
        let stem = std::env::temp_dir();
        for suffix in [
            "bell\u{7}.kdbx",
            "escape\u{1b}[31m.kdbx",
            "delete\u{7f}.kdbx",
            "c1\u{9b}0m.kdbx",
        ] {
            let path = stem.join(suffix);
            let path = path.to_str().unwrap();
            assert_eq!(
                vault_path(path).unwrap_err().0,
                "vault path cannot contain terminal-control bytes",
                "{path:?} should be refused for its control bytes"
            );
        }
    }

    #[test]
    fn a_private_install_refuses_to_clobber_and_leaves_the_original_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.kdbx");
        fs::write(&path, b"original").unwrap();
        let mut staged = StagedFile::new(
            &path,
            InstallDiagnostics {
                staging: "staging",
                permissions: "permissions",
                write: "write",
                exists: "exists",
                durable: "durable",
            },
        )
        .unwrap();
        staged.writer().write_all(b"replacement").unwrap();
        assert_eq!(staged.install().unwrap_err().0, "exists");
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn a_private_install_is_owner_only_before_the_first_byte_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fresh.kdbx");
        let mut staged = StagedFile::new(
            &path,
            InstallDiagnostics {
                staging: "staging",
                permissions: "permissions",
                write: "write",
                exists: "exists",
                durable: "durable",
            },
        )
        .unwrap();
        // The mode is a property of the empty staging file, not of the
        // installed one, so it is checked here: a `chmod` after the write would
        // leave a window in which the secret was readable by another user.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(staged.file.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        staged.writer().write_all(b"secret").unwrap();
        staged.install().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn public_command_aliases_are_explicit() {
        assert_eq!(public_secrets_action("list"), Some("ls"));
        assert_eq!(public_secrets_action("remove"), Some("rm"));
        assert_eq!(public_secrets_action("environment"), Some("env"));
        assert_eq!(public_secrets_action("field-get"), None);
        assert_eq!(public_automation_action("field-set"), None);
        assert_eq!(public_automation_action("sync"), Some("sync"));
    }

    #[test]
    fn production_cli_source_cannot_reintroduce_direct_model_access() {
        let source = include_str!("main.rs");
        let production = production_cli_source(source);
        assert_eq!(
            cli_boundary_violations(production),
            Vec::<String>::new(),
            "production CLI source must cross the vault boundary only through the service"
        );
        for (path, module) in [
            ("completion.rs", include_str!("completion.rs")),
            ("glob.rs", include_str!("glob.rs")),
            ("private_file.rs", include_str!("private_file.rs")),
        ] {
            let production = production_cli_source(module);
            assert_eq!(
                cli_boundary_violations_with_completion_macro(production, path == "completion.rs"),
                Vec::<String>::new(),
                "production CLI module {path} must cross the vault boundary only through the service"
            );
        }
        // These are the deliberate model-touching service implementation
        // boundary. Keep them explicit rather than accidentally scanning or
        // exempting arbitrary newly-added CLI modules.
        // `interchange` is deliberately a model translation adapter shared by
        // the CLI and service; like automation it remains on the trusted side
        // of the boundary rather than being mistaken for a frontend module.
        assert_eq!(
            cli_boundary_violations(production_cli_source(include_str!("interchange.rs")))
                .into_iter()
                .filter(|violation| is_macro_policy_violation(violation))
                .collect::<Vec<_>>(),
            Vec::<String>::new(),
            "trusted interchange adapter must not grow unreviewed macros"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "module-boundary audit and its coverage regressions stay together"
    )]
    fn every_main_and_library_module_declaration_is_accounted_for_by_the_boundary_scan() {
        use std::collections::BTreeMap;

        fn has_path_redirection(attributes: &[syn::Attribute]) -> bool {
            fn meta_redirects(meta: &syn::Meta) -> bool {
                match meta {
                    syn::Meta::NameValue(value) => value.path.is_ident("path"),
                    syn::Meta::List(list) if list.path.is_ident("cfg_attr") => {
                        let nested = list
                            .parse_args_with(syn::punctuated::Punctuated::<
                                syn::Meta,
                                syn::Token![,],
                            >::parse_terminated);
                        nested.is_ok_and(|nested| nested.iter().skip(1).any(meta_redirects))
                    }
                    syn::Meta::List(list) => list
                        .parse_args_with(syn::punctuated::Punctuated::<
                            syn::Meta,
                            syn::Token![,],
                        >::parse_terminated)
                        .is_ok_and(|nested| nested.iter().any(meta_redirects)),
                    syn::Meta::Path(_) => false,
                }
            }

            attributes.iter().any(|attribute| {
                attribute.path().is_ident("path")
                    || (attribute.path().is_ident("cfg_attr")
                        && attribute
                            .parse_args_with(syn::punctuated::Punctuated::<
                                syn::Meta,
                                syn::Token![,],
                            >::parse_terminated)
                            .is_ok_and(|nested| nested.iter().skip(1).any(meta_redirects)))
            })
        }

        fn external_modules(source: &str) -> Vec<(String, bool)> {
            let file = syn::parse_file(source).expect("valid Rust source");
            file.items
                .into_iter()
                .filter_map(|item| match item {
                    syn::Item::Mod(module) if module.content.is_none() => Some((
                        module.ident.to_string(),
                        has_path_redirection(&module.attrs),
                    )),
                    _ => None,
                })
                .collect()
        }

        fn audit_covered_modules(
            source: &str,
            sources: &BTreeMap<String, String>,
            path: &str,
            is_root: bool,
            inside_inline: bool,
            violations: &mut Vec<String>,
        ) {
            let file = syn::parse_file(source).expect("valid Rust source");
            audit_items(
                &file.items,
                sources,
                path,
                is_root,
                inside_inline,
                violations,
            );
        }

        fn audit_items(
            items: &[syn::Item],
            sources: &BTreeMap<String, String>,
            path: &str,
            is_root: bool,
            inside_inline: bool,
            violations: &mut Vec<String>,
        ) {
            for item in items {
                let syn::Item::Mod(module) = item else {
                    continue;
                };
                let name = module.ident.to_string();
                if let Some((_, content)) = &module.content {
                    if has_path_redirection(&module.attrs) {
                        violations.push(format!("{path}: #[path] redirects covered module {name}"));
                    }
                    audit_items(content, sources, path, is_root, true, violations);
                    continue;
                }
                if has_path_redirection(&module.attrs) {
                    violations.push(format!("{path}: #[path] redirects covered module {name}"));
                    continue;
                }
                let child = if is_root {
                    format!("{name}.rs")
                } else {
                    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                    let stem = path.rsplit('/').next().unwrap().trim_end_matches(".rs");
                    if parent.is_empty() {
                        format!("{stem}/{name}.rs")
                    } else {
                        format!("{parent}/{stem}/{name}.rs")
                    }
                };
                if inside_inline && !sources.contains_key(&child) {
                    violations.push(format!(
                        "{path}: external module {name} nested in an inline module requires an explicit source mapping"
                    ));
                    continue;
                }
                let child_source = sources.get(&child).cloned().or_else(|| {
                    std::fs::read_to_string(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("src")
                            .join(&child),
                    )
                    .ok()
                });
                let Some(child_source) = child_source else {
                    violations.push(format!(
                        "{path}: covered module {name} has no audited source {child}"
                    ));
                    continue;
                };
                audit_covered_modules(&child_source, sources, &child, false, false, violations);
            }
        }

        const SCANNED: &[&str] = &["clipboard", "completion", "tui"];
        const SCANNED_LIBRARY: &[&str] = &["glob", "private_file"];
        // These remain explicit trust-boundary exemptions: they are library-side
        // model adapters/implementations, not user-facing CLI modules.
        const TRUSTED_LIBRARY_BOUNDARIES: &[&str] = &["service", "automation", "interchange"];
        let declared = external_modules(include_str!("main.rs"));
        const EXPECTED_MODULE_SOURCES: &[(&str, &str)] = &[
            ("clipboard", "clipboard.rs"),
            ("completion", "completion.rs"),
            ("tui", "tui.rs"),
            ("service", "service.rs"),
            ("automation", "automation.rs"),
            ("interchange", "interchange.rs"),
        ];
        let accounted_for = [SCANNED, TRUSTED_LIBRARY_BOUNDARIES].concat();
        assert_eq!(
            declared
                .iter()
                .filter(|(name, _)| !accounted_for.contains(&name.as_str()))
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>(),
            Vec::<String>::new()
        );
        assert_eq!(
            declared
                .iter()
                .filter(|(name, _)| SCANNED.contains(&name.as_str()) && *name == "completion")
                .filter(|(_, redirected)| *redirected)
                .count(),
            0,
            "covered main modules must use the source path the audit scans"
        );
        for (name, redirected) in &declared {
            let expected = EXPECTED_MODULE_SOURCES
                .iter()
                .find_map(|(module, source)| (*module == name).then_some(*source));
            assert!(
                expected.is_some_and(|source| source == format!("{name}.rs")),
                "module {name} must resolve to its exact audited source"
            );
            assert!(!redirected, "module {name} must not redirect its source");
        }

        // Keep library declarations independently accountable: the library
        // shares some frontend modules, but service-side implementations are
        // trusted boundaries and must not be fed through the CLI checker.
        let declared_library = external_modules(include_str!("lib.rs"));
        const EXPECTED_LIBRARY_MODULE_SOURCES: &[(&str, &str)] = &[
            ("automation", "automation.rs"),
            ("glob", "glob.rs"),
            ("interchange", "interchange.rs"),
            ("private_file", "private_file.rs"),
            ("service", "service.rs"),
        ];
        let library_accounted_for = [SCANNED_LIBRARY, TRUSTED_LIBRARY_BOUNDARIES].concat();
        assert_eq!(
            declared_library
                .iter()
                .filter(|(name, _)| !library_accounted_for.contains(&name.as_str()))
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>(),
            Vec::<String>::new(),
            "every lib.rs module must be scanned or an explicit trusted boundary"
        );
        for (name, redirected) in &declared_library {
            let expected = EXPECTED_LIBRARY_MODULE_SOURCES
                .iter()
                .find_map(|(module, source)| (*module == name).then_some(*source));
            assert!(
                expected.is_some_and(|source| source == format!("{name}.rs")),
                "library module {name} must resolve to its exact audited source"
            );
            assert!(
                !redirected,
                "library module {name} must not redirect its source"
            );
        }
        assert_eq!(
            declared_library
                .iter()
                .filter(|(name, _)| SCANNED_LIBRARY.contains(&name.as_str()))
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["glob", "private_file"],
            "only non-service library modules are scanned as frontend code"
        );

        let sources = BTreeMap::new();
        let mut violations = Vec::new();
        audit_covered_modules(
            include_str!("completion.rs"),
            &sources,
            "completion.rs",
            false,
            false,
            &mut violations,
        );
        audit_covered_modules(
            include_str!("tui.rs"),
            &sources,
            "tui.rs",
            false,
            false,
            &mut violations,
        );
        assert_eq!(violations, Vec::<String>::new());
        for module in SCANNED_LIBRARY {
            let source = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src")
                    .join(format!("{module}.rs")),
            )
            .expect("scanned library module source");
            assert_eq!(
                cli_boundary_violations(production_cli_source(&source)),
                Vec::<String>::new(),
                "scanned library frontend module {module} must respect the service boundary"
            );
            audit_covered_modules(
                &source,
                &sources,
                &format!("{module}.rs"),
                false,
                false,
                &mut violations,
            );
        }
        assert_eq!(violations, Vec::<String>::new());

        assert_eq!(
            external_modules("#[path = \"unscanned.rs\"] mod completion;"),
            [("completion".to_owned(), true)]
        );
        let mutated_library = "mod automation; mod glob; mod interchange; mod private_file; mod service; mod unchecked;";
        let declared_mutated_library = external_modules(mutated_library);
        assert!(
            declared_mutated_library
                .iter()
                .any(|(name, _)| !library_accounted_for.contains(&name.as_str())),
            "adding an unaccounted module to lib.rs must fail the audit"
        );
        let redirected_main = "#[path = \"unscanned.rs\"] mod completion;";
        let mut violations = Vec::new();
        audit_covered_modules(
            redirected_main,
            &sources,
            "main.rs",
            true,
            false,
            &mut violations,
        );
        assert_eq!(
            violations.len(),
            1,
            "main path redirection must be rejected"
        );

        for redirected in [
            "#[path = \"alternate.rs\"] mod service;",
            "#[cfg_attr(feature = \"alternate\", path = \"alternate.rs\")] mod interchange;",
        ] {
            let mut violations = Vec::new();
            audit_covered_modules(
                redirected,
                &sources,
                "main.rs",
                true,
                false,
                &mut violations,
            );
            assert_eq!(
                violations.len(),
                1,
                "redirect must be rejected: {redirected}"
            );
        }

        let nested_root = "mod completion;";
        let mut nested_sources = BTreeMap::new();
        nested_sources.insert("completion.rs".to_owned(), "mod omitted;".to_owned());
        let mut violations = Vec::new();
        audit_covered_modules(
            nested_root,
            &nested_sources,
            "main.rs",
            true,
            false,
            &mut violations,
        );
        assert_eq!(
            violations.len(),
            1,
            "nested external modules cannot escape the audit"
        );
        nested_sources.insert(
            "completion/omitted.rs".to_owned(),
            "fn covered() {}".to_owned(),
        );
        let mut violations = Vec::new();
        audit_covered_modules(
            nested_root,
            &nested_sources,
            "main.rs",
            true,
            false,
            &mut violations,
        );
        assert_eq!(
            violations,
            Vec::<String>::new(),
            "nested module source is recursively audited"
        );

        let mut violations = Vec::new();
        audit_covered_modules(
            "mod inline { mod external; }",
            &BTreeMap::new(),
            "main.rs",
            true,
            false,
            &mut violations,
        );
        assert_eq!(
            violations.len(),
            1,
            "external modules nested in inline modules require explicit mapping"
        );
    }

    #[test]
    fn a_direct_model_read_in_a_non_service_cli_module_is_rejected() {
        let cli_module = "mod completion { fn bypass(entry: Entry) { let _ = entry.password; } }";
        assert!(
            cli_boundary_violations(cli_module)
                .iter()
                .any(|violation| violation.contains("direct model field access .password")),
            "a CLI module cannot bypass the service boundary"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "boundary bypass fixtures remain grouped as one auditable regression set"
    )]
    fn production_boundary_checker_rejects_reveal_text_and_model_mutation_fixtures() {
        for (fixture, expected_violation) in [
            (
                "use neotales_keepass::Entry as Record; fn bypass(value: Record) {}",
                "aliased or direct KeePass model import",
            ),
            (
                "use neotales_keepass as safe_macros; fn bypass() { safe_macros::assert!(true); }",
                "aliased or direct KeePass model import",
            ),
            (
                "use attacker::assert; fn bypass() { assert!(true); }",
                "macro import shadows a reviewed safe macro name",
            ),
            (
                "use attacker::not_assert as assert; fn bypass() { assert!(true); }",
                "macro import shadows a reviewed safe macro name",
            ),
            (
                "fn bypass(value: &str) { value.reveal_text(); }",
                "direct reveal method .reveal_text",
            ),
            (
                "fn bypass<'a>(db: &'a Any) { let _ = db.root; let _valid_char = 'x'; }",
                "direct model field access .root",
            ),
            (
                "fn bypass(value: &str) { value . reveal_bytes ( ); }",
                "direct reveal method .reveal_bytes",
            ),
            (
                "fn bypass(value: &str) { value.reveal(); }",
                "direct reveal method .reveal",
            ),
            (
                "fn bypass(value: &str) { ProtectedValue :: reveal_text(value); }",
                "ProtectedValue::reveal_text",
            ),
            (
                "fn bypass(entry: &Any, value: Value) { entry.password = value; }",
                "direct model field access .password",
            ),
            (
                "fn bypass(db: &Any) { db.root.entries[0].attachments.push(item); }",
                "direct model field access .root",
            ),
            (
                "fn bypass(db: &Any) { let _ = db . binary_pool . get(0); }",
                "direct model field access .binary_pool",
            ),
            (
                "fn bypass(entry: &Any) { entry.fields[0].value = replacement; }",
                "direct model field access .fields",
            ),
            (
                "fn bypass(opts: &Any) { let _ = opts.root; }",
                "direct model field access .root",
            ),
            (
                "fn bypass(report: &Any) { let _ = report.password; }",
                "direct model field access .password",
            ),
            (
                "fn bypass(entry: &Any) { entry.set_field(key, value); }",
                "direct model mutation method .set_field",
            ),
            (
                "macro_rules! read { ($r:expr, $f:ident) => { $r.$f }; } fn bypass(entry: &Any) { read!(entry, password); }",
                "user-defined macro can synthesize production code",
            ),
            (
                "fn bypass(entry: &Any) { read!(entry, password); }",
                "unreviewed macro invocation read!",
            ),
            (
                "fn bypass(entry: &Any) { let _ = entry.r#password; }",
                "direct model field access .password",
            ),
            (
                "fn bypass(value: &str) { value.r#reveal_text(); }",
                "direct reveal method .reveal_text",
            ),
            (
                "fn bypass(uri: OtpUri) { Totp::generate(uri); }",
                "direct KeePass model/OTP type OtpUri",
            ),
            (
                "fn bypass(uri: OtpSecret) { TotpParameters::parse(uri); }",
                "direct KeePass model/OTP type OtpSecret",
            ),
            (
                "fn bypass(file: File) { KdbxFile :: load(file); }",
                "direct KdbxFile::load",
            ),
            (
                "fn bypass(file: File) { KdbxFile::save(file); }",
                "direct KdbxFile::save",
            ),
        ] {
            let violations = cli_boundary_violations(fixture);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected_violation)),
                "checker accepted bypass fixture: {fixture}"
            );
        }
    }

    #[test]
    fn production_boundary_checker_rejects_unreviewed_macros_attributes_and_derives() {
        for (fixture, expected_violation) in [
            (
                "fn bypass() { untrusted::assert!(true); }",
                "unreviewed macro invocation untrusted::assert!",
            ),
            (
                "fn bypass() { ::assert!(true); }",
                "unreviewed macro invocation ::assert!",
            ),
            (
                "macro_rules! define_nushell_completion { () => {} }",
                "user-defined macro can synthesize production code",
            ),
            (
                "#[untrusted::generate] fn bypass() {}",
                "unreviewed CLI attribute untrusted",
            ),
            (
                "#[generate] fn bypass() {}",
                "unreviewed CLI attribute generate",
            ),
            (
                "#[derive(Unreviewed)] struct Bypass;",
                "unreviewed CLI derive Unreviewed",
            ),
            (
                "#[derive(untrusted::Reviewed)] struct Bypass;",
                "unreviewed CLI derive Reviewed",
            ),
        ] {
            let violations = cli_boundary_violations(fixture);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected_violation)),
                "checker accepted bypass fixture: {fixture}"
            );
        }

        // Interchange is a trusted model adapter, not CLI frontend code, but
        // its macro policy is still enforced on the actual production source.
        // Exercise both declaration and invocation detection against that
        // source, while preserving the explicitly reviewed serde_json macro.
        let interchange = production_cli_source(include_str!("interchange.rs"));
        for suffix in [
            "macro_rules! surprise { () => {} }",
            "fn injected() { surprise!(); }",
        ] {
            let source = format!("{interchange}\n{suffix}");
            assert!(
                cli_boundary_violations(&source)
                    .iter()
                    .any(|violation| { is_macro_policy_violation(violation) }),
                "interchange production source accepted unreviewed macro fixture: {suffix}"
            );
        }
        assert_eq!(
            cli_boundary_violations("fn reviewed() { let _ = serde_json::json!({\"ok\": true}); }")
                .into_iter()
                .filter(|violation| is_macro_policy_violation(violation))
                .collect::<Vec<_>>(),
            Vec::<String>::new(),
            "the exact serde_json::json! macro path is explicitly reviewed"
        );
    }

    #[test]
    fn production_boundary_checker_rejects_sensitive_field_reads_and_mutations() {
        for (fixture, expected_violation) in [
            (
                "fn bypass(field: Field) { field.protected = false; }",
                "direct model field access .protected",
            ),
            (
                "fn bypass(field: Field) { let _ = field.key; }",
                "direct model field access .key",
            ),
            (
                "fn bypass(field: Field) { let _ = field.value; }",
                "direct model field access .value",
            ),
            (
                "fn bypass(entry: Entry) { let _ = entry.auto_type.default_sequence; }",
                "direct model field access .default_sequence",
            ),
            (
                "fn bypass(pool: BinaryPool) { pool.add(bytes, false); }",
                "direct model mutation method .add",
            ),
            (
                "fn bypass(field: Field) { field.key = replacement; }",
                "direct model field access .key",
            ),
        ] {
            let violations = cli_boundary_violations(fixture);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected_violation)),
                "checker accepted sensitive field fixture: {fixture}"
            );
        }
    }

    #[test]
    fn production_boundary_checker_allows_service_calls_and_test_fixtures() {
        let source = r#"
            fn cli(service: &VaultService, opts: &Options, report: &ImportReport) {
                let _ = service.reveal_field(&entry);
                let _ = service.reveal_native_field(&entry, "Password");
                let _ = service.reveal_attachment(&attachment);
                let _ = service.reveal_password(&entry);
                let _ = service.set_field(&entry, "Password", "value");
                let _ = service.save(path, credentials);
                let _ = opts.password;
                let _ = opts.key;
                let _ = opts.name;
                let _ = report.groups;
                let _ = report.fields;
                let _ = report.entries;
                let _ = report.attachments;
                let update = FieldUpdate { key, value, protected, protect_in_memory };
                let _ = update.key;
                let _ = update.value;
                let _ = update.protected;
                let _ = update.protect_in_memory;
                let binding = Binding { key, name };
                let _ = binding.key;
                let _ = binding.name;
                let _ = selected.fields();
                let _ = selected.attachments();
            }
            // A comment must not act like code: value.reveal_text();
            const HELP: &str = "db.root.entries[0].attachments.push(item)";
        "#;
        assert_eq!(cli_boundary_violations(source), Vec::<String>::new());

        let with_test_fixture = format!(
            "{source}\n#[cfg(test)]\nmod tests {{ KdbxFile::load(file, credentials, limits); }}"
        );
        assert_eq!(
            cli_boundary_violations(production_cli_source(&with_test_fixture)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn production_boundary_test_module_detection_ignores_comments_and_literals() {
        for decoy in [
            "// #[cfg(test)]\n// mod tests {",
            "/* #[cfg(test)]\nmod tests { */",
            "const DECOY: &str = \"#[cfg(test)]\\nmod tests {\";",
            "const DECOY: &str = r\"#[cfg(test)]\nmod tests {\";",
        ] {
            let source = format!(
                "{decoy}\nfn bypass(entry: &Any) {{ let _ = entry.password; }}\n#[cfg(test)]\nmod tests {{}}"
            );
            assert!(
                cli_boundary_violations(production_cli_source(&source))
                    .iter()
                    .any(|violation| violation.contains("direct model field access .password")),
                "a lexical decoy must not truncate production code: {decoy}"
            );
        }

        let suffix = "fn before() {}\n#[cfg(test)]\nmod tests { fn fixture() {} }\nfn bypass(entry: &Any) { let _ = entry.password; }";
        assert!(
            cli_boundary_violations(production_cli_source(suffix))
                .iter()
                .any(|violation| violation.contains("direct model field access .password")),
            "production code after the test module must stay in the scan"
        );
    }

    #[test]
    fn unsupported_operations_are_rejected_before_vault_or_credentials() {
        assert_eq!(
            operation("unsupported", &[], None, &Config::default())
                .unwrap_err()
                .0,
            "unknown operation"
        );
    }

    #[test]
    fn accepts_explicit_scripting_password() {
        let args = ["--password".to_owned(), "scripting-password".to_owned()];
        let opts = options(&args, Positional::Forbidden).unwrap();
        assert_eq!(opts.password, Some("scripting-password"));
        assert_eq!(
            password(&opts).unwrap().unwrap().as_str(),
            "scripting-password"
        );
    }

    #[test]
    fn rejects_duplicate_password_sources() {
        let duplicate = [
            "--password".to_owned(),
            "first".to_owned(),
            "--password".to_owned(),
            "second".to_owned(),
        ];
        assert_eq!(
            options(&duplicate, Positional::Forbidden).err().unwrap().0,
            "invalid or duplicate option"
        );

        let mixed = [
            "--password".to_owned(),
            "first".to_owned(),
            "--password-stdin".to_owned(),
        ];
        assert_eq!(
            options(&mixed, Positional::Forbidden).err().unwrap().0,
            "select exactly one credential source"
        );
    }

    #[test]
    fn rejects_password_and_value_on_the_same_stdin_contract() {
        let args = ["--password-stdin".to_owned(), "--stdin".to_owned()];
        let Err(error) = options(&args, Positional::Forbidden) else {
            panic!("conflicting stdin roles were accepted");
        };
        assert_eq!(error.0, "stdin cannot carry both password and value");
    }

    #[test]
    fn generated_passwords_reject_partial_byte_range() {
        assert_eq!(password_index(0), Some(0));
        assert_eq!(password_index(247), Some(61));
        assert_eq!(password_index(248), None);
        assert_eq!(password_index(255), None);
    }

    #[test]
    fn rejects_escaping_aliases() {
        assert!(entry_path("../secret").is_err());
        assert!(entry_path("a//b").is_err());
        // Built from the platform's temporary directory so the path really is
        // absolute here, and the refusal is for the `..` rather than for being
        // relative. A literal `/tmp/../secret.kdbx` is refused on Windows too, but
        // for the wrong reason -- it is not absolute there either -- so the
        // assertion held even if the parent-directory check were deleted.
        let escaping = std::env::temp_dir().join("..").join("secret.kdbx");
        let escaping = escaping.to_str().unwrap();
        assert_eq!(
            vault_path(escaping).unwrap_err().0,
            "vault path must be absolute and normalized",
            "{escaping:?} should be refused for its parent-directory component"
        );
        assert!(!valid_name("a\nsecret"));
    }
}
