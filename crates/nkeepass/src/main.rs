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
    reason = "also supplies the CLI's interchange format constants"
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
    examples: &'static [&'static str],
    help_notes: &'static [&'static str],
    options: &'static [HelpOption],
    children: &'static [HelpCommand],
}

const NO_EXAMPLES: &[&str] = &[];
const NO_NOTES: &[&str] = &[];

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
        examples: NO_EXAMPLES,
        help_notes: NO_NOTES,
        options,
        children,
    }
}

const fn help_command_with(
    names: &'static str,
    usage: &'static str,
    summary: &'static str,
    examples: &'static [&'static str],
    help_notes: &'static [&'static str],
    options: &'static [HelpOption],
    children: &'static [HelpCommand],
) -> HelpCommand {
    HelpCommand {
        names,
        usage,
        summary,
        examples,
        help_notes,
        options,
        children,
    }
}

const ROOT_EXAMPLES: &[&str] = &[
    "use work",
    "ls",
    "show mail",
    "get mail --clipboard",
    "x -B TOKEN=mail -- env",
    "inject .env.tmpl -o .env.resolved",
    "shell init bash",
];

const GLOBAL_VAULT_OPTION: HelpOption = HelpOption {
    label: "-V, --vault PATH",
    summary: "Select a vault path or configured alias before the command.",
};
const GLOBAL_COLOR_OPTION: HelpOption = HelpOption {
    label: "--color MODE, --no-color",
    summary: "Style human help, --format human, and diagnostics: auto, always, never, basic, or truecolor.",
};
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
const DEFAULT_PASSWORD_ENV: &str = "NEO_KEEPASS_PASSWORD";

/// Reads a supported application environment variable using canonical-name
/// precedence: `NEO_KEEPASS_*`, then `NKP_*`.
fn app_env_var_os(name: &str) -> Option<std::ffi::OsString> {
    let suffix = name.strip_prefix("NEO_KEEPASS_")?;
    env::var_os(name).or_else(|| env::var_os(format!("NKP_{suffix}")))
}
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
const ENTRY_KEY_OPTION: HelpOption = HelpOption {
    label: "-k, --key PATH",
    summary: "Select an entry by path or alias (alternative to positional PATH).",
};
const ENTRY_ONLY_KEY_OPTION: HelpOption = HelpOption {
    label: "-k, --key ENTRY",
    summary: "Select an entry by path or alias (alternative to positional ENTRY).",
};
const OTP_KEY_OPTION: HelpOption = HelpOption {
    label: "-k, --key PATH",
    summary: "Select a TOTP entry by path or alias (alternative to positional PATH).",
};
const ENTRY_FIELD_OPTION: HelpOption = HelpOption {
    label: "-F, --field FIELD",
    summary: "Select a field (defaults to Password or the entry alias's bound field).",
};
const MANY_FIELD_OPTION: HelpOption = HelpOption {
    label: "-F, --field FIELD",
    summary: "Select one common field for all requested paths (defaults to Password).",
};
const CUSTOM_FIELD_OPTION: HelpOption = HelpOption {
    label: "-F, --field FIELD",
    summary: "Select a custom field (alternative to positional FIELD; built-in fields refused).",
};
const FILE_OPTION: HelpOption = HelpOption {
    label: "-f, --file PATH",
    summary: "Read input from a file.",
};
const BIN_OPTION: HelpOption = HelpOption {
    label: "-b, --bin NAME=FILE_PATH",
    summary: "Add an attachment; repeat for multiple files.",
};
const STDIN_OPTION: HelpOption = HelpOption {
    label: "--stdin",
    summary: "Read input from stdin.",
};
const REPORT_DRY_RUN_OPTION: HelpOption = HelpOption {
    label: "--dry-run",
    summary: "Validate and emit report without saving changes.",
};
const SILENT_DRY_RUN_OPTION: HelpOption = HelpOption {
    label: "--dry-run",
    summary: "Validate without modifying or saving the vault; produces no output.",
};
const VALUE_FORMAT_OPTION: HelpOption = HelpOption {
    label: "--format FORMAT",
    summary: "Choose text (default), json, null, dotenv, shell, pwsh, powershell, github-actions, or azure-devops.",
};
const ENV_FORMAT_OPTION: HelpOption = HelpOption {
    label: "--format FORMAT",
    summary: "Choose shell (default), dotenv, pwsh, powershell, github-actions, azure-devops, json, or null.",
};
const METADATA_FORMAT_OPTION: HelpOption = HelpOption {
    label: "--format json|human",
    summary: "Choose JSON (default) or bounded human-readable output.",
};
const IS_OUTPUT_OPTION: HelpOption = HelpOption {
    label: "--is-output",
    summary: "Mark Azure DevOps output as an output variable.",
};
const NAME_OPTION: HelpOption = HelpOption {
    label: "-n, --name NAME",
    summary: "Name the output variable for a named format.",
};
const YES_OPTION: HelpOption = HelpOption {
    label: "-y, --yes",
    summary: "Confirm a destructive operation without prompting.",
};

const CONTEXT_LS_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--json",
    summary: "Emit one {\"alias\",\"path\"} JSON record per vault alias; omits unaliased paths.",
}];
const CONTEXT_SHOW_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--json",
    summary: "Emit {\"path\",\"source\",\"alias\"} JSON (alias is populated only for context source).",
}];
const CONTEXT_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls [--json]",
        "List configured vault aliases and paths.",
        &["context ls", "context ls --json"],
        &[
            "JSON output emits configured vault aliases only; human text also lists unaliased current and default paths.",
        ],
        CONTEXT_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "show",
        "show [--json]",
        "Show the selected vault and its source.",
        &["context show"],
        NO_NOTES,
        CONTEXT_SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "use",
        "use <ALIAS|PATH>",
        "Select a configured vault alias or normalized absolute vault path.",
        &["context use work", "context use \"$HOME/vaults/work.kdbx\""],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm ALIAS",
        "Remove a vault alias.",
        &["context rm work"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "set",
        "set ALIAS PATH",
        "Create or update a vault alias and its normalized absolute path.",
        &["context set work \"$HOME/vaults/work.kdbx\""],
        NO_NOTES,
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
        label: "-F, --field FIELD",
        summary: "Bind an entry alias to a default field.",
    },
];
const ALIAS_LS_OPTIONS: &[HelpOption] = &[METADATA_FORMAT_OPTION];
const ALIAS_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls [--format json|human]",
        "List configured aliases as JSON lines or bounded human columns.",
        &["alias ls", "alias ls --format human"],
        NO_NOTES,
        ALIAS_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "set",
        "set NAME TARGET [OPTIONS]",
        "Create or replace a validated vault or entry alias.",
        &[
            "alias set mail Services/mail",
            "alias set work \"$HOME/vaults/work.kdbx\"",
        ],
        NO_NOTES,
        ALIAS_SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm NAME",
        "Remove an alias.",
        &["alias rm mail"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "resolve",
        "resolve NAME",
        "Show the target of an alias as JSON.",
        &["alias resolve mail"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
];
const CONFIG_LS_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--json",
    summary: "Emit one JSON record per configuration key.",
}];
const CONFIG_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls [GLOB] [--json]",
        "List the closed configuration key set.",
        &["config ls", "config ls --json"],
        NO_NOTES,
        CONFIG_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "get|show",
        "get KEY",
        "Print one configured value.",
        &["config get current"],
        &["Valid KEY values: aliases, current, default_vault."],
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "set",
        "set KEY VALUE",
        "Set a supported scalar configuration key (current or default_vault).",
        &["config set default_vault work"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm KEY",
        "Clear a configured scalar key (current or default_vault).",
        &["config rm current"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
];
const COMMON_LIST_OPTIONS: &[HelpOption] = &[METADATA_FORMAT_OPTION];
const SEARCH_OPTIONS: &[HelpOption] = &[METADATA_FORMAT_OPTION];
const SHOW_OPTIONS: &[HelpOption] = &[ENTRY_KEY_OPTION, METADATA_FORMAT_OPTION];
const GET_OPTIONS: &[HelpOption] = &[
    ENTRY_KEY_OPTION,
    ENTRY_FIELD_OPTION,
    VALUE_FORMAT_OPTION,
    NAME_OPTION,
    HelpOption {
        label: "--clipboard",
        summary: "Copy the selected value instead of writing it to stdout.",
    },
    IS_OUTPUT_OPTION,
    HelpOption {
        label: "--age-encrypt",
        summary: "Encrypt the selected value to one or more age recipients.",
    },
    HelpOption {
        label: "-r, --age-recipient KEY",
        summary: "Age/SSH key, @FILE, gh:USER, or HTTPS source; repeatable.",
    },
    HelpOption {
        label: "-o, --output PATH",
        summary: "Write encrypted output to a private, no-clobber file (requires --age-encrypt).",
    },
];
const GET_MANY_OPTIONS: &[HelpOption] = &[
    MANY_FIELD_OPTION,
    VALUE_FORMAT_OPTION,
    HelpOption {
        label: "--age-encrypt",
        summary: "Encrypt the complete rendered bundle once.",
    },
    HelpOption {
        label: "-r, --age-recipient KEY",
        summary: "Age/SSH key, @FILE, gh:USER, or HTTPS source; repeatable.",
    },
    HelpOption {
        label: "-o, --output PATH",
        summary: "Write encrypted output to a private, no-clobber file (requires --age-encrypt).",
    },
    IS_OUTPUT_OPTION,
];
const GET_MANY_COMMANDS: &[HelpCommand] = &[help_command_with(
    "many",
    "many PATH... [OPTIONS]",
    "Bundle selected fields in supplied path order; default field Password.",
    &["get many mail backup --format json"],
    &[
        "Path keys: JSON uses literal paths; named formats require identifier-style paths or aliases.",
    ],
    GET_MANY_OPTIONS,
    NO_COMMANDS,
)];
const SET_OPTIONS: &[HelpOption] = &[
    ENTRY_KEY_OPTION,
    HelpOption {
        label: "-F, --field NAME=VALUE",
        summary: "Repeatable assignments; -F/--field NAME selects a value-source target (default Password).",
    },
    HelpOption {
        label: "--value VALUE",
        summary: "Set the selected field from argv (visible in process listings).",
    },
    HelpOption {
        label: "--value-stdin",
        summary: "Read the selected value from stdin; alias for --stdin.",
    },
    HelpOption {
        label: "--value-env NAME",
        summary: "Read the selected value from this environment variable.",
    },
    HelpOption {
        label: "--value-file PATH",
        summary: "Read a bounded UTF-8 value file; alias for --file.",
    },
    HelpOption {
        label: "--generate",
        summary: "Generate the selected field instead of reading a value.",
    },
    HelpOption {
        label: "-c, --chars N, --size N",
        summary: "Generated length 1..=4096 (default 16); requires --generate.",
    },
    HelpOption {
        label: "-U, --upper",
        summary: "Select uppercase ASCII letters for generation.",
    },
    HelpOption {
        label: "-L, --lower",
        summary: "Select lowercase ASCII letters for generation.",
    },
    HelpOption {
        label: "-D, --digits",
        summary: "Select ASCII digits for generation.",
    },
    HelpOption {
        label: "-S, --symbols",
        summary: "Select ASCII punctuation for generation.",
    },
    HelpOption {
        label: "--username VALUE",
        summary: "Set the UserName field from an argument.",
    },
    HelpOption {
        label: "--url VALUE",
        summary: "Set the URL field from an argument.",
    },
    HelpOption {
        label: "--notes VALUE",
        summary: "Set the Notes field from an argument.",
    },
    FILE_OPTION,
    STDIN_OPTION,
    BIN_OPTION,
    HelpOption {
        label: "--age-decrypt",
        summary: "Decrypt age-encrypted input before setting the field.",
    },
    HelpOption {
        label: "-i, --age-identity PATH",
        summary: "Explicit identity wins; otherwise discover init-password.agekey or age/keys.txt.",
    },
];
const ENTRY_RM_OPTIONS: &[HelpOption] = &[ENTRY_KEY_OPTION, YES_OPTION];
const ENSURE_OPTIONS: &[HelpOption] = &[
    ENTRY_KEY_OPTION,
    HelpOption {
        label: "-c, --chars N, --size N",
        summary: "Generated length 1..=4096 for new entries only (default 16).",
    },
    HelpOption {
        label: "-U, --upper",
        summary: "Select uppercase ASCII letters.",
    },
    HelpOption {
        label: "-L, --lower",
        summary: "Select lowercase ASCII letters.",
    },
    HelpOption {
        label: "-D, --digits",
        summary: "Select ASCII digits.",
    },
    HelpOption {
        label: "-S, --symbols",
        summary: "Select ASCII punctuation.",
    },
    SILENT_DRY_RUN_OPTION,
];
const OTP_OPTIONS: &[HelpOption] = &[
    OTP_KEY_OPTION,
    VALUE_FORMAT_OPTION,
    NAME_OPTION,
    IS_OUTPUT_OPTION,
];
const IMPORT_OPTIONS: &[HelpOption] = &[
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "--replace",
        summary: "Allow replacing a non-empty vault.",
    },
    REPORT_DRY_RUN_OPTION,
    HelpOption {
        label: "--format json|keepass-xml",
        summary: "Import JSON snapshot (default) or KeePass XML.",
    },
];
const EXPORT_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "-o, --output PATH",
        summary: "Write the interchange snapshot to this private, no-clobber output file.",
    },
    HelpOption {
        label: "--format json|keepass-xml",
        summary: "Export JSON snapshot (default) or KeePass XML.",
    },
    HelpOption {
        label: "--allow-plaintext",
        summary: "Acknowledge that KeePass XML is unencrypted plaintext.",
    },
];
const SYNC_OPTIONS: &[HelpOption] = &[
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "--strategy newest|source|target",
        summary: "Choose conflict strategy: newest (default), source, or target.",
    },
    REPORT_DRY_RUN_OPTION,
];
const ENV_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "-k, --key PATH",
        summary: "Start a value binding (repeatable).",
    },
    HelpOption {
        label: "-F, --field FIELD",
        summary: "Select the field for the current binding (required unless alias binds a field); otp emits a code.",
    },
    HelpOption {
        label: "-n, --name NAME",
        summary: "Finish a binding with its output variable name.",
    },
    ENV_FORMAT_OPTION,
    IS_OUTPUT_OPTION,
];
const ATTACHMENT_NAME_OPTION: HelpOption = HelpOption {
    label: "-n, --name NAME",
    summary: "Select the attachment name (alternative to positional NAME or -F/--field).",
};
const ATTACHMENT_FIELD_OPTION: HelpOption = HelpOption {
    label: "-F, --field NAME",
    summary: "Compatibility alias for --name; selects the attachment name (no default).",
};
const ATTACHMENT_LS_OPTIONS: &[HelpOption] = &[ENTRY_ONLY_KEY_OPTION, METADATA_FORMAT_OPTION];
const ATTACHMENT_ADD_OPTIONS: &[HelpOption] = &[
    ENTRY_ONLY_KEY_OPTION,
    ATTACHMENT_NAME_OPTION,
    ATTACHMENT_FIELD_OPTION,
    HelpOption {
        label: "-f, --file PATH",
        summary: "Read attachment bytes from a file.",
    },
    HelpOption {
        label: "--stdin",
        summary: "Read attachment bytes from stdin.",
    },
];
const ATTACHMENT_GET_OPTIONS: &[HelpOption] = &[
    ENTRY_ONLY_KEY_OPTION,
    ATTACHMENT_NAME_OPTION,
    ATTACHMENT_FIELD_OPTION,
    HelpOption {
        label: "-o, --output PATH",
        summary: "Private output destination; existing files are not overwritten.",
    },
];
const ATTACHMENT_RM_OPTIONS: &[HelpOption] = &[
    ENTRY_ONLY_KEY_OPTION,
    ATTACHMENT_NAME_OPTION,
    ATTACHMENT_FIELD_OPTION,
    YES_OPTION,
];
const FIELD_LS_OPTIONS: &[HelpOption] = &[ENTRY_ONLY_KEY_OPTION, METADATA_FORMAT_OPTION];
const FIELD_GET_OPTIONS: &[HelpOption] = &[
    ENTRY_ONLY_KEY_OPTION,
    CUSTOM_FIELD_OPTION,
    VALUE_FORMAT_OPTION,
    NAME_OPTION,
    IS_OUTPUT_OPTION,
];
const FIELD_SET_OPTIONS: &[HelpOption] = &[
    ENTRY_ONLY_KEY_OPTION,
    CUSTOM_FIELD_OPTION,
    HelpOption {
        label: "-f, --file PATH",
        summary: "Read the bounded UTF-8 field value from a file.",
    },
    HelpOption {
        label: "--stdin",
        summary: "Read the UTF-8 field value from stdin.",
    },
];
const FIELD_RM_OPTIONS: &[HelpOption] = &[ENTRY_ONLY_KEY_OPTION, CUSTOM_FIELD_OPTION, YES_OPTION];
const SECRETS_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls [--] [GLOB] [--format json|human]",
        "List redacted entry metadata as JSON lines or bounded human columns.",
        &["ls", "ls 'Services/*'", "ls --format human"],
        NO_NOTES,
        COMMON_LIST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "search",
        "search [--] QUERY [--format json|human]",
        "Search bounded, allowlisted entry metadata.",
        &["search mail", "search mail --format human"],
        NO_NOTES,
        SEARCH_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "env|environment",
        "env (-k PATH [-F FIELD] -n NAME)... [OPTIONS]",
        "Emit selected values in a named format.",
        &["env -k mail -F UserName -n MAIL_USER"],
        NO_NOTES,
        ENV_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "show",
        "show PATH [--format json|human]",
        "Show redacted descriptors for one entry.",
        &["show mail", "show mail --format human"],
        NO_NOTES,
        SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "get",
        "get [PATH] [OPTIONS]",
        "Reveal one explicitly selected value.",
        &["get mail", "get mail --clipboard"],
        NO_NOTES,
        GET_OPTIONS,
        GET_MANY_COMMANDS,
    ),
    help_command_with(
        "set",
        "set [PATH] [OPTIONS]",
        "Set an entry field from explicit input.",
        &["set mail", "set mail -F UserName=alice"],
        &[
            "With no update supplied, prompts without echo for up to 60 seconds; redirected stdin is refused.",
        ],
        SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm (PATH | -k PATH | --key PATH) (-y | --yes)",
        "Remove an entry.",
        &["rm mail -y"],
        NO_NOTES,
        ENTRY_RM_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "ensure",
        "ensure PATH [OPTIONS]",
        "Create a missing entry and its parent groups; keep existing entries.",
        &["ensure Demo/mail"],
        &[
            "Character policy: no class flags uses all four; selected classes only, each is guaranteed.",
        ],
        ENSURE_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "otp",
        "otp PATH [OPTIONS]",
        "Generate a TOTP code; never disclose the seed. HOTP is refused.",
        &["otp mail"],
        NO_NOTES,
        OTP_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "import",
        "import (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Import a bounded interchange snapshot.",
        &["import snapshot.json --dry-run"],
        NO_NOTES,
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "export",
        "export (DEST | -o DEST | --output DEST) [OPTIONS]",
        "Write a private interchange snapshot.",
        &["export snapshot.json"],
        NO_NOTES,
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "sync",
        "sync (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Synchronize a bounded interchange snapshot.",
        &["sync snapshot.json --strategy newest --dry-run"],
        NO_NOTES,
        SYNC_OPTIONS,
        NO_COMMANDS,
    ),
];
const AUTOMATION_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "import",
        "import (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Import a bounded interchange snapshot.",
        &["automation import snapshot.json --dry-run"],
        NO_NOTES,
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "export",
        "export (DEST | -o DEST | --output DEST) [OPTIONS]",
        "Write a private interchange snapshot.",
        &["automation export snapshot.json"],
        NO_NOTES,
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "sync",
        "sync (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Synchronize a bounded interchange snapshot.",
        &["automation sync snapshot.json --strategy newest --dry-run"],
        NO_NOTES,
        SYNC_OPTIONS,
        NO_COMMANDS,
    ),
];
const ATTACHMENT_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls (ENTRY | --key ENTRY) [--format json|human]",
        "List attachment metadata for one entry.",
        &["files ls mail", "files ls mail --format human"],
        NO_NOTES,
        ATTACHMENT_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "add|import",
        "add (ENTRY | --key ENTRY) (NAME | --name NAME | --field NAME) (-f PATH | --file PATH | --stdin)",
        "Add an attachment from explicit input.",
        &["files add mail note.txt -f ./note.txt"],
        NO_NOTES,
        ATTACHMENT_ADD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "get|export",
        "get (ENTRY | --key ENTRY) (NAME | --name NAME | --field NAME) (-o PATH | --output PATH)",
        "Write one attachment to a private, no-clobber output file.",
        &["files get mail note.txt -o ./note.txt"],
        NO_NOTES,
        ATTACHMENT_GET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm (ENTRY | --key ENTRY) (NAME | --name NAME | --field NAME) (-y | --yes)",
        "Remove one attachment.",
        &["files rm mail note.txt -y"],
        NO_NOTES,
        ATTACHMENT_RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const FIELD_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls (ENTRY | --key ENTRY) [--format json|human]",
        "List field names present on one entry.",
        &["field ls mail", "field ls mail --format human"],
        NO_NOTES,
        FIELD_LS_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "get|reveal",
        "get (ENTRY | --key ENTRY) (FIELD | --field FIELD) [OPTIONS]",
        "Reveal one custom field.",
        &["field get mail ApiKey"],
        NO_NOTES,
        FIELD_GET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "set|edit",
        "set (ENTRY | --key ENTRY) (FIELD | --field FIELD) (-f PATH | --file PATH | --stdin)",
        "Set one custom field from a file or stdin.",
        &["field set mail ApiKey -f ./value.txt"],
        NO_NOTES,
        FIELD_SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm (ENTRY | --key ENTRY) (FIELD | --field FIELD) (-y | --yes)",
        "Remove one custom field.",
        &["field rm mail ApiKey -y"],
        NO_NOTES,
        FIELD_RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const INIT_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--json",
        summary: "Print a machine-readable result instead of text.",
    },
    HelpOption {
        label: "--generate-master-password",
        summary: "Generate a random master password; recover it from the encrypted backup and age identity.",
    },
    HelpOption {
        label: "--size N",
        summary: "Store a generated N-character password in a new entry.",
    },
    HelpOption {
        label: "--kdf aes|argon2d|argon2id",
        summary: "Choose the key derivation function (default aes).",
    },
    HelpOption {
        label: "--memory KIB",
        summary: "Argon2 memory cost in KiB; requires an Argon2 KDF.",
    },
    HelpOption {
        label: "--iterations N",
        summary: "KDF transform rounds or Argon2 time cost.",
    },
    HelpOption {
        label: "--parallelism N",
        summary: "Argon2 lanes; requires an Argon2 KDF.",
    },
];
const INIT_NOTES: &[&str] = &[
    "Recovery: Privately pipe age --decrypt -i IDENTITY BACKUP to {program} --vault DATABASE secrets ls --password-stdin. Protect the identity; see the vault reference.",
    "Password persistence: Password-only master passwords are saved age-encrypted in the data directory; identity is in config.",
    "Crash recovery: Directory ancestry durability is unconfirmed; keep independent protected copies of the identity and encrypted backup.",
    "Partial failure: Supplied password-only: backup follows successful vault creation; backup failure leaves the vault installed. Generated master: backup and association precede vault creation; their failure stops creation.",
    "Windows private files: Vaults and backups use owner-only ACLs on supported filesystems.",
];
const EXEC_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "-B, --bind NAME=ENTRY",
        summary: "Bind a literal entry's Password into the child environment (repeatable).",
    },
    HelpOption {
        label: "-k, --key PATH",
        summary: "Entry to bind into the child environment (repeatable).",
    },
    HelpOption {
        label: "-F, --field FIELD",
        summary: "Bind this field for the preceding --key; otp emits a code.",
    },
    HelpOption {
        label: "--env NAME",
        summary: "Child variable for the preceding --key (repeatable).",
    },
    HelpOption {
        label: "--env-file FILE",
        summary: "Load KEY=VALUE or nkp:// bindings from a .env file (repeatable).",
    },
];
const NO_COMMANDS: &[HelpCommand] = &[];
const GROUP_KEY_OPTION: HelpOption = HelpOption {
    label: "-k, --key PATH",
    summary: "Select a group path, with or without the root name (alternative to positional PATH).",
};
const GROUP_ADD_OPTIONS: &[HelpOption] = &[GROUP_KEY_OPTION, SILENT_DRY_RUN_OPTION];
const GROUP_RM_OPTIONS: &[HelpOption] = &[GROUP_KEY_OPTION, YES_OPTION, SILENT_DRY_RUN_OPTION];
const GROUP_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "ls|list",
        "ls",
        "List group paths.",
        &["group ls"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "add|create|ensure",
        "add (PATH | --key PATH) [--dry-run]",
        "Create missing groups; keep existing groups.",
        &["group add Services/Prod"],
        NO_NOTES,
        GROUP_ADD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm (PATH | --key PATH) (-y | --yes | --dry-run)",
        "Remove a group and its contents; never remove the root.",
        &["group rm Services/Old -y"],
        NO_NOTES,
        GROUP_RM_OPTIONS,
        NO_COMMANDS,
    ),
];
const INJECT_OPTIONS: &[HelpOption] = &[
    FILE_OPTION,
    STDIN_OPTION,
    HelpOption {
        label: "-o, --output PATH",
        summary: "Write rendered output privately without overwriting an existing file.",
    },
    HelpOption {
        label: "--format raw|dotenv",
        summary: "Render raw text (default) or double-quoted dotenv assignments.",
    },
    HelpOption {
        label: "--check",
        summary: "Validate template and resolve references without emitting secrets.",
    },
];
const TRUST_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--list",
        summary: "List trusted manifest and .env entries.",
    },
    HelpOption {
        label: "--json",
        summary: "Emit NDJSON records when used with --list.",
    },
    HelpOption {
        label: "--prune",
        summary: "Remove trusted entries whose target files no longer exist.",
    },
];
const UNTRUST_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--all",
    summary: "Revoke every entry in the trust store.",
}];
const SHELL_INIT_OPTIONS: &[HelpOption] = &[
    HelpOption {
        label: "--no-completion",
        summary: "Omit static completion generation from init output.",
    },
    HelpOption {
        label: "--no-env",
        summary: "Omit directory hook and wrapper functions from init output.",
    },
];
const SHELL_LOAD_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--shell SHELL",
    summary: "Target shell (bash, zsh, fish, pwsh, powershell, or nushell) outside the shell wrapper.",
}];
const SHELL_UNLOAD_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--shell SHELL",
    summary: "Target shell (bash, zsh, fish, pwsh, powershell, or nushell) outside the shell wrapper.",
}];
const SHELL_STATUS_OPTIONS: &[HelpOption] = &[HelpOption {
    label: "--json",
    summary: "Print non-disclosing JSON status.",
}];
const SHELL_COMMANDS: &[HelpCommand] = &[
    help_command_with(
        "init",
        "init SHELL [--no-completion] [--no-env]",
        "Emit completions and direnv-style hooks for bash, zsh, fish, pwsh, powershell, or nushell.",
        &["shell init bash"],
        &[
            "POSIX sh does not support directory hooks; use `{program} shell completions sh` or `{program} completion sh` for completions.",
        ],
        SHELL_INIT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "completions|completion",
        "completions SHELL",
        "Print static shell completion for bash, sh, zsh, fish, powershell, pwsh, or nushell.",
        &["shell completions bash"],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "load",
        "load [--shell SHELL] [OPTIONS]",
        "Load the current directory's trusted manifest into the shell.",
        &["shell load"],
        NO_NOTES,
        SHELL_LOAD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "unload",
        "unload [--shell SHELL]",
        "Unload active nkp-managed environment variables.",
        &["shell unload"],
        NO_NOTES,
        SHELL_UNLOAD_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "status",
        "status [--json]",
        "Show discovered manifest chain, trust status, and managed variable names.",
        &["shell status", "shell status --json"],
        NO_NOTES,
        SHELL_STATUS_OPTIONS,
        NO_COMMANDS,
    ),
];
const ROOT_COMMANDS: &[HelpCommand] = &[
    // Daily secrets & execution
    help_command_with(
        "list|ls",
        "ls [--] [GLOB] [--format json|human]",
        "Shortcut for secrets ls.",
        &["ls", "ls 'Services/*'", "ls --format human"],
        NO_NOTES,
        COMMON_LIST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "show",
        "show PATH [--format json|human]",
        "Shortcut for secrets show.",
        &["show mail", "show mail --format human"],
        NO_NOTES,
        SHOW_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "get",
        "get [PATH] [OPTIONS]",
        "Shortcut for secrets get.",
        &["get mail", "get mail --clipboard"],
        NO_NOTES,
        GET_OPTIONS,
        GET_MANY_COMMANDS,
    ),
    help_command_with(
        "set",
        "set [PATH] [OPTIONS]",
        "Shortcut for secrets set.",
        &["set mail", "set mail -F UserName=alice"],
        &[
            "With no update supplied, prompts without echo for up to 60 seconds; redirected stdin is refused.",
        ],
        SET_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "ensure",
        "ensure PATH [OPTIONS]",
        "Shortcut for secrets ensure.",
        &["ensure Demo/mail"],
        &[
            "Character policy: no class flags uses all four; selected classes only, each is guaranteed.",
        ],
        ENSURE_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "otp",
        "otp PATH [OPTIONS]",
        "Shortcut for secrets otp.",
        &["otp mail"],
        NO_NOTES,
        OTP_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "rm|remove",
        "rm (PATH | -k PATH | --key PATH) (-y | --yes)",
        "Shortcut for secrets rm.",
        &["rm mail -y"],
        NO_NOTES,
        ENTRY_RM_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "exec|x",
        "exec (-B NAME=ENTRY | -k PATH [-F FIELD] --env NAME | --env-file FILE)... [OPTIONS] -- COMMAND [ARG ...]",
        "Run a child with selected values in its environment.",
        &["x -B TOKEN=mail -- env", "x --env-file .env -- env"],
        NO_NOTES,
        EXEC_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "env",
        "env (-k PATH [-F FIELD] -n NAME)... [OPTIONS]",
        "Emit selected values in a named format.",
        &["env -k mail -F UserName -n MAIL_USER"],
        NO_NOTES,
        ENV_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "search",
        "search [--] QUERY [--format json|human]",
        "Shortcut for secrets search.",
        &["search mail", "search mail --format human"],
        NO_NOTES,
        SEARCH_OPTIONS,
        NO_COMMANDS,
    ),
    // Vaults, shell & browser
    help_command_with(
        "use",
        "use <ALIAS|PATH>",
        "Select a configured vault alias or normalized absolute vault path.",
        &["use work", "use \"$HOME/vaults/work.kdbx\""],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "inject",
        "inject (FILE | -f FILE | --file FILE | --stdin) [-o PATH] [--format raw|dotenv] [--check]",
        "Render templates or .env files with nkp:// secret references.",
        &["inject .env.tmpl -o .env.resolved", "inject .env --check"],
        NO_NOTES,
        INJECT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "trust",
        "trust [PATH] | --list [--json] | --prune",
        "Trust a directory manifest or .env file for shell hooks.",
        &["trust", "trust .env"],
        NO_NOTES,
        TRUST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "untrust",
        "untrust [PATH | --all]",
        "Revoke trust for a manifest, .env file, or all entries.",
        &["untrust", "untrust --all"],
        NO_NOTES,
        UNTRUST_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "shell",
        "shell <COMMAND>",
        "Configure shell hooks, completions, and environment loading.",
        &["shell init bash", "shell status"],
        NO_NOTES,
        NO_OPTIONS,
        SHELL_COMMANDS,
    ),
    help_command_with(
        "tui",
        "tui PATH",
        "Open the interactive private-terminal browser.",
        &["tui \"$HOME/vaults/work.kdbx\""],
        NO_NOTES,
        NO_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "init",
        "init [PATH] [OPTIONS]",
        "Create a KDBX 4.1 vault; never overwrites.",
        &["init \"$HOME/vaults/work.kdbx\""],
        INIT_NOTES,
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
    // Entries, interchange & system
    help_command(
        "files|attachment|attachments",
        "files <COMMAND>",
        "List or manage attachments.",
        NO_OPTIONS,
        ATTACHMENT_COMMANDS,
    ),
    help_command(
        "field|custom-field",
        "field <COMMAND>",
        "List or manage custom fields.",
        NO_OPTIONS,
        FIELD_COMMANDS,
    ),
    help_command(
        "group|groups",
        "group <COMMAND>",
        "List, create, or remove vault groups.",
        NO_OPTIONS,
        GROUP_COMMANDS,
    ),
    help_command_with(
        "import",
        "import (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Shortcut for secrets import.",
        &["import snapshot.json --dry-run"],
        NO_NOTES,
        IMPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "export",
        "export (DEST | -o DEST | --output DEST) [OPTIONS]",
        "Shortcut for secrets export.",
        &["export snapshot.json"],
        NO_NOTES,
        EXPORT_OPTIONS,
        NO_COMMANDS,
    ),
    help_command_with(
        "sync",
        "sync (SRC | -f SRC | --file SRC | --stdin) [OPTIONS]",
        "Shortcut for secrets sync.",
        &["sync snapshot.json --strategy newest --dry-run"],
        NO_NOTES,
        SYNC_OPTIONS,
        NO_COMMANDS,
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
        "config",
        "config <COMMAND>",
        "Inspect or change configuration.",
        NO_OPTIONS,
        CONFIG_COMMANDS,
    ),
    help_command_with(
        "completion",
        "completion SHELL",
        "Print static shell completion for bash, sh, zsh, fish, powershell, pwsh, or nushell.",
        &["completion bash"],
        NO_NOTES,
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
    let app_override = app_env_var_os("NEO_KEEPASS_CONFIG_DIR");
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
    let app_override = app_env_var_os("NEO_KEEPASS_DATA_DIR");
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
    let mut temp = nkeepass::private_file::new_private_temp(&dir).map_err(|error| {
        if nkeepass::private_file::capability_query_failed(&error) {
            err("cannot query filesystem ACL capability")
        } else if error.kind() == io::ErrorKind::Unsupported {
            err("filesystem cannot verify persistent owner-only ACL support")
        } else {
            err("cannot create private configuration temporary file")
        }
    })?;
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
const CONFIG_ALIASES_NOT_SCALAR: &str = "aliases is a map; use nkp alias set and nkp alias rm";

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

/// Lexical comparison key; Windows comparisons do not change displayed paths.
fn vault_path_key(text: &str) -> String {
    vault_path_key_for_platform(text, cfg!(windows))
}

/// Applies the platform's lexical comparison policy without changing output.
fn vault_path_key_for_platform(text: &str, windows: bool) -> String {
    if windows {
        text.replace('/', "\\")
    } else {
        text.to_owned()
    }
}

/// Platform-normalized deduplication key for vault paths (strips `/`->`\` and
/// folds ASCII case on Windows, matching `fs_safe::path_lookup_key`).
fn platform_vault_dedup_key_for_platform(text: &str, windows: bool) -> String {
    if windows {
        text.replace('/', "\\").to_ascii_lowercase()
    } else {
        text.to_owned()
    }
}

fn platform_vault_dedup_key(path: &Path) -> String {
    platform_vault_dedup_key_for_platform(&normalized_vault_text(path), cfg!(windows))
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
        || !nkeepass::template::is_safe_display_text(target)
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

fn use_context_alias(config: &mut Config, target: &str) -> Result<()> {
    if Path::new(target).is_absolute() {
        let path = vault_path(target)?;
        config.current = Some(normalized_vault_text(&path));
        return Ok(());
    }
    match config.aliases.get(target) {
        Some(Alias {
            kind: Kind::Vault, ..
        }) => {
            config.current = Some(target.to_owned());
            Ok(())
        }
        _ if target.contains('/') || target.contains('\\') || target.contains('.') => {
            Err(err("vault path must be absolute and normalized"))
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
    let Some(path) = app_env_var_os(name) else {
        return Ok(None);
    };
    let path = path
        .into_string()
        .map_err(|_| err("vault environment variable is not valid UTF-8"))?;
    if path.is_empty() {
        return Err(err("vault environment variable must not be empty"));
    }
    Ok(Some(path))
}

fn active_vault<'a>(
    explicit: Option<&'a str>,
    config: &'a Config,
) -> Result<(PathBuf, &'static str)> {
    if let Some(path) = explicit {
        return Ok((resolve_vault(path, config)?, "argument"));
    }
    if let Some(path) = environment_vault("NEO_KEEPASS_VAULT")? {
        return Ok((resolve_vault(&path, config)?, "environment"));
    }
    if let Some(path) = environment_vault("NEO_KEEPASS_VAULT_PATH")? {
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

struct TtyJsonFormatter;

impl serde_json::ser::Formatter for TtyJsonFormatter {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (idx, ch) in fragment.char_indices() {
            if matches!(ch, '\u{007f}' | '\u{0080}'..='\u{009f}')
                || nkeepass::template::is_bidi_or_line_separator(ch)
            {
                if start < idx {
                    writer.write_all(&fragment.as_bytes()[start..idx])?;
                }
                write!(writer, "\\u{:04x}", ch as u32)?;
                start = idx + ch.len_utf8();
            }
        }
        if start < fragment.len() {
            writer.write_all(&fragment.as_bytes()[start..])?;
        }
        Ok(())
    }
}

fn validate_tty_raw_bytes(bytes: &[u8]) -> Result<()> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(err(
            "raw output contains non-UTF-8 or terminal-control bytes; redirect stdout to a file or pipe",
        ));
    };
    if text.chars().any(|character| {
        (character.is_control() && !matches!(character, '\n' | '\t'))
            || nkeepass::template::is_bidi_or_line_separator(character)
    }) {
        return Err(err(
            "raw output contains terminal-control bytes; redirect stdout to a file or pipe",
        ));
    }
    Ok(())
}

fn write_json_for_sink<T: Serialize>(
    output: &mut impl Write,
    value: &T,
    stdout_is_tty: bool,
) -> Result<()> {
    let mut text = Vec::new();
    if stdout_is_tty {
        let mut serializer = serde_json::Serializer::with_formatter(&mut text, TtyJsonFormatter);
        value
            .serialize(&mut serializer)
            .map_err(|_| err("cannot encode output"))?;
    } else {
        serde_json::to_writer(&mut text, value).map_err(|_| err("cannot encode output"))?;
    }
    text.push(b'\n');
    output
        .write_all(&text)
        .and_then(|()| output.flush())
        .map_err(|_| err("cannot write output"))
}

fn json<T: Serialize>(value: &T) -> Result<()> {
    write_json_for_sink(&mut io::stdout().lock(), value, io::stdout().is_terminal())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataFormat {
    Json,
    Human,
}

impl MetadataFormat {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("json") => Ok(Self::Json),
            Some("human") => Ok(Self::Human),
            Some(_) => Err(err("invalid output format")),
        }
    }
}

fn sanitize_human_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() || nkeepass::template::is_bidi_or_line_separator(ch) {
            for escaped in ch.escape_default() {
                out.push(escaped);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn human_display_width(text: &str) -> usize {
    ratatui::text::Span::raw(text).width()
}

fn truncate_human_cell(text: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if human_display_width(text) <= max_width {
        return text.to_owned();
    }
    let target = max_width.saturating_sub(1);
    let mut best_end = 0;
    for (idx, ch) in text.char_indices() {
        let next_end = idx + ch.len_utf8();
        if human_display_width(&text[..next_end]) > target {
            break;
        }
        best_end = next_end;
    }
    let mut out = String::with_capacity(best_end + 3);
    out.push_str(&text[..best_end]);
    out.push('…');
    out
}

fn pad_human_cell(text: &str, width: usize) -> String {
    let current = human_display_width(text);
    if current >= width {
        text.to_owned()
    } else {
        let mut out = String::with_capacity(text.len() + (width - current));
        out.push_str(text);
        out.extend(std::iter::repeat_n(' ', width - current));
        out
    }
}

fn human_output_width() -> usize {
    if io::stdout().is_terminal()
        && let Ok((cols, _)) = crossterm::terminal::size()
        && cols > 0
    {
        return usize::from(cols).clamp(40, 120);
    }
    HELP_WIDTH
}

fn current_stdout_style() -> u8 {
    COLOR_STYLE.load(std::sync::atomic::Ordering::Relaxed)
}

fn style_human_header(text: &str, style: u8) -> String {
    match style {
        1 => format!("\x1b[1;36m{text}\x1b[0m"),
        2 => format!("\x1b[1;38;5;39m{text}\x1b[0m"),
        3 => format!("\x1b[1;38;2;80;190;255m{text}\x1b[0m"),
        _ => text.to_owned(),
    }
}

fn style_human_badge(badge: &str, style: u8, protected_tone: bool) -> String {
    match (style, protected_tone) {
        (1, true) => format!("\x1b[33m{badge}\x1b[0m"),
        (2, true) => format!("\x1b[38;5;220m{badge}\x1b[0m"),
        (3, true) => format!("\x1b[38;2;240;190;70m{badge}\x1b[0m"),
        (1, false) => format!("\x1b[32m{badge}\x1b[0m"),
        (2, false) => format!("\x1b[38;5;78m{badge}\x1b[0m"),
        (3, false) => format!("\x1b[38;2;90;210;130m{badge}\x1b[0m"),
        _ => badge.to_owned(),
    }
}

fn fit_column_widths(
    natural: &[usize],
    mins: &[usize],
    caps: &[usize],
    total_width: usize,
    gap: usize,
) -> Vec<usize> {
    let total_gap = gap.saturating_mul(natural.len().saturating_sub(1));
    let budget = total_width.saturating_sub(total_gap).max(natural.len());
    let mut widths: Vec<usize> = natural
        .iter()
        .zip(caps)
        .map(|(n, c)| (*n).min(*c).max(1))
        .collect();
    while widths.iter().sum::<usize>() > budget {
        let candidate = widths
            .iter()
            .enumerate()
            .filter(|(i, w)| **w > mins[*i])
            .max_by_key(|(i, w)| *w - mins[*i]);
        let Some((idx, _)) = candidate else {
            let Some((wide_idx, _)) = widths
                .iter()
                .enumerate()
                .filter(|(_, w)| **w > 1)
                .max_by_key(|(_, w)| **w)
            else {
                break;
            };
            widths[wide_idx] -= 1;
            continue;
        };
        widths[idx] -= 1;
    }
    widths
}

fn render_table_header(headers: &[&str], widths: &[usize], style: u8) -> String {
    let mut line = String::new();
    for (idx, (header, width)) in headers.iter().zip(widths).enumerate() {
        if idx > 0 {
            line.push_str("  ");
        }
        let truncated = truncate_human_cell(header, *width);
        let styled = style_human_header(&truncated, style);
        if idx + 1 < headers.len() {
            let pad = width.saturating_sub(human_display_width(&truncated));
            line.push_str(&styled);
            line.extend(std::iter::repeat_n(' ', pad));
        } else {
            line.push_str(&styled);
        }
    }
    line
}

fn write_human_lines(lines: &[String]) -> Result<()> {
    for line in lines {
        print_line(line)?;
    }
    Ok(())
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
    json(&SearchJsonRow {
        field_names: hit.field_names(),
        path: hit.path(),
        tags: hit.tags(),
        title: hit.title(),
    })
}

fn render_search_hits_human(
    hits: &[SearchHit],
    empty_label: &str,
    max_width: usize,
    style: u8,
) -> Vec<String> {
    if hits.is_empty() {
        return vec![empty_label.to_owned()];
    }
    let rows: Vec<([String; 4], bool)> = hits
        .iter()
        .map(|hit| {
            let path = sanitize_human_text(hit.path());
            let title = if hit.title().is_empty() {
                "-".to_owned()
            } else {
                sanitize_human_text(hit.title())
            };
            let tags = if hit.tags().is_empty() {
                "-".to_owned()
            } else {
                hit.tags()
                    .iter()
                    .map(|tag| sanitize_human_text(tag))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let has_otp = hit.field_names().iter().any(|name| name == "otp");
            let joined_fields = if hit.field_names().is_empty() {
                "-".to_owned()
            } else {
                hit.field_names()
                    .iter()
                    .map(|name| sanitize_human_text(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let fields = if has_otp {
                format!("[otp] {joined_fields}")
            } else {
                joined_fields
            };
            ([path, title, tags, fields], has_otp)
        })
        .collect();
    let headers = ["PATH", "TITLE", "TAGS", "FIELDS"];
    let mut natural = headers.map(human_display_width);
    for (cols, _) in &rows {
        for (i, cell) in cols.iter().enumerate() {
            natural[i] = natural[i].max(human_display_width(cell));
        }
    }
    let widths = fit_column_widths(&natural, &[8, 8, 6, 10], &[36, 24, 16, 40], max_width, 2);
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(render_table_header(&headers, &widths, style));
    for (cols, has_otp) in &rows {
        let path = pad_human_cell(&truncate_human_cell(&cols[0], widths[0]), widths[0]);
        let title = pad_human_cell(&truncate_human_cell(&cols[1], widths[1]), widths[1]);
        let tags = pad_human_cell(&truncate_human_cell(&cols[2], widths[2]), widths[2]);
        let mut fields = truncate_human_cell(&cols[3], widths[3]);
        if *has_otp
            && style > 0
            && let Some(rest) = fields.strip_prefix("[otp]")
        {
            fields = format!("{}{rest}", style_human_badge("[otp]", style, false));
        }
        lines.push(format!("{path}  {title}  {tags}  {fields}"));
    }
    lines
}

/// Writes one text line, reporting a failed write rather than panicking.
///
/// `println!` aborts on a write error, so a listing consumed by a pipeline that
/// closes early -- `nkp config ls | head -1` -- would die with a panic
/// message on stderr instead of stopping. `json` already returns the refusal
/// for a closed pipe, and this is the same contract for the text form.
fn print_line(line: &str) -> Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{line}").map_err(|_| err("cannot write output"))?;
    output.flush().map_err(|_| err("cannot write output"))
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
    nkeepass::template::is_safe_display_text(value)
}

fn safe_search_hit(hit: &nkeepass::SearchHit) -> bool {
    safe_metadata(hit.path())
        && safe_metadata(hit.title())
        && hit.tags().iter().all(|tag| safe_metadata(tag))
        && hit.field_names().iter().all(|field| safe_metadata(field))
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
        let _ = writeln!(
            io::stderr(),
            "nkp: {withheld} record(s) withheld: vault metadata contains \
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

fn format_field_flags(field: &nkeepass::FieldMetadata, style: u8) -> String {
    let mut parts = Vec::new();
    if field.protected() {
        parts.push(style_human_badge("[protected]", style, true));
    } else {
        parts.push("[plain]".to_owned());
    }
    if field.protect_in_memory() {
        parts.push("[in-memory]".to_owned());
    }
    if field.name() == "otp" {
        parts.push(style_human_badge("[otp]", style, false));
    }
    parts.join(" ")
}

fn render_fields_human(
    fields: &[nkeepass::FieldMetadata],
    max_width: usize,
    style: u8,
) -> Vec<String> {
    if fields.is_empty() {
        return vec!["(no fields)".to_owned()];
    }
    let rows: Vec<(String, String, &nkeepass::FieldMetadata)> = fields
        .iter()
        .map(|field| {
            (
                sanitize_human_text(field.name()),
                format_field_flags(field, 0),
                field,
            )
        })
        .collect();
    let headers = ["NAME", "FLAGS"];
    let mut natural = headers.map(human_display_width);
    for (name, flags, _) in &rows {
        natural[0] = natural[0].max(human_display_width(name));
        natural[1] = natural[1].max(human_display_width(flags));
    }
    let widths = fit_column_widths(&natural, &[8, 12], &[40, 36], max_width, 2);
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(render_table_header(&headers, &widths, style));
    for (name, _, field) in &rows {
        let name_cell = pad_human_cell(&truncate_human_cell(name, widths[0]), widths[0]);
        let flags_plain = format_field_flags(field, 0);
        let flags_cell = if human_display_width(&flags_plain) <= widths[1] {
            format_field_flags(field, style)
        } else {
            truncate_human_cell(&flags_plain, widths[1])
        };
        lines.push(format!("{name_cell}  {flags_cell}"));
    }
    lines
}

fn write_selected_fields(fields: &[nkeepass::FieldMetadata], format: MetadataFormat) -> Result<()> {
    match format {
        MetadataFormat::Json => {
            for field in fields {
                json(&serde_json::json!({
                    "name": field.name(),
                    "protected": field.protected(),
                    "protect_in_memory": field.protect_in_memory(),
                }))?;
            }
            Ok(())
        }
        MetadataFormat::Human => {
            let lines = render_fields_human(fields, human_output_width(), current_stdout_style());
            write_human_lines(&lines)
        }
    }
}

fn render_selected_entry_human(
    selected: &nkeepass::SelectedEntry,
    path: &str,
    max_width: usize,
    style: u8,
) -> Vec<String> {
    let mut lines = Vec::new();
    let label = |name: &str| style_human_header(name, style);
    let safe_path = truncate_human_cell(&sanitize_human_text(path), max_width.saturating_sub(7));
    let safe_title = if selected.title().is_empty() {
        "(none)".to_owned()
    } else {
        truncate_human_cell(
            &sanitize_human_text(selected.title()),
            max_width.saturating_sub(7),
        )
    };
    let safe_tags = if selected.tags().is_empty() {
        "(none)".to_owned()
    } else {
        let joined = selected
            .tags()
            .iter()
            .map(|tag| sanitize_human_text(tag))
            .collect::<Vec<_>>()
            .join(", ");
        truncate_human_cell(&joined, max_width.saturating_sub(6))
    };
    lines.push(format!("{} {safe_path}", label("Entry:")));
    lines.push(format!("{} {safe_title}", label("Title:")));
    lines.push(format!("{} {safe_tags}", label("Tags:")));
    if selected.has_otp() {
        lines.push(format!(
            "{} {} configured",
            label("OTP:"),
            style_human_badge("[otp]", style, false)
        ));
    } else {
        lines.push(format!("{} none", label("OTP:")));
    }
    let auto_state = if selected.auto_type_enabled() {
        "enabled"
    } else {
        "disabled"
    };
    let assoc_count = selected.auto_type_associations();
    let assoc_word = if assoc_count == 1 {
        "association"
    } else {
        "associations"
    };
    lines.push(format!(
        "{} {auto_state} ({assoc_count} {assoc_word})",
        label("Auto-type:")
    ));
    lines.push(label("Fields:"));
    if selected.fields().is_empty() {
        lines.push("  (no fields)".to_owned());
    } else {
        let field_names: Vec<String> = selected
            .fields()
            .iter()
            .map(|field| sanitize_human_text(field.name()))
            .collect();
        let name_col = field_names
            .iter()
            .map(|name| human_display_width(name))
            .max()
            .unwrap_or(8)
            .clamp(8, max_width.saturating_sub(28).clamp(8, 36));
        let flags_budget = max_width.saturating_sub(name_col + 4);
        for (field, safe_name) in selected.fields().iter().zip(&field_names) {
            let name_cell = pad_human_cell(&truncate_human_cell(safe_name, name_col), name_col);
            let flags_plain = format_field_flags(field, 0);
            let flags = if human_display_width(&flags_plain) <= flags_budget {
                format_field_flags(field, style)
            } else {
                truncate_human_cell(&flags_plain, flags_budget)
            };
            lines.push(format!("  {name_cell}  {flags}"));
        }
    }
    lines.push(label("Attachments:"));
    if selected.attachments().is_empty() {
        lines.push("  (no attachments)".to_owned());
    } else {
        let att_budget = max_width.saturating_sub(2);
        for attachment in selected.attachments() {
            lines.push(format!(
                "  {}",
                truncate_human_cell(&sanitize_human_text(attachment.name()), att_budget)
            ));
        }
    }
    lines
}

fn write_selected_entry(
    selected: &nkeepass::SelectedEntry,
    path: &str,
    format: MetadataFormat,
) -> Result<()> {
    if selected
        .fields()
        .iter()
        .filter(|field| field.name() == "otp")
        .count()
        > 1
    {
        return Err(err("ambiguous field name"));
    }
    let has_otp = selected
        .fields()
        .iter()
        .find(|field| field.name() == "otp")
        .is_some_and(nkeepass::FieldMetadata::protected);
    match format {
        MetadataFormat::Json => {
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
        MetadataFormat::Human => {
            let lines = render_selected_entry_human(
                selected,
                path,
                human_output_width(),
                current_stdout_style(),
            );
            write_human_lines(&lines)
        }
    }
}

fn render_attachments_human(
    attachments: &[nkeepass::AttachmentDescriptor],
    max_width: usize,
    style: u8,
) -> Vec<String> {
    if attachments.is_empty() {
        return vec!["(no attachments)".to_owned()];
    }
    let rows: Vec<(String, String, bool)> = attachments
        .iter()
        .map(|attachment| {
            (
                sanitize_human_text(attachment.name()),
                format!("{} B", attachment.size()),
                attachment.protected(),
            )
        })
        .collect();
    let headers = ["NAME", "BYTES", "FLAGS"];
    let mut natural = headers.map(human_display_width);
    for (name, bytes, protected) in &rows {
        natural[0] = natural[0].max(human_display_width(name));
        natural[1] = natural[1].max(human_display_width(bytes));
        natural[2] = natural[2].max(if *protected { 11 } else { 7 });
    }
    let widths = fit_column_widths(&natural, &[8, 6, 7], &[44, 14, 12], max_width, 2);
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(render_table_header(&headers, &widths, style));
    for (name, bytes, protected) in &rows {
        let name_cell = pad_human_cell(&truncate_human_cell(name, widths[0]), widths[0]);
        let bytes_cell = pad_human_cell(&truncate_human_cell(bytes, widths[1]), widths[1]);
        let badge_plain = if *protected { "[protected]" } else { "[plain]" };
        let badge_cell = if human_display_width(badge_plain) <= widths[2] {
            if *protected {
                style_human_badge("[protected]", style, true)
            } else {
                "[plain]".to_owned()
            }
        } else {
            truncate_human_cell(badge_plain, widths[2])
        };
        lines.push(format!("{name_cell}  {bytes_cell}  {badge_cell}"));
    }
    lines
}

fn render_aliases_human(aliases: &[(&String, &Alias)], max_width: usize, style: u8) -> Vec<String> {
    if aliases.is_empty() {
        return vec!["(no aliases)".to_owned()];
    }
    let rows: Vec<[String; 4]> = aliases
        .iter()
        .map(|(name, alias)| {
            let kind = match alias.kind {
                Kind::Vault => "[vault]",
                Kind::Entry => "[entry]",
            };
            [
                sanitize_human_text(name),
                kind.to_owned(),
                sanitize_human_text(&alias.target),
                alias
                    .field
                    .as_deref()
                    .map_or_else(|| "-".to_owned(), sanitize_human_text),
            ]
        })
        .collect();
    let headers = ["NAME", "KIND", "TARGET", "FIELD"];
    let mut natural = headers.map(human_display_width);
    for cols in &rows {
        for (i, cell) in cols.iter().enumerate() {
            natural[i] = natural[i].max(human_display_width(cell));
        }
    }
    let widths = fit_column_widths(&natural, &[6, 7, 10, 6], &[20, 8, 42, 20], max_width, 2);
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(render_table_header(&headers, &widths, style));
    for cols in &rows {
        let name = pad_human_cell(&truncate_human_cell(&cols[0], widths[0]), widths[0]);
        let kind = pad_human_cell(&truncate_human_cell(&cols[1], widths[1]), widths[1]);
        let target = pad_human_cell(&truncate_human_cell(&cols[2], widths[2]), widths[2]);
        let field = truncate_human_cell(&cols[3], widths[3]);
        lines.push(format!("{name}  {kind}  {target}  {field}"));
    }
    lines
}

/// Whether a command accepts a bare positional word.
///
/// Every command shares one option parser, so the positional policy is a
/// parameter of it rather than a second parser. Naming the cases keeps
/// walk-command globs, target paths, entry/group selectors, and repeatable
/// bundle paths distinct; folding them into one "allow a word" flag would
/// silently change what a bare argument means.
#[derive(Clone, Copy)]
enum Positional {
    /// No bare positional is accepted.
    Forbidden,
    /// One `secrets ls`/`secrets search` glob, taken after the `--` terminator.
    Glob,
    /// One bare target path, as `init PATH` takes.
    Path,
    /// One output destination path, as `export DEST` takes.
    Output,
    /// One input file path, as `import SRC` and `sync SRC` take.
    File,
    /// One entry or group selector on a route with an unambiguous key role.
    Key,
    /// Set additionally accepts repeatable field assignments.
    SetKey,
    /// One entry selector followed by one custom-field name.
    KeyAndField,
    /// One entry selector followed by one attachment name.
    KeyAndAttachment,
    /// Multiple explicit entry paths for the reserved get-many subcommand.
    Many,
}

impl Positional {
    /// Selects the deliberately narrow positional syntax for each command.
    fn for_action(action: &str) -> Self {
        if action == "get-many" {
            return Self::Many;
        }
        if action == "set" {
            return Self::SetKey;
        }
        if matches!(action, "field-get" | "field-set" | "field-rm") {
            return Self::KeyAndField;
        }
        if matches!(
            action,
            "attachment-add" | "attachment-get" | "attachment-rm"
        ) {
            return Self::KeyAndAttachment;
        }
        if action == "export" {
            return Self::Output;
        }
        if matches!(action, "import" | "sync") {
            return Self::File;
        }
        if matches!(
            action,
            "get"
                | "rm"
                | "show"
                | "ensure"
                | "otp"
                | "group-add"
                | "group-rm"
                | "field-ls"
                | "attachment-ls"
        ) {
            return Self::Key;
        }
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
    requested_paths: Vec<&'a str>,
    field: Option<&'a str>,
    assignment_inputs: Vec<&'a str>,
    literal_input: Option<&'a str>,
    value_env: Option<&'a str>,
    value_alias: bool,
    chars_alias: bool,
    generate: bool,
    generation_policy: nkeepass::password_generator::Policy,
    username: Option<&'a str>,
    url: Option<&'a str>,
    notes: Option<&'a str>,
    bins: Vec<&'a str>,
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
    allow_plaintext: bool,
    size: Option<usize>,
    glob: Option<&'a str>,
    format: Option<&'a str>,
    is_output: bool,
    clipboard: bool,
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
    json: bool,
    check: bool,
    generate_master_password: bool,
}

fn options(args: &[String], positional: Positional) -> Result<Options<'_>> {
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    options_from_refs(&refs, positional)
}

fn assign_positional<'a>(
    opts: &mut Options<'a>,
    positional: Positional,
    word: &'a str,
    positional_index: &mut usize,
) -> Result<()> {
    match positional {
        Positional::Many => opts.requested_paths.push(word),
        Positional::Glob if opts.glob.is_none() => opts.glob = Some(word),
        Positional::Path if opts.path.is_none() => opts.path = Some(word),
        Positional::Output if opts.output.is_none() => opts.output = Some(word),
        Positional::Output => {
            return Err(err(
                "output path specified more than once; use either a positional destination or --output",
            ));
        }
        Positional::File if opts.file.is_none() => opts.file = Some(word),
        Positional::File => {
            return Err(err(
                "input file specified more than once; use either a positional file or --file",
            ));
        }
        Positional::Key | Positional::SetKey if opts.key.is_none() => opts.key = Some(word),
        Positional::Key | Positional::SetKey => {
            return Err(err(
                "entry key specified more than once; use either a positional key or --key",
            ));
        }
        Positional::KeyAndField => match *positional_index {
            0 if opts.key.is_none() => opts.key = Some(word),
            0 => {
                return Err(err(
                    "entry key specified more than once; use either a positional key or --key",
                ));
            }
            1 if opts.field.is_none() => opts.field = Some(word),
            1 => {
                return Err(err(
                    "field specified more than once; use either a positional field or --field",
                ));
            }
            _ => return Err(err("invalid or duplicate option")),
        },
        Positional::KeyAndAttachment => match *positional_index {
            0 if opts.key.is_none() => opts.key = Some(word),
            0 => {
                return Err(err(
                    "entry key specified more than once; use either a positional key or --key",
                ));
            }
            1 if opts.field.is_none() && opts.name.is_none() => opts.field = Some(word),
            1 => {
                return Err(err(
                    "attachment name specified more than once; use positional NAME, --name, or --field",
                ));
            }
            _ => return Err(err("invalid or duplicate option")),
        },
        _ => return Err(err("invalid or duplicate option")),
    }
    *positional_index += 1;
    Ok(())
}

fn options_from_refs<'a>(args: &[&'a str], positional: Positional) -> Result<Options<'a>> {
    let mut opts = Options::default();
    let mut positional_index = 0usize;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if !matches!(positional, Positional::Forbidden) && arg == "--" {
            i += 1;
            while i < args.len() {
                assign_positional(&mut opts, positional, args[i], &mut positional_index)?;
                i += 1;
            }
            break;
        }
        let value = if !matches!(arg, "--kind" | "--env") && takes_option_value(arg) {
            i += 1;
            Some(
                args.get(i)
                    .copied()
                    .ok_or_else(|| err("missing argument; see --help"))?,
            )
        } else {
            None
        };
        match arg {
            "--key" if opts.key.is_none() => opts.key = value,
            "--key" => {
                return Err(err(
                    "entry key specified more than once; use either a positional key or --key",
                ));
            }
            "--field"
                if matches!(positional, Positional::SetKey)
                    && value.is_some_and(|value| value.contains('=')) =>
            {
                opts.assignment_inputs
                    .push(value.ok_or_else(|| err("field assignment required"))?)
            }
            "--field" if opts.field.is_none() => opts.field = value,
            "--value" if opts.literal_input.is_none() => opts.literal_input = value,
            "--value-env" if opts.value_env.is_none() => opts.value_env = value,
            "--generate" if !opts.generate => opts.generate = true,
            "--upper" | "-U" if !opts.generation_policy.upper => {
                opts.generation_policy.upper = true
            }
            "--lower" | "-L" if !opts.generation_policy.lower => {
                opts.generation_policy.lower = true
            }
            "--digits" | "-D" if !opts.generation_policy.digits => {
                opts.generation_policy.digits = true
            }
            "--symbols" | "-S" if !opts.generation_policy.symbols => {
                opts.generation_policy.symbols = true
            }
            "--username" if opts.username.is_none() => opts.username = value,
            "--url" if opts.url.is_none() => opts.url = value,
            "--notes" if opts.notes.is_none() => opts.notes = value,
            "--bin" | "-b" => opts.bins.push(value.ok_or_else(|| err("invalid option"))?),
            "--name" if opts.name.is_none() => opts.name = value,
            "--file" | "--value-file" if opts.file.is_none() => opts.file = value,
            "--output" if opts.output.is_none() => opts.output = value,
            "--password" if opts.password.is_none() => opts.password = value,
            "--password-env" if opts.password_env.is_none() => opts.password_env = value,
            "--password-file" if opts.password_file.is_none() => opts.password_file = value,
            "--key-file" if opts.key_file.is_none() => opts.key_file = value,
            "--password-stdin" if !opts.password_stdin => opts.password_stdin = true,
            "--stdin" | "--value-stdin" if !opts.stdin => opts.stdin = true,
            "--yes" if !opts.yes => opts.yes = true,
            "--dry-run" if !opts.dry_run => opts.dry_run = true,
            "--replace" if !opts.replace => opts.replace = true,
            "--allow-plaintext" if !opts.allow_plaintext => opts.allow_plaintext = true,
            "--size" | "--chars" | "-c" if opts.size.is_none() => {
                opts.size = Some(count(value, "invalid size")?)
            }
            "--format" if opts.format.is_none() => opts.format = value,
            "--is-output" if !opts.is_output => opts.is_output = true,
            "--clipboard" if !opts.clipboard => opts.clipboard = true,
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
            "--json" if !opts.json => opts.json = true,
            "--check" if !opts.check => opts.check = true,
            "--generate-master-password" if !opts.generate_master_password => {
                opts.generate_master_password = true;
            }
            word if !word.starts_with('-') => {
                assign_positional(&mut opts, positional, word, &mut positional_index)?;
            }
            _ => return Err(err("invalid or duplicate option")),
        }
        opts.value_alias |= matches!(arg, "--value-file" | "--value-stdin");
        opts.chars_alias |= matches!(arg, "--chars" | "-c");
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
    let value_sources = usize::from(opts.literal_input.is_some())
        + usize::from(opts.value_env.is_some())
        + usize::from(opts.file.is_some())
        + usize::from(opts.stdin)
        + usize::from(opts.generate);
    if value_sources > 1 {
        return Err(err("select exactly one value source"));
    }
    if opts.value_env.is_some_and(|name| !valid_name(name)) {
        return Err(err("invalid value environment variable name"));
    }
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

/// Explicit per-route allowlist for non-credential options parsed by [`options`].
/// Every field defaults to `false` so adding a new CLI flag fails closed on every
/// route until that route explicitly opts in.
#[derive(Clone, Copy, Default)]
struct AllowedOptions {
    allow_key: bool,
    allow_requested_paths: bool,
    allow_field: bool,
    allow_assignments: bool,
    allow_literal_input: bool,
    allow_value_env: bool,
    allow_value_aliases: bool,
    allow_chars_alias: bool,
    allow_generate: bool,
    allow_generation_policy: bool,
    allow_username: bool,
    allow_url: bool,
    allow_notes: bool,
    allow_bins: bool,
    allow_name: bool,
    allow_file: bool,
    allow_output: bool,
    allow_stdin: bool,
    allow_yes: bool,
    allow_dry_run: bool,
    allow_replace: bool,
    allow_allow_plaintext: bool,
    allow_size: bool,
    allow_glob: bool,
    allow_format: bool,
    allow_is_output: bool,
    allow_clipboard: bool,
    allow_strategy: bool,
    allow_path: bool,
    allow_kdf: bool,
    allow_age_encrypt: bool,
    allow_age_decrypt: bool,
    allow_age_recipients: bool,
    allow_age_identity: bool,
    allow_json: bool,
    allow_check: bool,
    allow_generate_master_password: bool,
}

impl AllowedOptions {
    const fn none() -> Self {
        Self {
            allow_key: false,
            allow_requested_paths: false,
            allow_field: false,
            allow_assignments: false,
            allow_literal_input: false,
            allow_value_env: false,
            allow_value_aliases: false,
            allow_chars_alias: false,
            allow_generate: false,
            allow_generation_policy: false,
            allow_username: false,
            allow_url: false,
            allow_notes: false,
            allow_bins: false,
            allow_name: false,
            allow_file: false,
            allow_output: false,
            allow_stdin: false,
            allow_yes: false,
            allow_dry_run: false,
            allow_replace: false,
            allow_allow_plaintext: false,
            allow_size: false,
            allow_glob: false,
            allow_format: false,
            allow_is_output: false,
            allow_clipboard: false,
            allow_strategy: false,
            allow_path: false,
            allow_kdf: false,
            allow_age_encrypt: false,
            allow_age_decrypt: false,
            allow_age_recipients: false,
            allow_age_identity: false,
            allow_json: false,
            allow_check: false,
            allow_generate_master_password: false,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "exhaustive destructuring ensures no Options field can be silently ignored"
)]
fn validate_allowed_options(
    opts: &Options<'_>,
    allowed: &AllowedOptions,
    rejection: &'static str,
    allow_plaintext_error: Option<&'static str>,
    age_error: &'static str,
) -> Result<()> {
    let Options {
        key,
        requested_paths,
        field,
        assignment_inputs,
        literal_input,
        value_env,
        value_alias,
        chars_alias,
        generate,
        generation_policy,
        username,
        url,
        notes,
        bins,
        name,
        file,
        output,
        password: _,
        password_env: _,
        password_file: _,
        key_file: _,
        password_stdin: _,
        stdin,
        yes,
        dry_run,
        replace,
        allow_plaintext,
        size,
        glob,
        format,
        is_output,
        clipboard,
        strategy,
        path,
        kdf,
        memory,
        iterations,
        parallelism,
        age_encrypt,
        age_decrypt,
        age_recipients,
        age_identity,
        json,
        check,
        generate_master_password,
    } = opts;
    let AllowedOptions {
        allow_key,
        allow_requested_paths,
        allow_field,
        allow_assignments,
        allow_literal_input,
        allow_value_env,
        allow_value_aliases,
        allow_chars_alias,
        allow_generate,
        allow_generation_policy,
        allow_username,
        allow_url,
        allow_notes,
        allow_bins,
        allow_name,
        allow_file,
        allow_output,
        allow_stdin,
        allow_yes,
        allow_dry_run,
        allow_replace,
        allow_allow_plaintext,
        allow_size,
        allow_glob,
        allow_format,
        allow_is_output,
        allow_clipboard,
        allow_strategy,
        allow_path,
        allow_kdf,
        allow_age_encrypt,
        allow_age_decrypt,
        allow_age_recipients,
        allow_age_identity,
        allow_json,
        allow_check,
        allow_generate_master_password,
    } = *allowed;

    if *allow_plaintext && !allow_allow_plaintext {
        return Err(err(allow_plaintext_error.unwrap_or(rejection)));
    }
    let any_age_allowed =
        allow_age_encrypt || allow_age_decrypt || allow_age_recipients || allow_age_identity;
    let has_any_age =
        *age_encrypt || *age_decrypt || !age_recipients.is_empty() || age_identity.is_some();
    if has_any_age && !any_age_allowed {
        return Err(err(age_error));
    }
    if (!allow_key && key.is_some())
        || (!allow_requested_paths && !requested_paths.is_empty())
        || (!allow_field && field.is_some())
        || (!allow_assignments && !assignment_inputs.is_empty())
        || (!allow_literal_input && literal_input.is_some())
        || (!allow_value_env && value_env.is_some())
        || (!allow_value_aliases && *value_alias)
        || (!allow_chars_alias && *chars_alias)
        || (!allow_generate && *generate)
        || (!allow_generation_policy && generation_policy.selected())
        || (!allow_username && username.is_some())
        || (!allow_url && url.is_some())
        || (!allow_notes && notes.is_some())
        || (!allow_bins && !bins.is_empty())
        || (!allow_name && name.is_some())
        || (!allow_file && file.is_some())
        || (!allow_output && output.is_some())
        || (!allow_stdin && *stdin)
        || (!allow_yes && *yes)
        || (!allow_dry_run && *dry_run)
        || (!allow_replace && *replace)
        || (!allow_size && size.is_some())
        || (!allow_glob && glob.is_some())
        || (!allow_format && format.is_some())
        || (!allow_is_output && *is_output)
        || (!allow_clipboard && *clipboard)
        || (!allow_strategy && strategy.is_some())
        || (!allow_path && path.is_some())
        || (!allow_kdf
            && (kdf.is_some() || memory.is_some() || iterations.is_some() || parallelism.is_some()))
        || (!allow_age_encrypt && *age_encrypt)
        || (!allow_age_decrypt && *age_decrypt)
        || (!allow_age_recipients && !age_recipients.is_empty())
        || (!allow_age_identity && age_identity.is_some())
        || (!allow_json && *json)
        || (!allow_check && *check)
        || (!allow_generate_master_password && *generate_master_password)
    {
        return Err(err(rejection));
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
    match app_env_var_os(DEFAULT_PASSWORD_ENV) {
        Some(value) => match value.into_string() {
            Ok(value) if !value.is_empty() => return Ok(Some(Zeroizing::new(value))),
            Ok(_) | Err(_) => return Err(err("password environment variable unavailable")),
        },
        None => {}
    }
    if !io::stdin().is_terminal() {
        return Err(err("password source required for non-interactive input"));
    }
    let _ = write!(io::stderr(), "Master password: ");
    io::stderr()
        .flush()
        .map_err(|_| err("cannot start password prompt"))?;
    let value = rpassword::read_password().map_err(|_| err("cannot read password"))?;
    let _ = writeln!(io::stderr());
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
    credentials_with_password(opts, password.as_deref().map(String::as_str))
}

fn credentials_with_password(
    opts: &Options<'_>,
    password: Option<&str>,
) -> Result<KdbxCredentials> {
    credentials_with_password_and_keyfile(password, opts.key_file)
}

fn credentials_with_password_and_keyfile(
    password: Option<&str>,
    key_file_path: Option<&str>,
) -> Result<KdbxCredentials> {
    let key_file = key_file_path
        .map(|path| {
            nkeepass::fs_safe::open_regular_file_nofollow(Path::new(path))
                .map_err(|_| err("cannot open key file"))
                .and_then(|(file, _)| read_key_file(file).map_err(|_| err("invalid key file")))
        })
        .transpose()?;
    let providers = key_file
        .map(|provider| {
            vec![Box::new(provider) as Box<dyn neotales_keepass::CredentialProvider + Send>]
        })
        .unwrap_or_default();
    KdbxCredentials::from_parts(password.map(str::as_bytes), providers)
        .map_err(|_| err("invalid credentials"))
}

/// Stores the init password in age-encrypted form using a private local identity.
///
/// The identity and ciphertext are installed with owner-only permissions and
/// create-if-absent semantics. Existing files are never replaced.
struct InitPasswordBackup {
    path: PathBuf,
    identity_path: PathBuf,
    identity_created: bool,
    association_path: Option<PathBuf>,
}

#[cfg(test)]
fn backup_init_password_in(password: &str, home: &Path) -> Result<PathBuf> {
    backup_init_password_at(
        password,
        &home.join("config/nkeepass"),
        &home.join("data/nkeepass"),
    )
    .map(|backup| backup.path)
}

fn backup_init_password_at(
    password: &str,
    config_root: &Path,
    data_root: &Path,
) -> Result<InitPasswordBackup> {
    backup_init_password_at_with(
        password,
        config_root,
        data_root,
        confirm_backup_identity_durability,
    )
}

fn backup_init_password_at_with(
    password: &str,
    config_root: &Path,
    data_root: &Path,
    confirm: impl FnOnce(&File, &Path) -> Result<()>,
) -> Result<InitPasswordBackup> {
    for path in [config_root, data_root] {
        if !path.to_str().is_some_and(safe_metadata) {
            return Err(err("password backup directory is not safe to report"));
        }
    }
    ensure_backup_dir(config_root, "cannot prepare password identity directory")?;
    ensure_backup_dir(data_root, "cannot prepare password backup directory")?;
    #[cfg(not(any(unix, windows)))]
    return Err(err(
        "secure password backup storage is unsupported on this platform",
    ));

    let config = config_root;
    let data = data_root;
    let identity_path = config.join("init-password.agekey");
    let (identity, identity_created) =
        load_or_create_backup_identity_with(&identity_path, confirm)?;

    let recipient = identity
        .recipient()
        .map_err(|_| err("password backup identity is invalid"))?;
    let encrypted = AgeFile::encrypt_armored(password.as_bytes(), &[recipient])
        .map_err(|_| err("cannot encrypt init password"))?;
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| err("cannot generate password backup name"))?;
    let mut name = String::with_capacity(suffix.len() * 2);
    for byte in suffix {
        write!(name, "{byte:02x}").map_err(|_| err("cannot generate password backup name"))?;
    }
    let target = data.join(format!("init-password-{name}.age"));
    nkeepass::private_file::write_private_noclobber(&target, encrypted.as_bytes()).map_err(
        |cause| match cause {
            "output installed but directory durability is unconfirmed" => err(
                "encrypted password backup was installed but directory durability is unconfirmed",
            ),
            "output exists" => err("encrypted password backup target already exists"),
            "filesystem cannot verify persistent owner-only ACL support" => {
                err("filesystem cannot verify persistent owner-only ACL support")
            }
            "cannot query filesystem ACL capability" => {
                err("cannot query filesystem ACL capability")
            }
            "cannot restrict output permissions" => {
                err("cannot restrict password backup permissions")
            }
            _ => err("cannot install encrypted password backup"),
        },
    )?;
    Ok(InitPasswordBackup {
        path: target,
        identity_path,
        identity_created,
        association_path: None,
    })
}

/// Installs a private, no-clobber recovery candidate before vault creation.
///
/// The record describes an attempt, not proof that the vault was installed.
#[derive(Debug)]
struct AssociationError {
    message: &'static str,
    installed: bool,
}

fn associate_init_backup(
    backup: &mut InitPasswordBackup,
    vault: &str,
) -> std::result::Result<(), AssociationError> {
    associate_init_backup_with(
        backup,
        vault,
        nkeepass::private_file::write_private_noclobber,
    )
}

fn associate_init_backup_with(
    backup: &mut InitPasswordBackup,
    vault: &str,
    install: impl FnOnce(&Path, &[u8]) -> std::result::Result<(), &'static str>,
) -> std::result::Result<(), AssociationError> {
    let mut name = backup.path.as_os_str().to_os_string();
    name.push(".json");
    let path = PathBuf::from(name);
    let record = serde_json::json!({
        "version": 1,
        "vault": vault,
        "password_backup": backup.path.to_string_lossy(),
        "age_identity": backup.identity_path.to_string_lossy(),
        "status": "candidate",
        "directory_sync_policy": backup_directory_sync_policy(),
        "ancestor_durability": "unconfirmed",
    });
    let bytes = serde_json::to_vec(&record).map_err(|_| AssociationError {
        message: "cannot encode recovery association",
        installed: false,
    })?;
    if let Err(cause) = install(&path, &bytes) {
        let installed = cause == "output installed but directory durability is unconfirmed";
        if installed {
            backup.association_path = Some(path);
        }
        return Err(AssociationError {
            message: match cause {
                "output installed but directory durability is unconfirmed" => {
                    "recovery association installed but directory durability is unconfirmed"
                }
                "output exists" => "recovery association already exists",
                "filesystem cannot verify persistent owner-only ACL support" => {
                    "filesystem cannot verify persistent owner-only ACL support"
                }
                "cannot query filesystem ACL capability" => {
                    "cannot query filesystem ACL capability"
                }
                "cannot restrict output permissions" => {
                    "cannot restrict recovery association permissions"
                }
                "cannot stage output" => "cannot stage recovery association",
                "cannot write output" => "cannot write recovery association",
                "cannot sync output" => "cannot sync recovery association",
                "cannot install output" => "cannot install recovery association",
                _ => "cannot securely install recovery association",
            },
            installed,
        });
    }
    backup.association_path = Some(path);
    Ok(())
}

fn ensure_backup_dir(path: &Path, diagnostic: &'static str) -> Result<()> {
    #[cfg(unix)]
    let mut new_dirs = {
        let mut dirs = Vec::new();
        let mut current = path;
        loop {
            match fs::symlink_metadata(current) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    dirs.push(current.to_path_buf());
                    current = current.parent().ok_or_else(|| err(diagnostic))?;
                }
                Err(_) => return Err(err(diagnostic)),
            }
        }
        dirs
    };
    fs::create_dir_all(path).map_err(|_| err(diagnostic))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| err(diagnostic))?;
    if !metadata.file_type().is_dir() {
        return Err(err(
            "password backup directory must not be a symlink or non-directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| err(diagnostic))?;
        // Sync each newly created directory and its parent so the directory
        // entries themselves survive, not just files later installed within it.
        while let Some(dir) = new_dirs.pop() {
            File::open(&dir)
                .and_then(|file| file.sync_all())
                .map_err(|_| err(diagnostic))?;
            if let Some(parent) = dir.parent() {
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| err(diagnostic))?;
            }
        }
    }
    #[cfg(windows)]
    nkeepass::private_file::set_owner_only(path, diagnostic).map_err(err)?;
    Ok(())
}

fn load_or_create_backup_identity_with(
    path: &Path,
    confirm: impl FnOnce(&File, &Path) -> Result<()>,
) -> Result<(AgeIdentity, bool)> {
    match fs::symlink_metadata(path) {
        Ok(_) => return read_backup_identity(path, confirm).map(|identity| (identity, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(err("cannot inspect password backup identity")),
    }

    let key = neotales_age::AgeKey::generate()
        .map_err(|_| err("cannot generate password backup identity"))?;
    let private_key = Zeroizing::new(key.private_key);
    let identity_bytes = Zeroizing::new(format!("{}\n", private_key.as_str()));
    match nkeepass::private_file::write_private_noclobber(path, identity_bytes.as_bytes()) {
        Ok(()) => AgeIdentity::from_private_key(private_key.as_str())
            .map(|identity| (identity, true))
            .map_err(|_| err("cannot initialize password backup identity")),
        Err("output exists") => {
            // Another initializer may have installed the shared identity. Only
            // adopt it after the same type, permission, and key validation.
            read_backup_identity(path, confirm).map(|identity| (identity, false))
        }
        Err("output installed but directory durability is unconfirmed") => Err(err(
            "password backup identity was installed but directory durability is unconfirmed",
        )),
        Err("cannot install output") => Err(err("cannot install password backup identity")),
        Err("filesystem cannot verify persistent owner-only ACL support") => Err(err(
            "filesystem cannot verify persistent owner-only ACL support",
        )),
        Err("cannot query filesystem ACL capability") => {
            Err(err("cannot query filesystem ACL capability"))
        }
        Err("cannot restrict output permissions") => {
            Err(err("cannot restrict password backup identity permissions"))
        }
        Err(_) => Err(err("cannot install password backup identity")),
    }
}

fn read_backup_identity(
    path: &Path,
    confirm: impl FnOnce(&File, &Path) -> Result<()>,
) -> Result<AgeIdentity> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| err("cannot inspect password backup identity"))?;
    if !metadata.file_type().is_file() {
        return Err(err("password backup identity must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(err("password backup identity permissions are too broad"));
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(err(
        "cannot verify password backup identity permissions on this platform",
    ));

    let mut identity_file =
        File::open(path).map_err(|_| err("cannot read password backup identity"))?;
    #[cfg(windows)]
    windows_private_file::verify(&identity_file).map_err(|error| {
        if nkeepass::private_file::capability_query_failed(&error) {
            err("cannot query filesystem ACL capability")
        } else if error.kind() == io::ErrorKind::Unsupported {
            err("filesystem cannot verify persistent owner-only ACL support")
        } else {
            err("password backup identity permissions are too broad")
        }
    })?;
    let mut identity_text = Zeroizing::new(String::new());
    identity_file
        .read_to_string(&mut identity_text)
        .map_err(|_| err("cannot read password backup identity"))?;
    let identity = AgeIdentity::from_private_key(identity_text.trim())
        .map_err(|_| err("password backup identity is invalid"))?;
    confirm(&identity_file, path)?;
    Ok(identity)
}

/// Applies the platform's existing durability policy to a reused identity.
fn confirm_backup_identity_durability(file: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        file.sync_all()
            .map_err(|_| err("cannot confirm password backup identity durability"))?;
        let parent = path
            .parent()
            .ok_or_else(|| err("cannot confirm password backup identity durability"))?;
        // Sync the directory containing the identity, not unrelated ancestors:
        // traversable parent directories need not be readable. As with existing
        // private-file writes, preexisting directory entries are assumed durable.
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| err("cannot confirm password backup identity durability"))?;
    }
    #[cfg(not(unix))]
    {
        // The identity file is synced before publication. The Windows private
        // file policy cannot confirm directory sync; report that limitation
        // rather than claiming a power-loss guarantee or rejecting reuse.
        let _ = (file, path);
    }
    Ok(())
}

/// Describes the directory-sync policy, not an assertion of actual durability.
fn backup_directory_sync_policy() -> &'static str {
    if cfg!(unix) {
        "required"
    } else {
        "unconfirmed"
    }
}

fn bounded_file(path: &str, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let (file, _) = nkeepass::fs_safe::open_regular_file_nofollow(Path::new(path))
        .map_err(|_| err("cannot open input file"))?;
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

#[cfg(test)]
#[derive(Clone, Copy)]
enum CurlFixtureProcess {
    CouldNotStart,
    Completed(Option<i32>),
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
    fetch_recipient_url_with_program(url, transport, std::ffi::OsStr::new("curl"))
}

/// Fetches a recipient document using the given curl program.
fn fetch_recipient_url_with_program(
    url: &str,
    transport: RecipientTransport,
    curl_program: &std::ffi::OsStr,
) -> Result<String> {
    let mut command = std::process::Command::new(curl_program);
    command.args([
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
    ]);
    // A local HTTP fixture must connect directly even on runners whose curl
    // installation is configured with a system proxy.
    #[cfg(test)]
    if let RecipientTransport::HttpFixture = transport {
        command.args(["--noproxy", "*"]);
    }
    command
        .arg("--url")
        .arg(url)
        .args(["--write-out", "\n%{http_code}"])
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        // Keep the Windows installation root available to curl's native
        // certificate-store and CA bundle discovery without inheriting the
        // caller's environment.
        .envs(recipient_curl_windows_environment())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(test)]
    if matches!(transport, RecipientTransport::HttpFixture) {
        // Inject a controlled proxy in the test child so --noproxy is a
        // load-bearing condition, not an unexercised defensive option.
        let proxy = url
            .get("http://".len()..)
            .and_then(|tail| tail.find('/').map(|end| end + "http://".len()))
            .map_or(url, |end| &url[..end]);
        command.env("http_proxy", proxy);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            #[cfg(test)]
            if matches!(transport, RecipientTransport::HttpFixture) {
                return Err(err(&format!(
                    "HTTP fixture curl could not start ({})",
                    curl_fixture_diagnostic(CurlFixtureProcess::CouldNotStart)
                )));
            }
            return Err(err("HTTPS recipient lookup unavailable"));
        }
    };
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
        #[cfg(test)]
        if matches!(transport, RecipientTransport::HttpFixture) {
            return Err(err(&format!(
                "HTTP fixture curl failed ({})",
                curl_fixture_diagnostic(CurlFixtureProcess::Completed(status.code()))
            )));
        }
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

/// Classifies fixture failures without running another process or retaining
/// arbitrary diagnostic output.
#[cfg(test)]
fn curl_fixture_diagnostic(process: CurlFixtureProcess) -> String {
    match process {
        CurlFixtureProcess::CouldNotStart => {
            "process=not-started; category=executable unavailable".to_owned()
        }
        CurlFixtureProcess::Completed(None) => {
            "process=completed_without_exit_code; category=abnormal termination".to_owned()
        }
        CurlFixtureProcess::Completed(Some(exit_code)) => {
            let category = match exit_code {
                1 | 2 | 4 | 48 => "curl configuration or protocol error",
                5 | 6 => "name resolution error",
                7 => "connection error",
                _ => "curl transfer error",
            };
            format!("process=exited; exit_code={exit_code}; category={category}")
        }
    }
}

/// Returns the minimal platform environment needed by curl's Windows TLS
/// certificate lookup. No caller-controlled variables are inherited.
#[cfg(windows)]
fn recipient_curl_windows_environment() -> impl Iterator<Item = (&'static str, std::ffi::OsString)>
{
    env::var_os("SystemRoot")
        .map(|system_root| ("SystemRoot", system_root))
        .into_iter()
}

#[cfg(not(windows))]
fn recipient_curl_windows_environment() -> impl Iterator<Item = (&'static str, std::ffi::OsString)>
{
    std::iter::empty()
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

/// Explicit identities never fall back. Discovery is local, deterministic and
/// never creates a key: prefer this application's init backup identity, then
/// the conventional age keys.txt file.
fn selected_age_identities(explicit: Option<&str>) -> Result<Vec<AgeIdentity>> {
    if let Some(path) = explicit {
        return age_identities(path);
    }
    let application = config_dir()?.join("init-password.agekey");
    if let Some(identities) = existing_age_identities(&application)? {
        return Ok(identities);
    }
    let age = if let Some(root) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(root).join("age/keys.txt")
    } else {
        home_dir()?.join(".config/age/keys.txt")
    };
    existing_age_identities(&age)?
        .ok_or_else(|| err("no known age identity; supply --age-identity"))
}

fn existing_age_identities(path: &Path) -> Result<Option<Vec<AgeIdentity>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => age_identities(
            path.to_str()
                .ok_or_else(|| err("age identity path is not Unicode"))?,
        )
        .map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(err("cannot inspect age identity file")),
    }
}

fn set_input_value(opts: &Options<'_>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(value) = opts.literal_input {
        if value.len() > 16 * 1024 * 1024 {
            return Err(err("input exceeds size limit"));
        }
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    }
    if let Some(name) = opts.value_env {
        let value = Zeroizing::new(
            env::var(name).map_err(|_| err("cannot read value environment variable"))?,
        );
        if value.len() > 16 * 1024 * 1024 {
            return Err(err("input exceeds size limit"));
        }
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    }
    input_value(opts)
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
        let file = nkeepass::private_file::new_private_temp(&parent).map_err(|error| {
            if nkeepass::private_file::capability_query_failed(&error) {
                err("cannot query filesystem ACL capability")
            } else if error.kind() == io::ErrorKind::Unsupported {
                err("filesystem cannot verify persistent owner-only ACL support")
            } else if error.kind() == io::ErrorKind::NotFound {
                err(diagnostics.staging)
            } else {
                err(diagnostics.permissions)
            }
        })?;
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
    let mut output = io::stdout().lock();
    output.write_all(bytes).map_err(|_| err(error))?;
    output.flush().map_err(|_| err(error))
}

// Formatted output is commonly redirected to a terminal or evaluated by a
// shell. Permit line feeds because the established dotenv/shell contract
// treats them as escaped/quoted data, but reject every other Unicode control
// character (including ESC, BEL, DEL, and C1 controls) before writing bytes.
fn validate_formatted_controls(value: &str) -> Result<()> {
    if value.chars().any(|character| {
        (character.is_control() && character != '\n')
            || nkeepass::template::is_bidi_or_line_separator(character)
    }) {
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
const GITHUB_EOF: &str = "NKP_EOF";

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

/// Compare the namespace the consumer will assign, not just the spelling we
/// print. Named output accepts ASCII identifiers, so ASCII folding is enough.
/// PowerShell output is conservatively Windows-safe even when rendered on Unix.
fn validate_binding_names<'a>(
    format: &str,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let case_insensitive = matches!(
        format,
        "azure-devops" | "github-actions" | "pwsh" | "powershell"
    ) || (cfg!(windows) && format == "dotenv");
    let mut seen = BTreeSet::new();
    for name in names {
        let key = if case_insensitive {
            Cow::Owned(name.to_ascii_uppercase())
        } else {
            Cow::Borrowed(name)
        };
        if !seen.insert(key) {
            return Err(err("output names collide for selected format"));
        }
    }
    Ok(())
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
fn emit_shell_value(output: &mut impl Write, name: &str, value: &str) -> Result<()> {
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
/// escape. ASCII `'` is doubled (`''`), while PowerShell Unicode curly single
/// quotes (`U+2018..=U+201B`) are split and concatenated via `[char]0x2018..`
/// because PowerShell's lexer treats them as single-quote delimiters.
fn emit_powershell_value(output: &mut impl Write, name: &str, value: &str) -> Result<()> {
    let has_curly = value
        .chars()
        .any(|ch| matches!(ch, '\u{2018}'..='\u{201B}'));
    write!(output, "$env:{name} = ").map_err(|_| err("cannot write value"))?;
    if has_curly {
        output
            .write_all(b"(")
            .map_err(|_| err("cannot write value"))?;
    }
    output
        .write_all(b"'")
        .map_err(|_| err("cannot write value"))?;
    for ch in value.chars() {
        match ch {
            '\'' => output
                .write_all(b"''")
                .map_err(|_| err("cannot write value"))?,
            '\u{2018}'..='\u{201B}' => {
                write!(output, "' + [char]0x{:04X} + '", u32::from(ch))
                    .map_err(|_| err("cannot write value"))?;
            }
            other => {
                let mut buf = [0_u8; 4];
                let encoded = other.encode_utf8(&mut buf);
                output
                    .write_all(encoded.as_bytes())
                    .map_err(|_| err("cannot write value"))?;
            }
        }
    }
    output
        .write_all(b"'")
        .map_err(|_| err("cannot write value"))?;
    if has_curly {
        output
            .write_all(b")")
            .map_err(|_| err("cannot write value"))?;
    }
    output
        .write_all(b"\n")
        .map_err(|_| err("cannot write value"))
}

/// `NAME<<NKP_EOF` / value / `NKP_EOF`, the `$GITHUB_OUTPUT` form.
///
/// Nothing is quoted, so there is no value that can break out of the block and no
/// escape to get wrong. That is the reason to prefer it over the deprecated
/// `::set-output name=value` workflow command, which is a quoted string the
/// runner has to parse, and which GitHub has scheduled for removal.
fn emit_github_actions_value(output: &mut impl Write, name: &str, value: &str) -> Result<()> {
    writeln!(output, "{name}<<{GITHUB_EOF}\n{value}\n{GITHUB_EOF}")
        .map_err(|_| err("cannot write value"))
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
fn emit_azure_devops_value(
    output: &mut impl Write,
    name: &str,
    value: &str,
    is_output: bool,
) -> Result<()> {
    let is_output = if is_output { ";isOutput=true" } else { "" };
    writeln!(
        output,
        "##vso[task.setvariable variable={name}{is_output}]{value}"
    )
    .map_err(|_| err("cannot write value"))
}

fn emit_value(value: &[u8], format: &str, name: Option<&str>, is_output: bool) -> Result<()> {
    write_value_for_sink(
        &mut io::stdout().lock(),
        value,
        format,
        name,
        is_output,
        io::stdout().is_terminal(),
    )
}

fn write_value_for_sink(
    output: &mut impl Write,
    value: &[u8],
    format: &str,
    name: Option<&str>,
    is_output: bool,
    stdout_is_tty: bool,
) -> Result<()> {
    if is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    match format {
        "text" => {
            if stdout_is_tty {
                validate_tty_raw_bytes(value)?;
            }
            output
                .write_all(value)
                .and_then(|()| output.flush())
                .map_err(|_| err("cannot write value"))
        }
        "null" => {
            if stdout_is_tty {
                validate_tty_raw_bytes(value)?;
            }
            output
                .write_all(value)
                .and_then(|()| output.write_all(b"\0"))
                .and_then(|()| output.flush())
                .map_err(|_| err("cannot write value"))
        }
        "json" => {
            let text = std::str::from_utf8(value).map_err(|_| err("value is not UTF-8"))?;
            if stdout_is_tty {
                let mut serializer =
                    serde_json::Serializer::with_formatter(&mut *output, TtyJsonFormatter);
                let mut map = serializer
                    .serialize_map(Some(1))
                    .map_err(|_| err("cannot encode output"))?;
                map.serialize_entry("value", text)
                    .map_err(|_| err("cannot encode output"))?;
                map.end().map_err(|_| err("cannot encode output"))?;
            } else {
                let mut serializer = serde_json::Serializer::new(&mut *output);
                let mut map = serializer
                    .serialize_map(Some(1))
                    .map_err(|_| err("cannot encode output"))?;
                map.serialize_entry("value", text)
                    .map_err(|_| err("cannot encode output"))?;
                map.end().map_err(|_| err("cannot encode output"))?;
            }
            output
                .write_all(b"\n")
                .and_then(|()| output.flush())
                .map_err(|_| err("cannot write value"))
        }
        "dotenv" => {
            let (name, text) = named_text(format, name, value)?;
            write!(output, "{name}=").map_err(|_| err("cannot write value"))?;
            serde_json::to_writer(&mut *output, text).map_err(|_| err("cannot encode value"))?;
            output
                .write_all(b"\n")
                .and_then(|()| output.flush())
                .map_err(|_| err("cannot write value"))
        }
        "shell" => {
            let (name, text) = named_text(format, name, value)?;
            emit_shell_value(output, name, text)?;
            output.flush().map_err(|_| err("cannot write value"))
        }
        "pwsh" | "powershell" => {
            let (name, text) = named_text(format, name, value)?;
            emit_powershell_value(output, name, text)?;
            output.flush().map_err(|_| err("cannot write value"))
        }
        "github-actions" => {
            let (name, text) = named_text(format, name, value)?;
            emit_github_actions_value(output, name, text)?;
            output.flush().map_err(|_| err("cannot write value"))
        }
        "azure-devops" => {
            let (name, text) = named_text(format, name, value)?;
            emit_azure_devops_value(output, name, text, is_output)?;
            output.flush().map_err(|_| err("cannot write value"))
        }
        _ => Err(err("invalid output format")),
    }
}

/// Copies an explicitly selected secret without sending plaintext to stdout.
/// On Linux, keeps this process alive for the bounded paste interval because
/// the clipboard provider may need its owner to serve pasted data. Windows
/// conditionally clears after that interval only if the clipboard owner is
/// still this process.
fn copy_secret_to_clipboard(value: Zeroizing<String>) -> Result<()> {
    use crate::clipboard::{ArboardAdapter, ClipboardCopyOutcome, copy_with_lifetime};
    use std::time::Duration;

    let ttl = Duration::from_secs(30);
    let copied = copy_with_lifetime(
        ArboardAdapter::default(),
        value,
        ttl,
        cfg!(target_os = "linux"),
        |duration| {
            if cfg!(target_os = "linux") {
                let _ = writeln!(
                    io::stderr(),
                    "nkp: keeping clipboard available for up to 30 seconds"
                );
            }
            std::thread::sleep(duration);
        },
    )
    .map_err(|_| err("clipboard is unavailable"))?;
    match copied {
        ClipboardCopyOutcome::RejectedNul => {
            return Err(err("value cannot be copied to clipboard"));
        }
        ClipboardCopyOutcome::MayHaveCopied => {
            return Err(err("clipboard write may have been incomplete"));
        }
        ClipboardCopyOutcome::TimedClearFailed => {
            return Err(err(
                "clipboard could not be cleared; the copied secret may remain",
            ));
        }
        ClipboardCopyOutcome::Copied => {}
    }
    if !cfg!(windows) && !cfg!(target_os = "linux") {
        let _ = writeln!(
            io::stderr(),
            "nkp: clipboard may retain the secret; this platform cannot safely clear it"
        );
    }
    Ok(())
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
                if opts.format == Some("keepass-xml") {
                    service
                        .import_keepass_xml(
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
                            "format": "keepass-xml",
                            "dry_run": opts.dry_run,
                        }),
                        !opts.dry_run,
                    )
                } else {
                    if let Some(format) = opts.format
                        && format != "json"
                    {
                        return Err(err("unsupported import format"));
                    }
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
            }
            "export" => {
                let xml = opts.format == Some("keepass-xml");
                if let Some(format) = opts.format
                    && !matches!(format, "json" | "keepass-xml")
                {
                    return Err(err("unsupported export format"));
                }
                if xml && !opts.allow_plaintext {
                    return Err(err(
                        "KeePass XML export is plaintext; pass --allow-plaintext to confirm",
                    ));
                }
                if !xml && opts.allow_plaintext {
                    return Err(err(
                        "--allow-plaintext is only valid with --format keepass-xml",
                    ));
                }
                let snapshot = if xml {
                    service.export_keepass_xml_allow_plaintext()
                } else {
                    service.export_snapshot()
                }
                .map_err(|error| err(error.message()))?;
                write_private_output(
                    opts.output.ok_or_else(|| err("--output required"))?,
                    snapshot.bytes(),
                )?;
                (
                    serde_json::json!({
                        "operation": "export",
                        "format": if xml { "keepass-xml" } else { interchange::FORMAT },
                        "version": if xml { None } else { Some(interchange::VERSION) },
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

fn validate_new_options(action: &str, opts: &Options<'_>) -> Result<()> {
    if action != "set"
        && (opts.literal_input.is_some()
            || opts.value_env.is_some()
            || opts.value_alias
            || opts.generate
            || !opts.assignment_inputs.is_empty())
    {
        return Err(err(
            "value sources and field assignments are only valid for set",
        ));
    }
    if (opts.generation_policy.selected() || opts.chars_alias)
        && action != "ensure"
        && !(action == "set" && opts.generate)
    {
        return Err(err("generator options require ensure or set --generate"));
    }
    if action == "set" && opts.size.is_some() && !opts.generate {
        return Err(err("--size requires --generate"));
    }
    if action == "ensure" || (action == "set" && opts.generate) {
        opts.generation_policy
            .validate(opts.size.unwrap_or(16))
            .map_err(|_| err("invalid size for selected character classes"))?;
    }
    if opts.age_decrypt && opts.generate {
        return Err(err("--age-decrypt conflicts with --generate"));
    }
    Ok(())
}

fn validate_output_format_options(opts: &Options<'_>) -> Result<&'static str> {
    let format = match opts.format.unwrap_or("text") {
        "text" => "text",
        "json" => "json",
        "null" => "null",
        "dotenv" => "dotenv",
        "shell" => "shell",
        "pwsh" => "pwsh",
        "powershell" => "powershell",
        "github-actions" => "github-actions",
        "azure-devops" => "azure-devops",
        _ => return Err(err("invalid output format")),
    };
    if is_named_format(format) && opts.name.is_none() {
        return Err(err("--name required for formatted output"));
    }
    if !is_named_format(format) && opts.name.is_some() {
        return Err(err("--name requires a named output format"));
    }
    if !opts.name.is_none_or(valid_env_name) {
        return Err(err("invalid output name"));
    }
    if opts.is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    Ok(format)
}

#[allow(
    clippy::too_many_lines,
    reason = "the explicit per-action option allowlist is easier to audit in one place"
)]
fn validate_regular_options(action: &str, opts: &Options<'_>) -> Result<()> {
    validate_new_options(action, opts)?;
    if opts.clipboard && action != "get" {
        return Err(err("--clipboard is only valid for get"));
    }
    if action != "set"
        && (opts.username.is_some()
            || opts.url.is_some()
            || opts.notes.is_some()
            || !opts.bins.is_empty())
    {
        return Err(err("set-only option used with another command"));
    }
    if vault_creation_options(opts) {
        return Err(err("invalid operation option"));
    }
    let allowed = match action {
        "ls" | "search" => AllowedOptions {
            allow_glob: true,
            allow_format: true,
            ..AllowedOptions::none()
        },
        "group-ls" => AllowedOptions::none(),
        "show" | "field-ls" | "attachment-ls" => AllowedOptions {
            allow_key: true,
            allow_format: true,
            ..AllowedOptions::none()
        },
        "get" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_format: true,
            allow_name: true,
            allow_is_output: true,
            allow_clipboard: true,
            allow_age_encrypt: true,
            allow_age_recipients: true,
            allow_output: true,
            ..AllowedOptions::none()
        },
        "get-many" => AllowedOptions {
            allow_requested_paths: true,
            allow_field: true,
            allow_format: true,
            allow_is_output: true,
            allow_age_encrypt: true,
            allow_age_recipients: true,
            allow_output: true,
            ..AllowedOptions::none()
        },
        "field-get" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_format: true,
            allow_name: true,
            allow_is_output: true,
            ..AllowedOptions::none()
        },
        "otp" => AllowedOptions {
            allow_key: true,
            allow_format: true,
            allow_name: true,
            allow_is_output: true,
            ..AllowedOptions::none()
        },
        "set" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_assignments: true,
            allow_literal_input: true,
            allow_value_env: true,
            allow_value_aliases: true,
            allow_chars_alias: true,
            allow_generate: true,
            allow_generation_policy: true,
            allow_size: true,
            allow_username: true,
            allow_url: true,
            allow_notes: true,
            allow_bins: true,
            allow_file: true,
            allow_stdin: true,
            allow_age_decrypt: true,
            allow_age_identity: true,
            ..AllowedOptions::none()
        },
        "field-set" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_file: true,
            allow_stdin: true,
            ..AllowedOptions::none()
        },
        "attachment-add" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_name: true,
            allow_file: true,
            allow_stdin: true,
            ..AllowedOptions::none()
        },
        "attachment-get" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_name: true,
            allow_output: true,
            ..AllowedOptions::none()
        },
        "rm" => AllowedOptions {
            allow_key: true,
            allow_yes: true,
            ..AllowedOptions::none()
        },
        "field-rm" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_yes: true,
            ..AllowedOptions::none()
        },
        "attachment-rm" => AllowedOptions {
            allow_key: true,
            allow_field: true,
            allow_name: true,
            allow_yes: true,
            ..AllowedOptions::none()
        },
        "ensure" => AllowedOptions {
            allow_key: true,
            allow_size: true,
            allow_chars_alias: true,
            allow_generation_policy: true,
            allow_dry_run: true,
            ..AllowedOptions::none()
        },
        "group-add" => AllowedOptions {
            allow_key: true,
            allow_dry_run: true,
            ..AllowedOptions::none()
        },
        "group-rm" => AllowedOptions {
            allow_key: true,
            allow_yes: true,
            allow_dry_run: true,
            ..AllowedOptions::none()
        },
        _ => return Err(err("unknown operation")),
    };
    validate_allowed_options(
        opts,
        &allowed,
        "invalid operation option",
        Some("--allow-plaintext is only valid for KeePass XML export"),
        "age options are only valid for get, get many, and set",
    )?;

    match action {
        "ls" => {
            MetadataFormat::parse(opts.format)?;
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
        }
        "search" => {
            MetadataFormat::parse(opts.format)?;
            let query = opts.glob.ok_or_else(|| err("search query required"))?;
            if query.is_empty() || query.len() > MAX_SEARCH_QUERY_BYTES {
                return Err(err("invalid search query"));
            }
        }
        "show" | "group-add" | "group-rm" => {
            if action == "show" {
                MetadataFormat::parse(opts.format)?;
            }
            if opts.key.is_none() {
                return Err(err("invalid operation option"));
            }
            if action == "group-rm" && !opts.yes && !opts.dry_run {
                return Err(err("removal requires --yes"));
            }
        }
        "get" => {
            if (opts.output.is_some() && !opts.age_encrypt)
                || (!opts.age_encrypt && !opts.age_recipients.is_empty())
                || (opts.age_encrypt && opts.age_recipients.is_empty())
            {
                return Err(err("invalid operation option"));
            }
            opts.key.ok_or_else(|| err("--key required"))?;
            let format = validate_output_format_options(opts)?;
            if opts.age_encrypt && (format != "text" || opts.name.is_some() || opts.is_output) {
                return Err(err("age encryption requires plain get output"));
            }
            if opts.clipboard
                && (format != "text"
                    || opts.name.is_some()
                    || opts.is_output
                    || opts.output.is_some()
                    || opts.age_encrypt)
            {
                return Err(err("--clipboard requires plain get output"));
            }
        }
        "get-many" => {
            if opts.requested_paths.is_empty() || opts.requested_paths.len() > 256 {
                return Err(err("get many requires 1 to 256 explicit paths"));
            }
            let mut seen = BTreeSet::new();
            if opts.requested_paths.iter().any(|path| !seen.insert(*path)) {
                return Err(err("get many paths must be unique"));
            }
            if opts
                .requested_paths
                .iter()
                .map(|path| path.len())
                .sum::<usize>()
                > 64 * 1024
            {
                return Err(err("get many paths exceed size limit"));
            }
            if (opts.output.is_some() && !opts.age_encrypt)
                || (!opts.age_encrypt && !opts.age_recipients.is_empty())
                || (opts.age_encrypt && opts.age_recipients.is_empty())
            {
                return Err(err("invalid operation option"));
            }
            let format = opts.format.unwrap_or("text");
            if is_named_format(format) {
                validate_binding_names(format, opts.requested_paths.iter().copied())?;
            }
            if !is_named_format(format) && !matches!(format, "text" | "json" | "null") {
                return Err(err("invalid output format"));
            }
            if opts.is_output && format != "azure-devops" {
                return Err(err("--is-output requires the azure-devops format"));
            }
        }
        "field-get" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            let field = opts.field.ok_or_else(|| err("--field required"))?;
            if matches!(field, "Password" | "Title" | "UserName" | "URL" | "Notes") {
                return Err(err("custom field required"));
            }
            validate_output_format_options(opts)?;
        }
        "otp" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            validate_output_format_options(opts)?;
        }
        "set" => {
            if opts.key.is_none() || (!opts.age_decrypt && opts.age_identity.is_some()) {
                return Err(err("invalid operation option"));
            }
            let has_input = opts.file.is_some()
                || opts.stdin
                || opts.literal_input.is_some()
                || opts.value_env.is_some();
            if opts.field.is_some()
                && !has_input
                && !opts.generate
                && !opts.assignment_inputs.is_empty()
            {
                return Err(err(
                    "legacy --field NAME requires a value source when combined with assignments",
                ));
            }
            if opts.age_decrypt && !has_input {
                return Err(err("age decryption requires an explicit value source"));
            }
        }
        "field-set" => {
            if opts.key.is_none() || (opts.file.is_none() && !opts.stdin) {
                return Err(err("invalid operation option"));
            }
            let field = opts.field.unwrap_or("Password");
            if opts.field.is_none()
                || matches!(field, "Password" | "Title" | "UserName" | "URL" | "Notes")
            {
                return Err(err("custom field required"));
            }
        }
        "attachment-add" => {
            if opts.key.is_none() || (opts.file.is_none() && !opts.stdin) {
                return Err(err("invalid operation option"));
            }
            if opts.field.is_some() && opts.name.is_some() {
                return Err(err(
                    "attachment name specified more than once; use positional NAME, --name, or --field",
                ));
            }
            let name = opts
                .field
                .or(opts.name)
                .ok_or_else(|| err("attachment name required"))?;
            if name.is_empty()
                || name.contains('/')
                || !nkeepass::template::is_safe_display_text(name)
            {
                return Err(err("invalid attachment name"));
            }
        }
        "attachment-get" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            if opts.field.is_some() && opts.name.is_some() {
                return Err(err(
                    "attachment name specified more than once; use positional NAME, --name, or --field",
                ));
            }
            opts.field
                .or(opts.name)
                .ok_or_else(|| err("attachment name required"))?;
            opts.output.ok_or_else(|| err("--output required"))?;
        }
        "rm" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            if !opts.yes {
                return Err(err("removal requires --yes"));
            }
        }
        "field-rm" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            let field = opts.field.ok_or_else(|| err("--field required"))?;
            if matches!(field, "Password" | "Title" | "UserName" | "URL" | "Notes") {
                return Err(err("custom field required"));
            }
            if !opts.yes {
                return Err(err("removal requires --yes"));
            }
        }
        "attachment-rm" => {
            opts.key.ok_or_else(|| err("--key required"))?;
            if opts.field.is_some() && opts.name.is_some() {
                return Err(err(
                    "attachment name specified more than once; use positional NAME, --name, or --field",
                ));
            }
            opts.field
                .or(opts.name)
                .ok_or_else(|| err("attachment name required"))?;
            if !opts.yes {
                return Err(err("removal requires --yes"));
            }
        }
        "ensure" | "field-ls" | "attachment-ls" => {
            if matches!(action, "field-ls" | "attachment-ls") {
                MetadataFormat::parse(opts.format)?;
            }
            opts.key.ok_or_else(|| err("--key required"))?;
        }
        _ => {}
    }
    Ok(())
}

// Shared parsers must not silently downgrade a request for encryption to plaintext.
fn reject_age_options(opts: &Options<'_>) -> Result<()> {
    if opts.age_encrypt
        || opts.age_decrypt
        || !opts.age_recipients.is_empty()
        || opts.age_identity.is_some()
    {
        return Err(err("age options are not supported for this command"));
    }
    Ok(())
}

fn validate_automation_options(action: &str, opts: &Options<'_>) -> Result<()> {
    validate_new_options(action, opts)?;
    reject_age_options(opts)
        .map_err(|_| err("age options are not supported for automation commands"))?;
    if vault_creation_options(opts) {
        return Err(err("invalid operation option"));
    }
    match action {
        "import" => {
            let allowed = AllowedOptions {
                allow_file: true,
                allow_stdin: true,
                allow_replace: true,
                allow_dry_run: true,
                allow_format: true,
                ..AllowedOptions::none()
            };
            validate_allowed_options(
                opts,
                &allowed,
                "invalid import option",
                None,
                "age options are not supported for automation commands",
            )?;
            if usize::from(opts.file.is_some()) + usize::from(opts.stdin) != 1 {
                return Err(err("invalid import option"));
            }
            if let Some(format) = opts.format
                && !matches!(format, "json" | "keepass-xml")
            {
                return Err(err("unsupported import format"));
            }
        }
        "export" => {
            let allowed = AllowedOptions {
                allow_output: true,
                allow_format: true,
                allow_allow_plaintext: true,
                ..AllowedOptions::none()
            };
            validate_allowed_options(
                opts,
                &allowed,
                "invalid export option",
                None,
                "age options are not supported for automation commands",
            )?;
            if opts.output.is_none() {
                return Err(err("invalid export option"));
            }
            let xml = opts.format == Some("keepass-xml");
            if let Some(format) = opts.format
                && !matches!(format, "json" | "keepass-xml")
            {
                return Err(err("unsupported export format"));
            }
            if opts.allow_plaintext && !xml {
                return Err(err(
                    "--allow-plaintext is only valid with --format keepass-xml",
                ));
            }
            if xml && !opts.allow_plaintext {
                return Err(err(
                    "KeePass XML export is plaintext; pass --allow-plaintext to confirm",
                ));
            }
        }
        "sync" => {
            let allowed = AllowedOptions {
                allow_file: true,
                allow_stdin: true,
                allow_strategy: true,
                allow_dry_run: true,
                ..AllowedOptions::none()
            };
            validate_allowed_options(
                opts,
                &allowed,
                "invalid sync option",
                None,
                "age options are not supported for automation commands",
            )?;
            if usize::from(opts.file.is_some()) + usize::from(opts.stdin) != 1 {
                return Err(err("invalid sync option"));
            }
            if let Some(strategy) = opts.strategy {
                nkeepass::SyncStrategy::parse(strategy).map_err(|error| err(error.message()))?;
            }
        }
        _ => return Err(err("unknown operation")),
    }
    Ok(())
}

/// A preallocated, zeroizing, bounded renderer. Capacity is chosen before any
/// plaintext is written so Vec growth never leaves secret-bearing old buffers.
struct BundleBuffer(Zeroizing<Vec<u8>>);

impl Write for BundleBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.len()
            || bytes.len() > (64 * 1024 * 1024_usize).saturating_sub(self.0.len())
        {
            return Err(io::Error::other("bundle exceeds output limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn get_many(
    opts: &Options<'_>,
    path: &Path,
    credentials: &mut KdbxCredentials,
    config: &Config,
) -> Result<()> {
    let mut service = VaultService::default();
    let session = service
        .open(path, credentials, &KDBX_LIMITS)
        .map_err(|error| err(error.message()))?;
    let result = (|| {
        let mut bindings = Vec::with_capacity(opts.requested_paths.len());
        let mut total = 0_usize;
        let mut worst_encoded = 0_usize;
        for supplied in &opts.requested_paths {
            let selector = if let Some(alias) = config.aliases.get(*supplied) {
                if alias.kind != Kind::Entry {
                    return Err(err("entry alias required"));
                }
                entry_path(&alias.target)?;
                if alias.target != *supplied {
                    match service.resolve_entry(session, supplied) {
                        Ok(_) => return Err(err("ambiguous entry selector")),
                        Err(nkeepass::ServiceError::NotFound) => {}
                        Err(error) => return Err(err(error.message())),
                    }
                }
                alias.target.as_str()
            } else {
                supplied
            };
            let entry = service
                .resolve_entry(session, selector)
                .map_err(|error| match error {
                    // Do not send user/vault labels through suggestion errors
                    // during a multi-value disclosure.
                    nkeepass::ServiceError::NotFound => err("get many entry not found"),
                    error => err(error.message()),
                })?;
            let value = reveal_service_field(&service, &entry, opts.field.unwrap_or("Password"))?;
            total = total
                .checked_add(value.as_slice().len())
                .filter(|total| *total <= 16 * 1024 * 1024)
                .ok_or_else(|| err("get many values exceed size limit"))?;
            worst_encoded = worst_encoded.saturating_add(
                value
                    .as_slice()
                    .len()
                    .saturating_add(supplied.len())
                    .saturating_mul(6)
                    .saturating_add(128),
            );
            bindings.push(((*supplied).to_owned(), value));
        }
        let mut bundle = BundleBuffer(Zeroizing::new(Vec::with_capacity(
            worst_encoded.min(64 * 1024 * 1024),
        )));
        write_environment_for_sink(
            &mut bundle,
            &bindings,
            opts.format.unwrap_or("text"),
            opts.is_output,
            true,
            !opts.age_encrypt && io::stdout().is_terminal(),
        )?;
        if opts.age_encrypt {
            let recipients = age_recipients(&opts.age_recipients)?;
            let encrypted = AgeFile::encrypt_armored(&bundle.0, &recipients)
                .map_err(|_| err("age encryption failed"))?;
            if let Some(output) = opts.output {
                write_private_output(output, encrypted.as_bytes())
            } else {
                let mut output = io::stdout().lock();
                output
                    .write_all(encrypted.as_bytes())
                    .and_then(|()| output.write_all(b"\n"))
                    .and_then(|()| output.flush())
                    .map_err(|_| err("cannot write encrypted output"))
            }
        } else {
            write_stdout(&bundle.0, "cannot write value")
        }
    })();
    let locked = service.lock(session).map_err(|error| err(error.message()));
    result?;
    locked?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "shared command handler keeps nested and shortcut operations identical"
)]
fn operation(action: &str, args: &[String], vault: Option<&str>, config: &Config) -> Result<()> {
    if action == "get" && args.first().is_some_and(|argument| argument == "many") {
        return operation("get-many", &args[1..], vault, config);
    }
    if !matches!(
        action,
        "ls" | "search"
            | "show"
            | "field-ls"
            | "get"
            | "get-many"
            | "field-get"
            | "attachment-ls"
            | "attachment-get"
            | "set"
            | "field-set"
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
    if matches!(action, "import" | "export" | "sync") {
        validate_automation_options(action, &opts)?;
    } else {
        validate_regular_options(action, &opts)?;
    }
    if matches!(action, "get" | "set") && opts.field.is_none() {
        opts.field = opts
            .key
            .and_then(|name| config.aliases.get(name))
            .and_then(|alias| alias.field.as_deref());
    }
    let requires_key = !matches!(
        action,
        "ls" | "search" | "import" | "export" | "sync" | "group-ls" | "get-many"
    );
    let selector = if requires_key {
        Some(opts.key.ok_or_else(|| err("--key required"))?)
    } else {
        None
    };
    let (path, _) = active_vault(vault, config)?;
    let mut credentials = credentials(&opts)?;
    if action == "get-many" {
        return get_many(&opts, &path, &mut credentials, config);
    }
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
        let format = MetadataFormat::parse(opts.format)?;
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
        let mut human_hits = Vec::new();
        let outcome = (|| -> Result<()> {
            loop {
                let page = service
                    .search_page(session, query, cursor)
                    .map_err(|error| err(error.message()))?;
                withheld = withheld.saturating_add(page.withheld);
                for hit in page.hits {
                    match format {
                        MetadataFormat::Json => {
                            if safe_search_hit(&hit) {
                                write_search_hit(&hit)?;
                            } else {
                                withheld = withheld.saturating_add(1);
                                continue;
                            }
                        }
                        MetadataFormat::Human => human_hits.push(hit),
                    }
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
            if format == MetadataFormat::Human {
                let lines = render_search_hits_human(
                    &human_hits,
                    "(no matches)",
                    human_output_width(),
                    current_stdout_style(),
                );
                write_human_lines(&lines)?;
            }
            Ok(())
        })();
        report_withheld(withheld);
        let locked = service.lock(session).map_err(|error| err(error.message()));
        outcome?;
        locked?;
        return Ok(());
    }
    if action == "ls" {
        if opts.key.is_some() || opts.field.is_some() || opts.name.is_some() {
            return Err(err("invalid list option"));
        }
        let format = MetadataFormat::parse(opts.format)?;
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
        let mut human_hits = Vec::new();
        let outcome = (|| -> Result<()> {
            loop {
                let page = service
                    .list_page(session, opts.glob, cursor)
                    .map_err(|error| err(error.message()))?;
                withheld = withheld.saturating_add(page.withheld);
                match format {
                    MetadataFormat::Json => {
                        for hit in &page.hits {
                            if safe_search_hit(hit) {
                                write_search_hit(hit)?;
                            } else {
                                withheld = withheld.saturating_add(1);
                            }
                        }
                    }
                    MetadataFormat::Human => {
                        human_hits.extend(page.hits);
                    }
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
            if format == MetadataFormat::Human {
                let lines = render_search_hits_human(
                    &human_hits,
                    "(no entries)",
                    human_output_width(),
                    current_stdout_style(),
                );
                write_human_lines(&lines)?;
            }
            Ok(())
        })();
        report_withheld(withheld);
        let locked = service.lock(session).map_err(|error| err(error.message()));
        outcome?;
        locked?;
        return Ok(());
    }
    if matches!(action, "show" | "field-ls") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let format = MetadataFormat::parse(opts.format)?;
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
                write_selected_entry(&selected, output_path, format)
            } else {
                let fields = service
                    .field_metadata(&resolved.reference())
                    .map_err(|error| err(error.message()))?;
                write_selected_fields(&fields, format)
            }
        })();
        let locked = service.lock(session).map_err(|error| err(error.message()));
        result?;
        locked?;
        return Ok(());
    }
    if matches!(action, "get" | "field-get") {
        let selector = selector.ok_or_else(|| err("--key required"))?;
        let format = opts.format.unwrap_or("text");
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
        if opts.clipboard
            && (action != "get"
                || format != "text"
                || opts.name.is_some()
                || opts.is_output
                || opts.output.is_some()
                || opts.age_encrypt)
        {
            return Err(err("--clipboard requires plain get output"));
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
                    let mut output = io::stdout().lock();
                    output
                        .write_all(encrypted.as_bytes())
                        .and_then(|()| output.write_all(b"\n"))
                        .and_then(|()| output.flush())
                        .map_err(|_| err("cannot write encrypted output"))
                }
            } else if opts.clipboard {
                let text = std::str::from_utf8(value.as_slice())
                    .map_err(|_| err("clipboard requires UTF-8 text"))?;
                copy_secret_to_clipboard(Zeroizing::new(text.to_owned()))
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
                    .or(opts.name)
                    .ok_or_else(|| err("attachment name required"))?,
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
                let format = MetadataFormat::parse(opts.format)?;
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
                match format {
                    MetadataFormat::Json => {
                        for attachment in attachments {
                            json(&serde_json::json!({
                                "name": attachment.name(),
                                "bytes": attachment.size(),
                                "protected": attachment.protected(),
                            }))?;
                        }
                    }
                    MetadataFormat::Human => {
                        let lines = render_attachments_human(
                            &attachments,
                            human_output_width(),
                            current_stdout_style(),
                        );
                        write_human_lines(&lines)?;
                    }
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
        let has_input = opts.file.is_some()
            || opts.stdin
            || opts.literal_input.is_some()
            || opts.value_env.is_some();
        if opts.field.is_some()
            && !has_input
            && !opts.generate
            && !opts.assignment_inputs.is_empty()
        {
            return Err(err(
                "legacy --field NAME requires a value source when combined with assignments",
            ));
        }
        if opts.age_decrypt && !has_input {
            return Err(err("age decryption requires an explicit value source"));
        }
        let mut updates = Vec::new();
        if has_input {
            let bytes = set_input_value(&opts)?;
            let bytes = if opts.age_decrypt {
                let identities = selected_age_identities(opts.age_identity)?;
                decrypt_age_input(&bytes, &identities)?
            } else {
                bytes
            };
            let value = Zeroizing::new(
                String::from_utf8(bytes.to_vec()).map_err(|_| err("field requires UTF-8"))?,
            );
            updates.push(FieldUpdate {
                key: name.to_owned(),
                value,
                protected: None,
                protect_in_memory: None,
            });
        }
        if opts.generate {
            updates.push(FieldUpdate {
                key: name.to_owned(),
                value: opts
                    .generation_policy
                    .generate(opts.size.unwrap_or(16))
                    .map_err(|error| err(error.message()))?,
                protected: None,
                protect_in_memory: None,
            });
        }
        for specification in &opts.assignment_inputs {
            let (key, value) = specification
                .split_once('=')
                .ok_or_else(|| err("--field requires NAME=VALUE"))?;
            if key.is_empty() || !nkeepass::template::is_safe_display_text(key) {
                return Err(err("invalid field name"));
            }
            updates.push(FieldUpdate {
                key: key.to_owned(),
                value: Zeroizing::new(value.to_owned()),
                protected: None,
                protect_in_memory: None,
            });
        }
        for (key, value) in [
            ("UserName", opts.username),
            ("URL", opts.url),
            ("Notes", opts.notes),
        ] {
            if let Some(value) = value {
                updates.push(FieldUpdate {
                    key: key.to_owned(),
                    value: Zeroizing::new(value.to_owned()),
                    protected: None,
                    protect_in_memory: None,
                });
            }
        }
        if action == "set" && updates.is_empty() && opts.bins.is_empty() {
            if !io::stdin().is_terminal() {
                return Err(err("value input requires a terminal or an explicit source"));
            }
            let _ = write!(io::stderr(), "Value (hidden; 60 second timeout): ");
            io::stderr()
                .flush()
                .map_err(|_| err("cannot write prompt"))?;
            let value = terminal_password::read(std::time::Duration::from_secs(60));
            let _ = writeln!(io::stderr());
            updates.push(FieldUpdate {
                key: name.to_owned(),
                value: value.map_err(|error| err(error.to_string()))?,
                protected: None,
                protect_in_memory: None,
            });
        }
        let mut update_names = BTreeSet::new();
        if updates
            .iter()
            .any(|update| !update_names.insert(update.key.as_str()))
        {
            return Err(err("field specified more than once"));
        }
        let mut binaries = Vec::with_capacity(opts.bins.len());
        let mut binary_names = BTreeSet::new();
        let mut total_binary_bytes = 0usize;
        if opts.bins.len() > 256 {
            return Err(err("too many attachment inputs"));
        }
        for specification in &opts.bins {
            let (binary_name, file_path) = specification
                .split_once('=')
                .ok_or_else(|| err("--bin requires NAME=FILE_PATH"))?;
            if binary_name.is_empty()
                || file_path.is_empty()
                || binary_name.contains('/')
                || !nkeepass::template::is_safe_display_text(binary_name)
            {
                return Err(err("invalid --bin NAME=FILE_PATH"));
            }
            if !binary_names.insert(binary_name) {
                return Err(err("duplicate attachment name"));
            }
            let remaining = 16 * 1024 * 1024usize - total_binary_bytes;
            let bytes = bounded_file(file_path, remaining as u64)?;
            total_binary_bytes = total_binary_bytes
                .checked_add(bytes.len())
                .filter(|size| *size <= 16 * 1024 * 1024)
                .ok_or_else(|| err("attachment input exceeds size limit"))?;
            binaries.push((binary_name, bytes));
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
            for (binary_name, bytes) in binaries {
                let resolved = service
                    .resolve_entry(session, entry_selector)
                    .map_err(|error| match error {
                        nkeepass::ServiceError::NotFound => {
                            entry_not_found(&service, session, entry_selector)
                        }
                        error => err(error.message()),
                    })?;
                service
                    .add_attachment(&resolved.reference(), binary_name, bytes)
                    .map_err(|error| match error {
                        nkeepass::ServiceError::AttachmentExists => {
                            err("attachment already exists")
                        }
                        nkeepass::ServiceError::Ambiguous => err("ambiguous attachment name"),
                        nkeepass::ServiceError::InvalidInput => err("invalid attachment name"),
                        error => err(error.message()),
                    })?;
            }
            if !updates.is_empty() {
                let resolved = service
                    .resolve_entry(session, entry_selector)
                    .map_err(|error| match error {
                        nkeepass::ServiceError::NotFound => {
                            entry_not_found(&service, session, entry_selector)
                        }
                        error => err(error.message()),
                    })?;
                if action == "field-set" {
                    let update = updates
                        .into_iter()
                        .next()
                        .ok_or_else(|| err("invalid field update"))?;
                    service
                        .set_custom_field(&resolved.reference(), &update.key, update.value.as_str())
                        .map_err(|error| err(error.message()))?;
                } else {
                    service
                        .set_fields_creating_custom(&resolved.reference(), updates)
                        .map_err(|error| match error {
                            nkeepass::ServiceError::DuplicateIds => {
                                err("vault contains duplicate object UUIDs")
                            }
                            nkeepass::ServiceError::DuplicateFields => {
                                err("entry contains duplicate fields")
                            }
                            nkeepass::ServiceError::AmbiguousField => err("ambiguous field name"),
                            nkeepass::ServiceError::InvalidFieldName => err("invalid field name"),
                            nkeepass::ServiceError::FieldConflict => {
                                err("title cannot be changed through set")
                            }
                            error => err(error.message()),
                        })?;
                }
            }
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
                .ensure_entry_with_policy(
                    session,
                    entry_selector,
                    opts.size.unwrap_or(16),
                    opts.dry_run,
                    opts.generation_policy,
                )
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
            .or(opts.name)
            .ok_or_else(|| err("attachment name required"))?;
        if action == "attachment-add"
            && (name.is_empty()
                || name.contains('/')
                || !nkeepass::template::is_safe_display_text(name))
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
                let mut withheld = 0usize;
                for group in metadata.groups {
                    if safe_metadata(&group) {
                        print_line(&group)?;
                    } else {
                        withheld += 1;
                    }
                }
                report_withheld(withheld);
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
    format: &'a str,
    common: Options<'a>,
}

fn parse_env_options(args: &[String]) -> Result<EnvOptions<'_>> {
    let mut bindings = Vec::new();
    let mut current: Option<(&str, Option<&str>)> = None;
    let mut common_refs: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--key" => {
                if current.is_some() {
                    return Err(err("--key must start a value binding"));
                }
                i += 1;
                current = Some((take_arg(args, i)?, None));
            }
            "--field" if current.is_none() => return Err(err("--key required before --field")),
            "--name" if current.is_none() => return Err(err("--name requires a value binding")),
            "--field" => {
                i += 1;
                let (key, field) = current.ok_or_else(|| err("--key required before --field"))?;
                if field.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                current = Some((key, Some(take_arg(args, i)?)));
            }
            "--name" => {
                i += 1;
                let name = take_arg(args, i)?;
                let (key, field) = current.take().ok_or_else(|| err("invalid value binding"))?;
                bindings.push(EnvBinding { key, field, name });
            }
            _ => {
                common_refs.push(arg);
                if takes_option_value(arg) {
                    i += 1;
                    common_refs.push(take_arg(args, i)?);
                }
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
    let common_options = options_from_refs(&common_refs, Positional::Forbidden)?;
    validate_new_options("env", &common_options)?;
    reject_age_options(&common_options)?;
    // `secrets env` has no value-file, mutation, clipboard, or interchange options.
    // Validate this allowlist before resolving a vault or reading credentials.
    let allowed = AllowedOptions {
        allow_format: true,
        allow_is_output: true,
        ..AllowedOptions::none()
    };
    validate_allowed_options(
        &common_options,
        &allowed,
        "invalid operation option",
        Some("--allow-plaintext is only valid for KeePass XML export"),
        "age options are not supported for this command",
    )?;
    let format = common_options.format.unwrap_or("shell");
    if !is_named_format(format) && !matches!(format, "json" | "null") {
        return Err(err("invalid output format"));
    }
    if common_options.is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    Ok(EnvOptions {
        bindings,
        format,
        common: common_options,
    })
}

fn emit_environment(
    bindings: &[(String, SecretBytes)],
    format: &str,
    is_output: bool,
) -> Result<()> {
    write_environment_for_sink(
        &mut io::stdout().lock(),
        bindings,
        format,
        is_output,
        false,
        io::stdout().is_terminal(),
    )
}

// Shared key/value formatting for env and get many. The latter supplies paths
// as names, and changes only text/null framing, not quoting or name validation.
fn write_environment_for_sink(
    output: &mut impl Write,
    bindings: &[(String, SecretBytes)],
    format: &str,
    is_output: bool,
    values_only: bool,
    stdout_is_tty: bool,
) -> Result<()> {
    if is_output && format != "azure-devops" {
        return Err(err("--is-output requires the azure-devops format"));
    }
    if is_named_format(format) {
        validate_binding_names(format, bindings.iter().map(|(name, _)| name.as_str()))?;
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
                    if stdout_is_tty {
                        if !values_only {
                            validate_tty_raw_bytes(name.as_bytes())?;
                        }
                        validate_tty_raw_bytes(value.as_slice())?;
                    }
                }
            }
            "text" if values_only => {
                if stdout_is_tty {
                    for (_, value) in bindings {
                        validate_tty_raw_bytes(value.as_slice())?;
                    }
                }
            }
            _ => return Err(err("invalid output format")),
        }
    }
    if is_named_format(format) {
        for (name, value) in bindings {
            write_value_for_sink(
                output,
                value.as_slice(),
                format,
                Some(name),
                is_output,
                stdout_is_tty,
            )?;
        }
        return Ok(());
    }
    match format {
        "text" if values_only => {
            for (index, (_, value)) in bindings.iter().enumerate() {
                if index > 0 {
                    output
                        .write_all(b",")
                        .map_err(|_| err("cannot write value"))?;
                }
                output
                    .write_all(value.as_slice())
                    .map_err(|_| err("cannot write value"))?;
            }
            output.flush().map_err(|_| err("cannot write value"))
        }
        "null" => {
            for (name, value) in bindings {
                if !values_only {
                    output
                        .write_all(name.as_bytes())
                        .and_then(|()| output.write_all(b"\0"))
                        .map_err(|_| err("cannot write value"))?;
                }
                output
                    .write_all(value.as_slice())
                    .and_then(|()| output.write_all(b"\0"))
                    .map_err(|_| err("cannot write value"))?;
            }
            output.flush().map_err(|_| err("cannot write value"))
        }
        "json" => {
            if stdout_is_tty {
                let mut serializer =
                    serde_json::Serializer::with_formatter(&mut *output, TtyJsonFormatter);
                let mut map = serializer
                    .serialize_map(Some(bindings.len()))
                    .map_err(|_| err("cannot encode output"))?;
                for (name, value) in bindings {
                    let text = std::str::from_utf8(value.as_slice())
                        .map_err(|_| err("value is not UTF-8"))?;
                    map.serialize_entry(name, text)
                        .map_err(|_| err("cannot encode output"))?;
                }
                map.end().map_err(|_| err("cannot encode output"))?;
            } else {
                let mut serializer = serde_json::Serializer::new(&mut *output);
                let mut map = serializer
                    .serialize_map(Some(bindings.len()))
                    .map_err(|_| err("cannot encode output"))?;
                for (name, value) in bindings {
                    let text = std::str::from_utf8(value.as_slice())
                        .map_err(|_| err("value is not UTF-8"))?;
                    map.serialize_entry(name, text)
                        .map_err(|_| err("cannot encode output"))?;
                }
                map.end().map_err(|_| err("cannot encode output"))?;
            }
            output
                .write_all(b"\n")
                .and_then(|()| output.flush())
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
    validate_new_options("init", opts)?;
    reject_age_options(opts)?;
    let allowed = AllowedOptions {
        allow_path: true,
        allow_size: true,
        allow_kdf: true,
        allow_json: true,
        allow_generate_master_password: true,
        ..AllowedOptions::none()
    };
    validate_allowed_options(
        opts,
        &allowed,
        "invalid operation option",
        Some("--allow-plaintext is only valid for KeePass XML export"),
        "age options are not supported for this command",
    )?;
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
/// `nkp` save already uses, and every override is bounded by the same
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
    let as_json = opts.json;
    let generate_master = opts.generate_master_password;
    let write = init_write_options(&opts)?;
    if generate_master
        && (opts.password.is_some()
            || opts.password_env.is_some()
            || opts.password_file.is_some()
            || opts.password_stdin
            || opts.key_file.is_some())
    {
        return Err(err(
            "generated master password cannot be combined with credential options",
        ));
    }

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

    // Both backup roots must be reportable before creating a password-only
    // vault. Keep these exact paths for the subsequent backup transaction.
    let backup_roots = if opts.key_file.is_none() {
        let roots = (|| {
            let config = config_dir()?;
            let data = data_dir()?;
            for root in [&config, &data] {
                if !root.to_str().is_some_and(safe_metadata) {
                    return Err(err("password backup directory is not safe to report"));
                }
            }
            Ok((config, data))
        })()
        .map_err(|error: CliError| err(format!("vault creation did not start; {}", error.0)))?;
        Some(roots)
    } else {
        None
    };

    let master_password = if generate_master {
        Some(
            nkeepass::service::generate_master_password()
                .map_err(|_| err("cannot generate master password"))?,
        )
    } else {
        password(&opts)?
    };
    let mut credentials =
        credentials_with_password(&opts, master_password.as_deref().map(String::as_str))?;
    // A generated master password must be recoverable even if creation installs
    // the vault but later reports a durability or configuration failure.
    let generated_backup = if generate_master {
        let (config_root, data_root) = backup_roots.as_ref().ok_or_else(|| {
            err("vault creation did not start; password backup roots unavailable")
        })?;
        let mut backup = backup_init_password_at(
            master_password
                .as_deref()
                .ok_or_else(|| err("cannot generate master password"))?,
            config_root,
            data_root,
        )?;
        if let Err(error) = associate_init_backup(&mut backup, &path_text) {
            // Reporting must not replace the original failure when stdout is
            // also unavailable. No vault installation has been attempted.
            let _ = write_association_failure(&backup, &path_text, &error, as_json);
            return Err(err(format!(
                "vault creation not started; {}",
                error.message
            )));
        }
        Some(backup)
    } else {
        None
    };
    let service = VaultService::default();
    // `init` exists so the next command works, and the context is what makes
    // that true with no extra step. Replacing a context the user chose is a
    // different matter: silently retargeting someone's selection at a vault
    // they did not ask for is the kind of surprise this CLI refuses elsewhere,
    // so an existing context is left alone and `nkp context use` remains
    // the way to change it. The flag is reported because "usable immediately"
    // and "did not touch your configuration" must not look identical.
    let create_result = service.create(&path, &mut credentials, write, opts.size);
    let vault_installed = matches!(
        create_result,
        Ok(()) | Err(nkeepass::ServiceError::CreateDurability)
    );
    let password_backup = if generated_backup.is_some() {
        Ok(generated_backup)
    } else if create_result.is_ok() {
        if let Some((config_root, data_root)) = &backup_roots {
            master_password
                .as_deref()
                .map(|password| backup_init_password_at(password, config_root, data_root))
                .transpose()
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    };
    let context_result = adopt_after_init_create(
        config,
        &path_text,
        use_default_alias,
        create_result,
        save_config,
    );
    let password_backup = password_backup
        .map_err(|error| err(format!("encrypted password backup failed: {}", error.0)));
    let context_set = match (context_result, password_backup) {
        (Ok(context_set), Ok(backup)) => (context_set, backup),
        (Err(context_error), Ok(backup)) => {
            if generate_master && let Some(backup) = &backup {
                if write_init_recovery(backup, as_json, &path_text, Some(vault_installed)).is_err()
                {
                    return Err(CliError(
                        format!("{}; recovery report could not be written", context_error.0),
                        context_error.1,
                    ));
                }
            }
            return Err(context_error);
        }
        (Ok(_), Err(backup_error)) => {
            return Err(err(format!("vault created; {}", backup_error.0)));
        }
        (Err(context_error), Err(backup_error)) => {
            return Err(err(format!(
                "{}; vault created but {}",
                context_error.0, backup_error.0
            )));
        }
    };

    let backup = context_set.1.as_ref();
    let result = serde_json::json!({
        "operation": "init",
        "path": path_text,
        "source": source,
        "context_set": context_set.0,
        "kdf": kdf_name(write.kdf),
        "kdf_parameters": kdf_parameters(&write),
        "generated_password": opts.size.is_some(),
        "password_backup": backup.map(|value| value.path.to_string_lossy().into_owned()),
        "password_backup_skipped": opts.key_file.is_some(),
        "master_password_generated": generate_master,
        "age_identity": backup.map(|value| value.identity_path.to_string_lossy().into_owned()),
        "age_identity_created": backup.map(|value| value.identity_created),
        "recovery_association": backup.and_then(|value| value.association_path.as_ref()).map(|path| path.to_string_lossy().into_owned()),
        "directory_sync_policy": backup.map(|_| backup_directory_sync_policy()),
        "ancestor_durability": backup.map(|_| "unconfirmed"),
    });
    if as_json {
        json(&result)
    } else {
        let mut output = io::stdout().lock();
        writeln!(output, "Database: {path_text}").map_err(|_| err("cannot write output"))?;
        writeln!(
            output,
            "Context selected: {}",
            if context_set.0 { "yes" } else { "no" }
        )
        .map_err(|_| err("cannot write output"))?;
        drop(output);
        if let Some(backup) = backup {
            write_init_recovery(backup, false, &path_text, None)?;
        } else {
            writeln!(
                io::stdout(),
                "Encrypted password backup: skipped (key-file credentials)\nAge identity: not used"
            )
            .map_err(|_| err("cannot write output"))?;
        }
        Ok(())
    }
}

/// Reports an association failure without revealing the backed-up password.
fn write_association_failure(
    backup: &InitPasswordBackup,
    vault: &str,
    error: &AssociationError,
    as_json: bool,
) -> Result<()> {
    let record = association_failure_record(backup, vault, error);
    let candidate = record["association_candidate"]
        .as_str()
        .ok_or_else(|| err("cannot encode recovery association"))?;
    if as_json {
        json(&record)
    } else {
        writeln!(io::stdout(), "Vault creation not started.\nRecovery association candidate: {candidate}\n{}\nEncrypted password backup: {}\nAge identity: {}\nRecovery directory ancestry durability: unconfirmed.",
            error.message, backup.path.display(), backup.identity_path.display())
            .map_err(|_| err("cannot write output"))
    }
}

/// The non-secret partial-state report emitted before vault creation starts.
fn association_failure_record(
    backup: &InitPasswordBackup,
    vault: &str,
    error: &AssociationError,
) -> serde_json::Value {
    let mut candidate = backup.path.as_os_str().to_os_string();
    candidate.push(".json");
    let candidate = PathBuf::from(candidate);
    serde_json::json!({
        "operation": "init-association-failed",
        "path": vault,
        "vault_install_started": false,
        "association_installed": error.installed,
        "association_candidate": candidate.to_string_lossy(),
        "password_backup": backup.path.to_string_lossy(),
        "age_identity": backup.identity_path.to_string_lossy(),
        "reason": error.message,
        "directory_sync_policy": backup_directory_sync_policy(),
        "ancestor_durability": "unconfirmed",
    })
}

/// Reports where the encrypted backup and its identity were installed.
fn write_init_recovery(
    backup: &InitPasswordBackup,
    as_json: bool,
    vault: &str,
    installed: Option<bool>,
) -> Result<()> {
    if as_json {
        json(&serde_json::json!({
            "operation": if installed == Some(false) { "init-unused-backup" } else { "init-recovery" },
            "path": vault,
            "vault_installed": installed,
            "password_backup": backup.path.to_string_lossy(),
            "age_identity": backup.identity_path.to_string_lossy(),
            "age_identity_created": backup.identity_created,
            "recovery_association": backup.association_path.as_ref().map(|path| path.to_string_lossy().into_owned()),
            "directory_sync_policy": backup_directory_sync_policy(),
            "ancestor_durability": "unconfirmed",
        }))
    } else {
        let mut output = io::stdout().lock();
        if let Some(installed) = installed {
            writeln!(
                output,
                "Database: {vault}\n{}",
                if installed {
                    "Vault installed; recovery backup follows."
                } else {
                    "Vault not created; unused backup follows and cannot unlock an existing vault."
                }
            )
            .map_err(|_| err("cannot write output"))?;
        }
        writeln!(
            output,
            "Encrypted password backup: {}\nAge identity {}: {}",
            backup.path.display(),
            if backup.identity_created {
                "created"
            } else {
                "reused"
            },
            backup.identity_path.display()
        )
        .map_err(|_| err("cannot write output"))?;
        if let Some(path) = &backup.association_path {
            writeln!(output, "Recovery candidate record: {}", path.display())
                .map_err(|_| err("cannot write output"))?;
        }
        if !cfg!(unix) {
            writeln!(
                output,
                "Directory durability: unconfirmed on this platform."
            )
            .map_err(|_| err("cannot write output"))?;
        }
        writeln!(
            output,
            "Recovery directory ancestry durability: unconfirmed. Keep independent protected copies of the identity and encrypted backup."
        )
        .map_err(|_| err("cannot write output"))?;
        if installed != Some(false) {
            writeln!(output, "Recovery: decrypt the backup with this identity in a private environment; see nkp init --help.")
                .map_err(|_| err("cannot write output"))?;
        }
        Ok(())
    }
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
        Err(nkeepass::ServiceError::SecureFileCapabilityUnknown {
            os_code: Some(code),
        }) => Err(err(format!(
            "cannot query filesystem ACL capability (OS error {code})"
        ))),
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
        let mut name = "default".to_owned();
        let mut suffix = 1_u64;
        loop {
            match config.aliases.get(&name) {
                Some(alias)
                    if alias.kind == Kind::Vault
                        && vault_path_key(&alias.target) == vault_path_key(path) =>
                {
                    break;
                }
                Some(_) => {
                    name = format!("default-{suffix}");
                    suffix = suffix
                        .checked_add(1)
                        .ok_or_else(|| err("cannot select default context"))?;
                }
                None => {
                    config.aliases.insert(
                        name.clone(),
                        Alias {
                            kind: Kind::Vault,
                            target: path.to_owned(),
                            field: None,
                        },
                    );
                    break;
                }
            }
        }
        name
    } else {
        path.to_owned()
    };
    config.current = Some(current);
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
        let safe_name = sanitize_terminal_text(name);
        let _ = writeln!(
            io::stderr(),
            "nkp: warning: the code bound to {safe_name} expires in {remaining}s; \
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

fn list_aliases(config: &Config, format: MetadataFormat) -> Result<()> {
    // Built before writing so one hostile record does not leave benign ones
    // already on stdout.
    for (name, alias) in &config.aliases {
        check_alias_metadata(name, alias)?;
    }
    match format {
        MetadataFormat::Json => {
            let records = config
                .aliases
                .iter()
                .map(|(name, alias)| {
                    serde_json::json!({
                        "name": name,
                        "kind": alias.kind,
                        "target": alias.target,
                        "field": alias.field,
                    })
                })
                .collect::<Vec<_>>();
            for record in records {
                json(&record)?;
            }
            Ok(())
        }
        MetadataFormat::Human => {
            let entries: Vec<(&String, &Alias)> = config.aliases.iter().collect();
            let lines =
                render_aliases_human(&entries, human_output_width(), current_stdout_style());
            write_human_lines(&lines)
        }
    }
}

fn parse_alias_list_format(args: &[String]) -> Result<MetadataFormat> {
    match args {
        [] => Ok(MetadataFormat::Json),
        [flag, value] if flag == "--format" => MetadataFormat::parse(Some(value)),
        [flag] if flag == "--format" => Err(err("missing argument; see --help")),
        _ => Err(err("invalid alias command; see --help")),
    }
}

/// `config get` -- one key's value, in the shape a caller can use it in.
fn config_get(config: &Config, key: ConfigKey) -> Result<()> {
    if key == ConfigKey::Aliases {
        return list_aliases(config, MetadataFormat::Json);
    }
    let value = config.value(key).ok_or_else(|| err(CONFIG_KEY_NOT_SET))?;
    check_config_value(value)?;
    // The bare value, not a JSON document, so `$(nkp config get current)`
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
    if is_named_format(opts.format) {
        validate_binding_names(
            opts.format,
            opts.bindings.iter().map(|binding| binding.name),
        )?;
    }
    let (path, _) = active_vault(vault, config)?;
    let is_output = opts.common.is_output;
    let mut credentials = credentials(&opts.common)?;
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
    // The first separator belongs to exec, even when an option is missing its
    // value. Never consume the separator (or child argv) as that value.
    let cli_args = &args[..sep];
    let mut keys = Vec::new();
    let mut fields: Vec<Option<&str>> = Vec::new();
    let mut env_names = Vec::new();
    let mut env_files = Vec::new();
    let mut used_compact = false;
    let mut used_legacy = false;
    let mut password_arg = None;
    let mut password_env = None;
    let mut password_file = None;
    let mut key_file = None;
    let mut password_stdin = false;
    let mut i = 0;
    while i < sep {
        match args[i].as_str() {
            "--bind" => {
                used_compact = true;
                if used_legacy {
                    return Err(err("cannot mix --bind with --key/--field/--env"));
                }
                i += 1;
                let spec = take_arg(cli_args, i)?;
                let (name, entry) = spec
                    .split_once('=')
                    .ok_or_else(|| err("--bind requires NAME=ENTRY"))?;
                if entry.is_empty() {
                    return Err(err("--bind requires NAME=ENTRY"));
                }
                env_names.push(name.to_owned());
                keys.push(entry.to_owned());
                fields.push(None);
            }
            "--key" => {
                used_legacy = true;
                if used_compact {
                    return Err(err("cannot mix --bind with --key/--field/--env"));
                }
                i += 1;
                keys.push(take_arg(cli_args, i)?.to_owned());
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
                used_legacy = true;
                if used_compact {
                    return Err(err("cannot mix --bind with --key/--field/--env"));
                }
                i += 1;
                let slot = fields
                    .last_mut()
                    .ok_or_else(|| err("--key required before --field"))?;
                if slot.is_some() {
                    return Err(err("invalid or duplicate option"));
                }
                *slot = Some(take_arg(cli_args, i)?);
            }
            "--env" => {
                used_legacy = true;
                if used_compact {
                    return Err(err("cannot mix --bind with --key/--field/--env"));
                }
                i += 1;
                env_names.push(take_arg(cli_args, i)?.to_owned());
            }
            "--env-file" => {
                i += 1;
                env_files.push(take_arg(cli_args, i)?);
            }
            "--password" if password_arg.is_none() => {
                i += 1;
                password_arg = Some(take_arg(cli_args, i)?);
            }
            "--password-env" if password_env.is_none() => {
                i += 1;
                password_env = Some(take_arg(cli_args, i)?);
            }
            "--password-file" if password_file.is_none() => {
                i += 1;
                password_file = Some(take_arg(cli_args, i)?);
            }
            "--key-file" if key_file.is_none() => {
                i += 1;
                key_file = Some(take_arg(cli_args, i)?);
            }
            "--password-stdin" if !password_stdin => password_stdin = true,
            "--allow-plaintext" => {
                return Err(err(
                    "--allow-plaintext is only valid for KeePass XML export",
                ));
            }
            _ => return Err(err("invalid exec option")),
        }
        i += 1;
    }
    if keys.is_empty() && env_files.is_empty() {
        return Err(err(
            "exec requires at least one --key, --bind, or --env-file",
        ));
    }
    if keys.len() != env_names.len() {
        return Err(err("exec requires one --env name for each --key"));
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

    let mut env_lines = Vec::new();
    for env_file_path in env_files {
        let bytes = bounded_regular_file(env_file_path, nkeepass::env_file::MAX_ENV_FILE_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| err("env file is not valid UTF-8"))?;
        let parsed = nkeepass::env_file::parse_env_file(text).map_err(template_cli_error)?;
        env_lines.extend(parsed);
    }

    let mut all_env_names = Vec::with_capacity(env_names.len() + env_lines.len());
    all_env_names.extend(env_names.iter().cloned());
    all_env_names.extend(env_lines.iter().map(|line| {
        let nkeepass::env_file::EnvLine { name, .. } = line;
        name.clone()
    }));
    validate_exec_env_names_for_platform(&all_env_names, password_env, cfg!(windows))?;

    for name in &all_env_names {
        if env::var_os(name).is_some() {
            return Err(err("exec environment name already exists"));
        }
    }

    let env_needs_vault = env_lines.iter().any(|line| {
        let nkeepass::env_file::EnvLine { value, .. } = line;
        matches!(value, nkeepass::env_file::EnvValueKind::Template(_))
    });
    let needs_default_vault = !keys.is_empty() || env_lines_need_default_vault(&env_lines)?;
    let mut values: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();

    if !keys.is_empty() || env_needs_vault {
        let default_vault = if needs_default_vault {
            Some(active_vault(vault, config)?.0)
        } else {
            None
        };
        let pw = password(&opts)?;
        // Pinned once for the whole invocation; see `otp_now`.
        let timestamp = otp_now()?;
        let mut lookup = MultiVaultLookup::new(
            config,
            default_vault.clone(),
            pw,
            opts.key_file,
            timestamp,
            false,
        );

        if !keys.is_empty() {
            let path = default_vault
                .as_deref()
                .ok_or_else(|| err("cannot open vault"))?;
            let (service, session) = lookup.open_or_get(path).map_err(|e| match e {
                nkeepass::template::TemplateError::Service(nkeepass::ServiceError::Io) => {
                    err("cannot open vault")
                }
                _ => err("cannot unlock vault"),
            })?;
            for ((key, field), name) in keys.iter().zip(&fields).zip(&env_names) {
                let entry = resolve_service_selector(service, session, key, config)?;
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
                                let value = reveal_service_field(service, &entry, field)?;
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
        }

        if !env_lines.is_empty() {
            let resolved_env = nkeepass::env_file::resolve_env_file(&env_lines, &mut lookup)
                .map_err(template_cli_error)?;
            for (name, val) in resolved_env {
                values.insert(name, val);
            }
        }

        // The child receives only explicitly selected, zeroizing values. Do not
        // keep any unlocked database or credentials alive while it runs.
        lookup.lock_all();
    } else if !env_lines.is_empty() {
        let resolved_env = nkeepass::env_file::resolve_env_file(&env_lines, &mut NoopLookup)
            .map_err(template_cli_error)?;
        for (name, val) in resolved_env {
            values.insert(name, val);
        }
    }

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

/// Reads an existing regular file up to `max` bytes without following symlinks
/// or reparse points and without blocking on FIFOs or devices.
fn bounded_regular_file(path: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let (file, _) =
        nkeepass::fs_safe::open_regular_file_nofollow(Path::new(path)).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput {
                err("input path must be a regular file")
            } else {
                err("cannot open input file")
            }
        })?;
    let max_u64 = u64::try_from(max).map_err(|_| err("input exceeds size limit"))?;
    let bytes = read_bounded(file, max_u64, "cannot read input file")?;
    if bytes.len() > max {
        return Err(err("input exceeds size limit"));
    }
    Ok(bytes)
}

fn template_cli_error(error: nkeepass::template::TemplateError) -> CliError {
    err(error.to_string())
}

fn manifest_cli_error(error: nkeepass::manifest::ManifestError) -> CliError {
    err(error.to_string())
}

fn trust_cli_error(error: nkeepass::trust::TrustError) -> CliError {
    err(error.to_string())
}

struct NoopLookup;

impl nkeepass::template::SecretLookup for NoopLookup {
    fn resolve_secret(
        &mut self,
        _uri: &nkeepass::template::NkpUri,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, nkeepass::template::TemplateError> {
        Err(nkeepass::template::TemplateError::VaultLocked)
    }
}

fn build_entry_aliases(config: &Config) -> BTreeMap<String, nkeepass::template::EntryAlias> {
    config
        .aliases
        .iter()
        .filter(|(_, alias)| alias.kind == Kind::Entry)
        .map(|(name, alias)| {
            (
                name.clone(),
                nkeepass::template::EntryAlias {
                    target: alias.target.clone(),
                    field: alias.field.clone(),
                },
            )
        })
        .collect()
}

struct MultiVaultLookup<'a> {
    config: &'a Config,
    default_vault: Option<PathBuf>,
    layer_vault: Option<PathBuf>,
    master_pw: Option<Zeroizing<String>>,
    key_file: Option<&'a str>,
    timestamp: u64,
    entry_aliases: BTreeMap<String, nkeepass::template::EntryAlias>,
    preopen_safe: bool,
    open_vaults: BTreeMap<String, (VaultService, nkeepass::SessionId)>,
}

impl<'a> MultiVaultLookup<'a> {
    fn new(
        config: &'a Config,
        default_vault: Option<PathBuf>,
        master_pw: Option<Zeroizing<String>>,
        key_file: Option<&'a str>,
        timestamp: u64,
        preopen_safe: bool,
    ) -> Self {
        Self {
            config,
            default_vault,
            layer_vault: None,
            master_pw,
            key_file,
            timestamp,
            entry_aliases: build_entry_aliases(config),
            preopen_safe,
            open_vaults: BTreeMap::new(),
        }
    }

    fn set_layer_vault(&mut self, path: Option<PathBuf>) {
        self.layer_vault = path;
    }

    fn open_or_get(
        &mut self,
        vault_path: &Path,
    ) -> std::result::Result<(&VaultService, nkeepass::SessionId), nkeepass::template::TemplateError>
    {
        use nkeepass::template::TemplateError;
        let key = platform_vault_dedup_key(vault_path);
        if !self.open_vaults.contains_key(&key) {
            if self.preopen_safe {
                nkeepass::hook::preopen_vault_fingerprint(vault_path)
                    .map_err(|_| TemplateError::Service(nkeepass::ServiceError::Io))?;
            }
            let mut creds = credentials_with_password_and_keyfile(
                self.master_pw.as_deref().map(String::as_str),
                self.key_file,
            )
            .map_err(|_| TemplateError::VaultLocked)?;
            let mut service = VaultService::default();
            let session =
                service
                    .open(vault_path, &mut creds, &KDBX_LIMITS)
                    .map_err(|e| match e {
                        nkeepass::ServiceError::Io => TemplateError::Service(e),
                        _ => TemplateError::VaultLocked,
                    })?;
            self.open_vaults.insert(key.clone(), (service, session));
        }
        self.open_vaults
            .get(&key)
            .map(|(service, session)| (service, *session))
            .ok_or(TemplateError::VaultLocked)
    }

    fn resolve_entry_binding(
        &mut self,
        binding: &nkeepass::manifest::EnvEntryBinding,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, nkeepass::template::TemplateError> {
        use nkeepass::template::SecretLookup;
        let uri = nkeepass::template::NkpUri {
            vault_alias: None,
            entry_path: binding.entry.clone(),
            field: binding.field.clone(),
        };
        self.resolve_secret(&uri)
    }

    fn lock_all(&mut self) {
        let vaults = std::mem::take(&mut self.open_vaults);
        for (_, (mut service, session)) in vaults {
            let _ = service.lock(session);
        }
    }
}

impl Drop for MultiVaultLookup<'_> {
    fn drop(&mut self) {
        self.lock_all();
    }
}

impl nkeepass::template::SecretLookup for MultiVaultLookup<'_> {
    fn resolve_secret(
        &mut self,
        uri: &nkeepass::template::NkpUri,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, nkeepass::template::TemplateError> {
        use nkeepass::template::{ServiceSecretLookup, TemplateError};
        let (target_path, alias_name) = match uri.vault_alias.as_deref() {
            Some(alias) => {
                let Some(Alias {
                    kind: Kind::Vault,
                    target,
                    ..
                }) = self.config.aliases.get(alias)
                else {
                    return Err(TemplateError::UnknownVaultAlias);
                };
                let resolved = vault_path(target).map_err(|_| TemplateError::UnknownVaultAlias)?;
                (resolved, Some(alias))
            }
            None => {
                let path = self
                    .layer_vault
                    .as_ref()
                    .or(self.default_vault.as_ref())
                    .cloned()
                    .ok_or(TemplateError::Service(nkeepass::ServiceError::Io))?;
                (path, None)
            }
        };
        let timestamp = self.timestamp;
        let entry_aliases = self.entry_aliases.clone();
        let (service, session) = self.open_or_get(&target_path)?;
        let mut adapter =
            ServiceSecretLookup::new(service, session, timestamp).with_entry_aliases(entry_aliases);
        if let Some(alias) = alias_name {
            adapter = adapter.with_vault_alias(alias);
        }
        adapter.resolve_secret(uri)
    }
}

fn env_lines_need_default_vault(lines: &[nkeepass::env_file::EnvLine]) -> Result<bool> {
    for line in lines {
        let nkeepass::env_file::EnvLine { value, .. } = line;
        if let nkeepass::env_file::EnvValueKind::Template(tmpl) = value {
            let refs = nkeepass::template::extract_references(tmpl).map_err(template_cli_error)?;
            if refs.iter().any(|uri| uri.vault_alias.is_none()) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Clone, Copy)]
enum InjectFormat {
    Raw,
    Dotenv,
}

fn inject_command(args: &[String], vault: Option<&str>, config: &Config) -> Result<()> {
    let opts = options(args, Positional::File)?;
    validate_allowed_options(
        &opts,
        &AllowedOptions {
            allow_file: true,
            allow_stdin: true,
            allow_output: true,
            allow_format: true,
            allow_check: true,
            ..AllowedOptions::none()
        },
        "invalid inject option",
        None,
        "age options are unsupported for inject",
    )?;
    let input_count = usize::from(opts.file.is_some()) + usize::from(opts.stdin);
    if input_count != 1 {
        return Err(err("select exactly one input file or --stdin"));
    }
    if opts.check && opts.output.is_some() {
        return Err(err("--check cannot be combined with --output"));
    }
    let format = match opts.format {
        None | Some("raw") => InjectFormat::Raw,
        Some("dotenv") => InjectFormat::Dotenv,
        Some(_) => return Err(err("invalid inject format")),
    };

    let raw_bytes = if let Some(path) = opts.file {
        bounded_regular_file(path, nkeepass::template::MAX_TEMPLATE_INPUT_BYTES)?
    } else {
        read_stdin(
            nkeepass::template::MAX_TEMPLATE_INPUT_BYTES,
            "cannot read input",
        )?
    };
    let text = Zeroizing::new(
        std::str::from_utf8(&raw_bytes)
            .map_err(|_| err("input is not valid UTF-8"))?
            .to_owned(),
    );
    drop(raw_bytes);

    let rendered: Zeroizing<String> = match format {
        InjectFormat::Raw => {
            let refs = nkeepass::template::extract_references(&text).map_err(template_cli_error)?;
            let render_opts = nkeepass::template::RenderOptions::default();
            if refs.is_empty() {
                nkeepass::template::render_text(&text, &mut NoopLookup, &render_opts)
                    .map_err(template_cli_error)?
            } else {
                let default_vault = if refs.iter().any(|uri| uri.vault_alias.is_none()) {
                    Some(active_vault(vault, config)?.0)
                } else {
                    None
                };
                let pw = password(&opts)?;
                let timestamp = otp_now()?;
                let mut lookup = MultiVaultLookup::new(
                    config,
                    default_vault,
                    pw,
                    opts.key_file,
                    timestamp,
                    false,
                );
                let out = nkeepass::template::render_text(&text, &mut lookup, &render_opts)
                    .map_err(template_cli_error)?;
                lookup.lock_all();
                out
            }
        }
        InjectFormat::Dotenv => {
            let lines = nkeepass::env_file::parse_env_file(&text).map_err(template_cli_error)?;
            let has_refs = lines.iter().any(|line| {
                let nkeepass::env_file::EnvLine { value, .. } = line;
                matches!(value, nkeepass::env_file::EnvValueKind::Template(_))
            });
            let resolved = if has_refs {
                let default_vault = if env_lines_need_default_vault(&lines)? {
                    Some(active_vault(vault, config)?.0)
                } else {
                    None
                };
                let pw = password(&opts)?;
                let timestamp = otp_now()?;
                let mut lookup = MultiVaultLookup::new(
                    config,
                    default_vault,
                    pw,
                    opts.key_file,
                    timestamp,
                    false,
                );
                let out = nkeepass::env_file::resolve_env_file(&lines, &mut lookup)
                    .map_err(template_cli_error)?;
                lookup.lock_all();
                out
            } else {
                nkeepass::env_file::resolve_env_file(&lines, &mut NoopLookup)
                    .map_err(template_cli_error)?
            };
            let mut quoted_entries = Vec::with_capacity(resolved.len());
            let mut total_len = 0usize;
            for (name, val) in resolved {
                let quoted = Zeroizing::new(
                    serde_json::to_string(val.as_str()).map_err(|_| err("cannot encode output"))?,
                );
                total_len = total_len
                    .saturating_add(name.len())
                    .saturating_add(1)
                    .saturating_add(quoted.len())
                    .saturating_add(1);
                quoted_entries.push((name, quoted));
            }
            let mut out = Zeroizing::new(String::with_capacity(total_len));
            for (name, quoted) in quoted_entries {
                out.push_str(&name);
                out.push('=');
                out.push_str(&quoted);
                out.push('\n');
            }
            out
        }
    };

    if opts.check {
        return Ok(());
    }
    if let Some(output_path) = opts.output {
        return nkeepass::private_file::write_private_noclobber(
            Path::new(output_path),
            rendered.as_bytes(),
        )
        .map_err(err);
    }
    if io::stdout().is_terminal() {
        validate_tty_raw_bytes(rendered.as_bytes())?;
        if rendered
            .chars()
            .any(nkeepass::template::is_bidi_or_line_separator)
        {
            return Err(err(
                "raw output contains terminal-control bytes; redirect stdout to a file or pipe",
            ));
        }
    }
    write_stdout(rendered.as_bytes(), "cannot write output")
}

fn trust_kind_label(kind: nkeepass::trust::TrustKind) -> &'static str {
    match kind {
        nkeepass::trust::TrustKind::Toml => "toml",
        nkeepass::trust::TrustKind::NkpEnv => "nkp-env",
        nkeepass::trust::TrustKind::DotEnv => "dotenv",
    }
}

fn resolve_trust_target_file(raw_target: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(raw_target).map_err(|_| err("cannot inspect trust target"))?;
    if meta.file_type().is_symlink() {
        return Err(err("trust target must not be a symlink"));
    }
    if meta.file_type().is_file() {
        return Ok(raw_target.to_path_buf());
    }
    if meta.file_type().is_dir() {
        for candidate_name in [".nkp.toml", ".nkp.env"] {
            let candidate = raw_target.join(candidate_name);
            match fs::symlink_metadata(&candidate) {
                Ok(cmeta) => {
                    if cmeta.file_type().is_symlink() || !cmeta.file_type().is_file() {
                        return Err(err("trust target must be a safe regular file"));
                    }
                    return Ok(candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(err("cannot inspect trust target")),
            }
        }
        return Err(err(
            "no .nkp.toml or .nkp.env found in directory; pass .env explicitly to trust a .env file",
        ));
    }
    Err(err("trust target must be a regular file or directory"))
}

fn trust_command(args: &[String]) -> Result<()> {
    let mut list = false;
    let mut as_json = false;
    let mut prune = false;
    let mut target: Option<&str> = None;
    let mut end_opts = false;

    for arg in args {
        let s = arg.as_str();
        if !end_opts && s == "--" {
            end_opts = true;
            continue;
        }
        if !end_opts && s.starts_with('-') {
            match s {
                "--list" if !list => list = true,
                "--json" if !as_json => as_json = true,
                "--prune" if !prune => prune = true,
                _ => return Err(err("invalid trust option")),
            }
            continue;
        }
        if target.is_some() {
            return Err(err("invalid or duplicate trust target"));
        }
        target = Some(s);
    }

    if list && prune {
        return Err(err("--list cannot be combined with --prune"));
    }
    if as_json && !list {
        return Err(err("--json requires --list"));
    }
    if (list || prune) && target.is_some() {
        return Err(err(
            "trust target path cannot be combined with --list or --prune",
        ));
    }

    let store_dir = data_dir()?;
    if list {
        let entries = nkeepass::trust::list_trusted(&store_dir).map_err(trust_cli_error)?;
        for entry in &entries {
            if !nkeepass::template::is_safe_display_text(&entry.path) {
                return Err(err("trusted path contains unsafe characters"));
            }
        }
        if as_json {
            for entry in &entries {
                json(entry)?;
            }
        } else {
            for entry in &entries {
                print_line(&format!(
                    "{}\t{}\t{}",
                    trust_kind_label(entry.kind),
                    entry.sha256,
                    entry.path
                ))?;
            }
        }
        return Ok(());
    }

    if prune {
        let removed = nkeepass::trust::prune_missing(&store_dir).map_err(trust_cli_error)?;
        let _ = writeln!(
            io::stderr(),
            "nkp: pruned {removed} missing trusted {}",
            if removed == 1 { "entry" } else { "entries" }
        );
        return Ok(());
    }

    let resolved = resolve_trust_target_file(Path::new(target.unwrap_or(".")))?;
    let now = otp_now()?;
    let (_loaded, entries) = nkeepass::trust::trust_manifest_file(&store_dir, &resolved, now)
        .map_err(trust_cli_error)?;
    for entry in &entries {
        if nkeepass::template::is_safe_display_text(&entry.path) {
            let _ = writeln!(
                io::stderr(),
                "nkp: trusted {} ({})",
                entry.path,
                &entry.sha256[..12]
            );
        }
    }
    Ok(())
}

fn untrust_command(args: &[String]) -> Result<()> {
    let mut all = false;
    let mut target: Option<&str> = None;
    let mut end_opts = false;

    for arg in args {
        let s = arg.as_str();
        if !end_opts && s == "--" {
            end_opts = true;
            continue;
        }
        if !end_opts && s.starts_with('-') {
            match s {
                "--all" if !all => all = true,
                _ => return Err(err("invalid untrust option")),
            }
            continue;
        }
        if target.is_some() {
            return Err(err("invalid or duplicate untrust target"));
        }
        target = Some(s);
    }

    if all && target.is_some() {
        return Err(err("--all cannot be combined with a path"));
    }

    let store_dir = data_dir()?;
    if all {
        let count = nkeepass::trust::untrust_all(&store_dir).map_err(trust_cli_error)?;
        let _ = writeln!(
            io::stderr(),
            "nkp: revoked {count} trusted {}",
            if count == 1 { "entry" } else { "entries" }
        );
        return Ok(());
    }

    let raw_target = Path::new(target.unwrap_or("."));
    let is_dir = fs::symlink_metadata(raw_target).is_ok_and(|meta| meta.file_type().is_dir());
    let mut removed_count = 0_usize;
    if is_dir {
        let toml_path = raw_target.join(".nkp.toml");
        if let Ok(loaded) = nkeepass::manifest::load_single_manifest_file(&toml_path) {
            for env_file in &loaded.env_files {
                if nkeepass::trust::untrust_file(&store_dir, &env_file.file.canonical_path)
                    .map_err(trust_cli_error)?
                {
                    removed_count += 1;
                }
            }
        }
        for name in [".nkp.toml", ".nkp.env", ".env"] {
            if nkeepass::trust::untrust_file(&store_dir, &raw_target.join(name))
                .map_err(trust_cli_error)?
            {
                removed_count += 1;
            }
        }
    } else if nkeepass::trust::untrust_file(&store_dir, raw_target).map_err(trust_cli_error)? {
        removed_count += 1;
    }

    if removed_count == 0 {
        let _ = writeln!(io::stderr(), "nkp: no matching trusted entry");
    } else {
        let _ = writeln!(
            io::stderr(),
            "nkp: revoked {removed_count} trusted {}",
            if removed_count == 1 {
                "entry"
            } else {
                "entries"
            }
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HookMode {
    Normal,
    Prompt,
    Unload,
}

fn detect_hook_shell(explicit: Option<&str>) -> Result<nkeepass::hook::HookShell> {
    if let Some(name) = explicit {
        return nkeepass::hook::HookShell::parse(name).map_err(|e| err(e.to_string()));
    }
    let shell_env = env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err("cannot detect supported shell; pass --shell SHELL"))?;
    let basename = Path::new(&shell_env)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| err("cannot detect supported shell; pass --shell SHELL"))?;
    nkeepass::hook::HookShell::parse(basename)
        .map_err(|_| err("cannot detect supported shell; pass --shell SHELL"))
}

fn shell_command(args: &[String], config: &Config) -> Result<()> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(err("shell subcommand required; see --help"));
    };
    let rest = &args[1..];
    match sub {
        "init" => shell_init_command(rest),
        "completions" | "completion" => shell_completions_command(rest),
        "load" => shell_load_command(rest, config),
        "unload" => shell_unload_command(rest, config),
        "status" => shell_status_command(rest),
        _ => Err(err("invalid shell command; see --help")),
    }
}

fn shell_init_command(args: &[String]) -> Result<()> {
    let mut no_completion = false;
    let mut no_env = false;
    let mut shell: Option<&str> = None;
    let mut end_opts = false;

    for arg in args {
        let s = arg.as_str();
        if !end_opts && s == "--" {
            end_opts = true;
            continue;
        }
        if !end_opts && s.starts_with('-') {
            match s {
                "--no-completion" if !no_completion => no_completion = true,
                "--no-env" if !no_env => no_env = true,
                _ => return Err(err("invalid shell init option")),
            }
            continue;
        }
        if shell.is_some() {
            return Err(err("invalid or duplicate shell argument"));
        }
        shell = Some(s);
    }

    let shell_name = shell.ok_or_else(|| err("shell name required"))?;
    let hook_shell =
        nkeepass::hook::HookShell::parse(shell_name).map_err(|e| err(e.to_string()))?;
    let comp = if no_completion {
        None
    } else {
        Some(completion::generate(hook_shell.as_str())?)
    };
    let pinned = nkeepass::hook::resolve_pinned_nkp_exe();
    let script =
        nkeepass::hook::emit_shell_init_with_bin(hook_shell, comp, !no_env, pinned.as_deref())
            .map_err(|e| err(e.to_string()))?;
    write_stdout(script.as_bytes(), "cannot write output")
}

fn shell_completions_command(args: &[String]) -> Result<()> {
    let [shell] = args else {
        return Err(err("unsupported completion shell"));
    };
    let script = completion::generate(shell)?;
    write_stdout(script.as_bytes(), "cannot write output")
}

fn shell_load_command(args: &[String], config: &Config) -> Result<()> {
    let mut shell_arg: Option<&str> = None;
    let mut password_arg = None;
    let mut password_env = None;
    let mut password_file = None;
    let mut key_file = None;
    let mut password_stdin = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shell" if shell_arg.is_none() => {
                i += 1;
                shell_arg = Some(take_arg(args, i)?);
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
            _ => return Err(err("invalid shell load option")),
        }
        i += 1;
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
    let hook_shell = detect_hook_shell(shell_arg)?;
    run_hook_with_mode(hook_shell, HookMode::Prompt, None, false, &opts, config)
}

fn shell_unload_command(args: &[String], config: &Config) -> Result<()> {
    let mut shell_arg: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shell" if shell_arg.is_none() => {
                i += 1;
                shell_arg = Some(take_arg(args, i)?);
            }
            _ => return Err(err("invalid shell unload option")),
        }
        i += 1;
    }
    let hook_shell = detect_hook_shell(shell_arg)?;
    let opts = Options::default();
    run_hook_with_mode(hook_shell, HookMode::Unload, None, false, &opts, config)
}

#[derive(Serialize)]
struct ShellStatusManifestFile<'a> {
    path: &'a str,
    sha256: &'a str,
    trust: &'static str,
}

fn shell_status_command(args: &[String]) -> Result<()> {
    let as_json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return Err(err("invalid shell status option")),
    };

    let encoded = env::var("__NKP_ENV_STATE").unwrap_or_default();
    let (state_corrupt, state_opt) = match nkeepass::hook::decode_state(&encoded) {
        nkeepass::hook::StateDecode::Empty => (false, None),
        nkeepass::hook::StateDecode::Valid(st) => (false, Some(st)),
        nkeepass::hook::StateDecode::Invalid => (true, None),
    };

    let store_dir = data_dir()?;
    let trust_store =
        nkeepass::trust::TrustStore::load_from_dir(&store_dir).map_err(trust_cli_error)?;
    let cwd = env::current_dir().map_err(|_| err("cannot determine current directory"))?;
    let chain_opt =
        nkeepass::manifest::discover_chain(&cwd, |path| trust_store.contains_path(path))
            .map_err(manifest_cli_error)?;

    let mut manifest_files = Vec::new();
    let mut any_modified = false;
    let mut any_untrusted = false;
    if let Some(chain) = &chain_opt {
        for file in &chain.files_to_verify {
            if !nkeepass::template::is_safe_display_text(&file.display_path) {
                return Err(err("manifest path contains unsafe characters"));
            }
            let file_trust = if trust_store.is_trusted(&file.canonical_path, &file.sha256) {
                "trusted"
            } else if trust_store.contains_path(&file.canonical_path) {
                any_modified = true;
                "modified"
            } else {
                any_untrusted = true;
                "untrusted"
            };
            manifest_files.push((file.display_path.clone(), file.sha256.clone(), file_trust));
        }
    }

    let overall_trust = if manifest_files.is_empty() {
        "none"
    } else if any_modified {
        "modified"
    } else if any_untrusted {
        "untrusted"
    } else {
        "trusted"
    };

    let current_chain_digest = chain_opt.as_ref().map(|chain| {
        let entries = nkeepass::hook::ChainEntry::from_discovered_chain(chain);
        nkeepass::hook::compute_chain_digest(&entries)
    });

    let is_unloaded = state_opt.as_ref().is_some_and(|st| {
        st.unloaded.is_some()
            && (current_chain_digest.is_none()
                || st.unloaded.as_deref() == current_chain_digest.as_deref())
    });

    let status_label = if state_corrupt {
        "invalid"
    } else if is_unloaded {
        "unloaded"
    } else if state_opt
        .as_ref()
        .is_some_and(|st| !st.chain.is_empty() && st.unloaded.is_none())
    {
        "active"
    } else {
        "inactive"
    };

    let managed_vars: Vec<String> = state_opt
        .as_ref()
        .map(|st| st.vars.keys().cloned().collect())
        .unwrap_or_default();

    if as_json {
        let records: Vec<ShellStatusManifestFile<'_>> = manifest_files
            .iter()
            .map(|(path, sha256, trust)| ShellStatusManifestFile {
                path,
                sha256,
                trust,
            })
            .collect();
        return json(&serde_json::json!({
            "status": status_label,
            "trust": overall_trust,
            "manifest_chain": records,
            "managed_vars": managed_vars,
            "unloaded": is_unloaded,
        }));
    }

    print_line(&format!("Status: {status_label}"))?;
    print_line(&format!("Trust: {overall_trust}"))?;
    if manifest_files.is_empty() {
        print_line("Manifests: (none)")?;
    } else {
        print_line("Manifests:")?;
        for (path, _sha256, trust) in &manifest_files {
            print_line(&format!("  {trust}\t{path}"))?;
        }
    }
    if managed_vars.is_empty() {
        print_line("Managed variables: (none)")?;
    } else {
        print_line(&format!("Managed variables: {}", managed_vars.join(", ")))?;
    }
    Ok(())
}

fn hook_command(args: &[String], config: &Config) -> Result<()> {
    let Some(shell_name) = args.first().map(String::as_str) else {
        return Err(err("shell name required"));
    };
    let hook_shell =
        nkeepass::hook::HookShell::parse(shell_name).map_err(|e| err(e.to_string()))?;

    let mut prompt = false;
    let mut unload = false;
    let mut startup = false;
    let mut cwd: Option<&str> = None;
    let mut password_arg = None;
    let mut password_env = None;
    let mut password_file = None;
    let mut key_file = None;
    let mut password_stdin = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--prompt" if !prompt => prompt = true,
            "--unload" if !unload => unload = true,
            "--startup" if !startup => startup = true,
            "--cwd" if cwd.is_none() => {
                i += 1;
                cwd = Some(take_arg(args, i)?);
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
            "-V" | "--vault" => {
                return Err(err("this command does not accept --vault"));
            }
            arg if arg.starts_with("-V=") || arg.starts_with("--vault=") => {
                return Err(err("this command does not accept --vault"));
            }
            _ => return Err(err("invalid hook option")),
        }
        i += 1;
    }
    if prompt && unload {
        return Err(err("--prompt cannot be combined with --unload"));
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
    let mode = if unload {
        HookMode::Unload
    } else if prompt {
        HookMode::Prompt
    } else {
        HookMode::Normal
    };
    run_hook_with_mode(hook_shell, mode, cwd, startup, &opts, config)
}

fn emit_hook_outcome(
    shell: nkeepass::hook::HookShell,
    outcome: &nkeepass::hook::TransitionOutcome,
) -> Result<()> {
    if outcome.discarded_corrupt_state {
        let _ = writeln!(io::stderr(), "nkp: warning: discarded invalid hook state");
    }
    if outcome.emit_patch {
        let script = nkeepass::hook::emit_hook_patch(shell, &outcome.patch)
            .map_err(|e| err(e.to_string()))?;
        write_stdout(script.as_bytes(), "cannot write hook output")?;
    }
    Ok(())
}

fn emit_blocked_or_fail(
    shell: nkeepass::hook::HookShell,
    mode: HookMode,
    encoded_state: &str,
    warned_digest: &str,
    message: &str,
) -> Result<()> {
    if mode == HookMode::Prompt {
        return Err(err(message));
    }
    let outcome = nkeepass::hook::compute_transition(
        encoded_state,
        nkeepass::hook::TransitionAction::Blocked { warned_digest },
        |name| env::var_os(name),
    )
    .map_err(|e| err(e.to_string()))?;
    if !outcome.suppress_duplicate_warning {
        let _ = writeln!(io::stderr(), "{message}");
    }
    emit_hook_outcome(shell, &outcome)
}

fn resolve_vault_spec_path(
    spec: &nkeepass::manifest::VaultSpec,
    config: &Config,
) -> Result<PathBuf> {
    match spec {
        nkeepass::manifest::VaultSpec::Alias(alias) => {
            let Some(Alias {
                kind: Kind::Vault,
                target,
                ..
            }) = config.aliases.get(alias)
            else {
                return Err(err("vault alias not found"));
            };
            vault_path(target)
        }
        nkeepass::manifest::VaultSpec::Path(path) => {
            let raw = path
                .to_str()
                .ok_or_else(|| err("vault path must be valid UTF-8"))?;
            vault_path(raw)
        }
    }
}

fn collect_hook_vault_paths(
    merged: &nkeepass::manifest::MergedBindings,
    config: &Config,
) -> Result<Vec<PathBuf>> {
    if !merged.requires_vault_unlock {
        return Ok(Vec::new());
    }
    let mut seen_keys = BTreeSet::new();
    let mut paths = Vec::new();
    let mut cached_default_vault: Option<PathBuf> = None;

    let mut push_path = |path: PathBuf| -> Result<()> {
        let key = platform_vault_dedup_key(&path);
        if seen_keys.insert(key) {
            if paths.len() >= nkeepass::manifest::MAX_VAULTS_PER_HOOK {
                return Err(err("manifest chain exceeds maximum distinct vault count"));
            }
            paths.push(path);
        }
        Ok(())
    };

    let mut resolve_default = || -> Result<PathBuf> {
        if let Some(existing) = &cached_default_vault {
            return Ok(existing.clone());
        }
        let (path, _) = active_vault(None, config)?;
        cached_default_vault = Some(path.clone());
        Ok(path)
    };

    for binding in merged.bindings.values() {
        match &binding.source {
            nkeepass::manifest::BindingSource::Entry(_) => {
                let path = match &binding.vault {
                    Some(spec) => resolve_vault_spec_path(spec, config)?,
                    None => resolve_default()?,
                };
                push_path(path)?;
            }
            nkeepass::manifest::BindingSource::DotEnv(
                nkeepass::env_file::EnvValueKind::Template(tmpl),
            ) => {
                let refs =
                    nkeepass::template::extract_references(tmpl).map_err(template_cli_error)?;
                for uri in refs {
                    let path = if let Some(alias) = &uri.vault_alias {
                        resolve_vault_spec_path(
                            &nkeepass::manifest::VaultSpec::Alias(alias.clone()),
                            config,
                        )?
                    } else if let Some(spec) = &binding.vault {
                        resolve_vault_spec_path(spec, config)?
                    } else {
                        resolve_default()?
                    };
                    push_path(path)?;
                }
            }
            nkeepass::manifest::BindingSource::DotEnv(
                nkeepass::env_file::EnvValueKind::Literal(_),
            ) => {}
        }
    }
    Ok(paths)
}

fn read_hook_tty_password() -> Result<Zeroizing<String>> {
    let timeout = std::time::Duration::from_secs(60);
    #[cfg(unix)]
    let pw = terminal_password::read_controlling("Master password: ", timeout)
        .map_err(|_| err("password source required for non-interactive input"))?;
    #[cfg(not(unix))]
    let pw = {
        let _ = write!(io::stderr(), "Master password: ");
        let _ = io::stderr().flush();
        let value = terminal_password::read(timeout)
            .map_err(|_| err("password source required for non-interactive input"))?;
        let _ = writeln!(io::stderr());
        value
    };
    if pw.is_empty() {
        return Err(err("password must not be empty"));
    }
    Ok(pw)
}

enum HookCredentialOutcome {
    Ready(Option<Zeroizing<String>>),
    Locked,
}

fn resolve_hook_password(
    opts: &Options<'_>,
    mode: HookMode,
    startup: bool,
) -> Result<HookCredentialOutcome> {
    let has_explicit = opts.password.is_some()
        || opts.password_env.is_some()
        || opts.password_file.is_some()
        || opts.key_file.is_some()
        || opts.password_stdin;
    if has_explicit {
        return password(opts).map(HookCredentialOutcome::Ready);
    }
    if let Some(value) = app_env_var_os(DEFAULT_PASSWORD_ENV) {
        return match value.into_string() {
            Ok(pw) if !pw.is_empty() => Ok(HookCredentialOutcome::Ready(Some(Zeroizing::new(pw)))),
            _ => Ok(HookCredentialOutcome::Locked),
        };
    }
    let opt_in_prompt = env::var_os("NKP_HOOK_PROMPT").as_deref() == Some(OsStr::new("1"))
        && !startup
        && env::var_os("CI").is_none()
        && io::stderr().is_terminal();
    if mode == HookMode::Prompt || opt_in_prompt {
        match read_hook_tty_password() {
            Ok(pw) => Ok(HookCredentialOutcome::Ready(Some(pw))),
            Err(error) => {
                if mode == HookMode::Prompt {
                    Err(error)
                } else {
                    Ok(HookCredentialOutcome::Locked)
                }
            }
        }
    } else {
        Ok(HookCredentialOutcome::Locked)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "hook state machine, trust verification, fast-path, and vault lookup share one fail-closed flow"
)]
fn run_hook_with_mode(
    shell: nkeepass::hook::HookShell,
    mode: HookMode,
    cwd_arg: Option<&str>,
    startup: bool,
    opts: &Options<'_>,
    config: &Config,
) -> Result<()> {
    let encoded_state = env::var("__NKP_ENV_STATE").unwrap_or_default();
    let state_decode = nkeepass::hook::decode_state(&encoded_state);
    let cwd_path = match cwd_arg {
        Some(raw) => PathBuf::from(raw),
        None => env::current_dir().map_err(|_| err("cannot determine current directory"))?,
    };
    let store_dir = data_dir()?;
    let trust_store = match nkeepass::trust::TrustStore::load_from_dir(&store_dir) {
        Ok(store) => store,
        Err(error) => {
            if mode == HookMode::Unload {
                let outcome = nkeepass::hook::compute_transition(
                    &encoded_state,
                    nkeepass::hook::TransitionAction::Unload {
                        current_chain_digest: None,
                    },
                    |name| env::var_os(name),
                )
                .map_err(|e| err(e.to_string()))?;
                return emit_hook_outcome(shell, &outcome);
            }
            if mode == HookMode::Prompt {
                return Err(trust_cli_error(error));
            }
            let warned = nkeepass::hook::compute_warned_digest("trust.json", "store-error");
            return emit_blocked_or_fail(
                shell,
                mode,
                &encoded_state,
                &warned,
                &format!("nkp: {error}"),
            );
        }
    };

    if mode == HookMode::Unload {
        let mut chain_digest = match &state_decode {
            nkeepass::hook::StateDecode::Valid(st) if !st.chain.is_empty() => {
                Some(nkeepass::hook::compute_chain_digest(&st.chain))
            }
            _ => None,
        };
        if chain_digest.is_none()
            && let Ok(Some(chain)) = nkeepass::manifest::discover_chain(&cwd_path, |path| {
                trust_store.contains_path(path)
            })
            && chain
                .files_to_verify
                .iter()
                .all(|f| trust_store.is_trusted(&f.canonical_path, &f.sha256))
        {
            let entries = nkeepass::hook::ChainEntry::from_discovered_chain(&chain);
            chain_digest = Some(nkeepass::hook::compute_chain_digest(&entries));
        }
        let outcome = nkeepass::hook::compute_transition(
            &encoded_state,
            nkeepass::hook::TransitionAction::Unload {
                current_chain_digest: chain_digest.as_deref(),
            },
            |name| env::var_os(name),
        )
        .map_err(|e| err(e.to_string()))?;
        return emit_hook_outcome(shell, &outcome);
    }

    let chain_opt =
        match nkeepass::manifest::discover_chain(&cwd_path, |path| trust_store.contains_path(path))
        {
            Ok(opt) => opt,
            Err(error) => {
                if mode == HookMode::Prompt {
                    return Err(manifest_cli_error(error));
                }
                let outcome = nkeepass::hook::compute_transition(
                    &encoded_state,
                    nkeepass::hook::TransitionAction::Leave,
                    |name| env::var_os(name),
                )
                .map_err(|e| err(e.to_string()))?;
                let _ = writeln!(io::stderr(), "nkp: {error}");
                return emit_hook_outcome(shell, &outcome);
            }
        };

    let Some(chain) = chain_opt else {
        let outcome = nkeepass::hook::compute_transition(
            &encoded_state,
            nkeepass::hook::TransitionAction::Leave,
            |name| env::var_os(name),
        )
        .map_err(|e| err(e.to_string()))?;
        emit_hook_outcome(shell, &outcome)?;
        if mode == HookMode::Prompt {
            return Err(err("no manifest found in current directory"));
        }
        return Ok(());
    };

    if let Some(untrusted) = chain
        .files_to_verify
        .iter()
        .find(|f| !trust_store.is_trusted(&f.canonical_path, &f.sha256))
    {
        let warned_digest =
            nkeepass::hook::compute_warned_digest(&untrusted.display_path, &untrusted.sha256);
        let msg = if trust_store.contains_path(&untrusted.canonical_path) {
            format!(
                "nkp: modified manifest {} is not trusted; run 'nkp trust'",
                untrusted.display_path
            )
        } else {
            format!(
                "nkp: untrusted manifest {}; run 'nkp trust'",
                untrusted.display_path
            )
        };
        return emit_blocked_or_fail(shell, mode, &encoded_state, &warned_digest, &msg);
    }

    let chain_entries = nkeepass::hook::ChainEntry::from_discovered_chain(&chain);
    let chain_digest = nkeepass::hook::compute_chain_digest(&chain_entries);
    let merged = match nkeepass::manifest::merge_chain_bindings(&chain) {
        Ok(m) => m,
        Err(error) => {
            if mode == HookMode::Prompt {
                return Err(manifest_cli_error(error));
            }
            let outcome = nkeepass::hook::compute_transition(
                &encoded_state,
                nkeepass::hook::TransitionAction::Leave,
                |name| env::var_os(name),
            )
            .map_err(|e| err(e.to_string()))?;
            let _ = writeln!(io::stderr(), "nkp: {error}");
            return emit_hook_outcome(shell, &outcome);
        }
    };

    if mode != HookMode::Prompt
        && let nkeepass::hook::StateDecode::Valid(ref old) = state_decode
        && old.unloaded.as_deref() == Some(chain_digest.as_str())
    {
        return Ok(());
    }

    let vault_paths = match collect_hook_vault_paths(&merged, config) {
        Ok(paths) => paths,
        Err(error) => {
            let warned =
                nkeepass::hook::compute_warned_digest(&chain_entries[0].path, &chain_digest);
            return emit_blocked_or_fail(
                shell,
                mode,
                &encoded_state,
                &warned,
                &format!("nkp: {}", error.0),
            );
        }
    };

    let mut vault_fps = Vec::with_capacity(vault_paths.len());
    for vp in &vault_paths {
        match nkeepass::hook::preopen_vault_fingerprint(vp) {
            Ok(fp) => vault_fps.push(fp),
            Err(_) => {
                let warned =
                    nkeepass::hook::compute_warned_digest(&chain_entries[0].path, &chain_digest);
                return emit_blocked_or_fail(
                    shell,
                    mode,
                    &encoded_state,
                    &warned,
                    "nkp: cannot open vault",
                );
            }
        }
    }

    if mode != HookMode::Prompt
        && let nkeepass::hook::StateDecode::Valid(ref old) = state_decode
        && nkeepass::hook::is_fast_path_unchanged(old, &chain_entries, &vault_fps, None)
    {
        return Ok(());
    }

    let resolved_vars: Vec<(String, Zeroizing<String>)> = if !merged.requires_vault_unlock {
        let mut out = Vec::with_capacity(merged.bindings.len());
        for (name, binding) in &merged.bindings {
            if let nkeepass::manifest::BindingSource::DotEnv(
                nkeepass::env_file::EnvValueKind::Literal(lit),
            ) = &binding.source
            {
                if !nkeepass::template::is_valid_secret_text(lit, true) {
                    let warned = nkeepass::hook::compute_warned_digest(
                        &chain_entries[0].path,
                        &chain_digest,
                    );
                    return emit_blocked_or_fail(
                        shell,
                        mode,
                        &encoded_state,
                        &warned,
                        "nkp: value contains disallowed control or BiDi characters",
                    );
                }
                out.push((name.clone(), Zeroizing::new(lit.clone())));
            }
        }
        out
    } else {
        let pw = match resolve_hook_password(opts, mode, startup)? {
            HookCredentialOutcome::Ready(pw) => pw,
            HookCredentialOutcome::Locked => {
                let warned =
                    nkeepass::hook::compute_warned_digest(&chain_entries[0].path, &chain_digest);
                return emit_blocked_or_fail(
                    shell,
                    mode,
                    &encoded_state,
                    &warned,
                    nkeepass::hook::LOCKED_VAULT_HINT,
                );
            }
        };
        let default_vault = active_vault(None, config).ok().map(|(p, _)| p);
        let timestamp = otp_now()?;
        let mut lookup =
            MultiVaultLookup::new(config, default_vault, pw, opts.key_file, timestamp, true);
        let render_opts = nkeepass::template::RenderOptions::default();
        let mut out = Vec::with_capacity(merged.bindings.len());

        for (name, binding) in &merged.bindings {
            let layer_vault = match &binding.vault {
                Some(spec) => match resolve_vault_spec_path(spec, config) {
                    Ok(p) => Some(p),
                    Err(error) => {
                        let warned = nkeepass::hook::compute_warned_digest(
                            &chain_entries[0].path,
                            &chain_digest,
                        );
                        return emit_blocked_or_fail(
                            shell,
                            mode,
                            &encoded_state,
                            &warned,
                            &format!("nkp: {}", error.0),
                        );
                    }
                },
                None => None,
            };
            lookup.set_layer_vault(layer_vault);
            let value_res: std::result::Result<
                Zeroizing<String>,
                nkeepass::template::TemplateError,
            > = match &binding.source {
                nkeepass::manifest::BindingSource::Entry(entry_binding) => {
                    lookup.resolve_entry_binding(entry_binding).and_then(|raw| {
                        let s = std::str::from_utf8(&raw)
                            .map_err(|_| nkeepass::template::TemplateError::NonUtf8Secret)?;
                        if !nkeepass::template::is_valid_secret_text(s, true) {
                            return Err(nkeepass::template::TemplateError::UnsafeSecretCharacters);
                        }
                        Ok(Zeroizing::new(s.to_owned()))
                    })
                }
                nkeepass::manifest::BindingSource::DotEnv(
                    nkeepass::env_file::EnvValueKind::Literal(lit),
                ) => {
                    if !nkeepass::template::is_valid_secret_text(lit, true) {
                        Err(nkeepass::template::TemplateError::UnsafeSecretCharacters)
                    } else {
                        Ok(Zeroizing::new(lit.clone()))
                    }
                }
                nkeepass::manifest::BindingSource::DotEnv(
                    nkeepass::env_file::EnvValueKind::Template(tmpl),
                ) => nkeepass::template::render_text(tmpl, &mut lookup, &render_opts),
            };
            match value_res {
                Ok(val) => out.push((name.clone(), val)),
                Err(nkeepass::template::TemplateError::VaultLocked) => {
                    lookup.lock_all();
                    let warned = nkeepass::hook::compute_warned_digest(
                        &chain_entries[0].path,
                        &chain_digest,
                    );
                    return emit_blocked_or_fail(
                        shell,
                        mode,
                        &encoded_state,
                        &warned,
                        nkeepass::hook::LOCKED_VAULT_HINT,
                    );
                }
                Err(error) => {
                    lookup.lock_all();
                    let warned = nkeepass::hook::compute_warned_digest(
                        &chain_entries[0].path,
                        &chain_digest,
                    );
                    return emit_blocked_or_fail(
                        shell,
                        mode,
                        &encoded_state,
                        &warned,
                        &format!("nkp: {error}"),
                    );
                }
            }
        }
        lookup.lock_all();
        out
    };

    let target = nkeepass::hook::TargetEnv {
        chain: chain_entries,
        vaults: vault_fps,
        session_id: None,
        resolved_vars,
    };

    match nkeepass::hook::compute_transition(
        &encoded_state,
        nkeepass::hook::TransitionAction::Activate {
            target: &target,
            force_reload: mode == HookMode::Prompt,
        },
        |name| env::var_os(name),
    ) {
        Ok(outcome) => emit_hook_outcome(shell, &outcome),
        Err(error) => {
            if mode == HookMode::Prompt {
                return Err(err(error.to_string()));
            }
            if let Some(patch) =
                nkeepass::hook::revert_only_patch(&encoded_state, |name| env::var_os(name))
            {
                let script = nkeepass::hook::emit_hook_patch(shell, &patch)
                    .map_err(|e| err(e.to_string()))?;
                write_stdout(script.as_bytes(), "cannot write hook output")?;
            }
            let _ = writeln!(io::stderr(), "nkp: {error}");
            Ok(())
        }
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

fn env_name_key_for_platform(name: &str, windows: bool) -> Cow<'_, str> {
    if windows {
        Cow::Owned(name.to_ascii_uppercase())
    } else {
        Cow::Borrowed(name)
    }
}

fn is_default_password_env_name_for_platform(name: &str, windows: bool) -> bool {
    const RESERVED: [&str; 2] = ["NEO_KEEPASS_PASSWORD", "NKP_PASSWORD"];
    let key = env_name_key_for_platform(name, windows);
    RESERVED
        .iter()
        .any(|reserved| key.as_ref() == env_name_key_for_platform(reserved, windows).as_ref())
}

#[cfg(test)]
fn is_default_password_env_name(name: &str) -> bool {
    is_default_password_env_name_for_platform(name, cfg!(windows))
}

fn validate_exec_env_names_for_platform(
    env_names: &[String],
    password_env: Option<&str>,
    windows: bool,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let password_env_key = password_env.map(|name| env_name_key_for_platform(name, windows));
    for name in env_names {
        let key = env_name_key_for_platform(name, windows);
        if is_default_password_env_name_for_platform(name, windows)
            || password_env_key
                .as_ref()
                .is_some_and(|pw_key| pw_key.as_ref() == key.as_ref())
        {
            return Err(err(
                "exec environment name is reserved for the master password",
            ));
        }
        if !valid_env_name(name) || !seen.insert(key.into_owned()) {
            return Err(err("invalid or duplicate exec environment name"));
        }
        if nkeepass::env_file::is_reserved_env_var(name) {
            return Err(err("reserved environment variable name is forbidden"));
        }
    }
    Ok(())
}

fn public_secrets_action(action: &str) -> Option<&str> {
    match action {
        "list" => Some("ls"),
        "remove" => Some("rm"),
        "environment" => Some("env"),
        "get" | "ls" | "search" | "show" | "env" | "set" | "rm" | "ensure" | "otp" | "import"
        | "export" | "sync" => Some(action),
        _ => None,
    }
}

fn public_automation_action(action: &str) -> Option<&str> {
    match action {
        "import" | "export" | "sync" => Some(action),
        _ => None,
    }
}

/// Whether these arguments are asking for help rather than doing anything.
///
/// Stops at a bare `--`, because past that separator the arguments belong to a
/// child process. `nkp exec --key K --env V -- myapp --help` has to run
/// `myapp --help`; printing this CLI's reference instead would be a command that
/// cannot launch a program whose name starts with a hyphen.
fn aliases(names: &str) -> impl Iterator<Item = &str> {
    names.split('|')
}

fn display_aliases(names: &str) -> String {
    names.replace('|', ", ")
}

fn find_help_command<'a>(commands: &'a [HelpCommand], name: &str) -> Option<&'a HelpCommand> {
    commands
        .iter()
        .find(|command| aliases(command.names).any(|alias| alias == name))
}

/// Returns the command route for a help request, without mistaking option
/// values for switches or scanning into an exec child's argument list.
fn help_request(args: &[String]) -> Option<Vec<String>> {
    // Consume root option values before applying any route-local terminator.
    // In particular, -V may own a literal -- before an exec/get-many route.
    let (mut i, route) = parsed_command_route(args);
    let mut route_tokens: Vec<String> = Vec::new();
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
                .is_some_and(|word| matches!(word.as_str(), "__complete" | "__hook"))
            {
                return None;
            }
            if (!route_tokens.is_empty() && route.is_empty())
                || (route_tokens.first().is_some_and(|group| {
                    matches!(
                        group.as_str(),
                        "secrets"
                            | "automation"
                            | "context"
                            | "alias"
                            | "config"
                            | "files"
                            | "attachment"
                            | "attachments"
                            | "group"
                            | "groups"
                            | "field"
                            | "custom-field"
                            | "shell"
                    )
                }) && route_tokens.len() > 1
                    && route.len() < 2)
            {
                return None;
            }
            return Some(route);
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
        "-k" | "-f"
            | "-b"
            | "-F"
            | "-n"
            | "-o"
            | "-B"
            | "--key"
            | "--field"
            | "--username"
            | "--url"
            | "--notes"
            | "--value"
            | "--value-env"
            | "--value-file"
            | "--chars"
            | "-c"
            | "--bin"
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
            | "--bind"
            | "--env-file"
            | "--shell"
            | "--cwd"
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

/// Route descent is contiguous, just like dispatch: `get many` reserves a
/// subcommand, but `get --field Password many` selects the entry named many.
/// Global value options own exactly one token before route parsing starts.
fn parsed_command_route(args: &[String]) -> (usize, Vec<String>) {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--vault" | "-V" | "--password-env" => index = (index + 2).min(args.len()),
            "--password-stdin" => index += 1,
            _ => break,
        }
    }
    (index, resolve_help_route(&args[index..]))
}

fn program_basename(argv0: &OsStr) -> String {
    let raw = Path::new(argv0)
        .file_name()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let stripped = match raw.len().checked_sub(4) {
        Some(prefix_len)
            if raw.is_char_boundary(prefix_len)
                && raw[prefix_len..].eq_ignore_ascii_case(".exe") =>
        {
            &raw[..prefix_len]
        }
        _ => raw.as_ref(),
    };
    if stripped.is_empty()
        || stripped
            .chars()
            .any(|c| c.is_control() || nkeepass::template::is_bidi_or_line_separator(c))
    {
        "nkp".to_owned()
    } else {
        stripped.to_owned()
    }
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

fn uses_vault_option(route: &[String]) -> bool {
    if route.is_empty() {
        return true;
    }
    if route.len() == 2 && route[0] == "context" && route[1] == "show" {
        return true;
    }
    !route.first().is_some_and(|cmd| {
        matches!(
            cmd.as_str(),
            "tui"
                | "completion"
                | "version"
                | "use"
                | "alias"
                | "config"
                | "trust"
                | "untrust"
                | "shell"
                | "context"
        )
    })
}

fn uses_credentials(route: &[String]) -> bool {
    match route {
        [get, many] if get == "get" && many == "many" => true,
        [secrets, get, many] if secrets == "secrets" && get == "get" && many == "many" => true,
        [shell, load] if shell == "shell" && load == "load" => true,
        [command] => matches!(
            command.as_str(),
            "init"
                | "exec"
                | "x"
                | "inject"
                | "get"
                | "list"
                | "ls"
                | "search"
                | "show"
                | "set"
                | "rm"
                | "remove"
                | "ensure"
                | "otp"
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
                    | "files"
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

#[cfg(test)]
fn render_help(program: &str, route: &[String], width: usize) -> String {
    render_help_with_style(program, route, width, 0)
}

fn render_help_with_style(program: &str, route: &[String], width: usize, style: u8) -> String {
    let mut output = String::new();
    let command = command_path(ROOT_COMMANDS, route);
    let usage_label = "Usage:";
    if route.is_empty() {
        let _ = writeln!(output, "{program} - {HELP_TITLE}");
        output.push('\n');
        write_paragraph(
            &mut output,
            &format!("{usage_label} {program} [GLOBAL OPTIONS] COMMAND"),
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
        output.push('\n');
        write_paragraph(
            &mut output,
            &format!("{usage_label} {program} {usage}"),
            width,
            "",
        );
        output.push('\n');
        let summary = if route.len() == 1 {
            shortcut_summary(command).unwrap_or(command.summary)
        } else {
            command.summary
        };
        write_paragraph(&mut output, summary, width, "");
        output.push('\n');
    }

    let examples = if route.is_empty() {
        ROOT_EXAMPLES
    } else {
        command.map_or(NO_EXAMPLES, |node| node.examples)
    };
    if !examples.is_empty() {
        output.push_str(if examples.len() == 1 {
            "EXAMPLE:\n"
        } else {
            "EXAMPLES:\n"
        });
        for example in examples {
            let _ = writeln!(output, "  {program} {example}");
        }
        output.push('\n');
    }

    let children = command.map_or(ROOT_COMMANDS, |node| node.children);
    if !children.is_empty() {
        output.push_str("COMMANDS:\n");
        let labels = children
            .iter()
            .map(|item| display_aliases(item.names))
            .collect::<Vec<_>>();
        let col = aligned_column(labels.iter().map(String::as_str), width);
        for (idx, (item, label)) in children.iter().zip(&labels).enumerate() {
            if route.is_empty() {
                if idx == 0 {
                    output.push_str("  Daily secrets & execution:\n");
                } else if idx == 10 {
                    output.push_str("\n  Vaults, shell & browser:\n");
                } else if idx == 19 {
                    output.push_str("\n  Entries, interchange & system:\n");
                }
            }
            let summary = if route.is_empty() {
                shortcut_summary(item).unwrap_or(item.summary)
            } else {
                item.summary
            };
            write_help_row(&mut output, label, summary, col, width);
        }
        output.push('\n');
    }

    write_help_options(&mut output, command, route, width);
    let help_notes = command.map_or(NO_NOTES, |node| node.help_notes);
    if !help_notes.is_empty() {
        output.push_str("NOTES:\n");
        for note in help_notes {
            let expanded = note.replace("{program}", program);
            write_paragraph(&mut output, &expanded, width, "  ");
        }
        output.push('\n');
    }
    if route.is_empty() || uses_credentials(route) {
        output.push_str("CREDENTIALS:\n");
        write_paragraph(
            &mut output,
            "Without an explicit source, use NEO_KEEPASS_PASSWORD, then NKP_PASSWORD. Explicit sources override them; NKEEPASS_SECRET is not an alias.",
            width,
            "  ",
        );
        output.push('\n');
        output.push_str("SAFETY:\n");
        write_paragraph(
            &mut output,
            "Credentials are prompted without echo; init never overwrites or prints a password.",
            width,
            "  ",
        );
        write_paragraph(
            &mut output,
            "WARNING: --password VALUE is exposed in process listings and shell history.",
            width,
            "  ",
        );
        write_paragraph(
            &mut output,
            "Selected values are explicit disclosures; stdout may be captured in logs or files.",
            width,
            "  ",
        );
        output.push('\n');
    }
    output.push_str("MORE HELP:\n");
    write_paragraph(
        &mut output,
        "Use -h/--help for command-specific usage and options.",
        width,
        "  ",
    );
    write_paragraph(
        &mut output,
        "See the README and docs/ for guides: “Creating a vault”, “Explicit value output”, “Glob syntax”, “Automation and interchange”, and “Shell integration”.",
        width,
        "  ",
    );
    // Wrap plain text first. Escape bytes must never affect column accounting.
    match style {
        1 => output.replacen("\nUsage:", "\n\x1b[1;36mUsage:\x1b[0m", 1),
        2 => output.replacen("\nUsage:", "\n\x1b[1;38;5;39mUsage:\x1b[0m", 1),
        3 => output.replacen("\nUsage:", "\n\x1b[1;38;2;80;190;255mUsage:\x1b[0m", 1),
        _ => output,
    }
}

fn shortcut_summary(command: &HelpCommand) -> Option<&'static str> {
    let name = aliases(command.names).next()?;
    find_help_command(SECRETS_COMMANDS, name).map(|source| source.summary)
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
    let mut globals = Vec::new();
    if uses_vault_option(route) {
        globals.push(&GLOBAL_VAULT_OPTION);
    }
    globals.push(&GLOBAL_COLOR_OPTION);
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

fn print_help(program: &str, route: &[String]) -> Result<()> {
    let style = COLOR_STYLE.load(std::sync::atomic::Ordering::Relaxed);
    let rendered =
        render_help_with_style(&sanitize_terminal_text(program), route, HELP_WIDTH, style);
    write_stdout(rendered.as_bytes(), "cannot write output")
}

static COLOR_STYLE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() || nkeepass::template::is_bidi_or_line_separator(character) {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
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
    // `get` is both a default operation and a parent. Insert credentials after
    // the actual route, never between `get` and reserved `many`.
    let offset = if command == "get" {
        usize::from(rest.first().is_some_and(|word| word == "many"))
    } else if command == "secrets"
        && rest.first().is_some_and(|word| word == "get")
        && rest.get(1).is_some_and(|word| word == "many")
    {
        2
    } else {
        usize::from(nested)
    };
    let mut route = vec![command.to_owned()];
    route.extend_from_slice(
        rest.get(..offset)
            .ok_or_else(|| err("subcommand required"))?,
    );
    if !uses_credentials(&route) {
        return Err(err("this command does not accept root credential options"));
    }
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
fn run(args: &[String], program: &str, color: ColorOption) -> Result<()> {
    if let Some(route) = help_request(args) {
        return print_help(program, &route);
    }
    if args.is_empty() {
        return print_help(program, &[]);
    }
    if args == ["--version"] || args == ["version"] {
        return print_line(&format!("nkp {}", env!("CARGO_PKG_VERSION")));
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
    if vault.is_some() {
        match command {
            "tui" => {
                return Err(err(
                    "--vault is not supported for tui; pass the vault path directly: nkp tui PATH",
                ));
            }
            "completion" | "version" | "--version" | "use" | "alias" | "config" | "trust"
            | "untrust" | "shell" | "__hook" => {
                return Err(err("this command does not accept --vault"));
            }
            "context" if rest.first().map(String::as_str) != Some("show") => {
                return Err(err("this command does not accept --vault"));
            }
            _ => {}
        }
    }
    // The help request is resolved before dispatch and configuration loading.
    // Its command tree supplies the route and the per-command option inventory;
    // it skips option values, honors the `--` boundary, and exempts the private
    // `__complete` protocol.
    if command == "tui" {
        let [path] = rest else {
            return Err(err("usage: nkp tui PATH"));
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
        return tui::launch(Path::new(path), aliases, color.into_tui_override())
            .map_err(|_| err("TUI operation failed"));
    }
    match command {
        "completion" => {
            let [shell] = rest else {
                return Err(err("unsupported completion shell"));
            };
            return write_stdout(
                completion::generate(shell)?.as_bytes(),
                "cannot write output",
            );
        }
        "trust" => return trust_command(rest),
        "untrust" => return untrust_command(rest),
        "shell"
            if matches!(
                rest.first().map(String::as_str),
                Some("init" | "completions" | "completion" | "status")
            ) =>
        {
            return shell_command(rest, &Config::default());
        }
        "__complete" => return completion::candidates(rest, vault),
        _ => {}
    }
    let mut config = load_config()?;
    match command {
        "init" => init_command(rest, vault, &mut config),
        "context" => match rest.first().map(String::as_str) {
            Some("ls" | "list") if rest.len() == 1 || (rest.len() == 2 && rest[1] == "--json") => {
                let as_json = rest.len() == 2;
                if as_json {
                    // Keep the original JSON contract: machine consumers receive
                    // configured vault aliases only. Unaliased selections are
                    // additional human-facing context rows, not alias records.
                    // Pre-validate all rows so a hostile alias never leaves
                    // partial records on stdout.
                    let mut records = Vec::new();
                    for (name, alias) in &config.aliases {
                        if alias.kind == Kind::Vault {
                            check_alias_metadata(name, alias)?;
                            let path = normalized_vault_text(&vault_path(&alias.target)?);
                            records.push(serde_json::json!({"alias": name, "path": path}));
                        }
                    }
                    for record in records {
                        json(&record)?;
                    }
                    return Ok(());
                }
                let current_path = config
                    .current
                    .as_deref()
                    .map(|value| resolve_vault(value, &config))
                    .transpose()?
                    .map(|path| normalized_vault_text(&path));
                let mut listed_paths = BTreeSet::new();
                let mut rows = Vec::new();
                for (name, alias) in &config.aliases {
                    if alias.kind == Kind::Vault {
                        check_alias_metadata(name, alias)?;
                        let path = normalized_vault_text(&vault_path(&alias.target)?);
                        let key = vault_path_key(&path);
                        let current = current_path
                            .as_deref()
                            .is_some_and(|value| vault_path_key(value) == key);
                        listed_paths.insert(key);
                        rows.push(format!(
                            "{name}\t{path}{}",
                            if current { "\t(current)" } else { "" }
                        ));
                    }
                }
                if let Some(path) = &current_path
                    && listed_paths.insert(vault_path_key(path))
                {
                    rows.push(format!("(current)\t{path}"));
                }
                if let Some(default) = &config.default_vault {
                    let path = normalized_vault_text(&resolve_vault(default, &config)?);
                    if listed_paths.insert(vault_path_key(&path)) {
                        rows.push(format!("(default)\t{path}"));
                    }
                }
                for row in rows {
                    print_line(&row)?;
                }
                Ok(())
            }
            Some("show") if rest.len() == 1 || (rest.len() == 2 && rest[1] == "--json") => {
                let (path, source) = active_vault(vault, &config)?;
                let path = normalized_vault_text(&path);
                check_config_value(&path)?;
                let environment = if source == "environment" {
                    match environment_vault("NEO_KEEPASS_VAULT")? {
                        Some(value) => Some(value),
                        None => environment_vault("NEO_KEEPASS_VAULT_PATH")?,
                    }
                } else {
                    None
                };
                let selected = match source {
                    "context" => config.current.as_deref(),
                    "argument" => vault,
                    "environment" => environment.as_deref(),
                    "default" => config.default_vault.as_deref(),
                    _ => None,
                };
                let alias = selected.and_then(|current| {
                    config
                        .aliases
                        .get(current)
                        .filter(|alias| alias.kind == Kind::Vault)
                        .map(|_| current)
                });
                if let Some(name) = alias {
                    check_config_value(name)?;
                }
                if rest.len() == 2 {
                    let legacy_alias = if source == "context" { alias } else { None };
                    json(
                        &serde_json::json!({"path": path, "source": source, "alias": legacy_alias}),
                    )
                } else {
                    writeln!(
                        io::stdout(),
                        "Name: {}\nPath: {path}\nSource: {source}",
                        alias.unwrap_or("(unnamed)")
                    )
                    .map_err(|_| err("cannot write output"))
                }
            }
            Some("use") => {
                let target = match &rest[1..] {
                    [target] if !target.starts_with('-') => target.as_str(),
                    [sep, target] if sep == "--" => target.as_str(),
                    _ => return Err(err("invalid context command; see --help")),
                };
                use_context_alias(&mut config, target)?;
                save_config(&config)
            }
            Some("rm" | "remove") if rest.len() == 2 => {
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
            Some("list" | "ls") => list_aliases(&config, parse_alias_list_format(&rest[1..])?),
            Some("resolve") if rest.len() == 2 => {
                let (name, alias) = config
                    .aliases
                    .get_key_value(&rest[1])
                    .ok_or_else(|| err("alias not found"))?;
                check_alias_metadata(name, alias)?;
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
                        if field.as_ref().is_some_and(|f| {
                            f.is_empty() || !nkeepass::template::is_safe_display_text(f)
                        }) {
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
        "get" | "list" | "ls" | "search" | "show" | "set" | "rm" | "remove" | "ensure" | "otp"
        | "import" | "export" | "sync" => {
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

        "files" | "attachment" | "attachments" | "field" | "custom-field" | "group" | "groups"
            if !rest.is_empty() =>
        {
            let action = match (command, rest[0].as_str()) {
                ("group" | "groups", "list" | "ls") => "group-ls",
                ("group" | "groups", "add" | "create" | "ensure") => "group-add",
                ("group" | "groups", "remove" | "rm") => "group-rm",
                ("files" | "attachment" | "attachments", "list" | "ls") => "attachment-ls",
                ("files" | "attachment" | "attachments", "add" | "import") => "attachment-add",
                ("files" | "attachment" | "attachments", "get" | "export") => "attachment-get",
                ("files" | "attachment" | "attachments", "remove" | "rm") => "attachment-rm",
                ("field" | "custom-field", "list" | "ls") => "field-ls",
                ("field" | "custom-field", "get" | "reveal") => "field-get",
                ("field" | "custom-field", "set" | "edit") => "field-set",
                ("field" | "custom-field", "remove" | "rm") => "field-rm",
                _ => return Err(err("unknown operation")),
            };
            operation(action, &rest[1..], vault, &config)
        }
        "use" => {
            let target = match rest {
                [target] if !target.starts_with('-') => target.as_str(),
                [sep, target] if sep == "--" => target.as_str(),
                _ => return Err(err("usage: nkp use ALIAS_OR_PATH")),
            };
            use_context_alias(&mut config, target)?;
            save_config(&config)
        }
        "exec" | "x" => exec_command(rest, vault, &config),
        "inject" => inject_command(rest, vault, &config),
        "shell" => shell_command(rest, &config),
        "__hook" => hook_command(rest, &config),
        _ => Err(err("unknown command; see --help")),
    }
}

fn main() {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map_or_else(|| "nkp".to_owned(), |arg| program_basename(&arg));
    let command_args = arguments
        .map(std::ffi::OsString::into_string)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(command_args) = command_args else {
        let _ = writeln!(io::stderr(), "nkp: arguments must be valid UTF-8");
        std::process::exit(2);
    };
    let (command_args, color) = match extract_root_color_options(&command_args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = writeln!(io::stderr(), "nkp: {}", sanitize_terminal_text(&error.0));
            std::process::exit(error.1);
        }
    };
    COLOR_STYLE.store(
        color.style(
            io::stdout().is_terminal(),
            env::var("TERM").ok().as_deref(),
            env::var("COLORTERM").ok().as_deref(),
        ),
        std::sync::atomic::Ordering::Relaxed,
    );
    let command_args = normalize_cli_aliases(&command_args);
    if let Err(error) = run(&command_args, &program, color) {
        let machine = machine_diagnostic_route(&command_args);
        let style = if machine {
            0
        } else {
            color.style(
                io::stderr().is_terminal(),
                env::var("TERM").ok().as_deref(),
                env::var("COLORTERM").ok().as_deref(),
            )
        };
        let message = sanitize_terminal_text(&error.0);
        if style == 1 {
            let _ = writeln!(io::stderr(), "\x1b[1;31mnkp:\x1b[0m {message}");
        } else if style == 2 {
            let _ = writeln!(io::stderr(), "\x1b[1;38;5;203mnkp:\x1b[0m {message}");
        } else if style == 3 {
            let _ = writeln!(io::stderr(), "\x1b[1;38;2;255;90;90mnkp:\x1b[0m {message}");
        } else {
            let _ = writeln!(io::stderr(), "nkp: {message}");
        }
        std::process::exit(error.1);
    }
}

/// Returns whether a command's diagnostics must remain plain because its route is data-oriented.
fn machine_diagnostic_route(args: &[String]) -> bool {
    let (index, route) = parsed_command_route(args);
    // Private protocol and version switch deliberately are not help nodes.
    if args
        .get(index)
        .is_some_and(|token| matches!(token.as_str(), "__complete" | "__hook" | "--version"))
    {
        return true;
    }
    let mut commands = ROOT_COMMANDS;
    let mut canonical = Vec::new();
    for token in &route {
        let Some(node) = find_help_command(commands, token) else {
            break;
        };
        canonical.push(aliases(node.names).next().unwrap_or(""));
        commands = node.children;
    }
    let Some(&command) = canonical.first() else {
        return false;
    };
    let action = canonical.get(1).copied().unwrap_or("");
    if matches!(
        command,
        "completion"
            | "__complete"
            | "__hook"
            | "version"
            | "exec"
            | "x"
            | "inject"
            | "tui"
            | "get"
            | "ls"
            | "list"
            | "search"
            | "show"
            | "otp"
            | "env"
            | "import"
            | "export"
            | "sync"
            | "config"
            | "automation"
    ) || matches!(
        command,
        "group" | "groups" | "field" | "custom-field" | "files" | "attachment" | "attachments"
    ) {
        return true;
    }
    if (command == "secrets"
        && matches!(
            action,
            "get"
                | "ls"
                | "list"
                | "search"
                | "show"
                | "otp"
                | "env"
                | "environment"
                | "import"
                | "export"
                | "sync"
        ))
        || (command == "alias" && matches!(action, "resolve" | "ls" | "list"))
        || (command == "shell"
            && matches!(
                action,
                "init" | "completions" | "completion" | "load" | "unload"
            ))
    {
        return true;
    }
    let accepts_json = command == "init"
        || command == "config"
        || command == "trust"
        || (command == "shell" && action == "status")
        || command == "context" && matches!(action, "ls" | "list" | "show")
        || command == "secrets" && matches!(action, "ls" | "list");
    let mut cursor = index + 1;
    while cursor < args.len() {
        let token = args[cursor].as_str();
        if token == "--" {
            break;
        }
        if token == "--json" && accepts_json {
            return true;
        }
        if takes_option_value(token) {
            cursor += 2;
        } else {
            cursor += 1;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorOption {
    Auto,
    Always,
    Never,
    Basic,
    Truecolor,
}

impl ColorOption {
    const fn into_tui_override(self) -> tui::ColorOverride {
        match self {
            Self::Auto => tui::ColorOverride::Auto,
            Self::Always => tui::ColorOverride::Always,
            Self::Never => tui::ColorOverride::Never,
            Self::Basic => tui::ColorOverride::Basic,
            Self::Truecolor => tui::ColorOverride::TrueColor,
        }
    }

    fn detected_style(term: Option<&str>, colorterm: Option<&str>) -> u8 {
        if matches!(
            colorterm,
            Some(value) if value.eq_ignore_ascii_case("truecolor")
                || value.eq_ignore_ascii_case("24bit")
        ) {
            3
        } else if term.is_some_and(|term| term.contains("256color")) {
            2
        } else {
            1
        }
    }

    fn style(self, tty: bool, term: Option<&str>, colorterm: Option<&str>) -> u8 {
        self.style_with_terminal_support(tty, term, colorterm, !cfg!(windows))
    }

    fn style_with_terminal_support(
        self,
        tty: bool,
        term: Option<&str>,
        colorterm: Option<&str>,
        terminal_supports_ansi: bool,
    ) -> u8 {
        if !terminal_supports_ansi || self == Self::Never || term == Some("dumb") {
            return 0;
        }
        match self {
            Self::Never => 0,
            Self::Basic => 1,
            Self::Truecolor | Self::Always => Self::detected_style(term, colorterm),
            Self::Auto if tty => Self::detected_style(term, colorterm),
            Self::Auto => 0,
        }
    }
}

/// Extracts presentation switches while leaving option values and child arguments intact.
fn extract_root_color_options(args: &[String]) -> Result<(Vec<String>, ColorOption)> {
    let mut output = Vec::with_capacity(args.len());
    let mut explicit = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = if let Some(value) = arg.strip_prefix("--color=") {
            Some(value)
        } else if arg == "--color" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| err("--color requires a value"))?;
            if value == "--" {
                return Err(err("--color requires a value before --"));
            }
            i += 1;
            Some(value.as_str())
        } else {
            None
        };
        if let Some(value) = value {
            if explicit.is_some() {
                return Err(err("duplicate color option"));
            }
            explicit = Some(match value {
                "auto" => ColorOption::Auto,
                "always" => ColorOption::Always,
                "never" => ColorOption::Never,
                "basic" => ColorOption::Basic,
                "truecolor" => ColorOption::Truecolor,
                _ => return Err(err("invalid --color value")),
            });
            i += 1;
            continue;
        }
        if arg == "--no-color" {
            if explicit.is_some() {
                return Err(err("duplicate color option"));
            }
            explicit = Some(ColorOption::Never);
            i += 1;
            continue;
        }
        match arg {
            "--vault" | "-V" | "--password-env" => {
                output.push(args[i].clone());
                if let Some(value) = args.get(i + 1) {
                    output.push(value.clone());
                }
                i = (i + 2).min(args.len());
            }
            "--password-stdin" => {
                output.push(args[i].clone());
                i += 1;
            }
            _ => {
                output.extend_from_slice(&args[i..]);
                break;
            }
        }
    }
    let env_choice = if let Some(no_color) = env::var_os("NO_COLOR") {
        if !no_color.is_empty() {
            Some(ColorOption::Never)
        } else {
            force_color_option()
        }
    } else {
        force_color_option()
    };
    Ok((output, explicit.or(env_choice).unwrap_or(ColorOption::Auto)))
}

fn force_color_option() -> Option<ColorOption> {
    match env::var("FORCE_COLOR").ok()?.as_str() {
        "0" => Some(ColorOption::Never),
        "" | "1" | "true" | "2" => Some(ColorOption::Basic),
        "3" => Some(ColorOption::Truecolor),
        _ => None,
    }
}

/// Expands short option and command aliases before dispatch, without rewriting
/// arguments belonging to an `exec` child after the `--` boundary.
fn normalize_cli_aliases(args: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(args.len());
    let (route_index, route) = parsed_command_route(args);
    let exec_route = route
        .first()
        .is_some_and(|route| matches!(route.as_str(), "exec" | "x"));
    let mut after_separator = false;
    let mut expects_value = false;
    for (index, arg) in args.iter().enumerate() {
        if after_separator {
            normalized.push(arg.clone());
            continue;
        }
        // Exec's first separator is local to its route. A root -V/--vault
        // value spelled -- is still data, as it is in global parsing.
        if arg == "--" && ((exec_route && index > route_index) || !expects_value) {
            after_separator = true;
            normalized.push(arg.clone());
            continue;
        }
        if expects_value {
            normalized.push(arg.clone());
            expects_value = false;
            continue;
        }
        expects_value = takes_option_value(arg)
            || (index < route_index && matches!(arg.as_str(), "-V" | "--vault"));
        let replacement = match arg.as_str() {
            "-k" => Some("--key"),
            "-f" => Some("--file"),
            "-F" => Some("--field"),
            "-n" => Some("--name"),
            "-o" => Some("--output"),
            "-y" => Some("--yes"),
            "-B" => Some("--bind"),
            _ => None,
        };
        normalized.push(replacement.unwrap_or(arg).to_owned());
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_policy_honors_tty_depth_and_safety() {
        let style = |color: ColorOption, tty: bool, term: Option<&str>, colorterm: Option<&str>| {
            color.style_with_terminal_support(tty, term, colorterm, true)
        };
        assert_eq!(
            style(ColorOption::Auto, false, Some("xterm-256color"), None),
            0
        );
        assert_eq!(
            style(ColorOption::Auto, true, Some("dumb"), Some("truecolor")),
            0
        );
        assert_eq!(style(ColorOption::Auto, true, Some("xterm"), None), 1);
        assert_eq!(
            style(ColorOption::Auto, true, Some("xterm-256color"), None),
            2
        );
        assert_eq!(
            style(
                ColorOption::Auto,
                true,
                Some("xterm-256color"),
                Some("24bit")
            ),
            3
        );
        assert_eq!(
            style(ColorOption::Auto, true, Some("xterm"), Some("24bit")),
            3
        );
        assert_eq!(style(ColorOption::Always, false, Some("xterm"), None), 1);
        assert_eq!(
            style(ColorOption::Always, false, Some("tmux-256color"), None),
            2
        );
        assert_eq!(
            style(ColorOption::Always, false, Some("dumb"), Some("truecolor")),
            0
        );
        assert_eq!(style(ColorOption::Truecolor, false, Some("xterm"), None), 1);
        assert_eq!(
            style(ColorOption::Truecolor, false, Some("xterm-256color"), None),
            2
        );
        assert_eq!(
            style(ColorOption::Never, true, Some("xterm"), Some("truecolor")),
            0
        );
        assert_eq!(
            ColorOption::Always.style_with_terminal_support(
                false,
                Some("xterm"),
                Some("truecolor"),
                false
            ),
            0
        );
    }

    #[test]
    fn color_switch_extraction_respects_values_and_separator() {
        let args = ["show", "--key", "--color", "--", "--color=always"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);

        let args = ["--color=always", "show"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, ["show"]);
        assert_eq!(color, ColorOption::Always);

        let args = ["show", "--color", "invalid"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);

        let args = ["--color", "invalid"].map(str::to_owned);
        assert!(extract_root_color_options(&args).is_err());
        let args = ["--color", "--", "show"].map(str::to_owned);
        assert!(extract_root_color_options(&args).is_err());

        let args = ["--vault", "--no-color", "show"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);

        let args = ["alias", "set", "demo", "--no-color"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);

        let args = ["__complete", "entries", "--color=bogus"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);

        let args = ["exec", "nkp", "--", "--no-color"].map(str::to_owned);
        let (remaining, color) = extract_root_color_options(&args).unwrap();
        assert_eq!(remaining, args);
        assert_eq!(color, ColorOption::Auto);
    }

    #[test]
    fn help_styles_only_usage_and_sanitizes_program_name() {
        let help = render_help_with_style("nkp Usage:", &[], HELP_WIDTH, 1);
        assert!(help.contains("\x1b[1;36mUsage:\x1b[0m nkp Usage: [GLOBAL OPTIONS] COMMAND"));
        assert_eq!(sanitize_terminal_text("nkp\u{1b}[31m"), "nkp\u{fffd}[31m");
        // Private formatter: layout must not depend on invisible SGR bytes.
        for width in [24, 40, 88] {
            for route in [vec![], vec!["get".to_owned(), "many".to_owned()]] {
                let plain = render_help("nkp", &route, width);
                for (style, sgr) in [
                    (1, "\x1b[1;36m"),
                    (2, "\x1b[1;38;5;39m"),
                    (3, "\x1b[1;38;2;80;190;255m"),
                ] {
                    let styled = render_help_with_style("nkp", &route, width, style);
                    assert_eq!(styled.replace(sgr, "").replace("\x1b[0m", ""), plain);
                }
            }
        }
    }

    #[test]
    fn program_basename_strips_exe_and_sanitizes() {
        for (argv0, expected) in [
            ("nkp", "nkp"),
            ("nkeepass", "nkeepass"),
            ("kp", "kp"),
            ("nkpo", "nkpo"),
            ("/usr/local/bin/kp", "kp"),
            ("nkp.exe", "nkp"),
            ("kp.EXE", "kp"),
            ("NKeepass.Exe", "NKeepass"),
            (".exe", "nkp"),
            (".EXE", "nkp"),
            ("", "nkp"),
            ("/", "nkp"),
            ("bad\x1bname", "nkp"),
            ("bad\u{202e}name", "nkp"),
        ] {
            assert_eq!(program_basename(OsStr::new(argv0)), expected, "{argv0}");
        }
        #[cfg(windows)]
        assert_eq!(program_basename(OsStr::new(r"C:\Tools\nkp.exe")), "nkp");

        let init_help = render_help("kp", &["init".to_owned()], HELP_WIDTH);
        assert!(init_help.contains("to kp --vault DATABASE"));
        assert!(!init_help.contains("to nkp --vault DATABASE"));

        let shell_help = render_help("kp", &["shell".to_owned(), "init".to_owned()], HELP_WIDTH);
        assert!(shell_help.contains("use `kp shell completions sh` or `kp completion sh`"));
        assert!(!shell_help.contains("`nkp shell completions sh`"));
    }

    #[test]
    fn machine_diagnostic_detection_uses_route_and_option_ownership() {
        let args = ["alias", "resolve", "demo"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        let args = ["alias", "ls"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        let args = ["context", "ls"].map(str::to_owned);
        assert!(!machine_diagnostic_route(&args));
        let args = ["context", "ls", "--json"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        let args = ["alias", "set", "completion", "--json"].map(str::to_owned);
        assert!(!machine_diagnostic_route(&args));
        let args = ["show", "--key", "--json"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        let args = ["exec", "child", "--json"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        let args = ["show", "--", "--json"].map(str::to_owned);
        assert!(machine_diagnostic_route(&args));
        for plain_route in [
            ["__hook", "bash"].as_slice(),
            ["inject", "tmpl.txt"].as_slice(),
            ["shell", "init", "bash"].as_slice(),
            ["shell", "completions", "fish"].as_slice(),
            ["shell", "status", "--json"].as_slice(),
            ["trust", "--list", "--json"].as_slice(),
        ] {
            let owned = plain_route
                .iter()
                .copied()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(
                machine_diagnostic_route(&owned),
                "{plain_route:?} should use machine diagnostics"
            );
        }
        let status_human = ["shell", "status"].map(str::to_owned);
        assert!(!machine_diagnostic_route(&status_human));
    }

    #[test]
    fn binding_collision_checks_follow_format_namespaces() {
        for format in ["azure-devops", "github-actions", "pwsh", "powershell"] {
            assert!(validate_binding_names(format, ["TOKEN", "token"]).is_err());
            assert!(validate_binding_names(format, ["TOKEN", "OTHER"]).is_ok());
        }
        for format in ["json", "text", "null", "shell"] {
            assert!(validate_binding_names(format, ["TOKEN", "token"]).is_ok());
        }
        assert_eq!(
            validate_binding_names("dotenv", ["TOKEN", "token"]).is_err(),
            cfg!(windows)
        );
    }

    #[test]
    fn bundle_writer_is_bounded_and_does_not_reallocate_secret_storage() {
        let mut bundle = BundleBuffer(Zeroizing::new(Vec::with_capacity(4)));
        let original = bundle.0.as_ptr();
        bundle.write_all(b"1234").unwrap();
        assert!(bundle.write_all(b"5").is_err());
        assert_eq!(bundle.0.as_ptr(), original);
        assert_eq!(bundle.0.as_slice(), b"1234");
    }

    #[test]
    fn get_many_path_budget_is_checked_before_vault_or_credentials() {
        let over_budget = "A".repeat(64 * 1024 + 1);
        let opts = Options {
            requested_paths: vec![over_budget.as_str()],
            ..Options::default()
        };
        assert!(validate_regular_options("get-many", &opts).is_err());
    }

    #[test]
    fn exec_reserves_all_default_password_variable_names() {
        for name in ["NEO_KEEPASS_PASSWORD", "NKP_PASSWORD"] {
            assert!(is_default_password_env_name(name));
        }
        #[cfg(windows)]
        assert!(is_default_password_env_name("neo_keepass_password"));
        #[cfg(not(windows))]
        assert!(!is_default_password_env_name("neo_keepass_password"));
    }

    #[test]
    fn short_key_file_and_field_options_expand_only_before_exec_separator() {
        let args =
            ["get", "-k", "Root/mail", "-F", "Password", "-f", "data.bin"].map(str::to_owned);
        assert_eq!(
            normalize_cli_aliases(&args),
            [
                "get",
                "--key",
                "Root/mail",
                "--field",
                "Password",
                "--file",
                "data.bin"
            ]
            .map(str::to_owned)
        );
        let value_is_alias_like = ["get", "--key", "-f"].map(str::to_owned);
        assert_eq!(
            normalize_cli_aliases(&value_is_alias_like),
            value_is_alias_like
        );
        let command_aliases = ["list", "remove"].map(str::to_owned);
        assert_eq!(normalize_cli_aliases(&command_aliases), command_aliases);
        let args = ["exec", "--", "child", "-k", "-f", "-F"].map(str::to_owned);
        assert_eq!(normalize_cli_aliases(&args), args);
    }

    #[test]
    fn exec_normalization_starts_its_separator_search_after_owned_root_values() {
        // Critical argv parser regression: -V owns --; only the later --,
        // after x and its binding options, belongs to exec.
        let args = [
            "-V",
            "--",
            "x",
            "-k",
            "test",
            "--env",
            "OUT",
            "--",
            "/bin/echo",
            "-k",
        ]
        .map(str::to_owned);
        assert_eq!(
            normalize_cli_aliases(&args),
            [
                "-V",
                "--",
                "x",
                "--key",
                "test",
                "--env",
                "OUT",
                "--",
                "/bin/echo",
                "-k"
            ]
            .map(str::to_owned)
        );
        let args = [
            "--vault",
            "-k",
            "x",
            "-k",
            "test",
            "--env",
            "OUT",
            "--",
            "/bin/echo",
            "-k",
        ]
        .map(str::to_owned);
        assert_eq!(
            normalize_cli_aliases(&args),
            [
                "--vault",
                "-k",
                "x",
                "--key",
                "test",
                "--env",
                "OUT",
                "--",
                "/bin/echo",
                "-k"
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn help_consumes_root_owned_separator_values_before_local_boundaries() {
        // Critical help parser: a root vault value is not exec's separator.
        for (args, expected) in [
            (vec!["-V", "--", "x", "--help"], Some(vec!["x"])),
            (
                vec!["-V", "--", "get", "many", "--help"],
                Some(vec!["get", "many"]),
            ),
            (
                vec!["--vault", "--", "secrets", "get", "many", "-h"],
                Some(vec!["secrets", "get", "many"]),
            ),
            (vec!["-V", "--", "x", "--", "child", "--help"], None),
            (
                vec!["-V", "--", "x", "--key", "--", "child", "--help"],
                None,
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                help_request(&args),
                expected.map(|route| route.into_iter().map(str::to_owned).collect())
            );
        }
    }

    #[test]
    fn entry_key_can_be_positional_before_or_after_options_and_preserves_paths() {
        for action in ["get", "set", "rm"] {
            for args in [
                vec![action, "Root/Mail Account"],
                vec![action, "--field", "Notes", "Root/Mail Account"],
                vec![action, "Root\\Mail Account", "--field", "Notes"],
                vec![
                    action,
                    "--field",
                    "Notes",
                    "--",
                    "C:\\Users\\name\\Vault\\Mail",
                ],
                vec![action, "--field", "Password", "--", "-DashEntry"],
                vec![action, "--key", "Root/Mail Account"],
            ] {
                let values = args
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>();
                let parsed =
                    options(&values[1..], Positional::for_action(action)).expect("valid selector");
                assert!(parsed.key.is_some(), "{args:?}");
            }
        }
        let short = ["get", "-k", "Root/Mail Account"].map(str::to_owned);
        let normalized = normalize_cli_aliases(&short);
        assert!(
            options(&normalized[1..], Positional::for_action("get"))
                .expect("normalized short selector")
                .key
                .is_some()
        );
    }

    #[test]
    fn grouped_route_selectors_are_positional_without_changing_nested_selectors() {
        for action in [
            "group-add",
            "group-rm",
            "field-ls",
            "field-get",
            "field-set",
            "field-rm",
            "attachment-ls",
            "attachment-get",
            "attachment-add",
            "attachment-rm",
        ] {
            let expected_positional = match action {
                "field-get" | "field-set" | "field-rm" => {
                    matches!(Positional::for_action(action), Positional::KeyAndField)
                }
                "attachment-get" | "attachment-add" | "attachment-rm" => {
                    matches!(Positional::for_action(action), Positional::KeyAndAttachment)
                }
                _ => matches!(Positional::for_action(action), Positional::Key),
            };
            assert!(expected_positional, "{action}");
            let values = vec!["--dry-run".to_owned(), "Root/Group/Entry".to_owned()];
            let parsed = options(&values, Positional::for_action(action)).expect("selector");
            assert_eq!(parsed.key, Some("Root/Group/Entry"), "{action}");
        }
        for action in ["group-rm", "field-get", "attachment-get"] {
            let values = vec![
                "Root/Group/Entry".to_owned(),
                "--key".to_owned(),
                "Other".to_owned(),
            ];
            assert!(
                options(&values, Positional::for_action(action)).is_err(),
                "{action}"
            );
        }
        let dash_path = vec!["--".to_owned(), "-Dash/Entry".to_owned()];
        assert_eq!(
            options(&dash_path, Positional::for_action("field-get"))
                .expect("literal selector")
                .key,
            Some("-Dash/Entry")
        );
    }

    #[test]
    fn entry_key_rejects_multiple_selectors_and_non_key_positionals() {
        for args in [
            vec!["get", "LOGIN", "--key", "LOGIN"],
            vec!["set", "--key", "LOGIN", "OTHER"],
            vec!["rm", "LOGIN", "OTHER"],
            vec!["get", "--key", "LOGIN", "--key", "OTHER"],
        ] {
            let action = args[0];
            let values = args
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
            let error = match options(&values[1..], Positional::for_action(action)) {
                Err(error) => error,
                Ok(_) => panic!("duplicate selector unexpectedly succeeded: {args:?}"),
            };
            assert!(
                error.0.contains("entry key specified more than once"),
                "{args:?}: {:?}",
                error
            );
        }
        assert!(
            options(
                &["show".to_owned(), "LOGIN".to_owned()],
                Positional::Forbidden
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(unix)]
    fn init_password_backup_is_encrypted_private_and_never_clobbers() {
        let home = tempfile::tempdir().expect("isolated home");
        let password = "user-selected-master-password";
        let target = backup_init_password_in(password, home.path()).expect("backup");
        let ciphertext = fs::read(&target).expect("encrypted backup");
        assert!(
            !ciphertext
                .windows(password.len())
                .any(|window| window == password.as_bytes())
        );
        let identity_path = home.path().join("config/nkeepass/init-password.agekey");
        let identity_text = fs::read_to_string(&identity_path).expect("identity");
        let identity = AgeIdentity::from_private_key(identity_text.trim()).expect("parse identity");
        assert_eq!(
            decrypt_age_input(&ciphertext, &[identity])
                .expect("decrypt")
                .as_slice(),
            password.as_bytes()
        );
        let other_backup =
            backup_init_password_in("different-password", home.path()).expect("second backup");
        assert_ne!(other_backup, target);
        assert_eq!(fs::read(&target).expect("preserved backup"), ciphertext);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [target, identity_path] {
                assert_eq!(
                    fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn concurrent_first_backups_validate_and_reuse_the_winning_identity() {
        let home = tempfile::tempdir().expect("isolated home");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = ["concurrent-master-one", "concurrent-master-two"]
            .into_iter()
            .map(|password| {
                let home = home.path().to_path_buf();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let backup = backup_init_password_in(password, &home).expect("backup");
                    (password, backup)
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("initializer thread"))
            .collect();
        let identity_path = home.path().join("config/nkeepass/init-password.agekey");
        let identity_text = fs::read_to_string(identity_path).expect("shared identity");
        let identity = AgeIdentity::from_private_key(identity_text.trim()).expect("valid winner");
        for (password, target) in results {
            let ciphertext = fs::read(target).expect("encrypted backup");
            assert_eq!(
                decrypt_age_input(&ciphertext, std::slice::from_ref(&identity))
                    .expect("decrypt")
                    .as_slice(),
                password.as_bytes()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn backup_storage_rejects_symlink_and_non_directory_targets_before_chmod() {
        let home = tempfile::tempdir().expect("isolated home");
        let config_parent = home.path().join("config");
        fs::create_dir_all(&config_parent).expect("config parent");
        let destination = home.path().join("unrelated-destination");
        fs::create_dir(&destination).expect("destination directory");
        #[cfg(unix)]
        let original_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&destination)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777
        };
        #[cfg(unix)]
        std::os::unix::fs::symlink(&destination, config_parent.join("nkeepass"))
            .expect("backup directory symlink");
        #[cfg(windows)]
        fs::write(config_parent.join("nkeepass"), b"preserve").expect("not a directory");
        assert!(backup_init_password_in("isolated-password", home.path()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination)
                    .expect("target metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                original_mode
            );
        }
        #[cfg(windows)]
        assert_eq!(
            fs::read(config_parent.join("nkeepass")).expect("preserved file"),
            b"preserve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn backup_data_directory_symlink_is_refused_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().expect("isolated home");
        let destination = home.path().join("data-target");
        fs::create_dir(&destination).expect("target directory");
        let mode = fs::metadata(&destination)
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777;
        fs::create_dir_all(home.path().join("config/nkeepass")).expect("config directory");
        fs::create_dir_all(home.path().join("data")).expect("data parent");
        std::os::unix::fs::symlink(&destination, home.path().join("data/nkeepass"))
            .expect("data directory symlink");

        assert!(backup_init_password_in("isolated-password", home.path()).is_err());
        assert_eq!(
            fs::metadata(destination)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }

    /// Puts a fixture connection into the mode its bounded blocking
    /// reads assume. The fixture listener is non-blocking so its accept
    /// loop can poll, and POSIX `accept` always yields a blocking socket —
    /// but Winsock sockets accepted from a non-blocking listener INHERIT
    /// the non-blocking mode, so the fixture's first request read failed
    /// with WouldBlock (os error 10035) and curl exited 56 while the
    /// fixture thread panicked (Windows run 134548307275). Making the
    /// accepted mode explicit keeps the read governed by the read timeout
    /// on every platform instead of relying on platform-specific
    /// inheritance.
    fn accepted_request_stream_blocking(stream: std::net::TcpStream) -> std::net::TcpStream {
        stream
            .set_nonblocking(false)
            .expect("fixture connection blocking mode");
        stream
    }

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
                    Ok((stream, _)) => {
                        let mut stream = accepted_request_stream_blocking(stream);
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

    /// Pins the blocking-read contract the HTTP fixture depends on after
    /// `accept`: the client deliberately writes its bytes only after the
    /// accept returned, so a socket still in the listener's non-blocking
    /// mode fails the read immediately instead of waiting. Winsock
    /// inheritance of the listener mode is what broke the fixture in
    /// Windows run 134548307275 (WouldBlock, os error 10035); POSIX
    /// `accept` always returns a blocking socket, so on Unix this can
    /// only ever validate the same sequence the fixture runs — the
    /// regression it guards is observable on Windows alone, the same
    /// honest reach note the completion source-gating test carries.
    /// The read timeout bounds the wait, so a lost mode flip fails fast
    /// instead of hanging the test binary.
    #[test]
    fn accepted_fixture_stream_blocks_until_the_client_writes() {
        use std::{
            io::{ErrorKind, Read},
            net::{TcpListener, TcpStream},
            sync::mpsc,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind regression listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking regression listener");
        let address = listener.local_addr().expect("regression address");
        let (connected, connected_rx) = mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let mut client = TcpStream::connect(address).expect("regression client connect");
            connected.send(()).expect("regression connect handshake");
            std::thread::sleep(std::time::Duration::from_millis(200));
            client
                .write_all(b"regression-payload")
                .expect("regression client write");
        });
        let accepted = {
            // Same poll shape as the fixture loop: a non-blocking
            // listener's accept reports WouldBlock until the handshake
            // completes, so retry within a bound instead of racing it.
            let deadline = std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(2))
                .expect("regression accept deadline");
            loop {
                match listener.accept() {
                    Ok((accepted, _)) => break accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "regression client never reached the listener"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("regression accept failed: {error}"),
                }
            }
        };
        let mut stream = accepted_request_stream_blocking(accepted);
        connected_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("client handshake before the delayed write");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("regression read timeout");
        let mut read = Vec::new();
        let expected = b"regression-payload";
        while read.len() < expected.len() {
            let mut chunk = [0_u8; 64];
            let count = stream
                .read(&mut chunk)
                .expect("accepted stream blocks until the client writes");
            assert!(count > 0, "accepted stream closed before the payload");
            read.extend_from_slice(&chunk[..count]);
        }
        writer.join().expect("regression writer thread");
        assert_eq!(read, expected);
    }

    #[test]
    fn recipient_curl_child_environment_is_minimal() {
        // Assert on std::process::Command's effective child environment. This
        // catches accidental re-inheritance while remaining independent of
        // credentials in the test runner's environment.
        let mut command = std::process::Command::new("curl");
        command
            .env_clear()
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .envs(recipient_curl_windows_environment());
        let environment: Vec<_> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(environment.iter().any(|(name, value)| {
            name == "PATH"
                && value.as_deref() == Some(env::var("PATH").unwrap_or_default().as_str())
        }));
        if cfg!(windows) {
            assert!(environment.iter().any(|(name, value)| {
                name == "SystemRoot" && value.as_deref() == env::var("SystemRoot").ok().as_deref()
            }));
        } else {
            assert_eq!(environment.len(), 1);
        }
        assert!(
            environment
                .iter()
                .all(|(name, _)| { name == "PATH" || cfg!(windows) && name == "SystemRoot" })
        );
    }

    #[test]
    fn curl_fixture_diagnostic_classifies_process_exit() {
        let diagnostic = curl_fixture_diagnostic(CurlFixtureProcess::Completed(Some(7)));
        assert!(diagnostic.contains("exit_code=7"));
        assert!(diagnostic.contains("connection error"));
        assert_eq!(
            curl_fixture_diagnostic(CurlFixtureProcess::CouldNotStart),
            "process=not-started; category=executable unavailable"
        );
        assert_eq!(
            curl_fixture_diagnostic(CurlFixtureProcess::Completed(None)),
            "process=completed_without_exit_code; category=abnormal termination"
        );
    }

    #[test]
    fn recipient_fixture_reports_missing_curl_without_changing_path() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let missing_program = temp.path().join("curl-that-does-not-exist");
        let error = fetch_recipient_url_with_program(
            "http://127.0.0.1:1/keys",
            RecipientTransport::HttpFixture,
            missing_program.as_os_str(),
        )
        .expect_err("missing executable");

        assert!(error.0.contains("category=executable unavailable"));
        assert!(!error.0.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn recipient_fixture_reports_signal_termination_separately_from_spawn_failure() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temporary directory");
        let program = temp.path().join("curl-terminated-by-signal");
        fs::write(&program, "#!/bin/sh\nkill -TERM $$\n").expect("write curl fixture");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
            .expect("make curl fixture executable");

        let error = fetch_recipient_url_with_program(
            "http://127.0.0.1:1/keys",
            RecipientTransport::HttpFixture,
            program.as_os_str(),
        )
        .expect_err("signal-terminated executable");

        assert!(error.0.contains("process=completed_without_exit_code"));
        assert!(error.0.contains("category=abnormal termination"));
        assert!(!error.0.contains("process=not-started"));
        assert!(!error.0.contains(temp.path().to_string_lossy().as_ref()));
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
        let help = render_help("nkp", &["get".to_owned()], HELP_WIDTH);
        let command_option = help.find("--key PATH").unwrap();
        let global_heading = help.find("GLOBAL OPTIONS:").unwrap();
        let global_option = help.find("-V, --vault PATH").unwrap();
        assert!(command_option < global_heading);
        assert!(global_heading < global_option);

        let context = render_help("nkp", &["context".to_owned()], HELP_WIDTH);
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
            let help = render_help("nkp", &route, HELP_WIDTH);
            let options = help.find("OPTIONS:\n").unwrap();
            let globals = help.find("GLOBAL OPTIONS:\n").unwrap();
            assert!(options < globals);
            let global_options = &help[globals..];
            assert!(global_options.contains("--password-env NAME"));
            assert!(global_options.contains("--password-stdin"));
            assert!(global_options.contains("NEO_KEEPASS_PASSWORD"));
            if !route.is_empty() {
                let command_options = &help[options..globals];
                assert!(command_options.contains("--key PATH"));
                assert!(command_options.contains("--password-env NAME"));
                assert!(command_options.contains("--password-stdin"));
            }
        }

        let context = render_help(
            "nkp",
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
                    "nkp",
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
                "nkp",
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
                Some("opts") => matches!(
                    field,
                    "password" | "key" | "name" | "username" | "url" | "notes" | "bins"
                ),
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
    #[cfg(unix)]
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
    fn generated_backup_association_survives_context_save_failure_without_clobber() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("synthetic.kdbx");
        let password = "synthetic-generated-password-for-test";
        let mut backup = backup_init_password_at(
            password,
            &temp.path().join("config"),
            &temp.path().join("data"),
        )
        .unwrap();
        associate_init_backup(&mut backup, vault.to_str().unwrap()).unwrap();
        let association = backup.association_path.as_ref().unwrap().clone();
        let initial = fs::read(&association).unwrap();
        assert!(associate_init_backup(&mut backup, vault.to_str().unwrap()).is_err());
        assert_eq!(fs::read(&association).unwrap(), initial);
        let mut credentials = KdbxCredentials::password(password).unwrap();
        let created = VaultService::default().create(
            &vault,
            &mut credentials,
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            None,
        );
        let error = adopt_after_init_create(
            &mut Config::default(),
            vault.to_str().unwrap(),
            true,
            created,
            |_| Err(err("injected configuration persistence failure")),
        )
        .unwrap_err();
        assert!(
            error
                .0
                .contains("injected configuration persistence failure")
        );
        assert!(vault.is_file());
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(association).unwrap()).unwrap();
        assert_eq!(record["vault"], vault.to_str().unwrap());
        assert_eq!(record["password_backup"], backup.path.to_str().unwrap());
        assert_eq!(record["status"], "candidate");
    }

    #[cfg(unix)]
    #[test]
    fn reused_published_identity_requires_its_own_durability_confirmation() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config");
        let data = temp.path().join("data");
        ensure_backup_dir(&config, "synthetic failure").unwrap();
        let identity_path = config.join("init-password.agekey");
        let key = neotales_age::AgeKey::generate().unwrap();
        let private = Zeroizing::new(key.private_key);
        // Simulate the publisher after no-clobber publication, but before its
        // parent sync has finished. The reader must perform its own barrier.
        let mut stage = nkeepass::private_file::new_private_temp(&config).unwrap();
        stage.write_all(private.as_bytes()).unwrap();
        stage.as_file().sync_all().unwrap();
        stage.persist_noclobber(&identity_path).unwrap();
        let called = std::cell::Cell::new(false);
        let result =
            backup_init_password_at_with("synthetic-password", &config, &data, |file, path| {
                called.set(true);
                assert_eq!(path, identity_path);
                assert!(file.metadata().unwrap().is_file());
                Err(err("injected identity parent durability failure"))
            });
        assert!(called.get());
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().0,
            "injected identity parent durability failure"
        );
        assert_eq!(fs::read_dir(&data).unwrap().count(), 0);
        let retry =
            backup_init_password_at_with("synthetic-password", &config, &data, |file, path| {
                confirm_backup_identity_durability(file, path)
            })
            .unwrap();
        assert!(!retry.identity_created);
        assert!(retry.path.is_file());
    }

    #[test]
    fn association_durability_failure_reports_installed_candidate_before_vault_creation() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault.kdbx");
        let mut backup = backup_init_password_at(
            "synthetic-password",
            &temp.path().join("config"),
            &temp.path().join("data"),
        )
        .unwrap();
        let error =
            associate_init_backup_with(&mut backup, vault.to_str().unwrap(), |path, bytes| {
                nkeepass::private_file::write_private_noclobber(path, bytes)?;
                Err("output installed but directory durability is unconfirmed")
            })
            .unwrap_err();
        assert!(error.installed);
        assert!(error.message.contains("durability is unconfirmed"));
        let candidate = backup.association_path.as_ref().unwrap();
        assert!(candidate.is_file());
        assert!(!vault.exists());
        let report = association_failure_record(&backup, vault.to_str().unwrap(), &error);
        assert_eq!(report["operation"], "init-association-failed");
        assert_eq!(report["vault_install_started"], false);
        assert_eq!(report["association_installed"], true);
        assert_eq!(report["association_candidate"], candidate.to_str().unwrap());
        assert!(!report.to_string().contains("synthetic-password"));
        let failure = associate_init_backup_with(&mut backup, vault.to_str().unwrap(), |_, _| {
            Err("output exists")
        })
        .unwrap_err();
        assert!(!failure.installed);
        assert_eq!(failure.message, "recovery association already exists");
        let report = association_failure_record(&backup, vault.to_str().unwrap(), &failure);
        assert_eq!(report["association_installed"], false);
        assert_eq!(report["vault_install_started"], false);
    }

    #[test]
    fn vault_comparison_policy_preserves_case_and_normalizes_windows_separators() {
        assert_eq!(
            vault_path_key_for_platform("C:/Users/Work/Vault.kdbx", true),
            vault_path_key_for_platform("C:\\Users\\Work\\Vault.kdbx", true)
        );
        assert_ne!(
            vault_path_key_for_platform("C:/Users/Work/Vault.kdbx", true),
            vault_path_key_for_platform("C:\\Users\\Work\\vault.kdbx", true)
        );
        assert_ne!(
            vault_path_key_for_platform("/work/Vault.kdbx", false),
            vault_path_key_for_platform("/work/vault.kdbx", false)
        );
        assert_eq!(
            platform_vault_dedup_key_for_platform("C:/Users/Work/Vault.kdbx", true),
            platform_vault_dedup_key_for_platform("C:\\Users\\Work\\vault.kdbx", true)
        );
        assert_ne!(
            platform_vault_dedup_key_for_platform("/work/Vault.kdbx", false),
            platform_vault_dedup_key_for_platform("/work/vault.kdbx", false)
        );
    }

    #[test]
    #[cfg(unix)]
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
    #[cfg(unix)]
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

        #[cfg(unix)]
        {
            let target = dir.path().join("target.bin");
            fs::write(&target, b"ok").unwrap();
            let link = dir.path().join("target.link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(bounded_file(link.to_str().unwrap(), 32).is_err());
            assert!(bounded_regular_file(link.to_str().unwrap(), 32).is_err());

            let fifo = dir.path().join("target.fifo");
            if std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .is_ok_and(|status| status.success())
            {
                assert!(bounded_file(fifo.to_str().unwrap(), 32).is_err());
                assert!(bounded_regular_file(fifo.to_str().unwrap(), 32).is_err());
            }
        }
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
        for bidi in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}', '\u{202A}', '\u{202E}',
            '\u{2066}', '\u{2069}',
        ] {
            assert!(
                !safe_metadata(&format!("group{bidi}name")),
                "U+{:04X} must make CLI metadata unsafe",
                bidi as u32
            );
            let sample = format!("text{bidi}more");
            assert!(validate_tty_raw_bytes(sample.as_bytes()).is_err());
            assert!(validate_formatted_controls(&sample).is_err());
            assert_eq!(sanitize_terminal_text(&sample), "text\u{fffd}more");
            assert_eq!(
                sanitize_human_text(&sample),
                format!("text{}more", bidi.escape_default())
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
        assert!(validate_named_value("github-actions", "NKP_EO").is_ok());
        assert!(validate_named_value("github-actions", "NKP_EOF extra").is_ok());
        assert_eq!(
            validate_named_value("github-actions", "NKP_EOF")
                .unwrap_err()
                .0,
            "github-actions output cannot contain the heredoc delimiter"
        );
        assert_eq!(
            validate_named_value("github-actions", "before\nNKP_EOF\nafter")
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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

    #[cfg(windows)]
    #[test]
    fn windows_vault_creation_installs_private_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("unsupported.kdbx");
        VaultService::default()
            .create(
                &path,
                &mut KdbxCredentials::password("synthetic-test-password").unwrap(),
                KdbxWriteOptions::default(),
                None,
            )
            .unwrap();
        windows_private_file::verify(&File::open(path).unwrap()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_output_stages_with_private_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("unsupported-output.txt");
        let result = StagedFile::new(
            &path,
            InstallDiagnostics {
                staging: "cannot stage output",
                permissions: "cannot set output permissions",
                write: "cannot write output",
                exists: "output exists",
                durable: "output durability unconfirmed",
            },
        );
        let staged = result.unwrap();
        windows_private_file::verify(staged.file.as_file()).unwrap();
        assert!(!path.exists());
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
        const SCANNED_LIBRARY: &[&str] = &["glob", "icons", "private_file", "password_generator"];
        // These remain explicit library-side exemptions: service/model adapters
        // plus non-vault shell/hook/manifest/template/trust helpers that have
        // no neotales_keepass model dependency.
        const TRUSTED_LIBRARY_BOUNDARIES: &[&str] = &[
            "service",
            "automation",
            "interchange",
            "env_file",
            "fs_safe",
            "hook",
            "manifest",
            "sha256",
            "template",
            "trust",
        ];
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
            ("env_file", "env_file.rs"),
            ("fs_safe", "fs_safe.rs"),
            ("glob", "glob.rs"),
            ("hook", "hook.rs"),
            ("icons", "icons.rs"),
            ("interchange", "interchange.rs"),
            ("manifest", "manifest.rs"),
            ("password_generator", "password_generator.rs"),
            ("private_file", "private_file.rs"),
            ("service", "service.rs"),
            ("sha256", "sha256.rs"),
            ("template", "template.rs"),
            ("trust", "trust.rs"),
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
            ["glob", "icons", "password_generator", "private_file"],
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

    #[test]
    fn env_parser_consumes_option_values_and_rejects_foreign_flags() {
        let args = [
            "--key".to_owned(),
            "Demo/mail".to_owned(),
            "--field".to_owned(),
            "UserName".to_owned(),
            "--name".to_owned(),
            "DEMO".to_owned(),
            "--password-env".to_owned(),
            "--key".to_owned(),
        ];
        let parsed = parse_env_options(&args).unwrap();
        assert_eq!(parsed.common.password_env, Some("--key"));
        assert_eq!(parsed.bindings.len(), 1);
        assert_eq!(parsed.bindings[0].key, "Demo/mail");
        assert_eq!(parsed.bindings[0].field, Some("UserName"));
        assert_eq!(parsed.bindings[0].name, "DEMO");

        let clipboard = [
            "--key".to_owned(),
            "Demo/mail".to_owned(),
            "--field".to_owned(),
            "UserName".to_owned(),
            "--name".to_owned(),
            "DEMO".to_owned(),
            "--clipboard".to_owned(),
        ];
        assert_eq!(
            parse_env_options(&clipboard).err().unwrap().0,
            "invalid operation option"
        );
    }

    #[test]
    fn exec_env_name_collision_respects_platform_case_semantics() {
        let names = vec!["Foo".to_owned(), "foo".to_owned()];
        assert!(validate_exec_env_names_for_platform(&names, None, false).is_ok());
        assert_eq!(
            validate_exec_env_names_for_platform(&names, None, true)
                .unwrap_err()
                .0,
            "invalid or duplicate exec environment name"
        );

        let single = vec!["secret_pw".to_owned()];
        assert!(validate_exec_env_names_for_platform(&single, Some("SECRET_PW"), false).is_ok());
        assert_eq!(
            validate_exec_env_names_for_platform(&single, Some("SECRET_PW"), true)
                .unwrap_err()
                .0,
            "exec environment name is reserved for the master password"
        );
    }

    #[test]
    fn tty_raw_and_json_output_preserve_pipes_and_protect_terminals() {
        let unsafe_c1 = "secret\u{009b}31m\u{007f}end";
        let mut piped_raw = Vec::new();
        write_value_for_sink(
            &mut piped_raw,
            unsafe_c1.as_bytes(),
            "text",
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(piped_raw, unsafe_c1.as_bytes());

        let mut tty_raw = Vec::new();
        let refused = write_value_for_sink(
            &mut tty_raw,
            unsafe_c1.as_bytes(),
            "text",
            None,
            false,
            true,
        )
        .unwrap_err();
        assert!(tty_raw.is_empty());
        assert!(refused.0.contains("redirect stdout to a file or pipe"));

        let safe_multiline = b"line1\tcol\nline2";
        let mut tty_null = Vec::new();
        write_value_for_sink(&mut tty_null, safe_multiline, "null", None, false, true).unwrap();
        assert_eq!(tty_null, b"line1\tcol\nline2\0");

        let mut piped_json = Vec::new();
        write_value_for_sink(
            &mut piped_json,
            unsafe_c1.as_bytes(),
            "json",
            None,
            false,
            false,
        )
        .unwrap();
        assert!(piped_json.windows(2).any(|w| w == [0xc2, 0x9b]));
        assert!(piped_json.contains(&0x7f));

        let mut tty_json = Vec::new();
        write_value_for_sink(
            &mut tty_json,
            unsafe_c1.as_bytes(),
            "json",
            None,
            false,
            true,
        )
        .unwrap();
        assert!(!tty_json.windows(2).any(|w| w == [0xc2, 0x9b]));
        assert!(!tty_json.contains(&0x7f));
        let tty_str = std::str::from_utf8(&tty_json).unwrap();
        assert!(tty_str.contains("\\u009b"));
        assert!(tty_str.contains("\\u007f"));
        let decoded: serde_json::Value = serde_json::from_slice(&tty_json).unwrap();
        assert_eq!(decoded["value"].as_str().unwrap(), unsafe_c1);

        let bindings = vec![
            ("FIRST".to_owned(), SecretBytes::from_vec(b"safe".to_vec())),
            (
                "SECOND".to_owned(),
                SecretBytes::from_vec(unsafe_c1.as_bytes().to_vec()),
            ),
        ];
        let mut tty_multi_null = Vec::new();
        assert!(
            write_environment_for_sink(&mut tty_multi_null, &bindings, "null", false, false, true)
                .is_err()
        );
        assert!(
            tty_multi_null.is_empty(),
            "refusal must precede first disclosure"
        );
    }

    fn collect_help_routes<'a>(
        commands: &'a [HelpCommand],
        prefix: &[String],
        out: &mut Vec<(Vec<String>, &'a HelpCommand)>,
    ) {
        for command in commands {
            let canonical = aliases(command.names).next().unwrap().to_owned();
            let mut route = prefix.to_vec();
            route.push(canonical);
            out.push((route.clone(), command));
            collect_help_routes(command.children, &route, out);
        }
    }

    fn extract_section_lines<'a>(help: &'a str, section: &str) -> Vec<&'a str> {
        let marker = format!("{section}:");
        let Some(start) = help.lines().position(|line| line == marker) else {
            return Vec::new();
        };
        help.lines()
            .skip(start + 1)
            .take_while(|line| line.is_empty() || line.starts_with(' '))
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn advertised_flags(option_label: &str) -> Vec<&str> {
        option_label
            .split([',', ' '])
            .filter(|token| token.starts_with('-'))
            .collect()
    }

    #[test]
    fn help_schema_matches_parser_allowlists_across_all_routes() {
        let mut routes = Vec::new();
        collect_help_routes(ROOT_COMMANDS, &[], &mut routes);

        for (route, node) in &routes {
            let help = render_help("nkp", route, HELP_WIDTH);
            let options_lines = extract_section_lines(&help, "OPTIONS");
            assert!(
                !options_lines.is_empty(),
                "route {route:?} missing OPTIONS section"
            );

            // Every option row in OPTIONS: must start with '-' and have no duplicate flags.
            let mut seen_flags = BTreeSet::new();
            for opt in node.options {
                assert!(
                    opt.label.starts_with('-'),
                    "route {route:?} has fake option row in OPTIONS: {:?}",
                    opt.label
                );
                for flag in advertised_flags(opt.label) {
                    assert!(
                        seen_flags.insert(flag),
                        "route {route:?} duplicates option flag {flag} in OPTIONS:\n{help}"
                    );
                }
            }
            if uses_credentials(route) {
                for opt in CREDENTIAL_OPTIONS {
                    for flag in advertised_flags(opt.label) {
                        assert!(
                            seen_flags.insert(flag),
                            "route {route:?} duplicates credential flag {flag} in OPTIONS:\n{help}"
                        );
                    }
                }
            }

            let globals_text = extract_section_lines(&help, "GLOBAL OPTIONS").join("\n");
            assert_eq!(
                globals_text.contains("-V, --vault PATH"),
                uses_vault_option(route),
                "route {route:?} vault legend mismatch:\n{help}"
            );
            assert_eq!(
                help.contains("\nCREDENTIALS:\n"),
                uses_credentials(route),
                "route {route:?} CREDENTIALS section mismatch:\n{help}"
            );
            assert_eq!(
                help.contains("\nSAFETY:\n"),
                uses_credentials(route),
                "route {route:?} SAFETY section mismatch:\n{help}"
            );
            assert_eq!(
                globals_text.contains("--password-env NAME"),
                uses_credentials(route),
                "route {route:?} GLOBAL CREDENTIAL OPTIONS mismatch:\n{help}"
            );
        }

        // Verify specific baseline audit fixes.
        for route in [vec!["rm"], vec!["secrets", "rm"]] {
            let owned: Vec<String> = route.iter().map(|s| (*s).to_owned()).collect();
            let help = render_help("nkp", &owned, HELP_WIDTH);
            assert!(!help.contains("--field"), "{route:?} advertised --field");
            assert!(!help.contains("-F"), "{route:?} advertised -F");
            assert!(
                !help.contains("selected field"),
                "{route:?} claimed field removal"
            );
            assert!(
                help.contains("(-y | --yes)"),
                "{route:?} omitted (-y | --yes)"
            );
        }

        for route in [vec!["field", "get"], vec!["custom-field", "get"]] {
            let owned: Vec<String> = route.iter().map(|s| (*s).to_owned()).collect();
            let help = render_help("nkp", &owned, HELP_WIDTH);
            for forbidden in [
                "--output",
                "-o,",
                "--clipboard",
                "--age-encrypt",
                "-r,",
                "--age-recipient",
            ] {
                assert!(
                    !help.contains(forbidden),
                    "{route:?} advertised {forbidden}"
                );
            }
        }

        for route in [vec!["field", "set"], vec!["custom-field", "set"]] {
            let owned: Vec<String> = route.iter().map(|s| (*s).to_owned()).collect();
            let help = render_help("nkp", &owned, HELP_WIDTH);
            for forbidden in [
                "--generate",
                "--value",
                "--chars",
                "--size",
                "--upper",
                "--lower",
                "--digits",
                "--symbols",
                "--username",
                "--url",
                "--notes",
                "--bin",
                "-b,",
                "--age-decrypt",
                "--age-identity",
            ] {
                assert!(
                    !help.contains(forbidden),
                    "{route:?} advertised {forbidden}"
                );
            }
        }

        for route in [vec!["exec"], vec!["x"]] {
            let owned: Vec<String> = route.iter().map(|s| (*s).to_owned()).collect();
            let help = render_help("nkp", &owned, HELP_WIDTH);
            let opts_section = extract_section_lines(&help, "OPTIONS").join("\n");
            assert_eq!(
                opts_section.matches("--password-env").count(),
                1,
                "{route:?} repeated --password-env:\n{help}"
            );
        }

        // Verify non-vault routes omit -V, --vault, and context show keeps it.
        for non_vault in [
            vec!["trust"],
            vec!["untrust"],
            vec!["use"],
            vec!["tui"],
            vec!["version"],
            vec!["completion"],
            vec!["shell"],
            vec!["shell", "init"],
            vec!["shell", "completions"],
            vec!["shell", "load"],
            vec!["shell", "unload"],
            vec!["shell", "status"],
            vec!["context"],
            vec!["context", "ls"],
            vec!["context", "use"],
            vec!["context", "set"],
            vec!["context", "rm"],
            vec!["alias"],
            vec!["alias", "set"],
            vec!["config"],
            vec!["config", "ls"],
        ] {
            let owned: Vec<String> = non_vault.iter().map(|s| (*s).to_owned()).collect();
            let help = render_help("nkp", &owned, HELP_WIDTH);
            assert!(
                !help.contains("--vault"),
                "non-vault route {non_vault:?} advertised --vault:\n{help}"
            );
        }
        assert!(
            render_help("nkp", &["context".into(), "show".into()], HELP_WIDTH)
                .contains("-V, --vault PATH")
        );

        // Verify every advertised flag on operation() routes is accepted by the parser.
        let operation_routes: &[(&str, &[&str])] = &[
            ("ls", &["ls"]),
            ("search", &["search"]),
            ("show", &["show"]),
            ("get", &["get"]),
            ("get-many", &["get", "many"]),
            ("set", &["set"]),
            ("rm", &["rm"]),
            ("ensure", &["ensure"]),
            ("otp", &["otp"]),
            ("import", &["import"]),
            ("export", &["export"]),
            ("sync", &["sync"]),
            ("attachment-ls", &["files", "ls"]),
            ("attachment-add", &["files", "add"]),
            ("attachment-get", &["files", "get"]),
            ("attachment-rm", &["files", "rm"]),
            ("field-ls", &["field", "ls"]),
            ("field-get", &["field", "get"]),
            ("field-set", &["field", "set"]),
            ("field-rm", &["field", "rm"]),
            ("group-ls", &["group", "ls"]),
            ("group-add", &["group", "add"]),
            ("group-rm", &["group", "rm"]),
        ];
        for (action, route) in operation_routes {
            let owned: Vec<String> = route.iter().map(|s| (*s).to_owned()).collect();
            let node = command_path(ROOT_COMMANDS, &owned).unwrap();
            for opt in node.options {
                for flag in advertised_flags(opt.label) {
                    let mut raw_args: Vec<String> = Vec::new();
                    match flag {
                        "-h" | "--help" => continue,
                        "-k" | "--key" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("Demo/Entry".to_owned());
                        }
                        "-F" | "--field" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push(if *action == "set" {
                                "Custom=val".to_owned()
                            } else {
                                "Custom".to_owned()
                            });
                        }
                        "-f" | "--file" | "--value-file" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("input.txt".to_owned());
                        }
                        "-b" | "--bin" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("note=note.txt".to_owned());
                        }
                        "-n" | "--name" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("OUT_VAR".to_owned());
                            if matches!(*action, "get" | "field-get" | "otp") {
                                raw_args.push("--format".to_owned());
                                raw_args.push("dotenv".to_owned());
                            }
                        }
                        "-o" | "--output" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("out.txt".to_owned());
                        }
                        "-r" | "--age-recipient" => {
                            raw_args.push("--age-encrypt".to_owned());
                            raw_args.push(flag.to_owned());
                            raw_args.push("age1example".to_owned());
                        }
                        "-i" | "--age-identity" => {
                            raw_args.push("--age-decrypt".to_owned());
                            raw_args.push(flag.to_owned());
                            raw_args.push("id.txt".to_owned());
                            raw_args.push("--stdin".to_owned());
                        }
                        "-c" | "--chars" | "--size" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("20".to_owned());
                        }
                        "--format" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push(if matches!(*action, "import" | "export") {
                                "keepass-xml".to_owned()
                            } else {
                                "json".to_owned()
                            });
                        }
                        "--strategy" => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("target".to_owned());
                        }
                        _ if takes_option_value(flag) => {
                            raw_args.push(flag.to_owned());
                            raw_args.push("SAMPLE".to_owned());
                        }
                        _ => raw_args.push(flag.to_owned()),
                    }
                    // Supply required companion flags so allowlist check tests the target flag itself.
                    if !raw_args
                        .iter()
                        .any(|a| matches!(a.as_str(), "-k" | "--key"))
                        && !matches!(
                            *action,
                            "ls" | "search"
                                | "get-many"
                                | "import"
                                | "export"
                                | "sync"
                                | "group-ls"
                        )
                    {
                        raw_args.push("--key".to_owned());
                        raw_args.push("Demo/Entry".to_owned());
                    }
                    if *action == "search" {
                        raw_args.push("Demo".to_owned());
                    }
                    if *action == "get-many" {
                        raw_args.push("Demo/One".to_owned());
                    }
                    if matches!(*action, "field-get" | "field-set" | "field-rm")
                        && !matches!(flag, "-F" | "--field")
                    {
                        raw_args.push("--field".to_owned());
                        raw_args.push("Custom".to_owned());
                    }
                    if matches!(
                        *action,
                        "attachment-add" | "attachment-get" | "attachment-rm"
                    ) && !matches!(flag, "-n" | "--name" | "-F" | "--field")
                    {
                        raw_args.push("--name".to_owned());
                        raw_args.push("note.txt".to_owned());
                    }
                    if matches!(*action, "attachment-get" | "export")
                        && !matches!(flag, "-o" | "--output")
                    {
                        raw_args.push("--output".to_owned());
                        raw_args.push("out.txt".to_owned());
                    }
                    if *action == "export" && flag == "--allow-plaintext" {
                        raw_args.push("--format".to_owned());
                        raw_args.push("keepass-xml".to_owned());
                    }
                    if *action == "export"
                        && flag == "--format"
                        && !raw_args.iter().any(|a| a == "--allow-plaintext")
                    {
                        raw_args.push("--allow-plaintext".to_owned());
                    }
                    if matches!(*action, "attachment-add" | "field-set" | "import" | "sync")
                        && !matches!(flag, "-f" | "--file" | "--stdin")
                    {
                        raw_args.push("--stdin".to_owned());
                    }
                    if matches!(*action, "rm" | "field-rm" | "attachment-rm" | "group-rm")
                        && !matches!(flag, "-y" | "--yes" | "--dry-run")
                    {
                        raw_args.push("--yes".to_owned());
                    }
                    if *action == "set"
                        && matches!(
                            flag,
                            "-c" | "--chars"
                                | "--size"
                                | "-U"
                                | "--upper"
                                | "-L"
                                | "--lower"
                                | "-D"
                                | "--digits"
                                | "-S"
                                | "--symbols"
                        )
                    {
                        raw_args.push("--generate".to_owned());
                    }
                    if *action == "set" && flag == "--age-decrypt" {
                        raw_args.push("--stdin".to_owned());
                    }
                    if matches!(*action, "get" | "get-many") && matches!(flag, "-o" | "--output") {
                        raw_args.push("--age-encrypt".to_owned());
                        raw_args.push("--age-recipient".to_owned());
                        raw_args.push("age1example".to_owned());
                    }
                    if matches!(*action, "get" | "get-many")
                        && flag == "--age-encrypt"
                        && !raw_args
                            .iter()
                            .any(|a| matches!(a.as_str(), "-r" | "--age-recipient"))
                    {
                        raw_args.push("--age-recipient".to_owned());
                        raw_args.push("age1example".to_owned());
                    }
                    if flag == "--is-output" && !raw_args.iter().any(|a| a == "--format") {
                        raw_args.push("--format".to_owned());
                        raw_args.push("azure-devops".to_owned());
                    }
                    if flag == "--is-output"
                        && *action != "get-many"
                        && !raw_args
                            .iter()
                            .any(|a| matches!(a.as_str(), "-n" | "--name"))
                    {
                        raw_args.push("--name".to_owned());
                        raw_args.push("OUT_VAR".to_owned());
                    }
                    let mut full_argv = owned.clone();
                    full_argv.extend(raw_args);
                    let normalized = normalize_cli_aliases(&full_argv);
                    let parsed =
                        options(&normalized[owned.len()..], Positional::for_action(action))
                            .unwrap_or_else(|e| {
                                panic!("flag {flag} on {action} failed options(): {e:?}")
                            });
                    let validated = if matches!(*action, "import" | "export" | "sync") {
                        validate_automation_options(action, &parsed)
                    } else {
                        validate_regular_options(action, &parsed)
                    };
                    assert!(
                        validated.is_ok(),
                        "advertised flag {flag} on {action} was rejected: {validated:?}"
                    );
                }
            }
        }

        // Verify unknown subcommands on parent-only groups do not return parent help.
        for bogus in [
            vec!["context", "bogus", "--help"],
            vec!["shell", "bogus", "--help"],
            vec!["files", "bogus", "--help"],
            vec!["field", "bogus", "--help"],
            vec!["group", "bogus", "--help"],
            vec!["alias", "bogus", "--help"],
            vec!["config", "bogus", "--help"],
            vec!["secrets", "bogus", "--help"],
            vec!["automation", "bogus", "--help"],
        ] {
            let owned: Vec<String> = bogus.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(
                help_request(&owned),
                None,
                "{bogus:?} disguised unknown subcommand as parent help"
            );
        }
    }

    #[test]
    fn human_metadata_helpers_sanitize_truncate_unicode_and_fit_narrow_widths() {
        assert_eq!(
            sanitize_human_text("a\u{1b}[31m\u{202e}b\u{2066}\nc"),
            "a\\u{1b}[31m\\u{202e}b\\u{2066}\\nc"
        );
        assert_eq!(truncate_human_cell("你好世界", 5), "你好…");
        assert_eq!(truncate_human_cell("你好世界", 4), "你…");
        assert!(human_display_width(&truncate_human_cell("e\u{0301}xyz", 2)) <= 2);
        assert_eq!(truncate_human_cell("abc", 1), "…");

        let empty_aliases = render_aliases_human(&[], 40, 0);
        assert_eq!(empty_aliases, vec!["(no aliases)"]);

        let name = "long-alias-name-prefix".to_owned();
        let alias = Alias {
            kind: Kind::Entry,
            target: format!("Group/{}", "日本語".repeat(12)),
            field: Some("Custom\u{202E}Field".to_owned()),
        };
        let rendered = render_aliases_human(&[(&name, &alias)], 44, 0);
        assert_eq!(rendered.len(), 2);
        assert!(rendered[0].starts_with("NAME"));
        assert!(rendered[1].contains('…'));
        assert!(!rendered[1].contains('\u{202E}'));
        for line in &rendered {
            assert!(
                human_display_width(line) <= 44,
                "narrow width exceeded: {line:?}"
            );
        }
        let wide = render_aliases_human(&[(&name, &alias)], 88, 0);
        assert!(wide[1].contains("\\u{202e}"));
        assert!(!wide[1].contains('\u{202E}'));
    }
}
