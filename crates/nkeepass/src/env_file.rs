//! Non-executing `.env` parser, reserved environment variable validator, and
//! atomic single-pass resolver.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::template::{
    RenderOptions, SecretLookup, TemplateError, ValueEscape, extract_references,
    is_valid_secret_text, render_text,
};

/// Maximum length in bytes for an environment variable name.
pub const MAX_ENV_VAR_NAME_BYTES: usize = 128;

/// Maximum `.env` file size in bytes accepted by [`parse_env_file`] (64 KiB).
pub const MAX_ENV_FILE_BYTES: usize = 64 * 1024;

/// Maximum number of variable assignments accepted in a single `.env` file.
pub const MAX_ENV_FILE_ENTRIES: usize = 256;

const RESERVED_PREFIXES: &[&str] = &[
    "NEO_KEEPASS_",
    "NKP_",
    "NKEEPASS_",
    "__NKP_",
    "LD_",
    "DYLD_",
    "COMPLUS_",
    "CORECLR_PROFILER",
    "COR_PROFILER",
    "PROMPT",
    "SSL_CERT_",
    "NU_",
];

const RESERVED_EXACT: &[&str] = &[
    // Shell / prompt / OS execution
    "PATH",
    "PATHEXT",
    "IFS",
    "ENV",
    "BASH_ENV",
    "ZDOTDIR",
    "FPATH",
    "CDPATH",
    "SHELL",
    "PROMPT_COMMAND",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "RPROMPT",
    "RPROMPT2",
    "SPROMPT",
    "MODULE_PATH",
    "EXECIGNORE",
    "INPUTRC",
    "TMOUT",
    "SHELLOPTS",
    "BASHOPTS",
    "BASH_LOADABLES_PATH",
    "BASH_XTRACEFD",
    "BASH_ARGV0",
    "POSIXLY_CORRECT",
    "COMSPEC",
    "SYSTEMROOT",
    "WINDIR",
    // Fish / PowerShell / Nushell / .NET
    "UMASK",
    "FISH_FUNCTION_PATH",
    "FISH_COMPLETE_PATH",
    "FISH_USER_PATHS",
    "FISH_CLIPBOARD_CMD",
    "PSMODULEPATH",
    "PSEXECUTIONPOLICYPREFERENCE",
    "DOTNET_STARTUP_HOOKS",
    "DOTNET_ADDITIONAL_DEPS",
    "CONFIG",
    "ENV_CONVERSIONS",
    // Dynamic loaders / language runtimes / helpers
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    "RES_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONEXECUTABLE",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "RUBYOPT",
    "RUBYLIB",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "LESSOPEN",
    "LESSCLOSE",
    // Identity / directories / readonly shell magic
    "HOME",
    "USER",
    "LOGNAME",
    "USERPROFILE",
    "USERNAME",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "TEMP",
    "TMP",
    "TERM",
    "COLORTERM",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIR",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_DATA_DIR",
    "XDG_DATA_DIRS",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "UID",
    "EUID",
    "GID",
    "EGID",
    "PPID",
    "SHLVL",
    "RANDOM",
    "SECONDS",
    "LINENO",
    "STATUS",
    "PIPESTATUS",
    "HOSTNAME",
    "COLUMNS",
    "LINES",
    "VERSION",
    "HISTORY",
];

/// Returns `true` if `name` is on the case-insensitive reserved environment
/// variable blocklist (shell/prompt controls, dynamic loaders, runtime hooks,
/// `nkeepass` internals, and readonly shell magic variables).
#[must_use]
pub fn is_reserved_env_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    RESERVED_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
        || (upper.starts_with("XDG_") && upper.ends_with("_DIRS"))
        || RESERVED_EXACT.contains(&upper.as_str())
}

/// Validates an environment variable name as `1..=128` ASCII characters
/// matching `[A-Za-z_][A-Za-z0-9_]*` and rejects reserved names.
///
/// # Errors
///
/// Returns [`TemplateError::InvalidEnvVarName`] when the identifier syntax or
/// length is invalid, or [`TemplateError::ReservedEnvVar`] when the name is on
/// the reserved blocklist.
pub fn validate_env_var_name(name: &str) -> Result<(), TemplateError> {
    if name.is_empty() || name.len() > MAX_ENV_VAR_NAME_BYTES {
        return Err(TemplateError::InvalidEnvVarName);
    }
    let bytes = name.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(TemplateError::InvalidEnvVarName);
    }
    if is_reserved_env_var(name) {
        return Err(TemplateError::ReservedEnvVar);
    }
    Ok(())
}

/// Parsed `.env` assignment value classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvValueKind {
    /// Plain literal string containing no `nkp://` references.
    Literal(String),
    /// Template string containing one or more validated `nkp://` references.
    Template(String),
}

/// One validated assignment parsed from a `.env` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvLine {
    /// Validated environment variable name.
    pub name: String,
    /// Parsed value (plain literal or `nkp://` template).
    pub value: EnvValueKind,
}

fn validate_trailing_comment(rest: &str, line: usize) -> Result<(), TemplateError> {
    let trimmed = rest.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        Ok(())
    } else {
        Err(TemplateError::InvalidEnvSyntax { line })
    }
}

fn parse_single_quoted(input: &str, line: usize) -> Result<String, TemplateError> {
    let after_open = &input[1..];
    let Some(close_idx) = after_open.find('\'') else {
        return Err(TemplateError::InvalidEnvSyntax { line });
    };
    let value = &after_open[..close_idx];
    validate_trailing_comment(&after_open[close_idx + 1..], line)?;
    Ok(value.to_owned())
}

fn parse_double_quoted(input: &str, line: usize) -> Result<String, TemplateError> {
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '"' => {
                validate_trailing_comment(&input[1 + idx + 1..], line)?;
                return Ok(out);
            }
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(TemplateError::InvalidEnvSyntax { line });
                };
                match escaped {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    _ => return Err(TemplateError::InvalidEnvSyntax { line }),
                }
            }
            other => out.push(other),
        }
    }
    Err(TemplateError::InvalidEnvSyntax { line })
}

fn parse_unquoted(raw_value: &str, has_leading_ws: bool) -> String {
    if has_leading_ws && raw_value.starts_with('#') {
        return String::new();
    }
    let bytes = raw_value.as_bytes();
    let mut end = raw_value.len();
    for (idx, &byte) in bytes.iter().enumerate() {
        if byte == b'#' && idx > 0 && matches!(bytes[idx - 1], b' ' | b'\t') {
            end = idx;
            break;
        }
    }
    raw_value[..end].trim_end_matches([' ', '\t']).to_owned()
}

fn parse_env_value(raw_value: &str, line: usize) -> Result<String, TemplateError> {
    let has_leading_ws = raw_value.starts_with([' ', '\t']);
    let trimmed = raw_value.trim_start_matches([' ', '\t']);

    let value = if trimmed.starts_with('\'') {
        parse_single_quoted(trimmed, line)?
    } else if trimmed.starts_with('"') {
        parse_double_quoted(trimmed, line)?
    } else {
        parse_unquoted(trimmed, has_leading_ws)
    };

    if !is_valid_secret_text(&value, true) {
        return Err(TemplateError::UnsafeSecretCharacters);
    }
    Ok(value)
}

/// Parses a non-executing `.env` document into validated [`EnvLine`] entries.
///
/// Supports `KEY=VALUE`, `export KEY=VALUE`, blank lines, `#` comment lines,
/// single-quoted literals, double-quoted values (`\"`, `\\`, `\n`), and
/// unquoted values with inline `# comment` stripped only after unquoted
/// horizontal whitespace (preserving `#Field` in `nkp://path#Field`).
///
/// Rejects reserved variable names, invalid identifiers, duplicate or
/// case-colliding variable names, oversized inputs (`> 64 KiB`), too many
/// entries (`> 256`), malformed `nkp://` references, and unsafe control/BiDi
/// characters.
///
/// # Errors
///
/// Returns [`TemplateError`] on size/count limit violations, syntax errors,
/// invalid or reserved variable names, duplicate/case-colliding keys, unsafe
/// value characters, or malformed `nkp://` URIs.
pub fn parse_env_file(input: &str) -> Result<Vec<EnvLine>, TemplateError> {
    if input.len() > MAX_ENV_FILE_BYTES {
        return Err(TemplateError::InvalidEnvFileSize);
    }
    if input.contains('\0') {
        return Err(TemplateError::UnsafeSecretCharacters);
    }

    let mut seen_names = BTreeSet::new();
    let mut lines = Vec::new();

    for (index, raw_line) in input.split('\n').enumerate() {
        let line_num = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed_start = line.trim_start_matches([' ', '\t']);
        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            continue;
        }

        let assignment = if let Some(after_export) = trimmed_start.strip_prefix("export") {
            if after_export.starts_with([' ', '\t']) {
                after_export.trim_start_matches([' ', '\t'])
            } else {
                trimmed_start
            }
        } else {
            trimmed_start
        };

        let Some((name, raw_value)) = assignment.split_once('=') else {
            return Err(TemplateError::InvalidEnvSyntax { line: line_num });
        };
        validate_env_var_name(name)?;
        if !seen_names.insert(name.to_ascii_uppercase()) {
            return Err(TemplateError::DuplicateEnvVar);
        }
        if lines.len() >= MAX_ENV_FILE_ENTRIES {
            return Err(TemplateError::TooManyEnvEntries);
        }

        let decoded = parse_env_value(raw_value, line_num)?;
        let refs = extract_references(&decoded)?;
        let value = if refs.is_empty() {
            EnvValueKind::Literal(decoded)
        } else {
            EnvValueKind::Template(decoded)
        };

        lines.push(EnvLine {
            name: name.to_owned(),
            value,
        });
    }

    Ok(lines)
}

/// Atomically resolves parsed `.env` assignments into zeroizing `(KEY, VALUE)`
/// pairs.
///
/// Plain [`EnvValueKind::Literal`] lines never invoke `lookup`, so literal-only
/// `.env` files can be activated without an unlocked vault. Every resolved
/// value is validated for UTF-8, no NUL, no unsafe controls, and no bidirectional
/// characters before anything is returned.
///
/// # Errors
///
/// Returns [`TemplateError`] when entry counts, variable names, uniqueness,
/// template rendering, secret lookup, or output character safety fails.
pub fn resolve_env_file(
    lines: &[EnvLine],
    lookup: &mut dyn SecretLookup,
) -> Result<Vec<(String, Zeroizing<String>)>, TemplateError> {
    if lines.len() > MAX_ENV_FILE_ENTRIES {
        return Err(TemplateError::TooManyEnvEntries);
    }

    let options = RenderOptions {
        escape: ValueEscape::Raw,
        allow_newlines: true,
        ..RenderOptions::default()
    };

    let mut seen_names = BTreeSet::new();
    let mut resolved = Vec::with_capacity(lines.len());

    for line in lines {
        validate_env_var_name(&line.name)?;
        if !seen_names.insert(line.name.to_ascii_uppercase()) {
            return Err(TemplateError::DuplicateEnvVar);
        }

        let value = match &line.value {
            EnvValueKind::Literal(literal) => {
                if !is_valid_secret_text(literal, true) {
                    return Err(TemplateError::UnsafeSecretCharacters);
                }
                Zeroizing::new(literal.clone())
            }
            EnvValueKind::Template(template) => {
                if !is_valid_secret_text(template, true) {
                    return Err(TemplateError::UnsafeSecretCharacters);
                }
                render_text(template, lookup, &options)?
            }
        };

        resolved.push((line.name.clone(), value));
    }

    Ok(resolved)
}
