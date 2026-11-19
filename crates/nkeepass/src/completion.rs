use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use neotales_keepass::KdbxCredentials;
use zeroize::Zeroizing;

use super::{
    Config, KDBX_LIMITS, Kind, Result, active_vault, entry_path, err, load_config, valid_name,
};
use nkeepass::service::{ServiceError, VaultService};

const MAX_VAULT_DEPTH: usize = 16;
const MAX_VAULT_FILE_ENTRIES: usize = 10_000;
const MAX_METADATA_INDEX_ITEMS: usize = 10_000;
const MAX_METADATA_INDEX_BYTES: usize = 2 * 1024 * 1024;
const MAX_METADATA_COMPLETION_ITEMS: usize = 1_000;

/// Generates the completion script for `shell`.
///
/// The embedded scripts are LF under every checkout — rustc normalizes
/// CRLF to LF inside string literals while lexing — so the generated
/// text is byte-stable and safe to hand to `bash -n` on any platform.
pub fn generate(shell: &str) -> Result<&'static str> {
    match shell {
        "bash" => Ok(BASH),
        "sh" => Ok(POSIX_SH),
        "zsh" => Ok(ZSH),
        "fish" => Ok(FISH),
        "powershell" | "pwsh" => Ok(POWERSHELL),
        "nushell" => Ok(NUSHELL),
        _ => Err(err("unsupported completion shell")),
    }
}

#[derive(Clone, Copy)]
enum CandidateKind {
    Aliases,
    VaultAliases,
    VaultFiles,
    Vaults,
    Entries,
    Groups,
    Keys,
}

impl CandidateKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "aliases" => Some(Self::Aliases),
            "vault-aliases" => Some(Self::VaultAliases),
            "vault-files" => Some(Self::VaultFiles),
            "vaults" => Some(Self::Vaults),
            "entries" => Some(Self::Entries),
            "groups" => Some(Self::Groups),
            "keys" => Some(Self::Keys),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetadataKind {
    Entry,
    Group,
}

#[derive(Clone, Debug)]
struct MetadataCandidate {
    kind: MetadataKind,
    path: String,
}

#[derive(Debug, Default)]
struct MetadataIndex {
    paths: BTreeMap<String, Option<MetadataCandidate>>,
    ambiguous_groups: BTreeSet<String>,
    seen_groups: BTreeSet<String>,
    bytes: usize,
    work: usize,
}

impl MetadataIndex {
    fn insert(&mut self, kind: MetadataKind, path: String) -> Result<()> {
        self.work = self
            .work
            .checked_add(1)
            .ok_or_else(|| err("completion metadata limit exceeded"))?;
        if self.work > MAX_METADATA_INDEX_ITEMS {
            return Err(err("completion metadata limit exceeded"));
        }
        if entry_path(&path).is_err() {
            return Ok(());
        }
        let normalized = path.to_ascii_lowercase();
        if kind == MetadataKind::Group && !self.seen_groups.insert(normalized.clone()) {
            self.ambiguous_groups.insert(normalized.clone());
        }
        if let Some(existing) = self.paths.get_mut(&normalized) {
            *existing = None;
        } else {
            self.account_path(path.len())?;
            let candidate = MetadataCandidate { kind, path };
            self.paths.insert(normalized, Some(candidate));
        }
        Ok(())
    }

    fn account_path(&mut self, bytes: usize) -> Result<()> {
        if self.paths.len() >= MAX_METADATA_INDEX_ITEMS
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > MAX_METADATA_INDEX_BYTES)
        {
            return Err(err("completion metadata limit exceeded"));
        }
        self.bytes += bytes;
        Ok(())
    }

    fn candidates(&self, kind: MetadataKind, prefix: &str) -> Result<Vec<String>> {
        let mut candidates = Vec::new();
        let mut bytes = 0_usize;
        for candidate in self.paths.values().filter_map(Option::as_ref) {
            if candidate.kind != kind
                || !candidate.path.starts_with(prefix)
                || self.is_under_ambiguous_group(&candidate.path)
            {
                continue;
            }
            if candidates.len() >= MAX_METADATA_COMPLETION_ITEMS
                || bytes
                    .checked_add(candidate.path.len())
                    .is_none_or(|total| total > MAX_METADATA_INDEX_BYTES)
            {
                return Err(err("completion metadata limit exceeded"));
            }
            bytes += candidate.path.len();
            candidates.push(candidate.path.clone());
        }
        Ok(candidates)
    }

    fn is_under_ambiguous_group(&self, path: &str) -> bool {
        let normalized = path.to_ascii_lowercase();
        normalized
            .match_indices('/')
            .map(|(index, _)| &normalized[..index])
            .chain(std::iter::once(normalized.as_str()))
            .any(|group| self.ambiguous_groups.contains(group))
    }
}

fn valid_tree_completion_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.chars().any(char::is_control)
}

fn metadata_candidates(metadata: nkeepass::service::CompletionMetadata) -> Result<MetadataIndex> {
    let mut index = MetadataIndex::default();
    let mut key_bytes = 0_usize;
    if metadata.keys.len() > MAX_METADATA_INDEX_ITEMS {
        return Err(err("completion metadata limit exceeded"));
    }
    for key in &metadata.keys {
        key_bytes = key_bytes
            .checked_add(key.len())
            .ok_or_else(|| err("completion metadata limit exceeded"))?;
        if key_bytes > MAX_METADATA_INDEX_BYTES {
            return Err(err("completion metadata limit exceeded"));
        }
    }
    for path in metadata.groups {
        if valid_metadata_path(&path) {
            index.insert(MetadataKind::Group, path)?;
        }
    }
    for path in metadata.entries {
        if valid_metadata_path(&path) {
            index.insert(MetadataKind::Entry, path)?;
        }
    }
    Ok(index)
}

fn valid_metadata_path(path: &str) -> bool {
    entry_path(path).is_ok() && path.split('/').all(valid_tree_completion_name)
}

fn completion_password() -> Result<Option<Zeroizing<String>>> {
    let Some(name) = crate::app_env_var_os("NEO_KEEPASS_COMPLETE_PASSWORD_ENV")
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let name = name
        .into_string()
        .map_err(|_| err("completion password environment name is not valid UTF-8"))?;
    if !valid_name(&name) {
        return Err(err("invalid completion password environment name"));
    }
    let password = env::var(&name)
        .map(Zeroizing::new)
        .map_err(|_| err("completion password environment variable unavailable"))?;
    Ok(Some(password))
}

fn authenticated_metadata(
    vault: Option<&str>,
    config: &Config,
    password: &Zeroizing<String>,
) -> Result<MetadataIndex> {
    let (path, _) = active_vault(vault, config)?;
    let mut credentials =
        KdbxCredentials::password(password.as_bytes()).map_err(|_| err("invalid credentials"))?;
    let mut service = VaultService::default();
    service
        .open(&path, &mut credentials, &KDBX_LIMITS)
        .map_err(|error| match error {
            ServiceError::Io => err("cannot open vault"),
            _ => err("cannot unlock vault"),
        })?;
    let metadata = service
        .completion_metadata()
        .map_err(|_| err("completion metadata limit exceeded"))?;
    metadata_candidates(metadata)
}

fn visible_file_candidate(path: &Path, prefix: &str, root: &Path) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let prefix_path = Path::new(prefix);
    if prefix_path.is_absolute() {
        return path.starts_with(prefix_path);
    }
    if prefix.contains('/') || prefix.contains('\\') {
        let relative = prefix_path.strip_prefix(".").unwrap_or(prefix_path);
        return path.starts_with(root.join(relative));
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(prefix))
}

fn vault_file_candidates(prefix: &str) -> Result<Vec<String>> {
    let root = env::current_dir().map_err(|_| err("current directory unavailable"))?;
    let root = root
        .canonicalize()
        .map_err(|_| err("current directory unavailable"))?;
    let mut pending = vec![(root.clone(), 0_usize)];
    let mut visited = 0_usize;
    let mut candidates = BTreeSet::new();
    while let Some((directory, depth)) = pending.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|_| err("cannot read completion directory"))?;
        for entry in entries {
            if visited >= MAX_VAULT_FILE_ENTRIES {
                return Ok(candidates.into_iter().collect());
            }
            visited += 1;
            let entry = entry.map_err(|_| err("cannot read completion directory"))?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| err("cannot read completion directory"))?;
            let file_type = metadata.file_type();
            if file_type.is_dir() && depth < MAX_VAULT_DEPTH {
                pending.push((entry.path(), depth + 1));
            } else if depth > 0
                && file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("kdbx"))
                && visible_file_candidate(&entry.path(), prefix, &root)
                && let Some(path) = entry.path().to_str()
                && !path.chars().any(char::is_control)
            {
                candidates.insert(path.to_owned());
            }
        }
    }
    Ok(candidates.into_iter().collect())
}

fn emit_candidates(candidates: impl IntoIterator<Item = String>) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for candidate in candidates {
        writeln!(output, "{candidate}").map_err(|_| err("cannot write completion candidates"))?;
    }
    Ok(())
}

fn alias_candidates(config: &Config, prefix: &str, kind: Option<Kind>) -> Vec<String> {
    config
        .aliases
        .iter()
        .filter(|(_, alias)| kind.is_none_or(|kind| alias.kind == kind))
        .map(|(name, _)| name)
        .filter(|name| valid_name(name) && name.starts_with(prefix))
        .cloned()
        .collect()
}

pub fn candidates(args: &[String], vault: Option<&str>) -> Result<()> {
    let (kind, prefix) = match args {
        [kind] => (kind, ""),
        [kind, prefix] => (kind, prefix.as_str()),
        _ => return Err(err("invalid completion protocol request")),
    };
    let kind =
        CandidateKind::parse(kind).ok_or_else(|| err("invalid completion protocol request"))?;
    match kind {
        CandidateKind::VaultFiles => emit_candidates(vault_file_candidates(prefix)?),
        CandidateKind::Aliases => emit_candidates(alias_candidates(&load_config()?, prefix, None)),
        CandidateKind::VaultAliases => {
            emit_candidates(alias_candidates(&load_config()?, prefix, Some(Kind::Vault)))
        }
        CandidateKind::Vaults => {
            let config = load_config()?;
            let mut candidates = alias_candidates(&config, prefix, Some(Kind::Vault));
            candidates.extend(vault_file_candidates(prefix)?);
            candidates.sort();
            candidates.dedup();
            emit_candidates(candidates)
        }
        CandidateKind::Entries | CandidateKind::Groups => {
            let Some(password) = completion_password()? else {
                return Ok(());
            };
            let index = authenticated_metadata(vault, &load_config()?, &password)?;
            let metadata_kind = if matches!(kind, CandidateKind::Entries) {
                MetadataKind::Entry
            } else {
                MetadataKind::Group
            };
            emit_candidates(index.candidates(metadata_kind, prefix)?)
        }
        CandidateKind::Keys => {
            let config = load_config()?;
            let aliases = alias_candidates(&config, prefix, Some(Kind::Entry));
            let Some(password) = completion_password()? else {
                return emit_candidates(aliases);
            };
            let index = authenticated_metadata(vault, &config, &password)?;
            let mut candidates = aliases;
            candidates.extend(index.candidates(MetadataKind::Entry, prefix)?);
            candidates.extend(
                index
                    .candidates(MetadataKind::Group, prefix)?
                    .into_iter()
                    .map(|path| format!("{path}/")),
            );
            candidates.sort();
            candidates.dedup();
            emit_candidates(candidates)
        }
    }
}

const BASH: &str = r#"# Static nkp completion. Dynamic queries return metadata only and never secrets.
_nkp_complete() {
    local current previous command action choices kind
    local index=1 element position
    local -a vault_args=()
    current="${COMP_WORDS[COMP_CWORD]}"
    local route_command='' route_action='' command_index=-1 action_index=-1
    local scan=1 option_value
    while (( scan < COMP_CWORD )); do
        element="${COMP_WORDS[scan]}"
        [[ "$element" == -- ]] && break
        if [[ -z "$route_command" ]]; then
            case "$element" in
                --vault|-V|--password|--password-env|--password-file|--key-file)
                    ((scan++))
                    if (( scan < COMP_CWORD )); then
                        ((scan++))
                        while (( scan + 1 < COMP_CWORD )) && [[ "${COMP_WORDS[scan]}" == = ]]; do
                            ((scan += 2))
                        done
                    fi
                    continue
                    ;;
                --password-stdin) ((scan++)); continue ;;
            esac
            route_command="$element"
            command_index=$scan
            ((scan++))
            if [[ "$route_command" == secrets ]]; then
                (( scan < COMP_CWORD )) || break
                route_action="${COMP_WORDS[scan]}"
                action_index=$scan
                ((scan++))
            fi
            break
        fi
    done

    local args_index=$((command_index + 1))
    if [[ "$route_command" == secrets ]]; then
        args_index=$((action_index + 1))
    fi
    local pending_owner='' value_owner='' value_start=-1 last_value_equals=false
    local bin_value_start=-1
    if { [[ "$route_command" == set && -z "$route_action" ]] \
        || [[ "$route_command" == secrets && "$route_action" == set ]]; } \
        && (( command_index >= 0 )); then
        for ((scan = args_index; scan < COMP_CWORD; scan++)); do
            element="${COMP_WORDS[scan]}"
            if [[ -n "$pending_owner" ]]; then
                value_owner="$pending_owner"
                pending_owner=''
                value_start=$scan
                last_value_equals=false
                if [[ "$value_owner" == bin ]]; then
                    bin_value_start=$scan
                fi
                continue
            fi
            if [[ "$element" == = && -n "$value_owner" ]]; then
                last_value_equals=true
                continue
            fi
            if [[ "$last_value_equals" == true && -n "$value_owner" ]]; then
                last_value_equals=false
                continue
            fi
            value_owner=''
            case "$element" in
                --) break ;;
                --bin|-b) pending_owner=bin; bin_value_start=-1 ;;
                --key|-k) pending_owner=key ;;
                --field|-F) pending_owner=field ;;
                --file|-f) pending_owner=file ;;
                --username) pending_owner=username ;;
                --url) pending_owner=url ;;
                --notes) pending_owner=notes ;;
                --value) pending_owner=value ;;
                --value-env) pending_owner=value-env ;;
                --value-file) pending_owner=value-file ;;
                --chars|-c|--size) pending_owner=size ;;
                --password) pending_owner=password ;;
                --password-env) pending_owner=password-env ;;
                --password-file) pending_owner=password-file ;;
                --key-file) pending_owner=key-file ;;
                --age-identity|-i) pending_owner=age-identity ;;
                --age-recipient|-r) pending_owner=age-recipient ;;
                --output) pending_owner=output ;;
            esac
        done

        local current_owner="$pending_owner"
        if [[ -z "$current_owner" ]]; then
            current_owner="$value_owner"
        fi
        if [[ "$current_owner" == bin ]]; then
            local file_name='' file_path_before_current='' found_separator=false candidate
            local current_path="$current"
            local bin_word="$current" current_quote='' whole_assignment=false
            local bin_space_boundary=false quote_state='' escaped_char=false word=''
            local line_prefix="${COMP_LINE:0:COMP_POINT}" character
            for ((scan = 0; scan < ${#line_prefix}; scan++)); do
                character="${line_prefix:scan:1}"
                if [[ "$escaped_char" == true ]]; then
                    word+="$character"
                    escaped_char=false
                    continue
                fi
                if [[ "$quote_state" == single ]]; then
                    [[ "$character" == "'" ]] && quote_state=''
                    word+="$character"
                    continue
                fi
                if [[ "$character" == '\' ]]; then
                    escaped_char=true
                    word+="$character"
                    continue
                fi
                if [[ "$quote_state" == double ]]; then
                    [[ "$character" == '"' ]] && quote_state=''
                    word+="$character"
                    continue
                fi
                case "$character" in
                    "'") quote_state=single; word+="$character" ;;
                    '"') quote_state=double; word+="$character" ;;
                    =) word+="$character" ;;
                    ' '|$'\t'|$'\n')
                        if [[ "$word" == --bin || "$word" == -b ]]; then
                            bin_space_boundary=false
                        elif [[ "$word" == *=* || "$word" == *'='* ]]; then
                            bin_space_boundary=true
                        fi
                        word=''
                        ;;
                    *) word+="$character" ;;
                esac
            done
            case "$bin_word" in
                \'*) current_quote=single; bin_word="${bin_word:1}" ;;
                \"*) current_quote=double; bin_word="${bin_word:1}" ;;
            esac
            if (( bin_value_start < 0 )) && [[ "$bin_word" == *=* ]]; then
                file_name="${bin_word%%=*}"
                current_path="${bin_word#*=}"
                found_separator=true
                whole_assignment=true
            fi
            if (( bin_value_start >= 0 )); then
                for ((scan = bin_value_start; scan < COMP_CWORD; scan++)); do
                    element="${COMP_WORDS[scan]}"
                    if [[ "$found_separator" == false ]]; then
                        if [[ "$element" == *=* ]]; then
                            file_name="${element%%=*}"
                            file_path_before_current="${element#*=}"
                            found_separator=true
                        elif [[ "$element" == = ]]; then
                            file_name="${COMP_WORDS[scan - 1]-}"
                            found_separator=true
                        fi
                    elif [[ "$element" == = ]]; then
                        file_path_before_current+="="
                    else
                        file_path_before_current+="$element"
                    fi
                done
            fi
            if [[ "$current" == = ]]; then
                current_path=''
                if [[ "$found_separator" == false ]] && (( bin_value_start > 0 )); then
                    file_name="${COMP_WORDS[COMP_CWORD - 1]-}"
                    found_separator=true
                else
                    file_path_before_current+="="
                fi
            fi
            if [[ "$found_separator" == true && "$bin_space_boundary" == false ]] \
                && [[ "$current_owner" == bin ]]; then
                COMPREPLY=()
                while IFS= read -r candidate; do
                    if [[ "$whole_assignment" == true ]]; then
                        local assignment="$file_name=${candidate#"$file_path_before_current"}"
                        local escaped
                        case "$current_quote" in
                            single) escaped="${assignment//\'/\'\\\'\'}" ;;
                            double)
                                escaped="${assignment//\\/\\\\}"
                                escaped="${escaped//\$/\\$}"
                                escaped="${escaped//\`/\\\`}"
                                escaped="${escaped//\"/\\\"}"
                                ;;
                            *) printf -v escaped '%q' "$assignment" ;;
                        esac
                        COMPREPLY+=("$escaped")
                    else
                        COMPREPLY+=("${candidate#"$file_path_before_current"}")
                    fi
                done < <(compgen -f -- "$file_path_before_current$current_path")
                if [[ "$whole_assignment" == true ]]; then
                    compopt -o noquote -o nospace 2>/dev/null || true
                else
                    compopt -o filenames -o nospace 2>/dev/null || true
                fi
                return
            fi
        fi
    fi
    if (( COMP_CWORD > 0 )) && [[ "${COMP_WORDS[COMP_CWORD - 1]}" == --password-env ]]; then
        COMPREPLY=()
        return
    fi
    while (( index < COMP_CWORD )); do
        element="${COMP_WORDS[index]}"
        case "$element" in
            --vault|-V)
                if (( index + 1 < COMP_CWORD )); then
                    vault_args=(--vault "${COMP_WORDS[index + 1]}")
                fi
                index=$((index + 2))
                ;;
            --password-env) index=$((index + 2)) ;;
            --password-stdin) index=$((index + 1)) ;;
            *) break ;;
        esac
    done
    if (( index >= COMP_CWORD )); then
        if (( COMP_CWORD > 0 )) && [[ "${COMP_WORDS[COMP_CWORD - 1]}" == "--vault" || "${COMP_WORDS[COMP_CWORD - 1]}" == "-V" ]]; then
            # A while-read accumulator instead of mapfile: mapfile is
            # bash 4.0+, and on bash 3.2 it would print an unredirected
            # "command not found" on every vault completion while leaving
            # COMPREPLY empty. The loop below behaves identically on
            # every bash that can source this script.
            COMPREPLY=()
            while IFS= read -r candidate; do COMPREPLY+=("$candidate"); done \
                < <(command nkp __complete vaults "$current" 2>/dev/null)
        else
            choices='init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion --help -h --version --vault -V --password-env --password-stdin'
            COMPREPLY=( $(compgen -W "$choices" -- "$current") )
        fi
        return
    fi
    command="${COMP_WORDS[index]}"
    action=''
    if (( index + 1 < COMP_CWORD )); then
        action="${COMP_WORDS[index + 1]}"
    fi
    previous="${COMP_WORDS[COMP_CWORD - 1]}"
    kind=''
    position=$((COMP_CWORD - index))
    local positional_key_command=false selector_seen=false separator_seen=false
    local waiting_for_value=false waiting_for_key=false invalid_option=false
    local waiting_owner='' last_value_owner=''
    case "$command:$action" in
        get:*|set:*|rm:*|remove:*|secrets:get|secrets:set|secrets:rm|secrets:remove)
            positional_key_command=true
            ;;
    esac
    if [[ "$positional_key_command" == true ]]; then
        if [[ "$command" == secrets ]]; then
            scan=$((index + 2))
        else
            scan=$((index + 1))
        fi
        while (( scan < COMP_CWORD )); do
            element="${COMP_WORDS[scan]}"
            if [[ "$waiting_for_value" == true ]]; then
                [[ "$waiting_for_key" == true ]] && selector_seen=true
                last_value_owner="$waiting_owner"
                waiting_for_value=false
                waiting_for_key=false
                waiting_owner=''
                ((scan++))
                continue
            fi
            last_value_owner=''
            if [[ "$element" == -- ]]; then
                separator_seen=true
                ((scan++))
                if (( scan < COMP_CWORD )); then
                    selector_seen=true
                fi
                break
            fi
            case "$element" in
                --key|-k)
                    waiting_for_value=true
                    waiting_for_key=true
                    waiting_owner=key
                    ;;
                --field|-F)
                    waiting_for_value=true
                    waiting_owner=field
                    ;;
                --username|--url|--notes|--value|--value-env|--value-file|--chars|-c|--bin|-b|--name|--file|-f|--output|--password|--password-env|--password-file|--key-file|--size|--format|--strategy|--kdf|--memory|--iterations|--parallelism|--age-recipient|-r|--age-identity|-i)
                    waiting_for_value=true
                    waiting_owner=other
                    ;;
                --yes|--dry-run|--replace|--allow-plaintext|--password-stdin|--stdin|--value-stdin|--generate|--upper|-U|--lower|-L|--digits|-D|--symbols|-S|--is-output|--clipboard|--age-encrypt|--age-decrypt)
                    ;;
                -*)
                    invalid_option=true
                    ;;
                *)
                    selector_seen=true
                    ;;
            esac
            ((scan++))
        done
        if [[ "${COMP_WORDS[COMP_CWORD - 1]-}" == -* \
            && ( "$last_value_owner" == field || "$last_value_owner" == key ) ]]; then
            previous="--$last_value_owner"
        fi
        if [[ "$selector_seen" == false && "$waiting_for_value" == false \
            && "$invalid_option" == false \
            && ! ( "$last_value_owner" == field \
                && "${COMP_WORDS[COMP_CWORD - 1]-}" == -* ) \
            && ( "$current" != -* || "$separator_seen" == true ) ]]; then
            kind=keys
        fi
        if [[ "$separator_seen" == true && "$selector_seen" == true ]]; then
            COMPREPLY=()
            return
        fi
    fi
    case "$previous" in
        --key|-k)
            if [[ "$positional_key_command" == true ]]; then
                if [[ "$waiting_for_key" == true && "$selector_seen" == false \
                    && "$separator_seen" == false ]]; then
                    kind=keys
                elif [[ "$waiting_for_key" == true || "$selector_seen" == true ]]; then
                    COMPREPLY=()
                    return
                fi
            elif [[ "$command" == group || "$command" == groups ]]; then
                kind='groups'
            else
                kind='keys'
            fi
            ;;
        --vault|-V) kind='vaults' ;;
    esac
    if [[ "$command" == context && ( "$action" == use || "$action" == rm ) && $position -eq 2 ]]; then
        kind='vault-aliases'
    elif [[ "$command" == context && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    elif [[ "$command" == alias && $position -eq 1 ]]; then
        kind='aliases'
    elif [[ "$command" == alias && "$action" == set && $position -eq 2 ]]; then
        kind='aliases'
    elif [[ "$command" == alias && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    elif [[ "$command" == alias && "$position" -eq 2 && ( "$action" == resolve || "$action" == rm || "$action" == remove ) ]]; then
        kind='aliases'
    elif [[ "$command" == config && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    fi
    if [[ -n "$kind" ]]; then
        # Same while-read accumulator as the vault branch: mapfile is
        # bash 4.0+ and macOS's default /bin/bash is 3.2.
        COMPREPLY=()
        while IFS= read -r candidate; do COMPREPLY+=("$candidate"); done \
            < <(command nkp "${vault_args[@]}" __complete "$kind" "$current" 2>/dev/null)
        return
    fi
    if [[ "$previous" == "--" && -z "$kind" ]]; then
        return
    fi
    case "$previous:$command:$action" in
        --kind:alias:set) choices='vault entry' ;;
        --kdf:init:*) choices='aes argon2d argon2id' ;;
        --format:get:*|--format:secrets:get) choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:otp:*|--format:secrets:otp) choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:field:get|--format:field:reveal|--format:custom-field:get|--format:custom-field:reveal) choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:env:*|--format:secrets:env) choices='dotenv shell pwsh powershell github-actions azure-devops json null' ;;
        --format:getx:*|--format:secrets:getx) choices='json' ;;
        --strategy:sync:*|--strategy:secrets:sync|--strategy:automation:sync) choices='newest source target' ;;
        --field:get:*|--field:getx:*|--field:set:*|--field:secrets:get|--field:secrets:getx|--field:secrets:set|--field:field:get|--field:field:reveal|--field:field:set|--field:field:edit|--field:custom-field:get|--field:custom-field:reveal|--field:custom-field:set|--field:custom-field:edit) choices='Password Title UserName URL Notes' ;;
        *) choices='' ;;
    esac
    if [[ -n "$choices" ]]; then
        COMPREPLY=( $(compgen -W "$choices" -- "$current") )
        return
    fi
    case "$command" in
        init) choices='--password --password-env --password-file --password-stdin --key-file --kdf --memory --iterations --parallelism --size' ;;
        context)
            [[ -n "$action" ]] || choices='ls list show use rm remove set'
            ;;
        alias)
            if [[ -z "$action" ]]; then
                choices='ls list set rm remove resolve'
            elif [[ "$action" == set ]]; then
                choices='--kind --field'
            fi
            ;;
        config)
            if [[ -z "$action" ]]; then
                choices='ls list get show set rm remove'
            else
                case "$action" in
                    ls|list) choices='--json --' ;;
                    get|show|set|rm|remove) choices='aliases current default_vault' ;;
                esac
            fi
            ;;
        secrets)
            if [[ -z "$action" ]]; then
                choices='get getx list ls search show env environment set rm remove ensure otp setx import export sync'
            else
                case "$action" in
                    ls|list) choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                    search) choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                    show) choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                    env|environment) choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                    get) choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file --clipboard' ;;
                    getx) choices='--key --field --format --password --password-env --password-file --password-stdin --key-file' ;;
                    set) choices='--key --field --username --url --notes --file --bin -b --stdin --value --value-env --value-file --value-stdin --generate --chars -c --size --upper -U --lower -L --digits -D --symbols -S --age-decrypt --age-identity -i --password --password-env --password-file --password-stdin --key-file' ;;
                    rm|remove) choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                    ensure) choices='--key --chars -c --size --upper -U --lower -L --digits -D --symbols -S --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                    otp) choices='--key --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                    setx) choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                    import) choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                    export) choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
                    sync) choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                esac
            fi
            ;;
        get) choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file --clipboard' ;;
        getx) choices='--key --field --format --password --password-env --password-file --password-stdin --key-file' ;;
        list|ls) choices='--password --password-env --password-file --password-stdin --key-file --' ;;
        search) choices='--password --password-env --password-file --password-stdin --key-file --' ;;
        show) choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
        env) choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
        set) choices='--key --field --username --url --notes --file --bin -b --stdin --value --value-env --value-file --value-stdin --generate --chars -c --size --upper -U --lower -L --digits -D --symbols -S --age-decrypt --age-identity -i --password --password-env --password-file --password-stdin --key-file' ;;
        rm|remove) choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
        ensure) choices='--key --chars -c --size --upper -U --lower -L --digits -D --symbols -S --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
        otp) choices='--key --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
        setx) choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
        import) choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
        export) choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
        sync) choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
        automation)
            choices='setx import export sync'
            case "$action" in
                setx) choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                import) choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                export) choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
                sync) choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
            esac
            ;;
        group|groups)
            choices='ls list add create ensure rm remove'
            case "$action" in
                ls|list) choices='--password --password-env --password-file --password-stdin --key-file' ;;
                add|create|ensure) choices='--key --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                rm|remove) choices='--key --yes --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
            esac
            ;;
        files|attachment|attachments)
            if [[ -z "$action" ]]; then
                choices='ls list add import get export rm remove'
            else
                case "$action" in
                    ls|list) choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                    add|import) choices='--key --field --file --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                    get|export) choices='--key --field --output --password --password-env --password-file --password-stdin --key-file' ;;
                    rm|remove) choices='--key --field --yes --password --password-env --password-file --password-stdin --key-file' ;;
                esac
            fi
            ;;
        field|custom-field)
            if [[ -z "$action" ]]; then
                choices='ls list get reveal set edit rm remove'
            else
                case "$action" in
                    ls|list) choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                    get|reveal) choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                    set|edit) choices='--key --field --file --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                    rm|remove) choices='--key --field --yes --password --password-env --password-file --password-stdin --key-file' ;;
                esac
            fi
            ;;
        exec|x) choices='--key --env --password --password-env --password-file --password-stdin --key-file --' ;;
        completion) [[ -z "$action" ]] && choices='bash sh zsh fish powershell pwsh nushell' ;;
    esac
    COMPREPLY=( $(compgen -W "$choices" -- "$current") )
}
complete -o filenames -F _nkp_complete nkp
"#;

const POSIX_SH: &str = r#"# Static nkp completion for POSIX sh. Dynamic queries return metadata only and never secrets.
# POSIX sh has no standard programmable tab-completion registration. This stable
# helper prints matching candidates for CURRENT PREVIOUS COMMAND [ACTION [VAULT_OPTION VAULT_PATH]].
# A POSIX-shell integration can call `nkp_complete "$cur" "$prev" "$command" "$action"`.
_nkp_complete_candidates() {
    _nk_current=$1
    _nk_previous=$2
    _nk_command=$3
    _nk_action=$4
    _nk_vault_option=${5-}
    _nk_vault_path=${6-}
    _nk_kind=''
    case "$_nk_previous" in
        --key) case "$_nk_command" in group|groups) _nk_kind='groups' ;; *) _nk_kind='keys' ;; esac ;;
        --vault|-V) _nk_kind='vaults' ;;
        use|rm)
            if [ "$_nk_command" = context ]; then
                _nk_kind='vault-aliases'
            elif [ "$_nk_command" != config ] && { [ "$_nk_action" = remove ] || [ "$_nk_action" = resolve ] || [ "$_nk_action" = set ]; }; then
                _nk_kind='aliases'
            fi
            ;;
        set)
            if [ "$_nk_command" != context ] && [ "$_nk_command" != config ] && [ "$_nk_action" = set ]; then
                _nk_kind='aliases'
            fi
            ;;
        current|default_vault)
            # `config set KEY VALUE` takes a vault path, as does the path
            # argument of `context set`.
            if [ "$_nk_command" = config ] && [ "$_nk_action" = set ]; then
                _nk_kind='vaults'
            fi
            ;;
    esac
    if [ -n "$_nk_kind" ]; then
        case "$_nk_vault_option" in
            --vault|-V)
                if [ -n "$_nk_vault_path" ]; then
                    nkp "$_nk_vault_option" "$_nk_vault_path" __complete "$_nk_kind" "$_nk_current" 2>/dev/null
                fi
                ;;
            *) nkp __complete "$_nk_kind" "$_nk_current" 2>/dev/null ;;
        esac
        unset _nk_current _nk_previous _nk_command _nk_action _nk_kind _nk_vault_option _nk_vault_path
        return
    fi
    _nk_choices=''
    case "$_nk_previous:$_nk_command:$_nk_action" in
        --password-env:*) _nk_choices='' ;;
        --kind:alias:set) _nk_choices='vault entry' ;;
        --kdf:init:*) _nk_choices='aes argon2d argon2id' ;;
        --format:get:*|--format:secrets:get) _nk_choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:otp:*|--format:secrets:otp) _nk_choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:field:get|--format:field:reveal|--format:custom-field:get|--format:custom-field:reveal) _nk_choices='text json dotenv shell pwsh powershell github-actions azure-devops null' ;;
        --format:env:*|--format:secrets:env) _nk_choices='dotenv shell pwsh powershell github-actions azure-devops json null' ;;
        --format:getx:*|--format:secrets:getx) _nk_choices='json' ;;
        --strategy:sync:*|--strategy:secrets:sync|--strategy:automation:sync) _nk_choices='newest source target' ;;
        --field:get:*|--field:getx:*|--field:set:*|--field:secrets:get|--field:secrets:getx|--field:secrets:set|--field:field:get|--field:field:reveal|--field:field:set|--field:field:edit|--field:custom-field:get|--field:custom-field:reveal|--field:custom-field:set|--field:custom-field:edit) _nk_choices='Password Title UserName URL Notes' ;;
        *)
            case "$_nk_command:$_nk_action" in
                :) _nk_choices='init context alias config secrets automation files attachment attachments group groups exec --vault -V --password-env --password-stdin --help' ;;
                init:*) _nk_choices='--password --password-env --password-file --password-stdin --key-file --kdf --memory --iterations --parallelism --size' ;;
                context:) _nk_choices='ls list show use rm remove set' ;;
                config:ls|config:list) _nk_choices='--json --' ;;
                config:get|config:show|config:set|config:rm|config:remove) _nk_choices='aliases current default_vault' ;;
                config:*) _nk_choices='ls list get show set rm remove' ;;
                alias:) _nk_choices='ls list set rm remove resolve' ;;
                alias:set) _nk_choices='--kind --field' ;;
                secrets:) _nk_choices='get getx list ls search show env environment set rm remove ensure otp setx import export sync' ;;
                secrets:ls|secrets:list) _nk_choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                secrets:search) _nk_choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                secrets:show) _nk_choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:env|secrets:environment) _nk_choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:get) _nk_choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file --clipboard' ;;
                secrets:getx) _nk_choices='--key --field --format --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:set) _nk_choices='--key --field --username --url --notes --file --bin -b --stdin --value --value-env --value-file --value-stdin --generate --chars -c --size --upper -U --lower -L --digits -D --symbols -S --age-decrypt --age-identity -i --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:rm|secrets:remove) _nk_choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:ensure) _nk_choices='--key --chars -c --size --upper -U --lower -L --digits -D --symbols -S --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:otp) _nk_choices='--key --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:setx) _nk_choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:import) _nk_choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:export) _nk_choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:sync) _nk_choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                get:) _nk_choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file --clipboard' ;;
                getx:) _nk_choices='--key --field --format --password --password-env --password-file --password-stdin --key-file' ;;
                list:|ls:) _nk_choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                search:) _nk_choices='--password --password-env --password-file --password-stdin --key-file --' ;;
                show:) _nk_choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                env:) _nk_choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                set:) _nk_choices='--key --field --username --url --notes --file --bin -b --stdin --value --value-env --value-file --value-stdin --generate --chars -c --size --upper -U --lower -L --digits -D --symbols -S --age-decrypt --age-identity -i --password --password-env --password-file --password-stdin --key-file' ;;
                rm:|remove:) _nk_choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                ensure:) _nk_choices='--key --chars -c --size --upper -U --lower -L --digits -D --symbols -S --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                otp:) _nk_choices='--key --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                setx:) _nk_choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                import:) _nk_choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                export:) _nk_choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
                sync:) _nk_choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                automation:*) _nk_choices='setx import export sync' ;;
                automation:setx) _nk_choices='--key --file --stdin --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                automation:import) _nk_choices='--file --stdin --replace --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                automation:export) _nk_choices='--output --password --password-env --password-file --password-stdin --key-file' ;;
                automation:sync) _nk_choices='--file --stdin --strategy --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                group:ls|groups:ls|group:list|groups:list) _nk_choices='--password --password-env --password-file --password-stdin --key-file' ;;
                group:add|groups:add|group:create|groups:create|group:ensure|groups:ensure) _nk_choices='--key --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                group:rm|groups:rm|group:remove|groups:remove) _nk_choices='--key --yes --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
                group:*|groups:*) _nk_choices='ls list add create ensure rm remove' ;;
                files:ls|attachment:ls|attachments:ls|files:list|attachment:list|attachments:list) _nk_choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                files:add|attachment:add|attachments:add|files:import|attachment:import|attachments:import) _nk_choices='--key --field --file --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                files:get|attachment:get|attachments:get|files:export|attachment:export|attachments:export) _nk_choices='--key --field --output --password --password-env --password-file --password-stdin --key-file' ;;
                files:rm|attachment:rm|attachments:rm|files:remove|attachment:remove|attachments:remove) _nk_choices='--key --field --yes --password --password-env --password-file --password-stdin --key-file' ;;
                files:*|attachment:*|attachments:*) _nk_choices='ls list add import get export rm remove' ;;
                field:*) _nk_choices='ls list get reveal set edit rm remove' ;;
                custom-field:*) _nk_choices='ls list get reveal set edit rm remove' ;;
                field:ls|custom-field:ls|field:list|custom-field:list) _nk_choices='--key --password --password-env --password-file --password-stdin --key-file' ;;
                field:get|custom-field:get|field:reveal|custom-field:reveal) _nk_choices='--key --field --name --format --is-output --password --password-env --password-file --password-stdin --key-file' ;;
                field:set|custom-field:set|field:edit|custom-field:edit) _nk_choices='--key --field --file --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                field:rm|custom-field:rm|field:remove|custom-field:remove) _nk_choices='--key --field --yes --password --password-env --password-file --password-stdin --key-file' ;;
                exec:*) _nk_choices='--key --env --password --password-env --password-file --password-stdin --key-file --' ;;
                x:*) _nk_choices='--key --env --password --password-env --password-file --password-stdin --key-file --' ;;
                completion:) _nk_choices='bash sh zsh fish powershell pwsh nushell' ;;
            esac
            ;;
    esac
    for _nk_candidate in $_nk_choices; do
        case "$_nk_candidate" in
            "$_nk_current"*) printf '%s\n' "$_nk_candidate" ;;
        esac
    done
    unset _nk_current _nk_previous _nk_command _nk_action _nk_kind _nk_choices _nk_candidate
}
nkp_complete() {
    _nkp_complete_candidates "${1-}" "${2-}" "${3-}" "${4-}" "${5-}" "${6-}"
}
"#;

const ZSH: &str = r#"#compdef nkp
# Static nkp completion. Dynamic queries return metadata only and never secrets.
_nkp() {
    local -a choices dynamic vault_args
    local -i command_index=2 position
    local command action previous element kind
    vault_args=()
    if (( CURRENT > 1 )) && [[ "${words[CURRENT - 1]}" == --password-env ]]; then
        return
    fi
    while (( command_index < CURRENT )); do
        element="${words[command_index]}"
        case "$element" in
            --vault|-V)
                if (( command_index + 1 < CURRENT )); then
                    vault_args=(--vault "${words[command_index + 1]}")
                fi
                command_index=$((command_index + 2))
                ;;
            --password-env) command_index=$((command_index + 2)) ;;
            --password-stdin) command_index=$((command_index + 1)) ;;
            *) break ;;
        esac
    done
    if (( CURRENT <= command_index )); then
        if [[ "${words[CURRENT - 1]}" == "--vault" || "${words[CURRENT - 1]}" == "-V" ]]; then
            dynamic=("${(@f)$(command nkp __complete vaults "$cur" 2>/dev/null)}")
            (( ${#dynamic} && ${#dynamic[1]} )) && _describe -t values 'nkp metadata' dynamic
        else
            choices=(init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion '--help' '-h' '--version' '--vault' '-V' '--password-env' '--password-stdin')
            _describe -t commands 'nkp command' choices
        fi
        return
    fi
    command="${words[command_index]}"
    action=''
    (( command_index + 1 < CURRENT )) && action="${words[command_index + 1]}"
    previous="${words[CURRENT - 1]}"
    kind=''
    position=$((CURRENT - command_index))
    case "$previous" in
        --key) if [[ "$command" == group || "$command" == groups ]]; then kind='groups'; else kind='keys'; fi ;;
        --vault|-V) kind='vaults' ;;
    esac
    if [[ "$command" == context && ( "$action" == use || "$action" == rm ) && $position -eq 2 ]]; then
        kind='vault-aliases'
    elif [[ "$command" == context && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    elif [[ "$command" == alias && $position -eq 1 ]]; then
        kind='aliases'
    elif [[ "$command" == alias && "$action" == set && $position -eq 2 ]]; then
        kind='aliases'
    elif [[ "$command" == alias && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    elif [[ "$command" == alias && $position -eq 2 && ( "$action" == resolve || "$action" == rm || "$action" == remove ) ]]; then
        kind='aliases'
    elif [[ "$command" == config && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    fi
    if [[ -n "$kind" ]]; then
        dynamic=("${(@f)$(command nkp "${vault_args[@]}" __complete "$kind" "$cur" 2>/dev/null)}")
        (( ${#dynamic} && ${#dynamic[1]} )) && _describe -t values 'nkp metadata' dynamic
        return
    fi
    if [[ "$previous" == "--" ]]; then
        return
    fi
    choices=()
    case "$previous:$command:$action" in
        --kind:alias:set) choices=(vault entry) ;;
        --kdf:init:*) choices=(aes argon2d argon2id) ;;
        --format:get:*|--format:secrets:get) choices=(text json dotenv shell pwsh powershell github-actions azure-devops null) ;;
        --format:otp:*|--format:secrets:otp) choices=(text json dotenv shell pwsh powershell github-actions azure-devops null) ;;
        --format:field:get|--format:field:reveal|--format:custom-field:get|--format:custom-field:reveal) choices=(text json dotenv shell pwsh powershell github-actions azure-devops null) ;;
        --format:env:*|--format:secrets:env) choices=(dotenv shell pwsh powershell github-actions azure-devops json null) ;;
        --format:getx:*|--format:secrets:getx) choices=(json) ;;
        --strategy:sync:*|--strategy:secrets:sync|--strategy:automation:sync) choices=(newest source target) ;;
        --field:get:*|--field:getx:*|--field:set:*|--field:secrets:get|--field:secrets:getx|--field:secrets:set|--field:field:get|--field:field:reveal|--field:field:set|--field:field:edit|--field:custom-field:get|--field:custom-field:reveal|--field:custom-field:set|--field:custom-field:edit) choices=(Password Title UserName URL Notes) ;;
    esac
    if (( ${#choices} )); then
        _describe -t values 'nkp value' choices
        return
    fi
    case "$command" in
        init) choices=('--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--kdf' '--memory' '--iterations' '--parallelism' '--size') ;;
        context)
            [[ -n "$action" ]] || choices=(ls list show use rm remove set) ;;
        alias)
            if [[ -z "$action" ]]; then
                choices=(ls list set rm remove resolve)
            elif [[ "$action" == set ]]; then
                choices=('--kind' '--field')
            fi ;;
        config)
            if [[ -z "$action" ]]; then
                choices=(ls list get show set rm remove)
            else
                case "$action" in
                    ls|list) choices=('--json' '--') ;;
                    get|show|set|rm|remove) choices=(aliases current default_vault) ;;
                esac
            fi ;;
        secrets)
            if [[ -z "$action" ]]; then
                choices=(get getx list ls search show env environment set rm remove ensure otp setx import export sync)
            else
                case "$action" in
                    ls|list) choices=('--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--') ;;
                    search) choices=('--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--') ;;
                    show) choices=('--key' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    env|environment) choices=('--key' '--field' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    get) choices=('--key' '--field' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--clipboard') ;;
                    getx) choices=('--key' '--field' '--format' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    set) choices=('--key' '--field' '--username' '--url' '--notes' '--file' '--bin' '-b' '--stdin' '--value' '--value-env' '--value-file' '--value-stdin' '--generate' '--chars' '-c' '--size' '--upper' '-U' '--lower' '-L' '--digits' '-D' '--symbols' '-S' '--age-decrypt' '--age-identity' '-i' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    rm|remove) choices=('--key' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    ensure) choices=('--key' '--size' '--chars' '-c' '--upper' '-U' '--lower' '-L' '--digits' '-D' '--symbols' '-S' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    otp) choices=('--key' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    setx) choices=('--key' '--file' '--stdin' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    import) choices=('--file' '--stdin' '--replace' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    export) choices=('--output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    sync) choices=('--file' '--stdin' '--strategy' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                esac
            fi ;;
        get) choices=('--key' '--field' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--clipboard') ;;
        getx) choices=('--key' '--field' '--format' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        show) choices=('--key' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        list|ls) choices=('--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--') ;;
        search) choices=('--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--') ;;
        env) choices=('--key' '--field' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        set) choices=('--key' '--field' '--username' '--url' '--notes' '--file' '--bin' '-b' '--stdin' '--value' '--value-env' '--value-file' '--value-stdin' '--generate' '--chars' '-c' '--size' '--upper' '-U' '--lower' '-L' '--digits' '-D' '--symbols' '-S' '--age-decrypt' '--age-identity' '-i' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        rm|remove) choices=('--key' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        ensure) choices=('--key' '--size' '--chars' '-c' '--upper' '-U' '--lower' '-L' '--digits' '-D' '--symbols' '-S' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        otp) choices=('--key' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        setx) choices=('--key' '--file' '--stdin' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        import) choices=('--file' '--stdin' '--replace' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        export) choices=('--output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        sync) choices=('--file' '--stdin' '--strategy' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        automation)
            choices=(setx import export sync)
            case "$action" in
                setx) choices=('--key' '--file' '--stdin' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                import) choices=('--file' '--stdin' '--replace' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                export) choices=('--output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                sync) choices=('--file' '--stdin' '--strategy' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
            esac
            ;;
        group|groups)
            choices=(ls list add create ensure rm remove)
            case "$action" in
                ls|list) choices=(--password --password-env --password-file --password-stdin --key-file) ;;
                add|create|ensure) choices=(--key --dry-run --password --password-env --password-file --password-stdin --key-file) ;;
                rm|remove) choices=(--key --yes --dry-run --password --password-env --password-file --password-stdin --key-file) ;;
            esac
            ;;
        files|attachment|attachments)
            if [[ -z "$action" ]]; then
                choices=(ls list add import get export rm remove)
            else
                case "$action" in
                    ls|list) choices=('--key' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    add|import) choices=('--key' '--field' '--file' '--stdin' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    get|export) choices=('--key' '--field' '--output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    rm|remove) choices=('--key' '--field' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                esac
            fi ;;
        field|custom-field)
            if [[ -z "$action" ]]; then
                choices=(ls list get reveal set edit rm remove)
            else
                case "$action" in
                    ls|list) choices=('--key' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    get|reveal) choices=('--key' '--field' '--name' '--format' '--is-output' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    set|edit) choices=('--key' '--field' '--file' '--stdin' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    rm|remove) choices=('--key' '--field' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                esac
            fi ;;
        exec|x) choices=('--key' '--env' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file' '--') ;;
        completion) [[ -z "$action" ]] && choices=(bash sh zsh fish powershell pwsh nushell) ;;
    esac
    (( ${#choices} )) && _describe -t values 'nkp value' choices
}
if [[ "$funcstack[1]" == "_nkp" ]]; then
    _nkp "$@"
else
    compdef _nkp nkp
fi
"#;

const FISH: &str = r"# Static nkp completion. Dynamic queries return metadata only and never secrets.
function __nkp_complete_vault_args
    set -l words (commandline -opc)
    set -l i 1
    while test $i -lt (count $words)
        switch $words[$i]
            case --vault -V
                set -l value_index (math $i + 1)
                if test $value_index -lt (count $words)
                    printf '%s\n' --vault $words[$value_index]
                    return
                end
        end
        set i (math $i + 1)
    end
end
complete -c nkp -f
complete -c nkp -n '__fish_use_subcommand' -a 'init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion'
complete -c nkp -n '__fish_use_subcommand' -s h -l help
complete -c nkp -n '__fish_use_subcommand' -s V -l vault -r -a '(nkp (__nkp_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkp -n '__fish_use_subcommand' -l version
complete -c nkp -n '__fish_use_subcommand' -l password-env -r
complete -c nkp -n '__fish_use_subcommand' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from set ensure' -s c -l chars -r
complete -c nkp -n '__fish_seen_subcommand_from set ensure' -s U -l upper
complete -c nkp -n '__fish_seen_subcommand_from set ensure' -s L -l lower
complete -c nkp -n '__fish_seen_subcommand_from set ensure' -s D -l digits
complete -c nkp -n '__fish_seen_subcommand_from set ensure' -s S -l symbols
complete -c nkp -n '__fish_seen_subcommand_from set' -l value -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l value-env -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l value-file -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l value-stdin
complete -c nkp -n '__fish_seen_subcommand_from set' -l generate
complete -c nkp -n '__fish_seen_subcommand_from set' -l age-decrypt
complete -c nkp -n '__fish_seen_subcommand_from set' -s i -l age-identity -r
complete -c nkp -n '__fish_seen_subcommand_from context' -a 'ls list show use rm remove set'
complete -c nkp -n '__fish_seen_subcommand_from init' -l kdf -a 'aes argon2d argon2id'
complete -c nkp -n '__fish_seen_subcommand_from init' -l memory
complete -c nkp -n '__fish_seen_subcommand_from init' -l iterations
complete -c nkp -n '__fish_seen_subcommand_from init' -l parallelism
complete -c nkp -n '__fish_seen_subcommand_from init' -l size
complete -c nkp -n '__fish_seen_subcommand_from init' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from init' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from init' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from init' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from alias' -a 'ls list set rm remove resolve'
complete -c nkp -n '__fish_seen_subcommand_from alias set rm remove resolve' -a '(nkp (__nkp_complete_vault_args) __complete aliases (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from context use rm' -a '(nkp (__nkp_complete_vault_args) __complete vault-aliases (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from context set' -a '(nkp (__nkp_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from alias; and __fish_seen_argument set' -l kind -a 'vault entry'
complete -c nkp -n '__fish_seen_subcommand_from alias; and __fish_seen_argument set' -l field
complete -c nkp -n '__fish_seen_subcommand_from config' -a 'ls list get show set rm remove'
complete -c nkp -n '__fish_seen_subcommand_from config ls list' -l json
complete -c nkp -n '__fish_seen_subcommand_from config get show set rm remove' -a 'aliases current default_vault'
complete -c nkp -n '__fish_seen_subcommand_from config set' -a '(nkp (__nkp_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from secrets' -a 'get getx list ls search show env environment set rm remove ensure otp setx import export sync'
complete -c nkp -n '__fish_seen_subcommand_from automation' -a 'setx import export sync'
complete -c nkp -n '__fish_seen_subcommand_from get getx set setx rm remove ensure search show env environment otp files attachment attachments field custom-field exec x' -l key -r -a '(nkp (__nkp_complete_vault_args) __complete keys (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from get getx set' -l field -a 'Password Title UserName URL Notes'
complete -c nkp -n '__fish_seen_subcommand_from get otp' -l format -a 'text json dotenv shell pwsh powershell github-actions azure-devops null'
complete -c nkp -n '__fish_seen_subcommand_from env environment' -l format -a 'dotenv shell pwsh powershell github-actions azure-devops json null'
complete -c nkp -n '__fish_seen_subcommand_from get' -l clipboard
complete -c nkp -n '__fish_seen_subcommand_from get env environment otp' -l is-output
complete -c nkp -n '__fish_seen_subcommand_from getx' -l format -a 'json'
complete -c nkp -n '__fish_seen_subcommand_from ls' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from get env environment otp field custom-field' -l name
complete -c nkp -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password
complete -c nkp -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from ls list search' -a '--'
complete -c nkp -n '__fish_seen_subcommand_from set' -l file
complete -c nkp -n '__fish_seen_subcommand_from set' -s b -l bin -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l username -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l url -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l notes -r
complete -c nkp -n '__fish_seen_subcommand_from set' -l stdin
complete -c nkp -n '__fish_seen_subcommand_from rm' -l yes
complete -c nkp -n '__fish_seen_subcommand_from ensure' -l size
complete -c nkp -n '__fish_seen_subcommand_from setx import sync' -l file
complete -c nkp -n '__fish_seen_subcommand_from setx import sync' -l stdin
complete -c nkp -n '__fish_seen_subcommand_from import' -l replace
complete -c nkp -n '__fish_seen_subcommand_from setx import sync' -l dry-run
complete -c nkp -n '__fish_seen_subcommand_from sync' -l strategy -a 'newest source target'
complete -c nkp -n '__fish_seen_subcommand_from export' -l output
complete -c nkp -n '__fish_seen_subcommand_from setx import export sync' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from setx import export sync' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from setx import export sync' -l password
complete -c nkp -n '__fish_seen_subcommand_from setx import export sync' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from setx import export sync' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from ensure' -l dry-run
complete -c nkp -n '__fish_seen_subcommand_from group groups' -a 'ls list add create ensure rm remove'
complete -c nkp -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument add create ensure rm remove' -l key -r -a '(nkp (__nkp_complete_vault_args) __complete groups (commandline -ct))'
complete -c nkp -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument add create ensure rm remove' -l dry-run
complete -c nkp -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument rm remove' -l yes
complete -c nkp -n '__fish_seen_subcommand_from group groups' -l password -r
complete -c nkp -n '__fish_seen_subcommand_from group groups' -l password-env -r
complete -c nkp -n '__fish_seen_subcommand_from group groups' -l password-file -r
complete -c nkp -n '__fish_seen_subcommand_from group groups' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from group groups' -l key-file -r
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments' -a 'ls list add import get export rm remove'
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l key
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l field
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l file
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l stdin
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument get export' -l field
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument get export' -l output
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument rm remove' -l field
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument rm remove' -l yes
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l password
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from add' -l field
complete -c nkp -n '__fish_seen_subcommand_from add' -l file
complete -c nkp -n '__fish_seen_subcommand_from add' -l stdin
complete -c nkp -n '__fish_seen_subcommand_from get' -l output
complete -c nkp -n '__fish_seen_subcommand_from get' -l field
complete -c nkp -n '__fish_seen_subcommand_from rm' -l field
complete -c nkp -n '__fish_seen_subcommand_from add get rm' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from add get rm' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from rm' -l yes
complete -c nkp -n '__fish_seen_subcommand_from field custom-field' -a 'ls list get reveal set edit rm remove'
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l key
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l field
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit rm remove' -l field
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l format -a 'text json dotenv shell pwsh powershell github-actions azure-devops null'
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l is-output
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit' -l file
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit' -l stdin
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument rm remove' -l yes
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l password
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l env
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l password-env
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l password-stdin
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l password
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l password-file
complete -c nkp -n '__fish_seen_subcommand_from exec x' -l key-file
complete -c nkp -n '__fish_seen_subcommand_from exec x' -a '--'
complete -c nkp -n '__fish_seen_subcommand_from completion' -a 'bash sh zsh fish powershell pwsh nushell'
";

const POWERSHELL: &str = r#"# Static nkp completion. Dynamic queries return metadata only and never secrets.
Register-ArgumentCompleter -Native -CommandName nkp -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = @($commandAst.CommandElements | ForEach-Object {
        $text = $_.Extent.Text
        if (($text.StartsWith("'") -and $text.EndsWith("'")) -or ($text.StartsWith('"') -and $text.EndsWith('"'))) {
            $text = $text.Substring(1, $text.Length - 2)
        }
        $text
    })
    if ($elements.Count -gt 0 -and $cursorPosition -gt $commandAst.Extent.EndOffset) {
        $elements += ''
    }
    $commandIndex = 1
    $vaultArguments = @()
    while ($commandIndex -lt $elements.Count) {
        $element = $elements[$commandIndex]
        if ($element -eq '--vault' -or $element -eq '-V') {
            if ($commandIndex + 1 -lt $elements.Count) {
                $vaultArguments = @('--vault', [string]$elements[$commandIndex + 1])
            }
            $commandIndex += 2
        } elseif ($element -eq '--password-env') {
            $commandIndex += 2
        } elseif ($element -eq '--password-stdin') {
            $commandIndex += 1
        } else {
            break
        }
    }
    $command = ''
    $action = ''
    $currentIndex = $elements.Count - 1
    $previous = ''
    if ($currentIndex -gt 0) {
        $previous = [string]$elements[$currentIndex - 1]
    }
    if ($previous -eq '--password-env') { return }
    if ($commandIndex -lt $elements.Count) {
        $command = [string]$elements[$commandIndex]
        if ($currentIndex -gt ($commandIndex + 1) -and $elements.Count -gt ($commandIndex + 1)) {
            $action = [string]$elements[$commandIndex + 1]
        }
    }
    if ($currentIndex -le $commandIndex) {
        $command = ''
        $action = ''
    }
    $values = @()
    $protocolKind = ''
    if ($previous -eq '--key') {
        if ($command -in @('group', 'groups')) { $protocolKind = 'groups' }
        else { $protocolKind = 'keys' }
    } elseif ($previous -eq '--vault' -or $previous -eq '-V') {
        $protocolKind = 'vaults'
    } elseif ($command -eq 'context' -and ($action -eq 'use' -or $action -eq 'rm') -and $currentIndex -eq ($commandIndex + 2)) {
        $protocolKind = 'vault-aliases'
    } elseif ($command -eq 'context' -and $action -eq 'set' -and $currentIndex -eq ($commandIndex + 3)) {
        $protocolKind = 'vaults'
    } elseif ($command -eq 'alias' -and $currentIndex -eq ($commandIndex + 1)) {
        $protocolKind = 'aliases'
    } elseif ($command -eq 'alias' -and $action -eq 'set' -and $currentIndex -eq ($commandIndex + 2)) {
        $protocolKind = 'aliases'
    } elseif ($command -eq 'alias' -and $action -eq 'set' -and $currentIndex -eq ($commandIndex + 3)) {
        $protocolKind = 'vaults'
    } elseif ($command -eq 'alias' -and $currentIndex -eq ($commandIndex + 2) -and ($action -eq 'resolve' -or $action -eq 'rm' -or $action -eq 'remove')) {
        $protocolKind = 'aliases'
    } elseif ($command -eq 'config' -and $action -eq 'set' -and $currentIndex -eq ($commandIndex + 3)) {
        $protocolKind = 'vaults'
    }
    if ($protocolKind) {
        $values = @(& nkp @vaultArguments __complete $protocolKind $wordToComplete 2>$null | ForEach-Object { $_.ToString() } | Where-Object { $_ })
    } else {
        if ($previous -ne '--') {
            switch ("$previous`:$command`:$action") {
        '--kind:alias:set' { $values = @('vault', 'entry') }
        '--kdf:init:*' { $values = @('aes', 'argon2d', 'argon2id') }
        '--format:get:*' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:otp:*' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:field:get' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:field:reveal' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:custom-field:get' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:custom-field:reveal' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:env:*' { $values = @('dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'json', 'null') }
        '--format:getx:*' { $values = @('json') }
        '--format:secrets:get' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:secrets:otp' { $values = @('text', 'json', 'dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'null') }
        '--format:secrets:env' { $values = @('dotenv', 'shell', 'pwsh', 'powershell', 'github-actions', 'azure-devops', 'json', 'null') }
        '--format:secrets:getx' { $values = @('json') }
        '--strategy:sync:*' { $values = @('newest', 'source', 'target') }
        '--strategy:secrets:sync' { $values = @('newest', 'source', 'target') }
        '--strategy:automation:sync' { $values = @('newest', 'source', 'target') }
        '--field:get:*' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:getx:*' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:set:*' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:secrets:get' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:secrets:getx' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:secrets:set' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:field:get' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:field:reveal' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:field:set' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:field:edit' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:custom-field:get' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:custom-field:reveal' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:custom-field:set' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        '--field:custom-field:edit' { $values = @('Password', 'Title', 'UserName', 'URL', 'Notes') }
        default {
            switch ($command) {
                '' { $values = @('init', 'context', 'alias', 'config', 'secrets', 'automation', 'get', 'getx', 'list', 'ls', 'search', 'env', 'set', 'rm', 'remove', 'ensure', 'otp', 'setx', 'import', 'export', 'sync', 'files', 'attachment', 'attachments', 'group', 'groups', 'field', 'custom-field', 'exec', 'x', 'version', 'completion', '--help', '-h', '--version', '--vault', '-V', '--password-env', '--password-stdin') }
                'init' { $values = @('--password', '--password-env', '--password-file', '--password-stdin', '--key-file', '--kdf', '--memory', '--iterations', '--parallelism', '--size') }
                'context' { if (-not $action) { $values = @('ls', 'list', 'show', 'use', 'rm', 'remove', 'set') } }
                'alias' {
                    if (-not $action) { $values = @('ls', 'list', 'set', 'rm', 'remove', 'resolve') }
                    elseif ($action -eq 'set') { $values = @('--kind', '--field') }
                }
                'config' {
                    if (-not $action) { $values = @('ls', 'list', 'get', 'show', 'set', 'rm', 'remove') }
                    else {
                        switch ($action) {
                            { $_ -in @('ls', 'list') } { $values = @('--json', '--') }
                            { $_ -in @('get', 'show', 'set', 'rm', 'remove') } { $values = @('aliases', 'current', 'default_vault') }
                        }
                    }
                }
                'secrets' {
                    if (-not $action) { $values = @('get', 'getx', 'list', 'ls', 'search', 'show', 'env', 'environment', 'set', 'rm', 'remove', 'ensure', 'otp', 'setx', 'import', 'export', 'sync') }
                    else {
                        switch ($action) {
                            { $_ -in @('ls', 'list') } { $values = @('--password', '--password-env', '--password-file', '--password-stdin', '--key-file', '--') }
                            'search' { $values = @('--password', '--password-env', '--password-file', '--password-stdin', '--key-file', '--') }
                            'show' { $values = @('--key', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('env', 'environment') } { $values = @('--key', '--field', '--name', '--format', '--is-output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'get' { $values = @('--key', '--field', '--name', '--format', '--is-output', '--clipboard', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'getx' { $values = @('--key', '--field', '--format', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'set' { $values = @('--key', '--field', '--username', '--url', '--notes', '--file', '--bin', '-b', '--stdin', '--value', '--value-env', '--value-file', '--value-stdin', '--generate', '--chars', '-c', '--size', '--upper', '-U', '--lower', '-L', '--digits', '-D', '--symbols', '-S', '--age-decrypt', '--age-identity', '-i', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('rm', 'remove') } { $values = @('--key', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'ensure' { $values = @('--key', '--size', '--chars', '-c', '--upper', '-U', '--lower', '-L', '--digits', '-D', '--symbols', '-S', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'otp' { $values = @('--key', '--name', '--format', '--is-output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'setx' { $values = @('--key', '--file', '--stdin', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'import' { $values = @('--file', '--stdin', '--replace', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'export' { $values = @('--output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'sync' { $values = @('--file', '--stdin', '--strategy', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                        }
                    }
                }
                'get' { $values = @('--key', '--field', '--name', '--format', '--is-output', '--clipboard', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'getx' { $values = @('--key', '--field', '--format', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                { $_ -in @('list', 'ls', 'search') } { $values = @('--password', '--password-env', '--password-file', '--password-stdin', '--key-file', '--') }
                'show' { $values = @('--key', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'env' { $values = @('--key', '--field', '--name', '--format', '--is-output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'set' { $values = @('--key', '--field', '--username', '--url', '--notes', '--file', '--bin', '-b', '--stdin', '--value', '--value-env', '--value-file', '--value-stdin', '--generate', '--chars', '-c', '--size', '--upper', '-U', '--lower', '-L', '--digits', '-D', '--symbols', '-S', '--age-decrypt', '--age-identity', '-i', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                { $_ -in @('rm', 'remove') } { $values = @('--key', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'ensure' { $values = @('--key', '--size', '--chars', '-c', '--upper', '-U', '--lower', '-L', '--digits', '-D', '--symbols', '-S', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'otp' { $values = @('--key', '--name', '--format', '--is-output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'setx' { $values = @('--key', '--file', '--stdin', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'import' { $values = @('--file', '--stdin', '--replace', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'export' { $values = @('--output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'sync' { $values = @('--file', '--stdin', '--strategy', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'automation' {
                    if (-not $action) { $values = @('setx', 'import', 'export', 'sync') }
                    else {
                        switch ($action) {
                            'setx' { $values = @('--key', '--file', '--stdin', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'import' { $values = @('--file', '--stdin', '--replace', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'export' { $values = @('--output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'sync' { $values = @('--file', '--stdin', '--strategy', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                        }
                    }
                }
                { $_ -in @('files', 'attachment', 'attachments') } {
                    if (-not $action) { $values = @('ls', 'list', 'add', 'import', 'get', 'export', 'rm', 'remove') }
                    else {
                        switch ($action) {
                            { $_ -in @('ls', 'list') } { $values = @('--key', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('add', 'import') } { $values = @('--key', '--field', '--file', '--stdin', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('get', 'export') } { $values = @('--key', '--field', '--output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('rm', 'remove') } { $values = @('--key', '--field', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                        }
                    }
                }
                { $_ -in @('group', 'groups') } {
                    if (-not $action) { $values = @('ls', 'list', 'add', 'create', 'ensure', 'rm', 'remove') }
                    else {
                        switch ($action) {
                            { $_ -in @('ls', 'list') } { $values = @('--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('add', 'create', 'ensure') } { $values = @('--key', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('rm', 'remove') } { $values = @('--key', '--yes', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                        }
                    }
                }
                { $_ -in @('field', 'custom-field') } {
                    if (-not $action) { $values = @('ls', 'list', 'get', 'reveal', 'set', 'edit', 'rm', 'remove') }
                    else {
                        switch ($action) {
                            { $_ -in @('ls', 'list') } { $values = @('--key', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('get', 'reveal') } { $values = @('--key', '--field', '--name', '--format', '--is-output', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('set', 'edit') } { $values = @('--key', '--field', '--file', '--stdin', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('rm', 'remove') } { $values = @('--key', '--field', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                        }
                    }
                }
                { $_ -in @('exec', 'x') } { $values = @('--key', '--env', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file', '--') }
                'completion' { if (-not $action) { $values = @('bash', 'sh', 'zsh', 'fish', 'powershell', 'pwsh', 'nushell') } }
            }
        }
    }
    }
    }
    $prefix = [string]$wordToComplete
    $values | Sort-Object -Unique | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::Ordinal) } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
"#;

macro_rules! define_nushell_completion {
    ($vault_regex:literal) => {
#[cfg(test)]
const NUSHELL_VAULT_CONTEXT_REGEX: &str = $vault_regex;
const NUSHELL: &str = concat!(
    r#"# Static nkp completion. Dynamic queries return metadata only and never secrets.
# Nushell custom completers receive the whole command context as their first argument.
def "nu-complete nkp vault-args" [context: string] {
  let matches = ($context | parse --regex r#'"#,
    $vault_regex,
    r#"'#)
  if ($matches | is-empty) { [] } else {
    let parsed = ($matches | last)
    let vault = if $parsed.double != null { $parsed.double } else if $parsed.single != null { $parsed.single } else { $parsed.bare }
    ["--vault", $vault]
  }
}
def "nu-complete nkp aliases" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete aliases | lines }
def "nu-complete nkp vault-files" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete vault-files | lines }
def "nu-complete nkp vaults" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete vaults | lines }
def "nu-complete nkp entries" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete entries | lines }
def "nu-complete nkp groups" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete groups | lines }
def "nu-complete nkp keys" [context: string] { let args = (nu-complete nkp vault-args $context); ^nkp ...$args __complete keys | lines }
export extern nkp [
  command?: string@"init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion"
  --help(-h)
  --version
  --vault(-V): string@"nu-complete nkp vaults"
  --password-env: string
  --password-stdin
]
export extern "nkp init" [path?: string@"nu-complete nkp vault-files" --kdf: string@"aes argon2d argon2id" --memory: int --iterations: int --parallelism: int --size: int --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp context" [action: string@"ls list show use rm remove set"]
export extern "nkp context ls" []
export extern "nkp context show" []
export extern "nkp context use" [alias: string@"nu-complete nkp vault-aliases"]
export extern "nkp context rm" [alias: string@"nu-complete nkp vault-aliases"]
export extern "nkp context set" [alias: string path: string@"nu-complete nkp vaults"]
export extern "nkp alias" [action: string@"ls list set rm remove resolve"]
export extern "nkp alias ls" []
export extern "nkp alias list" []
export extern "nkp alias set" [name: string@"nu-complete nkp aliases" target: string@"nu-complete nkp vaults" --kind: string@"vault entry" --field: string]
export extern "nkp alias rm" [name: string@"nu-complete nkp aliases"]
export extern "nkp alias remove" [name: string@"nu-complete nkp aliases"]
export extern "nkp alias resolve" [name: string@"nu-complete nkp aliases"]
export extern "nkp config" [action: string@"ls list get show set rm remove"]
export extern "nkp config ls" [glob?: string --json]
export extern "nkp config list" [glob?: string --json]
export extern "nkp config get" [key: string@"aliases current default_vault"]
export extern "nkp config show" [key: string@"aliases current default_vault"]
export extern "nkp config set" [key: string@"aliases current default_vault" value: string@"nu-complete nkp vaults"]
export extern "nkp config rm" [key: string@"aliases current default_vault"]
export extern "nkp config remove" [key: string@"aliases current default_vault"]
export extern "nkp secrets" [action: string@"get getx list ls search show env environment set rm remove ensure otp setx import export sync"]
export extern "nkp secrets list" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets search" [query: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets show" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets env" [--key: string@"nu-complete nkp keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkp secrets environment" [--key: string@"nu-complete nkp keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkp secrets get" [--key: string@"nu-complete nkp keys" --field: string@"Password Title UserName URL Notes" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --clipboard --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkp secrets getx" [--key: string@"nu-complete nkp keys" --field: string@"Password Title UserName URL Notes" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --format: string@"json"]
export extern "nkp secrets ls" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets set" [--key: string@"nu-complete nkp keys" --username: string --url: string --notes: string --field: string --file: string --bin: string --stdin --value: string --value-env: string --value-file: string --value-stdin --generate --chars(-c): int --size: int --upper(-U) --lower(-L) --digits(-D) --symbols(-S) --age-decrypt --age-identity(-i): string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets rm" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp secrets remove" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp secrets ensure" [--key: string@"nu-complete nkp keys" --size: int --chars(-c): int --upper(-U) --lower(-L) --digits(-D) --symbols(-S) --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets otp" [--key: string@"nu-complete nkp keys" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkp secrets setx" [--key: string@"nu-complete nkp keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp automation" [action: string@"setx import export sync"]
export extern "nkp automation setx" [--key: string@"nu-complete nkp keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp automation import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp automation export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp automation sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp get" [--key: string@"nu-complete nkp keys" --field: string@"Password Title UserName URL Notes" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --clipboard --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkp getx" [--key: string@"nu-complete nkp keys" --field: string@"Password Title UserName URL Notes" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --format: string@"json"]
export extern "nkp list" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp ls" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp search" [query: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp show" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp env" [--key: string@"nu-complete nkp keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkp set" [--key: string@"nu-complete nkp keys" --username: string --url: string --notes: string --field: string --file: string --bin: string --stdin --value: string --value-env: string --value-file: string --value-stdin --generate --chars(-c): int --size: int --upper(-U) --lower(-L) --digits(-D) --symbols(-S) --age-decrypt --age-identity(-i): string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp rm" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp remove" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp ensure" [--key: string@"nu-complete nkp keys" --size: int --chars(-c): int --upper(-U) --lower(-L) --digits(-D) --symbols(-S) --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp otp" [--key: string@"nu-complete nkp keys" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkp setx" [--key: string@"nu-complete nkp keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group" [action: string@"ls list add create ensure rm remove"]
export extern "nkp groups" [action: string@"ls list add create ensure rm remove"]
export extern "nkp group ls" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group list" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups ls" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups list" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group add" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group create" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group ensure" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups add" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups create" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups ensure" [--key: string@"nu-complete nkp groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group rm" [--key: string@"nu-complete nkp groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp group remove" [--key: string@"nu-complete nkp groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups rm" [--key: string@"nu-complete nkp groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp groups remove" [--key: string@"nu-complete nkp groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment" [action: string@"ls list add import get export rm remove"]
export extern "nkp attachments" [action: string@"ls list add import get export rm remove"]
export extern "nkp attachment ls" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment list" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments ls" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments list" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment add" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment import" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments add" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments import" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment get" [--key: string@"nu-complete nkp keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment export" [--key: string@"nu-complete nkp keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments get" [--key: string@"nu-complete nkp keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachments export" [--key: string@"nu-complete nkp keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp attachment rm" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp attachment remove" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp attachments rm" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp attachments remove" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp field" [action: string@"ls list get reveal set edit rm remove"]
export extern "nkp custom-field" [action: string@"ls list get reveal set edit rm remove"]
export extern "nkp field ls" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field list" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field ls" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field list" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field get" [--key: string@"nu-complete nkp keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field reveal" [--key: string@"nu-complete nkp keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field get" [--key: string@"nu-complete nkp keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field reveal" [--key: string@"nu-complete nkp keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field set" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field edit" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field set" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp custom-field edit" [--key: string@"nu-complete nkp keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp field rm" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp field remove" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp custom-field rm" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp custom-field remove" [--key: string@"nu-complete nkp keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp exec" [--key: string@"nu-complete nkp keys" --env: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string ...args: string]
export extern "nkp x" [--key: string@"nu-complete nkp keys" --env: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string ...args: string]
export extern "nkp version" []
export extern "nkp completion" [shell: string@"bash sh zsh fish powershell pwsh nushell"]
"#,
);
    };
}

define_nushell_completion!(
    r#"(?m)^\s*nkp\s+(?:--vault|-V)\s+(?:"(?<double>[^"]*)"|'(?<single>[^']*)'|(?<bare>\S+))"#
);

#[cfg(test)]
mod tests {
    use super::{POWERSHELL, generate};
    use crate::CONFIG_KEYS;
    #[cfg(unix)]
    use std::ffi::OsStr;
    use std::time::Duration;

    /// Deadline for the driver PROCESS to exit, per case. Streams are
    /// drained under separate allowances. Healthy cases finish in a few
    /// seconds; a driver that exceeds this is killed as a tree and the case
    /// fails with diagnostics. The whole bounded run is therefore this
    /// deadline plus at most four drain/recovery allowances
    /// ([`PYTHON_DRIVER_DRAIN_ALLOWANCE`] × 4: two streams × drain and
    /// post-kill recovery) plus kill-helper spawn time.
    #[cfg(unix)]
    const PYTHON_DRIVER_DEADLINE: Duration = Duration::from_secs(20);

    /// Bounded allowance per drain or recovery attempt on a captured stream:
    /// the first drain after the driver exits, then — only after a group
    /// kill in the overflow path — one recovery attempt per stream. An
    /// expired attempt sets `drain_overflow` and is never retried within
    /// the same stage; the reader thread of an unrecovered stream leaks
    /// until process exit rather than risk blocking the harness forever —
    /// the same trade-off the packaging smoke harness documents for a
    /// failed Windows drain.
    #[cfg(unix)]
    const PYTHON_DRIVER_DRAIN_ALLOWANCE: Duration = Duration::from_secs(2);

    /// Outcome of [`run_python_bounded`] — everything a failure diagnostic
    /// needs, including what was captured before a kill.
    #[derive(Debug)]
    #[cfg(unix)]
    struct BoundedDriverRun {
        /// Exit status of the direct child, including the post-kill reap
        /// when the deadline fired.
        status: std::process::ExitStatus,
        /// Whether the deadline expired and the tree was killed.
        timed_out: bool,
        /// True when a captured stream failed to drain within the cleanup
        /// allowance — typically a descendant that kept the inherited pipe
        /// open past the driver's own exit.
        drain_overflow: bool,
        /// Wall-clock time of the whole run, deadline and cleanup included.
        elapsed: Duration,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    #[cfg(unix)]
    impl BoundedDriverRun {
        fn success(&self) -> bool {
            !self.timed_out && self.status.success()
        }

        fn failure_summary(&self) -> String {
            format!(
                "timed_out={} status={:?} elapsed={:?} drain_overflow={}\n\
                 -- driver stdout --\n{}\n\
                 -- driver stderr --\n{}",
                self.timed_out,
                self.status,
                self.elapsed,
                self.drain_overflow,
                String::from_utf8_lossy(&self.stdout),
                String::from_utf8_lossy(&self.stderr),
            )
        }
    }

    /// Run `python3 -c <script> <arguments>` bounded: one deadline for the
    /// driver PROCESS to exit, then separate bounded allowances to drain
    /// each captured stream — and, after a group kill in the overflow path,
    /// to recover what was captured before the kill. The test-side analogue
    /// of the packaging smoke-harness contract in `docs/ci-cd.md` and the
    /// direct answer to the macOS hang documented there: a wedged driver
    /// fails within a bounded budget instead of hanging the test binary,
    /// and no descendant holding inherited pipes survives the harness.
    ///
    /// Unix-only: every caller drives a pty or asserts process-group
    /// cleanup, and the kill needs process-group semantics. Native Windows
    /// tree containment is the packaging harness's job object, not this
    /// helper's. On Unix the driver is born into its own process group so
    /// the kill reaches every descendant, not just the direct child.
    #[cfg(unix)]
    fn run_python_bounded(
        script: &str,
        arguments: &[&OsStr],
        deadline: Duration,
    ) -> BoundedDriverRun {
        let started = std::time::Instant::now();
        let mut command = std::process::Command::new("python3");
        command
            .arg("-c")
            .arg(script)
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Own process group: killpg then reaches descendants that inherited
        // the redirected pipes, not just the direct child.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let mut child = command.spawn().expect("python3 driver should start");
        let mut stdout_pipe = child.stdout.take().expect("driver stdout is piped");
        let mut stderr_pipe = child.stderr.take().expect("driver stderr is piped");
        let (stdout_sender, stdout_receiver) = std::sync::mpsc::channel();
        let (stderr_sender, stderr_receiver) = std::sync::mpsc::channel();
        // Drains read to EOF on threads, so a full pipe can never deadlock a
        // wedged driver against the harness.
        std::thread::spawn(move || {
            let mut captured = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut captured);
            let _ = stdout_sender.send(captured);
        });
        std::thread::spawn(move || {
            let mut captured = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut captured);
            let _ = stderr_sender.send(captured);
        });

        let mut timed_out = false;
        loop {
            match child.try_wait().expect("driver status should be readable") {
                Some(_) => break,
                None if started.elapsed() >= deadline => {
                    timed_out = true;
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        if timed_out {
            kill_driver_tree(&mut child);
        }
        let status = child.wait().expect("driver reaping should succeed");

        let mut drain_overflow = false;
        let stdout = drain_capture(&stdout_receiver, &mut drain_overflow);
        let stderr = drain_capture(&stderr_receiver, &mut drain_overflow);
        if drain_overflow {
            // A descendant outlived the driver while holding the redirected
            // pipes. The direct child is already reaped here, so cleanup is
            // group-only — `Child::kill` on a reaped child could signal a
            // reused pid. The group kill closes the surviving write ends, so
            // one bounded recovery drain per stream can now reach EOF.
            kill_driver_group(child.id());
            let recovered_stdout = stdout_receiver
                .recv_timeout(PYTHON_DRIVER_DRAIN_ALLOWANCE)
                .unwrap_or_default();
            let recovered_stderr = stderr_receiver
                .recv_timeout(PYTHON_DRIVER_DRAIN_ALLOWANCE)
                .unwrap_or_default();
            return BoundedDriverRun {
                status,
                timed_out,
                drain_overflow,
                elapsed: started.elapsed(),
                stdout: if recovered_stdout.is_empty() {
                    stdout
                } else {
                    recovered_stdout
                },
                stderr: if recovered_stderr.is_empty() {
                    stderr
                } else {
                    recovered_stderr
                },
            };
        }
        BoundedDriverRun {
            status,
            timed_out,
            drain_overflow,
            elapsed: started.elapsed(),
            stdout,
            stderr,
        }
    }

    /// Drain one captured stream, bounded by a single allowance. An expired
    /// attempt sets the overflow flag; recovery happens only after the
    /// group kill in the caller, when EOF is actually reachable — the
    /// harness never stacks attempts on a pipe a live descendant still
    /// holds.
    #[cfg(unix)]
    fn drain_capture(
        receiver: &std::sync::mpsc::Receiver<Vec<u8>>,
        overflow: &mut bool,
    ) -> Vec<u8> {
        if let Ok(captured) = receiver.recv_timeout(PYTHON_DRIVER_DRAIN_ALLOWANCE) {
            return captured;
        }
        *overflow = true;
        Vec::new()
    }

    /// Deadline for the python3 kill-helper to exit. A healthy helper
    /// starts one interpreter, issues one `killpg`, and is done in well
    /// under a second; a helper that exceeds this is wedged the same way
    /// the macOS incident's driver was, so the harness kills and reaps it
    /// instead of waiting without end.
    #[cfg(unix)]
    const PYTHON_HELPER_DEADLINE: Duration = Duration::from_secs(10);

    /// Run a one-shot `python3 -c <script> <arguments>` helper whose exit
    /// wait is bounded — never `.status()`, which can block forever on a
    /// wedged interpreter. On deadline the helper is killed while it is
    /// still OUR un-reaped child — no pid-reuse window, the same rule the
    /// driver's cleanup follows — and then ALWAYS reaped, so nothing
    /// leaks. Best-effort by design: a helper that fails or wedges
    /// changes no verdict on its own; the consequence (a descendant
    /// surviving with a redirected pipe) surfaces as `drain_overflow` in
    /// the run's failure diagnostics.
    #[cfg(unix)]
    fn run_python_helper_bounded(
        script: &str,
        arguments: &[&str],
        deadline: Duration,
    ) -> std::process::ExitStatus {
        let mut helper = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .args(arguments)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("python3 helper should start");
        let started = std::time::Instant::now();
        loop {
            match helper.try_wait().expect("helper status should be readable") {
                Some(status) => return status,
                None if started.elapsed() >= deadline => break,
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        // Deadline fired: the helper is still our un-reaped child, so a
        // direct kill is exact here — and it must happen BEFORE the reap
        // below, while that is still true.
        let _ = helper.kill();
        helper.wait().expect("helper reaping should succeed")
    }

    /// Send SIGKILL to a driver process group via the python3 helper — this
    /// crate forbids `unsafe`, so libc/nix wrappers are unavailable, and
    /// python3 is already the hard dependency of every driver test here.
    /// Never passes 0: that would target our own group. The helper itself
    /// runs bounded ([`run_python_helper_bounded`]): a wedged helper is
    /// killed and reaped within its deadline, so nothing in the cleanup
    /// path can block the harness without end.
    #[cfg(unix)]
    fn signal_driver_group(group: i32) {
        let group = group.to_string();
        let group_kill = run_python_helper_bounded(
            "import os, signal, sys; os.killpg(int(sys.argv[1]), signal.SIGKILL)",
            &[&group],
            PYTHON_HELPER_DEADLINE,
        );
        let _ = group_kill;
    }

    /// Kill the driver tree while the direct child is still live: the
    /// process group first (the driver was born into its own group, so
    /// this reaches descendants that inherited the redirected pipes), then
    /// the direct child.
    #[cfg(unix)]
    fn kill_driver_tree(child: &mut std::process::Child) {
        if let Ok(group) = i32::try_from(child.id()) {
            signal_driver_group(group);
        }
        let _ = child.kill();
    }

    /// Group-only cleanup after the direct child was reaped. Never
    /// `Child::kill()` a reaped child — its pid may already have been
    /// reused for an unrelated process. `killpg` stays correct here: this
    /// path only runs while a descendant still holds a redirected pipe,
    /// and a process group with live members never recycles its id.
    #[cfg(unix)]
    fn kill_driver_group(driver_pid: u32) {
        if let Ok(group) = i32::try_from(driver_pid) {
            signal_driver_group(group);
        }
    }

    /// A wedged driver is killed within the deadline instead of hanging the
    /// test binary, with its captured output preserved in the diagnostic.
    /// This is the direct regression for the 75-minute macOS CI hang that
    /// orphaned python3 on cancellation (incident facts in
    /// `docs/ci-cd.md`); the wedging syscall itself was never captured, so
    /// the mitigation is OS-agnostic bounded cleanup, not a platform patch.
    #[test]
    #[cfg(unix)]
    fn bounded_driver_kills_wedged_python_within_deadline() {
        let run = run_python_bounded(
            "import time; print('wedged', flush=True); time.sleep(600)",
            &[],
            Duration::from_secs(3),
        );
        assert!(
            run.timed_out,
            "deadline should fire against a wedged driver: {}",
            run.failure_summary()
        );
        assert!(
            String::from_utf8_lossy(&run.stdout).contains("wedged"),
            "captured output should survive the kill: {}",
            run.failure_summary()
        );
        assert!(
            !run.drain_overflow,
            "drain should finish once the tree is killed: {}",
            run.failure_summary()
        );
        assert!(
            run.elapsed < Duration::from_secs(15),
            "deadline kill exceeded the bounded budget: {:?}",
            run.elapsed
        );
    }

    /// A driver with an exited leader and a surviving group descendant
    /// cleans up the escapee by group, then reaps the leader and observes
    /// group absence. The descendant inherits a captured stdout pipe, so
    /// successful cleanup must close the writer and let the harness drain
    /// to EOF. This also covers the
    /// post-reap cleanup path: the driver exits and is reaped BEFORE the
    /// drain overflows, so the kill must come from `kill_driver_group`
    /// alone, without touching the reaped child.
    #[test]
    #[cfg(unix)]
    fn bounded_driver_removes_pipe_holding_descendant_no_orphan_survives() {
        let script = r#"
import subprocess, sys
descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
print("descendant", descendant.pid, flush=True)
"#;
        let run = run_python_bounded(script, &[], Duration::from_secs(3));
        assert!(
            !run.timed_out && run.status.success(),
            "the driver itself exited cleanly: {}",
            run.failure_summary()
        );
        assert!(
            run.drain_overflow,
            "the pipe-holding descendant should overflow the drain allowance: {}",
            run.failure_summary()
        );
        assert!(
            run.elapsed < Duration::from_secs(15),
            "orphan removal exceeded the bounded budget: {:?}",
            run.elapsed
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let descendant: u32 = stdout
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .parse()
            .expect("driver should report the escapee pid on stdout");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &descendant.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !alive,
            "pipe-holding escapee {descendant} SURVIVED the bounded tree kill"
        );
    }

    /// A cleanup failure must not mask the case's own diagnostic. The old
    /// driver raised out of its finally, so a cleanup that could not
    /// complete replaced whatever failure was already in flight. A
    /// SIGKILLed group that ignores its reap allowance cannot be forced in
    /// a test, so this drives the driver's compose protocol with the
    /// cleanup failure injected: the primary diagnostic leads, the cleanup
    /// detail is appended after it, and a numeric success does not
    /// silently swallow one either.
    #[test]
    #[cfg(unix)]
    fn bounded_driver_cleanup_failure_appends_to_primary_diagnostic() {
        let script = r#"
import sys

transcript = "simulated transcript"

def fail(message):
    raise SystemExit(message + "; PTY transcript: " + repr(transcript))

def stop_child():
    # Simulated unresolved group; the real driver fails closed unless it
    # positively observes process-group absence.
    return (
        "process group absence not established after bounded cleanup"
        "; PTY transcript: " + repr(transcript)
    )

def compose_failure(primary, cleanup):
    # The hostile-filename driver's finally protocol, in the shape a
    # callable needs: append to the primary diagnostic, never replace it.
    if primary is not None:
        detail = primary.args[0] if primary.args else None
        if isinstance(detail, str):
            raise SystemExit(detail + "; cleanup also failed: " + cleanup)
        raise SystemExit(
            "case ended with " + repr(detail) + "; cleanup failed: " + cleanup
        )
    raise SystemExit("cleanup failed: " + cleanup)

def scenario_with_primary_failure():
    primary = None
    try:
        fail("unexpected completion match state")
    except BaseException as raised:
        primary = raised
    finally:
        cleanup = stop_child()
        if cleanup is not None:
            compose_failure(primary, cleanup)
        if primary is not None:
            raise primary

def scenario_with_numeric_success():
    primary = None
    try:
        raise SystemExit(0)
    except BaseException as raised:
        primary = raised
    finally:
        cleanup = stop_child()
        if cleanup is not None:
            compose_failure(primary, cleanup)
        if primary is not None:
            raise primary

failures = 0
for scenario in (scenario_with_primary_failure, scenario_with_numeric_success):
    try:
        scenario()
    except SystemExit as failure:
        failures += 1
        print(
            "scenario failure:",
            failure.args[0] if failure.args else failure,
            file=sys.stderr,
            flush=True,
        )
raise SystemExit(failures)
"#;
        let run = run_python_bounded(script, &[], Duration::from_secs(10));
        assert!(
            !run.success(),
            "a cleanup failure must fail the case: {}",
            run.failure_summary()
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        let primary = stderr.find("unexpected completion match state");
        let appended = stderr.find("cleanup also failed: ");
        assert!(
            primary.is_some() && appended.is_some() && primary.unwrap() < appended.unwrap(),
            "the primary diagnostic must lead, with the cleanup appended after it: {}",
            run.failure_summary()
        );
        assert!(
            stderr.contains("process group absence not established"),
            "the cleanup detail must be part of the composed diagnostic: {}",
            run.failure_summary()
        );
        assert!(
            stderr.contains("case ended with 0"),
            "a numeric success must not silently swallow a cleanup failure: {}",
            run.failure_summary()
        );
    }

    /// An exited-but-unreaped group leader pins its PGID while cleanup
    /// signals the group. After reaping that leader, cleanup only probes
    /// for group absence and never signals the numeric PGID again.
    #[cfg(unix)]
    fn owned_group_fixture() -> &'static str {
        r#"
import errno, os, signal, subprocess, sys, time

transcript = b""
started = time.monotonic()

def stop_child(pid):
    events = []
    last_probe = "none"
    # The leader has been observed exited via waitid(WNOWAIT) and remains
    # unreaped. Its PID was also its session/process-group ID at creation;
    # do not call getpgid on a zombie, which can return ESRCH on macOS.
    os.killpg(pid, signal.SIGCONT)
    events.append("continue")
    os.killpg(pid, signal.SIGKILL)
    events.append("kill")
    waited, _ = os.waitpid(pid, 0)
    assert waited == pid
    events.append("reap")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
            last_probe = "exists"
        except OSError as error:
            if error.errno == errno.ESRCH:
                events.append("absent")
                return events
            last_probe = "errno-%s" % error.errno
            if error.errno != errno.EPERM:
                return events + ["probe-errno-%s" % error.errno]
            # Darwin can report EPERM for a group with no signalable
            # members, including an unreaped zombie. EPERM is not absence.
        time.sleep(0.02)
    return events + ["group-absence-unconfirmed-" + last_probe]

# pty.fork() gives the real driver's child its own session and group;
# this replicates that shape so the group semantics are the real ones.
child = subprocess.Popen(
    ["bash", "--noprofile", "--norc", "-c", "sleep 600 & echo $!"],
    start_new_session=True,
    stdout=subprocess.PIPE,
)
straggler = int(child.stdout.readline().decode())
# Observe leader exit without reaping it. It must stay waitable while the
# descendant remains in the same process group.
deadline = time.monotonic() + 3
observation = None
while time.monotonic() < deadline:
    observation = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observation is not None and observation.si_pid == child.pid:
        break
    time.sleep(0.02)
assert observation is not None and observation.si_pid == child.pid
leader_observed_at = time.monotonic()
# A bystander in its own group, outside everything the cleanup owns: it
# must come through the cleanup untouched.
victim = subprocess.Popen(
    ["sleep", "600"],
    start_new_session=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    events = stop_child(child.pid)
    bystander_alive = victim.poll() is None
    print("straggler", straggler, "victim", victim.pid,
          "bystander_alive", bystander_alive,
          "events", ",".join(events),
          "leader_wait_s", round(leader_observed_at - started, 3),
          "cleanup_s", round(time.monotonic() - leader_observed_at, 3),
          flush=True)
    if events[-1] != "absent":
        try:
            snapshot = subprocess.run(
                ["ps", "-o", "pid=,ppid=,stat=,pgid=,uid=", "-p", str(straggler)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, timeout=1, check=False,
            )
            print("straggler ps exit=%s data=%r" %
                  (snapshot.returncode, snapshot.stdout.strip()), file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            print("straggler ps unavailable: %s" % type(error).__name__, file=sys.stderr)
finally:
    # The fixture owns this child; clean it even if an earlier assertion
    # fails, before its PID can be reused, and never orphan the bystander.
    if victim.poll() is None:
        os.killpg(victim.pid, signal.SIGKILL)
    victim.wait(timeout=3)
"#
    }

    #[test]
    #[cfg(unix)]
    fn bounded_driver_owned_group_cleanup_kills_descendant_before_reap() {
        let script = owned_group_fixture();
        let run = run_python_bounded(script, &[], Duration::from_secs(15));
        assert!(
            run.success(),
            "the owned-group cleanup scenario should complete: {}",
            run.failure_summary()
        );
        assert!(
            !run.drain_overflow,
            "group cleanup must kill the pipe-holder so the bounded drain \
             reaches EOF: {}",
            run.failure_summary()
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let mut straggler: Option<u32> = None;
        let mut victim: Option<u32> = None;
        let mut events = None;
        let mut bystander_alive = None;
        let mut fields = stdout.split_whitespace();
        while let Some(field) = fields.next() {
            match field {
                "straggler" => {
                    straggler = fields.next().and_then(|value| value.parse().ok());
                }
                "victim" => {
                    victim = fields.next().and_then(|value| value.parse().ok());
                }
                "events" => events = fields.next(),
                "bystander_alive" => bystander_alive = fields.next(),
                _ => {}
            }
        }
        let straggler =
            straggler.unwrap_or_else(|| panic!("driver should report the straggler pid"));
        let victim = victim.unwrap_or_else(|| panic!("driver should report the bystander pid"));
        assert_eq!(
            events,
            Some("continue,kill,reap,absent"),
            "signals must precede reap, then cleanup must observe group absence: {}",
            run.failure_summary()
        );
        // The straggler must be dead by pid: the group kill reached it
        // while the unreaped leader still pinned the process group.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut straggler_alive = true;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &straggler.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                straggler_alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !straggler_alive,
            "straggler {straggler} SURVIVED the owned-group kill"
        );
        assert_eq!(
            bystander_alive,
            Some("True"),
            "bystander {victim} was killed by a cleanup it never belonged to"
        );
    }

    /// Exercise the real fixture's probe, rather than a copy of its loop:
    /// transient EPERM may settle, but persistent EPERM is never absence.
    #[test]
    #[cfg(unix)]
    fn owned_group_fixture_retries_but_never_accepts_eperm() {
        let script = owned_group_fixture();
        assert_eq!(script.matches("os.killpg(pid, 0)").count(), 1);
        for persistent in [false, true] {
            let probe = format!(
                "probes = 0\ndef probe_group(pid):\n    global probes\n    probes += 1\n    if probes == 1 or {persistent}:\n        raise OSError(errno.EPERM, 'injected')\n    return os.killpg(pid, 0)\n\ndef stop_child(pid):",
                persistent = if persistent { "True" } else { "False" }
            );
            let injected = script
                .replace("os.killpg(pid, 0)", "probe_group(pid)")
                .replace("def stop_child(pid):", &probe);
            let run = run_python_bounded(&injected, &[], Duration::from_secs(15));
            assert!(
                run.success() && !run.drain_overflow,
                "fixture must finish boundedly: {}",
                run.failure_summary()
            );
            let stdout = String::from_utf8_lossy(&run.stdout);
            let expected = if persistent {
                "events continue,kill,reap,group-absence-unconfirmed-errno-1"
            } else {
                "events continue,kill,reap,absent"
            };
            assert!(stdout.contains(expected), "unexpected output: {stdout}");
            assert!(stdout.contains("bystander_alive True"));
            let fields: Vec<_> = stdout.split_whitespace().collect();
            for name in ["straggler", "victim"] {
                let index = fields.iter().position(|value| *value == name).unwrap();
                let pid = fields[index + 1];
                let probe = std::process::Command::new("ps")
                    .args(["-p", pid, "-o", "pid="])
                    .output()
                    .expect("ps must check fixture processes");
                assert!(
                    !probe.status.success() || probe.stdout.trim_ascii().is_empty(),
                    "{name} {pid} leaked: {stdout}"
                );
            }
        }
    }

    /// The diagnostic-only exit handshake records what it observed
    /// instead of hiding it: a clean exit 0 prints nothing, an
    /// exit-by-signal names the signal, a nonzero exit names the code,
    /// and a child that never exits reports the bounded non-exit — and
    /// every branch still lets the case pass, because the handshake is
    /// cleanup, not the behavior under test. The window is shortened to
    /// milliseconds; the loop shape is the real driver's.
    #[test]
    #[cfg(unix)]
    fn exit_handshake_records_status_without_failing_the_case() {
        let script = r#"
import os, signal, subprocess, sys, time

def handshake(pid, window):
    # The hostile-filename driver's exit handshake, verbatim in shape
    # with a test-sized window: a bounded waitpid loop, then whatever
    # was observed recorded on stderr without failing the case. The
    # observed kind is returned, since a shape-level waitpid reap is
    # invisible to subprocess.Popen.returncode.
    deadline = time.monotonic() + window
    exit_status = None
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if waited == pid:
            exit_status = status
            break
        time.sleep(0.02)
    if exit_status is None:
        print(
            "interactive bash did not exit within %ds after 'exit'; the case "
            "itself passed and the group cleanup follows" % window,
            file=sys.stderr,
            flush=True,
        )
        return "not-exited"
    if os.WIFSIGNALED(exit_status):
        print(
            "interactive bash exited to signal %d after 'exit'; the case "
            "itself passed and the group cleanup follows"
            % os.WTERMSIG(exit_status),
            file=sys.stderr,
            flush=True,
        )
        return "signal-%d" % os.WTERMSIG(exit_status)
    if os.WEXITSTATUS(exit_status) != 0:
        print(
            "interactive bash exited %d after 'exit'; the case itself "
            "passed and the group cleanup follows" % os.WEXITSTATUS(exit_status),
            file=sys.stderr,
            flush=True,
        )
        return "code-%d" % os.WEXITSTATUS(exit_status)
    return "clean"

# Clean exit 0: nothing is recorded.
child = subprocess.Popen(["sh", "-c", "exit 0"], start_new_session=True)
print("finding clean", handshake(child.pid, 1.0), flush=True)

# Exit by signal during the window: the signal is named, case passes.
child = subprocess.Popen(["sleep", "600"], start_new_session=True)
time.sleep(0.1)
os.kill(child.pid, signal.SIGKILL)
print("finding signaled", handshake(child.pid, 1.0), flush=True)

# Never exits: the bounded non-exit is recorded, case passes, and the
# shape's own group cleanup then reaps the straggler so nothing leaks.
child = subprocess.Popen(["sleep", "600"], start_new_session=True)
print("finding wedged", handshake(child.pid, 0.3), flush=True)
try:
    os.killpg(child.pid, signal.SIGKILL)
except OSError:
    pass
deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    try:
        waited, _ = os.waitpid(child.pid, os.WNOHANG)
    except ChildProcessError:
        break
    if waited == child.pid:
        break
    time.sleep(0.02)
else:
    raise SystemExit("straggler survived the shape test's own cleanup")
"#;
        let run = run_python_bounded(script, &[], Duration::from_secs(15));
        assert!(
            run.success(),
            "every handshake branch must let the case pass: {}",
            run.failure_summary()
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            stdout.contains("finding clean clean"),
            "the clean-exit scenario must have run and recorded nothing: {}",
            run.failure_summary()
        );
        assert!(
            stdout.contains("finding signaled signal-9"),
            "the signaled scenario must have observed the kill: {}",
            run.failure_summary()
        );
        assert!(
            stdout.contains("finding wedged not-exited"),
            "the wedged scenario must have observed the non-exit: {}",
            run.failure_summary()
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stderr.contains("exited to signal 9"),
            "an exit-by-signal during the window must name the signal: {}",
            run.failure_summary()
        );
        assert!(
            stderr.contains("did not exit within"),
            "a child that never exits must record the bounded non-exit: {}",
            run.failure_summary()
        );
        assert!(
            !stderr.contains("exited 0"),
            "a clean exit 0 must print nothing: {}",
            run.failure_summary()
        );
    }

    /// The args.bin wait waits for the EXPECTED literal argv content,
    /// not mere file existence: a review of 89485ad reproduced the
    /// creation-before-bytes race, where existence-then-read saw the
    /// file while its write was still in flight. The shape below drives
    /// the real loop's contract: a delayed write is waited out and the
    /// expected content is read; content that stays wrong is waited out
    /// too and then fails with the preserved mismatch spelling plus the
    /// last observed content; a file that never appears reports None.
    /// The slice-marker guard pins these spellings inside the real
    /// driver.
    #[test]
    #[cfg(unix)]
    fn args_bin_wait_reads_expected_content_and_reports_last_observed() {
        let script = r#"
import os, sys, threading, time

def wait_for_expected_args(path, expected, window):
    # The hostile-filename driver's args.bin wait, verbatim in shape
    # with a test-sized window: bounded re-read until the content
    # matches, then a single fail site that keeps the mismatch spelling
    # and includes the last observed content.
    deadline = time.monotonic() + window
    while True:
        try:
            with open(path, "rb") as stream:
                actual = stream.read().split(b"\0")[:-1]
        except OSError:
            actual = None
        if actual == expected:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    if actual != expected:
        raise SystemExit(
            "completion produced unexpected literal argv: " + repr(actual)
            + " (last observed after the bounded wait)"
        )
    return actual

directory = sys.argv[1]
expected = [b"set", b"--bin", b"payload=space name.bin"]
joined = b"\0".join(expected) + b"\0"
path = os.path.join(directory, "args.bin")

# Delayed write: the file appears only after the wait has already been
# re-reading an absent file; the loop waits it out and reads the
# expected argv, and it demonstrably waited rather than racing.
def delayed_writer():
    with open(path, "wb") as stream:
        stream.flush()  # file exists, but the command's argv is not written yet
        time.sleep(0.4)
        stream.write(joined)

writer = threading.Thread(target=delayed_writer)
writer.start()
started = time.monotonic()
actual = wait_for_expected_args(path, expected, 2.0)
elapsed = time.monotonic() - started
writer.join()
if actual != expected:
    raise SystemExit("the delayed write was not read as the expected argv")
if elapsed < 0.3:
    raise SystemExit(
        "the wait did not wait out the delayed write: %.2fs" % elapsed
    )

# Content that stays wrong: waited out, then the preserved mismatch
# spelling with the last observed content.
with open(path, "wb") as stream:
    stream.write(b"\0".join([b"set", b"--bin", b"wrong.bin"]) + b"\0")
try:
    wait_for_expected_args(path, expected, 0.3)
except SystemExit as failure:
    message = failure.args[0] if failure.args else ""
    if "completion produced unexpected literal argv" not in message:
        raise SystemExit("mismatch spelling lost: " + message)
    if "wrong.bin" not in message:
        raise SystemExit("last observed content lost: " + message)
else:
    raise SystemExit("wrong content passed the wait")

# Never appears: the wait reports None as the last observed content.
os.remove(path)
try:
    wait_for_expected_args(path, expected, 0.3)
except SystemExit as failure:
    message = failure.args[0] if failure.args else ""
    if "None" not in message:
        raise SystemExit(
            "a missing file's last observed content was not None: " + message
        )
else:
    raise SystemExit("a missing file passed the wait")
"#;
        let directory = tempfile::tempdir().expect("args wait tempdir");
        let run = run_python_bounded(
            script,
            &[directory.path().as_os_str()],
            Duration::from_secs(15),
        );
        assert!(
            run.success(),
            "the wait must read delayed content and report last observed: {}",
            run.failure_summary()
        );
    }

    /// The kill helper is itself a python3 process, and the macOS incident
    /// was precisely a python3 that stopped responding: waiting on it
    /// unbounded would reintroduce the hang class this harness exists to
    /// end. This simulates the unresponsive helper directly — a script
    /// that sleeps instead of signaling — and asserts the exit wait
    /// honors its full deadline, returns past it, and leaves the helper
    /// killed (the kill lands while it is still our un-reaped child, so
    /// no pid-reuse window) and reaped by the returning call.
    #[test]
    #[cfg(unix)]
    fn bounded_kill_helper_returns_within_deadline_from_unresponsive_helper() {
        let deadline = Duration::from_secs(2);
        let started = std::time::Instant::now();
        let status = run_python_helper_bounded("import time; time.sleep(600)", &[], deadline);
        let elapsed = started.elapsed();
        assert!(
            !status.success(),
            "a wedged helper must exit killed, not successfully"
        );
        assert!(
            elapsed >= deadline,
            "the helper wait should honor its full deadline before killing"
        );
        assert!(
            elapsed < deadline + Duration::from_secs(3),
            "a wedged helper must not pin the harness: waited {elapsed:?}"
        );
    }

    /// Every PTY-harness item stays `#[cfg(unix)]`-gated, item by item. The
    /// harness needs a pty and process-group kills, and an ungated
    /// `impl BoundedDriverRun` of a gated struct fails to compile the
    /// Windows unit-test job even though nothing here runs on Windows.
    /// This check is deliberately NOT `#[cfg(unix)]`: it reads the source
    /// as text, so it runs wherever the unit tests run and catches a lost
    /// gate on Linux before Windows CI does. It does not replace a real
    /// cross-target check — `cargo check --target x86_64-pc-windows-msvc`
    /// needs that target's std installed, which this machine does not have —
    /// it guards the one structural rule this file must keep.
    #[test]
    fn pty_harness_items_stay_unix_gated() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable");
        let lines: Vec<&str> = source.lines().collect();
        let gated_items = [
            "use std::ffi::OsStr;",
            "const PYTHON_DRIVER_DEADLINE",
            "const PYTHON_DRIVER_DRAIN_ALLOWANCE",
            "const PYTHON_HELPER_DEADLINE",
            "struct BoundedDriverRun",
            "impl BoundedDriverRun",
            "fn run_python_bounded",
            "fn drain_capture",
            "fn run_python_helper_bounded",
            "fn signal_driver_group",
            "fn kill_driver_tree",
            "fn kill_driver_group",
            "fn ambient_shell_major",
            "fn bash_binary_completion_uses_readline_quoting_for_hostile_filenames",
            "fn bounded_driver_kills_wedged_python_within_deadline",
            "fn bounded_driver_removes_pipe_holding_descendant_no_orphan_survives",
            "fn bounded_driver_cleanup_failure_appends_to_primary_diagnostic",
            "fn bounded_driver_owned_group_cleanup_kills_descendant_before_reap",
            "fn bounded_kill_helper_returns_within_deadline_from_unresponsive_helper",
            "fn pty_driver_cleanup_diagnostic_preserves_primary_and_leaves_no_child",
        ];
        for item in gated_items {
            let position = lines
                .iter()
                .position(|line| line.trim_start().starts_with(item))
                .unwrap_or_else(|| panic!("unix-gated item not found: {item}"));
            let previous = lines[..position]
                .iter()
                .rev()
                .find(|line| !line.trim().is_empty())
                .copied()
                .unwrap_or("");
            assert_eq!(
                previous.trim(),
                "#[cfg(unix)]",
                "unix-gated item `{item}` lost its #[cfg(unix)] attribute — \
                 the Windows unit-test job would fail to compile"
            );
        }
    }

    /// Collapses CRLF pairs to LF in raw source-file bytes.
    ///
    /// This exists for the source-text assertions that read
    /// `completion.rs` itself via `fs::read_to_string`: that path
    /// returns the working copy's raw bytes — a CRLF checkout (Git's
    /// default on Windows, the shape CI run 134548307275 hit) carries
    /// `\r\n`, and the line-sensitive `find`/`starts_with` boundaries
    /// in the driver-slice extraction would shift. String literals, by
    /// contrast, never need this: rustc normalizes CRLF (and lone CR)
    /// to LF before lexing, so the embedded completion scripts come out
    /// LF under any checkout — a guarantee
    /// `generated_scripts_carry_no_carriage_returns` pins.
    fn lf_script(script: &str) -> String {
        script.replace("\r\n", "\n")
    }

    /// Slices the hostile-filename PTY driver's raw-string script out of
    /// `source`, bounded by the driver's `r#"` opening and its `"#;`
    /// terminator. `source` must already be LF-normalized (`lf_script`):
    /// a CRLF working copy bakes `\r\n` into the line after `r#"`, and
    /// the slice-opening boundary below is line-ending sensitive —
    /// Windows CI run 134548307275 checked this file out with CRLF and
    /// failed the slice-opening assertion while every LF runner passed.
    fn hostile_filename_driver_slice(source: &str) -> Option<&str> {
        let execvp_at =
            source.find("os.execvp(\"bash\", [\"bash\", \"--noprofile\", \"--norc\", \"-i\"])")?;
        let script_open = source[..execvp_at].rfind("r#\"")?;
        let script_close = source[execvp_at..].find("\"#;").map(|at| execvp_at + at)?;
        Some(&source[script_open..script_close])
    }

    /// The PTY driver's cleanup must own the process GROUP, never the pid
    /// number: once the child is reaped its pid can be recycled into an
    /// unrelated process, and a direct kill on that path would target
    /// whoever owns the number now. This pins, in the driver's own
    /// raw-string script, the contract the behavior regressions above
    /// exercise: no direct pid kill exists within the driver's script —
    /// the search is bounded by the script's `r#"` opening and its
    /// `"#;` terminator, so tests after the driver keep their
    /// legitimate Rust kills — no direct-kill spelling survives there
    /// at all: `os.kill(` and `.kill(` are both forbidden while
    /// `killpg` alone is sanctioned. The driver
    /// kills through the group on every exit path, a cleanup failure is
    /// composed with the primary diagnostic instead of masking it, and
    /// an argv mismatch reports the PTY transcript. Like the gating check
    /// it reads the source as text and runs wherever the unit tests run
    /// — a Linux-side edit that loses one of these fails here before it
    /// ships.
    #[test]
    fn pty_driver_cleanup_owns_the_group_and_composes_failures() {
        // LF-normalize first: the boundary assertions below read this
        // file's own source text, and a CRLF checkout (Git's default on
        // Windows) shifts the driver slice's opening line.
        let source = lf_script(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable"),
        );
        // Everything asserted below must live in the hostile-filename
        // driver's own raw-string script — bounded exactly by its `r#"`
        // opening and its `"#;` terminator — not in a copy of its protocol
        // kept elsewhere in this file, and not in the Rust code before or
        // after the driver, where an un-reaped-child Rust kill stays
        // legitimate.
        let driver = hostile_filename_driver_slice(&source)
            .expect("the PTY driver's script should be sliceable from this file");
        // The boundary must be non-vacuous: the slice opens on the
        // driver's own first line and stops at its raw-string terminator,
        // swallowing neither the Rust before it nor the Rust after it — a
        // future test after the driver may legitimately keep an
        // un-reaped-child Rust kill.
        assert!(
            driver.starts_with(
                "r#\"\nimport errno, fcntl, os, pty, select, stat, subprocess, sys, time, signal"
            ),
            "the driver slice should open on the driver's own first line"
        );
        assert!(
            !driver.contains("serde_json"),
            "the driver slice must stop at the raw-string terminator — it \
             must not leak into the Rust code after the driver"
        );
        assert!(
            !driver.contains(
                "fn bash_filename_completion_does_not_cross_command_or_option_value_boundaries"
            ),
            "the driver slice must not swallow the tests that follow the driver"
        );
        // Retained from the first guard: the file-wide exact-spelling
        // check, assembled from pieces so this test's own source — which
        // must name the pattern to forbid it — can never satisfy the
        // search.
        let direct_kill_call = ["os.kill(", "pid,"].concat();
        assert!(
            !source.contains(&direct_kill_call),
            "the PTY driver must never kill by pid: a reaped pid can be \
             recycled into an unrelated process"
        );
        // Broadened beyond one spelling: within the driver's script, ANY
        // direct-kill form is forbidden — os.kill(...) calls and .kill()
        // methods alike, since both signal by number and a reaped number
        // can be recycled — while os.killpg(...) stays sanctioned. Rust
        // code before and after this slice may keep its own
        // un-reaped-child kills; this guards only the driver's script.
        let os_kill_call = ["os.", "kill("].concat();
        let method_kill_call = [".", "kill("].concat();
        for forbidden in [os_kill_call.as_str(), method_kill_call.as_str()] {
            assert!(
                !driver.contains(forbidden),
                "the PTY driver must never signal by pid: `{forbidden}` is a \
                 direct kill and a reaped pid can be recycled; killpg is the \
                 only sanctioned kill in the driver"
            );
        }
        for marker in [
            "import errno, fcntl, os, pty, select, stat, subprocess, sys, time, signal",
            "def stop_child():",
            "os.killpg(group_id, signal.SIGCONT)",
            "os.killpg(group_id, signal.SIGKILL)",
            "os.killpg(group_id, 0)",
            "os.WNOWAIT",
            "os.getpgid(pid)",
            "os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)",
            "os.tcgetpgrp(fd)",
            "no PTY child was started",
            "def cleanup_diagnostics(wait_observation):",
            "waitid-before=",
            "master=",
            "process group absence not established",
            "; cleanup also failed: ",
            "case ended with ",
            "raise primary",
            "fail(\"completion produced unexpected literal argv",
            "last observed after the bounded wait",
            "exit observation",
        ] {
            assert!(
                driver.contains(marker),
                "the PTY driver must keep `{marker}` — its cleanup owns the \
                 group (SIGCONT first, so a stopped member cannot hold the \
                 SIGKILL), composes failures, reports the transcript, waits \
                 for the expected argv content with the last observation, and \
                 records the exit handshake's actual status"
            );
        }
        let group_kill = driver
            .find("os.killpg(group_id, signal.SIGKILL)")
            .expect("cleanup should group-kill while the leader pins its PGID");
        let reap = driver
            .find("os.waitpid(pid, os.WNOHANG)")
            .expect("cleanup should reap the leader after signaling");
        let absence_probe = driver
            .find("os.killpg(group_id, 0)")
            .expect("cleanup should probe group absence");
        assert!(
            group_kill < reap && reap < absence_probe,
            "group signal must precede reaping; only a non-signaling absence \
             probe may follow reaping"
        );
        let preflight = driver
            .find("no PTY child was started")
            .expect("unsupported Python must fail before creating the PTY child");
        let fork = driver
            .find("pid, fd = pty.fork()")
            .expect("the driver should create its PTY child only after preflight");
        assert!(
            preflight < fork,
            "waitid capability must be checked before the PTY child is started"
        );
    }

    /// The actual PTY driver must reject a Python runtime without the
    /// non-reaping wait API before it forks Bash or enters cleanup.
    #[test]
    #[cfg(unix)]
    fn pty_driver_missing_waitid_fails_before_starting_a_child() {
        let source = lf_script(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable"),
        );
        let driver = hostile_filename_driver_slice(&source)
            .expect("the PTY driver's script should be sliceable")
            .strip_prefix("r#\"\n")
            .expect("the slice should start at the raw string");
        let encoded_driver =
            serde_json::to_string(driver).expect("the driver should encode as a JSON string");
        let wrapper = format!(
            "import os, sys\n\
             delattr(os, 'waitid')\n\
             delattr(os, 'WNOWAIT')\n\
             sys.argv = ['driver', '', '', '', '[]', 'default', '', 'true']\n\
             exec(compile({encoded_driver}, '<embedded-pty-driver>', 'exec'))\n"
        );
        let run = run_python_bounded(&wrapper, &[], Duration::from_secs(5));
        assert!(
            !run.timed_out && !run.success(),
            "missing waitid must fail promptly without entering the PTY: {}",
            run.failure_summary()
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stderr.contains("os.waitid and WNOWAIT; no PTY child was started"),
            "the actual driver should report its safe preflight failure: {}",
            run.failure_summary()
        );
    }

    #[test]
    #[cfg(unix)]
    fn pty_driver_requires_esrch_after_eperm() {
        let source = lf_script(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion source"),
        );
        let driver = hostile_filename_driver_slice(&source)
            .expect("driver slice")
            .strip_prefix("r#\"\n")
            .expect("raw string prefix");
        assert_eq!(driver.matches("os.killpg(group_id, 0)").count(), 1);
        let directory = tempfile::tempdir().expect("PTY test directory");
        std::fs::write(directory.path().join("present.bin"), b"").unwrap();
        let completion = directory.path().join("completion.bash");
        std::fs::write(&completion, generate("bash").unwrap()).unwrap();
        let expected = serde_json::to_string(&["set", "--bin", "payload=present.bin"]).unwrap();
        for persistent in [false, true] {
            let replacement = format!(
                "probe_count = 0\ndef probe_group(group):\n    global probe_count\n    probe_count += 1\n    if probe_count == 1 or {persistent}:\n        raise OSError(errno.EPERM, 'injected')\n    return os.killpg(group, 0)\n\ndef stop_child():",
                persistent = if persistent { "True" } else { "False" }
            );
            let injected = driver
                .replace("os.killpg(group_id, 0)", "probe_group(group_id)")
                .replace("def stop_child():", &replacement)
                .replace(
                    "os.set_blocking(fd, False)",
                    "os.set_blocking(fd, False)\nprint('PTY-TEST-PID', pid, flush=True)",
                );
            let _ = std::fs::remove_file(directory.path().join("args.bin"));
            let run = run_python_bounded(
                &injected,
                &[
                    directory.path().as_os_str(),
                    completion.as_os_str(),
                    OsStr::new("nkp set --bin payload=present"),
                    OsStr::new(&expected),
                    OsStr::new("default"),
                    OsStr::new(""),
                    OsStr::new("true"),
                ],
                Duration::from_secs(15),
            );
            assert!(!run.timed_out && !run.drain_overflow);
            assert_eq!(
                run.success(),
                !persistent,
                "EPERM must settle to ESRCH, not pass by itself: {}",
                run.failure_summary()
            );
            if persistent {
                let stderr = String::from_utf8_lossy(&run.stderr);
                assert!(stderr.contains("process group absence not established"));
                assert!(stderr.contains("group probe: errno-1:"));
            }
            let stdout = String::from_utf8_lossy(&run.stdout);
            let pid = stdout.split_whitespace().nth(1).expect("leader pid");
            let probe = std::process::Command::new("ps")
                .args(["-p", pid, "-o", "pid="])
                .output()
                .expect("ps should check for leaked leader");
            assert!(!probe.status.success() || probe.stdout.trim_ascii().is_empty());
        }
    }

    /// Exercise the actual driver with a simulated exit that cannot become
    /// waitable until the PTY master is closed. This is fault injection, not
    /// a claim that the Darwin kernel has that particular dependency.
    #[test]
    #[cfg(unix)]
    fn pty_driver_closes_master_before_waiting_for_exit() {
        let source = lf_script(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable"),
        );
        let driver = hostile_filename_driver_slice(&source)
            .expect("driver should be sliceable")
            .strip_prefix("r#\"\n")
            .expect("raw string prefix");
        let target = "waited, status = os.waitpid(pid, os.WNOHANG)";
        assert_eq!(driver.matches(target).count(), 1);
        let injected = driver.replace(
            target,
            "try:\n                os.fstat(fd)\n            except OSError as error:\n                if error.errno != errno.EBADF:\n                    raise\n                waited, status = os.waitpid(pid, os.WNOHANG)\n            else:\n                waited, status = (0, 0)",
        ).replace(
            "os.set_blocking(fd, False)",
            "os.set_blocking(fd, False)\nprint('PTY-TEST-PID', pid, flush=True)",
        );
        let directory = tempfile::tempdir().expect("PTY test directory");
        std::fs::write(directory.path().join("present.bin"), b"").unwrap();
        let completion = directory.path().join("completion.bash");
        std::fs::write(&completion, generate("bash").unwrap()).unwrap();
        let expected = serde_json::to_string(&["set", "--bin", "payload=present.bin"]).unwrap();
        let run = run_python_bounded(
            &injected,
            &[
                directory.path().as_os_str(),
                completion.as_os_str(),
                OsStr::new("nkp set --bin payload=present"),
                OsStr::new(&expected),
                OsStr::new("default"),
                OsStr::new(""),
                OsStr::new("true"),
            ],
            Duration::from_secs(15),
        );
        assert!(
            run.success() && !run.drain_overflow,
            "actual driver must close the master, reap the leader and observe group absence: {}",
            run.failure_summary()
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let pid = stdout
            .split_whitespace()
            .nth(1)
            .expect("driver must report its PTY leader");
        let probe = std::process::Command::new("ps")
            .args(["-p", pid, "-o", "pid="])
            .output()
            .expect("ps must check for a leaked leader");
        assert!(
            !probe.status.success() || probe.stdout.trim_ascii().is_empty(),
            "PTY leader {pid} remains after driver returned"
        );
        std::fs::remove_file(directory.path().join("args.bin")).unwrap();
        let failed_close = injected.replace(
            "        os.close(fd)\n        close_error = None",
            "        os.close(fd)\n        raise OSError(errno.EIO, 'injected close failure')\n        close_error = None",
        );
        assert_ne!(failed_close, injected, "close fault must be injected");
        let run = run_python_bounded(
            &failed_close,
            &[
                directory.path().as_os_str(),
                completion.as_os_str(),
                OsStr::new("nkp set --bin payload=present"),
                OsStr::new(&expected),
                OsStr::new("default"),
                OsStr::new(""),
                OsStr::new("true"),
            ],
            Duration::from_secs(15),
        );
        assert!(!run.success() && !run.timed_out && !run.drain_overflow);
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("PTY master close failed"),
            "close failure must not become a pass: {}",
            run.failure_summary()
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let pid = stdout.split_whitespace().nth(1).expect("leader pid");
        let probe = std::process::Command::new("ps")
            .args(["-p", pid, "-o", "pid="])
            .output()
            .expect("ps must check for a leaked leader");
        assert!(!probe.status.success() || probe.stdout.trim_ascii().is_empty());
    }

    /// Exercise the embedded driver end-to-end with a forced cleanup
    /// failure after it has safely reaped Bash and observed group absence.
    /// The primary argv assertion must remain first, the bounded diagnostic
    /// must be appended, and the driver must not leave a PTY child behind.
    #[test]
    #[cfg(unix)]
    fn pty_driver_cleanup_diagnostic_preserves_primary_and_leaves_no_child() {
        let source = lf_script(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable"),
        );
        let driver = hostile_filename_driver_slice(&source)
            .expect("the PTY driver's script should be sliceable")
            .strip_prefix("r#\"\n")
            .expect("the slice should start at the raw string");
        let old = "if error.errno == errno.ESRCH:\n                return close_error";
        assert_eq!(
            driver.matches(old).count(),
            1,
            "the test must inject only at confirmed group absence"
        );
        let forced = driver.replace(
            old,
            "if error.errno == errno.ESRCH:\n                return \"FORCED_CLEANUP_FAILURE \" + cleanup_diagnostics(wait_observation)",
        );
        let directory = tempfile::tempdir().expect("PTY test directory");
        std::fs::write(directory.path().join("present.bin"), b"fixture")
            .expect("fixture file should be created");
        let completion_path = directory.path().join("completion.bash");
        std::fs::write(&completion_path, generate("bash").expect("bash completion"))
            .expect("completion script should be written");
        let expected =
            serde_json::to_string(&["intentionally-wrong"]).expect("expected argv should encode");
        let line = "nkp set --bin payload=present";
        let run = run_python_bounded(
            &forced,
            &[
                directory.path().as_os_str(),
                completion_path.as_os_str(),
                OsStr::new(line),
                OsStr::new(&expected),
                OsStr::new("default"),
                OsStr::new(""),
                OsStr::new("true"),
            ],
            Duration::from_secs(15),
        );
        assert!(
            !run.timed_out && !run.drain_overflow && !run.success(),
            "forced cleanup failure should be bounded, fail, and leave no pipe holder: {}",
            run.failure_summary()
        );
        let stderr = String::from_utf8_lossy(&run.stderr);
        let primary = stderr
            .find("completion produced unexpected literal argv")
            .expect("primary behavior failure should be retained");
        let forced_failure = stderr
            .find("FORCED_CLEANUP_FAILURE")
            .expect("forced cleanup failure should be reported");
        assert!(
            primary < forced_failure,
            "cleanup must append, not mask, the primary failure"
        );
        for diagnostic in [
            "diagnostic[pty=",
            "waitid-before=",
            "process=",
            "wchan=",
            "master=",
        ] {
            assert!(
                stderr.contains(diagnostic),
                "cleanup failure should include `{diagnostic}`: {}",
                run.failure_summary()
            );
        }
        assert!(
            !stderr[forced_failure..].contains("PTY transcript:"),
            "the diagnostic snapshot must not duplicate the PTY transcript"
        );
        // Confirm group absence independently of the driver's own probe.
        // Its diagnostic reports the stable PTY leader PID at `pty=pid=`.
        let pid: i32 = stderr[forced_failure..]
            .split("pty=pid=")
            .nth(1)
            .and_then(|rest| rest.split(|ch: char| !ch.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .expect("diagnostic should report the PTY leader pid");
        let probe = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .output()
            .expect("ps should check for a leaked leader");
        assert!(
            !probe.status.success() || probe.stdout.trim_ascii().is_empty(),
            "the PTY leader {pid} must already be reaped: {:?}",
            String::from_utf8_lossy(&probe.stdout)
        );
    }

    fn fixture_vault_argument(pattern: &str, context: &str) -> Option<String> {
        assert_eq!(pattern, super::NUSHELL_VAULT_CONTEXT_REGEX);
        let remainder = context.strip_prefix("nkp ")?;
        let remainder = remainder
            .strip_prefix("--vault ")
            .or_else(|| remainder.strip_prefix("-V "))?;
        let (path, quote) = match remainder.chars().next()? {
            '"' => (&remainder[1..], '"'),
            '\'' => (&remainder[1..], '\''),
            _ => return remainder.split_whitespace().next().map(str::to_owned),
        };
        let end = path.find(quote)?;
        Some(path[..end].to_owned())
    }

    /// The `init` KDF flags and values every advertised shell must carry.
    ///
    /// Split out so the surface loop stays a statement of the shared contract
    /// rather than an inventory that grows a line per feature.
    fn assert_kdf_surface(shell: &str, script: &str) {
        for option in ["kdf", "memory", "iterations", "parallelism"] {
            let flag = if shell == "fish" {
                format!("-l {option}")
            } else {
                format!("--{option}")
            };
            assert!(script.contains(&flag), "{shell} omitted {flag}");
        }
        for value in ["aes", "argon2d", "argon2id"] {
            assert!(script.contains(value), "{shell} omitted kdf {value}");
        }
    }

    /// Every format the CLI accepts is a format completion offers.
    ///
    /// A value the tool renders but the shell will not offer is a feature nobody
    /// can reach, and the omission is invisible: the format still works when it
    /// is typed by hand. The whole list is matched rather than each value, so a
    /// value that merely appears elsewhere in the script -- `pwsh` is also a
    /// completion *shell* -- cannot stand in for a format value.
    /// The `config` group is the one surface whose key set is closed, so
    /// completion is where a user learns the vocabulary from, and a shell that
    /// offered a word outside the set would be advertising something the binary
    /// refuses. The names come from `CONFIG_KEYS` rather than a second literal,
    /// so the completion and the parser cannot drift apart.
    fn assert_config_surface(shell: &str, script: &str) {
        for key in CONFIG_KEYS {
            assert!(
                script.contains(key.name()),
                "{shell} does not complete the configuration key {}",
                key.name()
            );
        }
        let json_flag = if shell == "fish" { "-l json" } else { "--json" };
        assert!(
            script.contains(json_flag),
            "{shell} omitted the config ls --json flag"
        );
    }

    fn assert_format_surface(shell: &str, script: &str) {
        let formats = [
            "text",
            "json",
            "dotenv",
            "shell",
            "pwsh",
            "powershell",
            "github-actions",
            "azure-devops",
            "null",
        ];
        // `secrets env` has no `text`: there is no single value to print raw
        // when the caller asked for a named variable per binding.
        let bindings = [
            "dotenv",
            "shell",
            "pwsh",
            "powershell",
            "github-actions",
            "azure-devops",
            "json",
            "null",
        ];
        let render = |values: &[&str]| {
            if matches!(shell, "powershell" | "pwsh") {
                let quoted = values
                    .iter()
                    .map(|value| format!("'{value}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("@({quoted})")
            } else {
                values.join(" ")
            }
        };
        for list in [render(&formats), render(&bindings)] {
            assert!(script.contains(&list), "{shell} omitted {list}");
        }
        let is_output = if shell == "fish" {
            "-l is-output"
        } else {
            "--is-output"
        };
        assert!(script.contains(is_output), "{shell} omitted {is_output}");
    }

    #[test]
    fn every_advertised_shell_has_the_same_static_surface() {
        let shells = ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "nushell"];
        for shell in shells {
            let script = generate(shell).unwrap();
            for command in [
                "context",
                "alias",
                "config",
                "secrets",
                "automation",
                "attachment",
                "field",
                "env",
                "init",
                "search",
                "show",
                "otp",
                "setx",
                "import",
                "export",
                "sync",
                "exec",
                "completion",
            ] {
                assert!(script.contains(command), "{shell} omitted {command}");
            }
            let options: &[&str] = if shell == "fish" {
                &[
                    "-l key",
                    "-l field",
                    "-l name",
                    "-l file",
                    "-l output",
                    "-l password",
                    "-l password-env",
                    "-l password-file",
                    "-l password-stdin",
                    "-l key-file",
                    "-l stdin",
                    "-l yes",
                    "-l size",
                    "-l dry-run",
                    "-l replace",
                    "-l strategy",
                    "-l format",
                    "-l is-output",
                    "-l env",
                ]
            } else {
                &[
                    "--key",
                    "--field",
                    "--name",
                    "--file",
                    "--output",
                    "--password",
                    "--password-env",
                    "--password-file",
                    "--password-stdin",
                    "--key-file",
                    "--stdin",
                    "--yes",
                    "--size",
                    "--dry-run",
                    "--replace",
                    "--strategy",
                    "--format",
                    "--is-output",
                    "--env",
                ]
            };
            for option in options {
                assert!(script.contains(option), "{shell} omitted {option}");
            }
            assert_kdf_surface(shell, script);
            assert!(script.contains("__complete"));
            for value in ["newest", "source", "target"] {
                assert!(script.contains(value), "{shell} omitted sync value {value}");
            }
            assert_format_surface(shell, script);
            for kind in ["aliases", "vault-aliases", "keys", "vaults"] {
                assert!(script.contains(kind), "{shell} omitted {kind} metadata");
            }
            assert!(script.contains("metadata only and never secrets"));
            assert_config_surface(shell, script);
            for alias in [
                "list",
                "remove",
                "environment",
                "reveal",
                "edit",
                "import",
                "export",
            ] {
                assert!(script.contains(alias), "{shell} omitted alias {alias}");
            }
            for option in [
                "value",
                "value-env",
                "value-file",
                "value-stdin",
                "generate",
                "chars",
                "upper",
                "lower",
                "digits",
                "symbols",
            ] {
                let spelling = if shell == "fish" {
                    format!("-l {option}")
                } else {
                    format!("--{option}")
                };
                assert!(script.contains(&spelling), "{shell} omitted {option}");
            }
        }
        assert_eq!(generate("powershell").unwrap(), POWERSHELL);
        assert_eq!(generate("pwsh").unwrap(), POWERSHELL);
    }

    #[test]
    fn programmable_completions_forward_the_explicit_global_vault() {
        let bash = generate("bash").unwrap();
        assert!(bash.contains("vault_args=(--vault"));
        assert!(bash.contains("command nkp \"${vault_args[@]}\" __complete"));
        assert!(bash.contains("position -eq 1"));
        assert!(bash.contains("position -eq 3"));
        assert!(bash.contains("__complete vaults \"$current\""));
        assert!(bash.contains("compopt -o filenames -o nospace"));
        assert!(bash.contains("COMP_WORDS[scan - 1]"));

        let sh = generate("sh").unwrap();
        assert!(sh.contains("VAULT_OPTION VAULT_PATH"));
        assert!(sh.contains("nkp \"$_nk_vault_option\" \"$_nk_vault_path\" __complete"));
        assert!(sh.contains("\"${6-}\""));
        assert!(sh.contains("files:add|attachment:add|attachments:add"));

        let zsh = generate("zsh").unwrap();
        assert!(zsh.contains("vault_args=(--vault"));
        assert!(zsh.contains("command nkp \"${vault_args[@]}\" __complete"));
        assert!(zsh.contains("choices=('--key' '--field' '--username' '--url' '--notes'"));
        assert!(zsh.contains("command_index=2"));
        assert!(zsh.contains("position -eq 1"));
        assert!(zsh.contains("position -eq 3"));
        assert!(zsh.contains("__complete vaults \"$cur\""));

        let powershell = generate("powershell").unwrap();
        assert!(powershell.contains("$vaultArguments = @('--vault'"));
        assert!(
            powershell
                .contains("$values = @('--key', '--field', '--username', '--url', '--notes',")
        );
        assert!(!powershell.contains("'--field' '--username'"));
        assert!(powershell.contains("@('files', 'attachment', 'attachments')"));
        assert!(powershell.contains("& nkp @vaultArguments __complete"));
        assert!(powershell.contains("$cursorPosition -gt $commandAst.Extent.EndOffset"));
        assert!(powershell.contains("$currentIndex -le $commandIndex"));
        assert!(powershell.contains("$currentIndex -gt ($commandIndex + 1)"));
        assert!(powershell.contains("$commandIndex + 2"));
        assert!(powershell.contains("$commandIndex + 3"));

        let fish = generate("fish").unwrap();
        assert!(fish.contains("__nkp_complete_vault_args"));
        assert!(fish.contains("nkp (__nkp_complete_vault_args) __complete keys"));
        assert!(fish.contains("nkp (__nkp_complete_vault_args) __complete vaults"));

        let nushell = generate("nushell").unwrap();
        assert!(nushell.contains("nu-complete nkp vault-args"));
        assert!(nushell.contains("^nkp ...$args __complete keys"));
        assert!(nushell.contains("^nkp ...$args __complete vaults"));
        assert!(nushell.contains(&format!(
            "parse --regex r#'{}'#",
            super::NUSHELL_VAULT_CONTEXT_REGEX
        )));
        assert!(nushell.contains("[\"--vault\", $vault]"));

        for shell in ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "nushell"] {
            let script = generate(shell).unwrap();
            assert!(
                script.contains("--vault")
                    && (script.contains("__complete")
                        || script.contains("__nkp_complete_vault_args")),
                "{shell} has no vault-aware completion protocol"
            );
        }
    }

    /// Everything a failing interpreter run should report: the exit code
    /// (or signal), plus both captured streams. The silent Windows CI
    /// failures of the generated-script and boundary tests (run
    /// 134548307275) carried only a bare `exit N` with nothing on
    /// stderr, so the failure messages asserted below must surface the
    /// code and stdout too — an empty diagnostic cannot distinguish a
    /// real boundary regression from a wrong interpreter.
    fn subprocess_failure_detail(output: &std::process::Output) -> String {
        let exit = match output.status.code() {
            Some(code) => code.to_string(),
            None => "terminated-by-signal".to_owned(),
        };
        format!(
            "exit={} stdout={:?} stderr={:?}",
            exit,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    /// Run a shell script through stdin rather than `-c <script>`. Windows
    /// process argument quoting can reinterpret backticks in a long `-c`
    /// argument before Git Bash receives it; stdin preserves the script bytes.
    fn run_shell_script(
        program: &str,
        script: &str,
        path: Option<&std::ffi::OsStr>,
    ) -> std::io::Result<std::process::Output> {
        use std::io::Write;

        let mut child = std::process::Command::new(program)
            .arg("-s")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .envs(path.map(|path| [("PATH", path)]).into_iter().flatten())
            .spawn()?;
        child
            .stdin
            .take()
            .expect("shell stdin is piped")
            .write_all(script.as_bytes())?;
        child.wait_with_output()
    }

    /// The interpreter identity for failure diagnostics: how the
    /// program under test identifies itself, reported by that program.
    /// Callers pass either an ambient PATH-resolved shell name or an
    /// explicit NEO_KEEPASS_COMPLETION_BASH override path (the macOS
    /// canary passes `/bin/bash`), so a failure names exactly which
    /// program answered. On the Windows runner a bare PATH lookup can
    /// resolve differently from GitHub's own `shell: bash` selection
    /// (that one prefers Git for Windows' bash over the WSL launcher
    /// stub in System32) — which is why this self-report is part of
    /// every generated-script assertion message.
    fn shell_interpreter_identity(shell: &str) -> String {
        let report = std::process::Command::new(shell).arg("--version").output();
        let version = match report {
            Ok(output) => format!(
                "`{}` --version -> {}",
                output.status.code().map_or_else(
                    || "terminated-by-signal".to_owned(),
                    |code| code.to_string()
                ),
                String::from_utf8_lossy(&output.stdout).trim_end()
            ),
            Err(error) => format!("`{shell}` did not start ({error})"),
        };
        let location = std::process::Command::new(shell)
            .arg("-c")
            .arg(format!("command -v {shell}"))
            .output();
        let resolved = match location {
            Ok(output) if output.status.success() => {
                format!(
                    "resolved: {}",
                    String::from_utf8_lossy(&output.stdout).trim()
                )
            }
            _ => "resolution unknown".to_owned(),
        };
        format!("{version}; {resolved}")
    }

    #[test]
    fn generated_bash_and_posix_scripts_parse_and_posix_files_group_completes() {
        let directory = tempfile::tempdir().unwrap();
        for (shell, args) in [("bash", vec!["-n"]), ("sh", vec!["-n"])] {
            // The bash half honors NEO_KEEPASS_COMPLETION_BASH — the macOS
            // leg pins the native /bin/bash (3.2.57) so CI keeps
            // exercising the generated script against the legacy bash
            // its PATH no longer resolves, and the Windows leg pins the
            // validated Git for Windows bash (a bare `bash` there is
            // always the WSL stub in System32) — while the POSIX half
            // stays on the ambient sh on unix (macOS /bin/sh already is
            // the legacy bash in sh mode) and resolves sh.exe from the
            // same Git for Windows installation on Windows, where no
            // `sh` is on PATH at all.
            let program = if shell == "bash" {
                completion_bash_program()
            } else {
                completion_posix_program()
            };
            let path = directory.path().join(format!("completion.{shell}"));
            std::fs::write(&path, generate(shell).unwrap()).unwrap();
            let output = std::process::Command::new(&program)
                .args(args)
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{shell} syntax check of the generated completion failed: {} [interpreter: {}]",
                subprocess_failure_detail(&output),
                shell_interpreter_identity(&program),
            );
        }

        let path = directory.path().join("completion.sh");
        std::fs::write(&path, generate("sh").unwrap()).unwrap();
        let posix = completion_posix_program();
        let output = std::process::Command::new(&posix)
            .arg("-c")
            .arg(". ./completion.sh; nkp_complete '' '' files; nkp_complete '' '' files add")
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "POSIX sh helper run of the generated completion failed: {} [interpreter: {}]",
            subprocess_failure_detail(&output),
            shell_interpreter_identity(&posix),
        );
        let completions = String::from_utf8_lossy(&output.stdout);
        assert!(
            completions.lines().any(|line| line == "ls"),
            "files completion lost the `ls` group [stdout: {:?}][interpreter: {}]",
            completions,
            shell_interpreter_identity(&posix),
        );
        assert!(
            completions.lines().any(|line| line == "--file"),
            "files-add completion lost `--file` [stdout: {:?}][interpreter: {}]",
            completions,
            shell_interpreter_identity(&posix),
        );
    }

    #[test]
    fn generated_zsh_and_powershell_scripts_parse_when_interpreters_are_installed() {
        let directory = tempfile::tempdir().unwrap();
        let require_interpreters =
            crate::app_env_var_os("NEO_KEEPASS_REQUIRE_COMPLETION_SHELLS").is_some();
        let zsh_available = std::process::Command::new("zsh")
            .arg("--version")
            .output()
            .is_ok();
        if !zsh_available {
            eprintln!("SKIP: zsh completion syntax test; zsh is not installed");
            assert!(
                !require_interpreters,
                "required zsh interpreter is unavailable"
            );
        }
        for (shell, script, arguments) in [("zsh", generate("zsh").unwrap(), vec!["-n"])] {
            if zsh_available {
                let path = directory.path().join("completion.zsh");
                std::fs::write(&path, script).unwrap();
                let output = std::process::Command::new(shell)
                    .args(arguments)
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{shell} syntax failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let shell = ["pwsh", "powershell"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("-NoProfile")
                .arg("-Command")
                .arg("exit 0")
                .status()
                .is_ok()
        });
        if shell.is_none() {
            eprintln!("SKIP: PowerShell completion syntax test; pwsh is not installed");
            assert!(
                !require_interpreters,
                "required PowerShell interpreter is unavailable"
            );
        }
        if let Some(shell) = shell {
            let path = directory.path().join("completion.ps1");
            std::fs::write(&path, generate("powershell").unwrap()).unwrap();
            let output = std::process::Command::new(shell)
                .args(["-NoProfile", "-Command"])
                .arg(format!(
                    "$source = [IO.File]::ReadAllText('{}'); [void][scriptblock]::Create($source)",
                    path.display()
                ))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "PowerShell syntax failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Major version of the ambient `shell`, parsed from its own
    /// `--version` first line (`GNU bash, version 5.3.20(1)-release`).
    /// `None` when the probe cannot run or parse — callers treat that
    /// as "run anyway and let the driver report the evidence", never
    /// as a skip.
    #[cfg(unix)]
    fn ambient_shell_major(shell: &str) -> Option<u32> {
        let output = std::process::Command::new(shell)
            .arg("--version")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()?
            .to_owned();
        let version = first_line.split("version ").nth(1)?.trim().to_owned();
        version.split('.').next()?.parse().ok()
    }

    /// Whether the environment demands a bash the readline matrix can
    /// actually exercise. `NEO_KEEPASS_REQUIRE_COMPLETION_BASH` is the
    /// dedicated knob, so a leg can demand this one capability without
    /// also demanding the unrelated zsh and PowerShell interpreters
    /// that `NEO_KEEPASS_REQUIRE_COMPLETION_SHELLS` covers; the older
    /// flag still counts, because a leg demanding every completion
    /// shell demands this one too.
    fn completion_requirement_requested() -> bool {
        crate::app_env_var_os("NEO_KEEPASS_REQUIRE_COMPLETION_BASH").is_some()
            || crate::app_env_var_os("NEO_KEEPASS_REQUIRE_COMPLETION_SHELLS").is_some()
    }

    /// How long a `--version` probe may run before it is killed and
    /// reaped. Probes are millisecond-scale; the bound exists so a probe
    /// that blocks — an interpreter that prompts, or the WSL launcher
    /// waiting on something unexpected — cannot hang resolution.
    /// Generous for a cold CI runner.
    const SHELL_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    /// Drain allowance for a killed probe's captured streams.
    const SHELL_PROBE_DRAIN_ALLOWANCE: Duration = Duration::from_secs(2);

    /// How many bytes of probe output are captured before reading
    /// stops. A hostile or broken interpreter that prints forever is
    /// bounded instead of ballooning memory until the kill lands.
    const SHELL_PROBE_CAPTURE_LIMIT: usize = 64 * 1024;

    /// Unix probe-group sentinel. It is the process-group leader and stays
    /// alive and unreaped until cleanup, so its numeric PGID cannot be
    /// recycled between reaping the probed parent and the group signal.
    #[cfg(unix)]
    struct ProbeGroup {
        sentinel: Option<std::process::Child>,
        sentinel_stdin: Option<std::process::ChildStdin>,
        pgid: i32,
    }

    #[cfg(unix)]
    impl ProbeGroup {
        /// Start a Python sentinel as a new process-group leader. It
        /// remains alive until told to terminate the whole group itself,
        /// so it can provide a safe fallback if the external group-kill
        /// helper fails or times out.
        fn start() -> Result<Self, String> {
            use std::os::unix::process::CommandExt;
            let mut sentinel_command = std::process::Command::new("python3");
            sentinel_command
                .args([
                    "-c",
                    concat!(
                        "import os, signal, sys\n",
                        "command = sys.stdin.readline().strip()\n",
                        "if command == 'terminate':\n",
                        "    os.killpg(os.getpgrp(), signal.SIGKILL)\n",
                    ),
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .process_group(0);
            let mut sentinel = sentinel_command
                .spawn()
                .map_err(|error| format!("cannot start process-group sentinel: {error}"))?;
            let Ok(pgid) = i32::try_from(sentinel.id()) else {
                let _ = sentinel.kill();
                let _ = sentinel.wait();
                return Err("process-group sentinel returned an invalid group id".to_owned());
            };
            let Some(sentinel_stdin) = sentinel.stdin.take() else {
                let _ = sentinel.kill();
                let _ = sentinel.wait();
                return Err("process-group sentinel stdin was not piped".to_owned());
            };
            Ok(Self {
                sentinel: Some(sentinel),
                sentinel_stdin: Some(sentinel_stdin),
                pgid,
            })
        }

        /// Kill the owned process group while its sentinel is still a
        /// live, unreaped child; then reap the sentinel. If it exited
        /// unexpectedly, do not signal its possibly recycled PGID.
        fn terminate(&mut self) -> bool {
            self.terminate_with_helper_failure(false)
        }

        /// Testable variant for the failure path: when forced, skip the
        /// external group-kill helper and exercise the sentinel's
        /// self-termination fallback.
        fn terminate_with_helper_failure(&mut self, force_failure: bool) -> bool {
            let Some(sentinel) = self.sentinel.as_mut() else {
                return true;
            };
            match sentinel.try_wait() {
                Ok(None) => {
                    use std::os::unix::process::ExitStatusExt;
                    let pgid = self.pgid.to_string();
                    let helper_succeeded = !force_failure
                        && run_python_helper_bounded(
                            "import os, signal, sys; os.killpg(int(sys.argv[1]), signal.SIGKILL)",
                            &[&pgid],
                            PYTHON_HELPER_DEADLINE,
                        )
                        .success();
                    let mut fallback_write_succeeded = false;
                    if !helper_succeeded {
                        // Never release the sentinel after helper failure
                        // without first asking the sentinel itself to kill
                        // its own group. This does not use a parent-held
                        // numeric PGID, and the sentinel remains unreaped
                        // throughout the fallback.
                        if let Some(mut input) = self.sentinel_stdin.take() {
                            fallback_write_succeeded =
                                std::io::Write::write_all(&mut input, b"terminate\n")
                                    .and_then(|()| std::io::Write::flush(&mut input))
                                    .is_ok();
                        }
                    }
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    loop {
                        match sentinel.try_wait() {
                            Ok(Some(status)) => {
                                // A successful stdin write alone proves
                                // only that bytes entered the pipe. Count
                                // the fallback as successful only if the
                                // sentinel actually died from the
                                // SIGKILL it sends to its own group.
                                let fallback_succeeded =
                                    fallback_write_succeeded && status.signal() == Some(9);
                                self.sentinel = None;
                                self.sentinel_stdin = None;
                                return helper_succeeded || fallback_succeeded;
                            }
                            Ok(None) if std::time::Instant::now() < deadline => {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }
                    // The group helper and the sentinel fallback both
                    // failed. Directly kill only the still-owned,
                    // unreaped sentinel; never issue another group signal
                    // after it is reaped. Return failure, since same-group
                    // descendants may remain.
                    let _ = sentinel.kill();
                    let _ = sentinel.wait();
                    self.sentinel = None;
                    false
                }
                Ok(Some(_)) | Err(_) => {
                    // It is no longer safe to signal this numeric group
                    // id: the sentinel's group may already have vanished.
                    let _ = sentinel.wait();
                    self.sentinel = None;
                    self.sentinel_stdin = None;
                    false
                }
            }
        }
    }

    #[cfg(unix)]
    impl Drop for ProbeGroup {
        fn drop(&mut self) {
            let _ = self.terminate();
        }
    }

    /// A direct child fixture which is always terminated and reaped,
    /// including if an assertion unwinds early.
    #[cfg(unix)]
    struct ProbeChildGuard(std::process::Child);

    #[cfg(unix)]
    impl Drop for ProbeChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Decode a captured probe stream into text. Interpreters on
    /// Windows can emit UTF-16 — the WSL launcher stub reports "no
    /// installed distributions" as UTF-16, which lossy UTF-8 decoding
    /// renders as interleaved NULs — so a UTF-16 BOM, or a NUL-dominated
    /// even-length stream without one, is transcoded; everything else
    /// falls back to lossy UTF-8 so no byte is silently dropped.
    fn decode_console_output(bytes: &[u8]) -> String {
        if bytes.len() < 4 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let decode_utf16 = |units: &[u16]| -> String {
            let mut text = String::new();
            let mut index = 0;
            while index < units.len() {
                let unit = units[index];
                let decoded = if (0xD800..0xDC00).contains(&unit) {
                    if index + 1 < units.len() && (0xDC00..0xE000).contains(&units[index + 1]) {
                        let combined = 0x1_0000
                            + ((u32::from(unit) - 0xD800) << 10)
                            + (u32::from(units[index + 1]) - 0xDC00);
                        index += 1;
                        char::from_u32(combined)
                    } else {
                        None
                    }
                } else if (0xDC00..0xE000).contains(&unit) {
                    None
                } else {
                    char::from_u32(u32::from(unit))
                };
                text.push(decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
                index += 1;
            }
            text
        };
        let units_of = |bytes: &[u8], little_endian: bool| -> Vec<u16> {
            bytes
                .chunks_exact(2)
                .map(|pair| {
                    if little_endian {
                        u16::from_le_bytes([pair[0], pair[1]])
                    } else {
                        u16::from_be_bytes([pair[0], pair[1]])
                    }
                })
                .collect()
        };
        if bytes.starts_with(&[0xFF, 0xFE]) {
            return decode_utf16(&units_of(&bytes[2..], true));
        }
        if bytes.starts_with(&[0xFE, 0xFF]) {
            return decode_utf16(&units_of(&bytes[2..], false));
        }
        let head = &bytes[..bytes.len().min(64)];
        if bytes.len() % 2 == 0 && head.iter().filter(|byte| **byte == 0).count() * 2 >= head.len()
        {
            // No BOM but NUL-dominated: Windows console UTF-16LE. The
            // even-length chunks_exact split silently drops an odd
            // trailing byte, if any; nothing else to recover from a
            // heuristic decode.
            return decode_utf16(&units_of(bytes, true));
        }
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// First non-decoded line of a probe stream, for compact details.
    fn first_probe_line(text: &str) -> &str {
        text.lines().next().unwrap_or_default()
    }

    /// Probe whether `program` is a usable shell: a `--version` spawn
    /// that exits 0 with output, and — when `required_output` is set —
    /// stdout that contains it. `None` means usable; `Some` carries the
    /// detail of what actually happened, for the fail-closed diagnostic.
    /// The probe is BOUNDED: a spawn that never exits is killed, reaped
    /// (so the fake cannot linger as a zombie), and reported as
    /// "did not exit within", never as a script failure; captured
    /// output is capped, includes stderr alongside stdout, and is
    /// decoded so the WSL launcher stub's UTF-16 "no installed
    /// distributions" reads as text (see
    /// [`completion_bash_program`]). A missing interpreter is never
    /// mislabeled as a script or boundary failure.
    fn shell_probe_failure(program: &str, required_output: Option<&str>) -> Option<String> {
        shell_probe_failure_with_timeout(program, required_output, SHELL_PROBE_TIMEOUT)
    }

    /// Capture one probe stream on a thread, stopping at the capture
    /// limit and sending whatever was gathered — EOF after the kill
    /// ends the read; a child still writing past the limit blocks on the
    /// full pipe until the kill resolves it.
    fn spawn_probe_capturer<R: std::io::Read + Send + 'static>(
        mut pipe: R,
        sender: std::sync::mpsc::Sender<Vec<u8>>,
    ) {
        std::thread::spawn(move || {
            let mut captured = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                if captured.len() >= SHELL_PROBE_CAPTURE_LIMIT {
                    break;
                }
                match std::io::Read::read(&mut pipe, &mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => captured.extend_from_slice(&buffer[..read]),
                }
            }
            let _ = sender.send(captured);
        });
    }

    /// [`shell_probe_failure`] with an explicit bound, so tests can
    /// exercise the kill-and-reap path in milliseconds instead of
    /// waiting out the production timeout.
    fn shell_probe_failure_with_timeout(
        program: &str,
        required_output: Option<&str>,
        timeout: Duration,
    ) -> Option<String> {
        let mut command = std::process::Command::new(program);
        command
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        let mut probe_group = {
            use std::os::unix::process::CommandExt;
            let group = match ProbeGroup::start() {
                Ok(group) => group,
                Err(error) => {
                    return Some(format!(
                        "cannot establish an owned Unix process group for `{program}`: {error}"
                    ));
                }
            };
            command.process_group(group.pgid);
            group
        };
        let mut child = {
            let mut attempts = 0;
            loop {
                match command.spawn() {
                    Ok(child) => break child,
                    Err(error)
                        if cfg!(unix) && error.raw_os_error() == Some(26) && attempts < 10 =>
                    {
                        // Some filesystems can briefly report ETXTBSY
                        // immediately after a test creates an executable
                        // script. Retry only that transient error, with a
                        // strict small bound; all other spawn failures are
                        // reported unchanged.
                        attempts += 1;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        return Some(format!("`{program}` did not start ({error})"));
                    }
                }
            }
        };
        let stdout_pipe = child.stdout.take().expect("probe stdout is piped");
        let stderr_pipe = child.stderr.take().expect("probe stderr is piped");
        let (stdout_sender, stdout_receiver) = std::sync::mpsc::channel();
        let (stderr_sender, stderr_receiver) = std::sync::mpsc::channel();
        // Readers stop at the capture limit: if the child keeps writing
        // past it, the pipe fills and the child blocks — which the kill
        // below resolves. EOF after the kill ends a reader that is still
        // waiting, and the channel carries whatever was captured.
        spawn_probe_capturer(stdout_pipe, stdout_sender);
        spawn_probe_capturer(stderr_pipe, stderr_sender);
        let started = std::time::Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() >= timeout => {
                    timed_out = true;
                    #[cfg(unix)]
                    let _ = probe_group.terminate();
                    let _ = child.kill();
                    break child
                        .wait()
                        .expect("probe child should reap after the kill");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break child.wait().expect("probe child should reap"),
            }
        };
        // A successful parent exit does not imply its descendants closed
        // the inherited pipes. Drain both streams against one deadline;
        // if either remains open, terminate the owned Unix process group
        // (whose id remains reserved while descendants are members), then
        // give both readers a final bounded chance to reach EOF.
        let drain_deadline = std::time::Instant::now() + timeout.min(SHELL_PROBE_DRAIN_ALLOWANCE);
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;
        while std::time::Instant::now() < drain_deadline
            && (stdout_bytes.is_none() || stderr_bytes.is_none())
        {
            if stdout_bytes.is_none() {
                stdout_bytes = stdout_receiver.try_recv().ok();
            }
            if stderr_bytes.is_none() {
                stderr_bytes = stderr_receiver.try_recv().ok();
            }
            if stdout_bytes.is_none() || stderr_bytes.is_none() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let drain_timed_out = stdout_bytes.is_none() || stderr_bytes.is_none();
        #[cfg(unix)]
        let group_killed = if drain_timed_out {
            probe_group.terminate()
        } else {
            false
        };
        if drain_timed_out {
            // On Windows std::process::Child has no process-tree kill
            // primitive here. The direct child is already reaped; do not
            // claim descendant containment. Fail closed below, while
            // returning within the drain bound. A reader thread may remain
            // blocked if a descendant holds its pipe; see docs/ci-cd.md.
            let final_deadline = std::time::Instant::now() + SHELL_PROBE_DRAIN_ALLOWANCE;
            while std::time::Instant::now() < final_deadline
                && (stdout_bytes.is_none() || stderr_bytes.is_none())
            {
                if stdout_bytes.is_none() {
                    stdout_bytes = stdout_receiver.try_recv().ok();
                }
                if stderr_bytes.is_none() {
                    stderr_bytes = stderr_receiver.try_recv().ok();
                }
                if stdout_bytes.is_none() || stderr_bytes.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        let stdout = decode_console_output(&stdout_bytes.unwrap_or_default());
        let stderr = decode_console_output(&stderr_bytes.unwrap_or_default());
        if drain_timed_out {
            #[cfg(unix)]
            let cleanup_detail = if group_killed {
                "sentinel-owned Unix process group killed; stream cleanup bounded"
            } else {
                "owned Unix process-group cleanup failed; resolution failed closed"
            };
            #[cfg(not(unix))]
            let cleanup_detail =
                "process-tree containment unavailable on this platform; resolution failed closed";
            return Some(format!(
                "`{program}` --version exited {status:?}, but captured streams did not close \
                 within {:?}; {} [stdout: {:?}] [stderr: {:?}]",
                timeout.min(SHELL_PROBE_DRAIN_ALLOWANCE),
                cleanup_detail,
                first_probe_line(&stdout),
                first_probe_line(&stderr),
            ));
        }
        #[cfg(unix)]
        if !probe_group.terminate() {
            return Some(format!(
                "`{program}` --version completed, but owned Unix process-group cleanup failed"
            ));
        }
        if timed_out {
            return Some(format!(
                "`{program}` --version did not exit within {timeout:?}; killed and \
                 reaped [exit: {status:?}] [stdout: {:?}] [stderr: {:?}]",
                first_probe_line(&stdout),
                first_probe_line(&stderr),
            ));
        }
        if !status.success() {
            return Some(format!(
                "`{program}` --version exited {}: [stdout: {:?}] [stderr: {:?}]",
                status
                    .code()
                    .map_or_else(|| "by-signal".to_owned(), |code| code.to_string()),
                first_probe_line(&stdout),
                first_probe_line(&stderr),
            ));
        }
        if first_probe_line(&stdout).is_empty() {
            return Some(format!(
                "`{program}` --version exited 0 but printed nothing"
            ));
        }
        if let Some(required) = required_output
            && !stdout.contains(required)
        {
            return Some(format!(
                "`{program}` --version is not the required interpreter: {} \
                 [stderr: {:?}]",
                first_probe_line(&stdout),
                first_probe_line(&stderr),
            ));
        }
        None
    }

    /// Directories a Git for Windows installation may live in, most
    /// likely first: the system-wide Program Files locations (runner
    /// images and the per-machine installer), and the per-user install
    /// under `%LOCALAPPDATA%\Programs\Git` (the "current user only"
    /// installer's default). LOCALAPPDATA has no reconstructible
    /// fallback — the path is user-specific — so it is probed only when
    /// the environment provides it.
    #[cfg(windows)]
    fn git_for_windows_dirs() -> Vec<String> {
        let mut dirs = Vec::new();
        for key in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(value) = std::env::var(key) {
                if !value.trim().is_empty() {
                    dirs.push(format!("{value}\\Git"));
                }
            }
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                dirs.push(format!("{local}\\Programs\\Git"));
            }
        }
        for fallback in ["C:\\Program Files\\Git", "C:\\Program Files (x86)\\Git"] {
            if !dirs.iter().any(|dir| dir == fallback) {
                dirs.push(fallback.to_owned());
            }
        }
        dirs
    }

    /// The bash candidates [`completion_bash_program`] probes, in
    /// order. Unix: the ambient PATH `bash`. Windows: only the Git for
    /// Windows install locations — a bare `bash` on Windows always
    /// resolves to the WSL launcher stub in System32 (the
    /// `CreateProcess` search order checks System32 before any PATH
    /// entry, so no PATH arrangement can fix it), and it is never a
    /// candidate here: a missing WSL distro is an interpreter problem,
    /// not test behavior.
    #[cfg(not(windows))]
    fn completion_bash_candidates() -> Vec<String> {
        vec!["bash".to_owned()]
    }

    #[cfg(windows)]
    fn completion_bash_candidates() -> Vec<String> {
        let mut candidates = Vec::new();
        for dir in git_for_windows_dirs() {
            candidates.push(format!("{dir}\\bin\\bash.exe"));
            candidates.push(format!("{dir}\\usr\\bin\\bash.exe"));
        }
        candidates
    }

    /// The bash interpreter for the generated-script tests. The
    /// `NEO_KEEPASS_COMPLETION_BASH` value when set — the override wins
    /// unchanged, and a missing or non-executable override still fails
    /// the tests' own spawn loudly with the interpreter's identity in
    /// the message. Without an override the interpreter is resolved AND
    /// validated, never assumed: every candidate must pass the
    /// `--version` probe and identify as GNU bash, the first that does
    /// wins, and if none does the test panics fail-closed with each
    /// candidate's observed failure, stated as an
    /// interpreter-availability problem — never as a generated-script
    /// or completion-boundary failure. Resolution runs once per test
    /// binary and is cached.
    ///
    /// The macOS CI leg pins this to the native `/bin/bash` (3.2.57) as
    /// a canary: that leg's PATH otherwise resolves `bash` to
    /// Homebrew's 5.x, and without the pin nothing in CI would keep
    /// exercising the generated script against the legacy bash a stock
    /// macOS still ships. The interactive PTY matrix deliberately
    /// ignores this helper — that matrix pins `compopt` quoting 3.2
    /// cannot express and must keep testing whatever bash the ambient
    /// PATH provides.
    fn completion_bash_program() -> String {
        if let Some(program) = crate::app_env_var_os("NEO_KEEPASS_COMPLETION_BASH") {
            return program.to_string_lossy().into_owned();
        }
        static RESOLVED: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
        RESOLVED
            .get_or_init(|| {
                let mut failures = Vec::new();
                for candidate in completion_bash_candidates() {
                    match shell_probe_failure(&candidate, Some("GNU bash, version")) {
                        None => return Ok(candidate),
                        Some(failure) => failures.push(failure),
                    }
                }
                Err(format!(
                    "no bash interpreter for the generated-script tests — an \
                     interpreter-availability failure, not a generated-script or \
                     completion-boundary failure (candidates: {})",
                    failures.join("; ")
                ))
            })
            .clone()
            .unwrap_or_else(|diagnostic| panic!("{diagnostic}"))
    }

    /// The POSIX sh interpreter for the generated-script tests' sh
    /// half. The ambient `sh` on every unix leg is used exactly as
    /// before (macOS `/bin/sh` already is the legacy bash in sh mode,
    /// and probing dash's `--version` support is a behavior change unix
    /// legs do not need). Windows has no `sh` on PATH at all — Git for
    /// Windows keeps `sh.exe` in `usr\bin`, which installers do not add
    /// to PATH — so the candidates there come from the same Git for
    /// Windows locations [`completion_bash_program`] targets, probed
    /// for a usable spawn and failing closed with the same honest
    /// interpreter-availability diagnostic.
    fn completion_posix_program() -> String {
        #[cfg(windows)]
        {
            static RESOLVED: std::sync::OnceLock<Result<String, String>> =
                std::sync::OnceLock::new();
            RESOLVED
                .get_or_init(|| {
                    let mut candidates = Vec::new();
                    for dir in git_for_windows_dirs() {
                        candidates.push(format!("{dir}\\usr\\bin\\sh.exe"));
                    }
                    let mut failures = Vec::new();
                    for candidate in &candidates {
                        match shell_probe_failure(candidate, None) {
                            None => return Ok(candidate.clone()),
                            Some(failure) => failures.push(failure),
                        }
                    }
                    Err(format!(
                        "no POSIX sh interpreter for the generated-script tests — an \
                         interpreter-availability failure, not a generated-script or \
                         completion-boundary failure (candidates: {})",
                        failures.join("; ")
                    ))
                })
                .clone()
                .unwrap_or_else(|diagnostic| panic!("{diagnostic}"))
        }
        #[cfg(not(windows))]
        {
            "sh".to_owned()
        }
    }

    /// The interpreter-probe helpers are compiled on Windows too, even
    /// though PTY/process-group tests are Unix-only. Keep `Duration`
    /// available unconditionally in this test module: the Windows
    /// matrix previously found the missing import only at Check time.
    #[test]
    fn probe_duration_type_is_available_on_every_target() {
        let _probe_timeout = Duration::from_secs(1);
    }

    /// The probe must be bounded: an interpreter that never answers
    /// `--version` is killed, reaped, and reported — never hung on, and
    /// never misreported as a script failure. The fake reports its pid
    /// on stderr first, so the reap is verified externally: by the time
    /// the bounded probe returns, the pid is gone.
    #[test]
    #[cfg(unix)]
    fn shell_probe_bounds_a_hanging_interpreter_and_reaps_it() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("probe tempdir");
        let program = directory.path().join("hanging-interpreter");
        std::fs::write(&program, "#!/bin/sh\necho $$ >&2\nsleep 600\n")
            .expect("write hanging fake");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("fake executable");
        let started = std::time::Instant::now();
        let failure = shell_probe_failure_with_timeout(
            &program.to_string_lossy(),
            None,
            Duration::from_millis(300),
        )
        .expect("a hanging interpreter must fail the probe");
        assert!(
            failure.contains("did not exit within"),
            "the bound must be reported as a non-exit, not a script failure: {failure}"
        );
        assert!(
            failure.contains("killed and reaped"),
            "the kill must be part of the diagnostic: {failure}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the probe must finish within the bound plus drain, not hang: {:?}",
            started.elapsed()
        );
        // Reap verification: the fake printed its pid, and it must be
        // gone by the time the probe returned.
        let pid = failure
            .split("[stderr: \"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
            .and_then(|line| line.trim().parse::<u32>().ok())
            .unwrap_or_else(|| panic!("the fake's stderr should carry its pid: {failure}"));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!alive, "hanging fake {pid} SURVIVED the probe's kill+reap");
    }

    /// A successful probe parent is not enough: a descendant can inherit
    /// stdout/stderr, keep the drain threads blocked, and otherwise outlive
    /// the probe's bound. On Unix the probe owns a process group; when the
    /// bounded drain detects the inherited pipes, it kills that group and
    /// returns a fail-closed stream-cleanup diagnostic. The test verifies
    /// the descendant pid is gone when the probe returns.
    #[test]
    #[cfg(unix)]
    fn shell_probe_kills_descendant_holding_streams_after_parent_exit() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("probe tempdir");
        let program = directory.path().join("parent-exits-interpreter");
        let pid_file = directory.path().join("descendant.pid");
        let quoted_pid_file = format!("'{}'", pid_file.to_string_lossy().replace('\'', "'\\''"));
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nsleep 600 &\nprintf '%s\\n' \"$!\" > {quoted_pid_file}\nprintf 'GNU bash, version 9.9.9\\n'\nexit 0\n"
            ),
        )
        .expect("write parent-exits fake");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("fake executable");

        let started = std::time::Instant::now();
        let failure = shell_probe_failure_with_timeout(
            &program.to_string_lossy(),
            Some("GNU bash, version"),
            Duration::from_millis(300),
        )
        .expect("inherited streams must fail closed even when the parent exits 0");
        assert!(
            failure.contains("captured streams did not close"),
            "the failure must identify the bounded stream drain: {failure}"
        );
        assert!(
            failure.contains("sentinel-owned Unix process group killed"),
            "the Unix process-group cleanup must be explicit: {failure}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "probe drain must return within its bounded cleanup allowance: {:?}",
            started.elapsed()
        );

        let pid: u32 = std::fs::read_to_string(&pid_file)
            .expect("fake writes descendant pid before exiting")
            .trim()
            .parse()
            .expect("descendant pid is numeric");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !alive,
            "stream-holding descendant {pid} SURVIVED the owned-group cleanup"
        );
    }

    /// If the external group-kill helper fails, the sentinel must remain
    /// owned and unreaped while its in-group self-termination fallback
    /// runs. The forced-failure hook exercises that path; the direct
    /// sleeper joined to the group must be gone before cleanup reports
    /// success.
    #[test]
    #[cfg(unix)]
    fn probe_group_falls_back_safely_when_kill_helper_fails() {
        use std::os::unix::process::CommandExt;

        let mut group = ProbeGroup::start().expect("start owned probe group");
        let child = std::process::Command::new("sleep")
            .arg("600")
            .process_group(group.pgid)
            .spawn()
            .expect("same-group child should start");
        let mut child = ProbeChildGuard(child);

        assert!(
            group.terminate_with_helper_failure(true),
            "the sentinel self-kill fallback should clean the group"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut reaped = false;
        while std::time::Instant::now() < deadline {
            if child
                .0
                .try_wait()
                .expect("child status should be readable")
                .is_some()
            {
                reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            reaped,
            "same-group child remained after the helper-failure fallback"
        );
    }

    /// If the sentinel exits cleanly before reading the fallback command,
    /// neither successful stdin buffering nor that arbitrary exit may be
    /// mistaken for group cleanup. The same-group child must remain
    /// untouched, cleanup must report failure without signaling the PGID
    /// after the sentinel was reaped, and the test's directly-owned child
    /// guard cleans its fixture safely.
    #[test]
    #[cfg(unix)]
    fn probe_group_reports_failure_if_sentinel_exits_before_fallback() {
        use std::os::unix::process::CommandExt;

        let mut group = ProbeGroup::start().expect("start owned probe group");
        let child = std::process::Command::new("sleep")
            .arg("600")
            .process_group(group.pgid)
            .spawn()
            .expect("same-group child should start");
        let mut child = ProbeChildGuard(child);

        // EOF on the sentinel's input makes its readline return empty, so
        // it exits 0 without trying to kill the group.
        drop(group.sentinel_stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut sentinel_exited = false;
        while std::time::Instant::now() < deadline {
            if group
                .sentinel
                .as_mut()
                .expect("sentinel still owned")
                .try_wait()
                .expect("sentinel status should be readable")
                .is_some()
            {
                sentinel_exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(sentinel_exited, "sentinel should exit on stdin EOF");
        assert!(
            !group.terminate_with_helper_failure(true),
            "an unrelated sentinel exit must not claim process-group cleanup"
        );
        assert!(
            child
                .0
                .try_wait()
                .expect("same-group child status should be readable")
                .is_none(),
            "a same-group child must remain when the sentinel never accepted fallback"
        );
        // Explicitly terminate/reap only the directly-owned child. The
        // sentinel has exited, so no numeric process-group signal is safe.
        let _ = child.0.kill();
        let _ = child.0.wait();
    }

    /// A descendant can call setsid and escape the probe's group. The
    /// sentinel prevents the old PGID from being recycled while cleanup
    /// signals the owned group, but cannot contain this escapee. Verify
    /// bounded fail-closed return, that the detached child remains alive
    /// until its fixture's own short timer expires, and that an unrelated
    /// bystander is not signaled. The fixture cleans itself naturally;
    /// only the directly owned bystander child is explicitly killed.
    #[test]
    #[cfg(unix)]
    fn shell_probe_does_not_signal_recycled_group_for_detached_descendant() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("probe tempdir");
        let program = directory.path().join("detaching-interpreter");
        let pid_file = directory.path().join("detached.pid");
        let python_code = format!(
            "import os,time; os.setsid(); open({}, \"w\").write(str(os.getpid())); time.sleep(4)",
            serde_json::to_string(&pid_file.to_string_lossy().as_ref())
                .expect("pid path is JSON-serializable")
        );
        let quoted_python_code = format!("'{}'", python_code.replace('\'', "'\\''"));
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\npython3 -c {quoted_python_code} &\nprintf 'GNU bash, version 9.9.9\\n'\nexit 0\n"
            ),
        )
        .expect("write detaching fake");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("fake executable");

        let bystander = ProbeChildGuard(
            std::process::Command::new("sleep")
                .arg("4")
                .spawn()
                .expect("bystander should start"),
        );
        let started = std::time::Instant::now();
        let failure = shell_probe_failure_with_timeout(
            &program.to_string_lossy(),
            Some("GNU bash, version"),
            Duration::from_millis(300),
        )
        .expect("detached inherited streams must fail closed");
        assert!(
            failure.contains("captured streams did not close"),
            "the detached stream must be diagnosed: {failure}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "detached pipe must not make the probe unbounded: {:?}",
            started.elapsed()
        );

        let pid: u32 = std::fs::read_to_string(&pid_file)
            .expect("detached fake writes its pid")
            .trim()
            .parse()
            .expect("detached pid is numeric");
        let detached_probe = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("ps should run");
        assert!(
            detached_probe.success(),
            "the documented escaped descendant should survive group cleanup"
        );
        let bystander_probe = std::process::Command::new("ps")
            .args(["-p", &bystander.0.id().to_string(), "-o", "pid="])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("ps should run");
        assert!(
            bystander_probe.success(),
            "the unrelated bystander must not be signaled by probe cleanup"
        );
        // The escaped fixture has its own four-second lifetime. Wait it
        // out. ProbeChildGuard kills and reaps the directly-owned
        // bystander on normal return and on every assertion unwind.
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let mut detached_alive = true;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                detached_alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !detached_alive,
            "detached fixture {pid} did not exit on its own"
        );
    }

    /// The WSL launcher stub reports "no installed distributions" as
    /// UTF-16, which lossy UTF-8 decoding renders as interleaved NULs;
    /// the probe's failure detail must decode it so the diagnostic
    /// names the actual problem. The fake emits the BOM'd UTF-16LE
    /// message and exits 1 — the stub's shape — and the decode helper
    /// is additionally driven directly for the BOM-less heuristic, the
    /// big-endian BOM, and lossy garbage.
    #[test]
    #[cfg(unix)]
    fn shell_probe_decodes_utf16_output() {
        use std::os::unix::fs::PermissionsExt;

        let message = "no installed distributions";
        let utf16le = |text: &str| -> Vec<u8> {
            let mut bytes = vec![0xFF, 0xFE];
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        };
        let octal =
            |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("\\{byte:03o}")).collect() };
        let directory = tempfile::tempdir().expect("probe tempdir");
        let program = directory.path().join("utf16-stub");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%b' '{}' >&2\nexit 1\n",
                octal(&utf16le(message))
            ),
        )
        .expect("write utf16 stub");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("stub executable");
        let failure =
            shell_probe_failure_with_timeout(&program.to_string_lossy(), None, SHELL_PROBE_TIMEOUT)
                .expect("an exiting-1 stub must fail the probe");
        assert!(
            failure.contains(message),
            "the UTF-16 stderr must decode into the diagnostic: {failure}"
        );
        assert!(
            !failure.contains('\u{0}'),
            "interleaved NULs must not reach the diagnostic: {failure}"
        );

        // Decode helper, driven directly: BOM'd LE, BOM-less
        // NUL-dominated LE, big-endian BOM, and lossy garbage never
        // panic and never drop the message.
        let bytes = utf16le(message);
        assert_eq!(decode_console_output(&bytes), message);
        assert_eq!(decode_console_output(&bytes[2..]), message);
        let mut big_endian = vec![0xFE, 0xFF];
        for unit in message.encode_utf16() {
            big_endian.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(decode_console_output(&big_endian), message);
        assert_eq!(decode_console_output(&[0xFF, 0x41]), "\u{FFFD}A");
    }

    #[test]
    #[cfg(unix)]
    fn bash_binary_completion_uses_readline_quoting_for_hostile_filenames() {
        // The readline quoting contract this matrix pins — candidates
        // inserted verbatim because the script asks readline for
        // `compopt -o noquote -o nospace` — is only expressible from
        // bash 4.0 on (compopt is new in 4.0 per bash-4.0's NEWS).
        // macOS still ships bash 3.2.57 as /bin/bash, which predates
        // it: proven against a readline-enabled bash 3.2.57 build, the
        // completion registers and produces the right whole-assignment
        // candidate, but readline 5.2 then re-quotes it and inserts it
        // into the post-`=` word slot (`payload\=space\\ name.bin`),
        // so no candidate can round trip — identically before and
        // after the mapfile change, which is a dynamic-path fix, not a
        // quoting fix. Parse and boundary compatibility with the
        // legacy bash is a separate regression-guard concern, pinned
        // where it belongs: the macOS leg runs the generated-script
        // parse and boundary tests against the native /bin/bash
        // through NEO_KEEPASS_COMPLETION_BASH, and the dynamic-path
        // accumulator test below drives the while-read loops there
        // too. This interactive matrix alone needs the ambient bash to
        // honor compopt, which every CI leg's PATH provides.
        let ambient_major = ambient_shell_major("bash");
        if ambient_major.is_some_and(|major| major < 4) {
            // The notice below is quiet, not loud: libtest captures a
            // passing test's output and only replays it on failure or
            // with --nocapture. That is exactly why a leg that must run
            // this matrix also sets NEO_KEEPASS_REQUIRE_COMPLETION_BASH —
            // the assertion then fails, and libtest replays the notice.
            eprintln!(
                "SKIP: hostile-filename readline matrix; ambient bash {} predates \
                 compopt (bash 4.0+) and re-quotes candidates itself",
                ambient_major.map_or_else(|| "?".to_owned(), |major| major.to_string())
            );
            assert!(
                !completion_requirement_requested(),
                "required completion bash (>= 4, for compopt noquote/nospace) is unavailable"
            );
            return;
        }
        let bash = generate("bash").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("injected");
        let cases = [
            (
                "nkp set --bin payload=space",
                vec!["set", "--bin", "payload=space name.bin"],
                "space name.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin payload=danger-",
                vec!["set", "--bin", "payload=danger-$(touch injected).bin"],
                "danger-$(touch injected).bin",
                "default",
                "",
                true,
            ),
            (
                "nkp --password-env TEST set -b payload=ticks",
                vec![
                    "--password-env",
                    "TEST",
                    "set",
                    "-b",
                    "payload=ticks-`touch injected`.bin",
                ],
                "ticks-`touch injected`.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --password-file ./credential --bin payload=space",
                vec![
                    "set",
                    "--password-file",
                    "./credential",
                    "--bin",
                    "payload=space name.bin",
                ],
                "space name.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set -F Password --bin payload=apostrophe",
                vec![
                    "set",
                    "-F",
                    "Password",
                    "--bin",
                    "payload=apostrophe-'single'.bin",
                ],
                "apostrophe-'single'.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin first=old --bin payload=semi-",
                vec![
                    "set",
                    "--bin",
                    "first=old",
                    "--bin",
                    "payload=semi-;touch injected;.bin",
                ],
                "semi-;touch injected;.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin payload=equals=",
                vec!["set", "--bin", "payload=equals=more=equals.bin"],
                "equals=more=equals.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin 'payload=space",
                vec!["set", "--bin", "payload=space name.bin"],
                "space name.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin \"payload=danger-",
                vec!["set", "--bin", "payload=danger-$(touch injected).bin"],
                "danger-$(touch injected).bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin payload=semi-",
                vec!["set", "--bin", "payload=semi-;touch injected;.bin"],
                "semi-;touch injected;.bin",
                "exclude_equals",
                "",
                true,
            ),
            (
                "nkp set --bin 'payload=apostrophe",
                vec!["set", "--bin", "payload=apostrophe-'single'.bin"],
                "apostrophe-'single'.bin",
                "exclude_equals",
                "",
                true,
            ),
            (
                "nkp set --bin first=old --bin 'note=space",
                vec!["set", "--bin", "first=old", "--bin", "note=space name.bin"],
                "space name.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin first=old --bin note=space",
                vec!["set", "--bin", "first=old", "--bin", "note=space name.bin"],
                "space name.bin",
                "exclude_equals",
                "",
                true,
            ),
            (
                "nkp set --bin name = pre fix",
                vec![],
                "prefix-target",
                "default",
                "",
                false,
            ),
            (
                "nkp set --bin name=pre fix=c",
                vec![],
                "prefix=candidate",
                "exclude_equals",
                "",
                false,
            ),
            (
                "nkp set --bin note=--evil",
                vec!["set", "--bin", "note=--evil.bin"],
                "--evil.bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin note=--danger-",
                vec!["set", "--bin", "note=--danger-$(touch injected).bin"],
                "--danger-$(touch injected).bin",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin name=pre --bin",
                vec!["set", "--bin", "name=pre", "--bin"],
                "pre--bin-HIJACKED",
                "default",
                "",
                true,
            ),
            (
                "nkp set --bin name=pre -b",
                vec!["set", "--bin", "name=pre", "-b"],
                "pre-b-HIJACKED",
                "default",
                "",
                true,
            ),
        ];
        for (_, _, filename, _, _, _) in &cases {
            std::fs::write(directory.path().join(filename), b"").unwrap();
        }
        let completion_path = directory.path().join("nkp.bash");
        std::fs::write(&completion_path, bash).unwrap();

        for (line, expected_args, expected_filename, wordbreaks, close_quote, expect_match) in
            &cases
        {
            let script = r#"
import errno, fcntl, os, pty, select, stat, subprocess, sys, time, signal
directory, completion, line, expected_args, wordbreaks, close_quote, expect_match = sys.argv[1:]
expect_match = expect_match == "true"
import json
expected_args = json.loads(expected_args)
transcript = b""

def fail(message):
    raise SystemExit(message + "; PTY transcript: " + repr(transcript))

# CPython added os.waitid on macOS in 3.13. Without WNOWAIT the leader
# cannot safely pin its process group through the group kill. Fail before
# pty.fork rather than start a child that this driver cannot clean safely.
if (
    not callable(getattr(os, "waitid", None))
    or not all(hasattr(os, name) for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT"))
):
    print(
        "PTY cleanup requires os.waitid and WNOWAIT; no PTY child was started",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(2)

pid, fd = pty.fork()
if pid == 0:
    os.chdir(directory)
    os.execvp("bash", ["bash", "--noprofile", "--norc", "-i"])
# A macOS CI run hung >75 minutes with this driver orphaned on cancel; the
# exact blocking syscall was never captured (incident facts: docs/ci-cd.md).
# The mitigation is OS-agnostic rather than a platform patch: with a
# blocking master fd, os.read can wedge after a select-reported readiness
# that no longer holds, and os.write can wedge when bash stops consuming
# input. Keep the master non-blocking and bound every write instead.
os.set_blocking(fd, False)
group_id = pid

def pty_job_control_state():
    def query(label, operation):
        try:
            return "%s=%s" % (label, operation())
        except OSError as error:
            return "%s=errno-%s" % (label, error.errno)
    return "pid=%d %s %s %s" % (
        pid,
        query("pgrp", lambda: os.getpgid(pid)),
        query("session", lambda: os.getsid(pid)),
        query("foreground", lambda: os.tcgetpgrp(fd)),
    )

def cleanup_diagnostics(wait_observation):
    # Diagnostics are intentionally metadata-only: no command line, environ,
    # or PTY transcript is collected here. ps is bounded and optional.
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,ppid=,stat=,pgid=,tpgid=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
            check=False,
        )
        process_state = "exit-%d" % result.returncode
        if result.returncode == 0:
            process_state = "".join(
                char for char in result.stdout.strip() if char.isalnum() or char in " ._-"
            ) or "empty"
    except FileNotFoundError:
        process_state = "ps-unavailable"
    except subprocess.TimeoutExpired:
        process_state = "ps-timeout"
    except Exception as error:
        process_state = "ps-error-%s" % type(error).__name__
    try:
        channel = subprocess.run(
            ["ps", "-o", "wchan=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
            check=False,
        )
        if channel.returncode == 0:
            wait_channel = "".join(
                char for char in channel.stdout.strip() if char.isalnum() or char in " ._-"
            ) or "empty"
        else:
            wait_channel = "unavailable-exit-%d" % channel.returncode
    except FileNotFoundError:
        wait_channel = "ps-unavailable"
    except subprocess.TimeoutExpired:
        wait_channel = "ps-timeout"
    except Exception as error:
        wait_channel = "ps-error-%s" % type(error).__name__
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        master_state = "open mode=%s nonblocking=%s" % (
            "character" if stat.S_ISCHR(os.fstat(fd).st_mode) else "other",
            bool(flags & os.O_NONBLOCK),
        )
        readable = bool(select.select([fd], [], [], 0)[0])
        master_state += " readable=%s" % readable
    except OSError as error:
        master_state = "fd-error-%s" % error.errno
    try:
        observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        fresh_wait = (
            "no-status" if observed is None or not observed.si_pid else
            "pid=%d code=%s status=%s" %
            (observed.si_pid, observed.si_code, observed.si_status)
        )
    except ChildProcessError:
        fresh_wait = "ownership-lost"
    except OSError as error:
        fresh_wait = "errno-%s" % error.errno
    return (
        "diagnostic[pty=%s; waitid-before=%s; waitid-now=%s; process=%s; "
        "wchan=%s; master=%s]"
        % (
            pty_job_control_state(), wait_observation, fresh_wait,
            process_state, wait_channel, master_state
        )
    )

def drain(timeout=0.15):
    global transcript
    end = time.monotonic() + timeout
    data = b""
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            continue
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    transcript += data
    return data

def write_bounded(data, timeout=5.0):
    end = time.monotonic() + timeout
    pending = memoryview(data)
    while pending:
        remaining = end - time.monotonic()
        if remaining <= 0:
            fail("pty stopped accepting input within the write deadline")
        _, writable, _ = select.select([], [fd], [], min(0.1, remaining))
        if not writable:
            continue
        try:
            sent = os.write(fd, pending)
        except BlockingIOError:
            continue
        except OSError:
            fail("pty master rejected input; bash is gone")
        pending = pending[sent:]

def stop_child():
    # Keep the session-leading bash unreaped until after the group signals:
    # its unreaped process pins the PGID against reuse. Once waitpid reaps
    # bash, never signal that numeric PGID again. Success requires a
    # subsequent killpg(pgid, 0) to report ESRCH; reaping bash alone does
    # not prove its descendants are gone.
    identity_before = pty_job_control_state()
    signal_results = []
    wait_observation = "not-attempted"
    try:
        observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        wait_observation = (
            "no-status" if observed is None or not observed.si_pid else
            "pid=%d code=%s status=%s" %
            (observed.si_pid, observed.si_code, observed.si_status)
        )
    except ChildProcessError:
        return (
            "PTY leader is no longer an owned waitable child; refusing "
            "to signal recorded PGID; before: %s; %s; PTY transcript: "
            % (identity_before, cleanup_diagnostics(wait_observation))
            + repr(transcript)
        )
    except OSError as error:
        return (
            "cannot confirm PTY leader ownership before cleanup; "
            "waitid errno-%s:%s; before: %s; %s; PTY transcript: "
            % (error.errno, error.strerror, identity_before,
               cleanup_diagnostics(wait_observation))
            + repr(transcript)
        )
    # pty.fork() makes the child a session and process-group leader. The
    # startup handshake verified group_id == pid while the child was live;
    # waitid(WNOWAIT) keeps that exact PID unreaped until after signaling.
    if group_id != pid:
        return (
            "PTY leader PID does not anchor the recorded process group; "
            "pid=%d recorded=%d; before: %s; %s; PTY transcript: "
            % (pid, group_id, identity_before,
               cleanup_diagnostics(wait_observation))
            + repr(transcript)
        )
    try:
        os.killpg(group_id, signal.SIGCONT)
        signal_results.append("SIGCONT=sent")
    except OSError as error:
        signal_results.append("SIGCONT=errno-%s:%s" % (error.errno, error.strerror))
    try:
        os.killpg(group_id, signal.SIGKILL)
        signal_results.append("SIGKILL=sent")
    except OSError as error:
        signal_results.append("SIGKILL=errno-%s:%s" % (error.errno, error.strerror))
    # The behavior and literal argv have already been checked. Release our
    # PTY master after signaling the still-owned group but before waiting for
    # its leader: Darwin can wait in terminal teardown during exit. Apple's
    # tty_dev.c ptcclose flushes the open slave and drops carrier. The CI
    # observation of an exiting process with a readable master is consistent
    # with, but does not prove, such a dependency. The outer driver deadline
    # also bounds this close if a kernel call itself gets stuck.
    try:
        os.close(fd)
        close_error = None
    except OSError as error:
        close_error = "PTY master close failed: errno-%s:%s" % (error.errno, error.strerror)
        signal_results.append(close_error)
    deadline = time.monotonic() + 3
    last_wait = "not-attempted"
    reaped = False
    group_probe = "not-probed"
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            # Ownership is lost: do not signal again. Continue only with
            # the non-signaling group-absence observation below.
            last_wait = "ECHILD-before-observed-reap"
            reaped = True
            break
        except OSError as error:
            last_wait = "errno-%s:%s" % (error.errno, error.strerror)
            break
        if waited == pid:
            last_wait = "reaped-status=0x%x" % status
            if os.WIFSIGNALED(status):
                last_wait += "-signal-%d" % os.WTERMSIG(status)
            elif os.WIFEXITED(status):
                last_wait += "-exit-%d" % os.WEXITSTATUS(status)
            reaped = True
            break
        last_wait = "no-status"
        time.sleep(0.02)
    if not reaped:
        return (
            "PTY leader was not reaped within bounded group cleanup; "
            "cleanup: %s; before: %s; last waitpid: %s; %s; PTY transcript: "
            % (", ".join(signal_results), identity_before, last_wait,
               cleanup_diagnostics(wait_observation))
            + repr(transcript)
        )
    # The leader is now reaped, so the PGID is no longer ours to signal.
    # killpg(..., 0) is observation only. ESRCH is the sole success proof;
    # an extant group or any other errno fails closed.
    group_deadline = time.monotonic() + 3
    while time.monotonic() < group_deadline:
        try:
            os.killpg(group_id, 0)
            group_probe = "exists"
        except OSError as error:
            if error.errno == errno.ESRCH:
                return close_error
            group_probe = "errno-%s:%s" % (error.errno, error.strerror)
            # EPERM is not absence. Darwin can return it while a group
            # exists but has no signalable members (including zombies);
            # allow bounded settlement, failing if ESRCH never appears.
            if error.errno != errno.EPERM:
                break
        time.sleep(0.02)
    return (
        "process group absence not established after bounded cleanup; "
        "cleanup: %s; before: %s; after: %s; last waitpid: %s; "
        "group probe: %s; %s; PTY transcript: "
        % (
            ", ".join(signal_results),
            identity_before,
            pty_job_control_state(),
            last_wait,
            group_probe,
            cleanup_diagnostics(wait_observation),
        )
        + repr(transcript)
    )

primary = None
try:
    drain()
    # Interactive Bash may adjust job control after pty.fork() returns.
    # Wait boundedly for the controlling tty foreground group and Bash's
    # actual process group to agree before sending test input. Cleanup
    # targets that observed foreground group, not an assumed numeric PID.
    startup_deadline = time.monotonic() + 2
    startup_state = pty_job_control_state()
    while time.monotonic() < startup_deadline:
        try:
            actual_group = os.getpgid(pid)
            foreground_group = os.tcgetpgrp(fd)
        except OSError as error:
            actual_group = None
            startup_state = "query-errno-%s:%s" % (error.errno, error.strerror)
        if actual_group is not None and actual_group == foreground_group:
            if actual_group != pid:
                fail(
                    "interactive bash PTY leader is not its process-group "
                    "leader; pid=%d group=%d" % (pid, actual_group)
                )
            group_id = actual_group
            break
        drain(0.05)
        startup_state = pty_job_control_state()
    else:
        fail(
            "interactive bash PTY job-control setup did not reach the "
            "foreground group within 2s; observed: " + startup_state
        )
    if wordbreaks == "exclude_equals":
        write_bounded(b'COMP_WORDBREAKS="${COMP_WORDBREAKS//=}"\n')
        drain()
    write_bounded(b"nkp() { printf '%s\\0' \"$@\" > args.bin; }; source " + completion.encode() + b"\n")
    drain()
    write_bounded(line.encode() + b"\t")
    result = drain()
    no_match = b"\x07" in result
    if no_match:
        write_bounded(b"\x03")
        drain()
    else:
        write_bounded(close_quote.encode() + b"\n")
        drain()
    if no_match == expect_match:
        fail("unexpected completion match state")
    if not no_match:
        # The stub writes args.bin synchronously before the prompt
        # returns, but the drain above can return early on a slow
        # machine, and mere existence is not enough — a review of
        # 89485ad reproduced the creation-before-bytes race: the file
        # can exist while its write is still in flight, so an
        # existence-then-read can see it empty. Wait bounded for the
        # EXPECTED literal argv content instead, keep the mismatch
        # spelling (a stable wrong content is still a completion
        # failure, not a wait artifact), and include the last observed
        # content — the file never appearing reads as None — when the
        # window closes.
        args_path = os.path.join(directory, "args.bin")
        expected = [arg.encode() for arg in expected_args]
        deadline = time.monotonic() + 2
        while True:
            try:
                with open(args_path, "rb") as stream:
                    actual = stream.read().split(b"\0")[:-1]
            except OSError:
                actual = None
            if actual == expected:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        if actual != expected:
            fail("completion produced unexpected literal argv: " + repr(actual)
                 + " (last observed after the bounded wait)")
    # The case's own behavior is now asserted; bash's exit is CLEANUP,
    # not the behavior under test. macOS job 134579897677 completed the
    # case exactly to here — the completed command executed and the
    # prompt returned — and then bash never consumed `exit` (the exit
    # wedge documented in docs/ci-cd.md), so the old flow failed an
    # otherwise-passing case at the handshake. Attempt the polite exit
    # anyway, bounded; a non-exit is a recorded diagnostic, never a
    # failure, and the finally's group cleanup owns the shutdown.
    write_bounded(b"exit\n")
    deadline = time.monotonic() + 3
    exit_observation = None
    while time.monotonic() < deadline:
        try:
            # WNOWAIT observes the polite exit without consuming the
            # child. stop_child needs the unreaped leader to pin its PGID
            # while it signals the group.
            observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError as error:
            exit_observation = "waitid-errno-%s:%s" % (error.errno, error.strerror)
            break
        if observed is not None and observed.si_pid:
            exit_observation = "exit-code=%s signal=%s" % (
                observed.si_status if observed.si_code == os.CLD_EXITED else "n/a",
                observed.si_status if observed.si_code == os.CLD_KILLED else "n/a",
            )
            break
        time.sleep(0.02)
    # Diagnostic-only on every branch: the case itself already passed,
    # and the finally's group cleanup owns the shutdown. A clean exit 0
    # prints nothing; the other observations are recorded, not hidden —
    # an exit-by-signal or a nonzero code after `exit` is exactly the
    # kind of interpreter behavior the wedge investigation needs.
    if exit_observation is None:
        print(
            "interactive bash did not exit within 3s after 'exit'; the case "
            "itself passed and the group cleanup follows; PTY transcript: "
            + repr(transcript),
            file=sys.stderr,
            flush=True,
        )
    elif exit_observation != "exit-code=0 signal=n/a":
        print(
            "interactive bash exit observation %s after 'exit'; the case "
            "itself passed and the group cleanup follows; PTY transcript: "
            % exit_observation + repr(transcript),
            file=sys.stderr,
            flush=True,
        )
    raise SystemExit(0)
except BaseException as raised:
    # Hold the primary diagnostic — fail() raises SystemExit, and an
    # unexpected exception is held the same way. The finally decides what
    # the process exits with: a cleanup failure appends to this, never
    # masks it.
    primary = raised
finally:
    cleanup = stop_child()
    if cleanup is not None:
        if primary is not None:
            detail = primary.args[0] if primary.args else None
            if isinstance(detail, str):
                raise SystemExit(detail + "; cleanup also failed: " + cleanup)
            raise SystemExit(
                "case ended with " + repr(detail) + "; cleanup failed: " + cleanup
            )
        raise SystemExit("cleanup failed: " + cleanup)
    if primary is not None:
        raise primary
"#;
            let expected_json = serde_json::to_string(&expected_args).unwrap();
            let expect_match_flag = expect_match.to_string();
            let run = run_python_bounded(
                script,
                &[
                    directory.path().as_os_str(),
                    completion_path.as_os_str(),
                    OsStr::new(line),
                    OsStr::new(&expected_json),
                    OsStr::new(wordbreaks),
                    OsStr::new(close_quote),
                    OsStr::new(&expect_match_flag),
                ],
                PYTHON_DRIVER_DEADLINE,
            );
            assert!(
                run.success(),
                "Readline PTY failed for {expected_filename:?} (line {line:?}): {}",
                run.failure_summary(),
            );
            assert!(!marker.exists(), "completion executed an injected command");
            let _ = std::fs::remove_file(directory.path().join("args.bin"));
        }
    }

    /// Windows CI run 134548307275 checked this file out with CRLF
    /// line endings and failed the driver-slice opening assertion
    /// while every LF runner passed: the slice extraction reads this
    /// file's own source, and every `find`/`rfind`/`starts_with`
    /// boundary in it is line-ending sensitive. The positive half
    /// below feeds the extraction a minimal source shaped like the
    /// real driver — Rust before, raw string, terminator, Rust
    /// after — mangled to CRLF and back through the same LF
    /// normalization the driver-slice test applies, proving the
    /// boundaries survive the normalization. The negative half slices
    /// the raw CRLF copy WITHOUT that normalization and requires the
    /// opening boundary to fail, proving the normalization is
    /// load-bearing rather than decorative. Position in this file is
    /// not a constraint on this test: the synthetic's marker lines are
    /// ordinary escaped Rust strings, so the file bytes never contain
    /// the plain-quote `os.execvp(...)` or `r#"` spellings the
    /// production extraction searches for — only the real driver's
    /// raw string carries them, and nothing written here can shadow
    /// it.
    #[test]
    fn driver_slice_extraction_survives_a_crlf_working_copy() {
        let synthetic = concat!(
            "fn rust_before() {}\n",
            "let script = r#\"\n",
            "import os, pty, select, sys, time, signal\n",
            "os.execvp(\"bash\", [\"bash\", \"--noprofile\", \"--norc\", \"-i\"])\n",
            "raise primary\n",
            "\"#;\n",
            "fn tests_after() {}\n",
        );
        for line_ending in ["\n", "\r\n"] {
            let source = lf_script(&synthetic.replace('\n', line_ending));
            let driver =
                hostile_filename_driver_slice(&source).expect("slice of the synthetic source");
            assert!(
                driver.starts_with("r#\"\nimport os, pty, select, sys, time, signal"),
                "the driver slice should open on its own first line under {line_ending:?}"
            );
            assert!(
                driver.contains(
                    "os.execvp(\"bash\", [\"bash\", \"--noprofile\", \"--norc\", \"-i\"])"
                )
            );
            assert!(driver.contains("raise primary"));
            assert!(
                !driver.contains("rust_before"),
                "the slice must not swallow the Rust before the driver"
            );
            assert!(
                !driver.contains("tests_after"),
                "the slice must not swallow the tests after the driver"
            );
        }
        // Negative half: without the LF normalization, the same CRLF
        // copy must fail the slice-opening boundary — the exact
        // assertion the Windows run failed.
        let raw = synthetic.replace('\n', "\r\n");
        let driver = hostile_filename_driver_slice(&raw)
            .expect("the raw copy still slices; only its boundaries shift");
        assert!(
            !driver.starts_with("r#\"\nimport os, pty, select, sys, time, signal"),
            "a raw CRLF copy must fail the slice-opening boundary the Windows run failed"
        );
    }

    /// Generated completion scripts must never carry a carriage
    /// return: POSIX interpreters treat a stray `\r` as input, and
    /// `bash -n` on a CRLF script fails with ``syntax error near
    /// unexpected token `$'{\r''`` — verified by feeding a CRLF copy
    /// of the bash completion to `bash -n`. The guarantee holds under
    /// any checkout because rustc normalizes CRLF (and lone CR) to LF
    /// inside string literals while lexing — proven empirically: with
    /// this very file CRLF-mangled end to end, the generated bash
    /// script still parses. This test pins that invariant where the
    /// lexer provides it; if it ever fails, the `bash -n` assumption
    /// behind the generated-script tests is broken.
    #[test]
    fn generated_scripts_carry_no_carriage_returns() {
        for shell in ["bash", "sh", "zsh", "fish", "powershell", "pwsh", "nushell"] {
            let script = generate(shell).unwrap();
            assert!(
                !script.contains('\r'),
                "{shell} completion carries a carriage return"
            );
        }
    }

    #[test]
    fn bash_filename_completion_does_not_cross_command_or_option_value_boundaries() {
        let bash = generate("bash").unwrap();
        let script = format!(
            r#"{bash}
COMP_WORDS=(nkp exec -- set --bin payload = candidate)
COMP_CWORD=7
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 1
COMP_WORDS=(nkp set -- --bin payload = candidate)
COMP_CWORD=6
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 2
COMP_WORDS=(nkp set --notes --bin payload = candidate)
COMP_CWORD=6
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 3
"#
        );
        // Honors NEO_KEEPASS_COMPLETION_BASH alongside the parse test:
        // the macOS canary pins this boundary contract to the native
        // /bin/bash too, not just to the modern bash the PATH prefers.
        let bash_program = completion_bash_program();
        let output = run_shell_script(&bash_program, &script, None).expect("bash should run");
        // The script's exit codes name the crossed boundary; the
        // detail carries the streams because a bare `exit N` prints
        // nothing (the silent Windows failure of run 134548307275
        // carried no diagnostics at all), and the interpreter report
        // names which bash actually judged the case.
        assert!(
            output.status.success(),
            "Bash option ownership failed: {} [crossed boundary: {}] [interpreter: {}]",
            subprocess_failure_detail(&output),
            match (output.status.code(), output.stderr.is_empty()) {
                (Some(1), true) =>
                    "nkp exec -- set --bin payload = candidate completed a candidate".to_owned(),
                (Some(2), true) =>
                    "nkp set -- --bin payload = candidate completed a candidate".to_owned(),
                (Some(3), true) =>
                    "nkp set --notes --bin payload = candidate completed a candidate".to_owned(),
                (Some(1..=3), false) =>
                    "shell reported an execution or syntax error before a boundary assertion"
                        .to_owned(),
                (other, _) => format!("unexpected exit status {other:?}"),
            },
            shell_interpreter_identity(&bash_program),
        );
    }

    /// Drives the generated bash completion's 3.2-relevant paths
    /// through whatever bash `NEO_KEEPASS_COMPLETION_BASH` selects: both
    /// dynamic completion sites — the `--vault` branch and the metadata
    /// `kind` branch, the two sites whose `mapfile` accumulators became
    /// while-read loops — plus positive cases for the static command
    /// and option vocabulary, the paths the completion reference
    /// (docs/reference/system.md) states work on bash 3.2.
    /// mapfile/readarray are new in bash 4.0 (per bash-4.0's NEWS) and
    /// bash 3.2 — still stock macOS's /bin/bash — has no mapfile, so
    /// the old code failed every dynamic completion with an
    /// unredirected "mapfile: command not found" and left COMPREPLY
    /// empty. `command nkp` bypasses shell functions, so a stub
    /// EXECUTABLE on the child PATH is the only way to answer the
    /// `__complete` queries; without it both dynamic branches would
    /// leave COMPREPLY empty and the count assertions would fail, so
    /// the stub keeps those assertions non-vacuous. The macOS canary
    /// step runs this against the native /bin/bash alongside the
    /// parse and boundary tests.
    #[test]
    #[cfg(unix)]
    fn bash_dynamic_completion_accumulates_candidates_without_mapfile() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("dynamic completion tempdir");
        let stub = directory.path().join("nkp");
        std::fs::write(&stub, "#!/bin/sh\nprintf '%s\\n' vault-one vault-two\n")
            .expect("write stub nkp");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700))
            .expect("stub nkp executable");
        let bash = generate("bash").unwrap();
        let script = format!(
            r#"{bash}
COMP_WORDS=(nkp --vault pre)
COMP_CWORD=2
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 2 ]] || exit 1
[[ "${{COMPREPLY[0]}}" == "vault-one" ]] || exit 2
COMP_WORDS=(nkp --key pre)
COMP_CWORD=2
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 2 ]] || exit 3
[[ "${{COMPREPLY[1]}}" == "vault-two" ]] || exit 4
COMP_WORDS=(nkp se)
COMP_CWORD=1
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 4 ]] || exit 5
[[ "${{COMPREPLY[0]}}" == "secrets" ]] || exit 6
[[ "${{COMPREPLY[3]}}" == "setx" ]] || exit 7
COMP_WORDS=(nkp --password)
COMP_CWORD=1
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 2 ]] || exit 8
[[ "${{COMPREPLY[0]}}" == "--password-env" ]] || exit 9
[[ "${{COMPREPLY[1]}}" == "--password-stdin" ]] || exit 10
"#
        );
        let program = completion_bash_program();
        let child_path = std::env::join_paths(std::iter::once(directory.path().to_owned()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .expect("child PATH with the stub directory");
        let output =
            run_shell_script(&program, &script, Some(&child_path)).expect("bash should run");
        assert!(
            output.status.success(),
            "dynamic vault/keys completion failed: {} [failed check: {}] [interpreter: {}]",
            subprocess_failure_detail(&output),
            match output.status.code() {
                Some(1) =>
                    "the --vault branch did not accumulate the stub's two candidates".to_owned(),
                Some(2) => "the --vault branch lost vault-one".to_owned(),
                Some(3) =>
                    "the --key branch did not accumulate the stub's two candidates".to_owned(),
                Some(4) => "the --key branch lost vault-two".to_owned(),
                Some(5) => {
                    "static command completion did not offer 4 candidates for `se`".to_owned()
                }
                Some(6) => "static command completion lost `secrets`".to_owned(),
                Some(7) => "static command completion lost `setx`".to_owned(),
                Some(8) => {
                    "static option completion did not offer 2 candidates for `--password`"
                        .to_owned()
                }
                Some(9) => "static option completion lost `--password-env`".to_owned(),
                Some(10) => "static option completion lost `--password-stdin`".to_owned(),
                other => format!("unexpected exit status {other:?}"),
            },
            shell_interpreter_identity(&program),
        );
    }

    #[test]
    #[cfg(unix)]
    fn bash_positional_key_completion_stops_at_selector_and_preserves_hostile_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("completion tempdir");
        let stub = directory.path().join("nkp");
        let log = directory.path().join("argv.bin");
        let marker = directory.path().join("executed");
        let hostile = format!("Root/Meta; touch {}", marker.display());
        let shell_quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        let hostile_bash = shell_quote(&hostile);
        let stub_source = format!(
            "#!/bin/sh\nprintf '%s\\0' \"$@\" >> {}\nif [ \"$1\" = __complete ] && [ \"$2\" = keys ]; then printf '%s\\n' '{}'; fi\n",
            shell_quote(&log.display().to_string()),
            hostile.replace('\'', "'\\''")
        );
        std::fs::write(&stub, stub_source).expect("write completion stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700))
            .expect("make completion stub executable");

        let bash = generate("bash").expect("generate bash completion");
        let script = format!(
            r#"{bash}
COMP_WORDS=(nkp get Root/Meta)
COMP_CWORD=2
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || {{ printf 'first=[%s] count=%s\\n' "${{COMPREPLY[0]-}}" "${{#COMPREPLY[@]}}" >&2; exit 11; }}

COMP_WORDS=(nkp get --key Root/Meta)
COMP_CWORD=3
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 21

COMP_WORDS=(nkp set Root/Meta)
COMP_CWORD=2
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 17

COMP_WORDS=(nkp rm Root/Meta)
COMP_CWORD=2
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 18

COMP_WORDS=(nkp secrets get Root/Meta)
COMP_CWORD=3
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 19

COMP_WORDS=(nkp secrets set --field Password Root/Meta)
COMP_CWORD=5
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 12

COMP_WORDS=(nkp secrets remove Root/Meta)
COMP_CWORD=3
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 20

COMP_WORDS=(nkp remove LOGIN '')
COMP_CWORD=3
_nkp_complete
[[ "${{COMPREPLY[0]-}}" != {hostile_bash} ]] || exit 13

COMP_WORDS=(nkp get --field P)
COMP_CWORD=3
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == Password ]] || exit 14

COMP_WORDS=(nkp get --field '')
COMP_CWORD=3
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 5 && "${{COMPREPLY[0]}}" == Password ]] || exit 15

COMP_WORDS=(nkp get LOGIN --key '')
COMP_CWORD=4
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 22

COMP_WORDS=(nkp secrets set --key LOGIN -k '')
COMP_CWORD=6
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 23

COMP_WORDS=(nkp get --field --key '')
COMP_CWORD=4
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 5 && "${{COMPREPLY[0]}}" == Password ]] || exit 24

COMP_WORDS=(nkp get -- -k '')
COMP_CWORD=4
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 25

COMP_WORDS=(nkp set -- --field '')
COMP_CWORD=4
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 26

COMP_WORDS=(nkp secrets get -- --field '')
COMP_CWORD=5
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 27

COMP_WORDS=(nkp secrets rm -- '')
COMP_CWORD=4
_nkp_complete
[[ "${{#COMPREPLY[@]}}" == 1 && "${{COMPREPLY[0]}}" == {hostile_bash} ]] || exit 16
"#
        );
        let program = completion_bash_program();
        let child_path = std::env::join_paths(std::iter::once(directory.path().to_owned()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .expect("child PATH with completion stub");
        let output = run_shell_script(&program, &script, Some(&child_path))
            .expect("bash completion scenario");
        assert!(
            output.status.success(),
            "bash positional key completion failed: {} [interpreter: {}]",
            subprocess_failure_detail(&output),
            shell_interpreter_identity(&program)
        );
        assert!(!marker.exists(), "completion evaluated a hostile candidate");

        let args = std::fs::read(log).expect("record completion protocol arguments");
        let key_requests = args
            .windows(b"__complete\0keys\0".len())
            .filter(|window| *window == b"__complete\0keys\0")
            .count();
        assert_eq!(
            key_requests, 8,
            "completion did not use the metadata-only key protocol"
        );
    }

    #[test]
    fn metadata_index_rejects_case_colliding_paths() {
        let index = super::metadata_candidates(nkeepass::service::CompletionMetadata {
            groups: vec!["Root".into()],
            entries: vec!["Root/Duplicate".into(), "Root/duplicate".into()],
            keys: vec![],
        })
        .unwrap();
        assert!(
            index
                .candidates(super::MetadataKind::Entry, "Root/Duplicate")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            index
                .candidates(super::MetadataKind::Group, "Root")
                .unwrap(),
            vec!["Root"]
        );
    }

    #[test]
    fn ambiguous_group_segments_suppress_descendant_suggestions() {
        let index = super::metadata_candidates(nkeepass::service::CompletionMetadata {
            groups: vec!["Root".into(), "Root/Foo".into(), "Root/foo".into()],
            entries: vec!["Root/Foo/first".into(), "Root/foo/second".into()],
            keys: vec![],
        })
        .unwrap();
        assert!(
            index
                .candidates(super::MetadataKind::Group, "Root/Foo")
                .unwrap()
                .is_empty()
        );
        assert!(
            index
                .candidates(super::MetadataKind::Entry, "Root/")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn metadata_index_fails_closed_at_candidate_limit() {
        let entries = (0..=super::MAX_METADATA_COMPLETION_ITEMS)
            .map(|index| format!("Root/entry-{index}"))
            .collect();
        let index = super::metadata_candidates(nkeepass::service::CompletionMetadata {
            groups: vec!["Root".into()],
            entries,
            keys: vec![],
        })
        .unwrap();
        assert_eq!(
            index
                .candidates(super::MetadataKind::Entry, "")
                .unwrap_err()
                .0,
            "completion metadata limit exceeded"
        );
    }

    #[test]
    fn ambiguity_lookup_is_bounded_for_many_groups_and_candidates() {
        let mut groups = vec!["Root".to_owned()];
        let mut entries = Vec::new();
        for index in 0..1_000 {
            groups.push(format!("Root/group-{index}"));
            groups.push(format!("Root/GROUP-{index}"));
            entries.push(format!("Root/group-{index}/first"));
            entries.push(format!("Root/GROUP-{index}/second"));
        }
        let index = super::metadata_candidates(nkeepass::service::CompletionMetadata {
            groups,
            entries,
            keys: vec![],
        })
        .unwrap();
        assert!(
            index
                .candidates(super::MetadataKind::Entry, "Root/")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn metadata_index_bounds_empty_custom_key_items() {
        let keys = vec![String::new(); super::MAX_METADATA_INDEX_ITEMS + 1];
        assert_eq!(
            super::metadata_candidates(nkeepass::service::CompletionMetadata {
                groups: vec![],
                entries: vec![],
                keys,
            })
            .unwrap_err()
            .0,
            "completion metadata limit exceeded"
        );
    }

    #[test]
    fn nushell_vault_context_fixture_preserves_quoted_paths() {
        let cases = [
            (
                r#"nkp --vault "/vaults/work vault.kdbx" get --key """#,
                "/vaults/work vault.kdbx",
            ),
            (
                "nkp -V '/vaults/my vault.kdbx' keys",
                "/vaults/my vault.kdbx",
            ),
            ("nkp --vault /vaults/plain.kdbx keys", "/vaults/plain.kdbx"),
        ];
        let script = generate("nushell").unwrap();
        let regex_invocation = format!("parse --regex r#'{}'#", super::NUSHELL_VAULT_CONTEXT_REGEX);
        assert!(script.contains(&regex_invocation));
        for (context, expected) in cases {
            assert_eq!(
                fixture_vault_argument(super::NUSHELL_VAULT_CONTEXT_REGEX, context).as_deref(),
                Some(expected)
            );
        }
        assert_eq!(
            fixture_vault_argument(
                super::NUSHELL_VAULT_CONTEXT_REGEX,
                "nkp --vault=/vaults/no.kdbx keys"
            ),
            None
        );
        // The CLI accepts the separated global option only; no equals-form
        // forwarding should be advertised unless its parser adds that syntax.
        assert!(!generate("nushell").unwrap().contains("--vault="));
    }

    #[test]
    fn authenticated_completion_uses_explicit_vault_and_preserves_unlock_errors() {
        use neotales_keepass::{Entry, KdbxCredentials, KdbxFile, KdbxWriteOptions};
        use std::fs::File;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("completion.kdbx");
        let mut database = neotales_keepass::KeePassDatabase::default();
        database.root.add_entry(Entry::new("mail"));
        let mut credentials = KdbxCredentials::password("completion-test-password").unwrap();
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut credentials,
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let explicit = path.to_str().unwrap();
        let config = crate::Config::default();
        let password = zeroize::Zeroizing::new("completion-test-password".to_owned());
        let index = super::authenticated_metadata(Some(explicit), &config, &password).unwrap();
        assert_eq!(
            index
                .candidates(super::MetadataKind::Entry, "Root/m")
                .unwrap(),
            ["Root/mail"]
        );

        let wrong = zeroize::Zeroizing::new("wrong-password".to_owned());
        assert_eq!(
            super::authenticated_metadata(Some(explicit), &config, &wrong)
                .unwrap_err()
                .0,
            "cannot unlock vault"
        );
    }

    #[test]
    fn unsupported_shell_error_is_static() {
        assert_eq!(
            generate("csh completion-secret-SENTINEL").unwrap_err().0,
            "unsupported completion shell"
        );
    }
}
