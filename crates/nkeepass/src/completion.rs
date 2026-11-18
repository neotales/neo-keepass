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
    let Some(name) =
        env::var_os("NKEEPASS_COMPLETE_PASSWORD_ENV").filter(|value| !value.is_empty())
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
            mapfile -t COMPREPLY < <(command nkp __complete vaults "$current" 2>/dev/null)
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
    elif [[ "$command" == alias && "$position" -eq 2 && ( "$action" == resolve || "$action" == rm || "$action" == remove ) ]]; then
        kind='aliases'
    elif [[ "$command" == config && "$action" == set && $position -eq 3 ]]; then
        kind='vaults'
    fi
    if [[ -n "$kind" ]]; then
        mapfile -t COMPREPLY < <(command nkp "${vault_args[@]}" __complete "$kind" "$current" 2>/dev/null)
        return
    fi
    if [[ "$previous" == "--" ]]; then
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
                    set) choices='--key --field --username --url --notes --file --bin -b --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                    rm|remove) choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                    ensure) choices='--key --size --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
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
        set) choices='--key --field --username --url --notes --file --bin -b --stdin --password --password-env --password-file --password-stdin --key-file' ;;
        rm|remove) choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
        ensure) choices='--key --size --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
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
                secrets:set) _nk_choices='--key --field --username --url --notes --file --bin -b --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:rm|secrets:remove) _nk_choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                secrets:ensure) _nk_choices='--key --size --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
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
                set:) _nk_choices='--key --field --username --url --notes --file --bin -b --stdin --password --password-env --password-file --password-stdin --key-file' ;;
                rm:|remove:) _nk_choices='--key --yes --password --password-env --password-file --password-stdin --key-file' ;;
                ensure:) _nk_choices='--key --size --dry-run --password --password-env --password-file --password-stdin --key-file' ;;
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
                    set) choices=('--key' '--field' '--username' '--url' '--notes' '--file' '--bin' '-b' '--stdin' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    rm|remove) choices=('--key' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
                    ensure) choices=('--key' '--size' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
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
        set) choices=('--key' '--field' '--username' '--url' '--notes' '--file' '--bin' '-b' '--stdin' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        rm|remove) choices=('--key' '--yes' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
        ensure) choices=('--key' '--size' '--dry-run' '--password' '--password-env' '--password-file' '--password-stdin' '--key-file') ;;
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
                            'set' { $values = @('--key', '--field', '--username', '--url', '--notes', '--file', '--bin', '-b', '--stdin', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            { $_ -in @('rm', 'remove') } { $values = @('--key', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                            'ensure' { $values = @('--key', '--size', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
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
                'set' { $values = @('--key', '--field', '--username', '--url', '--notes', '--file', '--bin', '-b', '--stdin', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                { $_ -in @('rm', 'remove') } { $values = @('--key', '--yes', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
                'ensure' { $values = @('--key', '--size', '--dry-run', '--password', '--password-env', '--password-file', '--password-stdin', '--key-file') }
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
export extern "nkp secrets set" [--key: string@"nu-complete nkp keys" --username: string --url: string --notes: string --field: string@"Password Title UserName URL Notes" --file: string --bin: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp secrets rm" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp secrets remove" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp secrets ensure" [--key: string@"nu-complete nkp keys" --size: int --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
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
export extern "nkp set" [--key: string@"nu-complete nkp keys" --username: string --url: string --notes: string --field: string@"Password Title UserName URL Notes" --file: string --bin: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkp rm" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp remove" [--key: string@"nu-complete nkp keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkp ensure" [--key: string@"nu-complete nkp keys" --size: int --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
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
    #[cfg(unix)]
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

    /// A driver whose descendant holds the inherited stdout pipe cannot pin
    /// the harness: the drain overflows bounded, the group is killed, and
    /// the escapee is asserted dead BY PID — the same pattern as the
    /// packaging smoke harness's orphan fixture. This also covers the
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
    # Simulated: the real driver only reaches this return when a SIGKILLed
    # group ignores its reap allowance, which no test can force. What is
    # under test is the finally that composes the two diagnostics.
    return "interactive bash survived SIGKILL; PTY transcript: " + repr(transcript)

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
            stderr.contains("interactive bash survived SIGKILL"),
            "the cleanup detail must be part of the composed diagnostic: {}",
            run.failure_summary()
        );
        assert!(
            stderr.contains("case ended with 0"),
            "a numeric success must not silently swallow a cleanup failure: {}",
            run.failure_summary()
        );
    }

    /// Post-reap is exactly the state where the retired fallback killed by
    /// pid: the child has already been waited for, its pid may already
    /// have been recycled, and a direct `os.kill(pid)` there would signal
    /// whoever owns the number now. This drives the driver's cleanup shape
    /// end to end: a session-leading bash leaves a straggler in its group,
    /// the child is REAPED before any cleanup runs, and the group-only
    /// cleanup then executes. It asserts the straggler dies by pid, a
    /// bystander outside the group survives untouched, and the cleanup
    /// reports no failure — the group id is what the cleanup owns, not the
    /// pid number.
    #[test]
    #[cfg(unix)]
    fn bounded_driver_post_reap_cleanup_kills_group_members_only() {
        let script = r#"
import os, signal, subprocess, time

transcript = b""

def stop_child(pid):
    # The hostile-filename driver's cleanup, verbatim in shape: a group
    # kill only, on every path — never a direct pid kill.
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        return None
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if waited == pid:
            return None
        time.sleep(0.02)
    return "interactive bash survived SIGKILL; PTY transcript: " + repr(transcript)

# pty.fork() gives the real driver's child its own session and group;
# this replicates that shape so the group semantics are the real ones.
child = subprocess.Popen(
    ["bash", "--noprofile", "--norc", "-c", "sleep 600 & echo $!"],
    start_new_session=True,
    stdout=subprocess.PIPE,
)
straggler = int(child.stdout.readline().decode())
# The dangerous state comes first: reap the child BEFORE any cleanup runs,
# so the cleanup executes against a reaped pid.
_, status = os.waitpid(child.pid, 0)
child.returncode = os.waitstatus_to_exitcode(status)
# A bystander in its own group, outside everything the cleanup owns: it
# must come through the cleanup untouched.
victim = subprocess.Popen(
    ["sleep", "600"],
    start_new_session=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
failure = stop_child(child.pid)
print("straggler", straggler, "victim", victim.pid, "cleanup", repr(failure), flush=True)
"#;
        let run = run_python_bounded(script, &[], Duration::from_secs(15));
        assert!(
            run.success(),
            "the post-reap cleanup scenario should complete: {}",
            run.failure_summary()
        );
        assert!(
            !run.drain_overflow,
            "the straggler holds bash's stdout; it must be dead before the \
             driver exits: {}",
            run.failure_summary()
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let mut straggler: Option<u32> = None;
        let mut victim: Option<u32> = None;
        let mut cleanup = None;
        let mut fields = stdout.split_whitespace();
        while let Some(field) = fields.next() {
            match field {
                "straggler" => {
                    straggler = fields.next().and_then(|value| value.parse().ok());
                }
                "victim" => {
                    victim = fields.next().and_then(|value| value.parse().ok());
                }
                "cleanup" => cleanup = fields.next(),
                _ => {}
            }
        }
        let straggler =
            straggler.unwrap_or_else(|| panic!("driver should report the straggler pid"));
        let victim = victim.unwrap_or_else(|| panic!("driver should report the bystander pid"));
        assert_eq!(
            cleanup,
            Some("None"),
            "a reaped child's cleanup should report no failure"
        );
        // The straggler must be dead by pid: the group kill reached it
        // after the reap, without any pid-based kill existing in the driver.
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
            "straggler {straggler} SURVIVED the post-reap group kill"
        );
        // The bystander must still be alive: the cleanup signaled its OWN
        // group only, never a pid it no longer owned.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut victim_alive = false;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &victim.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if probe.success() {
                victim_alive = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            victim_alive,
            "bystander {victim} was killed by a cleanup it never belonged to"
        );
        // Leave nothing behind: the bystander leads its own group, so the
        // established group-kill helper removes it — still no pid kill.
        signal_driver_group(i32::try_from(victim).expect("bystander pid should fit i32"));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut victim_dead = false;
        while std::time::Instant::now() < deadline {
            let probe = std::process::Command::new("ps")
                .args(["-p", &victim.to_string(), "-o", "pid="])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("ps should run");
            if !probe.success() {
                victim_dead = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            victim_dead,
            "bystander {victim} could not be cleaned up after the assertion"
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
            "use std::time::Duration;",
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
            "fn bash_binary_completion_uses_readline_quoting_for_hostile_filenames",
            "fn bounded_driver_kills_wedged_python_within_deadline",
            "fn bounded_driver_removes_pipe_holding_descendant_no_orphan_survives",
            "fn bounded_driver_cleanup_failure_appends_to_primary_diagnostic",
            "fn bounded_driver_post_reap_cleanup_kills_group_members_only",
            "fn bounded_kill_helper_returns_within_deadline_from_unresponsive_helper",
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
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/completion.rs"))
                .expect("completion.rs source should be readable");
        // Everything asserted below must live in the hostile-filename
        // driver's own raw-string script — bounded exactly by its `r#"`
        // opening and its `"#;` terminator — not in a copy of its protocol
        // kept elsewhere in this file, and not in the Rust code before or
        // after the driver, where an un-reaped-child Rust kill stays
        // legitimate.
        let execvp_at = source
            .find("os.execvp(\"bash\", [\"bash\", \"--noprofile\", \"--norc\", \"-i\"])")
            .expect("the PTY driver should fork interactive bash");
        let script_open = source[..execvp_at]
            .rfind("r#\"")
            .expect("the driver should be a raw string literal");
        let script_close = source[execvp_at..]
            .find("\"#;")
            .map(|at| execvp_at + at)
            .expect("the driver raw string should terminate");
        let driver = &source[script_open..script_close];
        // The boundary must be non-vacuous: the slice opens on the
        // driver's own first line and stops at its raw-string terminator,
        // swallowing neither the Rust before it nor the Rust after it — a
        // future test after the driver may legitimately keep an
        // un-reaped-child Rust kill.
        assert!(
            driver.starts_with("r#\"\nimport os, pty, select, sys, time, signal"),
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
            "import os, pty, select, sys, time, signal",
            "def stop_child():",
            "os.killpg(pid, signal.SIGKILL)",
            "; cleanup: ",
            "; cleanup also failed: ",
            "case ended with ",
            "raise primary",
            "fail(\"completion produced unexpected literal argv",
        ] {
            assert!(
                driver.contains(marker),
                "the PTY driver must keep `{marker}` — its cleanup owns the \
                 group, composes failures, and reports the transcript"
            );
        }
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
            assert!(!script.contains("--value"));
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

    #[test]
    fn generated_bash_and_posix_scripts_parse_and_posix_files_group_completes() {
        let directory = tempfile::tempdir().unwrap();
        for (shell, args) in [("bash", vec!["-n"]), ("sh", vec!["-n"])] {
            let path = directory.path().join(format!("completion.{shell}"));
            std::fs::write(&path, generate(shell).unwrap()).unwrap();
            let output = std::process::Command::new(shell)
                .args(args)
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{shell} syntax failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let path = directory.path().join("completion.sh");
        std::fs::write(&path, generate("sh").unwrap()).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(". ./completion.sh; nkp_complete '' '' files; nkp_complete '' '' files add")
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let completions = String::from_utf8_lossy(&output.stdout);
        assert!(completions.lines().any(|line| line == "ls"));
        assert!(completions.lines().any(|line| line == "--file"));
    }

    #[test]
    fn generated_zsh_and_powershell_scripts_parse_when_interpreters_are_installed() {
        let directory = tempfile::tempdir().unwrap();
        let require_interpreters = std::env::var_os("NKEEPASS_REQUIRE_COMPLETION_SHELLS").is_some();
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

    #[test]
    #[cfg(unix)]
    fn bash_binary_completion_uses_readline_quoting_for_hostile_filenames() {
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
import os, pty, select, sys, time, signal
directory, completion, line, expected_args, wordbreaks, close_quote, expect_match = sys.argv[1:]
expect_match = expect_match == "true"
import json
expected_args = json.loads(expected_args)
transcript = b""

def fail(message):
    raise SystemExit(message + "; PTY transcript: " + repr(transcript))

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
    # pty.fork()'s child called setsid(): bash leads its own session and
    # process group, so killpg reaches every job it spawned. Kill even on
    # the success paths, so a straggler subshell never outlives the
    # driver. Group kill ONLY, on every path: an un-reaped child — even
    # as a zombie — still counts as a group member, so killpg cannot miss
    # a child that is still ours, and a group with live members never has
    # its id recycled. killpg raising OSError therefore means the whole
    # group is gone, which is only possible once the child was reaped —
    # and the pid of a reaped child may already belong to an unrelated
    # process. NEVER fall back to a direct kill by pid on that path: after
    # a reap the number is not ours to signal; the group id was.
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        return None
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            # Already reaped (by the exit wait above, or an earlier
            # cleanup): nothing left to signal or reap, and killpg has
            # already covered the descendants.
            return None
        if waited == pid:
            return None
        time.sleep(0.02)
    # NOT raised: raising here — especially out of a finally — would mask
    # whatever failure is already propagating. Return the diagnostic; the
    # caller composes it with the primary one.
    return "interactive bash survived SIGKILL; PTY transcript: " + repr(transcript)

primary = None
try:
    drain()
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
    write_bounded(b"exit\n")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            break
        time.sleep(0.02)
    else:
        # The timeout is the primary failure; a cleanup that could not
        # finish is appended to it, never raised over it.
        cleanup = stop_child()
        fail("timed out waiting for interactive bash to exit"
             + (("; cleanup: " + cleanup) if cleanup else ""))
    if no_match == expect_match:
        fail("unexpected completion match state")
    if no_match:
        raise SystemExit(0)
    with open(os.path.join(directory, "args.bin"), "rb") as stream:
        actual = stream.read().split(b"\0")[:-1]
    if actual != [arg.encode() for arg in expected_args]:
        fail("completion produced unexpected literal argv: " + repr(actual))
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
        let output = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .expect("bash should run");
        assert!(
            output.status.success(),
            "Bash option ownership failed: {}",
            String::from_utf8_lossy(&output.stderr)
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
