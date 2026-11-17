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

const BASH: &str = r#"# Static nkeepass completion. Dynamic queries return metadata only and never secrets.
_nkeepass_complete() {
    local current previous command action choices kind
    local index=1 element position
    local -a vault_args=()
    current="${COMP_WORDS[COMP_CWORD]}"
    local file_name='' file_path='' file_prefix='' bin_index=-1
    local route_command='' route_action='' scan=1 argument_context=true
    while (( scan < COMP_CWORD )); do
        element="${COMP_WORDS[scan]}"
        if [[ "$element" == -- ]]; then
            argument_context=false
            break
        fi
        if [[ -z "$route_command" ]]; then
            case "$element" in
                --vault|-V|--password|--password-env|--password-file|--key-file)
                    ((scan += 2))
                    continue
                    ;;
                --password-stdin)
                    ((scan++))
                    continue
                    ;;
                *) route_command="$element" ;;
            esac
        elif [[ "$route_command" == secrets && -z "$route_action" ]]; then
            route_action="$element"
        fi
        if [[ "$element" == --bin || "$element" == -b ]]; then
            bin_index=$scan
        fi
        ((scan++))
    done
    if [[ "$route_command" == secrets && "$route_action" == set ]] \
        || [[ "$route_command" == set && -z "$route_action" ]]; then
        if [[ "$current" == *=* ]]; then
            file_name="${current%%=*}"
            file_path="${current#*=}"
            file_prefix="$file_name="
        elif (( COMP_CWORD > 0 )) && [[ "${COMP_WORDS[COMP_CWORD - 1]}" == = ]]; then
            file_name="${COMP_WORDS[COMP_CWORD - 2]-}"
            file_path="$current"
            file_prefix=''
        fi
        if (( bin_index >= 0 )) && [[ "$argument_context" == true ]] \
            && [[ -n "$file_name" ]] && [[ "$current" != --* ]]; then
            local file_arg=true
            for ((scan = bin_index + 1; scan < COMP_CWORD; scan++)); do
                case "${COMP_WORDS[scan]}" in
                    --bin|-b|--notes|--username|--url|--file|--stdin|--key|--field|--)
                        file_arg=false
                        ;;
                esac
            done
            if [[ "$file_arg" == true ]]; then
                local candidate
                COMPREPLY=()
                while IFS= read -r candidate; do
                    COMPREPLY+=("$file_prefix$candidate")
                done < <(compgen -f -- "$file_path")
                compopt -o nospace 2>/dev/null || true
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
            mapfile -t COMPREPLY < <(command nkeepass __complete vaults "$current" 2>/dev/null)
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
        mapfile -t COMPREPLY < <(command nkeepass "${vault_args[@]}" __complete "$kind" "$current" 2>/dev/null)
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
complete -F _nkeepass_complete nkeepass
"#;

const POSIX_SH: &str = r#"# Static nkeepass completion for POSIX sh. Dynamic queries return metadata only and never secrets.
# POSIX sh has no standard programmable tab-completion registration. This stable
# helper prints matching candidates for CURRENT PREVIOUS COMMAND [ACTION [VAULT_OPTION VAULT_PATH]].
# A POSIX-shell integration can call `nkeepass_complete "$cur" "$prev" "$command" "$action"`.
_nkeepass_complete_candidates() {
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
                    nkeepass "$_nk_vault_option" "$_nk_vault_path" __complete "$_nk_kind" "$_nk_current" 2>/dev/null
                fi
                ;;
            *) nkeepass __complete "$_nk_kind" "$_nk_current" 2>/dev/null ;;
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
nkeepass_complete() {
    _nkeepass_complete_candidates "${1-}" "${2-}" "${3-}" "${4-}" "${5-}" "${6-}"
}
"#;

const ZSH: &str = r#"#compdef nkeepass
# Static nkeepass completion. Dynamic queries return metadata only and never secrets.
_nkeepass() {
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
            dynamic=("${(@f)$(command nkeepass __complete vaults "$cur" 2>/dev/null)}")
            (( ${#dynamic} && ${#dynamic[1]} )) && _describe -t values 'nkeepass metadata' dynamic
        else
            choices=(init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion '--help' '-h' '--version' '--vault' '-V' '--password-env' '--password-stdin')
            _describe -t commands 'nkeepass command' choices
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
        dynamic=("${(@f)$(command nkeepass "${vault_args[@]}" __complete "$kind" "$cur" 2>/dev/null)}")
        (( ${#dynamic} && ${#dynamic[1]} )) && _describe -t values 'nkeepass metadata' dynamic
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
        _describe -t values 'nkeepass value' choices
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
    (( ${#choices} )) && _describe -t values 'nkeepass value' choices
}
if [[ "$funcstack[1]" == "_nkeepass" ]]; then
    _nkeepass "$@"
else
    compdef _nkeepass nkeepass
fi
"#;

const FISH: &str = r"# Static nkeepass completion. Dynamic queries return metadata only and never secrets.
function __nkeepass_complete_vault_args
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
complete -c nkeepass -f
complete -c nkeepass -n '__fish_use_subcommand' -a 'init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion'
complete -c nkeepass -n '__fish_use_subcommand' -s h -l help
complete -c nkeepass -n '__fish_use_subcommand' -s V -l vault -r -a '(nkeepass (__nkeepass_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkeepass -n '__fish_use_subcommand' -l version
complete -c nkeepass -n '__fish_use_subcommand' -l password-env -r
complete -c nkeepass -n '__fish_use_subcommand' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from context' -a 'ls list show use rm remove set'
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l kdf -a 'aes argon2d argon2id'
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l memory
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l iterations
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l parallelism
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l size
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from init' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from alias' -a 'ls list set rm remove resolve'
complete -c nkeepass -n '__fish_seen_subcommand_from alias set rm remove resolve' -a '(nkeepass (__nkeepass_complete_vault_args) __complete aliases (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from context use rm' -a '(nkeepass (__nkeepass_complete_vault_args) __complete vault-aliases (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from context set' -a '(nkeepass (__nkeepass_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from alias; and __fish_seen_argument set' -l kind -a 'vault entry'
complete -c nkeepass -n '__fish_seen_subcommand_from alias; and __fish_seen_argument set' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from config' -a 'ls list get show set rm remove'
complete -c nkeepass -n '__fish_seen_subcommand_from config ls list' -l json
complete -c nkeepass -n '__fish_seen_subcommand_from config get show set rm remove' -a 'aliases current default_vault'
complete -c nkeepass -n '__fish_seen_subcommand_from config set' -a '(nkeepass (__nkeepass_complete_vault_args) __complete vaults (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from secrets' -a 'get getx list ls search show env environment set rm remove ensure otp setx import export sync'
complete -c nkeepass -n '__fish_seen_subcommand_from automation' -a 'setx import export sync'
complete -c nkeepass -n '__fish_seen_subcommand_from get getx set setx rm remove ensure search show env environment otp files attachment attachments field custom-field exec x' -l key -r -a '(nkeepass (__nkeepass_complete_vault_args) __complete keys (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from get getx set' -l field -a 'Password Title UserName URL Notes'
complete -c nkeepass -n '__fish_seen_subcommand_from get otp' -l format -a 'text json dotenv shell pwsh powershell github-actions azure-devops null'
complete -c nkeepass -n '__fish_seen_subcommand_from env environment' -l format -a 'dotenv shell pwsh powershell github-actions azure-devops json null'
complete -c nkeepass -n '__fish_seen_subcommand_from get' -l clipboard
complete -c nkeepass -n '__fish_seen_subcommand_from get env environment otp' -l is-output
complete -c nkeepass -n '__fish_seen_subcommand_from getx' -l format -a 'json'
complete -c nkeepass -n '__fish_seen_subcommand_from ls' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from get env environment otp field custom-field' -l name
complete -c nkeepass -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password
complete -c nkeepass -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from get getx ls list search show set rm remove ensure env environment otp' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from ls list search' -a '--'
complete -c nkeepass -n '__fish_seen_subcommand_from set' -l file
complete -c nkeepass -n '__fish_seen_subcommand_from set' -s b -l bin -r
complete -c nkeepass -n '__fish_seen_subcommand_from set' -l username -r
complete -c nkeepass -n '__fish_seen_subcommand_from set' -l url -r
complete -c nkeepass -n '__fish_seen_subcommand_from set' -l notes -r
complete -c nkeepass -n '__fish_seen_subcommand_from set' -l stdin
complete -c nkeepass -n '__fish_seen_subcommand_from rm' -l yes
complete -c nkeepass -n '__fish_seen_subcommand_from ensure' -l size
complete -c nkeepass -n '__fish_seen_subcommand_from setx import sync' -l file
complete -c nkeepass -n '__fish_seen_subcommand_from setx import sync' -l stdin
complete -c nkeepass -n '__fish_seen_subcommand_from import' -l replace
complete -c nkeepass -n '__fish_seen_subcommand_from setx import sync' -l dry-run
complete -c nkeepass -n '__fish_seen_subcommand_from sync' -l strategy -a 'newest source target'
complete -c nkeepass -n '__fish_seen_subcommand_from export' -l output
complete -c nkeepass -n '__fish_seen_subcommand_from setx import export sync' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from setx import export sync' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from setx import export sync' -l password
complete -c nkeepass -n '__fish_seen_subcommand_from setx import export sync' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from setx import export sync' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from ensure' -l dry-run
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -a 'ls list add create ensure rm remove'
complete -c nkeepass -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument add create ensure rm remove' -l key -r -a '(nkeepass (__nkeepass_complete_vault_args) __complete groups (commandline -ct))'
complete -c nkeepass -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument add create ensure rm remove' -l dry-run
complete -c nkeepass -n '__fish_seen_subcommand_from group groups; and __fish_seen_argument rm remove' -l yes
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -l password -r
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -l password-env -r
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -l password-file -r
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from group groups' -l key-file -r
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments' -a 'ls list add import get export rm remove'
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l key
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l file
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument add import' -l stdin
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument get export' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument get export' -l output
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument rm remove' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument rm remove' -l yes
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l password
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from files attachment attachments; and __fish_seen_argument ls list add import get export rm remove' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from add' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from add' -l file
complete -c nkeepass -n '__fish_seen_subcommand_from add' -l stdin
complete -c nkeepass -n '__fish_seen_subcommand_from get' -l output
complete -c nkeepass -n '__fish_seen_subcommand_from get' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from rm' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from add get rm' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from add get rm' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from rm' -l yes
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field' -a 'ls list get reveal set edit rm remove'
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l key
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit rm remove' -l field
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l format -a 'text json dotenv shell pwsh powershell github-actions azure-devops null'
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument get reveal' -l is-output
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit' -l file
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument set edit' -l stdin
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument rm remove' -l yes
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l password
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from field custom-field; and __fish_seen_argument ls list get reveal set edit rm remove' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l env
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l password-env
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l password-stdin
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l password
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l password-file
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -l key-file
complete -c nkeepass -n '__fish_seen_subcommand_from exec x' -a '--'
complete -c nkeepass -n '__fish_seen_subcommand_from completion' -a 'bash sh zsh fish powershell pwsh nushell'
";

const POWERSHELL: &str = r#"# Static nkeepass completion. Dynamic queries return metadata only and never secrets.
Register-ArgumentCompleter -Native -CommandName nkeepass -ScriptBlock {
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
        $values = @(& nkeepass @vaultArguments __complete $protocolKind $wordToComplete 2>$null | ForEach-Object { $_.ToString() } | Where-Object { $_ })
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
    r#"# Static nkeepass completion. Dynamic queries return metadata only and never secrets.
# Nushell custom completers receive the whole command context as their first argument.
def "nu-complete nkeepass vault-args" [context: string] {
  let matches = ($context | parse --regex r#'"#,
    $vault_regex,
    r#"'#)
  if ($matches | is-empty) { [] } else {
    let parsed = ($matches | last)
    let vault = if $parsed.double != null { $parsed.double } else if $parsed.single != null { $parsed.single } else { $parsed.bare }
    ["--vault", $vault]
  }
}
def "nu-complete nkeepass aliases" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete aliases | lines }
def "nu-complete nkeepass vault-files" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete vault-files | lines }
def "nu-complete nkeepass vaults" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete vaults | lines }
def "nu-complete nkeepass entries" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete entries | lines }
def "nu-complete nkeepass groups" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete groups | lines }
def "nu-complete nkeepass keys" [context: string] { let args = (nu-complete nkeepass vault-args $context); ^nkeepass ...$args __complete keys | lines }
export extern nkeepass [
  command?: string@"init context alias config secrets automation get getx list ls search show env set rm remove ensure otp setx import export sync files attachment attachments group groups field custom-field exec x version completion"
  --help(-h)
  --version
  --vault(-V): string@"nu-complete nkeepass vaults"
  --password-env: string
  --password-stdin
]
export extern "nkeepass init" [path?: string@"nu-complete nkeepass vault-files" --kdf: string@"aes argon2d argon2id" --memory: int --iterations: int --parallelism: int --size: int --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass context" [action: string@"ls list show use rm remove set"]
export extern "nkeepass context ls" []
export extern "nkeepass context show" []
export extern "nkeepass context use" [alias: string@"nu-complete nkeepass vault-aliases"]
export extern "nkeepass context rm" [alias: string@"nu-complete nkeepass vault-aliases"]
export extern "nkeepass context set" [alias: string path: string@"nu-complete nkeepass vaults"]
export extern "nkeepass alias" [action: string@"ls list set rm remove resolve"]
export extern "nkeepass alias ls" []
export extern "nkeepass alias list" []
export extern "nkeepass alias set" [name: string@"nu-complete nkeepass aliases" target: string@"nu-complete nkeepass vaults" --kind: string@"vault entry" --field: string]
export extern "nkeepass alias rm" [name: string@"nu-complete nkeepass aliases"]
export extern "nkeepass alias remove" [name: string@"nu-complete nkeepass aliases"]
export extern "nkeepass alias resolve" [name: string@"nu-complete nkeepass aliases"]
export extern "nkeepass config" [action: string@"ls list get show set rm remove"]
export extern "nkeepass config ls" [glob?: string --json]
export extern "nkeepass config list" [glob?: string --json]
export extern "nkeepass config get" [key: string@"aliases current default_vault"]
export extern "nkeepass config show" [key: string@"aliases current default_vault"]
export extern "nkeepass config set" [key: string@"aliases current default_vault" value: string@"nu-complete nkeepass vaults"]
export extern "nkeepass config rm" [key: string@"aliases current default_vault"]
export extern "nkeepass config remove" [key: string@"aliases current default_vault"]
export extern "nkeepass secrets" [action: string@"get getx list ls search show env environment set rm remove ensure otp setx import export sync"]
export extern "nkeepass secrets list" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets search" [query: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets show" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets env" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkeepass secrets environment" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkeepass secrets get" [--key: string@"nu-complete nkeepass keys" --field: string@"Password Title UserName URL Notes" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --clipboard --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkeepass secrets getx" [--key: string@"nu-complete nkeepass keys" --field: string@"Password Title UserName URL Notes" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --format: string@"json"]
export extern "nkeepass secrets ls" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets set" [--key: string@"nu-complete nkeepass keys" --username: string --url: string --notes: string --field: string@"Password Title UserName URL Notes" --file: string --bin: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets rm" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass secrets remove" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass secrets ensure" [--key: string@"nu-complete nkeepass keys" --size: int --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets otp" [--key: string@"nu-complete nkeepass keys" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkeepass secrets setx" [--key: string@"nu-complete nkeepass keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass secrets sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass automation" [action: string@"setx import export sync"]
export extern "nkeepass automation setx" [--key: string@"nu-complete nkeepass keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass automation import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass automation export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass automation sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass get" [--key: string@"nu-complete nkeepass keys" --field: string@"Password Title UserName URL Notes" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --clipboard --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkeepass getx" [--key: string@"nu-complete nkeepass keys" --field: string@"Password Title UserName URL Notes" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --format: string@"json"]
export extern "nkeepass list" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass ls" [glob?: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass search" [query: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass show" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass env" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"dotenv shell pwsh powershell github-actions azure-devops json null"]
export extern "nkeepass set" [--key: string@"nu-complete nkeepass keys" --username: string --url: string --notes: string --field: string@"Password Title UserName URL Notes" --file: string --bin: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass rm" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass remove" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass ensure" [--key: string@"nu-complete nkeepass keys" --size: int --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass otp" [--key: string@"nu-complete nkeepass keys" --name: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null"]
export extern "nkeepass setx" [--key: string@"nu-complete nkeepass keys" --file: string --stdin --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass import" [--file: string --stdin --replace --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass export" [--output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass sync" [--file: string --stdin --strategy: string@"newest source target" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group" [action: string@"ls list add create ensure rm remove"]
export extern "nkeepass groups" [action: string@"ls list add create ensure rm remove"]
export extern "nkeepass group ls" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group list" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups ls" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups list" [--password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group add" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group create" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group ensure" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups add" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups create" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups ensure" [--key: string@"nu-complete nkeepass groups" --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group rm" [--key: string@"nu-complete nkeepass groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass group remove" [--key: string@"nu-complete nkeepass groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups rm" [--key: string@"nu-complete nkeepass groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass groups remove" [--key: string@"nu-complete nkeepass groups" --yes --dry-run --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment" [action: string@"ls list add import get export rm remove"]
export extern "nkeepass attachments" [action: string@"ls list add import get export rm remove"]
export extern "nkeepass attachment ls" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment list" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments ls" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments list" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment add" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment import" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments add" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments import" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment get" [--key: string@"nu-complete nkeepass keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment export" [--key: string@"nu-complete nkeepass keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments get" [--key: string@"nu-complete nkeepass keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachments export" [--key: string@"nu-complete nkeepass keys" --field: string --output: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass attachment rm" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass attachment remove" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass attachments rm" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass attachments remove" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass field" [action: string@"ls list get reveal set edit rm remove"]
export extern "nkeepass custom-field" [action: string@"ls list get reveal set edit rm remove"]
export extern "nkeepass field ls" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field list" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field ls" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field list" [--key: string@"nu-complete nkeepass keys" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field get" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field reveal" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field get" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field reveal" [--key: string@"nu-complete nkeepass keys" --field: string --name: string --is-output --format: string@"text json dotenv shell pwsh powershell github-actions azure-devops null" --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field set" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field edit" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field set" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass custom-field edit" [--key: string@"nu-complete nkeepass keys" --field: string --file: string --stdin --password: string --password-env: string --password-file: string --password-stdin --key-file: string]
export extern "nkeepass field rm" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass field remove" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass custom-field rm" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass custom-field remove" [--key: string@"nu-complete nkeepass keys" --field: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string --yes]
export extern "nkeepass exec" [--key: string@"nu-complete nkeepass keys" --env: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string ...args: string]
export extern "nkeepass x" [--key: string@"nu-complete nkeepass keys" --env: string --password: string --password-env: string --password-file: string --password-stdin --key-file: string ...args: string]
export extern "nkeepass version" []
export extern "nkeepass completion" [shell: string@"bash sh zsh fish powershell pwsh nushell"]
"#,
);
    };
}

define_nushell_completion!(
    r#"(?m)^\s*nkeepass\s+(?:--vault|-V)\s+(?:"(?<double>[^"]*)"|'(?<single>[^']*)'|(?<bare>\S+))"#
);

#[cfg(test)]
mod tests {
    use super::{POWERSHELL, generate};
    use crate::CONFIG_KEYS;

    fn fixture_vault_argument(pattern: &str, context: &str) -> Option<String> {
        assert_eq!(pattern, super::NUSHELL_VAULT_CONTEXT_REGEX);
        let remainder = context.strip_prefix("nkeepass ")?;
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
        assert!(bash.contains("command nkeepass \"${vault_args[@]}\" __complete"));
        assert!(bash.contains("position -eq 1"));
        assert!(bash.contains("position -eq 3"));
        assert!(bash.contains("__complete vaults \"$current\""));
        assert!(bash.contains("COMP_WORDS[COMP_CWORD - 2]"));

        let sh = generate("sh").unwrap();
        assert!(sh.contains("VAULT_OPTION VAULT_PATH"));
        assert!(sh.contains("nkeepass \"$_nk_vault_option\" \"$_nk_vault_path\" __complete"));
        assert!(sh.contains("\"${6-}\""));
        assert!(sh.contains("files:add|attachment:add|attachments:add"));

        let zsh = generate("zsh").unwrap();
        assert!(zsh.contains("vault_args=(--vault"));
        assert!(zsh.contains("command nkeepass \"${vault_args[@]}\" __complete"));
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
        assert!(powershell.contains("& nkeepass @vaultArguments __complete"));
        assert!(powershell.contains("$cursorPosition -gt $commandAst.Extent.EndOffset"));
        assert!(powershell.contains("$currentIndex -le $commandIndex"));
        assert!(powershell.contains("$currentIndex -gt ($commandIndex + 1)"));
        assert!(powershell.contains("$commandIndex + 2"));
        assert!(powershell.contains("$commandIndex + 3"));

        let fish = generate("fish").unwrap();
        assert!(fish.contains("__nkeepass_complete_vault_args"));
        assert!(fish.contains("nkeepass (__nkeepass_complete_vault_args) __complete keys"));
        assert!(fish.contains("nkeepass (__nkeepass_complete_vault_args) __complete vaults"));

        let nushell = generate("nushell").unwrap();
        assert!(nushell.contains("nu-complete nkeepass vault-args"));
        assert!(nushell.contains("^nkeepass ...$args __complete keys"));
        assert!(nushell.contains("^nkeepass ...$args __complete vaults"));
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
                        || script.contains("__nkeepass_complete_vault_args")),
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
            .arg(". ./completion.sh; nkeepass_complete '' '' files; nkeepass_complete '' '' files add")
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
        for (shell, script, arguments) in [("zsh", generate("zsh").unwrap(), vec!["-n"])] {
            if std::process::Command::new(shell)
                .arg("--version")
                .output()
                .is_ok()
            {
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
    fn bash_binary_completion_preserves_prefix_and_rejects_non_set_contexts() {
        let bash = generate("bash").unwrap();
        let Ok(directory) = tempfile::tempdir() else {
            panic!("temporary directory should be available");
        };
        std::fs::write(directory.path().join("payload-one.bin"), b"").unwrap();
        let script = format!(
            r#"{bash}
COMP_WORDBREAKS=' = '
original_wordbreaks=$COMP_WORDBREAKS
COMP_WORDS=(nkeepass set --bin payload = ./payload)
COMP_CWORD=5
_nkeepass_complete
[[ "${{COMPREPLY[*]}}" == "./payload-one.bin" ]] || exit 11
[[ "$COMP_WORDBREAKS" == "$original_wordbreaks" ]] || exit 12
COMP_WORDS=(nkeepass set --bin payload=./payload)
COMP_CWORD=3
_nkeepass_complete
[[ "${{COMPREPLY[*]}}" == "payload=./payload-one.bin" ]] || exit 13
COMP_WORDS=(nkeepass exec -- set --bin payload = ./payload)
COMP_CWORD=7
_nkeepass_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 14
COMP_WORDS=(nkeepass set --bin first=old --notes ./payload)
COMP_CWORD=5
_nkeepass_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 15
COMP_WORDS=(nkeepass set -- --bin payload = ./payload)
COMP_CWORD=6
_nkeepass_complete
[[ "${{#COMPREPLY[@]}}" == 0 ]] || exit 16
"#
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .current_dir(directory.path())
            .output()
            .expect("bash should run");
        assert!(
            output.status.success(),
            "bash completion behavior failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
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
                r#"nkeepass --vault "/vaults/work vault.kdbx" get --key """#,
                "/vaults/work vault.kdbx",
            ),
            (
                "nkeepass -V '/vaults/my vault.kdbx' keys",
                "/vaults/my vault.kdbx",
            ),
            (
                "nkeepass --vault /vaults/plain.kdbx keys",
                "/vaults/plain.kdbx",
            ),
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
                "nkeepass --vault=/vaults/no.kdbx keys"
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
