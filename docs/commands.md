# Command and option aliases

Use this page to find alternate spellings. For the command's purpose,
invocation, options, output, and failures, open the linked reference page.

| Canonical spelling | Accepted aliases | Reference |
| --- | --- | --- |
| `alias ls` | `alias list` | [Vault, context, and alias commands](reference/vault.md#alias) |
| `alias rm` | `alias remove` | [Vault, context, and alias commands](reference/vault.md#alias) |
| `files` | `attachment`, `attachments` | [Attachments, groups, and custom fields](reference/entries.md#attachments) |
| `files ls` | `files list`, and the same under attachment aliases | [Attachments](reference/entries.md#attachments) |
| `files add` | `files import`, and the same under attachment aliases | [Attachments](reference/entries.md#attachments) |
| `files get` | `files export`, and the same under attachment aliases | [Attachments](reference/entries.md#attachments) |
| `files rm` | `files remove`, and the same under attachment aliases | [Attachments](reference/entries.md#attachments) |
| `config ls` | `config list` | [System commands](reference/system.md#config) |
| `config get` | `config show` | [System commands](reference/system.md#config) |
| `config rm` | `config remove` | [System commands](reference/system.md#config) |
| `context ls` | `context list` | [Vault, context, and alias commands](reference/vault.md#context) |
| `context rm` | `context remove` | [Vault, context, and alias commands](reference/vault.md#context) |
| `context use` | Root `use` | [Vault, context, and alias commands](reference/vault.md#context) |
| `exec` | `x` | [System commands](reference/system.md#exec) |
| `shell completions` | `shell completion`, root `completion` | [Shell integration](how-to/shell-integration.md) |
| `field` | `custom-field` | [Attachments, groups, and custom fields](reference/entries.md#custom-fields) |
| `field ls` | `field list` | [Custom fields](reference/entries.md#custom-fields) |
| `field get` | `field reveal` | [Custom fields](reference/entries.md#custom-fields) |
| `field set` | `field edit` | [Custom fields](reference/entries.md#custom-fields) |
| `field rm` | `field remove` | [Custom fields](reference/entries.md#custom-fields) |
| `group` | `groups` | [Attachments, groups, and custom fields](reference/entries.md#groups) |
| `group ls` | `group list` | [Groups](reference/entries.md#groups) |
| `group add` | `group create`, `group ensure` | [Groups](reference/entries.md#groups) |
| `group rm` | `group remove` | [Groups](reference/entries.md#groups) |
| `secrets ls` | `secrets list` | [Secrets commands](reference/secrets.md#list-and-search) |
| `secrets env` | `secrets environment` | [Secrets commands](reference/secrets.md#read-selected-values) |
| `secrets show` | Root `show` | [Secrets commands](reference/secrets.md#secrets-show) |
| `secrets ensure` | Root `ensure` | [Secrets commands](reference/secrets.md#secrets-ensure) |
| `secrets otp` | Root `otp` | [Secrets commands](reference/secrets.md#secrets-otp) |
| `secrets rm` | `secrets remove` | [Secrets commands](reference/secrets.md#secrets-rm) |
| Root `ls` | Root `list` | [Root shortcuts](reference/system.md#root-shortcuts) |
| Root `rm` | Root `remove` | [Root shortcuts](reference/system.md#root-shortcuts) |
| `version` | Root `--version` | [System commands](reference/system.md#version) |
| `-h` | `--help` | [Global flags](reference/system.md#global-flags) |
| `-V PATH` | `--vault PATH` | [Global flags](reference/system.md#global-flags) |
| `-k PATH` | `--key PATH` | [Secrets commands](reference/secrets.md#read-selected-values) |
| `-F FIELD` | `--field FIELD` | [Secrets commands](reference/secrets.md#change-entries-and-fields) |
| `-f PATH` | `--file PATH` | [Secrets commands](reference/secrets.md#change-entries-and-fields) |
| `-n NAME` | `--name NAME` | [Secrets env and files add](reference/secrets.md#read-selected-values) |
| `-o PATH` | `--output PATH` | [Export, files get, get, and inject](reference/secrets.md#read-selected-values) |
| `-y` | `--yes` | [Destructive removals](reference/secrets.md#secrets-rm) |
| `-B NAME=ENTRY` | `--bind NAME=ENTRY` | [System commands](reference/system.md#exec) |
| `-b NAME=FILE_PATH` | `--bin NAME=FILE_PATH` | [Secrets set](reference/secrets.md#change-entries-and-fields) |
| `-r KEY` | `--age-recipient KEY` | [Secrets commands](reference/secrets.md#read-selected-values) |
| `-i PATH` | `--age-identity PATH` | [Secrets commands](reference/secrets.md#change-entries-and-fields) |
| Shell completion name `powershell` | `pwsh` | [System commands](reference/system.md#completion) |

Root `ls`/`list`, `get` (including `get many`), `search`, `show`, `set`,
`rm`/`remove`, `ensure`, `otp`, `import`, `export`, `sync`, and `env` are
shortcuts for the same `secrets` subcommand. Root `use` is a shortcut for
`context use`. Root `inject`, `trust`, `untrust`, and `shell` (`init`,
`completions`, `load`, `unload`, `status`) live in
[System commands](reference/system.md) and
[Shell integration](how-to/shell-integration.md). The aliases `field-get`,
`field-set`, and `attachment-add` are internal dispatch action names, not public
command routes.
`__complete` and `__hook` are private protocols used by generated shell
completion and directory hooks, not public commands.

Entry selection accepts `--key PATH` or `-k PATH`; `get`, `set`, `rm` /
`remove`, `show`, `ensure`, `otp`, `field`, and `files` routes also accept the
entry path or alias positionally. `group add` and `group rm` accept a group
path positionally. Do not supply both forms. `PATH` may be an entry path or
configured entry alias (group routes take group paths). For a selector
beginning with `-`, place `--` after options immediately before it, such as
`nkp show -- -DashEntry`.
`--field` also accepts `-F`; `--file` accepts `-f`; `--name` accepts `-n`;
`--output` accepts `-o`; `--yes` accepts `-y`; `--bind` accepts `-B` (on
`exec`/`x`). On `env`, `--name` also accepts legacy `--env`.
`set` additionally accepts repeatable `--field NAME=VALUE`. Its `--value-file`
and `--value-stdin` sources alias `--file` and `--stdin`.
Generator `--chars` / `-c` aliases `--size`; class flags are `--upper` / `-U`,
`--lower` / `-L`, `--digits` / `-D`, and `--symbols` / `-S`. These apply to
`ensure` and to `set --generate`.
`--bin NAME=FILE_PATH` accepts `-b` and may be repeated. Short options are not
rewritten after an `exec --` child separator. The global vault option is
`-V PATH` or `--vault PATH` (accepted on vault-opening commands).
