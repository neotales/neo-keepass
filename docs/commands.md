# Command and option aliases

Use this page to find alternate spellings. For the command's purpose,
invocation, options, output, and failures, open the linked reference page.

| Canonical spelling | Accepted aliases | Reference |
| --- | --- | --- |
| `alias ls` | `alias list` | [Vault, context, and alias commands](reference/vault.md#alias) |
| `alias rm` | `alias remove` | [Vault, context, and alias commands](reference/vault.md#alias) |
| `attachment` | `attachments` | [Attachments, groups, and custom fields](reference/entries.md#attachments) |
| `attachment ls` | `attachment list` | [Attachments](reference/entries.md#attachments) |
| `attachment add` | `attachment import` | [Attachments](reference/entries.md#attachments) |
| `attachment get` | `attachment export` | [Attachments](reference/entries.md#attachments) |
| `attachment rm` | `attachment remove` | [Attachments](reference/entries.md#attachments) |
| `config ls` | `config list` | [System commands](reference/system.md#config) |
| `config get` | `config show` | [System commands](reference/system.md#config) |
| `config rm` | `config remove` | [System commands](reference/system.md#config) |
| `exec` | `x` | [System commands](reference/system.md#exec) |
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
| `secrets rm` | `secrets remove` | [Secrets commands](reference/secrets.md#secrets-rm) |
| Root `ls` | Root `list` | [Root shortcuts](reference/system.md#root-shortcuts) |
| Root `rm` | Root `remove` | [Root shortcuts](reference/system.md#root-shortcuts) |
| `version` | Root `--version` | [System commands](reference/system.md#version) |
| `-h` | `--help` | [Global flags](reference/system.md#global-flags) |
| `-V PATH` | `--vault PATH` | [Global flags](reference/system.md#global-flags) |
| `-r KEY` | `--age-recipient KEY` | [Secrets commands](reference/secrets.md#read-selected-values) |
| `-i PATH` | `--age-identity PATH` | [Secrets commands](reference/secrets.md#change-entries-and-fields) |
| Shell completion name `powershell` | `pwsh` | [System commands](reference/system.md#completion) |

Root `get`, `getx`, `search`, `show`, `set`, `ensure`, `otp`, `setx`,
`import`, `export`, `sync`, and `env` are shortcuts for the same `secrets`
subcommand. The aliases `field-get`, `field-set`, and `attachment-add` are
internal dispatch action names, not public command routes.
`__complete` is a private protocol used by generated shell completion, not a
public command.

Entry selection has one option spelling: `--key PATH`. `PATH` may be an entry
path or a configured entry alias. There is no `--entry`, `--selector`, or
`-k` option.
