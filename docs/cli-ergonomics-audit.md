---
title: Make the safe nkp command the shortest one
description: CLI contract inventory, reproducible discrepancies, and acceptance criteria for shorter commands without changing machine output.
visibility: public
status: draft
tags: [keepass, cli, security]
updated: 2026-11-21
---

# Make the safe nkp command the shortest one

**Baseline:** `54c733c`, `nkp 0.0.0-alpha.25`. **Decision:** make the existing root
shortcuts the primary interactive vocabulary; retain all supported explicit forms for
scripts. Fix accepted-but-ignored flags before adding shortcuts. Keep this ticket as the
single implementation checklist, not as a second shipped user reference.

User test: someone with only `nkp COMMAND --help` and one working example should be able
to select the right vault and object, choose the right input/output channel, and know
whether running it reveals a secret, modifies data, or does neither. Currently even that
person can ask for encryption and get plaintext, choose a global vault that is ignored,
or copy flags from help that the parser refuses.

Scope is CLI dispatch, credentials, config/context, completion, docs/examples, output,
and the CLI entry point into `tui`, not TUI internals, KeePass interoperability, or
cryptographic review. Parallel CLI/TUI safety work is **not** assumed present: reconcile
P0 and renderer ownership with its eventual diff, then rerun this ticket's tests on
the integrated tree. Do not reimplement existing safety fixes or inherit their
behaviour by assumption.

## Baseline inventory

Source map: [`main.rs`](../crates/nkeepass/src/main.rs) help declarations (roughly 40–975),
config/resolution (1253–1728), shared parsing/credentials (1902–2310), output (1729–1894,
3318–3625 and 5264–5370), validation and execution (3803–5162), init (5371–5944),
env/exec/config (5175–5263 and 5990–6577), and help/dispatch (6579–7434).
[`completion.rs`](../crates/nkeepass/src/completion.rs) owns completion.
Unless marked as exercised in **Verification**, the inventory describes source-inferred
behaviour, not a tested result.

### Grammar and global placement

- All argv must be UTF-8, including child argv. Values are space-separated tokens, not
  `--flag=value`, joined short forms, grouped shorts, or flag prefixes. Option
  values may look like switches; spellings are case-sensitive. Shared parser singleton
  duplicates, including mixed aliases, error. Exceptions are repeatables indicated below
  and a few hand-written grammars. Most refusals write `nkp: …` plus LF to stderr, status
  2; no structured diagnostic format. Child exit is the exception below. Help is a
  preflight scan, not normal parsing; it can succeed despite invalid arguments.
- `-V, --vault PATH` only before a route, once; may interleave with prefix credential
  options. Used by vault-opening routes, `init`, `context show`, and private authenticated
  completion. Accepted but ignored by `tui PATH`, `context ls/use/set/rm`, `alias`,
  `config`, static `completion`, and private completion kinds that do not open a vault.
  `version` and `--version` only work as the entire argument list; neither accepts `-V`.
  `-v` is absent. Empty argv renders root help. No `help ROUTE` command.
- `-h, --help` before a bare `--`; tokens already consumed as values aren't help.
  Prefer `nkp ROUTE -h`; help at the front selects the root. Help routes use the
  requested alias in `Usage`, fixed width 88, stdout, and no vault access. Unknown
  root routes and unknown nested `secrets`/`automation` routes don't qualify; other
  unknown nested actions can fall back to group help. `get` can dispatch a single
  selector while help mistakenly treats `many` after other options as a subcommand.
  `__complete` suppresses help interception so dash-leading prefixes remain data.
- Terminator: in `ls/search/config ls` it admits at most one remaining glob/query;
  in `get/set/rm` it admits at most one remaining selector (not in addition to an
  existing `--key`/positional); in `get many` it admits all remaining paths.
  `exec --` requires a child command and stops CLI rewriting/scanning.
  No general terminator for `init` or other option-parsed routes. Fixed-arity
  metadata commands and `tui` take their literal operands, not a generic terminator.
- `-k` (`--key`), `-F` (`--field`) and `-f` (`--file`) normalize before dispatch
  except when consumed as values or after `--`. Other implemented shorts:
  `-b` (`--bin`), `-c` (`--chars`/`--size` on generator routes),
  `-U/-L/-D/-S` (class flags), `-r` (`--age-recipient`), `-i` (`--age-identity`),
  `-h`, `-V`. No `-o`, `-y`, `--json` generally, `--color`, or color environment
  contract for the headless CLI at this revision.

### Vault, directories and credentials

| Setting | Actual resolution and exceptions |
| --- | --- |
| Active vault | `-V` → `NEO_KEEPASS_VAULT` / `NKP_VAULT` → `NEO_KEEPASS_VAULT_PATH` / `NKP_VAULT_PATH` → `current` → `default_vault` → app data `default.kdbx`. Explicit normal selection is an absolute normalized path or vault alias, never CWD-relative. First present env selects, even if empty/invalid (fails rather than falls through). Invalid selected aliases/paths do not silently switch vault. `context ls` describes persisted metadata, not the effective override. `init`'s positional or `-V` is a literal filesystem path, including CWD-relative, mutually exclusive; omission uses the normal active resolution. `tui PATH` takes its own literal path, no inherited unlock flags. |
| Directories | For app `CONFIG_DIR` and `DATA_DIR`, first `NEO_KEEPASS_…`, then `NKP_…` (exact app root); then `XDG_CONFIG_DIR` / `XDG_DATA_DIR`, then `XDG_CONFIG_HOME` / `XDG_DATA_HOME` (append `nkeepass`); then home `.config/nkeepass` / `.local/share/nkeepass`. Selected OS path must validate; no fallthrough on invalid/empty override. Home uses platform-specific candidates. Config is closed/private; never persist credentials to ease typing. |
| Explicit password | At most one of `--password-env NAME` (literal environment name, non-empty Unicode), `--password-stdin` (one UTF-8 line through LF/EOF, strips trailing CR, up to 64 KiB), `--password-file PATH` (bounded 64 KiB UTF-8 file, takes first CR/LF-delimited line), `--password VALUE` (non-empty, **unsafe argv compatibility**). Explicit source failure never falls back. Credential/value env name validation currently uses the same 1–128 ASCII letters/digits/hyphens/underscores grammar as aliases, not output variable identifier grammar. |
| Key file / implicit password | `--key-file PATH` adds an independent component to one explicitly chosen password, or is key-file-only if no explicit password source, suppressing environment and prompt. Without either, `NEO_KEEPASS_PASSWORD` then `NKP_PASSWORD`, first present (empty/non-UTF-8 refuses); no `NKEEPASS_*` fallback. Otherwise a non-echo prompt on terminal stdin, error on noninteractive stdin. `--password-stdin` conflicts with payload `--stdin`/`--value-stdin`; neither is an alias of the other. |
| Placement | All five credential flags after complete routes for `init`, `exec/x`, all root entry/interchange/env routes, and all valid `secrets`, `automation`, `files/attachment/attachments`, `group/groups`, `field/custom-field` actions. Only `--password-env` and `--password-stdin` also work before the command; duplicates across placements still fail. No credential flags on `context`, `alias`, `config`, `completion`, `version`, `tui`, or `__complete`. For `exec` they must precede child `--`. |
| Completion credential | `NEO_KEEPASS_COMPLETE_PASSWORD_ENV` then `NKP_COMPLETE_PASSWORD_ENV` names a variable with a password for completion only. Empty selected name disables; invalid/unavailable selected name fails; default password vars do not independently enable unlock. It never prompts, accepts no inline credential flags, and does not support key-file unlock. |

Only nonsecret metadata (selectors/aliases/config) should be persisted or suggested.
Host environment case semantics apply (Windows case-insensitive); no proposed
change to credential defaults, fallback, component composition, or security limits.

### Entry routes (one table for root and nested)

Root `ls/list`, `search`, `show`, `get`, `get many`, `set`, `rm/remove`,
`ensure`, `otp`, `env`, `import`, `export`, `sync` map to matching `secrets`
subcommands. Only nested `secrets environment` aliases `env`; bare `environment`
is not a root alias. `automation import/export/sync` map to the same interchange
handlers. Internal dispatch names (`field-get`, `attachment-add`, `get-many`, etc.)
are not callable routes. Table omits common credential/help/address flags.

| Route | Selectors and flags | Stdout / effect |
| --- | --- | --- |
| `ls/list` | Optional positional path glob, max 1024 bytes, quote shell metacharacters; no selector. | NDJSON `{fields,path,tags,title}`, safe redacted metadata in vault order, stderr withheld count when applicable. |
| `search QUERY` | Required nonempty metadata query up to 4 KiB, not the `ls` path glob. | Same row schema, bounded search, up to 1,000 emitted hits; withheld count possible, no explicit hit-cap marker. |
| `show` | `-k PATH` required, no positional. | Single redacted JSON line `path,title,tags,fields,attachments,has_otp,auto_type`; `path` can be the original selector or alias target, not necessarily canonical `ls` path. |
| `get` | Positional `PATH` or `-k PATH`; `-F FIELD` overrides an alias binding, else `Password`. `--format`, `--name`, `--is-output`, `--clipboard`, `--age-encrypt`, repeatable `-r`, `--output PATH`; see output rules below. | Explicit disclosure, raw bytes default; clipboard and ciphertext are exclusive delivery modes. |
| `get many` | First token after `get` must literally be `many`. 1–256 unique supplied paths, 64 KiB path budget; `-F FIELD` common to all, default Password even for bound aliases; `--format`, `--is-output`, `--age-encrypt`, repeatable `-r`, `--output`; no `-k`, `--name`, `--clipboard`. Single entry named `many`: `get -- many`, `get -k many`, or put options first. | Ordered bundle; validation before first disclosure; selected values ≤16 MiB total and rendered bundle ≤64 MiB; optional age encryption of the complete rendered bundle. |
| `set` | Positional `PATH` or `-k PATH`. `-F NAME` selects target (alias binding then Password by default); repeatable `-F NAME=VALUE` splits at first `=` and adds assignments. `--value VALUE`, `--value-env NAME`, `--value-file PATH`/`--file`/`-f`, `--value-stdin`/`--stdin`, `--generate`: at most one. File/stdin/env/literal are bounded to 16 MiB, exact bytes before UTF-8 validation/decryption, no newline trim. `--username`, `--url`, `--notes` are argv updates; repeatable `-b NAME=FILE_PATH` adds ≤256 attachments, 16 MiB aggregate, no clobber. No legacy field selector without a source alongside assignments; duplicate update names fail. `--age-decrypt` requires explicit ciphertext source, not `--generate`; optional `-i PATH` only with decrypt. | Silent on success; modifies an existing entry, creates missing custom fields, not `Title`, saves combined field/attachment changes only after all succeed (post-install durability errors remain possible). Without updates/attachments uses hidden value prompt (60 seconds; non-TTY refused), not a literal argv fallback. |
| `ensure` | `-k PATH` required; `-c N` / `--chars N` / `--size N`, `-U/--upper`, `-L/--lower`, `-D/--digits`, `-S/--symbols`, `--dry-run`. Same generator knobs for `set --generate` only. Default 16, maximum 4096; no classes selects all four; explicit classes select only those, each guaranteed; length must fit even on existing entries/dry-run. | Silent; creates missing groups and entry; existing entry/password stays unchanged. Dry-run no generation/save. |
| `rm/remove` | Positional `PATH` or `-k PATH`; mandatory `--yes`, no `-F`, no dry-run. | Silent; deletes whole entry; no prompt/undo. |
| `otp` | `-k PATH` required. `--format`, `--name`, `--is-output` as single get. No clipboard, age, or field override. | One TOTP code, never seed; HOTP refused. |
| `env/environment` | At least one ordered `-k PATH [-F FIELD] --name NAME` (long forms too), `--name` closes binding, names unique. Omission of field requires bound entry alias; `otp` denotes TOTP. `--format` defaults `shell`, all named formats plus `json/null`, no `text`. `--is-output` Azure only. | Plaintext stdout, validate common representation before emitting bindings; codes share one timestamp, expiry warning may go to stderr. **Bug:** `--age-encrypt`, `--age-decrypt`, `-r`, `-i`, `--clipboard`, `--allow-plaintext` can parse but do nothing. |

Entry selector ambiguity is a refusal, not an alias precedence trick. Optional root
group segment, slash-separated paths and case-insensitive ASCII matching; avoid
claiming undocumented alternate separators. Entry aliases may bind a field, used as
above (`get`, `set`, `env` only). Groups take group paths, not entry aliases. File
or direct-argv inputs are distinct from vault unlock inputs. `--age-identity` is one
bounded file (native or unencrypted SSH); otherwise first existing config
`init-password.agekey`, then `age/keys.txt` under XDG config/home. Existing unreadable
or invalid identity fails closed; no discovery for recipients. `-r` takes age/SSH
public key, `@FILE`, `gh:USER`, or explicit HTTPS via bounded, no-redirect `curl`
(64 KiB, five seconds); no unsolicited network lookup.

### Groups, files, fields, automation

| Family | All routes, operands and flags | Output/effect |
| --- | --- | --- |
| `files` / `attachment` / `attachments` | `ls/list [ENTRY] [-k ENTRY]`; `add/import [ENTRY] [-k ENTRY] -F NAME (-f PATH\|--stdin)`; `get/export [ENTRY] [-k ENTRY] -F NAME --output PATH`; `rm/remove [ENTRY] [-k ENTRY] -F NAME --yes`. No `--name` attachment selection, no basename inference, `--value-file`/`--value-stdin` invalid. | List NDJSON `{name,bytes,protected}`; add bounded binary (16 MiB), no replacement; get private no-clobber plaintext file, empty stdout; add and rm silent. |
| `field` / `custom-field` | `ls/list [ENTRY] [-k ENTRY]`; `get/reveal [ENTRY] [-k ENTRY] -F FIELD [--format …] [--name …] [--is-output]`; `set/edit [ENTRY] [-k ENTRY] -F FIELD (-f PATH\|--stdin)`; `rm/remove [ENTRY] [-k ENTRY] -F FIELD --yes`. No age, clipboard, general `set` assignments/generator or value aliases. | List all fields (including built-ins) as NDJSON `{name,protected,protect_in_memory}`. Get formats as single entry get; mutations silent. Exact built-in names refused for get/set/rm; verify case variants in the safety pass, do not teach a bypass. |
| `group` / `groups` | `ls/list`; `add/create/ensure [GROUP] [-k GROUP] [--dry-run]`; `rm/remove [GROUP] [-k GROUP] [--dry-run] [--yes]`; `--yes` mandatory unless dry-run. Positional and option selectors are mutually exclusive. | List paths one per LF; add ensures missing groups; rm recursive, never root; both silent, dry-run does not save or print a report. |
| `import` | `-f PATH` or `--stdin`, exactly one, up to 128 MiB; `--replace`, `--dry-run`, optional `--format keepass-xml`. Omit format for JSON; explicit `--format json` is refused. | JSON report (`operation`, `dry_run`, for JSON also `replaced`, model and password counts; XML has `format`). Nonempty vault requires `--replace`. |
| `export` | `--output PATH`; optional `--format keepass-xml` **with** `--allow-plaintext` (flag refused for default JSON); no explicit `--format json`. Hidden `--name NAME` parses but has no effect. | Private no-clobber plaintext output file (JSON or XML with limited support); stdout JSON `{operation,format,version,bytes}`. No raw snapshot stdout. |
| `sync` | `-f PATH` or `--stdin`, exactly one, up to 128 MiB JSON; `--strategy newest\|source\|target` default `newest`; `--dry-run`; no `--format` or `--replace`. | JSON report (operation, strategy, dry-run, group/entry and password counts). Newest prefers source on ties; source/target choose conflict side, not wholesale replacement. |

Every normal-operation row above except `get many` can silently accept
`--allow-plaintext`; `init` can as well. This is not a supported capability.
Further validator gaps: `init` ignores `--username/--url/--notes/-b`,
`--clipboard` and age flags; interchange ignores the same metadata/attachment
arguments and `--clipboard` but **rejects** age flags in all three namespaces.
`env` rejects the set metadata/attachment/value inputs, but has the no-ops above.
Reject unexpected flags before prompting or I/O, not by dropping them after parse.

### Vault administration and system routes

| Route | Operands and flags | Output/effect |
| --- | --- | --- |
| `init [PATH]` | `--json`, `--generate-master-password`, `--size N` (1–4096, separate seeded entry's generated password, not master), `--kdf aes\|argon2d\|argon2id`, `--memory KIB`, `--iterations N`, `--parallelism N`. AES default 600,000 rounds; Argon2 defaults 65,536 KiB, 10 iterations, 1 lane. Nonzero counts bounded by reader policy; memory/lanes only Argon2; library may refuse invalid combinations. `--chars/-c` invalid here. Generated master conflicts with explicit password or key file and doesn't consult ambient password. | Never overwrites. Adopt absent current selection on successful create, never silently replace existing current. Password-only encrypted backup + protected recovery identity; generated-master backup/association **before** vault installation, supplied-password backup **after** successful vault install; key-file credentials skip. Human database/context/recovery lines or one JSON object (path/source, context, KDF/parameters, generated-entry/master booleans, backup and identity paths, recovery/association/durability fields). Some post-install failures leave a file or emit a distinct recovery record on nonzero exit. Never prints the password. |
| `context ls/list [--json]`, `context show [--json]` | Optional JSON is the only route option. Only `show` uses global `-V` and environment precedence. | `ls` text alias/path/current rows plus unaliased current/unlisted default; JSON is deliberately alias-only NDJSON `{alias,path}`. `show` text `Name/Path/Source`; JSON `{path,source,alias}` reports alias only for context source (legacy). |
| `context set ALIAS ABSOLUTE_PATH`, `use ALIAS`, `rm/remove ALIAS` | Positional only. `set` only vault alias, `use` selects existing vault alias, removing active alias clears current. | Silent private config save. `set` doesn't select. |
| `alias ls/list`, `resolve NAME`, `set NAME TARGET [--kind vault\|entry] [--field FIELD]`, `rm/remove NAME` | Infer vault from absolute target else entry, vault target must be absolute and cannot bind field; name 1–128 ASCII alphanumerics/`-`/`_`, field nonempty/control-free. Replace can clear current if changed to entry; rm clears matching current. `-F` works on set. | NDJSON `{name,kind,target,field}` for list; resolve one line without `name`; mutations silent. |
| `config ls/list [GLOB] [--json]`, `get/show KEY`, `set KEY VALUE`, `rm/remove KEY` | Closed `aliases/current/default_vault`; 1024-byte listing glob, `--` supported there. Only scalar keys mutable, set to valid path or existing vault alias, rm fails if unset. | List text `KEY<TAB>VALUE`, unset key alone, aliases as count; JSON rows `{key,value}` with full map and null for unset. Scalar get bare value plus LF or error; map get JSON Lines. Mutations silent. |
| `exec/x` | One or more `-k PATH [-F FIELD] --env NAME`, then mandatory `-- COMMAND [ARG…]`. Actual parser pairs ordered key and env lists by index (allows `--env` first); field modifies last key only. Defaults to `Password` (not bound alias field); `otp` means TOTP. No `--format/--name/--yes` etc. Names must be ASCII shell identifiers; conflicts with existing/reserved env names refused. | No own success stdout; child gets allowlisted env plus only explicit values, no inherited unlock vars; stdout/stderr inherited. Password stdin gives child null stdin. Propagates child status (Unix signal `128+signal`) with static diagnostic. |
| `tui PATH`; `version` / `--version`; `completion SHELL`; no args | Exact operand counts; `tui PATH` does not follow active vault. Shell names `bash`, `sh`, `zsh`, `fish`, `powershell/pwsh`, `nushell`. | TUI terminal-owned output; version `nkp VERSION` plus LF; completion static LF script; no args root help. |

KDF maxima are the application's pinned reader limits, not the dependency
defaults: AES 100M rounds, Argon2 65,536 KiB / 10 iterations / 16 lanes, with a
reader combined-work cap of 655,360 KiB-passes; see `nkeepass/src/lib.rs` and
writer shape checks. Format-specific lower bounds may still apply. On a
successful `init` with no current selection, an explicit path is adopted
directly; an implicit target uses/creates `default` (suffix `-1`, `-2`, …
to avoid collisions).
The private `__complete KIND [PREFIX]` response is newline-separated sorted/filterable
metadata: `aliases`, `vault-aliases`, `vault-files`, `vaults` (union), `entries`,
`groups`, `keys` (aliases + authenticated entry paths and group prefixes ending in
`/`). Default prefix empty. No secret-value completions; completion opt-in still exposes
metadata to the local shell, bounded and ambiguity-filtered. File discovery searches
beneath CWD, excludes symlinks and unsafe/non-Unicode names, currently suggests
only `.kdbx` files in descendant directories (not directly in CWD), and bounds
the walk to 10,000 items/depth 16. Authenticated names have an index budget of
10,000 items/2 MiB and a 1,000 item metadata response budget. Static `sh` only
provides a helper, not standardized shell registration. Bash does dynamic `--bin`
file suffix completion with Bash 4+ Readline quoting guarantees.

### Value and presentation contracts

| Output choice | Current stdout bytes and restrictions |
| --- | --- |
| `text` | Single get/field get/otp: raw selected bytes, **no** newline. `many`: comma-separated values without escaping or trailing delimiter; not general CSV or lossless. `env` refuses `text`. |
| `null` | Single: raw bytes + one NUL (single renderer does not check embedded NUL). `many`: value + NUL per item. `env`: `name` + NUL + value + NUL per binding. Multi renderers refuse embedded NUL before output. This is a delimiter, never a discard mode. |
| `json` | Single `{ "value": "…" }` logically, compact plus LF; many maps literal supplied paths to values; env maps binding names to values. Requires UTF-8; JSON escapes C0 but baseline serializer is not a universal terminal-control filter (C1/DEL need a deliberate policy). Do not equate a JSON syntax guarantee with terminal safety. |
| Named `dotenv`, `shell`, `pwsh/powershell`, `github-actions`, `azure-devops` | Single requires `--name`; bundle derives from supplied literal paths (not normalization); env explicit bindings. ASCII `[A-Za-z_][A-Za-z0-9_]*`; valid UTF-8, no NUL/control except LF. Dotenv JSON-quotes values, shell and PowerShell quote literal values, GitHub uses a fixed `NKP_EOF` heredoc and refuses delimiter lines, Azure refuses LF and emits literal logging-command payload (destination percent-decoding is a documented caveat). `--is-output` optionally adds `;isOutput=true` on Azure only, not required for Azure normal variables. Case-fold collisions refused for GitHub/Azure/PowerShell and Windows dotenv, case preserved for POSIX shell/JSON. |
| `--age-encrypt`, `-r`, `--output` | Single plain `text` get only (no `--name`, `--is-output`, or clipboard); many permits encrypting its selected format. Requires explicit ≥1 recipient, `-r`/`--output` invalid without mode. Writes armor to stdout + explicit LF, or exact armor to new private file, without stdout. No auto-encryption guessed from suffix. |
| `--clipboard` | Single plain `get` only; UTF-8, no NUL, no stdout; intentional disclosure to OS clipboard. Baseline 30s lifetime on Linux/Windows (different ownership semantics), retention warning elsewhere; not guaranteed erasure. No clipboard implicit defaults. |
| Non-value display | Help/init/context are formatted text; group listing and config scalar output are also text but **pipeable contracts**, not decorative human output. All current NDJSON, static completions, and machine reports remain machine output even on a TTY. Withheld-count, unsafe-input, expiry, credential prompts and recovery errors go on the relevant existing channels; do not infer success from stdout alone. Closed-pipe handling is not unified (`json/print_line` return errors; help/version/completion use print macros). |

## Implementation ticket

### Completed slices

- [x] Review hold correction: Bash's root scanner accepts only actual root
  value options (`--vault/-V`, `--password-env`, and presentation color), not
  local-only `--password`, `--password-file`, or `--key-file`. Unknown root
  flags stop completion before any metadata query. Real Readline/stub tests
  exercise all three invalid root credential forms, including an ensuing
  `get --key`, alongside valid root password-env/stdin and local credential
  placements. Help begins scanning after consumed root-prefix values, so
  `-V -- x --help` and `-V -- get many --help` resolve their actual routes;
  the first `--` after `exec/x` still protects child help, even following an
  incomplete exec value option. Parser and binary-boundary regressions cover
  these cases. No assembled-base integration or workflow change is included.
- [x] Follow-up review: root option values retain ownership even when spelled
  `--`, `--color`, or `-V`. Exec normalization starts its separator boundary
  only after the parsed root route, and preserves root vault values verbatim.
  Bash now uses one root scanner for route, vault forwarding, and current-slot
  ownership instead of guessing from the previous word. Real Readline double
  Tab tests cover `nkp -V --color ` and `nkp --password-env -V `; the exact
  `-V -- x -k test --env OUT -- /bin/echo -k` normalization regression is pinned.
  Group docs show required selector alternatives and describe silent dry-run
  validation, not a nonexistent report. The required native fish/Nushell
  behavioral CI lane is specified in [CI/CD](ci-cd.md#required-follow-up-native-fish-and-nushell-behavior-lane);
  coordinating/enabling that lane remains CI automation work, not an implied
  native verification result or a workflow change in this correction.
- [x] Review correction: preserve argument ownership across presentation, help,
  exec, and completion. The earlier implementation discarded option tokens
  before deciding whether `many` was a subcommand, treated exec's separator as
  an option value, and styled diagnostics using an incomplete spelling list.
  Help now descends only through contiguous route tokens; diagnostic policy
  canonicalizes that same parsed route through the help alias table. `show`,
  raw `otp`, env/environment, and import/sync reports are machine routes even
  on failure. The private completion protocol is explicitly plain too.
  Exec consumes option values only within the slice before the first `--`
  after its route;
  normalization uses that same boundary, leaving child switches untouched.
  Help wraps before inserting SGR, and grouped selectors are required
  alternatives with destructive confirmation outside the selector group.
- [x] Forced color is accepted globally but never styles machine output or its
  diagnostics. This is a deliberate correction to the original P2 rejection
  proposal, not accidental ignored input; see the shipped
  [color contract](reference/system.md#human-output-color).
  Byte tests now require successful raw/no-newline, NUL, JSON, NDJSON, named
  shell, attachment-file, child, and interchange-report operations before
  comparing bytes. A self-export is not a valid sync fixture (UUID collision),
  so successful sync tests use an independent source vault.
- [x] Completion review correction: Bash handles actual Readline `--color`,
  `=`, `always` word splitting and forwards an ensuing explicit vault; a
  bounded PTY test exercises real Tab presses. Bash, zsh and PowerShell track
  the owner of the current option-value slot. Exec/x child boundaries stop
  static flags as well as metadata queries. Fish guards every registered rule
  and recognizes global color options when selecting/forwarding vaults.
  Nushell defines its referenced vault-alias completer and uses a capture
  replacement to decode escaped double quotes. Native fish and Nushell tests
  explicitly report unavailable interpreters and fail when the required-shell
  gate is requested; they are not native verification on this Linux host.
  The POSIX sh helper has no full argv and requires its caller to pass the
  documented seventh `AFTER_SEPARATOR` argument for child slots.
- [x] Reject ignored age-encryption requests on plaintext-producing or unrelated
  routes, retaining the valid `get`, `get many`, and `set` modes. Landed as
  `232ec6f` (cherry-picked from the standalone fail-closed guard).
- [x] Reject `--allow-plaintext` outside explicit KeePass XML export, reject
  export `--name`, and validate JSON-export acknowledgement before vault access.
  Integration assertions require the exact validation diagnostic with a missing
  vault, so a vault-lookup failure cannot satisfy the regression. Landed as
  `bd4c279` and `0c1bdfb`.
- [x] Add positional selectors for `show`, `ensure`, and `otp` in both root and
  `secrets` routes while retaining `-k` / `--key`, refusing duplicate selectors,
  and advertising/completing the path slot. Verification:
  `cargo +1.98.1 test --locked --offline -p nkeepass --test cli
  common_selector_shortcuts_are_advertised_with_legacy_key_forms` (1 passed),
  `cargo +1.98.1 test --locked --offline -p nkeepass --test output_modes
  metadata_subcommands_aliases_and_otp_are_non_disclosing_except_otp` (1 passed),
  `cargo +1.98.1 test --locked --offline -p nkeepass --bin nkp
  programmable_completions_forward_the_explicit_global_vault` (1 passed,
  including PowerShell script-contract assertions), and
  `cargo +1.98.1 test --locked --offline -p nkeepass --bin nkp
  bash_positional_key_completion_stops_at_selector_and_preserves_hostile_candidates`
  (1 passed). PowerShell runtime validation was unavailable because neither
  `pwsh` nor `powershell` is installed in the test environment.

### P0 — Must fix before broadening syntax

- [x] **Reject all disallowed flags, especially promises of confidentiality.**
  `env … --age-encrypt` prints plaintext successfully; `env … --clipboard`
  is similarly ignored by source inspection. Replace subtractive validation
  with a per-route allowlist (including options accepted but constrained by mode).
  Do not enable a new encryption mode just to make that invocation pass.
  Preserve established valid behavior; remove compatibility only for no-ops,
  document the rejection and replacement (`get … --age-encrypt`, `get many`,
  or secure external file handling). `--allow-plaintext` belongs only to XML
  export. Reject or explicitly migrate export `--name`; don't silently report
  success when no name is applied. Validate wrong flags/modes before reading
  credentials or payload and before fetching remote public recipients. Standards:
  Code ergonomics § Cognitive load, Defaults and configuration resolution,
  Trust boundaries and wire formats.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) via
  `AllowedOptions` / `validate_allowed_options` across regular, grouped,
  interchange, `init`, and `env` routes before credential/vault access;
  `exec_command` enforces its own closed `match args[i].as_str()` allowlist
  over `args[..sep]` before credential/vault access.
- [x] **One token reader for help, normal commands, env, exec, and completion
  metadata; no cross-routing by option-value accident.** Today `env` extracts
  binding flags by scanning arbitrary tokens and then scans for `--format`
  again; `exec` searches for the first bare `--` before consuming values.
  Ensure values, selectors, subcommand boundaries and literal `--` are interpreted
  by the same grammar, and never normalize child argv. For `exec`, preserve
  legacy nth-key/nth-env pairing (including env before key) if unambiguous;
  new compact form below is atomic. Reject colliding child variables before
  attempting spawn, with host case semantics (including explicit unlock env
  and pairs with case-only differences on Windows). Keep password stdin
  unavailable to child; no widening environment inheritance. Apply the
  `config get aliases` metadata checks to **both** `alias resolve` and `alias ls`;
  the two currently emit C1 controls from hand-edited configuration. Ensure
  diagnostics do not echo unsafe labels, arbitrary `argv[0]` or formatter values.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs): `parse_env_options`
  and `init_command` share `takes_option_value` / `options_from_refs`,
  `validate_exec_env_names_for_platform` enforces host case semantics,
  `alias ls`/`alias resolve` share `check_alias_metadata`, and diagnostics
  pass through `sanitize_terminal_text`.
- [x] **Separate terminal-safe display and raw output.** Coordinate with parallel
  CLI/TUI work on TTY controls, clipboard, password readers, and write errors.
  For headless CLI never feed untrusted controls to a display sink; allow only
  formatter-owned escapes. Treat explicit raw output redirected to a file/pipe
  as byte-preserving (including C0/C1). Define raw `text`/`null` on a terminal:
  refuse unsafe controls before first disclosure, with static guidance to
  redirect exact bytes to a trusted sink; permit normal multiline text if LF is
  intentional, never execute control bytes. NUL delimiter itself can remain
  in an explicitly chosen `null` protocol; do not silently suppress/change it.
  Protect JSON terminal displays without changing redirected wire bytes (e.g.
  valid JSON Unicode escapes on TTY or standardized refusal). Never add a
  color choice that bypasses safety. Keep XML opt-in, no-clobber, key-only
  semantics, fail-closed resolution and destructive confirmation.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) via
  `validate_tty_raw_bytes` (preserving LF/HT and `null` delimiters while
  refusing unsafe C0/ESC/DEL/C1/non-UTF-8 on TTY before first disclosure) and
  `TtyJsonFormatter` (escaping DEL/C1 as `\u00XX` on TTY without changing
  piped/redirected bytes).
  Verification: `cargo +1.98.1 fmt --all --check` (passed),
  `TMPDIR="$PWD/target/audit-tmp" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo +1.98.1 clippy --locked --offline -p nkeepass --all-targets` (exited 0 with baseline advisory warnings),
  `TMPDIR="$PWD/target/audit-tmp" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo +1.98.1 test --locked --offline -p nkeepass --no-fail-fast`
  (lib 132/132, `automation` 20/20, `cli` 64/64, `config` 29/29,
  `context_output` 11/11, `get_many` 7/7, `groups` 4/4, `hardening` 21/21,
  `init` 29/29, `output_modes` 20/20, `password_mode` 2/2, `root_credentials` 11/11,
  `set_generator` 4/4, `totp_binding` 11/11, `tui_ui` 15/15 passed; in this
  sandbox environment `color_output` had 9/10 pass with
  `auto_styles_help_only_when_stdout_is_a_tty` failing because `script` is not
  installed, and `--bin nkp` had 197/202 pass with 5 pre-existing
  `completion::tests` process-group cleanup assertions failing under sandbox PID 1
  zombie behavior), and `git diff --check` (passed).

### P1 — Less to type, without silent retargeting

- [ ] Lead with short existing actions (`ls`, `get`, `set`, `ensure`, `show`,
  `otp`, `rm`, `x`, `files`), explain namespace forms and aliases in the
  reference. Add **one unambiguous positional selector** for `show`, `ensure`,
  `otp`, `group add/rm`, `files ls/add/get/rm`, `field ls/get/set/rm`; duplicate
  flag + positional is an error. Let `--` mark selectors consistently; `init -- PATH`
  should be supported for dash-leading literal paths. Keep `get many` reservation
  and documented escape, not a renamed bundle route. Avoid auto-create on `set`,
  fuzzy fallback on `get`, or inferred deletion mode on `rm`.
  (P1-A: positional selectors, `--` selector terminator, and `init -- PATH` implemented in `main.rs`; reference/docs lead and examples remain for P1-B.)
- [x] Add one positional entry/group selector to `group add/rm`, `files`
  entry-scoped actions, and `field` entry-scoped actions. Legacy `-k` /
  `--key` stays available; duplicate forms fail before vault lookup, and `--`
  protects dash-leading selectors. Verification:
  `cargo +1.98.1 test --locked --offline -p nkeepass --bin nkp
  grouped_route_selectors_are_positional_without_changing_nested_selectors`
  (1 passed), `cargo +1.98.1 test --locked --offline -p nkeepass --test cli
  grouped_routes_reject_a_positional_and_flag_selector_before_vault_lookup`
  (3 routes passed), plus Bash completion and help tests below.
  Full verification: `cargo +1.98.1 test --locked --offline -p nkeepass`
  (all package suites passed).
  Field names and attachment names intentionally remain option-only to avoid
  confusing them with the entry selector; this does not complete the broader
  `ENTRY NAME` positional proposal below.
- [x] For noun-scoped `files` actions, add `ENTRY [NAME]` (where NAME is required
  except `ls`), `--name NAME` for attachment name, retain legacy `--field/-F`.
  Do not infer a file name or implicitly write to CWD. Retain explicit `-f` or
  `--stdin` (input) and explicit destination; add `-o` for every actual
  `--output` route. `field get/set/rm ENTRY FIELD` keeps existing `-F` path,
  distinct from `set -F NAME=VALUE`. Add `-y` for existing `--yes` only;
  spell out `--yes` in examples that teach destructive behavior. No fresh short
  aliases for literal passwords, plaintext opt-in, or security mode switches.
  Optional positionals must have individual slots, reject duplicate roles
  even if values are identical, require explicit placeholders or use the
  named form when mixing would be ambiguous. Do not add `-f` for format.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) (P1-A): `Positional::KeyAndField`, `Positional::KeyAndAttachment`, `-n`/`--name` on `files add/get/rm`, `-o` on `get`/`get many`/`files get`/`export`, `-y` on `rm`/`files rm`/`field rm`/`group rm`.
- [x] Add `export DEST` and `import/sync SRC` as exact aliases of
  `--output` and `--file`; no extension-based format, no magic `-`, no
  ambiguity with `--stdin`. Add explicit `--format json` for default snapshot
  operations accepting `--format`; keep `sync` JSON-only. Use `--format` for
  encodings; keep existing `--json` convenience only on the report/context/config
  routes and don't turn it into a global switch. Keep `--chars/-c` generator
  vocabulary, `--size` alias; explain `init --size` separately as a generated
  entry, not a KDF or master setting (optional explicit long alias
  `--entry-password-length`, not a new required spelling).
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) (P1-A): `Positional::Output` (`export DEST`), `Positional::File` (`import`/`sync SRC`), explicit `--format json` on `import`/`export`.
- [x] Add compact repeatable `--bind NAME=ENTRY` (short `-B`) to `exec/x`,
  defaulting to Password as today. Split at first `=`, validate NAME, keep ENTRY
  as one quoted literal argument, no inline field delimiters that collide with
  paths. Keep explicit field bindings using existing `-k/-F/--env`. For env,
  first add `-n` as alias to `--name` (also single get/otp/named field get,
  plus files attachment NAME if parser/route semantics are clear); leave no-field
  `env` requiring a bound alias. Do not silently harmonize `many`/`exec`/`env`
  field defaults with single-get bound fields: it can disclose a different
  secret. If compact and legacy binding forms are mixed, refuse rather than
  re-pair or change order. Do not shorten by encouraging `eval` or exposing
  values through argv.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) (P1-A): `-B`/`--bind NAME=ENTRY` on `exec`/`x` (refusing mixed compact/legacy forms and leaving `--` child argv untouched) and `-n` -> `--name` on `env`/`get`/`otp`/`field get`/`files`.
- [x] Shorten context persistence with `nkp use ALIAS` as a synonym for
  `context use ALIAS`, and accept explicit absolute `PATH` there as a new
  selector form (no CWD inference; store path, not credentials). Keep `context
  set ALIAS PATH` separate from `use`, and `-V ALIAS` for a one-off; `context
  show` reports the effective source and warns in docs when environment wins
  over persisted selection. For `-V` on non-consuming routes, fail clearly,
  never accept-and-ignore a destination; implement `-V PATH tui` only if the
  other workstream agrees to route it explicitly and safely (otherwise point
  users to `tui PATH`). No implicit nearest vault, directory search, auto-unlock,
  stored password, overwrite, or silent context switch.
  Implemented in [`main.rs`](../crates/nkeepass/src/main.rs) (P1-A): `nkp use ALIAS_OR_PATH`, absolute normalized path support in `use` and `context use`, and `-V`/`--vault` rejection on non-consuming routes (`tui` points to `nkp tui PATH`).

Shortest common workflows (typed characters including spaces, no newline;
placeholders are literal example lengths; assumes the correct active vault
and existing entries except `ensure`, and terminal prompts when needed):

| Task | Baseline → recommended | Characters |
| --- | --- | --- |
| List redacted metadata | `nkp secrets ls` → **already** `nkp ls` | 14 → 6 |
| Create if absent | `nkp secrets ensure --key Demo/mail` → today `nkp ensure -k Demo/mail` → `nkp ensure Demo/mail` | 34 → 23 → 20 |
| See descriptors | `nkp secrets show --key mail` → today `nkp show -k mail` → `nkp show mail` | 27 → 16 → 13 |
| Copy selected secret | `nkp secrets get --key mail --clipboard` → **already** `nkp get mail --clipboard` | 38 → 24 |
| Update from hidden prompt | `nkp secrets set --key mail` → **already** `nkp set mail` | 26 → 12 |
| OTP | `nkp secrets otp --key mail` → today `nkp otp -k mail` → `nkp otp mail` | 26 → 15 → 12 |
| Add attachment | `nkp files add --key mail --field note --file ./note` → `nkp files add mail note -f ./note` | 51 → 33 |
| Extract attachment | `nkp files get -k mail -F note --output ./copy` → `nkp files get mail note -o ./copy` | 45 → 33 |
| Explicit deletion | `nkp secrets rm --key mail --yes` → **already** `nkp rm mail --yes` (optional `-y`) | 31 → 17 (14) |
| Inspect snapshot without writing | `nkp secrets import --file snapshot.json --dry-run` → `nkp import snapshot.json --dry-run` | 49 → 34 |
| Run trusted child with explicit binding | `nkp exec --key mail --env TOKEN -- client` → `nkp x -B TOKEN=mail -- client` | 41 → 29 |
| Persist named selection | `nkp context use work` → `nkp use work` | 20 → 12 |

For repeated work: set an alias once (`nkp context set work "$HOME/work.kdbx"`),
select it once (`nkp context use work`, proposed `nkp use work`), check
`nkp context show`, then run `nkp ls`, `nkp show mail` or `nkp get mail --clipboard`.
This saves retyping a vault path, **not** authentication. First successful
`init` may already adopt a fresh context; when testing or scripting keep explicit
targeting, and do not assume adoption with an existing selection or env override.
For a one-off use `nkp -V work ls`; prefer short forms in tutorials with the long
equivalent beside the first use. Do not hide sensitive operations behind a default
listing, confirmation, output name, or clipboard sink.

### P1 — Help, completion and documentation must agree

- [ ] Drive route aliases, option names/arity/repeatability/defaults, valid enum
  values and binding/operand completion from one command schema or one checked contract.
  Help should show “Usage, common example, command options, credentials” without
  duplicated password rows or unconditional warnings on unrelated commands. Keep
  warnings at point of use (argv, clipboard, secrets disclosure, export, stdin roles,
  post-install failures). Mark default/optional options and exclusive groups accurately.
  Keep help both `-h/--help`; `help ROUTE` is optional only if backed by the same grammar.
  Match actual initiated route, particularly `get --field Password many -h` vs
  `get many -h`; unknown actions/options shouldn't disguise themselves as valid
  subcommand help. Handle `exec -- CHILD --help` without interception.
- [ ] Fix actual baseline help issues: root `rm` wrongly offers `--field` and says
  it removes a field; `field rm` synopsis omits mandatory `--yes`. `field get`
  inherits unsupported age/output/clipboard flags; `field set` inherits wrong
  generator/assignment/env/stdin alias and age/specific metadata/binary flags;
  render only the field parser contract. `otp`, groups and other subset routes
  must use dedicated selector summaries, not advertise Password defaults or
  attachment names as fields. Group/ensure dry-run help promises a report although
  stdout is empty. Context JSON help hides its legacy alias-only schema.
  Root shortcuts need full usage, not generic `[OPTIONS]` where selection is
  mandatory. `set -F` aliases, group `-k`, `env/exec -k/-F`, and alias `-F`
  work but are inconsistently shown. Finite `--format` choices differ between
  env/get/interchange; `completion SHELL` should enumerate shells. Remove fake
  options represented as help labels (e.g. “Path keys”) from option inventory;
  keep as explanatory notes. Avoid a global `-V` legend on non-consuming routes.
- [ ] Fix static and dynamic completion, not just root command words.
  Bash/POSIX omit valid init JSON/generated-master, import/export XML flags
  and often route shorts/help; Bash misses `tui` and `exec --field`, POSIX
  root vocabulary is much shorter. Context `--json` and several nested options
  are under-advertised; Nushell's context externs omit JSON and its nested
  single get/set/rm are still flag-only. Fish's “seen subcommand” selectors can
  offer top-level entry flags for nested look-alikes (e.g. `rm --field`,
  `field get --age-encrypt`); stop completing based only on a verb anywhere in
  argv. PowerShell hand-maintains another route/value switch table, with the
  same missing XML/init switches and short-option drift. Zsh also omits init
  switches and uses action cases instead of the parser's route contract.
  Match `secrets environment` and all family aliases to canonical option
  specs; include `sync target` rather than deleting a valid choice.
  `config set/rm aliases` should not be suggested;
  custom-field get should not suggest forbidden built-ins; when completing
  a format/mode only offer supported values. Test all seven shell spellings
  (`pwsh` aliases `powershell`, POSIX `sh` helper intentionally limited).
  Complete selectors and paths only in the correct slot, preserve special
  characters and leading dashes, forward explicit vault, and never query
  after the exec separator or for password/value/env-source tokens. Preserve
  Bash `--bin` `=`/filename behavior. Include safe current-directory `.kdbx`
  files in explicit path completion rather than broadening search roots. No
  new vault unlock, prompt, broader traversal, or environment name enumeration
  without explicit opt-in.
- [ ] Fix shipped docs alongside new help:
  - [Credentials](reference/credentials.md) and [system](reference/system.md):
    replace contradictory short-form claims, list exact `--` and root-prefix
    rules, add `files` to credential prose, correct `exec` prefix placement.
    Replace CWD-relative `--vault ./tutorial.kdbx` example with an actual
    tutorial path or context; there is no `tutorial.kdbx` from setup.
  - [Secrets](reference/secrets.md) and [automation](reference/automation.md):
    remove stale claims that interchange ignores age flags (it rejects);
    remove/give migration for no-op export name. Cover XML flags and `target`
    merge semantics in all routes and [how-to](how-to/automation.md).
    Tidy `--is-output` as optional, not required for Azure. State single versus
    bundle framing and route-specific alias defaults where users choose a field.
    Update env's warning to document refusal after P0, not to normalize no-ops.
  - [Entries](reference/entries.md), [attachments](how-to/attachments.md),
    [age](how-to/age.md): update noun and positional forms, selectable fields,
    dry-run silence/report choice, exact name/attachment/input switches.
    Make clipboard, file permissions and known platform differences discoverable.
  - [Vault](reference/vault.md), [selection](how-to/vault-selection.md),
    [tutorial](getting-started.md), [README](../README.md): show first-init
    persistence and one-off explicit targeting as distinct workflows. Keep
    unmistakable disposable setup, environment caveats, and encrypted recovery
    instructions; trim redundant `secrets`, `--key` and default Password flags.
    Show actual no-newline value bytes and distinguish hidden prompt vs environment.
  - Update [alias index](commands.md) (and index links) with all root/nested
    exceptions, canonical short workflows, old-to-new equivalences. Keep
    [XML notes](keepass-xml-interchange.md) linked, including partial-install
    durability and independent interoperability limits. Do not duplicate
    a second flag catalog in each guide. Run examples from a clean profile.

### P2 — Human render and color contract (not a wire change)

- [ ] Add opt-in human metadata output (`--format human` on listings/descriptors
  where a user actually benefits). Keep current default raw/text/JSON/NDJSON
  schemas and status codes on **both** TTY and pipes; don't auto-reformat by
  detecting stdout. Can improve existing help, context and init human layout
  without changing parseable fields, order or pipe defaults. Group listings,
  `config get`, `version`, and completion remain plain. Use concise labels and
  a no-color semantic cue (e.g. current marker) instead of relying on color.
  Escape/withhold unsafe labels first; bound/truncate human rows only with a
  visible marker; handle Unicode column width and narrow terminals. Machine
  formats keep exact bytes: no headers, footers, styling, added newline, ANSI
  reset, or progress.
- [ ] Implement CLI presentation `--color auto|never|always|basic|truecolor`
  and `--no-color` alias `never` on actual presentation routes, once only.
  Explicit policy wins over env; absent CLI, nonempty `NO_COLOR` wins over
  `FORCE_COLOR`; empty `NO_COLOR` is absent. For human styling only,
  `FORCE_COLOR=0` disables, `1`/`true`/empty enables basic, `2` enables
  256-color if safely supported (or fall back to basic), `3` enables
  truecolor; invalid treated as absent. Without overrides, **auto** needs a
  suitable TTY for that stream and `TERM` not dumb; use basic if depth
  unknown, truecolor only with capability (`COLORTERM=truecolor/24bit` or
  verified equivalent), none for unsupported Windows terminals. An explicit
  CLI `auto` uses capability, not ambient force/no-color. Explicit force
  (`always` chooses capability/basic; `basic`/`truecolor` request depth)
  can tint explicitly human output piped to a color-aware pager, never raw,
  files, machine formats, completion, or child output. Explicit
  color policies are accepted on every route but ignored on operations with
  no human output. This deliberately supersedes the original proposal to
  reject forced color on data routes: a presentation flag must not break an
  otherwise valid scripted command. Machine diagnostics are plain as well.
  Global environmental policy never errors and is always
  ignored by those sinks. Plain `never` produces no app-added ANSI, even on
  TTY. Force cannot override unsupported terminal safety or metadata
  sanitization. No OSC, hyperlinks, cursor control, or secrets rendered by
  styling code. Evaluate stdout and stderr capabilities independently;
  keep machine-mode diagnostics plain. Publish exact precedence and examples.
- [ ] Normalize output failure and status language. Never panic on broken
  pipe (including help/version/completion); return a consistent documented
  controlled disposition without confusing post-mutation failures with
  rollback. Document stable categories/statuses before introducing any
  machine diagnostic schema. Describe `ensure/group` dry-run as silent
  validation unless an **explicit** report is designed; don't add default
  status chatter to existing silent commands. Standards: Code ergonomics
  § Error content, Repetition and partial failure, Compatibility and deprecation.

## Acceptance tests and release checks

1. **Parse matrix:** each public action × each declared flag/short and
   incompatible flag; aliases equivalent, hidden internals fail; distinguish
   absent/empty, bad numbers, duplicates, duplicate selector spellings, values
   equal to switches, alternate option positions, dash-leading selectors,
   `get many` reservation, and exact `exec` separator. Exercise at real binary
   boundary with empty stdin and nonexistent vault to verify a refusal precedes
   prompts/file changes; also use a disposable populated vault so a wrong
   command cannot falsely pass because unlock failed.
2. **Credential/safety matrix:** both env prefixes, empty/invalid higher
   priority, `-V` precedence, explicit source missing, prefix + local
   duplicate, key-only vs password+key-file, stdin roles, no mutation on
   refused combinations. `env --age-encrypt` / `--clipboard` and all
   other foreign options must fail nonzero with empty stdout; check both
   namespaces/root variants. Verify XML acknowledgement, no-clobber,
   generator policies, context adoption vs explicit/env overrides, and
   no confirmation relaxation. Assert no secret values in stderr; run child
   argv/environment tests (Windows case-fold collisions included).
3. **Byte golden tests:** raw default/no newline, literal commas, NUL framing,
   JSON/NDJSON schema, LF, ordering, name quoting/collision, refusal before
   first record, private output file bytes, clipboard/no stdout, age armor
   decrypt round-trip with local test keys, and pipe-close error. Run color
   policy with redirected stdout vs real PTY, each stream independently;
   include controls, `TERM=dumb`, `NO_COLOR`/`FORCE_COLOR` conflict, basic,
   256, truecolor, `never`, explicit force, and invariance of raw/machine/file
   outputs. No shared TTY, real clipboard, ambient credentials, or network
   dependency in the default gate.
4. **Discoverability:** table-driven all-route help, aliases, defaults and
   per-route release CLI examples; assert every suggested flag/value is
   accepted when prerequisites are met and all documented flags are
   discoverable. Behavioral completion tests in six shell implementations
   (seven accepted spellings), with a required availability lane instead
   of silently skipping; context switching, authenticated vs default
   completion, filenames and field/binding boundaries. Use the integration
   harnesses already in `crates/nkeepass/tests` and the completion CI gates
   described in [CI/CD](ci-cd.md).
5. **Compatibility review:** keep valid spellings and default bytes; call
   out intentional changes for previously ignored switches, unsafe TTY raw
   controls and rejected inapplicable `-V`, with replacement usage. Positional
   and short aliases must be additive and never reinterpret an accepted
   long form. No silent retarget, weaker KDF, auto-unlock, unconfirmed mutation,
   accidental new stdout, or release claim from partial verification.

## Verification

### Review correction environment

All review-correction commands use the pinned toolchain explicitly:

```sh
cargo +1.98.1 fmt --all --check
TMPDIR="$PWD/target/audit-tmp" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +1.98.1 test --locked --offline -p nkeepass
TMPDIR="$PWD/target/audit-tmp" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +1.98.1 clippy --locked --offline -p nkeepass --all-targets
git diff --check
```

Executed successfully on the final correction tree: all package test suites
passed (179 binary tests, 64 CLI integration tests, 10 color tests, plus the
remaining library/integration suites). Formatting and diff checks passed.
Pinned Clippy exited zero with the advisory warnings described below.
Direct isolated repros now produce `get [PATH]` help for
`get --field Password many --help`, a plain status-2 diagnostic for forced-color
`show missing`, and `missing argument` before vault access for
`x --key -- /bin/echo -k`.
The root-owned-value follow-up reproduced the normalization failure before
the fix; final binary tests also passed after tightening the real Readline
driver handshake. Required native-shell mode was separately checked to
fail for missing fish/Nushell rather than silently yielding.
The root-grammar/help hold reproduced both failures before correction. Its
package test and Clippy commands were additionally bounded with
`timeout --kill-after=10s 300s`; both exited zero, followed by successful
formatting and diff checks. Clippy's advisory-warning caveat still applies.

The private scratch directory avoids this host's `/tmp` quota; no shared
scratch is deleted. Fixtures contain only generated/public test data and use
isolated application directories. Color PTY tests use Linux `timeout` with a
25-second deadline and two-second kill allowance; the Python stream driver
also bounds reads and child waits. The real Bash/Readline driver runs under
the existing bounded, process-group-owned test harness.

Native coverage here is Linux Bash 5.3 and POSIX sh, plus real PTY color and
Readline tests. zsh, fish, PowerShell, Nushell, macOS Bash 3.2, and Windows
remain **unverified natively** on this host. Native fish/Nushell behavioral
tests are included, but an unavailable interpreter is not evidence they passed.
Windows styling deliberately stays plain until terminal support is detected;
no Windows truecolor claim is made. Existing documentation/Debug/dead-code and
Clippy advisory warnings (including the repository's test-fixture unwrap/expect
convention) remain; successful Clippy exit is not a warning-clean claim.

### Original baseline probes

Pinned Linux build succeeded (`cargo +1.98.1 build --locked --offline -p nkeepass
--bin nkp`, `CARGO_TARGET_DIR="$PWD/target"`, `TMPDIR="$PWD/target/audit-tmp"`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_INCREMENTAL=0`); baseline Rust documentation
and `Debug` warnings remain. An initial external scratch build hit tmpfs quota;
retry with a private scratch under the ignored build directory succeeded.

Subprocess probes used an otherwise empty environment with controlled `PATH`,
`HOME`, `NKP_CONFIG_DIR`, `NKP_DATA_DIR`, plus `NO_COLOR=1 FORCE_COLOR=3
COLORTERM=truecolor`. No real secrets, remote access, clipboard, or PTY. Test
setup in a fresh private directory (all values here are public test data):

```sh
printf 'public-demo-fixture\n' | nkp init "$scratch/sample.kdbx" --json --password-stdin
printf 'public-demo-fixture\n' | nkp --password-stdin ensure -k Demo/mail
printf 'public-demo-fixture\n' | nkp --password-stdin ensure -k Demo/next
printf 'public-demo-fixture\n' | nkp --password-stdin set Demo/mail -F Password=demo -F UserName=demo-user
printf 'public-demo-fixture\n' | nkp --password-stdin set Demo/next -F Password=next
```

Tested every help route in the inventory, including all nested alias
permutations and both get-many routes: 127 spellings including the empty
route × `-h/--help` = 254 status-0 stdout usage responses, empty stderr, no
escape bytes. This checks rendering presence, not validity of each advertised
option. `exec --help` contains `--password-env` three times; `get --field
Password many --help` shows `get many` incorrectly. Generated all seven
completion spellings (status 0, stdout LF/no ESC, no stderr); Bash/POSIX
scripts passed `bash -n` and `sh -n`. Shell interaction findings above are
source-inferred unless stated here.

With the fixture prefix `printf 'public-demo-fixture\n' | nkp --password-stdin`,
these route tails produced:

| Route tail | Observed result |
| --- | --- |
| `get Demo/mail`, `get Demo/mail --format json`, `get Demo/mail --format null` | 0, stdout exact `demo`, `{"value":"demo"}\n`, `demo\0` respectively |
| `get many Demo/mail Demo/next [--format json\|null]` | 0, exact `demo,next`, `{"Demo/mail":"demo","Demo/next":"next"}\n`, `demo\0next\0` |
| `env -k Demo/mail -F UserName --name USER_DEMO --age-encrypt` | 0, plaintext `export USER_DEMO='demo-user';\n`, empty stderr |
| `env -k Demo/mail --name USER_DEMO` | 2, `--field required`, empty stdout |
| `exec --env DEMO_NKP_AUDIT -k Demo/mail -- /bin/sh -c 'printf %s "$DEMO_NKP_AUDIT"'` | 0, `demo`, demonstrates legacy env-before-key pairing and Password default |
| `ls --allow-plaintext`, `files ls -k Demo/mail --allow-plaintext` | 0, ordinary listing (files list empty), flag ignored |
| `show Demo/mail`, `rm Demo/mail -F UserName --yes`, `get Demo/mail --color always` | 2, no stdout |
| `ensure -k Demo/mail --dry-run`, `group rm -k Demo --dry-run` | 0, stdout and stderr empty; no `--yes` needed on the latter |
| `field get -k Demo/mail -F UserName --age-encrypt` | 2, rejects age before field selection |
| `export --output "$scratch/snapshot.json" --name IGNORED` | 0 and usual JSON report; requested name not present |
| `sync -f "$scratch/snapshot.json" --strategy target --dry-run` | Reached service and refused fixture UUID collision, not invalid strategy; acceptance of `target` also independently traced to service parser |
| `export --format keepass-xml --output "$scratch/snapshot.xml"` | 2 with plaintext acknowledgement diagnostic |
| `search Demo`, `show -k Demo/mail` | 0, redacted JSON; `search` reported `Root/Demo/mail`, `show` reported supplied `Demo/mail` |

Without credential prefix: `context show` reported the unaliased initialized path
from `context`; `context ls --json` emitted zero rows; `config ls --json` emitted
three compact rows (`aliases`, `current`, `default_vault`); `version` printed
the version. `-V ABSOLUTE_PATH version`, prefix `--password-file unused get
Demo/mail`, and `help get` all exited 2; `-V ABSOLUTE_PATH completion bash`
exited 0 and produced the static script.

Not verified here: interactive terminal restore, actual completion keystrokes,
PowerShell/Fish/Zsh/Nushell execution, platform clipboard/ACLs, remote recipient
lookup, independent vault interoperability, full workspace tests, and pending
safety work. This is an audit commit, not a claim that the checklist is implemented.

Additional isolated probes: `__complete vault-files` returned only the nested
candidate, not the vault in CWD; `__complete entries` gave an empty response until
`NKP_COMPLETE_PASSWORD_ENV=PUBLIC_FIXTURE` selected the synthetic fixture password,
then returned the two full entry paths. `env -k Demo/mail -F UserName --name DEMO
--password-env --key` split the option-value token `--key` despite it being
valid under the explicit password-name grammar, exiting 2 with “missing argument”.
Injecting a synthetic `U+009B` into an alias target in the disposable private
config made both `alias ls` and `alias resolve demo_bad` emit raw UTF-8 C1 bytes
in captured stdout; no terminal was used for that output.

The focused baseline integration run passed all 97 tests:

```sh
cargo +1.98.1 test --locked --offline -p nkeepass \
  --test root_credentials --test get_many --test context_output --test config \
  --test groups --test automation --test output_modes
```

`cargo +1.98.1 fmt --check` passed. The audit's Markdown table column counts
and relative file link targets were checked locally.
