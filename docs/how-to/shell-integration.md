# Shell Integration, `.nkp.toml`, and Secret Injection

Use `nkp shell init`, `.nkp.toml` project manifests, `nkp trust`, and `nkp inject` to switch vaults automatically by directory and inject secrets into commands or environment files without storing plaintext credentials in shell history.

## Enable shell integration (`nkp shell init`)

Add `nkp shell init <shell>` to your shell profile for `bash`, `zsh`, `fish`, `powershell` / `pwsh`, or `nushell`:

```sh
# Bash (~/.bashrc)
eval "$(nkp shell init bash)"

# Zsh (~/.zshrc)
eval "$(nkp shell init zsh)"
```

```fish
# Fish (~/.config/fish/config.fish)
nkp shell init fish | source
```

```powershell
# PowerShell ($PROFILE)
nkp shell init pwsh | Out-String | Invoke-Expression
```

```nu
# Nushell ($nu.env-path or config.nu)
nkp shell init nushell | save --force ~/.cache/nkp-init.nu
source ~/.cache/nkp-init.nu
```

Pass `--no-completion` to skip programmable completion wiring, or `--no-env` to wire only completions without the directory hook.

> **POSIX `sh`:** Directory hooks are not supported for plain POSIX `sh`, because it has no standard prompt/directory-change hook API. You can still load static completions with `nkp shell completions sh` or `nkp completion sh`.

## Configure a project manifest (`.nkp.toml`)

Create a `.nkp.toml` (version `1`) in your project root to bind a default vault alias (or normalized absolute vault path) and declare secret environment bindings:

```toml
version = 1
vault = "work"
inherit = "stop" # or "merge" to inherit parent trusted .nkp.toml manifests

# Optional env template files (mutually exclusive: use env_file OR env_files)
env_file = ".env"
# env_files = [".env", ".env.local"]

[env]
API_TOKEN = "services/api"
DB_PASSWORD = { entry = "databases/app", field = "Password" }
NPM_TOKEN = { entry = "npm/ci", field = "token" }
```

Manifest limits enforced by `nkp`:
- Maximum file size: 64 KiB
- Maximum `[env]` bindings per manifest: 256
- Maximum directory walk depth: 64; maximum `inherit = "merge"` hops: 8
- Maximum distinct referenced vaults across merged manifests: 4
- `env_file` and `env_files` paths must be relative to the manifest directory (up to 16 files in `env_files`), and `vault` must be a configured alias or normalized absolute path.

## Write `.env` templates with `nkp://` references

In files referenced by `env_file` / `env_files` (or passed directly to `nkp inject` or `nkp x --env-file`), reference vault secrets using `nkp://` URIs:

```dotenv
# Whole-value reference (defaults to Password)
API_TOKEN=nkp://services/api

# Specific field or TOTP code (#otp), or another vault alias (@prod/)
DB_USER=nkp://@prod/databases/app#UserName
OTP_CODE=nkp://services/github#otp

# Inline template substitution inside larger strings
DATABASE_URL=postgres://app:{{nkp://databases/app#Password}}@db.internal:5432/app
```

Encode reserved URI characters (`%`, `#`, `@`, spaces, etc.) with percent-encoding (`%HH`). `nkp` performs single-pass, non-recursive replacement.

## Trust a directory before loading (`.nkp.toml`)

`nkp` never executes or loads an untrusted `.nkp.toml` automatically. Inspect the manifest first, then trust its directory:

```sh
nkp trust
nkp trust ./path/to/project
```

Manage trusted paths with:

```sh
nkp trust --list
nkp trust --list --json
nkp trust --prune
nkp untrust
nkp untrust --all
```

If an ancestor manifest is reached via `inherit = "merge"`, `nkp` checks trust along the manifest chain as well.

## Inspect, load, and unload directory state

Check what `nkp` detects for the current directory:

```sh
nkp shell status
nkp shell status --json
```

Load or unload the trusted directory's vault/environment state manually in an interactive shell where `nkp shell init` is enabled (supplying credentials via env var or stdin, never `--password VALUE`):

```sh
export NEO_KEEPASS_PASSWORD=...
nkp shell load
```

To clear environment variables exported by `nkp shell load`:

```sh
nkp shell unload
```

Call `nkp shell load` and `nkp shell unload` directly when `nkp shell init` is active (wrapping them in `eval "$(...)"` runs the shell wrapper inside a subshell where exported variables are discarded). Without `nkp shell init` loaded, use the explicit binary instead:

```sh
eval "$(command nkp shell load --shell bash)"
eval "$(command nkp shell unload --shell bash)"
```

## Render templates or run one-off commands (`nkp inject` & `nkp x`)

When you want to materialize a template file explicitly or inject a `.env` file into a single child process without modifying your shell environment:

```sh
# Render a template file to stdout or a file
nkp inject .env.template -o .env.resolved
nkp inject --format dotenv .env.template -o .env.resolved

# Or pipe via stdin
nkp inject < .env.template > .env.resolved

# Run a single command with bindings and/or an env file
nkp x -B TOKEN=services/api -- ./deploy.sh
nkp x --env-file .env -B OVERRIDE=services/staging -- ./deploy.sh
```

`-B`/`--bind NAME=ENTRY` binds `Password` (or a field-bound entry alias) literally and does not parse `#field`; pass `-k services/staging -F token --env OVERRIDE` when selecting another field. `nkp inject` requires `nkp://` / `{{nkp://...}}` placeholders for secret substitution; `nkp x --env-file` reads the same `nkp://` and `{{nkp://...}}` syntax per invocation.
