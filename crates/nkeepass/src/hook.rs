//! Reversible `__NKP_ENV_STATE` codec, state-transition engine, and 5-shell
//! hook/init script emitters (`bash`, `zsh`, `fish`, `pwsh`, `nushell`).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::env_file::validate_env_var_name;
pub use crate::fs_safe::VaultFingerprint;
use crate::fs_safe::is_safe_absolute_path_text;
use crate::manifest::{
    DiscoveredChain, MAX_INHERIT_DEPTH, MAX_MANIFEST_BINDINGS, MAX_VAULTS_PER_HOOK,
};
use crate::sha256::{constant_time_eq, hex_encode, is_lowercase_hex, sha256_hex};
use crate::template::{TemplateError, is_safe_display_text, is_valid_secret_text};

/// Current `__NKP_ENV_STATE` wire schema version.
pub const STATE_VERSION: u32 = 1;

/// Maximum encoded size in bytes of `__NKP_ENV_STATE` (32 KiB).
pub const MAX_STATE_ENCODED_BYTES: usize = 32 * 1024;

/// Maximum byte length permitted for a captured `prior` ambient variable.
pub const MAX_PRIOR_BYTES: usize = 4096;

/// Maximum byte length permitted for a Phase 2 `session_id` in state.
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// Static stderr hint emitted in Phase 1 when an active vault is locked (M5).
pub const LOCKED_VAULT_HINT: &str = "nkp: vault locked; run 'nkp shell load'";

/// Supported interactive shells for `nkp shell init` and `nkp __hook`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookShell {
    /// GNU Bash (`>= 3.2`).
    Bash,
    /// Zsh.
    Zsh,
    /// Fish shell.
    Fish,
    /// PowerShell (`pwsh` / `powershell`).
    Pwsh,
    /// Nushell.
    Nushell,
}

impl HookShell {
    /// Parses a shell name for `nkp shell init` or `nkp __hook`.
    ///
    /// Rejects POSIX `sh` specifically so callers can explain that directory
    /// hooks are unsupported on `sh` while completions remain available.
    ///
    /// # Errors
    ///
    /// Returns [`HookError::UnsupportedPosixSh`] for `"sh"` or
    /// [`HookError::UnsupportedShell`] for any other unknown name.
    pub fn parse(name: &str) -> Result<Self, HookError> {
        match name {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "pwsh" | "powershell" => Ok(Self::Pwsh),
            "nushell" => Ok(Self::Nushell),
            "sh" => Err(HookError::UnsupportedPosixSh),
            _ => Err(HookError::UnsupportedShell),
        }
    }

    /// Canonical CLI name used when invoking `nkp __hook <shell>`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Pwsh => "pwsh",
            Self::Nushell => "nushell",
        }
    }
}

/// Errors returned by `__NKP_ENV_STATE` encoding, transitions, or emitters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookError {
    /// POSIX `sh` does not support directory hooks (`nkp shell init sh`).
    UnsupportedPosixSh,
    /// Unrecognized shell name.
    UnsupportedShell,
    /// Both completion and env hooks were disabled (`--no-completion --no-env`).
    NothingToEmit,
    /// Pinned executable path failed safety validation.
    InvalidExecutablePath,
    /// Encoded `__NKP_ENV_STATE` exceeded [`MAX_STATE_ENCODED_BYTES`].
    StateTooLarge,
    /// State fields failed validation prior to encoding.
    InvalidState,
    /// Entropy source failed while generating per-session salt.
    EntropyUnavailable,
    /// An existing ambient environment variable is non-UTF-8, oversized, or
    /// contains unsafe characters; refusing to overwrite it.
    UnsafeAmbientVar {
        /// Validated safe variable name (never its value).
        name: String,
    },
    /// Binding name or resolved secret value failed safety validation.
    Template(TemplateError),
    /// JSON serialization failed.
    Encode,
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPosixSh => {
                f.write_str("init is not supported for sh; use nkp shell completions sh")
            }
            Self::UnsupportedShell => f.write_str("unsupported shell"),
            Self::NothingToEmit => f.write_str("cannot disable both completion and env hooks"),
            Self::InvalidExecutablePath => f.write_str("invalid executable path for shell init"),
            Self::StateTooLarge => f.write_str("hook state exceeds 32 KiB limit"),
            Self::InvalidState => f.write_str("hook state failed validation"),
            Self::EntropyUnavailable => f.write_str("cannot generate random hook state salt"),
            Self::UnsafeAmbientVar { name } => write!(
                f,
                "refusing to overwrite unsafe pre-existing environment variable {name}"
            ),
            Self::Template(err) => err.fmt(f),
            Self::Encode => f.write_str("cannot encode hook payload"),
        }
    }
}

impl std::error::Error for HookError {}

impl From<TemplateError> for HookError {
    fn from(err: TemplateError) -> Self {
        Self::Template(err)
    }
}

/// Manifest layer identity recorded in `__NKP_ENV_STATE`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEntry {
    /// Display-safe canonical path of the manifest file.
    pub path: String,
    /// Composite 64-hex SHA-256 digest of the manifest (and any `env_files`).
    pub sha256: String,
}

impl ChainEntry {
    /// Builds [`ChainEntry`] records from a [`DiscoveredChain`].
    #[must_use]
    pub fn from_discovered_chain(chain: &DiscoveredChain) -> Vec<Self> {
        chain
            .manifests
            .iter()
            .map(|m| Self {
                path: m.file.display_path.clone(),
                sha256: m.composite_sha256(),
            })
            .collect()
    }
}

/// Tracked variable entry inside `__NKP_ENV_STATE`.
///
/// Never stores resolved `KeePass` secret values; only the salted MAC of the
/// active value and (when applicable) the pre-`nkp` ambient `prior` value.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedVar {
    /// Lowercase 64-hex `SHA-256("nkp-env-v1\0" || salt || "\0" || name || "\0" || value)`.
    pub mac: String,
    /// Pre-`nkp` ambient value captured once (redacted in `Debug`).
    pub prior: Option<String>,
}

impl fmt::Debug for TrackedVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedVar")
            .field("mac", &self.mac)
            .field("prior", &self.prior.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Decoded and validated `__NKP_ENV_STATE` payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookState {
    /// Schema version (must be `1`).
    pub v: u32,
    /// 32-character lowercase hex 128-bit per-session random salt.
    pub salt: String,
    /// Active manifest chain (`<= 8`).
    pub chain: Vec<ChainEntry>,
    /// Active vault metadata fingerprints (`<= 4`).
    pub vaults: Vec<VaultFingerprint>,
    /// Optional Phase 2 agent session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Optional 64-hex digest suppressing repeated locked/untrusted warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warned: Option<String>,
    /// Optional 64-hex digest of an explicitly unloaded manifest chain (M1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unloaded: Option<String>,
    /// Active tracked environment variables (`<= 256`).
    pub vars: BTreeMap<String, TrackedVar>,
}

/// Outcome of decoding `__NKP_ENV_STATE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateDecode {
    /// Input was empty (clean shell start).
    Empty,
    /// Input decoded and passed all H4 validation checks.
    Valid(HookState),
    /// Input was malformed, oversized, tampered, or contained forbidden keys/values.
    Invalid,
}

/// Generates a fresh 128-bit random salt encoded as 32 lowercase hex chars.
///
/// # Errors
///
/// Returns [`HookError::EntropyUnavailable`] if OS entropy fails.
pub fn generate_salt() -> Result<String, HookError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| HookError::EntropyUnavailable)?;
    Ok(hex_encode(&bytes))
}

/// Computes `SHA-256("nkp-env-v1\0" || salt || "\0" || name || "\0" || value)`.
#[must_use]
pub fn compute_var_mac(salt: &str, name: &str, value: &str) -> String {
    let mut buf = Vec::with_capacity(11 + salt.len() + 1 + name.len() + 1 + value.len());
    buf.extend_from_slice(b"nkp-env-v1\0");
    buf.extend_from_slice(salt.as_bytes());
    buf.push(0);
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value.as_bytes());
    sha256_hex(&buf)
}

/// Computes a fixed 64-hex digest identifying a manifest chain.
#[must_use]
pub fn compute_chain_digest(chain: &[ChainEntry]) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"nkp-chain-v1\0");
    for entry in chain {
        buf.extend_from_slice(entry.path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(entry.sha256.as_bytes());
        buf.push(0);
    }
    sha256_hex(&buf)
}

/// Computes a fixed 64-hex digest identifying an untrusted/locked `(path, sha256)` warning.
#[must_use]
pub fn compute_warned_digest(path: &str, sha256: &str) -> String {
    let mut buf = Vec::with_capacity(12 + path.len() + 1 + sha256.len());
    buf.extend_from_slice(b"nkp-warn-v1\0");
    buf.extend_from_slice(path.as_bytes());
    buf.push(0);
    buf.extend_from_slice(sha256.as_bytes());
    sha256_hex(&buf)
}

fn validate_hook_state(state: &HookState) -> bool {
    if state.v != STATE_VERSION {
        return false;
    }
    if !is_lowercase_hex(&state.salt, 32) {
        return false;
    }
    if state.chain.len() > MAX_INHERIT_DEPTH {
        return false;
    }
    for entry in &state.chain {
        if entry.path.is_empty()
            || !is_safe_display_text(&entry.path)
            || !is_lowercase_hex(&entry.sha256, 64)
        {
            return false;
        }
    }
    if state.vaults.len() > MAX_VAULTS_PER_HOOK {
        return false;
    }
    for vault in &state.vaults {
        if vault.path.is_empty() || !is_safe_display_text(&vault.path) {
            return false;
        }
    }
    if let Some(session_id) = &state.session_id
        && (session_id.is_empty()
            || session_id.len() > MAX_SESSION_ID_BYTES
            || !is_safe_display_text(session_id))
    {
        return false;
    }
    if let Some(warned) = &state.warned
        && !is_lowercase_hex(warned, 64)
    {
        return false;
    }
    if let Some(unloaded) = &state.unloaded
        && !is_lowercase_hex(unloaded, 64)
    {
        return false;
    }
    if state.vars.len() > MAX_MANIFEST_BINDINGS {
        return false;
    }
    let mut seen_upper = BTreeSet::new();
    for (name, tracked) in &state.vars {
        if validate_env_var_name(name).is_err() {
            return false;
        }
        if !seen_upper.insert(name.to_ascii_uppercase()) {
            return false;
        }
        if !is_lowercase_hex(&tracked.mac, 64) {
            return false;
        }
        if let Some(prior) = &tracked.prior
            && (prior.len() > MAX_PRIOR_BYTES || !is_valid_secret_text(prior, true))
        {
            return false;
        }
    }
    true
}

/// Decodes and strictly validates `__NKP_ENV_STATE`.
///
/// Any oversized, malformed, or tampered state (including reserved variable
/// names, invalid identifiers, bad hex salts/MACs, or unsafe `prior` values)
/// returns [`StateDecode::Invalid`] so callers discard it safely.
#[must_use]
pub fn decode_state(encoded: &str) -> StateDecode {
    if encoded.is_empty() {
        return StateDecode::Empty;
    }
    if encoded.len() > MAX_STATE_ENCODED_BYTES {
        return StateDecode::Invalid;
    }
    let Ok(json_bytes) = URL_SAFE_NO_PAD.decode(encoded.as_bytes()) else {
        return StateDecode::Invalid;
    };
    let Ok(state) = serde_json::from_slice::<HookState>(&json_bytes) else {
        return StateDecode::Invalid;
    };
    if !validate_hook_state(&state) {
        return StateDecode::Invalid;
    }
    StateDecode::Valid(state)
}

/// Validates and encodes a [`HookState`] into compact base64url JSON
/// (`<= 32 KiB`).
///
/// # Errors
///
/// Returns [`HookError::InvalidState`] if any field violates invariants, or
/// [`HookError::StateTooLarge`] if the encoded string exceeds
/// [`MAX_STATE_ENCODED_BYTES`].
pub fn encode_state(state: &HookState) -> Result<String, HookError> {
    if !validate_hook_state(state) {
        return Err(HookError::InvalidState);
    }
    let json_bytes = serde_json::to_vec(state).map_err(|_| HookError::Encode)?;
    let encoded = URL_SAFE_NO_PAD.encode(json_bytes);
    if encoded.len() > MAX_STATE_ENCODED_BYTES {
        return Err(HookError::StateTooLarge);
    }
    Ok(encoded)
}

/// Returns `true` when `state` already matches the discovered directory chain,
/// vault fingerprints, and Phase 2 session without `--prompt` or `--unload`,
/// allowing `nkp __hook` to exit `0` in <2 ms without decrypting KDBX.
#[must_use]
pub fn is_fast_path_unchanged(
    state: &HookState,
    chain: &[ChainEntry],
    vaults: &[VaultFingerprint],
    session_id: Option<&str>,
) -> bool {
    if state.session_id.as_deref() != session_id {
        return false;
    }
    if let Some(unloaded) = &state.unloaded
        && unloaded == &compute_chain_digest(chain)
    {
        return true;
    }
    state.unloaded.is_none()
        && state.warned.is_none()
        && state.chain == chain
        && state.vaults == vaults
}

/// Target environment resolved from a trusted manifest chain.
#[derive(Clone)]
pub struct TargetEnv {
    /// Active manifest chain entries (`<= 8`).
    pub chain: Vec<ChainEntry>,
    /// Active vault fingerprints (`<= 4`).
    pub vaults: Vec<VaultFingerprint>,
    /// Optional Phase 2 session identifier.
    pub session_id: Option<String>,
    /// Resolved `(NAME, VALUE)` pairs ready to apply.
    pub resolved_vars: Vec<(String, Zeroizing<String>)>,
}

impl fmt::Debug for TargetEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.resolved_vars.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("TargetEnv")
            .field("chain", &self.chain)
            .field("vaults", &self.vaults)
            .field("session_id", &self.session_id)
            .field("var_names", &names)
            .finish()
    }
}

/// Input action supplied to [`compute_transition`].
#[derive(Clone, Copy, Debug)]
pub enum TransitionAction<'a> {
    /// Explicit `nkp shell unload` (or leaving `FileSystem` provider in pwsh).
    Unload {
        /// Digest of the directory chain being unloaded, if inside a manifest dir.
        current_chain_digest: Option<&'a str>,
    },
    /// Directory has no manifest chain (left managed project tree).
    Leave,
    /// Directory has an untrusted or locked manifest (reverts active vars and
    /// records a deduplicated `warned` digest).
    Blocked {
        /// 64-hex digest identifying this blocked state for warning deduplication.
        warned_digest: &'a str,
    },
    /// Activate or refresh a trusted, resolved manifest chain.
    Activate {
        /// Resolved target environment.
        target: &'a TargetEnv,
        /// `true` for `nkp shell load` / `nkp unlock` (clears `unloaded` tombstone).
        force_reload: bool,
    },
}

/// Environment variable patch emitted by [`compute_transition`].
#[derive(Clone, Default, Eq, PartialEq)]
pub struct HookPatch {
    /// Variable names to unset from the shell environment.
    pub unset: Vec<String>,
    /// Variable names and values to export/set (values redacted in `Debug`).
    pub set: BTreeMap<String, Zeroizing<String>>,
    /// Updated encoded `__NKP_ENV_STATE` value (`None` clears state).
    pub state: Option<String>,
}

impl fmt::Debug for HookPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set_keys: Vec<&str> = self.set.keys().map(String::as_str).collect();
        f.debug_struct("HookPatch")
            .field("unset", &self.unset)
            .field("set_keys", &set_keys)
            .field("has_state", &self.state.is_some())
            .finish()
    }
}

/// Result of [`compute_transition`].
#[derive(Clone, Debug)]
pub struct TransitionOutcome {
    /// Shell patch to emit when `emit_patch` is `true`.
    pub patch: HookPatch,
    /// Resulting state after transition (`None` when cleared).
    pub new_state: Option<HookState>,
    /// Whether any shell output needs to be emitted.
    pub emit_patch: bool,
    /// `true` when incoming encoded state failed validation and was dropped.
    pub discarded_corrupt_state: bool,
    /// `true` when `Blocked` matched `old.warned` and reverted nothing.
    pub suppress_duplicate_warning: bool,
}

fn ambient_matches_mac(
    ambient: &dyn Fn(&str) -> Option<OsString>,
    salt: &str,
    name: &str,
    expected_mac: &str,
) -> bool {
    let Some(os_val) = ambient(name) else {
        return false;
    };
    let Some(val_str) = os_val.to_str() else {
        return false;
    };
    let actual_mac = compute_var_mac(salt, name, val_str);
    constant_time_eq(actual_mac.as_bytes(), expected_mac.as_bytes())
}

fn revert_tracked_vars(
    old: &HookState,
    keep_names: Option<&BTreeSet<&str>>,
    ambient: &dyn Fn(&str) -> Option<OsString>,
    patch: &mut HookPatch,
) {
    for (name, tracked) in &old.vars {
        if let Some(keep) = keep_names
            && keep.contains(name.as_str())
        {
            continue;
        }
        if ambient_matches_mac(ambient, &old.salt, name, &tracked.mac) {
            if let Some(prior) = &tracked.prior {
                patch
                    .set
                    .insert(name.clone(), Zeroizing::new(prior.clone()));
            } else {
                patch.unset.push(name.clone());
            }
        }
    }
}

fn validate_ambient_prior(name: &str, os_val: &OsString) -> Result<String, HookError> {
    let text = os_val.to_str().ok_or_else(|| HookError::UnsafeAmbientVar {
        name: name.to_owned(),
    })?;
    if text.len() > MAX_PRIOR_BYTES || !is_valid_secret_text(text, true) {
        return Err(HookError::UnsafeAmbientVar {
            name: name.to_owned(),
        });
    }
    Ok(text.to_owned())
}

fn transition_leave(
    old_state: Option<&HookState>,
    discarded_corrupt_state: bool,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> TransitionOutcome {
    let mut patch = HookPatch::default();
    if let Some(old) = old_state {
        revert_tracked_vars(old, None, ambient, &mut patch);
    }
    let emit_patch = discarded_corrupt_state
        || old_state.is_some()
        || !patch.unset.is_empty()
        || !patch.set.is_empty();
    TransitionOutcome {
        patch,
        new_state: None,
        emit_patch,
        discarded_corrupt_state,
        suppress_duplicate_warning: false,
    }
}

fn transition_unload(
    old_state: Option<&HookState>,
    discarded_corrupt_state: bool,
    current_chain_digest: Option<&str>,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> Result<TransitionOutcome, HookError> {
    let mut patch = HookPatch::default();
    if let Some(old) = old_state {
        revert_tracked_vars(old, None, ambient, &mut patch);
    }
    let new_state = match current_chain_digest {
        Some(digest) => {
            if !is_lowercase_hex(digest, 64) {
                return Err(HookError::InvalidState);
            }
            let salt = match old_state {
                Some(old) => old.salt.clone(),
                None => generate_salt()?,
            };
            let state = HookState {
                v: STATE_VERSION,
                salt,
                chain: Vec::new(),
                vaults: Vec::new(),
                session_id: None,
                warned: None,
                unloaded: Some(digest.to_owned()),
                vars: BTreeMap::new(),
            };
            patch.state = Some(encode_state(&state)?);
            Some(state)
        }
        None => None,
    };
    let emit_patch = discarded_corrupt_state
        || old_state.is_some()
        || new_state.is_some()
        || !patch.unset.is_empty()
        || !patch.set.is_empty();
    Ok(TransitionOutcome {
        patch,
        new_state,
        emit_patch,
        discarded_corrupt_state,
        suppress_duplicate_warning: false,
    })
}

fn transition_blocked(
    old_state: Option<&HookState>,
    discarded_corrupt_state: bool,
    warned_digest: &str,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> Result<TransitionOutcome, HookError> {
    if !is_lowercase_hex(warned_digest, 64) {
        return Err(HookError::InvalidState);
    }
    let mut patch = HookPatch::default();
    if let Some(old) = old_state {
        revert_tracked_vars(old, None, ambient, &mut patch);
    }
    let already_warned = old_state.is_some_and(|old| {
        old.warned.as_deref() == Some(warned_digest) && old.vars.is_empty() && old.chain.is_empty()
    });
    let salt = match old_state {
        Some(old) => old.salt.clone(),
        None => generate_salt()?,
    };
    let state = HookState {
        v: STATE_VERSION,
        salt,
        chain: Vec::new(),
        vaults: Vec::new(),
        session_id: None,
        warned: Some(warned_digest.to_owned()),
        unloaded: None,
        vars: BTreeMap::new(),
    };
    let emit_patch = discarded_corrupt_state
        || !already_warned
        || !patch.unset.is_empty()
        || !patch.set.is_empty();
    if emit_patch {
        patch.state = Some(encode_state(&state)?);
    }
    Ok(TransitionOutcome {
        patch,
        new_state: Some(state),
        emit_patch,
        discarded_corrupt_state,
        suppress_duplicate_warning: already_warned && !discarded_corrupt_state,
    })
}

fn resolve_next_prior(
    old_state: Option<&HookState>,
    name: &str,
    new_val: &str,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<String>, HookError> {
    if let Some((old_salt, tracked)) =
        old_state.and_then(|old| old.vars.get(name).map(|t| (old.salt.as_str(), t)))
        && ambient_matches_mac(ambient, old_salt, name, &tracked.mac)
    {
        return Ok(tracked.prior.clone());
    }
    let Some(os_val) = ambient(name) else {
        return Ok(None);
    };
    let text = validate_ambient_prior(name, &os_val)?;
    // H4 subshell safeguard: if parent already exported the same secret,
    // do not capture it as `prior`.
    if text == new_val {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

fn transition_activate(
    old_state: Option<&HookState>,
    discarded_corrupt_state: bool,
    target: &TargetEnv,
    force_reload: bool,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> Result<TransitionOutcome, HookError> {
    let mut patch = HookPatch::default();
    let target_chain_digest = compute_chain_digest(&target.chain);
    if !force_reload
        && let Some(old) = old_state
        && old.unloaded.as_deref() == Some(target_chain_digest.as_str())
    {
        return Ok(TransitionOutcome {
            patch,
            new_state: Some(old.clone()),
            emit_patch: false,
            discarded_corrupt_state,
            suppress_duplicate_warning: false,
        });
    }

    if target.resolved_vars.len() > MAX_MANIFEST_BINDINGS {
        return Err(HookError::Template(TemplateError::TooManyEnvEntries));
    }

    let mut target_upper = BTreeSet::new();
    let mut target_names = BTreeSet::new();
    for (name, val) in &target.resolved_vars {
        validate_env_var_name(name)?;
        if !target_upper.insert(name.to_ascii_uppercase()) {
            return Err(HookError::Template(TemplateError::DuplicateEnvVar));
        }
        if !is_valid_secret_text(val, true) {
            return Err(HookError::Template(TemplateError::UnsafeSecretCharacters));
        }
        target_names.insert(name.as_str());
    }

    let new_salt = generate_salt()?;
    let mut new_vars = BTreeMap::new();

    for (name, new_val) in &target.resolved_vars {
        let prior = resolve_next_prior(old_state, name, new_val, ambient)?;
        let mac = compute_var_mac(&new_salt, name, new_val);
        new_vars.insert(name.clone(), TrackedVar { mac, prior });
        patch.set.insert(name.clone(), new_val.clone());
    }

    if let Some(old) = old_state {
        revert_tracked_vars(old, Some(&target_names), ambient, &mut patch);
    }

    let state = HookState {
        v: STATE_VERSION,
        salt: new_salt,
        chain: target.chain.clone(),
        vaults: target.vaults.clone(),
        session_id: target.session_id.clone(),
        warned: None,
        unloaded: None,
        vars: new_vars,
    };
    patch.state = Some(encode_state(&state)?);

    Ok(TransitionOutcome {
        patch,
        new_state: Some(state),
        emit_patch: true,
        discarded_corrupt_state,
        suppress_duplicate_warning: false,
    })
}

/// Computes the reversible state transition for `encoded_state` and `action`,
/// reading live shell variables through `ambient`.
///
/// Guarantees:
/// - Invalid/tampered `encoded_state` is safely discarded without executing any
///   reserved-variable writes.
/// - Manual user edits/unsets are preserved on leave/switch/unload.
/// - Original pre-`nkp` `prior` values are preserved across nested switches.
/// - Inherited secrets in spawned subshells (`old.vars` absent and ambient
///   value already equals the resolved secret) do not get captured into `prior`.
/// - Resolved secrets are never written into `__NKP_ENV_STATE`.
///
/// # Errors
///
/// Returns [`HookError`] when target bindings/secrets fail safety checks, a
/// pre-existing ambient variable is non-UTF-8/oversized/unsafe, entropy fails,
/// or state encoding exceeds [`MAX_STATE_ENCODED_BYTES`].
pub fn compute_transition(
    encoded_state: &str,
    action: TransitionAction<'_>,
    ambient: impl Fn(&str) -> Option<OsString>,
) -> Result<TransitionOutcome, HookError> {
    let (old_state, discarded_corrupt_state) = match decode_state(encoded_state) {
        StateDecode::Empty => (None, false),
        StateDecode::Valid(state) => (Some(state), false),
        StateDecode::Invalid => (None, true),
    };

    match action {
        TransitionAction::Leave => Ok(transition_leave(
            old_state.as_ref(),
            discarded_corrupt_state,
            &ambient,
        )),
        TransitionAction::Unload {
            current_chain_digest,
        } => transition_unload(
            old_state.as_ref(),
            discarded_corrupt_state,
            current_chain_digest,
            &ambient,
        ),
        TransitionAction::Blocked { warned_digest } => transition_blocked(
            old_state.as_ref(),
            discarded_corrupt_state,
            warned_digest,
            &ambient,
        ),
        TransitionAction::Activate {
            target,
            force_reload,
        } => transition_activate(
            old_state.as_ref(),
            discarded_corrupt_state,
            target,
            force_reload,
            &ambient,
        ),
    }
}

/// Pre-opens a vault file safely (`O_NOFOLLOW | O_NONBLOCK` on Unix or
/// `FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and returns its
/// [`VaultFingerprint`], rejecting symlinks, FIFOs, devices, and directories.
///
/// # Errors
///
/// Returns [`HookError::InvalidExecutablePath`] or [`HookError::InvalidState`]
/// when the vault file cannot be safely opened as a regular file.
pub fn preopen_vault_fingerprint(path: &Path) -> Result<VaultFingerprint, HookError> {
    crate::fs_safe::preopen_vault_fingerprint(path).map_err(|_| HookError::InvalidState)
}

/// Computes a revert-only patch from `encoded_state` (used when an activation
/// fails closed on e.g. an unsafe ambient variable).
#[must_use]
pub fn revert_only_patch(
    encoded_state: &str,
    ambient: impl Fn(&str) -> Option<OsString>,
) -> Option<HookPatch> {
    let StateDecode::Valid(old) = decode_state(encoded_state) else {
        return None;
    };
    let mut patch = HookPatch::default();
    revert_tracked_vars(&old, None, &ambient, &mut patch);
    if patch.unset.is_empty() && patch.set.is_empty() {
        return None;
    }
    Some(patch)
}

fn push_posix_single_quoted(out: &mut String, value: &str) {
    out.push('\'');
    for (idx, part) in value.split('\'').enumerate() {
        if idx > 0 {
            out.push_str("'\\''");
        }
        out.push_str(part);
    }
    out.push('\'');
}

fn push_fish_single_quoted(out: &mut String, value: &str) {
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out.push('\'');
}

fn push_pwsh_single_quoted(out: &mut String, value: &str) {
    let has_curly = value
        .chars()
        .any(|ch| matches!(ch, '\u{2018}'..='\u{201B}'));
    if has_curly {
        out.push('(');
    }
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => out.push_str("''"),
            '\u{2018}'..='\u{201B}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "' + [char]0x{:04X} + '", u32::from(ch));
            }
            other => out.push(other),
        }
    }
    out.push('\'');
    if has_curly {
        out.push(')');
    }
}

#[derive(Serialize)]
struct JsonPatchPayload<'a> {
    unset: &'a [String],
    set: BTreeMap<&'a str, &'a str>,
    state: &'a str,
}

/// Validates and serializes a [`HookPatch`] for `shell`.
///
/// - `bash` / `zsh`: emits POSIX single-quoted `unset` / `export` commands with
///   L3 `readonly` guards (`|| _nkp_ok=0`) and unexported `_nkp_env_state`.
/// - `fish`: emits Fish single-quoted `set -eg` / `set -gx` commands and
///   unexported `set -g _nkp_env_state`.
/// - `pwsh` / `nushell`: emits compact JSON (`{"unset":[...],"set":{...},"state":"..."}`)
///   avoiding `Invoke-Expression` and curly-quote injection (H1).
///
/// # Errors
///
/// Returns [`HookError`] if any variable name, value, or state token fails
/// safety validation.
pub fn emit_hook_patch(
    shell: HookShell,
    patch: &HookPatch,
) -> Result<Zeroizing<String>, HookError> {
    for name in &patch.unset {
        validate_env_var_name(name)?;
    }
    for (name, val) in &patch.set {
        validate_env_var_name(name)?;
        if !is_valid_secret_text(val, true) {
            return Err(HookError::Template(TemplateError::UnsafeSecretCharacters));
        }
    }
    let state_str = patch.state.as_deref().unwrap_or("");
    if state_str.len() > MAX_STATE_ENCODED_BYTES
        || !state_str
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(HookError::InvalidState);
    }

    match shell {
        HookShell::Bash | HookShell::Zsh => {
            let mut out = Zeroizing::new(String::new());
            out.push_str("_nkp_ok=1\n");
            for name in &patch.unset {
                out.push_str("unset ");
                out.push_str(name);
                out.push_str(" || _nkp_ok=0\n");
            }
            for (name, val) in &patch.set {
                out.push_str("export ");
                out.push_str(name);
                out.push('=');
                push_posix_single_quoted(&mut out, val);
                out.push_str(" || _nkp_ok=0\n");
            }
            out.push_str("if [ \"$_nkp_ok\" -eq 1 ]; then\n  _nkp_env_state=");
            push_posix_single_quoted(&mut out, state_str);
            out.push_str("\nfi\nunset _nkp_ok\n");
            Ok(out)
        }
        HookShell::Fish => {
            let mut out = Zeroizing::new(String::new());
            out.push_str("set -l _nkp_ok 1\n");
            for name in &patch.unset {
                out.push_str("set -eg ");
                out.push_str(name);
                out.push_str("; or set _nkp_ok 0\n");
            }
            for (name, val) in &patch.set {
                out.push_str("set -gx ");
                out.push_str(name);
                out.push(' ');
                push_fish_single_quoted(&mut out, val);
                out.push_str("; or set _nkp_ok 0\n");
            }
            out.push_str("if test $_nkp_ok -eq 1\n  set -g _nkp_env_state ");
            push_fish_single_quoted(&mut out, state_str);
            out.push_str("\nend\n");
            Ok(out)
        }
        HookShell::Pwsh | HookShell::Nushell => {
            let mut set_map = BTreeMap::new();
            for (name, val) in &patch.set {
                set_map.insert(name.as_str(), val.as_str());
            }
            let payload = JsonPatchPayload {
                unset: &patch.unset,
                set: set_map,
                state: state_str,
            };
            let json = serde_json::to_string(&payload).map_err(|_| HookError::Encode)?;
            let mut out = Zeroizing::new(json);
            out.push('\n');
            Ok(out)
        }
    }
}

/// Resolves the current executable path when it is absolute, display-safe, and
/// a regular file, so `nkp shell init` can pin it against later `PATH` changes.
#[must_use]
pub fn resolve_pinned_nkp_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let canon = std::fs::canonicalize(&exe).ok()?;
    let norm = crate::fs_safe::normalize_canonical_path(&canon).ok()?;
    let text = norm.to_str()?;
    if !is_safe_absolute_path_text(text) {
        return None;
    }
    let meta = std::fs::symlink_metadata(&norm).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some(norm)
}

fn validate_pinned_bin(bin_path: Option<&Path>) -> Result<Option<String>, HookError> {
    let Some(path) = bin_path else {
        return Ok(None);
    };
    let text = path.to_str().ok_or(HookError::InvalidExecutablePath)?;
    if !is_safe_absolute_path_text(text)
        || text
            .chars()
            .any(|ch| ch == '\n' || ch == '\r' || matches!(ch, '\u{2018}'..='\u{201B}'))
    {
        return Err(HookError::InvalidExecutablePath);
    }
    Ok(Some(text.to_owned()))
}

fn emit_posix_wrapper_load(invoke: &str, shell_name: &str) -> String {
    format!(
        r#"        load)
          local _nkp_load_rc=0
          local _nkp_script=""
          local _nkp_passthru=()
          local _nkp_saw_shell=0
          local _nkp_saw_load=0
          _nkp_skip=0
          _nkp_end_opts=0
          for _nkp_arg in "$@"; do
            if [ "$_nkp_skip" -eq 1 ]; then
              _nkp_passthru+=("$_nkp_arg")
              _nkp_skip=0
              continue
            fi
            if [ "$_nkp_saw_load" -eq 1 ]; then
              _nkp_passthru+=("$_nkp_arg")
              continue
            fi
            if [ "$_nkp_end_opts" -eq 0 ]; then
              case "$_nkp_arg" in
                --)
                  _nkp_end_opts=1
                  continue
                  ;;
                -V|--vault|--password-env|--key-file|--password-file|--color)
                  _nkp_passthru+=("$_nkp_arg")
                  _nkp_skip=1
                  continue
                  ;;
                -V=*|--vault=*|--password-env=*|--key-file=*|--password-file=*|--color=*)
                  _nkp_passthru+=("$_nkp_arg")
                  continue
                  ;;
                -*)
                  _nkp_passthru+=("$_nkp_arg")
                  continue
                  ;;
              esac
            fi
            if [ "$_nkp_saw_shell" -eq 0 ] && [ "$_nkp_arg" = "shell" ]; then
              _nkp_saw_shell=1
            elif [ "$_nkp_saw_shell" -eq 1 ] && [ "$_nkp_arg" = "load" ]; then
              _nkp_saw_load=1
            fi
          done
          if _nkp_script="$(__NKP_ENV_STATE="${{_nkp_env_state:-}}" {invoke} __hook {shell_name} --prompt "${{_nkp_passthru[@]+${{_nkp_passthru[@]}}}}")"; then
            if [ -n "$_nkp_script" ]; then
              eval "$_nkp_script"
            fi
            return 0
          else
            _nkp_load_rc=$?
            return $_nkp_load_rc
          fi
          ;;"#
    )
}

fn emit_posix_wrapper(invoke: &str, shell_name: &str) -> String {
    let load_arm = emit_posix_wrapper_load(invoke, shell_name);
    format!(
        r#"nkp() {{
  local _nkp_help=0
  local _nkp_skip=0
  local _nkp_end_opts=0
  local _nkp_cmd=""
  local _nkp_sub=""
  local _nkp_arg
  for _nkp_arg in "$@"; do
    if [ "$_nkp_skip" -eq 1 ]; then
      _nkp_skip=0
      continue
    fi
    if [ "$_nkp_end_opts" -eq 0 ]; then
      case "$_nkp_arg" in
        -h|--help)
          _nkp_help=1
          ;;
        --)
          _nkp_end_opts=1
          continue
          ;;
        -V|--vault|--password-env|--key-file|--password-file|--color)
          _nkp_skip=1
          continue
          ;;
        -V=*|--vault=*|--password-env=*|--key-file=*|--password-file=*|--color=*)
          continue
          ;;
        -*)
          continue
          ;;
      esac
    fi
    if [ -z "$_nkp_cmd" ]; then
      _nkp_cmd="$_nkp_arg"
    elif [ -z "$_nkp_sub" ]; then
      _nkp_sub="$_nkp_arg"
    fi
  done

  if [ "$_nkp_help" -eq 1 ]; then
    {invoke} "$@"
    return $?
  fi

  case "$_nkp_cmd" in
    shell)
      case "$_nkp_sub" in
{load_arm}
        unload)
          local _nkp_unload_rc=0
          local _nkp_script=""
          if _nkp_script="$(__NKP_ENV_STATE="${{_nkp_env_state:-}}" {invoke} __hook {shell_name} --unload)"; then
            if [ -n "$_nkp_script" ]; then
              eval "$_nkp_script"
            fi
            return 0
          else
            _nkp_unload_rc=$?
            return $_nkp_unload_rc
          fi
          ;;
      esac
      {invoke} "$@"
      return $?
      ;;
    trust|untrust|unlock|lock)
      {invoke} "$@"
      local _nkp_cmd_rc=$?
      if [ "$_nkp_cmd_rc" -eq 0 ]; then
        _nkp_hook
      fi
      return $_nkp_cmd_rc
      ;;
    *)
      {invoke} "$@"
      return $?
      ;;
  esac
}}
"#
    )
}

fn emit_posix_env_hook(shell: HookShell, bin: Option<&str>) -> String {
    let invoke = match bin {
        Some(p) => {
            let mut quoted = String::new();
            push_posix_single_quoted(&mut quoted, p);
            quoted
        }
        None => "command nkp".to_owned(),
    };
    let shell_name = shell.as_str();

    let mut out = format!(
        r#"_nkp_env_state="${{_nkp_env_state:-}}"

_nkp_hook() {{
  local _nkp_rc=$?
  local _nkp_script=""
  if _nkp_script="$(__NKP_ENV_STATE="${{_nkp_env_state:-}}" {invoke} __hook {shell_name} "$@")"; then
    if [ -n "$_nkp_script" ]; then
      eval "$_nkp_script"
    fi
  fi
  return $_nkp_rc
}}

"#
    );
    out.push_str(&emit_posix_wrapper(&invoke, shell_name));

    match shell {
        HookShell::Bash => {
            out.push_str(
                r#"
if declare -p PROMPT_COMMAND 2>/dev/null | grep -q '^declare -a '; then
  _nkp_has_hook=0
  for _nkp_pc in "${PROMPT_COMMAND[@]}"; do
    if [ "$_nkp_pc" = "_nkp_hook" ]; then
      _nkp_has_hook=1
      break
    fi
  done
  if [ "$_nkp_has_hook" -eq 0 ]; then
    PROMPT_COMMAND=("_nkp_hook" "${PROMPT_COMMAND[@]}")
  fi
  unset _nkp_has_hook _nkp_pc
else
  case ";${PROMPT_COMMAND:-};" in
    *";_nkp_hook;"*) ;;
    ";;") PROMPT_COMMAND="_nkp_hook" ;;
    *) PROMPT_COMMAND="_nkp_hook;${PROMPT_COMMAND}" ;;
  esac
fi

_nkp_hook --startup
"#,
            );
        }
        HookShell::Zsh => {
            out.push_str(
                r"
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _nkp_hook
add-zsh-hook precmd _nkp_hook

_nkp_hook --startup
",
            );
        }
        _ => {}
    }

    out
}

fn emit_fish_wrapper_load(invoke: &str) -> String {
    format!(
        r#"  if test "$_nkp_cmd" = "shell" -a "$_nkp_sub" = "load"
    set -l _nkp_passthru
    set -l _nkp_saw_shell 0
    set -l _nkp_saw_load 0
    set -l _nkp_skip 0
    set -l _nkp_end_opts 0
    for _nkp_arg in $argv
      if test $_nkp_skip -eq 1
        set -a _nkp_passthru $_nkp_arg
        set _nkp_skip 0
        continue
      end
      if test $_nkp_saw_load -eq 1
        set -a _nkp_passthru $_nkp_arg
        continue
      end
      if test $_nkp_end_opts -eq 0
        switch $_nkp_arg
          case --
            set _nkp_end_opts 1
            continue
          case -V --vault --password-env --key-file --password-file --color
            set -a _nkp_passthru $_nkp_arg
            set _nkp_skip 1
            continue
          case '-V=*' '--vault=*' '--password-env=*' '--key-file=*' '--password-file=*' '--color=*'
            set -a _nkp_passthru $_nkp_arg
            continue
          case '-*'
            set -a _nkp_passthru $_nkp_arg
            continue
        end
      end
      if test $_nkp_saw_shell -eq 0 -a "$_nkp_arg" = "shell"
        set _nkp_saw_shell 1
      else if test $_nkp_saw_shell -eq 1 -a "$_nkp_arg" = "load"
        set _nkp_saw_load 1
      end
    end
    set -l _nkp_rc 0
    set -l _nkp_lines
    begin
      set -lx __NKP_ENV_STATE "$_nkp_env_state"
      set _nkp_lines ({invoke} __hook fish --prompt $_nkp_passthru)
      set _nkp_rc $status
    end
    if test $_nkp_rc -eq 0
      if test (count $_nkp_lines) -gt 0
        printf '%s\n' $_nkp_lines | source
      end
      return 0
    end
    return $_nkp_rc"#
    )
}

fn emit_fish_wrapper(invoke: &str) -> String {
    let load_branch = emit_fish_wrapper_load(invoke);
    format!(
        r#"function nkp --wraps nkp
  set -l _nkp_help 0
  set -l _nkp_skip 0
  set -l _nkp_end_opts 0
  set -l _nkp_cmd ''
  set -l _nkp_sub ''
  for _nkp_arg in $argv
    if test $_nkp_skip -eq 1
      set _nkp_skip 0
      continue
    end
    if test $_nkp_end_opts -eq 0
      switch $_nkp_arg
        case -h --help
          set _nkp_help 1
        case --
          set _nkp_end_opts 1
          continue
        case -V --vault --password-env --key-file --password-file --color
          set _nkp_skip 1
          continue
        case '-V=*' '--vault=*' '--password-env=*' '--key-file=*' '--password-file=*' '--color=*'
          continue
        case '-*'
          continue
      end
    end
    if test -z "$_nkp_cmd"
      set _nkp_cmd $_nkp_arg
    else if test -z "$_nkp_sub"
      set _nkp_sub $_nkp_arg
    end
  end

  if test $_nkp_help -eq 1
    {invoke} $argv
    return $status
  end

{load_branch}
  else if test "$_nkp_cmd" = "shell" -a "$_nkp_sub" = "unload"
    set -l _nkp_rc 0
    set -l _nkp_lines
    begin
      set -lx __NKP_ENV_STATE "$_nkp_env_state"
      set _nkp_lines ({invoke} __hook fish --unload)
      set _nkp_rc $status
    end
    if test $_nkp_rc -eq 0
      if test (count $_nkp_lines) -gt 0
        printf '%s\n' $_nkp_lines | source
      end
      return 0
    end
    return $_nkp_rc
  else if contains -- "$_nkp_cmd" trust untrust unlock lock
    {invoke} $argv
    set -l _nkp_rc $status
    if test $_nkp_rc -eq 0
      _nkp_hook
    end
    return $_nkp_rc
  else
    {invoke} $argv
    return $status
  end
end

_nkp_hook --startup
"#
    )
}

fn emit_fish_env_hook(bin: Option<&str>) -> String {
    let invoke = match bin {
        Some(p) => {
            let mut quoted = String::new();
            push_fish_single_quoted(&mut quoted, p);
            quoted
        }
        None => "command nkp".to_owned(),
    };

    let mut out = format!(
        r#"if not set -q _nkp_env_state
  set -g _nkp_env_state ''
end

function _nkp_hook
  set -l _nkp_saved_status $status
  set -l _nkp_rc 0
  set -l _nkp_lines
  begin
    set -lx __NKP_ENV_STATE "$_nkp_env_state"
    set _nkp_lines ({invoke} __hook fish $argv)
    set _nkp_rc $status
  end
  if test $_nkp_rc -eq 0 -a (count $_nkp_lines) -gt 0
    printf '%s\n' $_nkp_lines | source
  end
  return $_nkp_saved_status
end

function _nkp_on_pwd --on-variable PWD
  _nkp_hook
end

function _nkp_on_prompt --on-event fish_prompt
  _nkp_hook
end

"#
    );
    out.push_str(&emit_fish_wrapper(&invoke));
    out
}

fn emit_pwsh_wrapper() -> &'static str {
    r"function global:nkp {
    $hasHelp = $false
    $skip = $false
    $endOpts = $false
    $cmd = ''
    $sub = ''
    $valOpts = @('-V', '--vault', '--password-env', '--key-file', '--password-file', '--color')
    foreach ($arg in $args) {
        $s = [string]$arg
        if ($skip) {
            $skip = $false
            continue
        }
        if (-not $endOpts) {
            if ($s -eq '-h' -or $s -eq '--help') {
                $hasHelp = $true
            } elseif ($s -eq '--') {
                $endOpts = $true
                continue
            } elseif ($s -in $valOpts) {
                $skip = $true
                continue
            } elseif ($s.StartsWith('-')) {
                continue
            }
        }
        if ($cmd -eq '') {
            $cmd = $s
        } elseif ($sub -eq '') {
            $sub = $s
        }
    }

    if ($hasHelp) {
        & $script:NkpExe @args
        return
    }

    if ($cmd -eq 'shell' -and $sub -eq 'load') {
        $passthru = [System.Collections.Generic.List[string]]::new()
        $passthru.Add('--prompt')
        $sawShell = $false
        $sawLoad = $false
        $skip = $false
        $endOpts = $false
        foreach ($arg in $args) {
            $s = [string]$arg
            if ($skip) {
                $passthru.Add($s)
                $skip = $false
                continue
            }
            if ($sawLoad) {
                $passthru.Add($s)
                continue
            }
            if (-not $endOpts) {
                if ($s -eq '--') {
                    $endOpts = $true
                    continue
                } elseif ($s -in $valOpts) {
                    $passthru.Add($s)
                    $skip = $true
                    continue
                } elseif ($s.StartsWith('-')) {
                    $passthru.Add($s)
                    continue
                }
            }
            if (-not $sawShell -and $s -eq 'shell') {
                $sawShell = $true
            } elseif ($sawShell -and $s -eq 'load') {
                $sawLoad = $true
            }
        }
        _NkpInvokeHook $passthru.ToArray() -Explicit
        return
    } elseif ($cmd -eq 'shell' -and $sub -eq 'unload') {
        _NkpInvokeHook @('--unload') -Explicit
        return
    }

    & $script:NkpExe @args
    $rc = $global:LASTEXITCODE
    if ($cmd -in @('trust', 'untrust', 'unlock', 'lock') -and $rc -eq 0) {
        _NkpInvokeHook
    }
    $global:LASTEXITCODE = $rc
}

_NkpInvokeHook @('--startup')
"
}

fn emit_pwsh_registrations() -> &'static str {
    r#"
if (-not (Test-Path variable:script:_NkpHookInstalled)) {
    $script:_NkpHookInstalled = $true
    $script:_NkpPrevLocationAction = $ExecutionContext.SessionState.InvokeCommand.LocationChangedAction
    $ExecutionContext.SessionState.InvokeCommand.LocationChangedAction = {
        param($sender, $eventArgs)
        if ($null -ne $script:_NkpPrevLocationAction) {
            & $script:_NkpPrevLocationAction $sender $eventArgs
        }
        _NkpInvokeHook
    }.GetNewClosure()

    if (-not (Test-Path variable:script:_NkpOriginalPrompt)) {
        $script:_NkpOriginalPrompt = $function:global:prompt
    }
    function global:prompt {
        _NkpInvokeHook
        if ($null -ne $script:_NkpOriginalPrompt) {
            & $script:_NkpOriginalPrompt
        } else {
            "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
        }
    }
}

"#
}

fn emit_pwsh_env_hook(bin: Option<&str>) -> String {
    let exe_expr = match bin {
        Some(p) => {
            let mut quoted = String::new();
            push_pwsh_single_quoted(&mut quoted, p);
            quoted
        }
        None => "(Get-Command nkp -CommandType Application -TotalCount 1).Source".to_owned(),
    };

    let mut out = format!(
        r#"$script:NkpExe = {exe_expr}
if (-not (Test-Path variable:script:NkpEnvState)) {{
    $script:NkpEnvState = ''
}}

function script:_NkpInvokeHook {{
    param(
        [string[]]$ExtraArgs = @(),
        [switch]$Explicit
    )
    $savedOk = $?
    $savedLastExit = $global:LASTEXITCODE
    if ([string]::IsNullOrEmpty($script:NkpExe)) {{
        return
    }}

    $hookArgs = [System.Collections.Generic.List[string]]::new()
    $hookArgs.Add('__hook')
    $hookArgs.Add('pwsh')
    $hasUnload = $false
    foreach ($a in $ExtraArgs) {{
        $hookArgs.Add($a)
        if ($a -eq '--unload') {{
            $hasUnload = $true
        }}
    }}
    if (-not $hasUnload) {{
        if ($PWD.Provider.Name -eq 'FileSystem') {{
            $hookArgs.Add('--cwd')
            $hookArgs.Add($PWD.ProviderPath)
        }} else {{
            $hookArgs.Add('--unload')
        }}
    }}

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:NkpExe
    foreach ($arg in $hookArgs) {{
        [void]$psi.ArgumentList.Add($arg)
    }}
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $false
    $psi.EnvironmentVariables['__NKP_ENV_STATE'] = $script:NkpEnvState

    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) {{
        if ($Explicit) {{
            $global:LASTEXITCODE = 1
        }} else {{
            $global:LASTEXITCODE = $savedLastExit
        }}
        return
    }}
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $hookExit = $proc.ExitCode
    $proc.Dispose()

    if ($hookExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($stdout)) {{
        $patch = $stdout | ConvertFrom-Json
        if ($null -ne $patch.unset) {{
            foreach ($name in $patch.unset) {{
                [System.Environment]::SetEnvironmentVariable([string]$name, $null, 'Process')
            }}
        }}
        if ($null -ne $patch.set) {{
            foreach ($prop in $patch.set.PSObject.Properties) {{
                $val = [string]$prop.Value
                if ($val.Length -eq 0 -and [System.Environment]::Version.Major -lt 9) {{
                    [System.Console]::Error.WriteLine("nkp: warning: PowerShell on .NET < 9 cannot set empty env var '$($prop.Name)'; variable unset")
                }}
                [System.Environment]::SetEnvironmentVariable([string]$prop.Name, $val, 'Process')
            }}
        }}
        if ($null -ne $patch.state) {{
            $script:NkpEnvState = [string]$patch.state
        }} else {{
            $script:NkpEnvState = ''
        }}
    }}

    if ($Explicit) {{
        $global:LASTEXITCODE = $hookExit
    }} else {{
        $global:LASTEXITCODE = $savedLastExit
        if (-not $savedOk) {{
            try {{ Write-Error -Message '' -ErrorAction SilentlyContinue }} catch {{}}
        }}
    }}
}}
"#
    );
    out.push_str(emit_pwsh_registrations());
    out.push_str(emit_pwsh_wrapper());
    out
}

fn emit_nushell_wrappers(exe_lit: &str) -> String {
    format!(
        r#"def --env --wrapped "nkp shell load" [...rest: string] {{
  if ("-h" in $rest) or ("--help" in $rest) {{
    run-external {exe_lit} "shell" "load" ...$rest
    return
  }}
  _nkp_apply_hook true "--prompt" ...$rest
}}

def --env --wrapped "nkp shell unload" [...rest: string] {{
  if ("-h" in $rest) or ("--help" in $rest) {{
    run-external {exe_lit} "shell" "unload" ...$rest
    return
  }}
  _nkp_apply_hook true "--unload"
}}

def --env --wrapped "nkp trust" [...rest: string] {{
  run-external {exe_lit} "trust" ...$rest
  if $env.LAST_EXIT_CODE == 0 and not (("-h" in $rest) or ("--help" in $rest)) {{
    _nkp_apply_hook false
  }}
}}

def --env --wrapped "nkp untrust" [...rest: string] {{
  run-external {exe_lit} "untrust" ...$rest
  if $env.LAST_EXIT_CODE == 0 and not (("-h" in $rest) or ("--help" in $rest)) {{
    _nkp_apply_hook false
  }}
}}

def --env --wrapped "nkp unlock" [...rest: string] {{
  run-external {exe_lit} "unlock" ...$rest
  if $env.LAST_EXIT_CODE == 0 and not (("-h" in $rest) or ("--help" in $rest)) {{
    _nkp_apply_hook false
  }}
}}

def --env --wrapped "nkp lock" [...rest: string] {{
  run-external {exe_lit} "lock" ...$rest
  if $env.LAST_EXIT_CODE == 0 and not (("-h" in $rest) or ("--help" in $rest)) {{
    _nkp_apply_hook false
  }}
}}
"#
    )
}

fn emit_nushell_env_hook(bin: Option<&str>) -> String {
    let exe_lit = match bin {
        Some(p) => {
            let escaped = p.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        None => "\"nkp\"".to_owned(),
    };
    let wrappers = emit_nushell_wrappers(&exe_lit);

    format!(
        r#"# Nushell closures/hooks lack shared mutable unexported state across `def --env`
# and `hooks`, so `$env.__NKP_ENV_STATE` lives in `$env` (it holds only MACs and
# non-secret `prior` values, never vault secrets, and `nkp x` strips it).
def --env _nkp_apply_hook [explicit: bool, ...extra_args: string] {{
  let prev_state = ($env.__NKP_ENV_STATE? | default "")
  let res = (with-env {{ __NKP_ENV_STATE: $prev_state }} {{
    run-external {exe_lit} "__hook" "nushell" ...$extra_args | complete
  }})
  if ($res.stderr | is-not-empty) {{
    print --stderr --no-newline $res.stderr
  }}
  if $res.exit_code == 0 {{
    let body = ($res.stdout | str trim)
    if ($body | is-not-empty) {{
      let patch = ($body | from json)
      for name in ($patch.unset? | default []) {{
        hide-env --ignore-errors $name
      }}
      let set_map = ($patch.set? | default {{}})
      if ($set_map | columns | is-not-empty) {{
        load-env $set_map
      }}
      load-env {{ __NKP_ENV_STATE: ($patch.state? | default "") }}
    }}
  }} else if $explicit {{
    error make --unspanned {{ msg: $"nkp hook failed with exit code ($res.exit_code)" }}
  }}
}}

{wrappers}
$env.config = ($env.config? | default {{}})
$env.config.hooks = ($env.config.hooks? | default {{}})
$env.config.hooks.env_change = ($env.config.hooks.env_change? | default {{}})
$env.config.hooks.env_change.PWD = (
  ($env.config.hooks.env_change.PWD? | default []) | append {{|before, after| _nkp_apply_hook false }}
)
$env.config.hooks.pre_prompt = (
  ($env.config.hooks.pre_prompt? | default []) | append {{|| _nkp_apply_hook false }}
)

_nkp_apply_hook false "--startup"
"#
    )
}

/// Emits the complete `nkp shell init <shell>` script with LF line endings.
///
/// When `completion_script` is `Some`, it is prepended before the env hook
/// block. When `include_env` is `true`, emits the dual-trigger hook, thin `nkp`
/// wrapper, and `--startup` initialization.
///
/// # Errors
///
/// Returns [`HookError::NothingToEmit`] if both `completion_script` is `None`
/// and `include_env` is `false`.
pub fn emit_shell_init(
    shell: HookShell,
    completion_script: Option<&str>,
    include_env: bool,
) -> Result<String, HookError> {
    emit_shell_init_with_bin(shell, completion_script, include_env, None)
}

/// Emits the `nkp shell init <shell>` script with an optional pinned `nkp`
/// executable path (validated to be absolute and display-safe).
///
/// # Errors
///
/// Returns [`HookError::NothingToEmit`] when both completion and env are
/// disabled, or [`HookError::InvalidExecutablePath`] when `bin_path` is
/// invalid.
pub fn emit_shell_init_with_bin(
    shell: HookShell,
    completion_script: Option<&str>,
    include_env: bool,
    bin_path: Option<&Path>,
) -> Result<String, HookError> {
    if completion_script.is_none() && !include_env {
        return Err(HookError::NothingToEmit);
    }
    let validated_bin = validate_pinned_bin(bin_path)?;

    let mut out = String::new();
    if let Some(comp) = completion_script {
        let normalized = comp.replace("\r\n", "\n");
        out.push_str(&normalized);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }

    if include_env {
        if !out.is_empty() {
            out.push('\n');
        }
        let env_block = match shell {
            HookShell::Bash | HookShell::Zsh => {
                emit_posix_env_hook(shell, validated_bin.as_deref())
            }
            HookShell::Fish => emit_fish_env_hook(validated_bin.as_deref()),
            HookShell::Pwsh => emit_pwsh_env_hook(validated_bin.as_deref()),
            HookShell::Nushell => emit_nushell_env_hook(validated_bin.as_deref()),
        };
        out.push_str(&env_block.replace("\r\n", "\n"));
    }

    Ok(out)
}
