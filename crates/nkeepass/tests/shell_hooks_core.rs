//! Integration tests for `.nkp.toml` manifest parsing & ancestor walk,
//! fail-closed `trust.json` store, `__NKP_ENV_STATE` transitions, and 5-shell
//! hook/init emitters.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "integration test assertions"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nkeepass::env_file::EnvValueKind;
use nkeepass::hook::{
    ChainEntry, HookError, HookPatch, HookShell, HookState, LOCKED_VAULT_HINT, MAX_PRIOR_BYTES,
    MAX_STATE_ENCODED_BYTES, STATE_VERSION, StateDecode, TargetEnv, TrackedVar, TransitionAction,
    VaultFingerprint, compute_chain_digest, compute_transition, compute_var_mac,
    compute_warned_digest, decode_state, emit_hook_patch, emit_shell_init,
    emit_shell_init_with_bin, encode_state, is_fast_path_unchanged, preopen_vault_fingerprint,
};
use nkeepass::manifest::{
    BindingSource, InheritMode, MAX_INHERIT_DEPTH, MAX_MANIFEST_BYTES, MAX_VAULTS_PER_HOOK,
    ManifestError, ManifestSourceKind, VaultSpec, discover_chain, load_single_manifest_file,
    merge_chain_bindings, parse_manifest_toml,
};
use nkeepass::template::TemplateError;
use nkeepass::trust::{
    TrustError, TrustKind, TrustStore, canonical_key_for_platform, is_trusted, list_trusted,
    normalize_display_path_for_platform, prune_missing, trust_file, trust_manifest_file,
    untrust_all, untrust_file,
};
use tempfile::tempdir;
use zeroize::Zeroizing;

fn write_safe_file(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
    let path = path.as_ref();
    fs::write(path, bytes.as_ref()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn make_ambient(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let mut map = BTreeMap::new();
    for &(k, v) in pairs {
        map.insert(k.to_owned(), OsString::from(v));
    }
    move |name: &str| map.get(name).cloned()
}

#[test]
fn manifest_parses_valid_v1_schema() {
    let toml = r#"
# Project secrets
version = 1
vault = "work"
inherit = "merge"
env_files = [".env", "config/local.env"]

[env]
STRIPE_KEY = "projects/myapp/stripe"
DATABASE_URL = { entry = "projects/myapp/postgres", field = "URL" }

[env.ADMIN_OTP]
entry = "services/admin"
field = "otp"
"#;
    let doc = parse_manifest_toml(toml).expect("valid .nkp.toml");
    assert_eq!(doc.version, 1);
    assert_eq!(doc.vault, Some(VaultSpec::Alias("work".to_owned())));
    assert_eq!(doc.inherit, InheritMode::Merge);
    assert_eq!(doc.env_files, vec![".env", "config/local.env"]);
    assert_eq!(doc.env.len(), 3);
    assert_eq!(doc.env[0].0, "STRIPE_KEY");
    assert_eq!(doc.env[0].1.entry, "projects/myapp/stripe");
    assert_eq!(doc.env[0].1.field, None);
    assert_eq!(doc.env[1].0, "DATABASE_URL");
    assert_eq!(doc.env[1].1.field.as_deref(), Some("URL"));
    assert_eq!(doc.env[2].0, "ADMIN_OTP");
    assert_eq!(doc.env[2].1.field.as_deref(), Some("otp"));
}

#[test]
fn manifest_rejects_unknown_duplicate_version_reserved_and_collisions() {
    // Missing version
    assert_eq!(
        parse_manifest_toml("[env]\nFOO = \"bar\"\n"),
        Err(ManifestError::UnsupportedVersion)
    );
    // Wrong version
    assert_eq!(
        parse_manifest_toml("version = 2\n[env]\nFOO = \"bar\"\n"),
        Err(ManifestError::UnsupportedVersion)
    );
    // Unknown field
    assert_eq!(
        parse_manifest_toml("version = 1\npassword = \"nope\"\n"),
        Err(ManifestError::UnknownField)
    );
    // Unknown table
    assert_eq!(
        parse_manifest_toml("version = 1\n[other]\nFOO = \"bar\"\n"),
        Err(ManifestError::UnknownField)
    );
    // Unknown inline table key
    assert_eq!(
        parse_manifest_toml("version = 1\n[env]\nFOO = { entry = \"a\", extra = \"b\" }\n"),
        Err(ManifestError::UnknownField)
    );
    // Duplicate top-level key
    assert_eq!(
        parse_manifest_toml("version = 1\nversion = 1\n"),
        Err(ManifestError::DuplicateField)
    );
    // Conflicting env_file and env_files
    assert_eq!(
        parse_manifest_toml("version = 1\nenv_file = \".env\"\nenv_files = [\".env\"]\n"),
        Err(ManifestError::ConflictingEnvFiles)
    );
    // Duplicate var in [env]
    assert_eq!(
        parse_manifest_toml("version = 1\n[env]\nFOO = \"a\"\nFOO = \"b\"\n"),
        Err(ManifestError::Template(TemplateError::DuplicateEnvVar))
    );
    // Case-only collision in [env]
    assert_eq!(
        parse_manifest_toml("version = 1\n[env]\nAPI_KEY = \"a\"\napi_key = \"b\"\n"),
        Err(ManifestError::Template(TemplateError::DuplicateEnvVar))
    );
    // Reserved vars (M3)
    for reserved in [
        "PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NKP_PASSWORD",
        "NEO_KEEPASS_DATA_DIR",
        "PROMPT_COMMAND",
        "PS0",
        "UMASK",
        "DOTNET_STARTUP_HOOKS",
        "NU_PLUGIN_DIRS",
        "CONFIG",
        "UID",
    ] {
        let doc = format!("version = 1\n[env]\n{reserved} = \"a/b\"\n");
        assert_eq!(
            parse_manifest_toml(&doc),
            Err(ManifestError::Template(TemplateError::ReservedEnvVar)),
            "expected reserved error for {reserved}"
        );
    }
    // Overlong var name (> 128)
    let long_name = "A".repeat(129);
    assert_eq!(
        parse_manifest_toml(&format!("version = 1\n[env]\n{long_name} = \"a/b\"\n")),
        Err(ManifestError::Template(TemplateError::InvalidEnvVarName))
    );
    // Relative vault path / traversal / BiDi
    for bad_vault in [
        "vault.kdbx",
        "./work.kdbx",
        "../work.kdbx",
        "dir/work.kdbx",
        "/tmp/va\u{202E}ult.kdbx",
    ] {
        let doc = format!("version = 1\nvault = \"{bad_vault}\"\n");
        assert_eq!(
            parse_manifest_toml(&doc),
            Err(ManifestError::InvalidVaultSpec),
            "expected invalid vault spec for {bad_vault:?}"
        );
    }
    // Path traversal / absolute in env_file
    for bad_env_file in ["../.env", "/etc/passwd", "./.env", "a/../.env", "C:\\x.env"] {
        let doc = format!(
            "version = 1\nenv_file = \"{}\"\n",
            bad_env_file.replace('\\', "\\\\")
        );
        assert_eq!(
            parse_manifest_toml(&doc),
            Err(ManifestError::InvalidEnvFilePath),
            "expected invalid env_file for {bad_env_file:?}"
        );
    }
    // Deeply nested / oversized TOML DoS
    let nested = "[".repeat(64 * 1024);
    assert!(parse_manifest_toml(&nested).is_err());
    let oversized = format!("version = 1\n# {}\n", "x".repeat(MAX_MANIFEST_BYTES + 1));
    assert_eq!(
        parse_manifest_toml(&oversized),
        Err(ManifestError::TooLarge)
    );
    // Regression: multi-byte UTF-8 inside \uXXXX escape must return ParseSyntax, never panic
    assert_eq!(
        parse_manifest_toml("version = 1\n[env]\nX = \"\\u123\u{00E9}\"\n"),
        Err(ManifestError::ParseSyntax { line: 3 })
    );
    assert_eq!(
        parse_manifest_toml("version = 1\n[env]\nX = \"\\U0000123\u{00E9}\"\n"),
        Err(ManifestError::ParseSyntax { line: 3 })
    );
}

#[test]
fn manifest_ancestor_walk_merge_stop_case_collision_and_symlinks() {
    let root = tempdir().unwrap();
    let org = root.path().join("org");
    let app = org.join("app");
    let sub = app.join("sub");
    fs::create_dir_all(&sub).unwrap();

    write_safe_file(
        org.join(".nkp.toml"),
        "version = 1\nvault = \"org_vault\"\ninherit = \"stop\"\n[env]\nSHARED = \"org/shared\"\nPARENT_ONLY = \"org/p\"\n",
    );
    write_safe_file(app.join(".env"), "LOCAL_LIT=hello\nSHARED=from_dotenv\n");
    write_safe_file(
        app.join(".nkp.toml"),
        "version = 1\ninherit = \"merge\"\nenv_file = \".env\"\n[env]\nSHARED = \"app/shared\"\n",
    );

    let chain = discover_chain(&sub, |_| false)
        .expect("discover succeeds")
        .expect("chain present");
    assert_eq!(chain.manifests.len(), 2);
    assert_eq!(chain.files_to_verify.len(), 3); // org/.nkp.toml, app/.nkp.toml, app/.env

    let merged = merge_chain_bindings(&chain).expect("merge succeeds");
    assert!(merged.requires_vault_unlock);
    assert_eq!(
        merged.bindings["PARENT_ONLY"].vault,
        Some(VaultSpec::Alias("org_vault".to_owned()))
    );
    // app inherits vault from org since app omitted vault, and app [env] overrides app .env and org [env]
    assert!(matches!(
        &merged.bindings["SHARED"].source,
        BindingSource::Entry(e) if e.entry == "app/shared"
    ));
    assert!(matches!(
        &merged.bindings["LOCAL_LIT"].source,
        BindingSource::DotEnv(EnvValueKind::Literal(s)) if s == "hello"
    ));

    // Case-only collision across merge boundary must fail closed
    write_safe_file(
        app.join(".nkp.toml"),
        "version = 1\ninherit = \"merge\"\n[env]\nparent_only = \"app/collide\"\n",
    );
    let bad_chain = discover_chain(&sub, |_| false).unwrap().unwrap();
    assert_eq!(
        merge_chain_bindings(&bad_chain),
        Err(ManifestError::Template(TemplateError::DuplicateEnvVar))
    );

    // inherit = "stop" stops before org
    write_safe_file(
        app.join(".nkp.toml"),
        "version = 1\ninherit = \"stop\"\n[env]\nAPP_KEY = \"app/k\"\n",
    );
    let stopped = discover_chain(&sub, |_| false).unwrap().unwrap();
    assert_eq!(stopped.manifests.len(), 1);
}

#[test]
fn manifest_ignores_untrusted_dotenv_and_loads_trusted_dotenv_zero_unlock() {
    let root = tempdir().unwrap();
    let proj = root.path().join("proj");
    fs::create_dir_all(&proj).unwrap();
    let dotenv = proj.join(".env");
    write_safe_file(&dotenv, "APP_ENV=local\nPORT=8080\n");

    // Untrusted ordinary .env is ignored completely
    assert!(discover_chain(&proj, |_| false).unwrap().is_none());

    // Explicitly trusted ordinary .env is discovered and needs no vault unlock
    let chain = discover_chain(&proj, |p| p.ends_with(".env"))
        .unwrap()
        .expect("trusted .env discovered");
    assert_eq!(chain.manifests[0].kind, ManifestSourceKind::DotEnv);
    let merged = merge_chain_bindings(&chain).unwrap();
    assert!(!merged.requires_vault_unlock);
    assert_eq!(merged.bindings.len(), 2);
}

#[test]
fn manifest_enforces_inherit_and_vault_bounds_and_rejects_symlinks() {
    // Inherit depth > MAX_INHERIT_DEPTH (8)
    let root = tempdir().unwrap();
    let mut cur = root.path().to_path_buf();
    for i in 0..=MAX_INHERIT_DEPTH {
        cur = cur.join(format!("d{i}"));
        fs::create_dir_all(&cur).unwrap();
        let vault_idx = i % MAX_VAULTS_PER_HOOK;
        write_safe_file(
            cur.join(".nkp.toml"),
            format!("version = 1\nvault = \"v{vault_idx}\"\ninherit = \"merge\"\n"),
        );
    }
    assert_eq!(
        discover_chain(&cur, |_| false),
        Err(ManifestError::TooManyManifests)
    );

    // Distinct vaults > MAX_VAULTS_PER_HOOK (4)
    let root2 = tempdir().unwrap();
    let mut cur2 = root2.path().to_path_buf();
    for i in 0..=MAX_VAULTS_PER_HOOK {
        cur2 = cur2.join(format!("v{i}"));
        fs::create_dir_all(&cur2).unwrap();
        write_safe_file(
            cur2.join(".nkp.toml"),
            format!("version = 1\nvault = \"vault_{i}\"\ninherit = \"merge\"\n"),
        );
    }
    assert_eq!(
        discover_chain(&cur2, |_| false),
        Err(ManifestError::TooManyVaults)
    );

    // Symlink manifest & world-writable refusal on Unix, plus vault pre-open safety (M4)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::symlink;

        let sroot = tempdir().unwrap();
        let real = sroot.path().join("real.toml");
        write_safe_file(&real, "version = 1\n");
        let link = sroot.path().join(".nkp.toml");
        symlink(&real, &link).unwrap();
        assert_eq!(
            discover_chain(sroot.path(), |_| false),
            Err(ManifestError::UnsafeFile)
        );

        // World-writable .nkp.toml refused on Unix
        let wroot = tempdir().unwrap();
        let wtoml = wroot.path().join(".nkp.toml");
        write_safe_file(&wtoml, "version = 1\n");
        fs::set_permissions(&wtoml, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            discover_chain(wroot.path(), |_| false),
            Err(ManifestError::UnsafeFile)
        );

        // preopen_vault_fingerprint accepts regular file and rejects symlink
        let vfile = sroot.path().join("vault.kdbx");
        write_safe_file(&vfile, b"kdbx-bytes");
        let fp = preopen_vault_fingerprint(&vfile).unwrap();
        assert_eq!(fp.size, 10);
        let vlink = sroot.path().join("link.kdbx");
        symlink(&vfile, &vlink).unwrap();
        assert!(preopen_vault_fingerprint(&vlink).is_err());
    }
}

#[test]
fn trust_store_lifecycle_tamper_rejection_and_cross_platform_keys() {
    let store_root = tempdir().unwrap();
    let store_dir = store_root.path().join("nkeepass");
    let work = tempdir().unwrap();
    let env_file = work.path().join(".env");
    let toml_file = work.path().join(".nkp.toml");
    write_safe_file(&env_file, "LITERAL=ok\n");
    write_safe_file(&toml_file, "version = 1\nenv_file = \".env\"\n");

    // Initially untrusted
    let empty = TrustStore::load_from_dir(&store_dir).unwrap();
    let pre_loaded = load_single_manifest_file(&toml_file).unwrap();
    assert!(!empty.is_trusted(&toml_file, &pre_loaded.file.sha256));

    // Trust manifest + referenced .env atomically
    let (loaded, entries) = trust_manifest_file(&store_dir, &toml_file, 1_700_000_000).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(is_trusted(&store_dir, &loaded.file.canonical_path, &loaded.file.sha256).unwrap());
    assert!(
        is_trusted(
            &store_dir,
            &loaded.env_files[0].file.canonical_path,
            &loaded.env_files[0].file.sha256
        )
        .unwrap()
    );

    // Modifying .env invalidates its trust immediately
    write_safe_file(&env_file, "LITERAL=tampered\n");
    let modified_env = load_single_manifest_file(&env_file).unwrap();
    assert!(
        !is_trusted(
            &store_dir,
            &modified_env.file.canonical_path,
            &modified_env.file.sha256
        )
        .unwrap()
    );

    // Trust standalone file, prune missing, untrust
    let extra = work.path().join("extra.env");
    write_safe_file(&extra, "A=1\n");
    let extra_sha = load_single_manifest_file(&extra).unwrap().file.sha256;
    trust_file(
        &store_dir,
        &extra,
        &extra_sha,
        TrustKind::DotEnv,
        1_700_000_001,
    )
    .unwrap();
    assert_eq!(list_trusted(&store_dir).unwrap().len(), 3);

    fs::remove_file(&extra).unwrap();
    assert_eq!(prune_missing(&store_dir).unwrap(), 1);
    assert_eq!(list_trusted(&store_dir).unwrap().len(), 2);

    assert!(untrust_file(&store_dir, &toml_file).unwrap());
    assert!(!is_trusted(&store_dir, &loaded.file.canonical_path, &loaded.file.sha256).unwrap());
    assert_eq!(untrust_all(&store_dir).unwrap(), 1);
    assert!(list_trusted(&store_dir).unwrap().is_empty());

    // Trusting a bad manifest preserves ManifestError detail
    let bad_toml = work.path().join("bad").join(".nkp.toml");
    fs::create_dir_all(bad_toml.parent().unwrap()).unwrap();
    write_safe_file(&bad_toml, "version = 2\n");
    assert_eq!(
        trust_manifest_file(&store_dir, &bad_toml, 1_700_000_000),
        Err(TrustError::Manifest(ManifestError::UnsupportedVersion))
    );

    // Windows key normalization (H3) & BiDi rejection (M4)
    assert_eq!(
        canonical_key_for_platform(r"\\?\C:\Work\App\.nkp.toml", true).unwrap(),
        r"c:\work\app\.nkp.toml"
    );
    assert_eq!(
        canonical_key_for_platform("c:/work/app/.nkp.toml", true).unwrap(),
        r"c:\work\app\.nkp.toml"
    );
    assert_eq!(
        normalize_display_path_for_platform(r"\\?\C:\Work\.nkp.toml", true).unwrap(),
        r"C:\Work\.nkp.toml"
    );
    assert_eq!(
        canonical_key_for_platform(r"\\?\UNC\server\share\.nkp.toml", true),
        Err(TrustError::InvalidPath)
    );
    assert_eq!(
        canonical_key_for_platform("/tmp/a\u{202E}b/.nkp.toml", false),
        Err(TrustError::InvalidPath)
    );

    // Unix permissions check on trust.json
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        write_safe_file(&extra, "A=1\n");
        let sha = load_single_manifest_file(&extra).unwrap().file.sha256;
        trust_file(&store_dir, &extra, &sha, TrustKind::DotEnv, 1_700_000_002).unwrap();
        let trust_json = store_dir.join("trust.json");
        fs::set_permissions(&trust_json, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            TrustStore::load_from_dir(&store_dir),
            Err(TrustError::UnsafePermissions)
        );
    }
}

#[test]
fn hook_state_transitions_nested_manual_edits_subshell_and_unload() {
    let chain_a = vec![ChainEntry {
        path: "/org/a/.nkp.toml".to_owned(),
        sha256: "a".repeat(64),
    }];
    let chain_b = vec![ChainEntry {
        path: "/org/b/.nkp.toml".to_owned(),
        sha256: "b".repeat(64),
    }];
    let target_a = TargetEnv {
        chain: chain_a.clone(),
        vaults: vec![VaultFingerprint {
            path: "/org/v.kdbx".to_owned(),
            mtime_secs: 100,
            mtime_nanos: 0,
            ctime_secs: 100,
            ctime_nanos: 0,
            size: 1024,
            ino: 42,
        }],
        session_id: None,
        resolved_vars: vec![
            ("API_KEY".to_owned(), Zeroizing::new("secret_a".to_owned())),
            ("APP_ENV".to_owned(), Zeroizing::new("staging".to_owned())),
        ],
    };

    // Enter Dir A while APP_ENV="local" exists in ambient env
    let out1 = compute_transition(
        "",
        TransitionAction::Activate {
            target: &target_a,
            force_reload: false,
        },
        make_ambient(&[("APP_ENV", "local")]),
    )
    .unwrap();
    assert!(out1.emit_patch);
    assert_eq!(out1.patch.set.get("API_KEY").unwrap().as_str(), "secret_a");
    assert_eq!(out1.patch.set.get("APP_ENV").unwrap().as_str(), "staging");
    let state1_enc = out1.patch.state.clone().unwrap();
    let state1 = out1.new_state.clone().unwrap();
    assert_eq!(state1.vars["API_KEY"].prior, None);
    assert_eq!(state1.vars["APP_ENV"].prior.as_deref(), Some("local"));
    // Verify Debug does not leak secret values or prior
    assert!(!format!("{:?}", out1.patch).contains("secret_a"));
    assert!(!format!("{state1:?}").contains("local"));
    assert!(!format!("{target_a:?}").contains("secret_a"));
    // Verify fast-path matches
    assert!(is_fast_path_unchanged(
        &state1,
        &chain_a,
        &target_a.vaults,
        None
    ));

    // Switch Dir A -> Dir B (nested/different project): keeps original prior "local" for APP_ENV!
    let target_b = TargetEnv {
        chain: chain_b.clone(),
        vaults: target_a.vaults.clone(),
        session_id: None,
        resolved_vars: vec![
            ("APP_ENV".to_owned(), Zeroizing::new("prod".to_owned())),
            ("ONLY_B".to_owned(), Zeroizing::new("b_val".to_owned())),
        ],
    };
    let out2 = compute_transition(
        &state1_enc,
        TransitionAction::Activate {
            target: &target_b,
            force_reload: false,
        },
        make_ambient(&[("API_KEY", "secret_a"), ("APP_ENV", "staging")]),
    )
    .unwrap();
    assert_eq!(out2.patch.unset, vec!["API_KEY"]);
    assert_eq!(out2.patch.set.get("APP_ENV").unwrap().as_str(), "prod");
    assert_eq!(out2.patch.set.get("ONLY_B").unwrap().as_str(), "b_val");
    let state2 = out2.new_state.unwrap();
    assert_eq!(state2.vars["APP_ENV"].prior.as_deref(), Some("local"));
    let state2_enc = out2.patch.state.unwrap();

    // User manually edits ONLY_B -> "user_custom", leaves APP_ENV untouched, then leaves dir!
    let out3 = compute_transition(
        &state2_enc,
        TransitionAction::Leave,
        make_ambient(&[("APP_ENV", "prod"), ("ONLY_B", "user_custom")]),
    )
    .unwrap();
    assert!(out3.patch.unset.is_empty()); // ONLY_B preserved!
    assert_eq!(out3.patch.set.get("APP_ENV").unwrap().as_str(), "local");
    assert!(out3.patch.state.is_none());

    // Explicit `nkp shell unload` sets unloaded tombstone (M1)
    let digest_a = compute_chain_digest(&chain_a);
    let unloaded = compute_transition(
        &state1_enc,
        TransitionAction::Unload {
            current_chain_digest: Some(&digest_a),
        },
        make_ambient(&[("API_KEY", "secret_a"), ("APP_ENV", "staging")]),
    )
    .unwrap();
    assert_eq!(unloaded.patch.unset, vec!["API_KEY"]);
    assert_eq!(unloaded.patch.set.get("APP_ENV").unwrap().as_str(), "local");
    let unloaded_enc = unloaded.patch.state.unwrap();

    // Subsequent prompt tick stays unloaded (no-op)
    let tick = compute_transition(
        &unloaded_enc,
        TransitionAction::Activate {
            target: &target_a,
            force_reload: false,
        },
        make_ambient(&[("APP_ENV", "local")]),
    )
    .unwrap();
    assert!(!tick.emit_patch);
    let unloaded_state = tick.new_state.unwrap();
    assert!(is_fast_path_unchanged(
        &unloaded_state,
        &chain_a,
        &target_a.vaults,
        None
    ));
    // Session change invalidates fast-path even when chain was unloaded
    assert!(!is_fast_path_unchanged(
        &unloaded_state,
        &chain_a,
        &target_a.vaults,
        Some("sess-123")
    ));

    // `nkp shell load` (force_reload = true) re-activates cleanly
    let reload = compute_transition(
        &unloaded_enc,
        TransitionAction::Activate {
            target: &target_a,
            force_reload: true,
        },
        make_ambient(&[("APP_ENV", "local")]),
    )
    .unwrap();
    assert!(reload.emit_patch);
    assert_eq!(
        reload.patch.set.get("API_KEY").unwrap().as_str(),
        "secret_a"
    );

    // Interactive subshell safeguard (H4): empty state + inherited matching secret -> prior = None
    let subshell = compute_transition(
        "",
        TransitionAction::Activate {
            target: &target_a,
            force_reload: false,
        },
        make_ambient(&[("API_KEY", "secret_a"), ("APP_ENV", "staging")]),
    )
    .unwrap();
    let sub_state = subshell.new_state.unwrap();
    assert_eq!(sub_state.vars["API_KEY"].prior, None);
    assert_eq!(sub_state.vars["APP_ENV"].prior, None);

    // Blocked warning deduplication
    let w_digest = compute_warned_digest("/org/a/.nkp.toml", &"a".repeat(64));
    let blk1 = compute_transition(
        &state1_enc,
        TransitionAction::Blocked {
            warned_digest: &w_digest,
        },
        make_ambient(&[("API_KEY", "secret_a"), ("APP_ENV", "staging")]),
    )
    .unwrap();
    assert!(!blk1.suppress_duplicate_warning);
    assert_eq!(blk1.patch.unset, vec!["API_KEY"]);
    let blk2 = compute_transition(
        blk1.patch.state.as_deref().unwrap(),
        TransitionAction::Blocked {
            warned_digest: &w_digest,
        },
        make_ambient(&[("APP_ENV", "local")]),
    )
    .unwrap();
    assert!(blk2.suppress_duplicate_warning);
    assert!(!blk2.emit_patch);
}

#[test]
fn hook_state_rejects_tampered_reserved_oversized_and_unsafe_ambient_vars() {
    let valid_salt = "0123456789abcdef0123456789abcdef".to_owned();
    let valid_mac = compute_var_mac(&valid_salt, "API_KEY", "x");

    let encode_raw_json = |val: serde_json::Value| -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&val).unwrap())
    };

    // Reserved var in tampered state (H4)
    let tainted_path = encode_raw_json(serde_json::json!({
        "v": STATE_VERSION,
        "salt": valid_salt,
        "chain": [],
        "vaults": [],
        "vars": {
            "PATH": { "mac": valid_mac, "prior": "/tmp/evil" }
        }
    }));
    assert_eq!(decode_state(&tainted_path), StateDecode::Invalid);

    // `compute_transition` discards invalid state safely without writing PATH
    let out =
        compute_transition(&tainted_path, TransitionAction::Leave, make_ambient(&[])).unwrap();
    assert!(out.discarded_corrupt_state);
    assert!(out.patch.set.is_empty());
    assert!(out.patch.unset.is_empty());
    assert!(out.patch.state.is_none());

    // Bad salt length
    let bad_salt = encode_raw_json(serde_json::json!({
        "v": STATE_VERSION,
        "salt": "short",
        "chain": [],
        "vaults": [],
        "vars": {}
    }));
    assert_eq!(decode_state(&bad_salt), StateDecode::Invalid);

    // Control byte in prior
    let bad_prior = encode_raw_json(serde_json::json!({
        "v": STATE_VERSION,
        "salt": valid_salt,
        "chain": [],
        "vaults": [],
        "vars": {
            "API_KEY": { "mac": valid_mac, "prior": "abc\x1b[31m" }
        }
    }));
    assert_eq!(decode_state(&bad_prior), StateDecode::Invalid);

    // Oversized prior > 4096
    let huge_prior = encode_raw_json(serde_json::json!({
        "v": STATE_VERSION,
        "salt": valid_salt,
        "chain": [],
        "vaults": [],
        "vars": {
            "API_KEY": { "mac": valid_mac, "prior": "x".repeat(MAX_PRIOR_BYTES + 1) }
        }
    }));
    assert_eq!(decode_state(&huge_prior), StateDecode::Invalid);

    // Unknown field
    let extra_field = encode_raw_json(serde_json::json!({
        "v": STATE_VERSION,
        "salt": valid_salt,
        "chain": [],
        "vaults": [],
        "extra": 1,
        "vars": {}
    }));
    assert_eq!(decode_state(&extra_field), StateDecode::Invalid);

    // Oversized state > 32 KiB
    assert_eq!(
        decode_state(&"A".repeat(MAX_STATE_ENCODED_BYTES + 1)),
        StateDecode::Invalid
    );

    // Valid round-trip
    let mut vars = BTreeMap::new();
    vars.insert(
        "API_KEY".to_owned(),
        TrackedVar {
            mac: valid_mac,
            prior: Some("old".to_owned()),
        },
    );
    let good = HookState {
        v: STATE_VERSION,
        salt: valid_salt,
        chain: vec![],
        vaults: vec![],
        session_id: None,
        warned: None,
        unloaded: None,
        vars,
    };
    let enc = encode_state(&good).unwrap();
    assert_eq!(decode_state(&enc), StateDecode::Valid(good));

    // Unsafe ambient variable refuses overwrite without leaking value
    let target = TargetEnv {
        chain: vec![],
        vaults: vec![],
        session_id: None,
        resolved_vars: vec![("API_KEY".to_owned(), Zeroizing::new("new".to_owned()))],
    };
    let err = compute_transition(
        "",
        TransitionAction::Activate {
            target: &target,
            force_reload: false,
        },
        make_ambient(&[("API_KEY", "bad\x1bvalue")]),
    )
    .unwrap_err();
    assert_eq!(
        err,
        HookError::UnsafeAmbientVar {
            name: "API_KEY".to_owned()
        }
    );
}

#[test]
fn shell_emitters_enforce_quoting_json_safety_and_unexported_state() {
    assert_eq!(HookShell::parse("sh"), Err(HookError::UnsupportedPosixSh));
    assert_eq!(
        emit_shell_init(HookShell::Bash, None, false),
        Err(HookError::NothingToEmit)
    );
    assert_eq!(LOCKED_VAULT_HINT, "nkp: vault locked; run 'nkp shell load'");
    assert!(!LOCKED_VAULT_HINT.contains("NKP_PASSWORD"));

    let mut set = BTreeMap::new();
    set.insert(
        "POSIX_VAR".to_owned(),
        Zeroizing::new("it's $(id) `uname`\nline2".to_owned()),
    );
    set.insert(
        "PWSH_CURLY".to_owned(),
        Zeroizing::new("a\u{2018}b\u{2019}c\u{201A}d\u{201B}; Start-Process calc".to_owned()),
    );
    set.insert(
        "FISH_VAR".to_owned(),
        Zeroizing::new("a\\b'c\nd".to_owned()),
    );
    let patch = HookPatch {
        unset: vec!["OLD_VAR".to_owned()],
        set,
        state: Some("abc_123-XYZ".to_owned()),
    };

    // Bash & Zsh: POSIX single-quoting, readonly guard, unexported _nkp_env_state
    for shell in [HookShell::Bash, HookShell::Zsh] {
        let script = emit_hook_patch(shell, &patch).unwrap();
        assert!(script.contains("unset OLD_VAR || _nkp_ok=0\n"));
        assert!(script.contains("export POSIX_VAR='it'\\''s $(id) `uname`\nline2' || _nkp_ok=0\n"));
        assert!(script.contains("_nkp_env_state='abc_123-XYZ'"));
        assert!(!script.contains("export _nkp_env_state"));
        assert!(!script.contains("export __NKP_ENV_STATE"));
    }

    // Fish: set -eg and escaped \ and ', unexported set -g _nkp_env_state
    let fish_patch = emit_hook_patch(HookShell::Fish, &patch).unwrap();
    assert!(fish_patch.contains("set -eg OLD_VAR; or set _nkp_ok 0\n"));
    assert!(fish_patch.contains("set -gx FISH_VAR 'a\\\\b\\'c\nd'; or set _nkp_ok 0\n"));
    assert!(fish_patch.contains("set -g _nkp_env_state 'abc_123-XYZ'"));
    assert!(!fish_patch.contains("set -gx _nkp_env_state"));

    // PowerShell & Nushell: JSON only, zero Invoke-Expression, safe U+2018..=U+201B
    for shell in [HookShell::Pwsh, HookShell::Nushell] {
        let json_str = emit_hook_patch(shell, &patch).unwrap();
        assert!(!json_str.contains("Invoke-Expression"));
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["unset"], serde_json::json!(["OLD_VAR"]));
        assert_eq!(
            parsed["set"]["PWSH_CURLY"],
            "a\u{2018}b\u{2019}c\u{201A}d\u{201B}; Start-Process calc"
        );
        assert_eq!(parsed["state"], "abc_123-XYZ");
    }

    // Shell init scripts
    #[cfg(windows)]
    let pinned_bin = Path::new(r"C:\Program Files\nkp\nkp.exe");
    #[cfg(not(windows))]
    let pinned_bin = Path::new("/usr/local/bin/nkp");
    let bash_init =
        emit_shell_init_with_bin(HookShell::Bash, Some("# bash comp"), true, Some(pinned_bin))
            .unwrap();
    assert!(bash_init.contains("# bash comp"));
    assert!(bash_init.contains("PROMPT_COMMAND"));
    assert!(bash_init.contains("__NKP_ENV_STATE=\"${_nkp_env_state:-}\""));
    assert!(bash_init.contains("status)\n          __NKP_ENV_STATE=\"${_nkp_env_state:-}\""));
    assert!(bash_init.contains("_nkp_hook --startup"));
    assert!(!bash_init.contains("--password-fd"));
    assert!(!bash_init.contains("\r\n"));

    let zsh_init = emit_shell_init(HookShell::Zsh, None, true).unwrap();
    assert!(zsh_init.contains("add-zsh-hook chpwd _nkp_hook"));
    assert!(zsh_init.contains("add-zsh-hook precmd _nkp_hook"));
    assert!(!zsh_init.contains("--password-fd"));

    let fish_init = emit_shell_init(HookShell::Fish, None, true).unwrap();
    assert!(fish_init.contains("begin\n    set -lx __NKP_ENV_STATE \"$_nkp_env_state\""));
    assert!(fish_init.contains("set _nkp_lines (command nkp __hook fish"));
    assert!(fish_init.contains(
        "set _nkp_lines (command nkp $_nkp_root_opts __hook fish --prompt $_nkp_passthru)"
    ));
    assert!(fish_init.contains("set _nkp_rc $status"));
    assert!(fish_init.contains("printf '%s\\n' $_nkp_lines | source"));
    assert!(!fish_init.contains("env __NKP_ENV_STATE="));
    assert!(!fish_init.contains("$pipestatus"));
    assert!(!fish_init.contains("--password-fd"));
    assert!(fish_init.contains("--on-variable PWD"));
    assert!(fish_init.contains("--on-event fish_prompt"));

    // Reject relative executable paths in pinned bin_path
    assert_eq!(
        emit_shell_init_with_bin(HookShell::Bash, None, true, Some(Path::new("bin/nkp"))),
        Err(HookError::InvalidExecutablePath)
    );

    // Reject PowerShell Unicode curly quotes U+2018..=U+201B in pinned bin_path
    for q in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
        let bad_bin = if cfg!(windows) {
            format!(r"C:\Program Files\nkp\nkp{q}evil.exe")
        } else {
            format!("/usr/local/bin/nkp{q}evil")
        };
        assert_eq!(
            emit_shell_init_with_bin(HookShell::Pwsh, None, true, Some(Path::new(&bad_bin))),
            Err(HookError::InvalidExecutablePath)
        );
    }

    let pwsh_init = emit_shell_init(HookShell::Pwsh, None, true).unwrap();
    assert!(pwsh_init.contains("(Get-Command nkp -CommandType Application -TotalCount 1).Source"));
    assert!(pwsh_init.contains("$PWD.Provider.Name -eq 'FileSystem'"));
    assert!(pwsh_init.contains("ConvertFrom-Json"));
    assert!(pwsh_init.contains("SetEnvironmentVariable"));
    assert!(pwsh_init.contains("$script:_NkpHookInstalled"));
    assert!(pwsh_init.contains("[switch]$Explicit"));
    assert!(pwsh_init.contains("[string[]]$RootArgs = @()"));
    assert!(pwsh_init.contains("-RootArgs $rootOpts.ToArray()"));
    assert!(pwsh_init.contains("[System.Environment]::Version.Major -lt 9"));
    assert!(!pwsh_init.contains("--password-fd"));
    assert!(!pwsh_init.contains("Invoke-Expression"));

    let nu_init = emit_shell_init(HookShell::Nushell, None, true).unwrap();
    assert!(nu_init.contains("from json"));
    assert!(nu_init.contains("hide-env"));
    assert!(nu_init.contains("load-env"));
    assert!(nu_init.contains("hooks.env_change.PWD"));
    assert!(nu_init.contains("hooks.pre_prompt"));
    assert!(nu_init.contains("def --env --wrapped \"nkp shell load\""));
    assert!(nu_init.contains("def --env --wrapped \"nkp shell unload\""));
    assert!(nu_init.contains("def --env --wrapped \"nkp trust\""));
    assert!(nu_init.contains("print --stderr --no-newline $res.stderr"));
    assert!(nu_init.contains("error make --unspanned"));

    // Syntax-check generated Bash scripts if `bash` is available on the host
    if let Ok(output) = std::process::Command::new("bash")
        .arg("-n")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(bash_init.as_bytes())?;
                let patch_script = emit_hook_patch(HookShell::Bash, &patch).unwrap();
                stdin.write_all(patch_script.as_bytes())?;
            }
            child.wait_with_output()
        })
    {
        assert!(
            output.status.success(),
            "bash -n failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
