//! Integration tests for `nkp://` URI parsing, single-pass text template
//! injection, non-executing `.env` parsing/resolution, and `VaultService`
//! end-to-end lookup.

use std::collections::BTreeMap;

use neotales_keepass::{
    Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxKdf, KdbxWriteOptions, KeePassDatabase,
    ProtectedValue,
};
use nkeepass::env_file::{
    EnvLine, EnvValueKind, MAX_ENV_FILE_BYTES, MAX_ENV_FILE_ENTRIES, is_reserved_env_var,
    parse_env_file, resolve_env_file, validate_env_var_name,
};
use nkeepass::template::{
    EntryAlias, MAX_TEMPLATE_INPUT_BYTES, MAX_TEMPLATE_REFS, NkpUri, RenderOptions, SecretLookup,
    ServiceSecretLookup, TemplateError, ValueEscape, extract_references, parse_nkp_uri,
    render_text,
};
use nkeepass::{KDBX_LIMITS, VaultService};
use zeroize::Zeroizing;

#[derive(Default)]
struct MapLookup {
    entries: BTreeMap<(Option<String>, String, Option<String>), Vec<u8>>,
    calls: usize,
}

impl MapLookup {
    fn insert(
        &mut self,
        vault_alias: Option<&str>,
        entry_path: &str,
        field: Option<&str>,
        value: impl Into<Vec<u8>>,
    ) {
        self.entries.insert(
            (
                vault_alias.map(str::to_owned),
                entry_path.to_owned(),
                field.map(str::to_owned),
            ),
            value.into(),
        );
    }
}

impl SecretLookup for MapLookup {
    fn resolve_secret(&mut self, uri: &NkpUri) -> Result<Zeroizing<Vec<u8>>, TemplateError> {
        self.calls += 1;
        let key = (
            uri.vault_alias.clone(),
            uri.entry_path.clone(),
            uri.field.clone(),
        );
        self.entries
            .get(&key)
            .cloned()
            .map(Zeroizing::new)
            .ok_or(TemplateError::EntryNotFound)
    }
}

struct PanickingLookup;

impl SecretLookup for PanickingLookup {
    fn resolve_secret(&mut self, _uri: &NkpUri) -> Result<Zeroizing<Vec<u8>>, TemplateError> {
        Err(TemplateError::VaultLocked)
    }
}

#[test]
fn parses_valid_nkp_uris() {
    assert_eq!(
        parse_nkp_uri("nkp://stripe"),
        Ok(NkpUri {
            vault_alias: None,
            entry_path: "stripe".to_owned(),
            field: None,
        })
    );
    assert_eq!(
        parse_nkp_uri("nkp://@work/Prod/API%20Key#Custom%20Field"),
        Ok(NkpUri {
            vault_alias: Some("work".to_owned()),
            entry_path: "Prod/API Key".to_owned(),
            field: Some("Custom Field".to_owned()),
        })
    );
    assert_eq!(
        parse_nkp_uri("nkp://%40social/handle"),
        Ok(NkpUri {
            vault_alias: None,
            entry_path: "@social/handle".to_owned(),
            field: None,
        })
    );
    assert_eq!(
        parse_nkp_uri("nkp://services/admin#otp"),
        Ok(NkpUri {
            vault_alias: None,
            entry_path: "services/admin".to_owned(),
            field: Some("otp".to_owned()),
        })
    );
    assert_eq!(
        parse_nkp_uri("nkp://Prod/caf%C3%A9"),
        Ok(NkpUri {
            vault_alias: None,
            entry_path: "Prod/café".to_owned(),
            field: None,
        })
    );
}

#[test]
fn rejects_invalid_and_unsafe_nkp_uris() {
    let invalid_uris = [
        "",
        "http://a/b",
        "nkp:/a/b",
        "nkp://",
        "nkp:///",
        "nkp:///etc/passwd",
        "nkp://a/",
        "nkp://a//b",
        "nkp://.",
        "nkp://..",
        "nkp://a/./b",
        "nkp://a/../b",
        "nkp://a/%2e%2e/b",
        "nkp://@/",
        "nkp://@work",
        "nkp://@work/",
        "nkp://@bad.alias/a",
        "nkp://@work/a#",
        "nkp://a/b#c#d",
        "nkp://a/b#c%23d",
        "nkp://a/%2",
        "nkp://a/%ZZ",
        "nkp://a/%FF",
        "nkp://a/b\0c",
        "nkp://a/b%00c",
        "nkp://a/b\x1bc",
        "nkp://a/b%1Bc",
        "nkp://a/b%7Fc",
        "nkp://a/b%C2%85c",
        "nkp://a/b\u{202E}c",
        "nkp://a/b%E2%80%AEc",
        "nkp://a/b\u{2066}c",
        "nkp://a/b\u{2028}c",
        "nkp://a/b\u{2029}c",
        "nkp://a/b\u{200E}c",
        "nkp://a/b#f\u{202E}",
        "nkp://a/b#f%00",
    ];
    for uri in invalid_uris {
        assert!(parse_nkp_uri(uri).is_err(), "expected failure for {uri:?}");
    }

    let long_alias = format!("nkp://@{}/entry", "a".repeat(129));
    assert_eq!(
        parse_nkp_uri(&long_alias),
        Err(TemplateError::InvalidVaultAlias)
    );

    let long_path = format!("nkp://{}", "a".repeat(1025));
    assert_eq!(
        parse_nkp_uri(&long_path),
        Err(TemplateError::InvalidEntryPath)
    );

    let long_field = format!("nkp://entry#{}", "f".repeat(257));
    assert_eq!(
        parse_nkp_uri(&long_field),
        Err(TemplateError::InvalidFieldName)
    );
}

#[test]
fn render_text_is_single_pass_non_recursive() -> Result<(), TemplateError> {
    let mut lookup = MapLookup::default();
    lookup.insert(
        None,
        "first/secret",
        None,
        b"literal-nkp://second/secret-{{nkp://second/secret}}".to_vec(),
    );
    lookup.insert(None, "second/secret", None, b"SHOULD_NOT_BE_READ".to_vec());

    let rendered = render_text(
        "token={{nkp://first/secret}}",
        &mut lookup,
        &RenderOptions::default(),
    )?;

    assert_eq!(
        rendered.as_str(),
        "token=literal-nkp://second/secret-{{nkp://second/secret}}"
    );
    assert_eq!(lookup.calls, 1);
    Ok(())
}

#[test]
fn render_text_handles_braced_adjacency_bare_tokens_and_literal_braces() -> Result<(), TemplateError>
{
    let mut lookup = MapLookup::default();
    lookup.insert(None, "db/creds", Some("UserName"), b"alice".to_vec());
    lookup.insert(None, "db/creds", Some("Password"), b"s3cr3t!".to_vec());
    lookup.insert(
        Some("work"),
        "Prod/My DB",
        Some("API Key"),
        b"k-123".to_vec(),
    );

    let template = concat!(
        "prefix {{not-a-ref}} ",
        "https://{{nkp://db/creds#UserName}}:{{nkp://db/creds#Password}}@db.internal:5432/app ",
        "key=\"nkp://@work/Prod/My%20DB#API%20Key\" ",
        "wrapped={{{nkp://@work/Prod/My DB#API Key}}} ",
        "(nkp://db/creds#UserName)"
    );

    let refs = extract_references(template)?;
    assert_eq!(refs.len(), 5);

    let rendered = render_text(template, &mut lookup, &RenderOptions::default())?;
    assert_eq!(
        rendered.as_str(),
        "prefix {{not-a-ref}} https://alice:s3cr3t!@db.internal:5432/app key=\"k-123\" wrapped={k-123} (alice)"
    );
    Ok(())
}

#[test]
fn render_text_fails_closed_atomically_on_unclosed_braces_missing_or_unsafe_secrets() {
    let mut lookup = MapLookup::default();
    lookup.insert(None, "ok/entry", None, b"fine".to_vec());
    lookup.insert(None, "bad/utf8", None, vec![0xff, 0xfe]);
    lookup.insert(None, "bad/nul", None, b"a\0b".to_vec());
    lookup.insert(None, "bad/esc", None, b"a\x1b[31mb".to_vec());
    lookup.insert(None, "bad/bidi", None, "a\u{202E}b".as_bytes().to_vec());
    lookup.insert(None, "has/nl", None, b"line1\nline2".to_vec());

    assert_eq!(
        render_text(
            "ok={{nkp://ok/entry}} bad={{nkp://ok/entry",
            &mut lookup,
            &RenderOptions::default()
        ),
        Err(TemplateError::UnterminatedReference)
    );
    assert_eq!(
        extract_references("{{nkp://ok/entry"),
        Err(TemplateError::UnterminatedReference)
    );
    assert_eq!(
        render_text(
            "a=nkp://ok/entry b=nkp://missing/entry",
            &mut lookup,
            &RenderOptions::default()
        ),
        Err(TemplateError::EntryNotFound)
    );
    assert_eq!(
        render_text("nkp://bad/utf8", &mut lookup, &RenderOptions::default()),
        Err(TemplateError::NonUtf8Secret)
    );
    assert_eq!(
        render_text("nkp://bad/nul", &mut lookup, &RenderOptions::default()),
        Err(TemplateError::UnsafeSecretCharacters)
    );
    assert_eq!(
        render_text("nkp://bad/esc", &mut lookup, &RenderOptions::default()),
        Err(TemplateError::UnsafeSecretCharacters)
    );
    assert_eq!(
        render_text("nkp://bad/bidi", &mut lookup, &RenderOptions::default()),
        Err(TemplateError::UnsafeSecretCharacters)
    );

    let no_nl = RenderOptions {
        allow_newlines: false,
        ..RenderOptions::default()
    };
    assert_eq!(
        render_text("nkp://has/nl", &mut lookup, &no_nl),
        Err(TemplateError::UnsafeSecretCharacters)
    );
}

#[test]
fn render_text_dotenv_double_quoted_escapes_and_round_trips() -> Result<(), TemplateError> {
    let mut lookup = MapLookup::default();
    lookup.insert(
        None,
        "app/cert",
        None,
        b"line1\\mid\"quote\"\nline2".to_vec(),
    );

    let opts = RenderOptions {
        escape: ValueEscape::DotenvDoubleQuoted,
        ..RenderOptions::default()
    };
    let rendered = render_text("CERT=nkp://app/cert\n", &mut lookup, &opts)?;
    assert_eq!(
        rendered.as_str(),
        "CERT=\"line1\\\\mid\\\"quote\\\"\\nline2\"\n"
    );

    let parsed = parse_env_file(rendered.as_str())?;
    assert_eq!(
        parsed,
        vec![EnvLine {
            name: "CERT".to_owned(),
            value: EnvValueKind::Literal("line1\\mid\"quote\"\nline2".to_owned()),
        }]
    );
    Ok(())
}

#[test]
fn render_text_enforces_input_output_and_ref_bounds() {
    let mut lookup = MapLookup::default();
    lookup.insert(None, "a/b", None, b"123456".to_vec());

    let invalid_opts = RenderOptions {
        max_input_bytes: MAX_TEMPLATE_INPUT_BYTES + 1,
        ..RenderOptions::default()
    };
    assert_eq!(
        render_text("x", &mut lookup, &invalid_opts),
        Err(TemplateError::InvalidOptions)
    );

    let tight_input = RenderOptions {
        max_input_bytes: 5,
        ..RenderOptions::default()
    };
    assert_eq!(
        render_text("123456", &mut lookup, &tight_input),
        Err(TemplateError::InputTooLarge)
    );

    let tight_output = RenderOptions {
        max_output_bytes: 8,
        ..RenderOptions::default()
    };
    assert_eq!(
        render_text("pfx=nkp://a/b", &mut lookup, &tight_output),
        Err(TemplateError::OutputTooLarge)
    );

    let tight_refs = RenderOptions {
        max_refs: 2,
        ..RenderOptions::default()
    };
    assert_eq!(
        render_text("nkp://a/b nkp://a/b nkp://a/b", &mut lookup, &tight_refs),
        Err(TemplateError::TooManyReferences)
    );

    let too_many_default = "nkp://a/b ".repeat(MAX_TEMPLATE_REFS + 1);
    assert_eq!(
        extract_references(&too_many_default),
        Err(TemplateError::TooManyReferences)
    );
}

#[test]
fn reserved_env_vars_and_name_validation_enforce_m3_blocklist() {
    let reserved = [
        "NEO_KEEPASS_PASSWORD",
        "neo_keepass_vault",
        "NKP_PASSWORD",
        "nkp_hook_prompt",
        "NKEEPASS_DATA_DIR",
        "__NKP_ENV_STATE",
        "__nkp_env_state",
        "PATH",
        "path",
        "LD_PRELOAD",
        "ld_library_path",
        "DYLD_INSERT_LIBRARIES",
        "COMPLUS_Version",
        "BASH_ENV",
        "PROMPT_COMMAND",
        "IFS",
        "ENV",
        "ZDOTDIR",
        "FPATH",
        "PS0",
        "PS1",
        "PS2",
        "PS3",
        "PS4",
        "PROMPT",
        "PROMPT2",
        "PROMPT_COMMAND_RIGHT",
        "RPROMPT",
        "MODULE_PATH",
        "EXECIGNORE",
        "INPUTRC",
        "TMOUT",
        "SHELLOPTS",
        "BASHOPTS",
        "umask",
        "UMASK",
        "fish_function_path",
        "fish_complete_path",
        "fish_user_paths",
        "PSModulePath",
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_PROFILER",
        "CORECLR_PROFILER_PATH",
        "GLIBC_TUNABLES",
        "PYTHONSTARTUP",
        "PERL5OPT",
        "RUBYLIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "NODE_OPTIONS",
        "GIT_SSH_COMMAND",
        "SSH_ASKPASS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_DIRS",
        "COMSPEC",
        "config",
        "NU_LIB_DIRS",
        "NU_PLUGIN_DIRS",
    ];
    for name in reserved {
        assert!(is_reserved_env_var(name), "expected {name} to be reserved");
        assert_eq!(
            validate_env_var_name(name),
            Err(TemplateError::ReservedEnvVar),
            "expected {name} to be rejected"
        );
    }

    for valid in ["API_KEY", "DATABASE_URL", "_APP_TOKEN_2", &"A".repeat(128)] {
        assert!(!is_reserved_env_var(valid));
        assert_eq!(validate_env_var_name(valid), Ok(()));
    }

    for invalid in [
        "",
        "1BAD",
        "BAD-NAME",
        "BAD.NAME",
        "BASH_FUNC_x%%",
        &"A".repeat(129),
    ] {
        assert_eq!(
            validate_env_var_name(invalid),
            Err(TemplateError::InvalidEnvVarName),
            "expected {invalid:?} to fail name validation"
        );
    }
}

#[test]
fn env_file_parses_non_executing_syntax_and_preserves_field_fragments() -> Result<(), TemplateError>
{
    let input = concat!(
        "# Leading comment\r\n",
        "\r\n",
        "export STRIPE_KEY=nkp://app/stripe/live # prod key\n",
        "DB_PASS=nkp://app/db#Password # trailing comment\n",
        "PLAIN_VAL=actualValue\n",
        "export_mode=not_export_keyword\n",
        "SHELL_SUB=$(whoami)\n",
        "BACKTICK=`id`\n",
        "HASH_NO_WS=#not_a_comment\n",
        "EMPTY_COMMENT= # empty with comment\n",
        "SINGLE='literal # not comment $HOME'\n",
        "DOUBLE=\"line1\\\"q\\\"\\\\s\\nline2\" # trailing\n",
        "COMPOSED=\"https://{{nkp://db/creds#UserName}}:{{nkp://db/creds#Password}}@host\"\n",
    );

    let parsed = parse_env_file(input)?;
    assert_eq!(
        parsed,
        vec![
            EnvLine {
                name: "STRIPE_KEY".to_owned(),
                value: EnvValueKind::Template("nkp://app/stripe/live".to_owned()),
            },
            EnvLine {
                name: "DB_PASS".to_owned(),
                value: EnvValueKind::Template("nkp://app/db#Password".to_owned()),
            },
            EnvLine {
                name: "PLAIN_VAL".to_owned(),
                value: EnvValueKind::Literal("actualValue".to_owned()),
            },
            EnvLine {
                name: "export_mode".to_owned(),
                value: EnvValueKind::Literal("not_export_keyword".to_owned()),
            },
            EnvLine {
                name: "SHELL_SUB".to_owned(),
                value: EnvValueKind::Literal("$(whoami)".to_owned()),
            },
            EnvLine {
                name: "BACKTICK".to_owned(),
                value: EnvValueKind::Literal("`id`".to_owned()),
            },
            EnvLine {
                name: "HASH_NO_WS".to_owned(),
                value: EnvValueKind::Literal("#not_a_comment".to_owned()),
            },
            EnvLine {
                name: "EMPTY_COMMENT".to_owned(),
                value: EnvValueKind::Literal(String::new()),
            },
            EnvLine {
                name: "SINGLE".to_owned(),
                value: EnvValueKind::Literal("literal # not comment $HOME".to_owned()),
            },
            EnvLine {
                name: "DOUBLE".to_owned(),
                value: EnvValueKind::Literal("line1\"q\"\\s\nline2".to_owned()),
            },
            EnvLine {
                name: "COMPOSED".to_owned(),
                value: EnvValueKind::Template(
                    "https://{{nkp://db/creds#UserName}}:{{nkp://db/creds#Password}}@host"
                        .to_owned(),
                ),
            },
        ]
    );
    Ok(())
}

#[test]
fn env_file_literal_only_never_calls_lookup() -> Result<(), TemplateError> {
    let lines =
        parse_env_file("export APP_ENV=production\nCMD=$(uname -a)\nESCAPED=\"hello\\nworld\"\n")?;
    let mut locked = PanickingLookup;
    let resolved = resolve_env_file(&lines, &mut locked)?;
    assert_eq!(resolved.len(), 3);
    assert_eq!(resolved[0].0, "APP_ENV");
    assert_eq!(resolved[0].1.as_str(), "production");
    assert_eq!(resolved[1].0, "CMD");
    assert_eq!(resolved[1].1.as_str(), "$(uname -a)");
    assert_eq!(resolved[2].0, "ESCAPED");
    assert_eq!(resolved[2].1.as_str(), "hello\nworld");
    Ok(())
}

#[test]
fn env_file_rejects_reserved_collisions_bad_escapes_and_bounds() {
    assert_eq!(
        parse_env_file("PATH=/tmp/evil\n"),
        Err(TemplateError::ReservedEnvVar)
    );
    assert_eq!(
        parse_env_file("export umask=0000\n"),
        Err(TemplateError::ReservedEnvVar)
    );
    assert_eq!(
        parse_env_file("API_KEY=one\napi_key=two\n"),
        Err(TemplateError::DuplicateEnvVar)
    );
    assert_eq!(
        parse_env_file("BAD=\"\\t\"\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("BAD=\"\\r\"\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("BAD=\"\\q\"\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("BAD='unclosed\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("BAD='ok'trailing\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("NO_EQUALS\n"),
        Err(TemplateError::InvalidEnvSyntax { line: 1 })
    );
    assert_eq!(
        parse_env_file("BAD=ok\u{202E}\n"),
        Err(TemplateError::UnsafeSecretCharacters)
    );

    let too_big = format!("BIG={}\n", "x".repeat(MAX_ENV_FILE_BYTES));
    assert_eq!(
        parse_env_file(&too_big),
        Err(TemplateError::InvalidEnvFileSize)
    );

    let mut too_many = String::new();
    for i in 0..=MAX_ENV_FILE_ENTRIES {
        use std::fmt::Write as _;
        let _ = writeln!(too_many, "VAR_{i}=ok");
    }
    assert_eq!(
        parse_env_file(&too_many),
        Err(TemplateError::TooManyEnvEntries)
    );
}

fn build_e2e_database() -> KeePassDatabase {
    let mut database = KeePassDatabase::default();

    let mut prod = Group::new("Prod");
    let mut dbs = Group::new("Databases");
    let mut pg = Entry::new("Postgres");
    "pg_admin".clone_into(&mut pg.username);
    pg.password = ProtectedValue::from_text("pg-secret-9f2a");
    "postgres://db.internal:5432/app".clone_into(&mut pg.url);
    pg.set_field(Field {
        key: "API Key".into(),
        value: ProtectedValue::from_text("api-custom-42"),
        protected: true,
        protect_in_memory: true,
    });
    dbs.entries.push(pg);
    prod.groups.push(dbs);
    database.root.groups.push(prod);

    let mut social = Group::new("@social");
    let mut handle = Entry::new("handle");
    handle.password = ProtectedValue::from_text("@neotales");
    social.entries.push(handle);
    database.root.groups.push(social);

    let mut auth = Group::new("Auth");
    let mut totp_entry = Entry::new("TOTP");
    totp_entry.password = ProtectedValue::from_text("totp-login-pass");
    totp_entry.set_field(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text(
            "otpauth://totp/Admin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test&period=30",
        ),
        protected: true,
        protect_in_memory: true,
    });
    auth.entries.push(totp_entry);

    let mut hotp_entry = Entry::new("HOTP");
    hotp_entry.set_field(Field {
        key: "otp".into(),
        value: ProtectedValue::from_text(
            "otpauth://hotp/Counter?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
        ),
        protected: true,
        protect_in_memory: true,
    });
    auth.entries.push(hotp_entry);
    database.root.groups.push(auth);

    let mut dup1 = Entry::new("Duplicate");
    dup1.password = ProtectedValue::from_text("one");
    let mut dup2 = Entry::new("duplicate");
    dup2.password = ProtectedValue::from_text("two");
    database.add_entry(dup1);
    database.add_entry(dup2);

    let mut self_ref = Entry::new("SelfRef");
    self_ref.password = ProtectedValue::from_text("{{nkp://Prod/Databases/Postgres#Password}}");
    database.add_entry(self_ref);

    database
}

#[test]
fn service_secret_lookup_end_to_end_with_kdbx_vault() -> Result<(), Box<dyn std::error::Error>> {
    let database = build_e2e_database();
    let dir = tempfile::tempdir()?;
    let vault_path = dir.path().join("template-e2e.kdbx");
    let mut creds = KdbxCredentials::password("master-pass-e2e-771b")?;
    KdbxFile::save(
        &database,
        std::fs::File::create(&vault_path)?,
        &mut creds,
        KdbxWriteOptions {
            kdf: KdbxKdf::Aes,
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KDBX_LIMITS,
    )?;

    let mut service = VaultService::default();
    let session = service
        .open(&vault_path, &mut creds, &KDBX_LIMITS)
        .map_err(|err| std::io::Error::other(err.message()))?;

    let mut aliases = BTreeMap::new();
    aliases.insert(
        "pg".to_owned(),
        EntryAlias {
            target: "Prod/Databases/Postgres".to_owned(),
            field: Some("URL".to_owned()),
        },
    );
    aliases.insert(
        "admin_otp".to_owned(),
        EntryAlias {
            target: "Auth/TOTP".to_owned(),
            field: Some("otp".to_owned()),
        },
    );

    // Timestamp 59s matches RFC 6238 SHA-1 6-digit test vector `287082`.
    let mut lookup = ServiceSecretLookup::new(&service, session, 59)
        .with_vault_alias("work")
        .with_entry_aliases(aliases);

    // Ensure Debug output of lookup never leaks secrets.
    let debug_str = format!("{lookup:?}");
    assert!(!debug_str.contains("pg-secret-9f2a"));
    assert!(!debug_str.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));

    let env_src = concat!(
        "export PG_USER=nkp://@work/Prod/Databases/Postgres#UserName\n",
        "export PG_PASS=nkp://Prod/Databases/Postgres#Password # default password\n",
        "PG_ALIAS_URL=nkp://pg\n",
        "PG_ALIAS_PASS_OVERRIDE=nkp://pg#Password\n",
        "CUSTOM_KEY={{nkp://Prod/Databases/Postgres#API%20Key}}\n",
        "SOCIAL=nkp://%40social/handle\n",
        "OTP_EXPLICIT=nkp://Auth/TOTP#otp\n",
        "OTP_BOUND=nkp://admin_otp\n",
        "SELF_REF=nkp://SelfRef\n",
        "LITERAL_ENV=production\n",
    );

    let parsed = parse_env_file(env_src)?;
    let resolved = resolve_env_file(&parsed, &mut lookup)?;
    let map: BTreeMap<&str, &str> = resolved
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    assert_eq!(map.get("PG_USER"), Some(&"pg_admin"));
    assert_eq!(map.get("PG_PASS"), Some(&"pg-secret-9f2a"));
    assert_eq!(
        map.get("PG_ALIAS_URL"),
        Some(&"postgres://db.internal:5432/app")
    );
    assert_eq!(map.get("PG_ALIAS_PASS_OVERRIDE"), Some(&"pg-secret-9f2a"));
    assert_eq!(map.get("CUSTOM_KEY"), Some(&"api-custom-42"));
    assert_eq!(map.get("SOCIAL"), Some(&"@neotales"));
    assert_eq!(map.get("OTP_EXPLICIT"), Some(&"287082"));
    assert_eq!(map.get("OTP_BOUND"), Some(&"287082"));
    assert_eq!(
        map.get("SELF_REF"),
        Some(&"{{nkp://Prod/Databases/Postgres#Password}}")
    );
    assert_eq!(map.get("LITERAL_ENV"), Some(&"production"));

    // Failure modes against real VaultService:
    assert_service_failure_modes(&mut lookup);

    drop(lookup);
    service
        .lock(session)
        .map_err(|err| std::io::Error::other(err.message()))?;
    let mut locked_lookup = ServiceSecretLookup::new(&service, session, 59);
    assert_eq!(
        render_text(
            "nkp://Prod/Databases/Postgres",
            &mut locked_lookup,
            &RenderOptions::default()
        ),
        Err(TemplateError::VaultLocked)
    );
    Ok(())
}

fn assert_service_failure_modes(lookup: &mut ServiceSecretLookup<'_>) {
    assert_eq!(
        render_text(
            "nkp://@other/Prod/Databases/Postgres",
            lookup,
            &RenderOptions::default()
        ),
        Err(TemplateError::UnknownVaultAlias)
    );
    assert_eq!(
        render_text("nkp://Duplicate", lookup, &RenderOptions::default()),
        Err(TemplateError::AmbiguousEntry)
    );
    assert_eq!(
        render_text("nkp://Auth/HOTP#otp", lookup, &RenderOptions::default()),
        Err(TemplateError::HotpUnsupported)
    );
    assert_eq!(
        render_text(
            "nkp://Prod/Databases/Postgres#NoSuchField",
            lookup,
            &RenderOptions::default()
        ),
        Err(TemplateError::FieldNotFound)
    );
}
