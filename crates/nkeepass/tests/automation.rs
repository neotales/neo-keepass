#![cfg(unix)]
#![allow(
    clippy::too_many_lines,
    reason = "end-to-end automation tests intentionally keep setup and assertions together"
)]

use std::path::Path;
use std::process::{Command, Output};

use neotales_keepass::{
    Attachment, Entry, Field, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxTimestamp,
    KdbxWriteOptions, KeePassDatabase, ProtectedValue, VariantValue,
};
use tempfile::TempDir;

const PASSWORD: &str = "automation-master-disposable-71d9";
const ENTRY_SECRET: &str = "automation-entry-disposable-93ac";
const FIELD_SECRET: &str = "automation-field-disposable-440e";
const NOTES_SECRET: &str = "automation-notes-disposable-e2b1";
const ATTACHMENT_SECRET: &[u8] = b"automation-attachment-disposable-5a90";
const SETX_SECRET: &str = "automation-setx-disposable-682f";
const IMPORT_SECRET: &str = "automation-import-disposable-03ce";

struct TestVault {
    _directory: TempDir,
    path: std::path::PathBuf,
}

impl TestVault {
    fn new(name: &str, database: &KeePassDatabase) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        save(database, &path);
        Self {
            _directory: directory,
            path,
        }
    }
}

fn save(database: &KeePassDatabase, path: &Path) {
    KdbxFile::save(
        database,
        std::fs::File::create(path).unwrap(),
        &mut KdbxCredentials::password(PASSWORD).unwrap(),
        KdbxWriteOptions {
            aes_kdf_rounds: 8,
            ..KdbxWriteOptions::default()
        },
        &KdbxReadLimits::default(),
    )
    .unwrap();
}

fn load(path: &Path) -> KeePassDatabase {
    KdbxFile::load(
        std::fs::File::open(path).unwrap(),
        &mut KdbxCredentials::password(PASSWORD).unwrap(),
        &KdbxReadLimits::default(),
    )
    .unwrap()
}

fn run(vault: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkeepass"))
        .args(["--vault", vault.to_str().unwrap()])
        .args(args)
        .env("XDG_CONFIG_HOME", home)
        .env("NKEEPASS_TEST_PASSWORD", PASSWORD)
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .output()
        .unwrap()
}

fn assert_success_without(output: &Output, forbidden: &[&str]) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for marker in forbidden {
        assert!(!stdout.contains(marker));
        assert!(!stderr.contains(marker));
    }
    serde_json::from_slice(&output.stdout).unwrap()
}

/// An interchange document, edited the way a committed policy file is.
struct Policy {
    home: TempDir,
    document: serde_json::Value,
}

impl Policy {
    /// Exports `vault` and returns the document, so a test starts from the real
    /// shape of a snapshot rather than a hand-written imitation of it.
    fn exported(vault: &Path, home: &Path, name: &str) -> Self {
        let own = tempfile::tempdir().unwrap();
        let path = own.path().join(name);
        let export = run(
            vault,
            home,
            &[
                "secrets",
                "export",
                "--output",
                path.to_str().unwrap(),
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ],
        );
        assert!(
            export.status.success(),
            "export failed: {}",
            String::from_utf8_lossy(&export.stderr)
        );
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let document = serde_json::from_slice(&bytes).unwrap();
        Self {
            home: own,
            document,
        }
    }

    fn entry(&mut self) -> &mut serde_json::Value {
        &mut self.document["database"]["root"]["entries"][0]
    }

    /// Attaches the directive the feature is named for.
    fn with_ensure(&mut self, size: u64) -> &mut Self {
        self.entry()["ensure"] = serde_json::json!({ "size": size });
        self
    }

    /// Empties both of the entry's Password representations, which is what a
    /// policy file that has no value to give looks like.
    fn without_password(&mut self) -> &mut Self {
        let empty = serde_json::json!({ "value": "", "memory_protected": false });
        self.entry()["password"] = empty.clone();
        self.entry()["fields"] = serde_json::json!([
            { "key": "Password", "value": empty, "protected": true, "protect_in_memory": false }
        ]);
        self
    }

    fn write(&self, name: &str) -> String {
        let path = self.home.path().join(name);
        std::fs::write(&path, serde_json::to_vec(&self.document).unwrap()).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

fn entry_password(vault: &Path) -> String {
    let database = load(vault);
    database.root.entries[0]
        .password
        .reveal_text()
        .unwrap()
        .as_str()
        .to_owned()
}

/// Asserts that a run disclosed nothing about `value`.
///
/// Both streams, because a secret on stderr is in a CI log and a secret on
/// stdout is in a pipeline, and a byte search rather than a `contains` so a
/// value with no alignment padding cannot slip past a partial comparison.
fn assert_no_disclosure(output: &Output, value: &str) {
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    assert!(
        !combined
            .windows(value.len())
            .any(|window| window == value.as_bytes()),
        "the value was disclosed: {}",
        String::from_utf8_lossy(&combined)
    );
}

fn database_with_entry(entry: Entry) -> KeePassDatabase {
    let mut database = KeePassDatabase::default();
    database.meta.name = "automation metadata".into();
    database
        .meta
        .custom_data
        .set("label", "metadata-value", None);
    database
        .typed_public_custom_data
        .set("outer", VariantValue::String("outer-value".into()));
    database.root.entries.push(entry);
    database
}

fn login_entry() -> Entry {
    let mut entry = Entry::new("LOGIN");
    entry.username = "automation-user".into();
    entry.url = "https://example.invalid".into();
    entry.notes = NOTES_SECRET.into();
    entry.password = ProtectedValue::from_text(ENTRY_SECRET);
    entry.set_field(Field {
        key: "Token".into(),
        value: ProtectedValue::from_text(FIELD_SECRET),
        protected: true,
        protect_in_memory: true,
    });
    entry.set_field(Field::new("Notes", NOTES_SECRET));
    entry
}

#[test]
fn setx_is_redacted_bounded_and_a_real_dry_run() {
    let database = database_with_entry(login_entry());
    let vault = TestVault::new("setx.kdbx", &database);
    let home = tempfile::tempdir().unwrap();
    let input = home.path().join("setx.json");
    let before = std::fs::read(&vault.path).unwrap();
    let document = format!(
        r#"{{"fields":[{{"key":"Token","value":"{SETX_SECRET}"}},{{"key":"Password","value":"{IMPORT_SECRET}","protected":true}}]}}"#
    );
    std::fs::write(&input, document).unwrap();

    let output = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "setx",
            "--key",
            "LOGIN",
            "--file",
            input.to_str().unwrap(),
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[SETX_SECRET, IMPORT_SECRET]);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["fields_updated"], 2);
    assert_eq!(std::fs::read(&vault.path).unwrap(), before);

    let original = load(&vault.path);
    let entry = &original.root.entries[0];
    assert_eq!(
        entry
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        FIELD_SECRET
    );
    assert_eq!(entry.password.reveal_text().unwrap().as_str(), ENTRY_SECRET);

    let output = run(
        &vault.path,
        home.path(),
        &[
            "setx",
            "--key",
            "LOGIN",
            "--file",
            input.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_success_without(&output, &[SETX_SECRET, IMPORT_SECRET]);
    let changed = load(&vault.path);
    let entry = &changed.root.entries[0];
    assert_eq!(
        entry
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        SETX_SECRET
    );
    assert_eq!(
        entry.password.reveal_text().unwrap().as_str(),
        IMPORT_SECRET
    );

    std::fs::write(
        &input,
        r#"{"fields":[{"key":"Token","value":"duplicate-secret"},{"key":"Token","value":"other-secret"}]}"#,
    )
    .unwrap();
    let output = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "setx",
            "--key",
            "LOGIN",
            "--file",
            input.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!output.status.success());
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    assert!(
        !combined
            .windows(b"duplicate-secret".len())
            .any(|window| window == b"duplicate-secret")
    );
    assert!(
        !combined
            .windows(b"other-secret".len())
            .any(|window| window == b"other-secret")
    );
}

#[test]
fn ensure_mutation_uses_service_paths_aliases_and_dry_run() {
    let mut database = database_with_entry(login_entry());
    database
        .root
        .add_group(neotales_keepass::Group::new("prod"));
    let vault = TestVault::new("ensure-service.kdbx", &database);
    let home = tempfile::tempdir().unwrap();
    let before = std::fs::read(&vault.path).unwrap();

    let dry_run = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "ensure",
            "--key",
            "prod/new",
            "--size",
            "24",
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert_eq!(std::fs::read(&vault.path).unwrap(), before);

    let root_name = load(&vault.path).root.name;
    let create = run(
        &vault.path,
        home.path(),
        &[
            "ensure",
            "--key",
            &format!("{root_name}/prod/new"),
            "--size",
            "24",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let reopened = load(&vault.path);
    let created = &reopened.root.groups[0].entries[0];
    assert_eq!(created.title, "new");
    assert_eq!(created.password.reveal_text().unwrap().as_str().len(), 24);

    // An existing entry is a no-op, even when --size would be invalid for a
    // new entry, and an alias resolves through the same service boundary.
    let alias = run(
        &vault.path,
        home.path(),
        &["alias", "set", "NEW", "prod/new"],
    );
    assert!(
        alias.status.success(),
        "{}",
        String::from_utf8_lossy(&alias.stderr)
    );
    let after_create = std::fs::read(&vault.path).unwrap();
    let no_op = run(
        &vault.path,
        home.path(),
        &[
            "ensure",
            "--key",
            "NEW",
            "--size",
            "0",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        no_op.status.success(),
        "{}",
        String::from_utf8_lossy(&no_op.stderr)
    );
    assert_eq!(std::fs::read(&vault.path).unwrap(), after_create);

    let missing_parent = [
        "ensure",
        "--key",
        "missing/new",
        "--password-env",
        "NKEEPASS_TEST_PASSWORD",
    ];
    let mut dry_run_args = missing_parent.to_vec();
    dry_run_args.push("--dry-run");
    let dry_run = run(&vault.path, home.path(), &dry_run_args);
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert_eq!(std::fs::read(&vault.path).unwrap(), after_create);

    let create_parent = run(&vault.path, home.path(), &missing_parent);
    assert!(
        create_parent.status.success(),
        "{}",
        String::from_utf8_lossy(&create_parent.stderr)
    );
    assert!(create_parent.stdout.is_empty());
    let hierarchy = load(&vault.path);
    assert_eq!(
        hierarchy
            .root
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        ["prod", "missing"]
    );
    let parent = &hierarchy.root.groups[1];
    assert_eq!(parent.entries.len(), 1);
    assert_eq!(parent.entries[0].title, "new");
    assert!(parent.entries[0].password.is_empty());
    assert_eq!(hierarchy.root.groups[0].id, reopened.root.groups[0].id);
    assert_eq!(hierarchy.root.groups[0].entries[0].id, created.id);
    assert_eq!(
        hierarchy.root.groups[0].entries[0]
            .password
            .reveal_text()
            .unwrap()
            .as_str(),
        created.password.reveal_text().unwrap().as_str()
    );
    let after_hierarchy = std::fs::read(&vault.path).unwrap();

    for bad_path in ["prod//bad", "prod/../bad"] {
        let output = run(
            &vault.path,
            home.path(),
            &[
                "ensure",
                "--key",
                bad_path,
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ],
        );
        assert!(!output.status.success(), "accepted {bad_path}");
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"nkeepass: invalid entry path\n");
        assert_eq!(std::fs::read(&vault.path).unwrap(), after_hierarchy);
    }
}

#[test]
fn set_and_field_set_save_values_visible_after_reopen() {
    let vault = TestVault::new("set-reopen.kdbx", &database_with_entry(login_entry()));
    let home = tempfile::tempdir().unwrap();
    let password_file = home.path().join("password.txt");
    let field_file = home.path().join("field.txt");
    std::fs::write(&password_file, "new-password-disposable-282c").unwrap();
    std::fs::write(&field_file, "new-token-disposable-d47f").unwrap();

    for args in [
        vec![
            "secrets",
            "set",
            "--key",
            "LOGIN",
            "--file",
            password_file.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
        vec![
            "field",
            "set",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--file",
            field_file.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    ] {
        let output = run(&vault.path, home.path(), &args);
        assert!(
            output.status.success(),
            "set command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }

    let reopened = load(&vault.path);
    let entry = &reopened.root.entries[0];
    assert_eq!(
        entry.password.reveal_text().unwrap().as_str(),
        "new-password-disposable-282c"
    );
    assert_eq!(
        entry
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "new-token-disposable-d47f"
    );
}

#[test]
fn field_rm_and_rm_save_visible_removals_and_prune_attachments() {
    let mut database = database_with_entry(login_entry());
    let removed_binary = database
        .binary_pool
        .add(b"removed attachment".to_vec(), true);
    let kept_binary = database.binary_pool.add(b"kept attachment".to_vec(), true);
    database.root.entries[0].attachments.push(Attachment {
        name: "removed.bin".into(),
        reference: removed_binary,
    });
    let mut survivor = Entry::new("SURVIVOR");
    survivor.attachments.push(Attachment {
        name: "kept.bin".into(),
        reference: kept_binary,
    });
    database.root.entries.push(survivor);
    let vault = TestVault::new("remove-reopen.kdbx", &database);
    let home = tempfile::tempdir().unwrap();

    let field_output = run(
        &vault.path,
        home.path(),
        &[
            "field",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--yes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        field_output.status.success(),
        "{}",
        String::from_utf8_lossy(&field_output.stderr)
    );
    let after_field_remove = load(&vault.path);
    assert!(after_field_remove.root.entries[0].field("Token").is_none());

    let remove_output = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "rm",
            "--key",
            "LOGIN",
            "--yes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        remove_output.status.success(),
        "{}",
        String::from_utf8_lossy(&remove_output.stderr)
    );
    let reopened = load(&vault.path);
    assert_eq!(reopened.root.entries.len(), 1);
    assert_eq!(reopened.root.entries[0].title, "SURVIVOR");
    assert_eq!(reopened.binary_pool.len(), 1);
    assert_eq!(
        reopened.binary_pool.get(0).unwrap().data,
        b"kept attachment"
    );
    assert_eq!(reopened.root.entries[0].attachments[0].reference, 0);
}

#[test]
fn attachment_add_rm_round_trip_export_and_preserve_exact_names() {
    let mut database = database_with_entry(login_entry());
    let old = database.binary_pool.add(b"old attachment".to_vec(), true);
    database.root.entries[0].attachments.push(Attachment {
        name: "Case.bin".into(),
        reference: old,
    });
    let vault = TestVault::new("attachment-mutation.kdbx", &database);
    let home = tempfile::tempdir().unwrap();
    let input = home.path().join("input=with-equals.bin");
    std::fs::write(&input, b"new\0attachment").unwrap();

    let add = run(
        &vault.path,
        home.path(),
        &[
            "files",
            "add",
            "--key",
            "LOGIN",
            "--field",
            "case.bin",
            "--file",
            input.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert!(add.stdout.is_empty());

    let legacy_path = home.path().join("legacy=input.bin");
    std::fs::write(&legacy_path, b"legacy file input").unwrap();
    let legacy_file = run(
        &vault.path,
        home.path(),
        &[
            "set",
            "--key",
            "LOGIN",
            "--field",
            "Token",
            "--file",
            legacy_path.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        legacy_file.status.success(),
        "{}",
        String::from_utf8_lossy(&legacy_file.stderr)
    );
    assert_eq!(
        load(&vault.path).root.entries[0]
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        "legacy file input"
    );

    let named_file = format!("from-set={}", input.display());
    let second_file = format!("second={}", input.display());
    let set_file = run(
        &vault.path,
        home.path(),
        &[
            "set",
            "--key",
            "LOGIN",
            "--bin",
            &named_file,
            "-b",
            &second_file,
            "--username",
            "set-user",
            "--url",
            "https://set.example",
            "--notes",
            "set-notes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        set_file.status.success(),
        "{}",
        String::from_utf8_lossy(&set_file.stderr)
    );
    let after_set_file = load(&vault.path);
    assert!(
        after_set_file.root.entries[0]
            .attachments
            .iter()
            .any(|attachment| attachment.name == "from-set")
    );
    assert_eq!(after_set_file.root.entries[0].username, "set-user");
    assert_eq!(after_set_file.root.entries[0].url, "https://set.example");
    assert_eq!(after_set_file.root.entries[0].notes, "set-notes");

    let duplicate = run(
        &vault.path,
        home.path(),
        &[
            "attachment",
            "add",
            "--key",
            "LOGIN",
            "--field",
            "case.bin",
            "--file",
            input.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("attachment already exists"));

    let reopened = load(&vault.path);
    assert_eq!(reopened.binary_pool.len(), 4);
    assert!(reopened.binary_pool.get(1).unwrap().protected);
    assert_eq!(reopened.root.entries[0].attachments[1].name, "case.bin");
    assert_eq!(reopened.root.entries[0].attachments[2].name, "from-set");
    assert_eq!(reopened.root.entries[0].attachments[3].name, "second");
    let exported = home.path().join("exported.nkp.json");
    let export = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "export",
            "--output",
            exported.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&exported).unwrap()).unwrap();
    assert_eq!(
        document["database"]["root"]["entries"][0]["attachments"][1]["name"],
        "case.bin"
    );
    assert_eq!(
        document["database"]["root"]["entries"][0]["attachments"][2]["name"],
        "from-set"
    );
    assert_eq!(
        document["database"]["root"]["entries"][0]["attachments"][3]["name"],
        "second"
    );

    let output = home.path().join("attachment.bin");
    let get = run(
        &vault.path,
        home.path(),
        &[
            "attachment",
            "get",
            "--key",
            "LOGIN",
            "--field",
            "case.bin",
            "--output",
            output.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"new\0attachment");

    let remove = run(
        &vault.path,
        home.path(),
        &[
            "attachment",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "case.bin",
            "--yes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    let after_remove = load(&vault.path);
    assert_eq!(after_remove.binary_pool.len(), 3);
    assert_eq!(after_remove.root.entries[0].attachments.len(), 3);
    assert_eq!(after_remove.root.entries[0].attachments[0].name, "Case.bin");
    assert_eq!(
        after_remove.binary_pool.get(0).unwrap().data,
        b"old attachment"
    );
    assert_eq!(after_remove.root.entries[0].attachments[1].name, "from-set");
    assert_eq!(after_remove.root.entries[0].attachments[2].name, "second");
}

#[test]
fn get_clipboard_never_writes_the_selected_secret_to_stdout_or_diagnostics() {
    let vault = TestVault::new("clipboard-get.kdbx", &database_with_entry(login_entry()));
    let home = tempfile::tempdir().unwrap();
    let output = run(
        &vault.path,
        home.path(),
        &[
            "get",
            "--key",
            "LOGIN",
            "--clipboard",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(ENTRY_SECRET));
}

#[test]
fn failed_multi_attachment_set_does_not_save_partial_changes() {
    let mut database = database_with_entry(login_entry());
    let reference = database.binary_pool.add(b"existing".to_vec(), true);
    database.root.entries[0].attachments.push(Attachment {
        name: "already-there".into(),
        reference,
    });
    let vault = TestVault::new("set-batch-failure.kdbx", &database);
    let home = tempfile::tempdir().unwrap();
    let input = home.path().join("batch.bin");
    std::fs::write(&input, b"new attachment").unwrap();
    let first = format!("first={}", input.display());
    let duplicate = format!("already-there={}", input.display());
    let output = run(
        &vault.path,
        home.path(),
        &[
            "set",
            "--key",
            "LOGIN",
            "-b",
            &first,
            "--bin",
            &duplicate,
            "--username",
            "should-not-save",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("attachment already exists"));
    let unchanged = load(&vault.path);
    assert_eq!(unchanged.root.entries[0].username, "automation-user");
    assert_eq!(unchanged.root.entries[0].attachments.len(), 1);
    assert_eq!(unchanged.binary_pool.len(), 1);
}

#[test]
fn rm_preserves_alias_collision_protection_and_confirmation() {
    let mut database = database_with_entry(login_entry());
    let attachment = database.binary_pool.add(b"alias attachment".to_vec(), true);
    database.root.entries[0].attachments.push(Attachment {
        name: "alias.bin".into(),
        reference: attachment,
    });
    database.root.add_entry(Entry::new("OTHER"));
    let vault = TestVault::new("remove-alias.kdbx", &database);
    let home = tempfile::tempdir().unwrap();
    let alias = run(
        &vault.path,
        home.path(),
        &["alias", "set", "LOGIN", "OTHER"],
    );
    assert!(
        alias.status.success(),
        "{}",
        String::from_utf8_lossy(&alias.stderr)
    );

    let collision = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "rm",
            "--key",
            "LOGIN",
            "--yes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("ambiguous entry selector"));
    assert_eq!(load(&vault.path).root.entries.len(), 2);

    let attachment_collision = run(
        &vault.path,
        home.path(),
        &[
            "attachment",
            "rm",
            "--key",
            "LOGIN",
            "--field",
            "alias.bin",
            "--yes",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!attachment_collision.status.success());
    assert!(
        String::from_utf8_lossy(&attachment_collision.stderr).contains("ambiguous entry selector")
    );
    assert_eq!(load(&vault.path).root.entries[0].attachments.len(), 1);

    let no_confirmation = run(
        &vault.path,
        home.path(),
        &[
            "secrets",
            "rm",
            "--key",
            "OTHER",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!no_confirmation.status.success());
    assert!(String::from_utf8_lossy(&no_confirmation.stderr).contains("removal requires --yes"));
}

#[test]
fn export_import_round_trip_preserves_protected_history_and_loss_relevant_data() {
    let source_db = database_with_entry(login_entry());
    let source_db = {
        let mut database = source_db;
        let reference = database.binary_pool.add(ATTACHMENT_SECRET.to_vec(), true);
        let entry = &mut database.root.entries[0];
        entry.attachments.push(Attachment {
            name: "secret.bin".into(),
            reference,
        });
        let mut history = Entry::new("LOGIN");
        history.password = ProtectedValue::from_text("history-password-disposable-82d0");
        history.set_field(Field {
            key: "Token".into(),
            value: ProtectedValue::from_text("history-token-disposable-f8a1"),
            protected: true,
            protect_in_memory: true,
        });
        entry.history.push(history);
        database
    };
    let source = TestVault::new("source.kdbx", &source_db);
    let target = TestVault::new("target.kdbx", &KeePassDatabase::default());
    let home = tempfile::tempdir().unwrap();
    let interchange = home.path().join("vault.nkp.json");
    let output_path = interchange.to_str().unwrap();

    let output = run(
        &source.path,
        home.path(),
        &[
            "secrets",
            "export",
            "--output",
            output_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(
        &output,
        &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET, IMPORT_SECRET],
    );
    assert_eq!(result["format"], "org.neotales.nkeepass.interchange");
    assert_eq!(result["version"], 1);
    let envelope = std::fs::read(&interchange).unwrap();
    assert!(
        !envelope
            .windows(ENTRY_SECRET.len())
            .any(|window| window == ENTRY_SECRET.as_bytes())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&interchange)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let mut duplicate_document: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    let typed_items = duplicate_document["database"]["typed_public_custom_data"]
        .as_array_mut()
        .unwrap();
    let duplicate_item = typed_items[0].clone();
    typed_items.push(duplicate_item);
    let duplicate_interchange = home.path().join("duplicate.nkp.json");
    std::fs::write(
        &duplicate_interchange,
        serde_json::to_vec(&duplicate_document).unwrap(),
    )
    .unwrap();
    let before = std::fs::read(&target.path).unwrap();
    let duplicate_import = run(
        &target.path,
        home.path(),
        &[
            "import",
            "--file",
            duplicate_interchange.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!duplicate_import.status.success());
    assert!(duplicate_import.stdout.is_empty());
    assert_eq!(
        duplicate_import.stderr,
        b"nkeepass: interchange contains duplicate typed custom-data keys\n".as_slice()
    );
    assert_eq!(std::fs::read(&target.path).unwrap(), before);
    for marker in [ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET, IMPORT_SECRET] {
        assert!(!String::from_utf8_lossy(&duplicate_import.stderr).contains(marker));
    }

    let before = std::fs::read(&target.path).unwrap();
    let output = run(
        &target.path,
        home.path(),
        &[
            "secrets",
            "import",
            "--file",
            output_path,
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(
        &output,
        &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET, IMPORT_SECRET],
    );
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["attachments"], 1);
    assert_eq!(std::fs::read(&target.path).unwrap(), before);

    let output = run(
        &target.path,
        home.path(),
        &[
            "import",
            "--file",
            output_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_success_without(
        &output,
        &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET, IMPORT_SECRET],
    );
    let imported = load(&target.path);
    assert_eq!(imported.meta.name, "automation metadata");
    assert_eq!(
        imported.meta.custom_data.get("label"),
        Some("metadata-value")
    );
    assert!(matches!(
        imported.typed_public_custom_data.get("outer"),
        Some(VariantValue::String(value)) if value == "outer-value"
    ));
    let entry = &imported.root.entries[0];
    assert_eq!(entry.password.reveal_text().unwrap().as_str(), ENTRY_SECRET);
    assert_eq!(
        entry
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        FIELD_SECRET
    );
    assert_eq!(
        entry
            .field("Notes")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        NOTES_SECRET
    );
    assert_eq!(entry.history.len(), 1);
    assert_eq!(
        entry.history[0].password.reveal_text().unwrap().as_str(),
        "history-password-disposable-82d0"
    );
    let attachment = &imported
        .binary_pool
        .get(entry.attachments[0].reference)
        .unwrap()
        .data;
    assert_eq!(attachment, ATTACHMENT_SECRET);
    assert!(imported.can_save_losslessly);

    let before = std::fs::read(&source.path).unwrap();
    let unauthorized = run(
        &source.path,
        home.path(),
        &[
            "import",
            "--file",
            output_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!unauthorized.status.success());
    assert!(unauthorized.stdout.is_empty());
    assert_eq!(
        unauthorized.stderr,
        b"nkeepass: target vault is not empty; use --replace to authorize replacement\n".as_slice()
    );
    assert_eq!(std::fs::read(&source.path).unwrap(), before);
    assert_no_disclosure(&unauthorized, ENTRY_SECRET);
    assert_no_disclosure(&unauthorized, FIELD_SECRET);

    let output = run(
        &source.path,
        home.path(),
        &[
            "export",
            "--output",
            output_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"nkeepass: output already exists or cannot be created\n".as_slice()
    );
    assert_eq!(std::fs::read(&interchange).unwrap(), envelope);
}

#[test]
fn sync_dry_run_does_not_save_and_merges_without_deleting_target_data() {
    let mut target_entry = login_entry();
    target_entry.times.modified = KdbxTimestamp::from_unix_seconds(10);
    let target_db = database_with_entry(target_entry);
    let target = TestVault::new("target.kdbx", &target_db);

    let mut source_entry = Entry::new("SOURCE");
    source_entry.times.modified = KdbxTimestamp::from_unix_seconds(100);
    source_entry.set_field(Field {
        key: "Token".into(),
        value: ProtectedValue::from_text(SETX_SECRET),
        protected: false,
        protect_in_memory: false,
    });
    let mut source_db = database_with_entry(source_entry);
    let reference = source_db.binary_pool.add(ATTACHMENT_SECRET.to_vec(), true);
    source_db.root.entries[0].attachments.push(Attachment {
        name: "source.bin".into(),
        reference,
    });
    let source = TestVault::new("source.kdbx", &source_db);
    let home = tempfile::tempdir().unwrap();
    let interchange = home.path().join("source.nkp.json");
    let interchange_path = interchange.to_str().unwrap();

    let output = run(
        &source.path,
        home.path(),
        &[
            "secrets",
            "export",
            "--output",
            interchange_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_success_without(&output, &[IMPORT_SECRET, SETX_SECRET]);

    let before = std::fs::read(&target.path).unwrap();
    let output = run(
        &target.path,
        home.path(),
        &[
            "secrets",
            "sync",
            "--file",
            interchange_path,
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[IMPORT_SECRET, SETX_SECRET]);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["entries_added"], 1);
    assert_eq!(std::fs::read(&target.path).unwrap(), before);

    let output = run(
        &target.path,
        home.path(),
        &[
            "sync",
            "--file",
            interchange_path,
            "--strategy",
            "newest",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_success_without(&output, &[IMPORT_SECRET, SETX_SECRET]);
    let merged = load(&target.path);
    assert_eq!(merged.root.entries.len(), 2);
    let original = merged
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "LOGIN")
        .unwrap();
    assert_eq!(
        original
            .field("Password")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        ENTRY_SECRET
    );
    let output = run(
        &target.path,
        home.path(),
        &[
            "get",
            "--key",
            "LOGIN",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(ENTRY_SECRET));
    assert_eq!(output.stdout, ENTRY_SECRET.as_bytes());
    let added = merged
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "SOURCE")
        .unwrap();
    assert_eq!(
        added
            .field("Token")
            .unwrap()
            .value
            .reveal_text()
            .unwrap()
            .as_str(),
        SETX_SECRET
    );
    assert_eq!(
        merged
            .binary_pool
            .get(added.attachments[0].reference)
            .unwrap()
            .data,
        ATTACHMENT_SECRET
    );
}

/// The generate-on-import directive, end to end through the real binary.
///
/// One test for the whole contract, because the parts are not separable: a
/// directive that generates, reports without disclosing, refuses to overwrite,
/// and answers `--dry-run` with a plan instead of a value. Splitting them would
/// let a change that breaks one pass the others.
#[test]
fn the_ensure_directive_generates_reports_and_never_overwrites() {
    let source_db = database_with_entry(login_entry());
    let source = TestVault::new("source.kdbx", &source_db);
    let target = TestVault::new("target.kdbx", &KeePassDatabase::default());
    let home = tempfile::tempdir().unwrap();

    // The policy file is the source snapshot with the value taken out and a
    // directive added, which is exactly the edit a user commits.
    let mut policy = Policy::exported(&source.path, home.path(), "policy.nkp.json");
    policy.with_ensure(32).without_password();
    let policy_path = policy.write("policy.nkp.json");

    // A dry run reports what it would do and writes nothing: the target is
    // still the empty vault it was created as.
    let before = std::fs::read(&target.path).unwrap();
    let output = run(
        &target.path,
        home.path(),
        &[
            "secrets",
            "import",
            "--file",
            &policy_path,
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET]);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_kept"], 0);
    assert_eq!(result["passwords_pending"], 1);
    assert_eq!(std::fs::read(&target.path).unwrap(), before);

    let output = run(
        &target.path,
        home.path(),
        &[
            "import",
            "--file",
            &policy_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET]);
    assert_eq!(result["passwords_generated"], 1);
    assert_eq!(result["passwords_kept"], 0);
    assert_eq!(result["passwords_pending"], 0);
    let generated = entry_password(&target.path);
    assert_eq!(generated.len(), 32);
    assert_ne!(generated, ENTRY_SECRET);

    // The disclosure rule, asserted against the value that was actually written
    // and against the run that wrote it. Reading the vault is the only way to
    // know the string the output must not contain, so the check cannot pass by
    // guessing -- and a later run that generates nothing would prove nothing.
    assert_no_disclosure(&output, &generated);

    // A second run of the same file converges instead of rotating, which is the
    // safety rule: a committed file that asks for a secret to exist must not be
    // able to replace one that already does. The value is checked before the
    // counts, because the value is the claim and the counts report it.
    let output = run(
        &target.path,
        home.path(),
        &[
            "secrets",
            "import",
            "--file",
            &policy_path,
            "--replace",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_eq!(entry_password(&target.path), generated);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_kept"], 1);
}

/// A value already in the file, or already in the vault, survives a directive.
///
/// This is the test that fails if the no-overwrite rule is reverted. Both cases
/// name a value the tool could have replaced and assert it is still there: the
/// one the snapshot carries, and the one the vault held before an `--replace`
/// that a policy file with nothing to give would otherwise use to mint a new
/// one on every run.
#[test]
fn the_ensure_directive_never_replaces_a_value_that_exists() {
    let source_db = database_with_entry(login_entry());
    let source = TestVault::new("source.kdbx", &source_db);
    let target = TestVault::new("target.kdbx", &KeePassDatabase::default());
    let home = tempfile::tempdir().unwrap();

    // The snapshot's own value is the one that must survive.
    let mut policy = Policy::exported(&source.path, home.path(), "kept.nkp.json");
    policy.with_ensure(48);
    let policy_path = policy.write("kept.nkp.json");
    let output = run(
        &target.path,
        home.path(),
        &[
            "import",
            "--file",
            &policy_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET]);
    assert_eq!(entry_password(&target.path), ENTRY_SECRET);
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_kept"], 1);

    // Now the value the vault already holds, across a whole-vault replacement.
    let mut empty = Policy::exported(&source.path, home.path(), "empty.nkp.json");
    empty.with_ensure(48).without_password();
    let empty_path = empty.write("empty.nkp.json");
    let output = run(
        &target.path,
        home.path(),
        &[
            "import",
            "--file",
            &empty_path,
            "--replace",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET, FIELD_SECRET, NOTES_SECRET]);
    assert_eq!(entry_password(&target.path), ENTRY_SECRET);
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_kept"], 1);
}

/// The refusals: a size outside the bound, a key that is not this one, and a
/// directive the build cannot honour.
///
/// A directive is an instruction in a committed file, so the difference between
/// "refused" and "ignored" is the difference between a policy that fails loudly
/// and a policy that reads as satisfied while doing nothing.
#[test]
fn the_ensure_directive_is_bounded_and_a_misspelling_is_refused() {
    let source_db = database_with_entry(login_entry());
    let source = TestVault::new("source.kdbx", &source_db);
    let target = TestVault::new("target.kdbx", &KeePassDatabase::default());
    let home = tempfile::tempdir().unwrap();
    let mut policy = Policy::exported(&source.path, home.path(), "bounded.nkp.json");
    policy.without_password();
    let before = std::fs::read(&target.path).unwrap();

    // The diagnostic names the value that broke the bound and the bound itself,
    // the way the glob-length refusal does.
    for (size, message) in [
        (
            0,
            "ensure size is 0 characters; the allowed range is 1 to 4096",
        ),
        (
            5000,
            "ensure size is 5000 characters; the allowed range is 1 to 4096",
        ),
        (
            u64::MAX,
            "ensure size is 18446744073709551615 characters; the allowed range is 1 to 4096",
        ),
    ] {
        policy.with_ensure(size);
        let path = policy.write("bounded.nkp.json");
        let output = run(
            &target.path,
            home.path(),
            &[
                "import",
                "--file",
                &path,
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ],
        );
        assert!(!output.status.success(), "size {size} was accepted");
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, format!("nkeepass: {message}\n").as_bytes());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(ENTRY_SECRET));
    }

    // A key this build does not have, a half-specified directive, and one that
    // asks for something it cannot do are all refusals. `classes` is here
    // because a directive promising more than this build honours is the case
    // that must fail rather than quietly do less.
    for directive in [
        serde_json::json!({ "size": 32 }),
        serde_json::json!({}),
        serde_json::json!({ "size": 32, "classes": { "lower": true } }),
        serde_json::json!({ "len": 32 }),
        serde_json::json!(true),
    ] {
        policy.entry()["ensur"] = directive.clone();
        policy.entry().as_object_mut().unwrap().remove("ensure");
        let path = policy.write("misspelled.nkp.json");
        let output = run(
            &target.path,
            home.path(),
            &[
                "import",
                "--file",
                &path,
                "--password-env",
                "NKEEPASS_TEST_PASSWORD",
            ],
        );
        assert!(!output.status.success(), "{directive} was accepted");
        assert_eq!(
            output.stderr,
            b"nkeepass: invalid interchange document\n".as_slice()
        );
    }

    assert_eq!(std::fs::read(&target.path).unwrap(), before);
}

/// `export` does not carry the directive back out, and the round trip says so.
///
/// The decision: the directive is an instruction in the policy file, not vault
/// state. A generated password is state and is exported like any other value;
/// "this file asked for one" belongs to the file. Carrying it out would need a
/// place in the vault model to put it -- a reserved custom-data key that would
/// ship to other `KeePass` clients, or a change to a model this CLI does not own.
/// What a round trip costs is the ability to regenerate, which is the one thing
/// this feature exists to decline to do.
#[test]
fn export_does_not_carry_the_directive_and_the_round_trip_reproduces_the_value() {
    let source_db = database_with_entry(login_entry());
    let source = TestVault::new("source.kdbx", &source_db);
    let first = TestVault::new("first.kdbx", &KeePassDatabase::default());
    let home = tempfile::tempdir().unwrap();

    let mut policy = Policy::exported(&source.path, home.path(), "policy.nkp.json");
    policy.with_ensure(40).without_password();
    let policy_path = policy.write("policy.nkp.json");
    let output = run(
        &first.path,
        home.path(),
        &[
            "import",
            "--file",
            &policy_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET]);
    assert_eq!(result["passwords_generated"], 1);
    let generated = entry_password(&first.path);
    assert_eq!(generated.len(), 40);
    assert_no_disclosure(&output, &generated);

    let exported = home.path().join("exported.nkp.json");
    let output = run(
        &first.path,
        home.path(),
        &[
            "secrets",
            "export",
            "--output",
            exported.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    assert_success_without(&output, &[ENTRY_SECRET, &generated]);
    let envelope = std::fs::read(&exported).unwrap();
    assert!(
        !envelope
            .windows(b"\"ensure\"".len())
            .any(|window| window == b"\"ensure\""),
        "export carried the directive out"
    );

    // The value survives the round trip, and re-importing it is a plain
    // import: no directive, nothing to generate, nothing to report.
    let second = TestVault::new("second.kdbx", &KeePassDatabase::default());
    let output = run(
        &second.path,
        home.path(),
        &[
            "import",
            "--file",
            exported.to_str().unwrap(),
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[ENTRY_SECRET, &generated]);
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_kept"], 0);
    assert_eq!(result["passwords_pending"], 0);
    assert_eq!(entry_password(&second.path), generated);
}

/// `sync` honours the directive, and the entry the vault already had is not
/// disturbed by a policy file that names a different one.
///
/// `sync` merges rather than replaces, so the entry the directive names is one
/// the merge brought in. The generation happens on the merged tree, after the
/// strategy has had its say, which is what keeps the guarantee a property of
/// the write and not of the merge order.
#[test]
fn sync_honours_the_directive_without_touching_the_rest_of_the_vault() {
    let mut source_entry = Entry::new("GENERATED");
    source_entry.set_field(Field::new("Token", SETX_SECRET));
    let source_db = database_with_entry(source_entry);
    let source = TestVault::new("source.kdbx", &source_db);
    let target = TestVault::new("target.kdbx", &database_with_entry(login_entry()));
    let home = tempfile::tempdir().unwrap();

    let mut policy = Policy::exported(&source.path, home.path(), "policy.nkp.json");
    policy.with_ensure(24).without_password();
    let policy_path = policy.write("policy.nkp.json");

    let before = std::fs::read(&target.path).unwrap();
    let output = run(
        &target.path,
        home.path(),
        &[
            "secrets",
            "sync",
            "--file",
            &policy_path,
            "--dry-run",
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[SETX_SECRET]);
    assert_eq!(result["dry_run"], true);
    assert_eq!(result["entries_added"], 1);
    assert_eq!(result["passwords_generated"], 0);
    assert_eq!(result["passwords_pending"], 1);
    assert_eq!(std::fs::read(&target.path).unwrap(), before);

    let output = run(
        &target.path,
        home.path(),
        &[
            "sync",
            "--file",
            &policy_path,
            "--password-env",
            "NKEEPASS_TEST_PASSWORD",
        ],
    );
    let result = assert_success_without(&output, &[SETX_SECRET]);
    assert_eq!(result["passwords_generated"], 1);
    assert_eq!(result["passwords_pending"], 0);

    let merged = load(&target.path);
    assert_eq!(merged.root.entries.len(), 2);
    let added = merged
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "GENERATED")
        .unwrap();
    let generated = added.password.reveal_text().unwrap().as_str().to_owned();
    assert_eq!(generated.len(), 24);
    assert_no_disclosure(&output, &generated);
    // The entry that was already there, and the value it had, are untouched.
    let original = merged
        .root
        .entries
        .iter()
        .find(|entry| entry.title == "LOGIN")
        .unwrap();
    assert_eq!(
        original.password.reveal_text().unwrap().as_str(),
        ENTRY_SECRET
    );
}
