#![cfg(unix)]

//! Integration coverage for the `nkp config` command group.
//!
//! Two claims are under test, and the second is the one that matters.
//!
//! The first is the group itself: a *closed* set of three keys that can be read
//! and written from the command line, with a listing a script can consume.
//!
//! The second is that adding a way to write the configuration file added no way
//! to *bypass* the checks that file already had. Every `config set` and
//! `config rm` has to land in the same owner-only, atomically installed file
//! `context set` writes, and every refusal the read path makes -- a symlinked
//! file, a group-readable directory, an unknown field, an oversized file -- has
//! to apply here too. The group has no private read or write of its own, and
//! these tests are what keeps that true: a parallel writer would pass every
//! behavioural test above and fail the ones below.

#[path = "support/application_environment.rs"]
mod application_environment;
use application_environment::IsolatedApplicationEnvironment;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// A vault path the group only ever stores and reports; it is never opened.
///
/// Derived from the platform's temporary directory rather than written as a
/// literal `/tmp/...`, and returned as `&'static str` so every call site reads the
/// same as the `const` it replaces.
///
/// The CLI validates every vault path it is given, and `Path::is_absolute` is
/// platform-defined: on Windows a rooted path with no drive prefix is not
/// absolute. So every `config set current /tmp/...` in this file was refused with
/// "vault path must be absolute and normalized", and nine tests failed for a reason
/// that has nothing to do with configuration -- the paths are never opened, but
/// they are still validated.
fn vault() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        std::env::temp_dir()
            .join("nkeepass-config-test.kdbx")
            .to_str()
            .expect("a temporary directory with a UTF-8 path")
            .to_owned()
    })
    .as_str()
}

/// A third path, for the test that writes a key and checks the others survived.
fn third_vault() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        std::env::temp_dir()
            .join("nkeepass-config-third.kdbx")
            .to_str()
            .expect("a temporary directory with a UTF-8 path")
            .to_owned()
    })
    .as_str()
}

fn other_vault() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        std::env::temp_dir()
            .join("nkeepass-config-other.kdbx")
            .to_str()
            .expect("a temporary directory with a UTF-8 path")
            .to_owned()
    })
    .as_str()
}

/// A configuration file holding all three keys, so a test can prove a write
/// leaves the keys it was not asked about alone.
///
/// Built rather than concatenated, because it has to name the same two paths the
/// commands store, and those are now computed per platform.
fn seeded() -> String {
    // Built with `serde_json`, not by interpolating paths into a string.
    //
    // The first attempt used `format!` with a raw string, which produced valid JSON
    // on Linux and malformed JSON on Windows: the substituted path contains
    // backslashes, and `\U` is not a JSON escape, so the seeded file failed to
    // parse. The failure surfaced three directories away -- the config would not
    // load, so `config get surprise` reported a parsing complaint instead of
    // "unknown configuration key", and `config set current` failed outright.
    //
    // A path is attacker-shaped text in general and JSON is not a place to
    // interpolate it by hand. This has no such seam.
    serde_json::json!({
        "current": vault(),
        "default_vault": other_vault(),
        "aliases": {
            "work": {"kind": "vault", "target": vault()},
            "mail": {"kind": "entry", "target": "Root/Email", "field": "UserName"},
        },
    })
    .to_string()
}

/// A throwaway `XDG_CONFIG_HOME`, so no run can read or write a real one.
struct ConfigHome {
    root: tempfile::TempDir,
    /// Stands in for `$XDG_DATA_HOME` so the data-directory fallback cannot
    /// resolve into the real home directory.
    data: tempfile::TempDir,
}

impl ConfigHome {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            data: tempfile::tempdir().unwrap(),
        }
    }

    /// The value to hand the binary as `XDG_CONFIG_HOME`.
    fn home(&self) -> &Path {
        self.root.path()
    }

    /// `<XDG_CONFIG_HOME>/nkeepass`, the directory the file's permissions apply
    /// to.
    fn directory(&self) -> PathBuf {
        self.root.path().join("nkeepass")
    }

    fn file(&self) -> PathBuf {
        self.directory().join("config.json")
    }

    /// Writes a configuration file the read path will accept.
    #[cfg(unix)]
    fn seed(&self, contents: &str) {
        self.seed_with_modes(contents, 0o700, 0o600);
    }

    #[cfg(not(unix))]
    fn seed(&self, contents: &str) {
        fs::create_dir_all(self.directory()).unwrap();
        fs::write(self.file(), contents).unwrap();
    }

    /// Writes a configuration file with explicit owner bits, so a test can put
    /// exactly one hardening property under test at a time.
    #[cfg(unix)]
    fn seed_with_modes(&self, contents: &str, directory: u32, file: u32) {
        fs::create_dir_all(self.directory()).unwrap();
        fs::write(self.file(), contents).unwrap();
        fs::set_permissions(self.file(), fs::Permissions::from_mode(file)).unwrap();
        fs::set_permissions(self.directory(), fs::Permissions::from_mode(directory)).unwrap();
    }

    fn contents(&self) -> String {
        fs::read_to_string(self.file()).unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.file()).unwrap()
    }

    /// Every entry in the configuration directory, sorted.
    ///
    /// A staged temporary file that survived a write would show up here, and a
    /// successful write that left one behind would mean the install did not
    /// rename it away.
    fn directory_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.directory())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

/// Runs the CLI with no vault, no credential, and no home directory.
///
/// `HOME` is removed rather than pointed somewhere plausible: if any command in
/// this group consulted it, the test would touch a real file instead of failing.
fn run(home: &ConfigHome, args: &[&str]) -> Output {
    let command = Command::new(env!("CARGO_BIN_EXE_nkp")).isolate_application_environment();
    let mut command = command;
    command
        .args(args)
        .env("XDG_CONFIG_HOME", home.home())
        .env("XDG_DATA_HOME", home.data.path())
        .env_remove("HOME")
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .stdin(Stdio::null());
    command.output().unwrap()
}

/// Asserts a refusal: non-zero exit, nothing on stdout, one static stderr line.
fn assert_refused(output: &Output, diagnostic: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("nkp: {diagnostic}\n").as_bytes(),
        "unexpected diagnostic"
    );
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The `--json` listing, as records.
fn records(output: &Output) -> Vec<serde_json::Value> {
    stdout(output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON record per line"))
        .collect()
}

// ---------------------------------------------------------------------------
// The group itself
// ---------------------------------------------------------------------------

#[test]
fn ls_reports_every_key_with_its_value_and_the_key_alone_when_unset() {
    let home = ConfigHome::new();
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );

    // `aliases` is a map, so it reports its size; an unset scalar reports the
    // bare key, which is what tells the two apart without a placeholder word.
    assert_eq!(
        stdout(&run(&home, &["config", "ls"])),
        format!("aliases\t0\ncurrent\t{}\ndefault_vault\n", vault())
    );

    assert!(
        run(&home, &["config", "set", "default_vault", other_vault()])
            .status
            .success()
    );
    assert_eq!(
        stdout(&run(&home, &["config", "ls"])),
        format!(
            "aliases\t0\ncurrent\t{}\ndefault_vault\t{}\n",
            vault(),
            other_vault()
        )
    );
}

#[test]
fn the_json_listing_is_one_record_per_key_with_null_for_an_unset_key() {
    let home = ConfigHome::new();
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );
    assert!(
        run(&home, &["alias", "set", "work", vault(), "--kind", "vault"])
            .status
            .success()
    );

    let listed = records(&run(&home, &["config", "ls", "--json"]));
    assert_eq!(listed.len(), 3, "every key is listed: {listed:?}");
    assert_eq!(listed[0]["key"], "aliases");
    assert_eq!(listed[0]["value"]["work"]["target"], vault());
    assert_eq!(listed[1]["key"], "current");
    assert_eq!(listed[1]["value"], vault());
    assert_eq!(listed[2]["key"], "default_vault");
    // An unset key is `null`, not an empty string: the two are different states
    // and a script asking "is a default configured" has to be able to tell.
    assert!(listed[2]["value"].is_null());

    // The same keys in the same order as the text listing, so a script can
    // switch between the two without re-deriving the vocabulary.
    let text = stdout(&run(&home, &["config", "ls"]));
    let text_keys: Vec<&str> = text
        .lines()
        .map(|row| row.split('\t').next().unwrap())
        .collect();
    let json_keys: Vec<&str> = listed
        .iter()
        .map(|record| record["key"].as_str().unwrap())
        .collect();
    assert_eq!(text_keys, json_keys);
}

#[test]
fn a_glob_filters_the_listed_keys() {
    let home = ConfigHome::new();
    for (glob, expected) in [
        ("c*", vec!["current"]),
        ("?urrent", vec!["current"]),
        ("d*", vec!["default_vault"]),
        ("*ault", vec!["default_vault"]),
        ("*", vec!["aliases", "current", "default_vault"]),
        ("no-such-key", vec![]),
    ] {
        let listing = stdout(&run(&home, &["config", "ls", glob]));
        let keys: Vec<&str> = listing
            .lines()
            .map(|row| row.split('\t').next().unwrap())
            .collect();
        assert_eq!(keys, expected, "glob {glob}");
    }

    // A pattern that matches nothing is an empty listing, not a failure: the
    // caller asked a question and the answer was "no keys".
    assert!(stdout(&run(&home, &["config", "ls", "no-such-key"])).is_empty());
    let filtered = records(&run(&home, &["config", "ls", "--json", "c*"]));
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["key"], "current");

    // `--` gives a pattern beginning with `-` a spelling, exactly as it does
    // for `secrets ls`.
    assert!(stdout(&run(&home, &["config", "ls", "--", "-*"])).is_empty());
    assert_eq!(
        stdout(&run(&home, &["config", "ls", "--", "d*"])),
        "default_vault\n"
    );
}

#[test]
fn get_prints_the_bare_value_so_it_can_be_substituted() {
    let home = ConfigHome::new();
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );
    // One line holding the path and nothing else: a JSON document here would
    // make `$(nkp config get current)` unusable without a parser.
    assert_eq!(
        stdout(&run(&home, &["config", "get", "current"])),
        format!("{}\n", vault())
    );

    // An unset key is a refusal rather than an empty line, so a script cannot
    // mistake "no default is configured" for "the default is the empty path".
    assert_refused(
        &run(&home, &["config", "get", "default_vault"]),
        "configuration key is not set",
    );
}

#[test]
fn a_set_context_is_the_context_the_existing_precedence_reports() {
    let home = ConfigHome::new();
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );

    // The point of the group: the value it wrote is read back by the resolution
    // every other command already uses, with no hand-edited file involved.
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&home, &["context", "show", "--json"]).stdout).unwrap();
    assert_eq!(shown["path"], vault());
    assert_eq!(shown["source"], "context");

    assert!(run(&home, &["config", "rm", "current"]).status.success());
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&home, &["context", "show", "--json"]).stdout).unwrap();
    assert_ne!(shown["source"], "context");
}

#[test]
fn a_set_default_vault_is_used_when_no_context_is_set() {
    let home = ConfigHome::new();
    assert!(
        run(&home, &["config", "set", "default_vault", other_vault()])
            .status
            .success()
    );
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&home, &["context", "show", "--json"]).stdout).unwrap();
    assert_eq!(shown["path"], other_vault());
    assert_eq!(shown["source"], "default");

    // The context still outranks it, so the two keys are not interchangeable.
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&home, &["context", "show", "--json"]).stdout).unwrap();
    assert_eq!(shown["source"], "context");

    assert!(run(&home, &["config", "rm", "current"]).status.success());
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&home, &["context", "show", "--json"]).stdout).unwrap();
    assert_eq!(shown["source"], "default");
}

#[test]
fn clearing_a_key_that_holds_nothing_is_a_refusal() {
    let home = ConfigHome::new();
    let before = run(&home, &["config", "rm", "current"]);
    assert_refused(&before, "configuration key is not set");
    // Nothing was created to report the refusal about.
    assert!(!home.file().exists());

    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );
    assert!(run(&home, &["config", "rm", "current"]).status.success());
    assert_refused(
        &run(&home, &["config", "rm", "current"]),
        "configuration key is not set",
    );
}

#[test]
fn setting_one_key_leaves_the_others_exactly_as_they_were() {
    let home = ConfigHome::new();
    home.seed(&seeded());
    assert!(
        run(&home, &["config", "set", "current", third_vault()])
            .status
            .success()
    );

    // A write that stored only the key it was asked about would drop the alias
    // map and the default, so the whole document is compared, not just `current`.
    let written: serde_json::Value = serde_json::from_str(&home.contents()).unwrap();
    let seeded: serde_json::Value = serde_json::from_str(&seeded()).unwrap();
    assert_eq!(written["current"], third_vault());
    assert_eq!(written["default_vault"], seeded["default_vault"]);
    assert_eq!(written["aliases"], seeded["aliases"]);

    // And clearing one key is equally surgical.
    assert!(
        run(&home, &["config", "rm", "default_vault"])
            .status
            .success()
    );
    let written: serde_json::Value = serde_json::from_str(&home.contents()).unwrap();
    assert!(written["default_vault"].is_null());
    assert_eq!(written["current"], third_vault());
    assert_eq!(written["aliases"], seeded["aliases"]);
}

#[test]
fn the_alias_map_is_left_to_the_alias_commands() {
    let home = ConfigHome::new();
    home.seed(&seeded());
    let before = home.bytes();

    // A `set` that "worked" here would have to flatten the map to text, and a
    // `rm` would have dropped every alias the user has.
    for args in [
        vec!["config", "set", "aliases", "anything"],
        vec!["config", "rm", "aliases"],
    ] {
        assert_refused(
            &run(&home, &args),
            "aliases is a map; use nkp alias set and nkp alias rm",
        );
    }
    assert_eq!(home.bytes(), before, "the alias map must be untouched");
    // The aliases are still there, and still usable.
    let resolved: serde_json::Value =
        serde_json::from_slice(&run(&home, &["alias", "resolve", "mail"]).stdout).unwrap();
    assert_eq!(resolved["field"], "UserName");

    // Reading it is allowed, and reports exactly what `alias ls` reports.
    assert_eq!(
        stdout(&run(&home, &["config", "get", "aliases"])),
        stdout(&run(&home, &["alias", "list"]))
    );
}

#[test]
fn an_unknown_key_is_refused_with_the_valid_keys_named() {
    let home = ConfigHome::new();
    home.seed(&seeded());
    let before = home.bytes();
    for args in [
        vec!["config", "get", "surprise"],
        vec!["config", "set", "surprise", third_vault()],
        vec!["config", "rm", "surprise"],
        vec!["config", "get", "Current"],
        vec!["config", "set", "default-vault", third_vault()],
    ] {
        assert_refused(
            &run(&home, &args),
            "unknown configuration key; valid keys are aliases, current, default_vault",
        );
    }
    assert_eq!(home.bytes(), before);
}

#[test]
fn a_refused_key_is_never_echoed_back() {
    let home = ConfigHome::new();
    // A key carrying an escape sequence would repaint the terminal of anyone
    // reading the diagnostic, so the message names the valid keys and stops.
    let output = run(&home, &["config", "get", "sur\u{1b}[2Jprise"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains('\u{1b}'),
        "the refused key reached stderr: {stderr:?}"
    );
    assert!(stderr.contains("aliases, current, default_vault"));
}

#[test]
fn the_group_refuses_every_option_it_does_not_have() {
    let home = ConfigHome::new();
    home.seed(&seeded());
    let before = home.bytes();
    for args in [
        vec!["config", "ls", "--key", "x"],
        vec!["config", "ls", "--format", "json"],
        vec!["config", "ls", "--json", "--json"],
        vec!["config", "ls", "a", "b"],
        vec!["config", "get", "current", "--json"],
        vec!["config", "set", "current", vault(), "--yes"],
        vec!["config", "rm", "current", "--dry-run"],
    ] {
        let output = run(&home, &args);
        assert!(
            !output.status.success(),
            "{args:?} was accepted; a silently ignored option is how a script \
             comes to believe it asked for something it did not get"
        );
    }
    assert_eq!(home.bytes(), before);
}

#[test]
fn the_group_refuses_an_ambiguous_or_incomplete_argument_list() {
    let home = ConfigHome::new();
    for args in [
        vec!["config"],
        vec!["config", "surprise"],
        vec!["config", "get"],
        vec!["config", "get", "current", "extra"],
        vec!["config", "set", "current"],
        vec!["config", "set", "current", vault(), "extra"],
        vec!["config", "rm"],
        vec!["config", "rm", "current", "extra"],
    ] {
        let output = run(&home, &args);
        assert!(!output.status.success(), "{args:?} was accepted");
        assert!(output.stdout.is_empty(), "{args:?} printed a result");
    }
}

#[test]
fn the_group_never_opens_a_vault_or_asks_for_a_credential() {
    let home = ConfigHome::new();
    // No `--vault`, no vault anywhere, stdin is null so a prompt would fail
    // rather than hang, and none of these commands is given a password source.
    assert!(run(&home, &["config", "ls"]).status.success());
    assert!(run(&home, &["config", "ls", "--json"]).status.success());
    assert_refused(
        &run(&home, &["config", "get", "current"]),
        "configuration key is not set",
    );
    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );
    assert!(run(&home, &["config", "get", "current"]).status.success());
    assert!(run(&home, &["config", "rm", "current"]).status.success());
    // The vault these commands name does not exist and never had to.
    assert!(!Path::new(vault()).exists());
}

#[test]
fn the_group_is_advertised_and_its_subcommand_help_is_reachable() {
    let home = ConfigHome::new();
    let help = stdout(&run(&home, &["--help"]));
    assert!(
        help.lines().any(|line| line.starts_with("  config ")),
        "root --help must advertise configuration commands"
    );

    // Root help is a concise overview; this group help lists only its direct
    // subcommands, while the README retains the full configuration contract.
    let group = run(&home, &["config", "--help"]);
    assert!(group.status.success());
    let group = stdout(&group);
    assert!(group.contains("COMMANDS:"));
    assert!(group.contains("ls, list"));
    assert!(!group.contains("aliases, current, default_vault"));

    let listing = stdout(&run(&home, &["config", "ls", "--help"]));
    let binary = Path::new(env!("CARGO_BIN_EXE_nkp"));
    let program = binary.file_name().unwrap().to_string_lossy();
    assert!(listing.contains(&format!("{program} config ls [GLOB] [--json]")));
    assert!(listing.contains("--json"));
}

// ---------------------------------------------------------------------------
// The group must not become a way around the file's existing hardening
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_config_write_leaves_the_file_owner_only_and_the_directory_private() {
    let home = ConfigHome::new();
    // The base directory is deliberately world-readable, so the 0700 on the
    // directory the CLI creates is the CLI's doing and not the umask's.
    fs::set_permissions(home.home(), fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        run(&home, &["config", "set", "current", vault()])
            .status
            .success()
    );

    let file = fs::metadata(home.file()).unwrap();
    let directory = fs::metadata(home.directory()).unwrap();
    assert_eq!(
        file.permissions().mode() & 0o777,
        0o600,
        "file must be 0600"
    );
    assert_eq!(
        directory.permissions().mode() & 0o777,
        0o700,
        "directory must be 0700"
    );
    // The staged file was renamed into place rather than left beside it.
    assert_eq!(home.directory_entries(), ["config.json"]);
}

/// `context set` and `alias set --kind vault` write the same alias record.
///
/// The group is only safe because it has no writer of its own, and that is not
/// something a behavioural test can see directly. This asserts it from the
/// outside: setting the same alias through either command has to leave
/// byte-identical files, so a second serialiser, a differently staged file, or
/// a partial rewrite would show up here as a difference.
#[test]
fn a_context_alias_write_matches_the_existing_alias_write_path() {
    let through_config = ConfigHome::new();
    let through_context = ConfigHome::new();

    assert!(
        run(
            &through_config,
            &["alias", "set", "work", vault(), "--kind", "vault"]
        )
        .status
        .success()
    );
    assert!(
        run(&through_context, &["context", "set", "work", vault()])
            .status
            .success()
    );

    assert_eq!(through_config.contents(), through_context.contents());
    assert_eq!(
        through_config.directory_entries(),
        through_context.directory_entries()
    );
}

#[cfg(unix)]
#[test]
fn a_config_write_replaces_the_file_rather_than_rewriting_it_in_place() {
    let home = ConfigHome::new();
    home.seed(&seeded());
    let before = fs::metadata(home.file()).unwrap().ino();

    assert!(
        run(&home, &["config", "set", "current", third_vault()])
            .status
            .success()
    );

    // An in-place write would keep the same inode. A different one means the
    // new file was staged beside the old and renamed over it, so a reader sees
    // either the whole old file or the whole new one.
    assert_ne!(
        fs::metadata(home.file()).unwrap().ino(),
        before,
        "the file was rewritten in place instead of installed by rename"
    );
    assert_eq!(home.directory_entries(), ["config.json"]);
}

#[cfg(unix)]
#[test]
fn a_group_readable_configuration_directory_is_refused_and_nothing_is_written() {
    let home = ConfigHome::new();
    home.seed_with_modes(&seeded(), 0o750, 0o600);
    let before = home.bytes();

    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        assert_refused(
            &run(&home, &args),
            "unsafe configuration directory permissions",
        );
    }
    assert_eq!(home.bytes(), before);
    assert_eq!(
        fs::metadata(home.directory()).unwrap().permissions().mode() & 0o777,
        0o750,
        "a refused command must not quietly repair the directory"
    );
    assert_eq!(home.directory_entries(), ["config.json"]);
}

#[cfg(unix)]
#[test]
fn a_group_readable_configuration_file_is_refused_and_nothing_is_written() {
    let home = ConfigHome::new();
    home.seed_with_modes(&seeded(), 0o700, 0o644);
    let before = home.bytes();

    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        assert_refused(&run(&home, &args), "unsafe configuration permissions");
    }
    assert_eq!(home.bytes(), before);
    assert_eq!(
        fs::metadata(home.file()).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_configuration_file_is_refused_and_its_target_is_untouched() {
    let home = ConfigHome::new();
    fs::create_dir_all(home.directory()).unwrap();
    fs::set_permissions(home.directory(), fs::Permissions::from_mode(0o700)).unwrap();
    let target = home.root.path().join("elsewhere.json");
    fs::write(&target, seeded()).unwrap();
    std::os::unix::fs::symlink(&target, home.file()).unwrap();

    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        assert_refused(&run(&home, &args), "unsafe configuration file");
    }
    // Following the link would have written through it to somewhere the CLI
    // never checked the permissions of.
    assert_eq!(fs::read(&target).unwrap(), seeded().as_bytes());
    assert!(fs::symlink_metadata(home.file()).unwrap().is_symlink());
}

#[cfg(unix)]
#[test]
fn a_configuration_file_that_is_not_a_regular_file_is_refused() {
    let home = ConfigHome::new();
    fs::create_dir_all(home.directory()).unwrap();
    fs::set_permissions(home.directory(), fs::Permissions::from_mode(0o700)).unwrap();
    // A directory in the file's place, and a fifo standing in for anything else
    // that is not a regular file.
    fs::create_dir_all(home.file()).unwrap();
    for args in [
        vec!["config", "ls"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        assert_refused(&run(&home, &args), "unsafe configuration file");
    }

    fs::remove_dir(home.file()).unwrap();
    let fifo = home.root.path().join("pipe");
    if Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|status| status.success())
    {
        std::os::unix::fs::symlink(&fifo, home.file()).unwrap();
        // Reached through a symlink, so the symlink rule answers first; that is
        // the same refusal for the same reason.
        assert_refused(&run(&home, &["config", "ls"]), "unsafe configuration file");
    }
}

#[test]
fn an_unknown_field_in_the_configuration_file_is_refused_and_nothing_is_written() {
    let home = ConfigHome::new();
    home.seed(r#"{"current":"/tmp/nkeepass-config-test.kdbx","surprise":true}"#);
    let before = home.bytes();

    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        // `deny_unknown_fields` is what stops the file from becoming a store
        // that a hand edit can add to and this CLI will then keep.
        assert_refused(&run(&home, &args), "invalid configuration");
    }
    assert_eq!(home.bytes(), before);
}

#[test]
fn an_oversized_configuration_file_is_refused() {
    let home = ConfigHome::new();
    // A megabyte of a valid JSON string: over the cap, and not a parse error,
    // so the diagnostic that comes back is the size one.
    let oversized = format!("{{\"current\":\"{}\"}}", "x".repeat(1024 * 1024));
    home.seed(&oversized);
    let before = home.bytes();

    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
        vec!["config", "set", "current", other_vault()],
        vec!["config", "rm", "current"],
    ] {
        assert_refused(&run(&home, &args), "configuration exceeds size limit");
    }
    assert_eq!(home.bytes(), before);
}

#[test]
fn a_value_that_could_never_be_read_back_is_refused_before_the_file_is_touched() {
    let home = ConfigHome::new();
    for value in [
        "relative/path.kdbx",
        "../escape.kdbx",
        "/absolute/../escape.kdbx",
        "",
    ] {
        let output = run(&home, &["config", "set", "current", value]);
        assert!(!output.status.success(), "{value:?} was stored");
        // Nothing was created at all: validation precedes the write, so a
        // refused value never leaves a configuration file behind.
        assert!(
            !home.file().exists(),
            "{value:?} created {}",
            home.file().display()
        );
    }
}

#[test]
fn a_stored_value_carrying_terminal_control_bytes_is_never_printed() {
    let home = ConfigHome::new();
    // Hand-edited, which is the only way a control byte gets into this file. It
    // would repaint, rename, or repurpose the terminal of anyone who listed or
    // read it, so the group refuses rather than rendering it.
    home.seed(r#"{"current":"/tmp/\u001b[2J\u009b31m.kdbx","default_vault":null,"aliases":{}}"#);
    for args in [
        vec!["config", "ls"],
        vec!["config", "ls", "--json"],
        vec!["config", "get", "current"],
    ] {
        let output = run(&home, &args);
        assert!(!output.status.success(), "{args:?} printed a hostile value");
        // A refusal after a partial listing would read as a complete one with
        // keys missing, so stdout has to be empty rather than short.
        assert!(
            output.stdout.is_empty(),
            "{args:?} printed a partial listing"
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains('\u{1b}'));
    }
}

#[test]
fn a_hostile_alias_record_is_never_printed() {
    let home = ConfigHome::new();
    home.seed(concat!(
        r#"{"aliases":{"ok":{"kind":"vault","target":"/tmp/a.kdbx"},"#,
        r#""bad\u001b[2J":{"kind":"entry","target":"Root/E"}}}"#,
    ));
    for args in [
        vec!["config", "ls", "--json"],
        vec!["config", "get", "aliases"],
    ] {
        let output = run(&home, &args);
        assert!(!output.status.success(), "{args:?} printed a hostile alias");
        assert!(
            output.stdout.is_empty(),
            "{args:?} printed the benign record before the hostile one"
        );
    }
}
