//! Process-level context output coverage with isolated synthetic vaults.

use std::process::{Command, Output, Stdio};

fn run(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nkp"))
        .current_dir(root)
        .env("NKEEPASS_CONFIG_DIR", root.join("config"))
        .env("NKEEPASS_DATA_DIR", root.join("data"))
        .env("NKEEPASS_CONTEXT_TEST_PASSWORD", "synthetic-test-password")
        .env_remove("NKEEPASS_VAULT")
        .env_remove("NKEEPASS_VAULT_PATH")
        .env_remove("NKEEPASS_PASSWORD")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn initialized_contexts_are_visible_as_text_and_json() {
    for explicit in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("named.kdbx");
        let mut args = vec!["init"];
        if explicit {
            args.push(vault.to_str().unwrap());
        }
        args.extend([
            "--iterations",
            "64",
            "--password-env",
            "NKEEPASS_CONTEXT_TEST_PASSWORD",
        ]);
        let created = run(root.path(), &args);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
        let path = value["path"].as_str().unwrap();
        for action in ["ls", "list", "show"] {
            let text = run(root.path(), &["context", action]);
            assert!(text.status.success());
            let text = String::from_utf8(text.stdout).unwrap();
            assert!(text.contains(path));
            assert!(text.contains(if explicit {
                if action == "show" {
                    "(unnamed)"
                } else {
                    "(current)"
                }
            } else {
                "default"
            }));
            let json = run(root.path(), &["context", action, "--json"]);
            assert!(json.status.success());
            let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
            assert_eq!(json["path"], path);
        }
        let opened = run(
            root.path(),
            &[
                "secrets",
                "ls",
                "--password-env",
                "NKEEPASS_CONTEXT_TEST_PASSWORD",
            ],
        );
        assert!(
            opened.status.success(),
            "{}",
            String::from_utf8_lossy(&opened.stderr)
        );
    }
}
