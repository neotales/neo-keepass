//! Benchmark starters for the nkeepass application crate.
//!
//! Run with `cargo bench -p nkeepass`. Criterion writes its reports under
//! `target/criterion`; the `bench` CI workflow uploads them as artifacts.
//!
//! Two areas are covered:
//!
//! - `glob` pattern compilation and matching (pure CPU, no I/O), because
//!   `secrets ls` runs patterns against every listed path.
//! - Vault create/open round trips against the pinned `KDBX_LIMITS` policy,
//!   using a deliberately cheap AES-KDF round count so the measurement is
//!   dominated by serialization, not KDF work. KDF cost itself is bounded by
//!   `KDBX_LIMITS` and is not the subject of these benches.
//!
//! `vault/create` unlinks the produced file inside the timed loop because
//! `VaultService::create` installs with a no-clobber guarantee; the unlink is
//! part of the measured cost.

#![allow(
    clippy::unwrap_used,
    reason = "bench setup failure is a bench bug, not a production path; failing loudly is fine"
)]

use criterion::{Criterion, criterion_group, criterion_main};
use neotales_keepass::{KdbxCredentials, KdbxWriteOptions};
use nkeepass::VaultService;
use nkeepass::glob::Glob;

/// Cheap AES-KDF settings: the point is to measure envelope work, not KDF work.
fn fast_write_options() -> KdbxWriteOptions {
    KdbxWriteOptions {
        aes_kdf_rounds: 8,
        ..KdbxWriteOptions::default()
    }
}

fn bench_glob(c: &mut Criterion) {
    let mut group = c.benchmark_group("glob");
    for (name, pattern, path) in [
        ("literal", "Root/Work/mail1", "Root/Work/mail1"),
        ("star_crosses_slash", "Root/*mail*", "Root/Work/mail1"),
        (
            "alternates",
            "Root/{Work,Personal}/mail?",
            "Root/Work/mail9",
        ),
    ] {
        group.bench_with_input(format!("compile/{name}"), &pattern, |b, pattern| {
            b.iter(|| Glob::new(pattern))
        });
        let compiled = Glob::new(pattern);
        group.bench_with_input(format!("match/{name}"), &path, |b, path| {
            b.iter(|| compiled.is_match(path))
        });
    }
    group.finish();
}

fn bench_vault_create(c: &mut Criterion) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bench-create.kdbx");
    c.bench_function("vault/create", |b| {
        b.iter(|| {
            let mut credentials = KdbxCredentials::password("bench-password").unwrap();
            VaultService::default()
                .create(&path, &mut credentials, fast_write_options(), None)
                .unwrap();
            std::fs::remove_file(&path).unwrap();
        });
    });
}

fn bench_vault_open(c: &mut Criterion) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bench-open.kdbx");
    let mut credentials = KdbxCredentials::password("bench-password").unwrap();
    VaultService::default()
        .create(&path, &mut credentials, fast_write_options(), None)
        .unwrap();

    c.bench_function("vault/open", |b| {
        b.iter(|| {
            let mut service = VaultService::default();
            service
                .open(&path, &mut credentials, &nkeepass::KDBX_LIMITS)
                .unwrap();
        });
    });
}

criterion_group!(benches, bench_glob, bench_vault_create, bench_vault_open);
criterion_main!(benches);
