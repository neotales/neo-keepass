# Test fixture provenance

`keepassxc-minimal.kdbx` is committed here rather than generated at test time,
because it is the one artefact in this repository that a *foreign* tool
produced. Everything else in `tests/` is built in-process by the test that needs
it; this file is the exception, and an unexplained binary blob in a password
manager's repository is exactly the kind of thing a reviewer should be able to
resolve without asking.

## What it is

| | |
| --- | --- |
| Format | KDBX 3.1, AES-KDF, AES-CBC |
| Producer | KeePassXC |
| Master password | `fixture-password` |
| Entries | none — the root group is empty |
| Origin | Library crate's test fixture directory |

## Why it is here

It arrived by copy from the KeePass library crate during the extraction from
the source monorepo. It is a KDBX **3** file, which is the point: it is the only
fixture that exercises a pre-4.x outer header, and the CLI's own writer only
emits KDBX 3.1 and 4.1, so a KDBX 3 read path would otherwise go untested here.

## The known-empty trap

**This vault contains no entries.** The library's own test asserts it:

```rust
// Library crate's roundtrip test
assert!(loaded.root.entries.is_empty());
```

So any test that points a *listing* command at this file and then asserts on
the listed records is vacuous — `secrets ls` writes zero bytes, and a `for` loop
over `text.lines()` never executes once. That is not a hypothetical: it is
exactly what happened to
`tests/cli.rs::metadata_listing_never_prints_password_or_values`, which passed
for as long as it existed while asserting nothing.

Listing behaviour is therefore tested against vaults built in-process — see
`hostile_metadata_vault` in `tests/cli.rs` — and this file is used only for what
it can actually prove: that a KDBX 3 vault opens.

## The four format-matrix fixtures that are deliberately absent

`keepass-rs-kdbx4-aes-kdf.kdbx`, `keepass-rs-kdbx4-argon2d.kdbx`,
`keepass-rs-kdbx4-argon2d-chacha20.kdbx` and `keepass-rs-kdbx4-argon2id.kdbx`
were **not** copied. They test the *library's* format matrix, and that matrix is
the library's responsibility, enforced by the library's own suite inside the
submodule. Two copies of one format matrix is one too many: they would drift,
and a failure would have to be attributed to the wrong repository.

If this repository later needs to assert on KDF or cipher selection end to end,
generate the vault in-process with `KdbxFile::save` and the relevant
`KdbxWriteOptions`, as the hostile-vault helper already does.
