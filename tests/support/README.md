# Shared CLI test support

`cli_support.rs` is the library's disposable KDBX fixture and its byte-level
secret-leak checks, copied verbatim from the library crate. `tests/cli.rs`
includes it and maps every scenario to this executable.

## Why it is a copy and not a path

It was originally reached with a `#[path]` attribute pointing into the library
submodule's test support directory. It is now a versioned dependency on a
*published crate*, and neither arrangement works:

- A published crate is unpacked into the cargo registry cache, and its path is
  machine-specific and hash-suffixed. A `#[path]` into that cache is not
  portable across machines or Cargo versions, and may not exist before the
  first build.
- The crate's own `tests/` directory is not part of its public API, so
  referencing it from a dependency is reaching into a private tree.

So it is a copy, and that is a real cost: **this copy and the library's can
diverge.** When the library updates its scenarios, this file does not, and the
divergence is invisible because both compile.

## What to do when they diverge

1. Copy the library's `tests/support/cli_support.rs` over this one.
2. `diff` before committing. A change here is a change in what this repository
   asserts, and it deserves its own commit message.
3. If the library's scenarios changed in *shape* rather than in content, the
   adapter in `tests/cli.rs` needs updating too -- `Scenario` arms map to real
   commands, so a new scenario is a new arm or an existing arm stops matching.

The `Scenario` list is the contract. A scenario this repository has not mapped
is a scenario that is not being tested here, and the test that would have
noticed is the one that stops compiling.
