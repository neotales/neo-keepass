# Shared CLI test support

## UI PTY checks

`cargo test -p nkeepass --test tui_ui` runs `tui_ui_pty.py` via Python 3 on Unix.
Every case uses its own disposable vault, HOME/config/data paths, and PTY;
display/clipboard environment access is removed. Captured terminal data is
never printed. The small cursor/erase emulator checks visible cells at 40×12.
Coverage includes disclosure focus, generation consent, long indexed targets,
selected attachment removal/export, and an actionable failed-save decision.
The 40×12 field-navigation case checks selection beyond the compact viewport
and the named target in its reveal prompt before consent. A private reducer
test expires a real lease with a fake clipboard adapter while confirmation is
open, covering successful, refused, and failed clears without clipboard access.
The long-field PTY case inspects two colliding name suffixes before consent,
then verifies only the second field is revealed. Private workflow coverage
confirms a replacement password with a failed-clear warning pending, overwrites
status/refreshes, and checks full warning review and explicit acknowledgement.
Private modal tests check that warning return/acknowledgement restores target
position and deletion drafts, repeated F3 does not nest, and dirty exit/lock
dialogs expose the warning shortcut at the minimum size.
Exact pagination/error retention and projection branches live in `tui.rs` tests.

This is UI coverage, not proof of terminal admission, signal safety, or
Crossterm event-reader identity. No split-terminal or signal machinery is
changed here. Linux was exercised; Windows and macOS runtime behavior is
unverified. Windows startup is not disabled by this patch.

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
