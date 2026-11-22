# Owned secret buffers: TUI lifecycle

## Diagnosis and boundary

Previously, `tui::launch` retained `KdbxCredentials` while `run_ui` borrowed it.
`App::lock_vault` could drop the database but could not drop those credentials.
They survived on the lock screen until process exit. This was an ownership
defect, not evidence that the credential destructor failed.

`App` now owns the credentials. All three save routes use `App::save`; missing
credentials reject a save before filesystem work. Lock takes and drops them
before clipboard cleanup. `KdbxCredentials::drop` already zeroizes its owned
password vector. Ordinary app destruction also drops credentials on return or
unwind. No new cache, derived-key retention, re-unlock flow, or crypto primitive
is introduced. Terminal admission and signal handling are separate work.

Dirty lock/exit decisions deliberately retain the unlocked session until save,
discard, or cancel. A failed save or unfinished edit must not destroy the only
credentials available to retry. See the [user contract](reference/system.md#lock-and-secret-lifetime).

## Verification boundary

Private lifecycle tests use disposable encrypted vaults and a credential
provider with a drop probe. They exercise the actual `App` ownership,
idle-lock, pending-decision, and save methods. They verify destruction while
the app remains alive, invalidated database access, denied saves after lock,
unchanged fixture bytes/no extra files on discard/cancel, failed-save retry
ownership, and persisted changes reopened with newly constructed credentials.
The probe observes credential destruction; it does **not** read freed memory
or establish erasure of every heap copy. Password wiping relies on the existing
credential destructor and `zeroize` implementation.

## Small follow-ups, not part of this fix

- **CLI input ownership:** `main::password` wraps accepted strings, but argv and
  environment sources have upstream copies the wrapper cannot erase. Move
  accepted prompt results into zeroizing ownership immediately, including
  empty/error branches; avoid extra `to_owned` conversions where an owned
  buffer can be transferred. Do not claim that removing an environment variable
  clears the OS or shell's copies.
- **CLI byte/string conversions:** password-file/stdin parsing currently copies
  slices to strings. Prefer consuming a validated owned zeroizing buffer where
  practical; audit rejected-input paths too. Keep input bounds and source
  precedence unchanged.
- **TUI input growth and rendering:** live input/reveal strings zeroize on
  cleanup, but growth can leave old allocations behind. Investigate bounded
  preallocation for masked input and fewer sanitized/rendering copies in
  `draw`. Ratatui cells and terminal-emulator storage are separate owners;
  repainting is not a memory-erasure proof.
- **Model/library boundaries:** inventory ordinary strings, decrypted XML,
  attachment buffers, KDF/cipher intermediates and caller-owned key components
  before replacing types. Introduce narrow owning zeroizing types and
  failure-path tests incrementally, rather than promise a wholesale crypto or
  allocator cleanup.

None of these measures establishes protection from a compromised process,
swap, crash dumps, forced termination, screenshots, or clipboard history.
