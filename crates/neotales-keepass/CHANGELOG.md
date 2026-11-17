# Changelog

## 0.0.0-alpha.3

- **Source compatibility change:** `KeePassMeta::history_max_items` and
  `KeePassMeta::history_max_size` now use `Option<i64>` instead of
  `Option<u64>` so the KeePass `-1` unlimited sentinel is representable.
  Accepted values are `-1..=i32::MAX` for item count and `-1..=i64::MAX` for
  size in bytes. Typed callers converting from unsigned values should use a
  checked conversion such as `i64::try_from` and handle out-of-range input.
  JSON snapshot imports with values outside these ranges are now rejected.
- **Breaking-ish behavior change:** Change the default Argon2 read and save
  ceilings from 65,536 to 1,048,576 KiB, from 10 to 4096 passes, and from 16
  to 64 lanes. Any consumer that relies on library defaults now accepts higher
  Argon2 memory, time, and lanes. A combined work budget is enforced. This
  changes the security policy for these consumers.
- Add `KdbxReadLimits::max_argon2_work_kib_passes`, with a default of
  16,777,216. Check total memory in KiB multiplied by passes before hashing.
  Do not multiply by lanes. Refuse arithmetic overflow.
- Add `KdbxLimitParameter`, `KdbxLimitDetail`, and
  `KdbxError::limit_detail()` for consistent Argon2 limit errors on read and
  save. The first failure is memory, time, lanes, then work.
- Adding a private detail field to `KdbxError` prevents external struct
  literals. Consumers that construct `KdbxError` by struct literal must switch
  to `KdbxError::new` or its existing named constructors.
  Full `KdbxReadLimits` literals must include the new work field.
