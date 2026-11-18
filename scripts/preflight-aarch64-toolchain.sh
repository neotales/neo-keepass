#!/usr/bin/env bash
# Verify the Ubuntu cross compiler and target libc headers before invoking
# Cargo. Keep this separate so its fail-closed checks can be exercised with
# synthetic compiler/header traces on hosts without an AArch64 toolchain.
set -euo pipefail

compiler=${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}
target=aarch64-linux-gnu
actual_target=$("$compiler" -dumpmachine)
if [[ "$actual_target" != "$target" ]]; then
  echo "error: $compiler targets '$actual_target', expected '$target'" >&2
  exit 1
fi

sysroot=$("$compiler" -print-sysroot)
if [[ -z "$sysroot" ]]; then
  sysroot=/
fi
if [[ "$sysroot" == / ]]; then
  target_include="/usr/$target/include"
else
  target_include="${sysroot%/}/usr/$target/include"
fi
target_include=$(realpath -m "$target_include")
expected_header="$target_include/bits/libc-header-start.h"
if [[ ! -f "$expected_header" ]]; then
  echo "error: expected target libc header is missing: $expected_header" >&2
  exit 1
fi

echo "compiler=$("$compiler" --version | head -n 1)"
echo "target=$actual_target"
echo "sysroot=$sysroot"
echo "target-include=$target_include"
echo "search-dirs:"
"$compiler" -print-search-dirs

# Exercise the real include search, not merely the presence of a file. GCC's
# -H trace identifies the exact header selected by stdint.h.
headers=$(printf '#include <stdint.h>\n' | "$compiler" -E -H -x c - 2>&1 >/dev/null)
printf '%s\n' "$headers"
mapfile -t resolved_headers < <(
  sed -nE 's/^\.+ (.*\/bits\/libc-header-start\.h)$/\1/p' <<<"$headers"
)
if [[ ${#resolved_headers[@]} -ne 1 ]]; then
  echo "error: expected exactly one libc-header-start.h in compiler trace; found ${#resolved_headers[@]}" >&2
  exit 1
fi
resolved_header=$(realpath "${resolved_headers[0]}")
if [[ "$resolved_header" != "$expected_header" ]]; then
  echo "error: compiler resolved libc header to '$resolved_header', expected target header '$expected_header'" >&2
  exit 1
fi
