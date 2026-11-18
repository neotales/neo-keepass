#!/usr/bin/env bash
# Synthetic regression tests for the cross-toolchain preflight's architecture
# and header provenance checks. No compiler or system package is modified.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/nkp-aarch64-preflight.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/sysroot/usr/aarch64-linux-gnu/include/bits" "$tmp/host/bits"
: >"$tmp/sysroot/usr/aarch64-linux-gnu/include/bits/libc-header-start.h"
: >"$tmp/host/bits/libc-header-start.h"

cat >"$tmp/fake-gcc" <<'FAKE_GCC'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -dumpmachine) printf '%s\n' "${FAKE_TARGET:-aarch64-linux-gnu}" ;;
  -print-sysroot) printf '%s\n' "$FAKE_SYSROOT" ;;
  --version) echo 'fake aarch64 gcc' ;;
  -print-search-dirs) echo 'install: synthetic' ;;
  -E)
    grep -qF '#include <stdint.h>'
    echo ". $FAKE_HEADER" >&2
    ;;
  *) echo "unexpected fake compiler args: $*" >&2; exit 2 ;;
esac
FAKE_GCC
chmod +x "$tmp/fake-gcc"

export CC_aarch64_unknown_linux_gnu="$tmp/fake-gcc"
export FAKE_SYSROOT="$tmp/sysroot"
export FAKE_HEADER="$tmp/sysroot/usr/aarch64-linux-gnu/include/bits/libc-header-start.h"
"$repo/scripts/preflight-aarch64-toolchain.sh" >/dev/null
echo 'ok   preflight accepts aarch64 target header'

if FAKE_TARGET=x86_64-linux-gnu "$repo/scripts/preflight-aarch64-toolchain.sh" >"$tmp/wrong-target.log" 2>&1; then
  echo 'FAIL preflight accepted incorrect compiler target' >&2
  exit 1
fi
grep -F "expected 'aarch64-linux-gnu'" "$tmp/wrong-target.log" >/dev/null
echo 'ok   preflight rejects incorrect compiler target'

export FAKE_HEADER="$tmp/host/bits/libc-header-start.h"
if "$repo/scripts/preflight-aarch64-toolchain.sh" >"$tmp/host-header.log" 2>&1; then
  echo 'FAIL preflight accepted host libc header' >&2
  exit 1
fi
grep -F 'resolved libc header to' "$tmp/host-header.log" >/dev/null
echo 'ok   preflight rejects host libc header trace'
