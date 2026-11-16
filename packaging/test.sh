#!/usr/bin/env bash
# Self-tests for the packaging scripts: positive path through archive/validator
# plus negative cases (wrong ELF architecture, wrong deb metadata, missing
# formats). Exits nonzero if any negative case is not caught or the positive
# case fails.
#
# Usage: packaging/test.sh <built-nkeepass-binary>
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
binary=$1
[ -x "$binary" ] || { echo "test.sh: not an executable: $binary" >&2; exit 1; }

version=$(bash "$repo/packaging/scripts/version.sh")
work=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-packtest.XXXXXX")
trap 'rm -rf "$work"' EXIT
pass=0
failcount=0

expect_fail() { # expect_fail <label> <cmd...>
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL (not caught): $label"
        failcount=$((failcount + 1))
    else
        echo "ok   (caught): $label"
        pass=$((pass + 1))
    fi
}

expect_pass() { # expect_pass <label> <cmd...>
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "ok   (passed): $label"
        pass=$((pass + 1))
    else
        echo "FAIL: $label"
        failcount=$((failcount + 1))
    fi
}

# Fabricate a structurally valid deb (ar archive) with chosen control fields,
# for exercising the structural validation path on machines without dpkg-deb.
make_fake_deb() { # make_fake_deb <out.deb> <version> <arch>
    local out=$1 ver=$2 arch=$3 stage
    stage=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-fakedeb.XXXXXX")
    printf '2.0\n' > "$stage/debian-binary"
    mkdir -p "$stage/control/DEBIAN"
    printf 'Package: nkeepass\nVersion: %s\nArchitecture: %s\nMaintainer: t <t@t.invalid>\nDescription: fake\n' \
        "$ver" "$arch" > "$stage/control/DEBIAN/control"
    mkdir -p "$stage/control/usr/bin"
    cp "$binary" "$stage/control/usr/bin/nkeepass"
    (cd "$stage/control" && tar -czf "$stage/control.tar.gz" DEBIAN usr)
    mkdir -p "$stage/data/usr/bin"
    cp "$binary" "$stage/data/usr/bin/nkeepass"
    (cd "$stage/data" && tar -czf "$stage/data.tar.gz" usr)
    (cd "$stage" && ar r "$out" debian-binary control.tar.gz data.tar.gz)
    rm -rf "$stage"
}

echo "== positive case: complete, correct artifacts"
pos="$work/positive"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$pos" >/dev/null
make_fake_deb "$pos/nkeepass-${version}-amd64.deb" "$version" amd64
if command -v makepkg >/dev/null; then
    bash "$repo/packaging/pacman/build.sh" \
        "$pos/nkeepass-${version}-x86_64-unknown-linux-gnu.tar.gz" \
        x86_64-unknown-linux-gnu "$pos" >/dev/null
fi
expect_pass "positive dir validates" \
    bash "$repo/packaging/validate.sh" "$pos" "$version" x86_64-unknown-linux-gnu

echo "== negative: aarch64-named archive containing an x86_64 binary"
neg="$work/wrong-elf"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" aarch64-unknown-linux-gnu "$neg" >/dev/null
expect_fail "ELF arch mismatch is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" aarch64-unknown-linux-gnu

echo "== negative: deb with wrong architecture metadata"
neg="$work/wrong-arch"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-amd64.deb" "$version" arm64
expect_fail "wrong deb architecture is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu

echo "== negative: missing zip and deb formats"
neg="$work/missing-formats"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
expect_fail "missing zip/deb formats are rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu

echo "== negative: deb version mismatch"
neg="$work/wrong-version"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-amd64.deb" "9.9.9" amd64
expect_fail "wrong deb version is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu

if [ "$failcount" -ne 0 ]; then
    echo "packaging tests failed: $failcount uncaught case(s)"
    exit 1
fi
echo "packaging tests passed ($pass checks)"
