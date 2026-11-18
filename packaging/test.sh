#!/usr/bin/env bash
# Self-tests for the packaging scripts: positive path through archive/validator
# plus negative cases, each isolating one property (wrong ELF architecture,
# wrong deb metadata, missing formats, hostile pacman filename) and asserting
# the rejection reason. Exits nonzero if any negative case is not caught with
# the expected reason or the positive case fails.
#
# When dpkg-deb is available (Debian/Ubuntu), the positive deb is built by the
# real builder (deb/build.sh); negative debs are still fabricated to isolate
# single properties. Without dpkg-deb the deb fixtures are fabricated with
# ar(1)+tar(1) in real Debian structure: ar members debian-binary,
# control.tar.*, data.tar.*, with ./control and ./usr/bin/nkp payloads.
#
# Usage: packaging/test.sh <built-nkp-binary>
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
binary=$1
[ -x "$binary" ] || { echo "test.sh: not an executable: $binary" >&2; exit 1; }

version=$(bash "$repo/packaging/scripts/version.sh")
work=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-packtest.XXXXXX")
trap 'rm -rf "$work"' EXIT
pass=0
failcount=0

LAST_OUTPUT=""
expect_fail() { # expect_fail <expected-reason-substring> <label> <cmd...>
    local reason=$1 label=$2
    shift 2
    local status=0
    LAST_OUTPUT=$("$@" 2>&1) || status=$?
    if [ "$status" -eq 0 ]; then
        echo "FAIL (not caught): $label"
        failcount=$((failcount + 1))
    elif echo "$LAST_OUTPUT" | grep -q -- "$reason"; then
        echo "ok   (caught, reason '$reason'): $label"
        pass=$((pass + 1))
    else
        echo "FAIL (caught for the wrong reason; expected '$reason'):"
        echo "$LAST_OUTPUT" | grep FAIL | head -3 | sed 's/^/       /'
        failcount=$((failcount + 1))
    fi
}

# Asserts the validator's most recent output reported it skipped the smoke
# run: a failed check must prevent execution of the payload.
expect_smoke_skipped() { # <label>
    if echo "$LAST_OUTPUT" | grep -q "skip smoke run"; then
        echo "ok   (smoke skipped): $1"
        pass=$((pass + 1))
    else
        echo "FAIL (smoke not skipped): $1"
        failcount=$((failcount + 1))
    fi
}

# Asserts the validator's most recent output shows the smoke run happened.
expect_smoke_ran() { # <label>
    if echo "$LAST_OUTPUT" | grep -q "smoke run:.*exits 0"; then
        echo "ok   (smoke ran): $1"
        pass=$((pass + 1))
    else
        echo "FAIL (smoke did not run): $1"
        failcount=$((failcount + 1))
    fi
}

# Asserts the validator's most recent output shows the smoke run was
# withheld because a validation elsewhere failed (deferred-smoke property).
expect_smoke_withheld() { # <label>
    if echo "$LAST_OUTPUT" | grep -q "smoke run:"; then
        echo "FAIL (smoke ran despite failure): $1"
        failcount=$((failcount + 1))
    elif echo "$LAST_OUTPUT" | grep -q "skip smoke run (validation failed"; then
        echo "ok   (smoke withheld): $1"
        pass=$((pass + 1))
    else
        echo "FAIL (no withheld-smoke marker): $1"
        failcount=$((failcount + 1))
    fi
}

expect_pass() { # expect_pass <label> <cmd...>
    local label=$1
    shift
    local status=0
    LAST_OUTPUT=$("$@" 2>&1) || status=$?
    if [ "$status" -eq 0 ]; then
        echo "ok   (passed): $label"
        pass=$((pass + 1))
    else
        echo "FAIL: $label"
        echo "$LAST_OUTPUT" | grep FAIL | head -5 | sed 's/^/       /'
        failcount=$((failcount + 1))
    fi
}

# Fabricate a structurally valid deb in real Debian layout: ar members
# debian-binary ("2.0"), control.tar.* containing ./control, data.tar.*
# containing ./usr/bin/nkp. Compression matches dpkg-deb's xz default.
make_fake_deb() { # make_fake_deb <out.deb> <version> <arch> [payload-binary]
    local out=$1 ver=$2 arch=$3 payload=${4:-$binary} stage
    stage=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-fakedeb.XXXXXX")
    printf '2.0\n' > "$stage/debian-binary"
    mkdir -p "$stage/control/DEBIAN"
    printf 'Package: nkeepass\nVersion: %s\nArchitecture: %s\nMaintainer: t <t@t.invalid>\nDescription: fake\n' \
        "$ver" "$arch" > "$stage/control/DEBIAN/control"
    # control.tar ships the control file at its root (./control), as dpkg-deb
    # does; DEBIAN/ above is only the staging directory for dpkg-deb builds.
    (cd "$stage/control/DEBIAN" && tar -cJf "$stage/control.tar.xz" ./control)
    mkdir -p "$stage/data/usr/bin"
    cp "$payload" "$stage/data/usr/bin/nkp"
    (cd "$stage/data" && tar -cJf "$stage/data.tar.xz" ./usr)
    (cd "$stage" && ar r "$out" debian-binary control.tar.xz data.tar.xz)
    rm -rf "$stage"
}

build_positive_deb() { # build_positive_deb <out-dir>
    if command -v dpkg-deb >/dev/null; then
        bash "$repo/packaging/deb/build.sh" "$binary" "$version" amd64 "$1" >/dev/null
    else
        make_fake_deb "$1/nkeepass-${version}-amd64.deb" "$version" amd64
    fi
}

echo "== positive case: manifest-only run (no args) must succeed with exit 0"
expect_pass "manifest-only validation exits 0" bash "$repo/packaging/validate.sh"

echo "== positive case: complete, correct artifacts (real structure)"
pos="$work/positive"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$pos" >/dev/null
build_positive_deb "$pos"
if command -v makepkg >/dev/null; then
    bash "$repo/packaging/pacman/build.sh" \
        "$pos/nkeepass-${version}-x86_64-unknown-linux-gnu.tar.gz" \
        x86_64-unknown-linux-gnu "$pos" >/dev/null
fi
if command -v dpkg-deb >/dev/null; then
    echo "     (positive deb built by the real dpkg-deb builder)"
else
    echo "     (dpkg-deb unavailable; positive deb fabricated in Debian structure)"
fi
expect_pass "positive dir validates" \
    bash "$repo/packaging/validate.sh" --binary "$binary" "$pos" "$version" x86_64-unknown-linux-gnu
expect_smoke_ran "positive validation ends in the native smoke run"

echo "== negative: aarch64-named archive containing an x86_64 binary"
neg="$work/wrong-elf"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" aarch64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-arm64.deb" "$version" arm64
expect_fail "ELF architecture" "wrong ELF arch is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" aarch64-unknown-linux-gnu

echo "== negative: deb with wrong architecture metadata (ELF left correct)"
neg="$work/wrong-arch"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-amd64.deb" "$version" arm64
expect_fail "deb metadata mismatch: Package=nkeepass Version=$version Architecture=arm64 (want nkeepass/$version/amd64)" \
    "wrong deb architecture is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu
expect_smoke_skipped "wrong deb architecture prevents smoke execution"

echo "== negative: deb with wrong version metadata (arch left correct)"
neg="$work/wrong-version"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-amd64.deb" "9.9.9" amd64
expect_fail "deb metadata mismatch: Package=nkeepass Version=9.9.9 Architecture=amd64 (want nkeepass/$version/amd64)" \
    "wrong deb version is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu
expect_smoke_skipped "wrong deb version prevents smoke execution"

echo "== negative: tar member is a symlink, not a regular file"
neg="$work/symlink"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
build_positive_deb "$neg"
link_stage="$neg/nkeepass-${version}-x86_64-unknown-linux-gnu"
mkdir -p "$link_stage"
ln -s "$binary" "$link_stage/nkp"
cp "$repo/README.md" "$repo/LICENSE.md" "$link_stage/"
tar -czf "$neg/nkeepass-${version}-x86_64-unknown-linux-gnu.tar.gz" -C "$neg" "nkeepass-${version}-x86_64-unknown-linux-gnu"
expect_fail "is a symlink" "symlink tar member is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu
expect_smoke_skipped "symlink member prevents smoke execution"

echo "== negative: missing zip format (deb left in place)"
neg="$work/missing-formats"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
build_positive_deb "$neg"
rm "$neg/nkeepass-${version}-x86_64-unknown-linux-gnu.zip"
expect_fail "missing nkeepass-${version}-x86_64-unknown-linux-gnu.zip" \
    "missing zip is rejected" \
    bash "$repo/packaging/validate.sh" "$neg" "$version" x86_64-unknown-linux-gnu

echo "== negative: deb whose payload binary is not the expected one"
neg="$work/wrong-payload"
bash "$repo/packaging/scripts/archive.sh" "$binary" "$version" x86_64-unknown-linux-gnu "$neg" >/dev/null
make_fake_deb "$neg/nkeepass-${version}-amd64.deb" "$version" amd64 /bin/true
expect_fail "hashes differ across containers" \
    "deb payload differing from the built binary is rejected" \
    bash "$repo/packaging/validate.sh" --binary "$binary" "$neg" "$version" x86_64-unknown-linux-gnu

if command -v makepkg >/dev/null; then
    echo "== regression: hostile pacman tarball filename must not reach the PKGBUILD"
    neg="$work/hostile-name"
    mkdir -p "$neg"
    # Command substitution in the name: if this reached the generated
    # PKGBUILD unquoted, makepkg would execute it. The builder must reject
    # the name and never run the payload.
    # Command substitution in the name: if this reached the generated
    # PKGBUILD unquoted, makepkg would execute it. The builder must reject
    # the name and never run the payload.
    marker="pwned-marker-$$"
    hostile="$neg/evil\"\$(touch $marker)\".tar.gz"
    cp "$pos/nkeepass-${version}-x86_64-unknown-linux-gnu.tar.gz" "$hostile"
    expect_fail "tarball must be named" \
        "hostile pacman filename is rejected" \
        bash "$repo/packaging/pacman/build.sh" "$hostile" x86_64-unknown-linux-gnu "$neg/out"
    if find "${TMPDIR:-/tmp}" -maxdepth 3 -name "$marker" 2>/dev/null | grep -q .; then
        echo "FAIL (injection executed): $marker file was created"
        failcount=$((failcount + 1))
    else
        echo "ok   (no injection): $marker was not created anywhere under ${TMPDIR:-/tmp}"
        pass=$((pass + 1))
    fi
fi

if command -v makepkg >/dev/null; then
    echo "== negative: pacman package with modified payload (harmless marker ELF)"
    neg="$work/pacman-modified"
    mkdir -p "$neg"
    cp -a "$pos/." "$neg/"
    pkg="nkeepass-$(echo "$version" | tr '-' '.')-1-x86_64.pkg.tar.zst"
    extract="$neg/repack"
    mkdir -p "$extract"
    tar --zstd -xf "$neg/$pkg" -C "$extract"
    cp /bin/true "$extract/usr/bin/nkp"
    (cd "$extract" && tar --zstd -cf "$neg/$pkg" .PKGINFO .MTREE .BUILDINFO usr)
    expect_fail "pacman payload modified" \
        "modified pacman payload (harmless marker ELF) is rejected" \
        bash "$repo/packaging/validate.sh" --binary "$binary" "$neg" "$version" x86_64-unknown-linux-gnu
    expect_smoke_withheld "invalid pacman payload defers the smoke run"

    echo "== negative: pacman package with missing payload"
    rm -rf "$extract/usr/bin"
    (cd "$extract" && tar --zstd -cf "$neg/$pkg" .PKGINFO .MTREE .BUILDINFO usr)
    expect_fail "pacman payload" \
        "missing pacman payload is rejected" \
        bash "$repo/packaging/validate.sh" --binary "$binary" "$neg" "$version" x86_64-unknown-linux-gnu
fi

echo "== regression: invalid manifest defers the smoke run even with perfect artifacts"
neg="$work/invalid-manifest"
mkdir -p "$neg"
cp -a "$repo/packaging" "$neg/packaging"
# Corrupt the nuspec XML only; artifacts stay the known-good positive set.
printf '<?xml version="1.0"?><package><unclosed>' > "$neg/packaging/choco/nkeepass.nuspec"
expect_fail "choco nuspec is not well-formed XML" \
    "invalid manifest is rejected" \
    env NEOKEEPASS_VALIDATE_MANIFEST_ROOT="$neg/packaging" \
    bash "$repo/packaging/validate.sh" --binary "$binary" "$pos" "$version" x86_64-unknown-linux-gnu
expect_smoke_withheld "invalid manifest defers the smoke run"

if [ "$failcount" -ne 0 ]; then
    echo "packaging tests failed: $failcount uncaught case(s)"
    exit 1
fi
echo "packaging tests passed ($pass checks)"
