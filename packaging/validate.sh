#!/usr/bin/env bash
# Validates packaging artifacts and manifests. Nonzero exit on any failure.
#
# Usage: validate.sh
#        validate.sh <artifacts-dir> <version> <target-triple> [triple...]
#
# With no arguments, only manifest syntax and version consistency are checked.
# With arguments, every listed target triple must have a complete set
# (tar.gz, zip, .deb) named nkeepass-<version>-<triple>, the ELF architecture
# of the shipped binary must match the triple, and the deb metadata must match
# the expected version/architecture. dpkg-deb is used when available;
# otherwise deb metadata is checked structurally via ar(1) + tar(1). If the
# host machine matches one of the triples (Linux, same machine architecture),
# the extracted binary is smoke-run with --help.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
fail=0
errors=()

record() { # record <ok|fail> <message>
    local status=$1 message=$2
    if [ "$status" = ok ]; then
        echo "ok   $message"
    else
        echo "FAIL $message"
        errors+=("$message")
        fail=1
    fi
}

elf_machine_for_triple() {
    # readelf prints "Machine: Advanced Micro Devices X86-64" for x86_64 and
    # "Machine: AArch64" for arm64.
    case $1 in
    x86_64*) echo "Advanced Micro Devices X86-64" ;;
    aarch64*) echo "AArch64" ;;
    *) echo "" ;;
    esac
}

# tar does not auto-detect compression when reading a stream from a pipe, so
# map the deb member name to an explicit modifier flag (no mode letter; the
# caller supplies -t or -x).
tar_flags_for_member() {
    case $1 in
    *.tar.gz) echo "-z" ;;
    *.tar.xz) echo "-J" ;;
    *.tar.zst) echo "--zstd" ;;
    *.tar) echo "" ;;
    *) echo "" ;;
    esac
}

deb_arch_for_triple() {
    case $1 in
    x86_64*) echo "amd64" ;;
    aarch64*) echo "arm64" ;;
    *) echo "" ;;
    esac
}

check_manifests() {
    local version=${1:-}

    # rpm spec: real metadata; keep the crate version pinned in one place.
    if grep -q -- "%global crate_version ${version}" "$repo/packaging/rpm/nkeepass.spec" 2>/dev/null; then
        record ok "rpm spec crate_version is ${version}"
    else
        record fail "rpm spec crate_version does not match ${version}"
    fi

    if grep -q -- "$version" "$repo/packaging/choco/nkeepass.nuspec" 2>/dev/null; then
        record ok "choco nuspec mentions version $version"
    else
        record fail "choco nuspec does not mention crate version $version"
    fi

    # nuspec: XML well-formed.
    if python3 -c "import xml.etree.ElementTree as ET; ET.parse('$repo/packaging/choco/nkeepass.nuspec')" 2>/dev/null; then
        record ok "choco nuspec is well-formed XML"
    else
        record fail "choco nuspec is not well-formed XML"
    fi

    # winget manifest: YAML if a parser is available, else skipped.
    if python3 -c "import yaml" 2>/dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$repo/packaging/winget/Neotales.nkeepass.yaml'))" 2>/dev/null; then
            record ok "winget manifest is valid YAML"
        else
            record fail "winget manifest is not valid YAML"
        fi
    else
        echo "skip winget manifest YAML check (pyyaml not installed)"
    fi
}

check_elf_arch() { # check_elf_arch <binary> <expected-machine>
    local binary=$1 expected=$2 got
    got=$(readelf -h "$binary" 2>/dev/null | sed -n 's/^ *Machine: *//p' || true)
    case $got in
    "$expected") record ok "binary ELF architecture is $expected" ;;
    "") record fail "could not read ELF machine from $binary" ;;
    *) record fail "binary ELF architecture is $got, expected $expected" ;;
    esac
}

check_deb() { # check_deb <deb> <expected-version> <expected-arch>
    local deb=$1 version=$2 arch=$3
    local control
    if command -v dpkg-deb >/dev/null; then
        local pkg gotver gotarch data_listing
        pkg=$(dpkg-deb -f "$deb" Package 2>/dev/null || true)
        gotver=$(dpkg-deb -f "$deb" Version 2>/dev/null || true)
        gotarch=$(dpkg-deb -f "$deb" Architecture 2>/dev/null || true)
        if [ "$pkg" = nkeepass ] && [ "$gotver" = "$version" ] && [ "$gotarch" = "$arch" ]; then
            record ok "deb metadata: Package=$pkg Version=$gotver Architecture=$gotarch"
        else
            record fail "deb metadata mismatch: Package=$pkg Version=$gotver Architecture=$gotarch (want nkeepass/$version/$arch)"
        fi
        data_listing=$(dpkg-deb -c "$deb" 2>/dev/null || true)
        if echo "$data_listing" | grep -q 'usr/bin/nkeepass'; then
            record ok "deb data archive installs /usr/bin/nkeepass"
        else
            record fail "deb data archive does not install /usr/bin/nkeepass"
        fi
        return
    fi

    # Structural fallback without dpkg tooling: a deb is an ar archive with
    # debian-binary plus control.tar.* and data.tar.* members.
    local members
    members=$(ar t "$deb" 2>/dev/null || true)
    if ! echo "$members" | grep -qx 'debian-binary'; then
        record fail "$deb is not a deb ar archive (no debian-binary member)"
        return
    fi
    local ctl
    ctl=$(echo "$members" | grep -E '^control\.tar(\.[a-z0-9]+)$' | head -n1 || true)
    [ -n "$ctl" ] || { record fail "$deb has no control.tar.* member"; return; }
    local tflags
    tflags=$(tar_flags_for_member "$ctl")
    local ctl_listing ctlfile
    # Capture listings before grepping: grep -q/head exit early, the producer
    # gets SIGPIPE, and pipefail would turn that into a false negative.
    ctl_listing=$(ar p "$deb" "$ctl" | tar $tflags -tf - 2>/dev/null || true)
    ctlfile=$(echo "$ctl_listing" | grep -E '/?control$' | head -n1 || true)
    [ -n "$ctlfile" ] || { record fail "$deb control archive has no control file"; return; }
    control=$(ar p "$deb" "$ctl" | tar $tflags -xOf - "$ctlfile" 2>/dev/null || true)
    local pkg gotver gotarch
    pkg=$(echo "$control" | sed -n 's/^Package: *//p')
    gotver=$(echo "$control" | sed -n 's/^Version: *//p')
    gotarch=$(echo "$control" | sed -n 's/^Architecture: *//p')
    if [ "$pkg" = nkeepass ] && [ "$gotver" = "$version" ] && [ "$gotarch" = "$arch" ]; then
        record ok "deb metadata (structural): Package=$pkg Version=$gotver Architecture=$gotarch"
    else
        record fail "deb metadata mismatch: Package=$pkg Version=$gotver Architecture=$gotarch (want nkeepass/$version/$arch)"
    fi
    # data archive must ship the binary path.
    local dat
    dat=$(echo "$members" | grep -E '^data\.tar(\.[a-z0-9]+)$' | head -n1 || true)
    [ -n "$dat" ] || { record fail "$deb has no data.tar.* member"; return; }
    tflags=$(tar_flags_for_member "$dat")
    local data_listing
    data_listing=$(ar p "$deb" "$dat" | tar $tflags -tf - 2>/dev/null || true)
    if echo "$data_listing" | grep -q 'usr/bin/nkeepass'; then
        record ok "deb data archive installs /usr/bin/nkeepass"
    else
        record fail "deb data archive does not install /usr/bin/nkeepass"
    fi
}

check_artifacts() {
    local dir=$1 version=$2
    shift 2
    local triple

    for triple in "$@"; do
        local machine debarch base
        machine=$(elf_machine_for_triple "$triple")
        debarch=$(deb_arch_for_triple "$triple")
        base="nkeepass-${version}-${triple}"

        local tarball="$dir/$base.tar.gz" zipfile="$dir/$base.zip" deb="$dir/nkeepass-${version}-$(deb_arch_for_triple "$triple").deb"

        # All three formats are required per target.
        [ -f "$tarball" ] || { record fail "missing $base.tar.gz"; continue; }
        [ -f "$zipfile" ] || { record fail "missing $base.zip"; continue; }
        [ -f "$deb" ] || { record fail "missing $base deb"; continue; }

        for a in "$tarball" "$zipfile"; do
            local listing
            case $a in
            *.tar.gz) listing=$(tar -tzf "$a" 2>/dev/null || true) ;;
            *.zip) listing=$(unzip -l "$a" 2>/dev/null || true) ;;
            esac
            if echo "$listing" | grep -q "$base/nkeepass$"; then
                record ok "$(basename "$a") contains the nkeepass binary"
            else
                record fail "$(basename "$a") does not contain the nkeepass binary"
            fi
            if echo "$listing" | grep -q 'README.md' && echo "$listing" | grep -q 'LICENSE.md'; then
                record ok "$(basename "$a") contains README.md and LICENSE.md"
            else
                record fail "$(basename "$a") missing README.md/LICENSE.md"
            fi
        done

        # ELF architecture of the shipped binary must match the triple.
        local work
        work=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-validate.XXXXXX")
        tar -xzf "$tarball" -C "$work" "$base/nkeepass"
        check_elf_arch "$work/$base/nkeepass" "$machine"

        # Smoke-run when the host matches the target.
        if [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = "${triple%%-*}" ]; then
            if "$work/$base/nkeepass" --help >/dev/null 2>&1; then
                record ok "smoke run: $base/nkeepass --help exits 0"
            else
                record fail "smoke run: $base/nkeepass --help failed"
            fi
        fi
        rm -rf "$work"

        check_deb "$deb" "$version" "$debarch"
    done
}

check_pacman_artifacts() { # check_pacman_artifacts <dir> <version>
    local dir=$1 version=$2 pkgver=${version//-/.}
    shopt -s nullglob
    local pkgs=("$dir"/nkeepass-*.pkg.tar.*)
    shopt -u nullglob
    [ "${#pkgs[@]}" -gt 0 ] || { echo "skip pacman package check (none present; built on Arch only)"; return; }
    local p flags info
    for p in "${pkgs[@]}"; do
        case $p in
        *.tar.gz) flags=-z ;;
        *.tar.xz) flags=-J ;;
        *.tar.zst) flags=--zstd ;;
        *) flags="" ;;
        esac
        # Capture the listing first: grep -q exits early, tar gets SIGPIPE,
        # and pipefail would turn that into a false negative.
        local listing
        listing=$(tar $flags -tf "$p" 2>/dev/null || true)
        if echo "$listing" | grep -qx '.PKGINFO'; then
            record ok "$(basename "$p") contains .PKGINFO"
        else
            record fail "$(basename "$p") has no .PKGINFO"
            continue
        fi
        info=$(tar $flags -xOf "$p" .PKGINFO 2>/dev/null || true)
        local gotname gotver gotarch
        gotname=$(echo "$info" | sed -n 's/^pkgname = //p')
        gotver=$(echo "$info" | sed -n 's/^pkgver = //p')
        gotarch=$(echo "$info" | sed -n 's/^arch = //p')
        # .PKGINFO pkgver includes the pkgrel suffix (0.0.0.alpha.25-1).
        if [ "$gotname" = nkeepass ] && [ "${gotver%-*}" = "$pkgver" ]; then
            record ok "pacman package metadata: pkgname=$gotname pkgver=$gotver arch=$gotarch"
        else
            record fail "pacman package metadata mismatch: pkgname=$gotname pkgver=$gotver (want nkeepass/$pkgver)"
        fi
    done
}

if [ $# -gt 0 ]; then
    [ $# -ge 3 ] || {
        echo "usage: validate.sh [<artifacts-dir> <version> <triple>...]" >&2
        exit 2
    }
    dir=$1
    version=$2
    [ -d "$dir" ] || { echo "FAIL artifacts dir not found: $dir" >&2; exit 1; }
    shift 2
    check_manifests "$version"
    check_artifacts "$dir" "$version" "$@"
    check_pacman_artifacts "$dir" "$version"
else
    version=$(bash "$repo/packaging/scripts/version.sh")
    [ -n "$version" ] || { echo "FAIL version.sh produced no version" >&2; exit 1; }
    check_manifests "$version"
fi

if [ "$fail" -ne 0 ]; then
    echo "validation failed: ${#errors[@]} problem(s)"
    exit 1
fi
echo "validation passed"
