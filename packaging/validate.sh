#!/usr/bin/env bash
# Validates packaging artifacts and manifests. Nonzero exit on any failure.
#
# Usage: validate.sh [--binary BUILT-BINARY]
#        validate.sh [--binary BUILT-BINARY] <artifacts-dir> <version> <triple> [triple...]
#
# With no arguments, only manifest syntax and version consistency are checked.
# With arguments, every listed target triple must have a complete set
# (tar.gz, zip, .deb) named nkeepass-<version>-<triple> /
# nkeepass-<version>-<deb-arch>.deb. For every container the shipped binary is
# extracted and checked: regular file, not a symlink, ELF architecture
# matching the triple, and a sha256 equal across all containers and, when
# --binary is given, equal to the expected built binary. Deb metadata
# (package/version/architecture) and pacman metadata (.PKGINFO, when pacman
# artifacts are present) are checked; the pacman package architecture must map
# to one of the expected triples. dpkg-deb is used when available; otherwise
# deb metadata is checked structurally via ar(1) + tar(1). The native
# target's binary is smoke-run with --help under timeout(1) ONLY after every
# check for that target has passed; a binary that failed any check is never
# executed.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
fail=0
errors=()
expected_binary=""

# ---- argument parsing ------------------------------------------------------
while [ $# -gt 0 ] && [ "$1" = --binary ]; do
    [ $# -ge 2 ] || { echo "usage: --binary needs a path" >&2; exit 2; }
    expected_binary=$2
    shift 2
done

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

pkg_arch_for_triple() {
    case $1 in
    x86_64*) echo "x86_64" ;;
    aarch64*) echo "aarch64" ;;
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

# tar does not auto-detect compression when reading a stream from a pipe, so
# map the archive member name to an explicit modifier flag (no mode letter;
# the caller supplies -t or -x).
tar_flags_for_member() {
    case $1 in
    *.tar.gz) echo "-z" ;;
    *.tar.xz) echo "-J" ;;
    *.tar.zst) echo "--zstd" ;;
    *.tar) echo "" ;;
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

# binary_sha_or_reason <path> <machine> <label>
# Pure check, never executes anything. On success prints the sha256 and
# returns 0; on failure prints the reason to stderr and returns 1. The caller
# records pass/fail (record() must run in the caller's shell, not a $()
# subshell, or the global failure counter is lost).
binary_sha_or_reason() {
    local path=$1 expected=$2 label=$3 got
    if [ -L "$path" ]; then
        echo "$label is a symlink, not a regular file" >&2
        return 1
    fi
    if [ ! -f "$path" ]; then
        echo "$label is not a regular file" >&2
        return 1
    fi
    got=$(readelf -h "$path" 2>/dev/null | sed -n 's/^ *Machine: *//p' || true)
    if [ "$got" != "$expected" ]; then
        echo "$label ELF architecture is '${got:-unreadable}', expected $expected" >&2
        return 1
    fi
    sha256sum "$path" | cut -d' ' -f1
}

# extract_binary_from_deb <deb> <dest>: streams the data archive's binary out
# without unpacking the whole archive.
extract_binary_from_deb() {
    local deb=$1 dest=$2 members dat tflags binmember
    members=$(ar t "$deb" 2>/dev/null || true)
    echo "$members" | grep -qx 'debian-binary' || return 1
    dat=$(echo "$members" | grep -E '^data\.tar(\.[a-z0-9]+)$' | head -n1 || true)
    [ -n "$dat" ] || return 1
    tflags=$(tar_flags_for_member "$dat")
    binmember=$(ar p "$deb" "$dat" | tar $tflags -tf - 2>/dev/null \
        | grep -E '^\./?usr/bin/nkeepass$' | head -n1 || true)
    [ -n "$binmember" ] || return 1
    ar p "$deb" "$dat" | tar $tflags -xOf - "$binmember" > "$dest"
}

check_deb_metadata() { # check_deb_metadata <deb> <expected-version> <expected-arch>
    local deb=$1 version=$2 arch=$3
    if command -v dpkg-deb >/dev/null; then
        local pkg gotver gotarch
        pkg=$(dpkg-deb -f "$deb" Package 2>/dev/null || true)
        gotver=$(dpkg-deb -f "$deb" Version 2>/dev/null || true)
        gotarch=$(dpkg-deb -f "$deb" Architecture 2>/dev/null || true)
        if [ "$pkg" = nkeepass ] && [ "$gotver" = "$version" ] && [ "$gotarch" = "$arch" ]; then
            record ok "deb metadata: Package=$pkg Version=$gotver Architecture=$gotarch"
        else
            record fail "deb metadata mismatch: Package=$pkg Version=$gotver Architecture=$gotarch (want nkeepass/$version/$arch)"
        fi
        return
    fi

    # Structural fallback without dpkg tooling: a deb is an ar archive with
    # debian-binary plus control.tar.* and data.tar.* members.
    local members ctl tflags ctl_listing ctlfile control pkg gotver gotarch
    members=$(ar t "$deb" 2>/dev/null || true)
    if ! echo "$members" | grep -qx 'debian-binary'; then
        record fail "deb structure: no debian-binary member in $deb"
        return
    fi
    ctl=$(echo "$members" | grep -E '^control\.tar(\.[a-z0-9]+)$' | head -n1 || true)
    if [ -z "$ctl" ]; then
        record fail "deb structure: no control.tar.* member in $deb"
        return
    fi
    tflags=$(tar_flags_for_member "$ctl")
    ctl_listing=$(ar p "$deb" "$ctl" | tar $tflags -tf - 2>/dev/null || true)
    ctlfile=$(echo "$ctl_listing" | grep -E '^\./?control$' | head -n1 || true)
    if [ -z "$ctlfile" ]; then
        record fail "deb structure: no control file in $deb"
        return
    fi
    control=$(ar p "$deb" "$ctl" | tar $tflags -xOf - "$ctlfile" 2>/dev/null || true)
    pkg=$(echo "$control" | sed -n 's/^Package: *//p')
    gotver=$(echo "$control" | sed -n 's/^Version: *//p')
    gotarch=$(echo "$control" | sed -n 's/^Architecture: *//p')
    if [ "$pkg" = nkeepass ] && [ "$gotver" = "$version" ] && [ "$gotarch" = "$arch" ]; then
        record ok "deb metadata (structural): Package=$pkg Version=$gotver Architecture=$gotarch"
    else
        record fail "deb metadata mismatch: Package=$pkg Version=$gotver Architecture=$gotarch (want nkeepass/$version/$arch)"
    fi
}

check_pacman_artifacts() { # check_pacman_artifacts <dir> <version> <triple>...
    local dir=$1 version=$2
    shift 2
    local pkgver=${version//-/.}
    shopt -s nullglob
    local pkgs=("$dir"/nkeepass-*.pkg.tar.*)
    shopt -u nullglob
    if [ "${#pkgs[@]}" -eq 0 ]; then
        echo "skip pacman package check (none present; built on Arch only)"
        return
    fi
    local p flags listing info gotname gotver gotarch
    for p in "${pkgs[@]}"; do
        case $p in
        *.tar.gz) flags=-z ;;
        *.tar.xz) flags=-J ;;
        *.tar.zst) flags=--zstd ;;
        *) flags="" ;;
        esac
        # Capture listings before grepping: grep -q exits early, the producer
        # gets SIGPIPE, and pipefail would turn that into a false negative.
        listing=$(tar $flags -tf "$p" 2>/dev/null || true)
        if ! echo "$listing" | grep -qx '.PKGINFO'; then
            record fail "$(basename "$p") has no .PKGINFO"
            continue
        fi
        record ok "$(basename "$p") contains .PKGINFO"
        info=$(tar $flags -xOf "$p" .PKGINFO 2>/dev/null || true)
        gotname=$(echo "$info" | sed -n 's/^pkgname = //p')
        gotver=$(echo "$info" | sed -n 's/^pkgver = //p')
        gotarch=$(echo "$info" | sed -n 's/^arch = //p')
        # .PKGINFO pkgver includes the pkgrel suffix (0.0.0.alpha.25-1).
        if [ "$gotname" != nkeepass ] || [ "${gotver%-*}" != "$pkgver" ]; then
            record fail "pacman package metadata mismatch: pkgname=$gotname pkgver=$gotver (want nkeepass/$pkgver)"
            continue
        fi
        # The package architecture must map back to an expected triple.
        local arch_ok=0 triple
        for triple in "$@"; do
            [ "$(pkg_arch_for_triple "$triple")" = "$gotarch" ] && arch_ok=1
        done
        if [ "$arch_ok" = 1 ]; then
            record ok "pacman package metadata: pkgname=$gotname pkgver=$gotver arch=$gotarch"
        else
            record fail "pacman package arch $gotarch does not map to any expected triple"
        fi
    done
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

        local tarball="$dir/$base.tar.gz" zipfile="$dir/$base.zip"
        local deb="$dir/nkeepass-${version}-${debarch}.deb"

        # All three formats are required per target.
        [ -f "$tarball" ] || { record fail "missing $base.tar.gz"; continue; }
        [ -f "$zipfile" ] || { record fail "missing $base.zip"; continue; }
        [ -f "$deb" ] || { record fail "missing $base deb"; continue; }

        local work
        work=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-validate.XXXXXX")
        local bin_tar="$work/from-tar" bin_zip="$work/from-zip" bin_deb="$work/from-deb"
        local smoke=1 tar_hash zip_hash deb_hash tar_extracted=0 zip_extracted=0
        local tar_member="$base/nkeepass"

        # Extract the binary from each container. Extraction is into a fresh
        # temp dir, members are named exactly, and nothing is executed here.
        if tar -xzf "$tarball" -C "$work" --no-same-owner --no-same-permissions "$tar_member" 2>/dev/null \
            && mv "$work/$tar_member" "$bin_tar" 2>/dev/null; then
            tar_extracted=1
        else
            record fail "tar.gz does not contain $tar_member as a regular member"
            smoke=0
        fi
        if unzip -q -o "$zipfile" "$tar_member" -d "$work" 2>/dev/null \
            && mv "$work/$tar_member" "$bin_zip" 2>/dev/null; then
            zip_extracted=1
        else
            record fail "zip does not contain $tar_member as a regular member"
            smoke=0
        fi
        if ! extract_binary_from_deb "$deb" "$bin_deb"; then
            record fail "deb data archive does not contain usr/bin/nkeepass"
            smoke=0
        fi

        # Per-container binary checks. record() runs in this shell.
        tar_hash=""
        if [ "$tar_extracted" = 1 ]; then
            if tar_hash=$(binary_sha_or_reason "$bin_tar" "$machine" "$base tar.gz binary"); then
                record ok "$base tar.gz binary is a regular $machine ELF"
            else
                record fail "$base tar.gz binary check failed (reason above)"
                smoke=0
                tar_hash=""
            fi
        fi
        zip_hash=""
        if [ "$zip_extracted" = 1 ]; then
            if zip_hash=$(binary_sha_or_reason "$bin_zip" "$machine" "$base zip binary"); then
                record ok "$base zip binary is a regular $machine ELF"
            else
                record fail "$base zip binary check failed (reason above)"
                smoke=0
                zip_hash=""
            fi
        fi
        deb_hash=""
        if [ -f "$bin_deb" ]; then
            if deb_hash=$(binary_sha_or_reason "$bin_deb" "$machine" "$base deb binary"); then
                record ok "$base deb binary is a regular $machine ELF"
            else
                record fail "$base deb binary check failed (reason above)"
                smoke=0
                deb_hash=""
            fi
        fi

        # The same binary must be in every container, and match the expected
        # built binary when one was supplied.
        if [ -n "$tar_hash" ] && [ "$tar_hash" = "$zip_hash" ] && [ "$tar_hash" = "$deb_hash" ]; then
            record ok "$base binary is identical (sha256) in tar.gz, zip, and deb"
            if [ -n "$expected_binary" ]; then
                local want
                want=$(sha256sum "$expected_binary" | cut -d' ' -f1)
                if [ "$tar_hash" = "$want" ]; then
                    record ok "$base binary matches the expected built binary"
                else
                    record fail "$base binary does not match the expected built binary"
                    smoke=0
                fi
            fi
        elif [ -n "$tar_hash" ] || [ -n "$zip_hash" ] || [ -n "$deb_hash" ]; then
            record fail "$base binary hashes differ across containers (tar=${tar_hash:-none} zip=${zip_hash:-none} deb=${deb_hash:-none})"
            smoke=0
        fi

        check_deb_metadata "$deb" "$version" "$debarch"

        # Smoke-run only the native target and only when every check above
        # passed for this triple. The run is bounded by timeout.
        if [ "$smoke" = 1 ] && [ "$(uname -s)" = Linux ] \
            && [ "$(uname -m)" = "$(pkg_arch_for_triple "$triple")" ]; then
            if timeout 10 "$bin_tar" --help >/dev/null 2>&1; then
                record ok "smoke run: $base binary --help exits 0 (timeout 10s)"
            else
                record fail "smoke run: $base binary --help failed or timed out"
            fi
        elif [ "$smoke" = 0 ]; then
            echo "skip smoke run for $base (a check failed; failed binaries are never executed)"
        fi
        rm -rf "$work"
    done

    check_pacman_artifacts "$dir" "$version" "$@"
}

if [ $# -gt 0 ]; then
    [ $# -ge 3 ] || {
        echo "usage: validate.sh [--binary BUILT-BINARY] [<artifacts-dir> <version> <triple>...]" >&2
        exit 2
    }
    dir=$1
    version=$2
    [ -d "$dir" ] || { echo "FAIL artifacts dir not found: $dir" >&2; exit 1; }
    shift 2
    check_manifests "$version"
    check_artifacts "$dir" "$version" "$@"
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
