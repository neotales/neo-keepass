#!/usr/bin/env bash
# Validates packaging artifacts and manifests. Nonzero exit on any failure.
#
# Usage: validate.sh [artifacts-dir]
# With an artifacts dir, archives and .deb files inside it are checked.
# Without one, only manifest syntax is checked.
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

check_manifests() {
    # PKGBUILD: bash syntax check.
    if bash -n "$repo/packaging/pacman/PKGBUILD" 2>/dev/null; then
        record ok "pacman PKGBUILD parses as bash"
    else
        record fail "pacman PKGBUILD has bash syntax errors"
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

    # Version consistency: packaging manifests must match the crate version.
    version=$(bash "$repo/packaging/scripts/version.sh")
    [ -n "$version" ] || { record fail "version.sh produced no version"; return; }
    record ok "crate version: $version"
    for f in "$repo/packaging/pacman/PKGBUILD" "$repo/packaging/choco/nkeepass.nuspec"; do
        # Arch pkgver forbids dashes, so PKGBUILD stores 0.0.0.alpha.25.
        version_pkgver=$(echo "$version" | tr '-' '.')
        if grep -q -- "$version" "$f" || grep -q -- "$version_pkgver" "$f"; then
            record ok "$f mentions version $version"
        else
            record fail "$f does not mention crate version $version"
        fi
    done
}

check_artifacts() {
    local dir=$1
    shopt -s nullglob
    local archives=("$dir"/nkeepass-*.tar.gz "$dir"/nkeepass-*.zip)
    local debs=("$dir"/nkeepass-*.deb)
    shopt -u nullglob
    local found=0

    for a in "${archives[@]}"; do
        found=1
        case "$a" in
        *.tar.gz)
            if tar -tzf "$a" | grep -q "nkeepass$"; then
                record ok "$(basename "$a") contains the nkeepass binary"
            else
                record fail "$(basename "$a") does not contain a nkeepass binary"
            fi
            ;;
        *.zip)
            if unzip -l "$a" | grep -q "nkeepass$"; then
                record ok "$(basename "$a") contains the nkeepass binary"
            else
                record fail "$(basename "$a") does not contain a nkeepass binary"
            fi
            ;;
        esac
        for member in README.md LICENSE.md; do
            if tar -tzf "$a" 2>/dev/null | grep -q "$member" \
                || unzip -l "$a" 2>/dev/null | grep -q "$member"; then
                record ok "$(basename "$a") contains $member"
            else
                record fail "$(basename "$a") missing $member"
            fi
        done
    done

    for d in "${debs[@]}"; do
        found=1
        if dpkg-deb -I "$d" >/dev/null 2>&1; then
            record ok "$(basename "$d") is a valid deb"
        else
            record fail "$(basename "$d") is not a valid deb"
        fi
        if [ "$(dpkg-deb -c "$d" 2>/dev/null | grep -c 'usr/bin/nkeepass')" -ge 1 ]; then
            record ok "$(basename "$d") installs /usr/bin/nkeepass"
        else
            record fail "$(basename "$d") does not install /usr/bin/nkeepass"
        fi
    done

    [ "$found" = 1 ] || {
        echo "FAIL no nkeepass archives or debs found in $dir"
        fail=1
        errors+=("no artifacts in $dir")
    }
}

check_manifests
if [ $# -ge 1 ]; then
    check_artifacts "$1"
fi

if [ "$fail" -ne 0 ]; then
    echo "validation failed: ${#errors[@]} problem(s)"
    exit 1
fi
echo "validation passed"
