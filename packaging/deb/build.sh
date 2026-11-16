#!/usr/bin/env bash
# Builds a .deb from an already-built release binary using dpkg-deb.
#
# Usage: deb/build.sh <binary-path> <version> <deb-arch> <output-dir>
#
# <deb-arch> is a Debian architecture (amd64, arm64), not a Rust target
# triple. Requires dpkg-deb (Debian, Ubuntu, and CI ubuntu runners have it);
# validation of the produced deb falls back to a structural check on machines
# without dpkg tooling (see validate.sh). Re-running overwrites the .deb;
# safe to re-run.
set -euo pipefail

binary=$1
version=$2
deb_arch=$3
out_dir=$4

[ -x "$binary" ] || { echo "deb/build.sh: not an executable: $binary" >&2; exit 1; }
command -v dpkg-deb >/dev/null || {
    echo "deb/build.sh: dpkg-deb not available; .deb is built on Debian/Ubuntu only" >&2
    exit 1
}

repo=$(cd "$(dirname "$0")/../.." && pwd)
# Normalize before cd-ing anywhere else, so relative output paths survive.
out_dir=$(mkdir -p "$out_dir" && cd "$out_dir" && pwd)
pkg_root="nkeepass-${version}-${deb_arch}-deb"
stage=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-deb.XXXXXX")
trap 'rm -rf "$stage"' EXIT

install -D -m 755 "$binary" "$stage/$pkg_root/usr/bin/nkeepass"
install -D -m 644 "$repo/README.md" "$stage/$pkg_root/usr/share/doc/nkeepass/README.md"
install -D -m 644 "$repo/LICENSE.md" "$stage/$pkg_root/usr/share/doc/nkeepass/LICENSE.md"

# dpkg-deb requires the control tree in a DEBIAN subdirectory of the staging
# root; create it explicitly.
mkdir -p "$stage/$pkg_root/DEBIAN"
cat > "$stage/$pkg_root/DEBIAN/control" <<EOF
Package: nkeepass
Version: ${version}
Section: utils
Priority: optional
Architecture: ${deb_arch}
Maintainer: Neotales <maintainers@neotales.invalid>
Description: Headless KeePass automation CLI and TUI
 KeePass CLI/TUI for vault navigation and entry operations. KDBX parsing is
 delegated to the vendored neotales-keepass crate.
 Built from source; not published to any apt repository.
EOF

dpkg-deb --root-owner-group --build "$stage/$pkg_root" \
    "$out_dir/${pkg_root}.deb"
echo "deb/build.sh: wrote $out_dir/${pkg_root}.deb"
