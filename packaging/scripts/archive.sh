#!/usr/bin/env bash
# Builds tar.gz and zip distribution archives from an already-built release
# binary.
#
# Usage: archive.sh <binary-path> <version> <target-triple> <output-dir>
#
# Produces: nkeepass-<version>-<target-triple>.tar.gz and .zip in <output-dir>.
# Re-running overwrites the archives; it is safe to re-run.
set -euo pipefail

binary=$1
version=$2
triple=$3
out_dir=$4

set -e
[ -x "$binary" ] || { echo "archive.sh: not an executable: $binary" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
name="nkeepass-${version}-${triple}"
stage=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-archive.XXXXXX")
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name"
cp "$binary" "$stage/$name/nkeepass"
chmod 755 "$stage/$name/nkeepass"
cp "$repo/README.md" "$repo/LICENSE.md" "$stage/$name/"

mkdir -p "$out_dir"
tar -czf "$out_dir/$name.tar.gz" -C "$stage" "$name"
(cd "$stage" && zip -r -q -X "$out_dir/$name.zip" "$name")
echo "archive.sh: wrote $out_dir/$name.tar.gz and $out_dir/$name.zip"
