#!/usr/bin/env bash
# Builds tar.gz and zip distribution archives from an already-built release
# binary.
#
# Usage: archive.sh <binary-path> <version> <target-triple> <output-dir>
#
# Produces: nkeepass-<version>-<target-triple>.tar.gz and .zip in <output-dir>,
# each containing one top-level directory nkeepass-<version>-<target-triple>/
# that holds the executable as `nkp` (the product's executable name) plus
# README.md and LICENSE.md. The archive basename keeps the historical
# `nkeepass` package identifier for compatibility; the executable inside is
# the real `nkp` binary name.
# <output-dir> may be relative; it is normalized here. Re-running overwrites
# the archives; it is safe to re-run.
set -euo pipefail

binary=$1
version=$2
triple=$3
out_dir=$4

[ -x "$binary" ] || { echo "archive.sh: not an executable: $binary" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
# Normalize before cd-ing anywhere else, so relative output paths survive the
# staging-directory change below.
out_dir=$(mkdir -p "$out_dir" && cd "$out_dir" && pwd)
name="nkeepass-${version}-${triple}"
stage=$(mktemp -d "${TMPDIR:-/tmp}/nkeepass-archive.XXXXXX")
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name"
cp "$binary" "$stage/$name/nkp"
chmod 755 "$stage/$name/nkp"
cp "$repo/README.md" "$repo/LICENSE.md" "$stage/$name/"

tar -czf "$out_dir/$name.tar.gz" -C "$stage" "$name"
(cd "$stage" && zip -r -q -X "$out_dir/$name.zip" "$name")
echo "archive.sh: wrote $out_dir/$name.tar.gz and $out_dir/$name.zip"
