#!/usr/bin/env bash
# Prints the nkeepass CLI version from crates/nkeepass/Cargo.toml.
# Single source of truth for all packaging scripts.
set -euo pipefail
cd "$(dirname "$0")/../.."
# sed, not toml parser: no parser dependency in packaging environments.
sed -n 's/^version = "\(.*\)"/\1/p' crates/nkeepass/Cargo.toml | head -n1
