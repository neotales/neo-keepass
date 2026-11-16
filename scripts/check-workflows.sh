#!/usr/bin/env bash
# Checks the workflow YAML for shell-semantics traps and syntax:
#
# 1. Every `run:` string containing a backslash followed by whitespace fails.
#    YAML plain/folded scalars join lines with a space, so a trailing `\` for
#    shell line continuation becomes `\ ` (escaped space) in the rendered
#    command — valid bash, wrong semantics. Continuations must live in block
#    scalars (`run: |`), where newlines are literal.
# 2. Every `run:` string must pass `bash -n` after GitHub's `${{ ... }}`
#    expressions are substituted with a placeholder.
#
# Usage: scripts/check-workflows.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$repo" <<'PY'
import os
import subprocess
import sys

import yaml

repo = sys.argv[1]
wf_dir = os.path.join(repo, ".github", "workflows")
problems = 0

PLACEHOLDER = "CI_EXPRESSION_PLACEHOLDER"

for name in sorted(os.listdir(wf_dir)):
    if not (name.endswith(".yml") or name.endswith(".yaml")):
        continue
    path = os.path.join(wf_dir, name)
    with open(path) as fh:
        doc = yaml.safe_load(fh)

    runs = []

    def collect(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "run" and isinstance(value, str):
                    runs.append(value)
                else:
                    collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(doc)

    for i, run in enumerate(runs):
        rendered = run.replace("${{", PLACEHOLDER).replace("}}", "")
        label = f"{name} run[{i}]"
        # Folded/plain scalars turn a line-leading continuation into
        # backslash-space, which silently changes shell semantics.
        if "\\ " in rendered or rendered.endswith("\\"):
            print(f"FAIL {label}: backslash continuation outside a block scalar")
            problems += 1
        result = subprocess.run(
            ["bash", "-n", "-c", rendered], capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"FAIL {label}: bash -n rejected rendered command:\n{result.stderr}")
            problems += 1

if problems:
    print(f"workflow check failed: {problems} problem(s)")
    sys.exit(1)
print("workflow run blocks ok (no folded continuations, bash -n clean)")
PY
