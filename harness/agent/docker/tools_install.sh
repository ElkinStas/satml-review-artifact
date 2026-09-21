#!/usr/bin/env bash
# Sanity-check: every tool in the agent toolchain launches.
# Run at image build time; failure here aborts the build.
set -euo pipefail

echo "=== System tools ==="
gcc --version           | head -n1
gdb --version           | head -n1
strace -V               | head -n1
ltrace -V               | head -n1
file --version          | head -n1
readelf --version       | head -n1
objdump --version       | head -n1
r2 -v                   | head -n1

echo "=== Python tools ==="
python3 - <<'PY'
import importlib, sys
mods = ["angr", "capstone", "pwn", "z3", "lief", "elftools"]
fail = []
for m in mods:
    try:
        importlib.import_module(m)
        print(f"  ok: {m}")
    except Exception as e:
        print(f"  FAIL: {m} -> {e}", file=sys.stderr)
        fail.append(m)
if fail:
    sys.exit(1)
PY

echo "=== All tools loaded successfully ==="
