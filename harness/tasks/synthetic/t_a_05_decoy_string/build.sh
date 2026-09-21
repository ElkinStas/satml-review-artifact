#!/usr/bin/env bash
# Reproducible build recipe. Compiles the source from STDIN (so the source filename is NOT embedded
# in the binary's string table -- avoids a `strings` self-spoiler), to a TEMP path. Does NOT overwrite
# the committed binary. The committed binary was built the same way, so this rebuilds bit-for-bit.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp)"
gcc -O2 -s -no-pie -fno-stack-protector -x c - -o "$OUT" < "$DIR/binary/decoy_string5.c"
echo "rebuilt   sha256: $(sha256sum "$OUT" | cut -d' ' -f1)"
echo "committed sha256: $(sha256sum "$DIR/binary/decoy_string5" | cut -d' ' -f1)"
rm -f "$OUT"
