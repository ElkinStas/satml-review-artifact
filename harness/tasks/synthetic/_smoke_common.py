"""Shared helpers for NON-MUTATING CI smoke tests.

A smoke test must NEVER recompile over a committed binary: the committed binary is the frozen
reproducibility fingerprint (manifest.binary_sha256 and pool_manifest_v0.1.json). Recompiling it in
place would mutate the sha on any toolchain whose codegen differs bit-for-bit, silently breaking the
pool hash. These helpers let a smoke test verify TWO layers:

  layer 1 - the COMMITTED binary: sha == manifest, and it behaves correctly;
  layer 2 - a REBUILT binary compiled to a TEMP path: it compiles and behaves the same.

Neither layer touches the committed artifact.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

FLAGS = ["gcc", "-O0", "-no-pie", "-fno-stack-protector"]


def sha256_file(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def committed_and_manifest_sha(task_dir: Path, binname: str):
    """Return (committed_path, disk_sha_or_None, manifest_sha_or_None) without recompiling."""
    binp = Path(task_dir) / "binary" / binname
    mf = json.load(open(Path(task_dir) / "manifest.json"))
    disk = sha256_file(binp) if binp.exists() else None
    return binp, disk, mf.get("binary_sha256")


def rebuild_temp(src, binname: str):
    """Compile `src` to a fresh temp binary (never over the committed one).

    Returns (tmpdir, binpath, ok, stderr). Caller MUST call cleanup(tmpdir).
    """
    tmpd = tempfile.mkdtemp(prefix="smoke_")
    out = Path(tmpd) / binname
    cp = subprocess.run(FLAGS + ["-o", str(out), str(src)], capture_output=True, text=True)
    return tmpd, out, cp.returncode == 0, cp.stderr


def cleanup(tmpd: str) -> None:
    shutil.rmtree(tmpd, ignore_errors=True)
