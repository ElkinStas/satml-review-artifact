"""tasks/verify.py -- real-task verification harness (Track B).

Implements Tier 1 of the manifest's verification protocol: given a candidate
binary, confirm it is a Linux x86-64 ELF, that its file size matches the
Nishizaka Table VI reference within tolerance, and that the declared input
method is known. Tier 1 needs no write-up and catches the during-CTF vs
post-CTF version mismatch (a wrong-version binary shows up as a size mismatch).

It also provides run_binary() -- execute a binary with a given input under a
declared input method (stdin / argv / file). Track C's BinaryOracle
(agent/submit.py, Weeks 3-5) reuses this primitive; at that point run_binary
should be lifted into a module shared by tasks/ and agent/.

Tier 2 (the binary reaches its verification logic) and Tier 3 (the known-good
solution reproduces -- the Definition-of-Done sense of "harness-verified") are
run per task inside the user's Docker evaluation container.

Usage:
  python tasks/verify.py --list
  python tasks/verify.py <task_id> --binary <path>      # Tier-1 inspect
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_MANIFEST = Path(__file__).resolve().parent / "manifest.json"

# Tier-1 size tolerance: post-CTF rebuilds drift slightly; a 2x difference is
# the wrong binary. Within MATCH -> ok; within CLOSE -> flag for manual check.
_SIZE_MATCH_FRAC = 0.05
_SIZE_CLOSE_FRAC = 0.25

_INPUT_METHODS = ("stdin", "argv", "file")


# --- manifest access --------------------------------------------------------
def load_manifest() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def all_tasks(manifest: dict) -> list[dict]:
    real = manifest.get("real", {})
    tasks: list[dict] = []
    for stratum in ("overlap_subset", "fresh_subset"):
        tasks += real.get(stratum, {}).get("tasks", [])
    return tasks


def find_task(manifest: dict, task_id: str) -> dict | None:
    return next((t for t in all_tasks(manifest) if t["task_id"] == task_id), None)


# --- size parsing -----------------------------------------------------------
def parse_size(text: str) -> int:
    """'18.6KB' / '2.35MB' / '340KB' -> bytes."""
    m = re.fullmatch(r"\s*([\d.]+)\s*([KMG]?B)\s*", text, re.IGNORECASE)
    if not m:
        raise ValueError(f"unparseable size: {text!r}")
    value, unit = float(m.group(1)), m.group(2).upper()
    factor = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}[unit]
    return int(value * factor)


# --- Tier 1 -----------------------------------------------------------------
def inspect(binary_path: Path) -> dict:
    """Return {exists, size_bytes, is_elf, arch} for a candidate binary."""
    if not binary_path.is_file():
        return {"exists": False}
    size = binary_path.stat().st_size
    try:
        out = subprocess.run(["file", "-b", str(binary_path)],
                             capture_output=True, text=True, timeout=15).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        out = ""
    is_elf = "ELF" in out
    arch = ("x86_64" if ("x86-64" in out or "x86_64" in out)
            else ("other" if is_elf else "n/a"))
    return {"exists": True, "size_bytes": size, "is_elf": is_elf,
            "arch": arch, "file_output": out.strip()}


def tier1(task: dict, binary_path: Path) -> dict:
    """Compare an inspected binary against the task's verification_reference."""
    ref = task.get("verification_reference", {})
    info = inspect(binary_path)
    reasons: list[str] = []
    verdict = "pass"

    if not info.get("exists"):
        return {"verdict": "fail", "reasons": ["binary not found at given path"],
                "inspected": info}

    if not info["is_elf"]:
        verdict, _ = "fail", reasons.append("not an ELF binary")
    elif info["arch"] != "x86_64":
        verdict, _ = "fail", reasons.append(f"arch is {info['arch']}, expected x86_64")

    ref_size_text = ref.get("ref_file_size")
    if ref_size_text:
        ref_bytes = parse_size(ref_size_text)
        diff = abs(info["size_bytes"] - ref_bytes) / ref_bytes
        if diff <= _SIZE_MATCH_FRAC:
            reasons.append(f"size matches Table VI ({ref_size_text}, {diff:.1%} off)")
        elif diff <= _SIZE_CLOSE_FRAC:
            if verdict == "pass":
                verdict = "check"
            reasons.append(f"size close but off by {diff:.1%} vs {ref_size_text} "
                           "-- possible post-CTF rebuild, verify version")
        else:
            verdict = "fail"
            reasons.append(f"size {info['size_bytes']}B is {diff:.0%} off "
                           f"Table VI {ref_size_text} -- likely the wrong binary")

    im = ref.get("input_method")
    if im and im not in _INPUT_METHODS:
        reasons.append(f"declared input method {im!r} is not recognised")

    return {"verdict": verdict, "reasons": reasons, "inspected": info}


# --- run primitive (reused by Track C's BinaryOracle) -----------------------
def run_binary(binary_path: Path, input_value: str, input_method: str,
               timeout: int = 20) -> dict:
    """Execute a binary with one input under the declared input method.

    input_method: 'stdin' -> piped to stdin; 'argv' -> passed as argv[1];
    'file' -> written to a temp file whose path is passed as argv[1].
    Returns {exit_code, stdout, stderr, timed_out}.
    """
    if input_method not in _INPUT_METHODS:
        raise ValueError(f"unknown input method: {input_method!r}")

    argv = [str(binary_path)]
    stdin_data = None
    tmp_file: Path | None = None
    try:
        if input_method == "stdin":
            stdin_data = input_value
        elif input_method == "argv":
            argv.append(input_value)
        else:  # file
            fd, name = tempfile.mkstemp(prefix="rr_input_")
            tmp_file = Path(name)
            os.write(fd, input_value.encode())
            os.close(fd)
            argv.append(str(tmp_file))

        try:
            proc = subprocess.run(argv, input=stdin_data, capture_output=True,
                                  text=True, timeout=timeout, check=False)
            return {"exit_code": proc.returncode, "stdout": proc.stdout,
                    "stderr": proc.stderr, "timed_out": False}
        except subprocess.TimeoutExpired:
            return {"exit_code": None, "stdout": "", "stderr": "",
                    "timed_out": True}
    finally:
        if tmp_file is not None:
            tmp_file.unlink(missing_ok=True)


# --- CLI --------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Track B real-task verification (Tier 1).")
    ap.add_argument("task_id", nargs="?", help="manifest task id")
    ap.add_argument("--binary", help="path to the candidate binary")
    ap.add_argument("--list", action="store_true", help="list manifest tasks")
    args = ap.parse_args()

    manifest = load_manifest()

    if args.list:
        for t in all_tasks(manifest):
            print(f"  {t['task_id']:24s} {t['role']:18s} "
                  f"ref={t['verification_reference'].get('ref_file_size','?')}")
        return 0

    if not args.task_id or not args.binary:
        ap.error("provide <task_id> and --binary, or use --list")

    task = find_task(manifest, args.task_id)
    if task is None:
        print(f"unknown task_id: {args.task_id}", file=sys.stderr)
        return 2

    result = tier1(task, Path(args.binary))
    print(f"task     : {task['task_id']}  ({task['challenge']})")
    print(f"role     : {task['role']}")
    print(f"Tier-1   : {result['verdict'].upper()}")
    for r in result["reasons"]:
        print(f"  - {r}")
    return 0 if result["verdict"] != "fail" else 1


if __name__ == "__main__":
    raise SystemExit(main())
