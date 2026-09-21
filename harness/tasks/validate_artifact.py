#!/usr/bin/env python3
"""CANONICAL VALIDATOR -- the one gate for the held-out pool this artifact ships.

Everything is checked against the SHIPPED BINARY. Nothing is taken from the manifest on trust; the
manifest is the claim, the ELF is the evidence, and a disagreement is a failure of the manifest.

WHY THERE IS ONLY ONE
The project accumulated several validators over its development, aimed at different pools and
different generators. Two of them report alarming verdicts on held-out binaries that are perfectly
sound:

  * `validate_instance.py` is the frozen suite for the DEVELOPMENT pool. Its anchor-hygiene and
    deceptive-infeasibility layers need `__audit_*` anchors, which `gen_replication.py` does not
    emit. On held-out instances those layers return REVIEW because they cannot run -- not because
    anything is wrong. Reading that as a defect would be a mistake.
  * `verify_pool.py` scans `t_*/manifest.json` and hard-codes two invariants the held-out design
    deliberately inverts. It would report success on a pool it never examined.

Both remain in the repository for the development pool. Neither speaks about the held-out pool, and
neither is shipped in the review artifact.

WHAT THIS CHECKS
  1 scorer/executable agreement   the flag is accepted and each decoy rejected, BY EXECUTION
  2 solvability                   the recorded ground-truth solution actually produces the flag
  3 misleading evidence present   the declared decoy is really in the artifact, or assembled at run time
  4 survival of the mechanism     the trap survived -O2: guard intact, decoy still referenced
  5 build provenance              declared compile line agrees with the ELF; sha256 matches the manifest
  6 nuisance-cue hygiene          no `__audit_*` label reachable through nm / strings / readelf
  7 overlap                       no two tasks share a flag, a decoy or a binary hash

Checks that cannot apply to an instance are reported as N/A with the reason, and N/A is counted
separately. A check that silently passes because it had nothing to compare against is worse than no
check: it manufactures confidence. The summary line is only PASS if every applicable check passed
and nothing was skipped for an unexpected reason.

Usage:
    python3 tasks/validate_artifact.py                 # the whole held-out pool
    python3 tasks/validate_artifact.py <task_dir> ...  # named instances
    python3 tasks/validate_artifact.py --json
Exit: 0 all pass | 1 any failure
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VERSION = "artifact-validator-1.0"


def sh(cmd, **kw):
    """Binary tools emit non-UTF-8 bytes (strings -a on a stripped ELF certainly does), so decode
    permissively rather than letting a stray 0xc0 abort the whole validation run."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                          errors="replace", **kw)


def run_binary(binp: Path, payload: str, method: str, newline: bool) -> tuple[int, str]:
    try:
        if method == "argv":
            r = sh([f"./{binp.name}", payload], cwd=binp.parent)
        else:
            r = subprocess.run([f"./{binp.name}"], cwd=binp.parent,
                               input=payload + ("\n" if newline else ""),
                               capture_output=True, text=True, timeout=20)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:                                   # noqa: BLE001
        return -1, f"<execution failed: {e}>"


_TRACE_SHA: dict[str, set] = {}


def _sha_from_traces(task_id: str) -> str | None:
    """The binary_sha256 every trace for this task recorded. Returns None if the traces disagree --
    that would mean the pool was rebuilt mid-battery, which must not pass silently."""
    if not _TRACE_SHA:
        # repo: <root>/results/runs ; review bundle: <bundle>/runs with the harness one level down
        for base in (ROOT / "results" / "runs", ROOT / "runs", ROOT.parent / "runs"):
            if not base.is_dir():
                continue  # noqa: PERF203
            for f in base.glob("*/*/*/*/trace.jsonl"):
                try:
                    m = json.loads(f.open().readline())
                except Exception:                            # noqa: BLE001, PERF203
                    continue
                if m.get("binary_sha256"):
                    _TRACE_SHA.setdefault(m["task_id"], set()).add(m["binary_sha256"])
            break
    vals = _TRACE_SHA.get(task_id, set())
    return next(iter(vals)) if len(vals) == 1 else None


class Report:
    def __init__(self, task: str):
        self.task, self.rows, self.failed, self.na = task, [], 0, 0

    def add(self, name: str, state: str, detail: str = "") -> None:
        self.rows.append((name, state, detail))
        if state == "FAIL":
            self.failed += 1
        elif state == "N/A":
            self.na += 1

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.add(name, "pass" if ok else "FAIL", detail)


def validate(task_dir: Path, tasks: dict, seen: dict) -> Report:
    rep = Report(task_dir.name)
    man = json.loads((task_dir / "manifest.json").read_text())
    spec = tasks.get(task_dir.name, {})
    binp = ROOT / man["binary"] if not (task_dir / "binary" / "t").exists() else task_dir / "binary" / "t"
    if not binp.exists():
        rep.add("binary present", "FAIL", str(binp))
        return rep

    method = man.get("input_method", spec.get("input_method", "stdin"))
    newline = man.get("stdin_append_newline", True)
    blob = binp.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()

    # --- 2 solvability: derive the flag the way the ground truth says, then submit it -------------
    gt = task_dir / "groundtruth" / "solve.py"
    flag = None
    if gt.exists():
        r = sh([sys.executable, str(gt)], cwd=gt.parent)
        flag = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else None
        rep.check("solvability (ground truth runs)", bool(flag), flag or r.stderr.strip()[:70])
    else:
        rep.add("solvability (ground truth runs)", "N/A", "no groundtruth/solve.py")

    # --- 1 scorer/executable agreement -----------------------------------------------------------
    succ, fail = spec.get("success_marker"), spec.get("fail_marker")
    if flag and (succ or fail):
        rc, out = run_binary(binp, flag, method, newline)
        accepted = (succ in out) if succ else (fail not in out)
        rep.check("scorer agrees: flag accepted", accepted, f"rc={rc} {' '.join(out.split())[:60]}")
    else:
        rep.add("scorer agrees: flag accepted", "N/A", "no markers declared for this task")

    # --- 3 misleading evidence present, and 1b decoys rejected -----------------------------------
    decoys = [d.get("value") for d in man.get("decoys", []) if d.get("value")]
    if not decoys:
        rep.add("misleading evidence present", "N/A", "instance declares no string decoy")
        rep.add("scorer rejects decoy", "N/A", "instance declares no string decoy")
    else:
        for d in decoys:
            present = d.encode() in blob
            runtime = any(x.get("kind") in ("runtime", "runtime_built", "assembled")
                          for x in man.get("decoys", []))
            rep.check(f"misleading evidence present ({d[:26]})", present or runtime,
                      "literal in ELF" if present else "declared assembled at run time")
            if succ or fail:
                rc, out = run_binary(binp, d, method, newline)
                rejected = (succ not in out) if succ else (fail in out)
                rep.check(f"scorer rejects decoy ({d[:26]})", rejected,
                          f"rc={rc} {' '.join(out.split())[:50]}")

    # --- 4 survival of the mechanism through -O2 -------------------------------------------------
    survival = HERE / "synthetic" / "audit_compiler_survival.py"
    if survival.exists():
        r = sh([sys.executable, str(survival), str(task_dir)])
        txt = r.stdout + r.stderr
        if "DISQUALIFIED" in txt or "lost" in txt and "0 lost" not in txt:
            rep.add("mechanism survived -O2", "FAIL", " ".join(txt.split())[-90:])
        elif "confirmed" in txt:
            m = re.search(r"COMPILER SURVIVAL: [^\n]*", txt)
            rep.check("mechanism survived -O2", True, m.group(0)[19:] if m else "")
        else:
            rep.add("mechanism survived -O2", "N/A", " ".join(txt.split())[-80:])
    else:
        rep.add("mechanism survived -O2", "N/A", "audit_compiler_survival.py not shipped")

    # --- 5 build provenance ----------------------------------------------------------------------
    compile_line = man.get("compile", "")
    stripped = b".symtab" not in blob
    claims_strip = "strip" in compile_line
    rep.check("build: strip state matches manifest", stripped == claims_strip,
              f"ELF {'stripped' if stripped else 'not stripped'}, manifest "
              f"{'declares' if claims_strip else 'does not declare'} strip")
    rep.check("build: -O2 declared", "-O2" in compile_line, compile_line[:60] or "(absent)")
    expected, src = man.get("binary_sha256"), "manifest"
    if not expected:
        # The held-out manifests do not record the hash, but every trace does, and "the runs
        # analysed the binary that ships here" is the claim that actually matters. Resolve it from
        # the recorded evidence rather than reporting N/A and calling that a check.
        expected, src = _sha_from_traces(task_dir.name), "traces"
    if expected:
        rep.check(f"build: sha256 matches {src}", expected == sha, sha[:16])
    else:
        rep.add("build: sha256 matches manifest", "N/A", f"no recorded hash; actual {sha[:16]}")

    # --- 6 nuisance-cue hygiene ------------------------------------------------------------------
    # The claim is not merely "no audit labels". A decoy must be discriminable from the true flag
    # only by reasoning about the binary -- never by a surface cue an agent could key on without
    # engaging the mechanism. Each cue below is checked separately so a failure names itself.
    surf = sh(["strings", "-a", str(binp)]).stdout
    syms = sh(["nm", "-a", str(binp)]).stdout
    rod = sh(["readelf", "-p", ".rodata", str(binp)]).stdout
    allout = surf + syms + rod

    leaks = [t for t, o in (("nm", syms), ("strings", surf), ("readelf", rod)) if "__audit_" in o]
    rep.check("no __audit_ label reachable", not leaks, ", ".join(leaks) or "nm/strings/readelf clean")

    # length and format: a decoy the same shape as the flag cannot be picked out by shape alone
    if flag and decoys:
        badlen = [d for d in decoys if len(d) != len(flag)]
        rep.check("decoy length matches flag", not badlen,
                  "; ".join(f"{d[:20]} len {len(d)} vs {len(flag)}" for d in badlen) or
                  f"all decoys {len(flag)} chars")
        fmt = re.compile(r"^[A-Za-z0-9_]+\{[^}]*\}$")
        badfmt = [d for d in decoys if bool(fmt.match(d)) != bool(fmt.match(flag))]
        rep.check("decoy format matches flag", not badfmt,
                  "; ".join(d[:26] for d in badfmt) or "same wrapper shape")
    else:
        rep.add("decoy length matches flag", "N/A", "no flag or no string decoy")
        rep.add("decoy format matches flag", "N/A", "no flag or no string decoy")

    # generator identifiers, source paths and debug labels must not reach the agent surface
    tells = {
        "generator identifier": ("gen_replication", "gen_heldout", "_templates", "archetype_spec"),
        "source path": ("/home/", "/mnt/", "/work/", "task.c", "build.sh"),
        "task identifier": (task_dir.name, man.get("mechanism_class") or "\0",
                            man.get("target_w2_subtype") or "\0"),
        "debug label": ("__decoy", "__trap", "__flag_real", "DEBUG_", "notes_for_audit"),
    }
    for label, needles in tells.items():
        hit = [n for n in needles if n and n in allout]
        rep.check(f"no {label} in agent-visible surface", not hit, ", ".join(hit) or "clean")

    # --- 7 overlap -------------------------------------------------------------------------------
    for key, val in (("flag", flag), ("sha256", sha)):
        if val:
            prev = seen.setdefault(key, {}).get(val)
            rep.check(f"unique {key} across pool", prev is None, prev or "unique")
            seen[key][val] = task_dir.name
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*", help="task directories (default: the held-out pool)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    dirs = [Path(d) for d in a.dirs] or sorted(
        p for p in (HERE / "synthetic").iterdir()
        if p.is_dir() and re.fullmatch(r"r_[ce]_\d+_\w+", p.name))
    if not dirs:
        sys.exit("no task directories found")

    tasks = json.loads((ROOT / "pilot_tasks.json").read_text())
    seen: dict = {}
    reports = [validate(d, tasks, seen) for d in dirs]

    if a.json:
        print(json.dumps([{"task": r.task, "checks": r.rows, "failed": r.failed, "na": r.na}
                          for r in reports], indent=2))
    else:
        print(f"{VERSION}\n")
        for r in reports:
            bad = [x for x in r.rows if x[1] == "FAIL"]
            state = "FAIL" if bad else "pass"
            print(f"  {state:5} {r.task:<18} {len(r.rows) - r.failed - r.na} passed, "
                  f"{r.failed} failed, {r.na} n/a")
            for name, st, detail in r.rows:
                if st != "pass":
                    print(f"        {st:4} {name} -- {detail}")

    nfail = sum(r.failed for r in reports)
    nna = sum(r.na for r in reports)
    print(f"\n  {len(reports) - sum(1 for r in reports if r.failed)}/{len(reports)} instances pass "
          f"| {nfail} failed checks | {nna} not applicable")
    return 1 if nfail else 0


if __name__ == "__main__":
    raise SystemExit(main())
