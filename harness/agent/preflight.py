"""Fail-closed lock preflight (#9).

run_pilot copies lock SHAs into the trace meta, but recording a value is not verifying it: change the
code, forget to re-run the tests, and the trace happily reports a stale locked SHA next to a run that
used different code. This module RECOMPUTES the reference SHAs from the source-of-truth files and
compares them to `preflight_lock.json`, so a registered run fails closed on any drift.

Covered surfaces (all recomputed from disk / live objects):
  cards_sha256                     bytes of cards_v1.0.json (frozen library)
  retrieval_py_sha256              bytes of agent/retrieval.py
  retrieval_policy_method_sha256   source of ClaudePolicy._retrieve_for_step (query/reinjection policy)
  pool_hash_sha256                 recomputed from the ACTUAL committed binaries (catches binary swap)
  task_metadata_sha256             recomputed from the PER-TASK manifests (catches taxonomy drift)
  tool_surface_sha256              the actual Anthropic tool schema (post _anthropic_tools)
  prompts_sha256                   system_common + delta_a1 + delta_a2 + scaffold_mode_note source

Usage:
  from agent.preflight import verify_locks
  ok, report, actual = verify_locks(repo_root, cards_path)          # verify
  python -m agent.preflight --regenerate                            # rewrite the lock after an intended change
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

LOCK_NAME = "preflight_lock.json"
_KEYS = ("cards_sha256", "retrieval_py_sha256", "retrieval_policy_method_sha256",
         "pool_hash_sha256", "task_metadata_sha256", "tool_surface_sha256", "prompts_sha256",
         "run_params_sha256", "execution_path_sha256", "sandbox_profile_sha256", "runtime_code_sha256")


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_actual_locks(repo, cards_path=None, tasks_file=None) -> dict:
    """Recompute every reference SHA from the current source-of-truth files / live objects."""
    repo = Path(repo)
    cards_path = Path(cards_path) if cards_path else repo / "cards" / "cards_v1.0.json"
    tasks_file = Path(tasks_file) if tasks_file else repo / "pilot_tasks.json"
    synth = repo / "tasks" / "synthetic"

    # imported lazily so this module is cheap to import and has no import cycle with policy
    from agent.policy import ClaudePolicy, _anthropic_tools
    from agent.tools.registry import llm_tool_specs
    import agent.prompting as prompting

    d: dict = {}
    d["cards_sha256"] = _sha_bytes(cards_path.read_bytes())
    d["retrieval_py_sha256"] = _sha_bytes((repo / "agent" / "retrieval.py").read_bytes())
    d["retrieval_policy_method_sha256"] = _sha_text(inspect.getsource(ClaudePolicy._retrieve_for_step))

    pm = json.loads((synth / "pool_manifest_v0.1.json").read_text(encoding="utf-8"))
    recomputed: list[tuple[str, str]] = []
    proj: list[dict] = []
    for e in pm["tasks"]:
        binp = synth / e["task_id"] / e["binary"]
        disk = _sha_bytes(binp.read_bytes()) if binp.exists() else "MISSING"
        recomputed.append((e["task_id"], disk))
        man = json.loads((synth / e["task_id"] / "manifest.json").read_text(encoding="utf-8"))
        proj.append({"task_id": e["task_id"], "archetype": man["archetype"],
                     "mechanism_variant": man.get("mechanism_variant"),
                     "template_group": man.get("template_group")})
    body = "\n".join(f"{t}:{s}" for t, s in sorted(recomputed))   # SAME formula as test_pool_lock
    d["pool_hash_sha256"] = _sha_text(body)
    proj.sort(key=lambda r: r["task_id"])
    d["task_metadata_sha256"] = _sha_text(json.dumps(proj, sort_keys=True, separators=(",", ":")))

    d["tool_surface_sha256"] = _sha_text(json.dumps(_anthropic_tools(llm_tool_specs()),
                                                    sort_keys=True, default=str))

    pd = repo / "agent" / "prompts"
    concat = "".join((pd / f).read_text(encoding="utf-8")
                     for f in ("system_common.txt", "delta_a1.txt", "delta_a2.txt"))
    concat += inspect.getsource(prompting.scaffold_mode_note)   # the A2 mode note is code, not a file
    d["prompts_sha256"] = _sha_text(concat)

    # run parameters (adjudication-affecting) -- pilot_tasks.json is not otherwise anchored, so a marker
    # or framing edit would change scoring while every other lock stayed green. known_flag is HASHED so
    # the lock never carries a plaintext flag.
    tasks = json.loads(tasks_file.read_text(encoding="utf-8"))
    rp: list[dict] = []
    for tid, e in tasks.items():
        if tid.startswith("_") or not isinstance(e, dict):
            continue
        kf = e.get("known_flag")
        binrel = e.get("binary", "")
        binp = repo / binrel
        bin_sha = _sha_bytes(binp.read_bytes()) if binrel and binp.exists() else "MISSING"
        rp.append({"task_id": tid, "binary": binrel, "binary_sha256": bin_sha,
                   "input_method": e.get("input_method"),
                   "success_marker": e.get("success_marker"), "fail_marker": e.get("fail_marker"),
                   "known_flag_sha256": _sha_text(kf) if kf else None,
                   "stdin_append_newline": bool(e.get("stdin_append_newline", True))})
    rp.sort(key=lambda r: r["task_id"])
    d["run_params_sha256"] = _sha_text(json.dumps(rp, sort_keys=True, separators=(",", ":")))

    # execution path (sandbox backend + the three tools that run subprocesses): a change here alters how
    # the target/tools are executed and must fail closed like any other locked surface.
    exec_files = ("agent/execution.py", "agent/tools/shell.py", "agent/tools/run_binary.py", "agent/submit.py")
    d["execution_path_sha256"] = _sha_bytes(b"".join((repo / f).read_bytes() for f in exec_files))

    # sandbox POLICY: the bwrap argv builder + resource profiles + runtime roots + the isolation probe.
    # A change to how the sandbox is constructed must fail closed like any other locked surface.
    from agent.execution import (ANALYSIS_RLIMITS, VALIDATOR_RLIMITS, _RUNTIME_ROOTS, FORBIDDEN_MOUNTS,
                                 BwrapExecutionBackend)
    import agent.isolation as _iso
    policy_src = (inspect.getsource(BwrapExecutionBackend.build_argv)
                  + inspect.getsource(_iso._probe_code)
                  + repr(sorted((int(k), v) for k, v in ANALYSIS_RLIMITS.items()))
                  + repr(sorted((int(k), v) for k, v in VALIDATOR_RLIMITS.items()))
                  + repr(_RUNTIME_ROOTS) + repr(FORBIDDEN_MOUNTS))
    d["sandbox_profile_sha256"] = _sha_text(policy_src)

    # broad runtime-code anchor: execution_path_sha256 covers only 4 files, so a change to scaffold /
    # trace_binary / loop / policy / registry / adjudicate / isolation would otherwise pass preflight.
    # This hashes EVERY run-affecting source file -> fail-closed on any of them.
    runtime_files = ["run_pilot.py", "agent/config.py", "agent/state.py", "agent/loop.py",
                     "agent/policy.py", "agent/policy_openai.py", "agent/prompting.py", "agent/retrieval.py", "agent/adjudicate.py",
                     "agent/scaffold.py", "agent/submit.py", "agent/execution.py", "agent/isolation.py",
                     "agent/preflight.py", "agent/pin_environment.py", "agent/integration_selftest.py"]
    runtime_files += sorted(str(p.relative_to(repo)) for p in (repo / "agent" / "tools").glob("*.py")
                            if p.name != "__init__.py")
    blob = b""
    for f in runtime_files:
        fp = repo / f
        if fp.exists():
            blob += f.encode() + b"\0" + fp.read_bytes() + b"\0"
    d["runtime_code_sha256"] = _sha_bytes(blob)
    return d


def load_lock(repo) -> dict:
    return json.loads((Path(repo) / LOCK_NAME).read_text(encoding="utf-8"))


def verify_locks(repo, cards_path=None, tasks_file=None, lock=None):
    """Return (ok, report, actual). report = list of (name, ok, expected, actual)."""
    actual = compute_actual_locks(repo, cards_path, tasks_file)
    lk = lock if lock is not None else load_lock(repo)
    report = [(k, lk.get(k) == actual[k], lk.get(k), actual[k]) for k in _KEYS]
    missing = [k for k in _KEYS if k not in lk]
    ok = all(r[1] for r in report) and not missing
    return ok, report, actual


def format_report(report) -> str:
    return "\n".join(
        f"  {'ok   ' if o else 'DRIFT'}  {k}: expected {str(e)[:12]}... got {str(a)[:12]}..."
        for k, o, e, a in report)


def regenerate(repo, cards_path=None, tasks_file=None) -> dict:
    repo = Path(repo)
    d = compute_actual_locks(repo, cards_path, tasks_file)
    out = {"_note": ("Fail-closed preflight reference SHAs (see agent/preflight.py). Regenerate ONLY "
                     "after an intended change to cards/retrieval/policy/pool/taxonomy/tool-surface/"
                     "prompts, then re-run the test suites and commit."), **d}
    (repo / LOCK_NAME).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true", help="rewrite preflight_lock.json from current state")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()
    if args.regenerate:
        d = regenerate(args.repo)
        print(f"wrote {LOCK_NAME}:")
        for k in _KEYS:
            print(f"  {k}: {d[k][:16]}...")
    else:
        ok, report, _ = verify_locks(args.repo)
        print(format_report(report))
        print("PREFLIGHT: " + ("OK" if ok else "DRIFT"))
        raise SystemExit(0 if ok else 1)
