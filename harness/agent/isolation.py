"""On-target isolation self-test (fail-closed).

Bubblewrap is a sandbox CONSTRUCTOR, not a policy: whether the sandbox actually isolates depends on the
argv we build AND on the host kernel (user-ns enabled? ptrace? seccomp?). Unit tests check the argv;
this checks the REAL boundary on the machine that will run the study, by executing a probe INSIDE the
sandbox that tries to break out and asserting every attempt fails:

  - network egress (connect out)                 -> must fail (--unshare-net)
  - read the orchestrator's env secret via /proc -> must fail (--unshare-pid + --clearenv)
  - reach the repo / groundtruth / .env / cards  -> must not exist (repo not mounted)
  - reach the pristine validator target copies   -> must not exist (separate namespace/tmp)

run_pilot runs this ONCE at startup for the bwrap backend and ABORTS if any probe succeeds -- no
registered run proceeds on a machine where isolation is incomplete. The unsandboxed local backend is
EXPECTED to fail this (it provides no isolation), so the self-test is skipped there with a warning.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from agent.execution import ExecutionRequest

CANARY_ENV = "RERAG_CANARY_SECRET"


def _probe_code(repo_path: str, groundtruth_path: str, canary: str) -> str:
    # Runs INSIDE the sandbox. Prints one JSON line: {"leaks": [...]} -- empty list == isolated.
    return (
        "import os, glob, json, socket\n"
        "leaks = []\n"
        "try:\n"
        "    s = socket.socket(); s.settimeout(1.5); s.connect(('1.1.1.1', 53)); s.close()\n"
        "    leaks.append('network_egress')\n"
        "except OSError:\n"
        "    pass\n"
        f"canary = {canary!r}\n"
        "try:\n"
        "    for pe in glob.glob('/proc/*/environ'):\n"
        "        try:\n"
        "            if canary.encode() in open(pe, 'rb').read():\n"
        "                leaks.append('proc_env_secret'); break\n"
        "        except OSError:\n"
        "            pass\n"
        "except OSError:\n"
        "    pass\n"
        f"for p in [{repo_path!r}, {groundtruth_path!r}, '/reverse_rag', '.env', 'pilot_tasks.json',\n"
        "          os.path.expanduser('~/.env')]:\n"
        "    try:\n"
        "        if p and os.path.exists(p):\n"
        "            leaks.append('path:' + p)\n"
        "    except OSError:\n"
        "        pass\n"
        "if glob.glob('/tmp/rerag_pristine_*') or glob.glob('../rerag_pristine_*/target'):\n"
        "    leaks.append('pristine_reachable')\n"
        "print(json.dumps({'leaks': sorted(set(leaks))}))\n"
    )


def isolation_selftest(backend, *, repo_path, timeout_s: float = 20.0):
    """Return (ok, report). ok is True only if the sandbox blocked EVERY probe. Fail-closed on any
    error / unparseable output / unsandboxed backend."""
    repo = Path(repo_path)
    gt = repo / "tasks" / "synthetic" / "t_d_05_silent_validation" / "groundtruth" / "solve.py"
    canary = "RERAG_ISO_" + secrets.token_hex(16)
    prev = os.environ.get(CANARY_ENV)
    os.environ[CANARY_ENV] = canary  # only in the ORCHESTRATOR env; the sandbox must not see it
    scratch = tempfile.mkdtemp(prefix="rerag_iso_")
    try:
        res = backend.execute(ExecutionRequest(
            argv=["python3", "-c", _probe_code(str(repo), str(gt), canary)],
            profile="analysis", scratch_host_path=scratch, timeout_s=timeout_s,
            max_output_bytes=65536))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if prev is None:
            os.environ.pop(CANARY_ENV, None)
        else:
            os.environ[CANARY_ENV] = prev

    if not res.sandbox_ok:
        return False, {"ok": False, "reason": "backend is not a real sandbox (sandbox_ok is False)",
                       "sandbox_profile": res.sandbox_profile}
    if res.error:
        return False, {"ok": False, "reason": f"probe failed to run: {res.error}"}
    line = (res.stdout or "").strip().splitlines()[-1:] or [""]
    try:
        leaks = json.loads(line[0]).get("leaks", ["<unparseable>"])
    except Exception:  # noqa: BLE001
        return False, {"ok": False, "reason": f"probe output unparseable: {res.stdout[:200]!r}"}
    return (len(leaks) == 0), {"ok": len(leaks) == 0, "leaks": leaks,
                               "sandbox_profile": res.sandbox_profile}


def format_selftest(report: dict) -> str:
    if report.get("ok"):
        return "isolation self-test PASSED -- sandbox blocked network / /proc-secret / repo / pristine"
    if "leaks" in report:
        return "isolation self-test FAILED -- sandbox LEAKED: " + ", ".join(report["leaks"])
    return "isolation self-test FAILED -- " + report.get("reason", "unknown")
