#!/usr/bin/env python3
"""Pilot-zero runner -- run A0/A1/A2 on a verified task, persist the trace.

NOT a registered result. Exploratory smoke run: harness validation + a demo for
the supervisor. Run from the repo root INSIDE the rerag-re container so the shell
tools reach the RE toolchain (radare2/gdb/angr/...).

Examples:
    python run_pilot.py --task ovl_11_jormugandr --arm A0
    python run_pilot.py --task ovl_11_jormugandr --arm all --attempts 1

Reads the API key + model from .env (ANTHROPIC_API_KEY, PILOT_MODEL) and per-task
run-params from pilot_tasks.json. Cards (A1/A2) come from the registered frozen library
cards/cards_v1.0.json (drift-guarded via retrieval_lock.json); override with --cards.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent

from agent.config import RunConfig
from agent.loop import AgentLoop
from agent.policy import ClaudePolicy
from agent.retrieval import load_cards
from agent.scaffold import LedgerScaffold
from agent.provenance import ArtifactIndex
from agent.state import Arm
from agent.submit import BinaryOracle, SubmissionController
from agent.tools.registry import ToolRegistry
from agent.tools.shell import ShellTool
from agent.tools.run_binary import RunBinaryTool
from agent.tools.registry import llm_tool_specs


# Values that are obviously not real credentials. `docker run -e ANTHROPIC_API_KEY="sk-..."` copied
# from a runbook sets the variable to a literal placeholder, and because the loader used
# os.environ.setdefault() the placeholder WON over the real key in .env -- the run then died at step
# 0 with an auth error and the key had to be exported by hand every session. A placeholder is not a
# configured value, so .env is allowed to replace it. A genuinely set variable still wins.
_PLACEHOLDERS = {"", "sk-...", "sk-ant-...", "<key>", "changeme", "your-key-here",
                 "unset", "UNSET", "TODO", "xxx"}


def _looks_unset(v: str | None) -> bool:
    if v is None:
        return True
    t = v.strip().strip('"').strip("'")
    return t in _PLACEHOLDERS or t.endswith("...")


def _load_env(path: str = ".env") -> None:
    """Load .env. Real environment values win; placeholders and empty values do not.

    Every key in the file is loaded, not just the API key -- RERAG_IMAGE_DIGEST belongs here too, so
    the environment pin stops depending on remembering an -e flag at docker run time.
    """
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if _looks_unset(os.environ.get(k)):
            os.environ[k] = v


def _card_diff_map(cards) -> dict:
    """card_id -> requires_differential. The scaffold enforces a differential when a card
    cited on the current hypothesis demands one (e.g. silent_validation_failure)."""
    return {c.card_id: bool(c.requires_differential) for c in cards}


def _stage_binary(binary_path: str) -> tuple[str, str, str, str]:
    """Two-copy staging (experiment integrity).

    ANALYSIS copy: <analysis_ws>/target, read-only (0555), shown to the agent as ./target and used by
    the inspection tools (ShellTool cwd=analysis_ws). PRISTINE copy: <pristine_dir>/target in a SEPARATE
    tempdir that is never shown to the agent; RunBinaryTool and BinaryOracle run THIS copy under a
    per-run SHA check. So even if the agent patches or replaces its analysis copy, execution and SCORING
    use the untouched binary, and tampering is caught.

    IMPORTANT (not a security boundary): the pristine dir is a sibling under the tmp root and IS
    discoverable from the analysis workspace (e.g. glob('../rerag_pristine_*/target')). The SHA check
    stops a scoring swap, but an agent with real code execution could still read/delete the pristine
    copy, attempt a TOCTOU between the check and exec, or spawn a background process. Closing that needs
    the deployment boundary -- the trusted-validator container / separate PID+mount namespace with the
    pristine path NOT mounted into the analysis sandbox, and a fresh executable copy per call. This
    two-copy staging is the in-process approximation of that, not a replacement for it.

    Returns (analysis_ws, pristine_dir, pristine_target, expected_sha256).
    """
    expected = hashlib.sha256(Path(binary_path).read_bytes()).hexdigest()
    analysis_ws = tempfile.mkdtemp(prefix="rerag_analysis_")
    a_target = Path(analysis_ws) / "target"
    shutil.copy2(binary_path, a_target)
    os.chmod(a_target, 0o555)
    pristine_dir = tempfile.mkdtemp(prefix="rerag_pristine_")
    p_target = str(Path(pristine_dir) / "target")
    shutil.copy2(binary_path, p_target)
    os.chmod(p_target, 0o555)
    return analysis_ws, pristine_dir, p_target, expected


def _sha_file(p) -> str:
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except Exception:
        return ""


def _git_commit() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO),
                           capture_output=True, text=True, timeout=5)
        return (r.stdout or "").strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _runtime_env() -> dict:
    """#8: the ACTUAL runtime environment (computed), separate from the binary build toolchain."""
    import platform
    def _first_line(argv):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            out = (r.stdout or r.stderr or "")
            return out.splitlines()[0].strip() if (r.returncode == 0 and out) else ""
        except Exception:
            return ""
    return {"platform": platform.platform(), "python": platform.python_version(),
            "gcc": _first_line(["gcc", "--version"]), "uname": " ".join(platform.uname())}


def _build_run_meta(*, model, cfg, binary, cards_path, im, markers,
                    system_text, tool_specs, per_call_max_tokens) -> dict:
    """#13: reproducibility-grade provenance so a trace ties to an exact configuration."""
    def _read_json(rel):
        try:
            return json.loads((REPO / rel).read_text())
        except Exception:
            return {}
    lk = _read_json("retrieval_lock.json")
    pool = _read_json("tasks/synthetic/pool_manifest_v0.1.json")
    marker_cfg = json.dumps({"input_method": im, "success_marker": markers.get("success_marker"),
                             "fail_marker": markers.get("fail_marker")}, sort_keys=True)
    tool_specs_json = json.dumps(tool_specs, sort_keys=True, default=str)  # ACTUAL policy.tools (post _anthropic_tools)
    kf = markers.get("known_flag")
    return {
        "model": model,
        "binary_sha256": _sha_file(binary),
        "card_library_path": str(cards_path),
        "card_library_sha256": _sha_file(cards_path),
        "pool_hash_sha256": pool.get("pool_hash_sha256", ""),
        "retrieval_algorithm_version": lk.get("retrieval_algorithm_version", ""),
        "retrieval_py_sha256": lk.get("retrieval_py_sha256", ""),
        "retrieval_policy_version": lk.get("retrieval_policy_version", ""),
        "retrieval_policy_method_sha256": lk.get("retrieval_policy_method_sha256", ""),
        "scaffold_strictness": cfg.scaffold_strictness if cfg.arm == Arm.A2 else None,
        "differential_trigger": cfg.differential_trigger if cfg.arm == Arm.A2 else None,
        "max_steps": cfg.max_steps,
        "max_total_tokens": cfg.max_total_tokens,
        "per_call_max_tokens": per_call_max_tokens,
        "shell_timeout_s": cfg.shell_timeout_s,
        "run_binary_timeout_s": cfg.run_binary_timeout_s,
        "oracle_timeout_s": cfg.oracle_timeout_s,
        "api_retry_count": cfg.api_retry_count,
        "api_retry_backoff_s": cfg.api_retry_backoff_s,
        "max_tool_output_bytes": cfg.max_tool_output_bytes,
        "marker_config_sha256": hashlib.sha256(marker_cfg.encode("utf-8")).hexdigest(),
        "known_flag_sha256": hashlib.sha256(kf.encode("utf-8")).hexdigest() if kf else "",
        "system_prompt_sha256": hashlib.sha256((system_text or "").encode("utf-8")).hexdigest(),
        "tool_specs_sha256": hashlib.sha256(tool_specs_json.encode("utf-8")).hexdigest(),
        "full_prompt_surface_sha256": hashlib.sha256(((system_text or "") + tool_specs_json).encode("utf-8")).hexdigest(),
        "git_commit": _git_commit(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        # Per-task, from the instance manifest. This used to fall back to a pool-level constant
        # from pilot_tasks.json that hard-coded -O0, which is the development pool's build line;
        # the held-out instances are -O2 (12 of them additionally strip --strip-all). The stale
        # constant is visible in every recorded trace -- see docs/ARTIFACT_NOTES.md. The manifest
        # and binary_sha256 are, and always were, the authoritative build provenance.
        "binary_build_toolchain": _task_compile_line(spec) or pool.get("_toolchain"),
        "runtime_environment": _runtime_env(),
    }


def run_one(task: str, arm: Arm, params: dict, model: str, attempts: int, cards_path: str,
            run_over: dict | None = None, allow_drift: bool = False, tasks_file: str = "pilot_tasks.json",
            unsandboxed: bool = False) -> None:
    run_over = dict(run_over or {})
    binary = params["binary"]
    if not Path(binary).exists():
        print(f"[{task}/{arm}] SKIP -- binary not found: {binary}")
        return
    # #9: fail-closed lock preflight -- the trace's locked SHAs must MATCH the actual code/data, not
    # merely be copied from the lock file. Verify once per run; a registered run aborts on any drift.
    from agent.preflight import LOCK_NAME, format_report, verify_locks
    pf_ok, pf_report, _ = verify_locks(REPO, cards_path, tasks_file)
    if not pf_ok:
        rep = format_report(pf_report)
        if not allow_drift:
            sys.exit(f"[{task}/{arm}] PREFLIGHT FAILED -- code/data drifted from {LOCK_NAME}:\n{rep}\n"
                     "-> re-run the test suites, then `python -m agent.preflight --regenerate` (only if the "
                     "change was intended), or pass --allow-drift for an exploratory (non-registered) run")
        print(f"[{task}/{arm}] WARNING (--allow-drift): preflight drift (NOT registered-grade):\n{rep}")
    # #15: environment / toolchain pin -- a registered run may only proceed in the pinned image.
    from agent.pin_environment import LOCK_NAME as ENV_LOCK, format_drift, verify as verify_env
    env_ok, env_drift = verify_env(REPO)
    if not env_ok:
        rep = format_drift(env_drift)
        if not allow_drift:
            sys.exit(f"[{task}/{arm}] ENVIRONMENT PIN drift ({ENV_LOCK}):\n{rep}\n"
                     "-> in the rerag-re image run `python -m agent.pin_environment --regenerate` (verify "
                     "the versions first), or pass --allow-drift for an exploratory (non-registered) run")
        print(f"[{task}/{arm}] WARNING (--allow-drift): environment drift:\n{rep}")

    im = params.get("input_method", "stdin")
    sanl = bool(params.get("stdin_append_newline", True))  # stdin framing (recorded + anchored)
    markers = dict(success_marker=params.get("success_marker"),
                   fail_marker=params.get("fail_marker"), known_flag=params.get("known_flag"))
    cards = load_cards(cards_path) if arm in (Arm.A1, Arm.A2) else []
    # Sandboxed execution backend: bubblewrap for registered runs (fail-closed if bwrap absent), or the
    # explicit unsandboxed local backend for exploratory runs only. NEVER an automatic fallback.
    from agent.execution import BwrapExecutionBackend, LocalExecutionBackend
    backend = (LocalExecutionBackend(allow_unsandboxed=True) if unsandboxed else BwrapExecutionBackend())
    # #3 isolation: verify the sandbox ACTUALLY isolates on THIS machine before any registered run.
    bwrap_ver = ""
    integ_meta = {"integration_selftest_ok": None, "integration_report_sha256": "",
                  "integration_image_digest": "", "integration_runtime_code_sha256": "",
                  "integration_executed_at": ""}
    if not unsandboxed:
        from agent.isolation import format_selftest, isolation_selftest
        bwrap_ver = backend.bwrap_version()
        iso_ok, iso_report = isolation_selftest(backend, repo_path=REPO)
        print(f"[{task}] {format_selftest(iso_report)} (bwrap {bwrap_ver})")
        if not iso_ok:
            sys.exit("-> the sandbox does not isolate on this machine (fix bwrap / user namespaces / "
                     "network egress), or pass --unsandboxed for an exploratory (non-registered) run")
        # #4: an integration self-test report must exist, have PASSED, and match THIS runtime + image.
        import hashlib as _hl
        from agent.pin_environment import _image_digest
        rep_path = REPO / "integration_report.json"
        cur_runtime = ""
        try:
            from agent.preflight import compute_actual_locks
            cur_runtime = compute_actual_locks(REPO).get("runtime_code_sha256", "")
        except Exception:  # noqa: BLE001
            pass
        if not rep_path.exists():
            if not allow_drift:
                sys.exit(f"-> no integration_report.json; run `python -m agent.integration_selftest "
                         f"--json {rep_path.name}` in the image (must PASS), or use --allow-drift")
        else:
            from agent.integration_selftest import validate_report
            rep = json.loads(rep_path.read_text())
            cur_env_sha = (_hl.sha256((REPO / "environment_lock.json").read_bytes()).hexdigest()
                           if (REPO / "environment_lock.json").exists() else "")
            valid, why = validate_report(rep)   # structure + completeness + every check passed
            stale = (rep.get("runtime_code_sha256") != cur_runtime
                     or rep.get("image_digest") != _image_digest()
                     or rep.get("environment_lock_sha256") != cur_env_sha)
            if (not valid) or stale:
                if not allow_drift:
                    sys.exit(f"-> integration_report.json rejected "
                             f"({why if not valid else 'stale: runtime/image/environment mismatch'}); re-run "
                             f"`python -m agent.integration_selftest --json integration_report.json` in the image")
            integ_meta = {
                "integration_selftest_ok": bool(rep.get("ok")),
                "integration_report_sha256": _hl.sha256(rep_path.read_bytes()).hexdigest(),
                "integration_image_digest": rep.get("image_digest", ""),
                "integration_runtime_code_sha256": rep.get("runtime_code_sha256", ""),
                "integration_executed_at": rep.get("executed_at", ""),
            }
    else:
        print(f"[{task}] WARNING: --unsandboxed -> NO isolation (exploratory only, never registered)")
    for i in range(attempts):
        attempt_id = f"a{i + 1}"
        # Sandbox model: the agent references the binary only as {TARGET} (bound ro at /work/target).
        # A FRESH EMPTY scratch is mounted rw at /work/scratch -- it deliberately does NOT contain a
        # second target copy, so there is exactly one analysis target and no ./target-vs-{TARGET} ambiguity.
        # run_binary/oracle execute a fresh SHA-checked PRISTINE copy per call.
        _ws_unused, pdir, ptarget, exp_sha = _stage_binary(binary)
        scratch = tempfile.mkdtemp(prefix="rerag_scratch_")
        try:
            cfg = RunConfig(arm=arm, task_id=task, attempt_id=attempt_id, binary_path="{TARGET}", **run_over)
            pcmt = cfg.per_call_max_tokens
            # oracle + run_binary execute the PRISTINE copy (integrity-guarded); NOT given known_flag to run_binary.
            oracle = BinaryOracle(backend=backend, binary_path=ptarget, input_method=im,
                                  timeout_s=cfg.oracle_timeout_s, expected_sha256=exp_sha,
                                  stdin_append_newline=sanl, **markers)
            # Provenance layer reads the PRISTINE staged copy once (same bytes the oracle runs).
            _artifact = ArtifactIndex.from_path(ptarget, sha256=exp_sha)
            scaffold = (LedgerScaffold(strictness=cfg.scaffold_strictness,
                                       differential_trigger=cfg.differential_trigger,
                                       cards=_card_diff_map(cards),
                                       require_terminality=True,
                                       require_reachability=True,
                                       artifact=_artifact) if arm == Arm.A2 else None)
            controller = SubmissionController(oracle, scaffold=scaffold)
            runner = RunBinaryTool(backend=backend, binary_path=ptarget, default_input_method=im,
                                   success_marker=markers["success_marker"], fail_marker=markers["fail_marker"],
                                   timeout_s=cfg.run_binary_timeout_s, expected_sha256=exp_sha,
                                   max_output_bytes=cfg.max_tool_output_bytes, stdin_append_newline=sanl)
            # ShellTool runs via the sandbox (analysis profile): target ro at /work/target, the
            # analysis workspace rw at /work/scratch. python3/angr run INSIDE the sandbox.
            from agent.tools.trace_binary import TraceBinaryTool
            tracer = TraceBinaryTool(backend=backend, binary_path=ptarget, default_input_method=im,
                                     timeout_s=cfg.run_binary_timeout_s, expected_sha256=exp_sha,
                                     max_output_bytes=cfg.max_tool_output_bytes, stdin_append_newline=sanl)
            registry = ToolRegistry(
                shell=ShellTool(backend=backend, target_host_path=ptarget, scratch_host_path=scratch,
                                timeout_s=cfg.shell_timeout_s, max_output_bytes=cfg.max_tool_output_bytes),
                controller=controller, runner=runner, tracer=tracer)
            # Agent references the binary as {TARGET} everywhere (system prompt + this message agree).
            # Provider selection. Default is unchanged, so every existing invocation keeps producing
            # exactly what it produced before; only an explicit --policy openai takes the other path.
            _pol_cls = ClaudePolicy
            _pol_kw = {}
            if str(globals().get("_POLICY_KIND", "claude")).lower() == "openai":
                from agent.policy_openai import OpenAIPolicy
                _pol_cls = OpenAIPolicy
                if globals().get("_POLICY_BASE_URL"):
                    _pol_kw["base_url"] = globals()["_POLICY_BASE_URL"]
                if globals().get("_POLICY_EFFORT"):
                    _pol_kw["reasoning_effort"] = globals()["_POLICY_EFFORT"]
            policy = _pol_cls(arm=arm, binary_path="{TARGET}", model=model, cards=cards,
                              max_tokens=pcmt, retry_count=cfg.api_retry_count,
                              retry_backoff_s=cfg.api_retry_backoff_s,
                              scaffold_strictness=cfg.scaffold_strictness,
                              differential_trigger=cfg.differential_trigger, **_pol_kw)
            # Provider and reasoning level belong in the trace: a run must say which model family
            # produced it without anyone having to remember the command line.
            meta = _build_run_meta(model=model, cfg=cfg, binary=binary, cards_path=cards_path,
                                   im=im, markers=markers, system_text=policy.system_text,
                                   tool_specs=policy.tools, per_call_max_tokens=pcmt)
            meta["provider"] = globals().get("_POLICY_KIND", "claude")
            meta["reasoning_effort"] = globals().get("_POLICY_EFFORT")
            meta["preflight_ok"] = pf_ok  # #9: True = code/data matched the lock at run time
            # PROVENANCE: --allow-drift downgrades a run from registered to exploratory by skipping a
            # fail-closed gate. Printing that to the console is not enough -- the trace is what gets
            # analysed months later, and a run that bypassed a gate must say so in its own record.
            meta["allow_drift"] = bool(allow_drift)
            meta["registered_grade"] = bool(pf_ok and not allow_drift and not unsandboxed)
            meta["stdin_append_newline"] = sanl
            meta["sandbox"] = "local-unsandboxed" if unsandboxed else "bwrap"
            meta["bwrap_version"] = bwrap_ver
            meta["isolation_selftest_ok"] = (None if unsandboxed else True)  # True: passed (else we exited)
            import hashlib as _hl
            _envp = REPO / "environment_lock.json"
            meta["environment_lock_sha256"] = (_hl.sha256(_envp.read_bytes()).hexdigest()
                                               if _envp.exists() else "")
            meta.update(integ_meta)  # #4: integration self-test provenance (ok + report/image/runtime SHAs)
            try:
                state = AgentLoop(cfg, policy, registry, run_meta=meta).run()
            except FileExistsError as e:
                print(f"[{task}/{arm}/{attempt_id}] SKIP -- {e}")
                continue
            print(
                f"[{task}/{arm}/{attempt_id}] {state.termination_reason} "
                f"steps={len(state.steps)} subs={len(state.submissions)} "
                f"blocked={len(state.blocked_submissions)} "
                f"budget_tok={state.tokens.budget_tokens} processed_tok={state.tokens.processed_tokens} "
                f"-> {cfg.trace_path()}"
            )
        finally:
            shutil.rmtree(_ws_unused, ignore_errors=True)
            shutil.rmtree(pdir, ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)



def _task_compile_line(spec: dict) -> str | None:
    """The compile line this task's own manifest declares, or None if it has no manifest."""
    try:
        b = Path(spec["binary"])
        for cand in (b.parent.parent / "manifest.json", b.parent / "manifest.json"):
            if cand.is_file():
                return json.loads(cand.read_text()).get("compile")
    except Exception:                                        # noqa: BLE001
        return None
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--arm", default="A0", help="A0 | A1 | A2 | all")
    ap.add_argument("--attempts", type=int, default=1)
    ap.add_argument("--tasks-file", default="pilot_tasks.json")
    ap.add_argument("--cards", default="cards/cards_v1.0.json")
    ap.add_argument("--strictness", type=int, default=None, choices=[1, 2, 3],
                    help="A2 scaffold strictness (1|2|3); default from config")
    ap.add_argument("--differential-trigger", default=None, choices=["cited", "retrieved", "always"],
                    help="A2 differential trigger; default from config (cited)")
    # #15: run-parameter surface (calibration = config, not code). CLI flags win over --run-config.
    ap.add_argument("--run-config", default=None, help="JSON file with RunConfig overrides")
    ap.add_argument("--runs-dir", default=None)
    ap.add_argument("--policy", default="claude", choices=["claude", "openai"],
                    help="model family. 'openai' also serves any OpenAI-compatible endpoint")
    ap.add_argument("--base-url", default=None,
                    help="base URL for an OpenAI-compatible server (vLLM, SGLang); ignored otherwise")
    ap.add_argument("--reasoning-effort", default=None,
                    choices=["none", "minimal", "low", "medium", "high", "xhigh", "max"],
                    help="pin the reasoning level explicitly (openai policy). Leaving it to the "
                         "model default is a silent confound between series. NOTE: the accepted "
                         "levels differ by model family -- gpt-5.2 takes none|medium|high|xhigh and "
                         "rejects 'low', so an invalid level fails the request rather than being "
                         "silently ignored.")
    ap.add_argument("--max-steps", type=int, default=None)
    ap.add_argument("--max-total-tokens", type=int, default=None)
    ap.add_argument("--shell-timeout", type=int, default=None, help="per-tool timeout (s)")
    ap.add_argument("--per-call-max-tokens", type=int, default=None, help="model max_tokens per call")
    ap.add_argument("--overwrite", action="store_true",
                    help="overwrite an existing trace (default: fail closed)")
    ap.add_argument("--allow-drift", action="store_true",
                    help="downgrade preflight lock DRIFT from fatal to a warning (exploratory runs only)")
    ap.add_argument("--unsandboxed", action="store_true",
                    help="use the local (no-namespace) execution backend -- EXPLORATORY ONLY, never registered")
    args = ap.parse_args()

    _load_env()
    # The argparse namespace is `args` here, not `a`; and the key check must follow the SELECTED
    # provider. Gating on ANTHROPIC_API_KEY unconditionally made an OpenAI-only run demand a Claude
    # key it never uses.
    globals()["_POLICY_KIND"] = args.policy
    globals()["_POLICY_BASE_URL"] = args.base_url
    globals()["_POLICY_EFFORT"] = args.reasoning_effort
    if args.policy == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY not set -- put it in .env")
    if args.policy == "openai" and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set -- put it in .env alongside PILOT_MODEL")
    model = os.environ.get("PILOT_MODEL")
    if not model:
        sys.exit("PILOT_MODEL not set -- put it in .env (e.g. PILOT_MODEL=claude-sonnet-4-5)")

    # RunConfig overrides: --run-config file first, then explicit CLI flags (CLI wins). Only the
    # config knobs are accepted -- run-identity fields (arm/task_id/attempt_id/binary_path) are set per run.
    _ALLOWED = {"runs_dir", "max_steps", "max_total_tokens", "shell_timeout_s",
                "max_tool_output_bytes", "run_binary_timeout_s", "oracle_timeout_s",
                "per_call_max_tokens", "api_retry_count", "api_retry_backoff_s",
                "scaffold_strictness", "differential_trigger", "overwrite"}
    run_over: dict = {}
    if args.run_config:
        raw = json.loads(Path(args.run_config).read_text(encoding="utf-8"))
        bad = set(raw) - _ALLOWED
        if bad:
            sys.exit(f"--run-config has non-override keys: {sorted(bad)}; allowed: {sorted(_ALLOWED)}")
        run_over.update(raw)
    for k, v in [("runs_dir", args.runs_dir), ("max_steps", args.max_steps),
                 ("max_total_tokens", args.max_total_tokens), ("shell_timeout_s", args.shell_timeout),
                 ("per_call_max_tokens", args.per_call_max_tokens),
                 ("scaffold_strictness", args.strictness), ("differential_trigger", args.differential_trigger)]:
        if v is not None:
            run_over[k] = v
    if args.overwrite:
        run_over["overwrite"] = True

    tasks = json.loads(Path(args.tasks_file).read_text(encoding="utf-8"))
    if args.task not in tasks:
        sys.exit(f"unknown task {args.task!r}; known: {[k for k in tasks if not k.startswith('_')]}")
    params = tasks[args.task]

    arms = [Arm.A0, Arm.A1, Arm.A2] if args.arm == "all" else [Arm(args.arm)]
    for arm in arms:
        run_one(args.task, arm, params, model, args.attempts, args.cards, run_over=run_over,
                allow_drift=args.allow_drift, tasks_file=args.tasks_file, unsandboxed=args.unsandboxed)


if __name__ == "__main__":
    main()
