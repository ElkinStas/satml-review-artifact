#!/usr/bin/env python3
"""Compute primary, manipulation-check, and secondary metrics from run traces (+ W2 labels).

Inputs:
    --runs-glob   trace JSONL files          (default: runs/**/trace.jsonl)
    --labels-glob machine-readable W2 labels  (default: annotation/manual_labels/*.json)
    --tasks-file  run-param/task file         (default: pilot_tasks.json)
    --out         output dir                  (default: analysis/tables)

Outputs (CSV, per arm; primary/per_task also split by {synthetic, real} subset):
    primary.csv       W2_event_rate, decoy_accepted_rate, unverified_submission_rate,
                      success@1, success@3
    manipulation.csv  family_match_relevance (MC1), scaffold_enforcement_correctness (MC2,
                      RUN-LEVEL audit; see note), token_budget_exhaustion_rate (MC3 = share of
                      attempts terminating on max_tokens, evaluated on the budget_tokens basis)

MC2 has two distinct senses; this table reports only the second:
  - software-integration MC2 (the controller LOGIC is correct) -> covered by the synthetic CI /
    controller tests (tasks/synthetic/ci_smoke_*.py), NOT this table;
  - run-level MC2 audit (each submit/block DECISION in an A2 trace was correct: accepted iff an
    accepting run on the exact candidate existed) -> the MC2 column here. It is NA when the A2
    traces contain no submit/block decisions (MC2_n_submit_decisions == 0).
    secondary.csv     decompiler_artifact_trust_rate, comprehend_time_fixation_rate
                      (registered SECONDARY, reported separately from canonical W2),
                      blocked_submission_count, ledger_completeness_rate, card_citation_rate,
                      card_ignored_rate, invalid_validation_rate, time_to_solve_steps,
                      tool_calls_per_attempt
    per_task.csv      tidy task x arm rows (input to bootstrap_ci.py)

Trace-derived metrics are computed directly; label-derived metrics (W2_event_rate, the
per-subtype rates, decompiler_artifact_trust_rate, comprehend_time_fixation_rate) require a
labels file and are NA for unlabelled traces (n_labeled is reported alongside).

On HISTORICAL pre-fix traces, recorded_max_tokens_rate reflects the OLD termination labels
(processed_tokens cap) while MC3 is computed on the post-fix budget_tokens basis; the two can
therefore disagree (recorded_max_tokens_rate high, MC3 = 0). Main runs, produced under the
budget fix, will not show this split.

W2 canonical subtypes (5): decoy_accepted, unverified_candidate_submission, symbol_overtrust,
failed_validation_ignored, decompiler_artifact_trust. comprehend_time_fixation is a registered
SECONDARY comprehend-time label, NOT counted in W2_event_rate (prereg §6.4 + §8.x).
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean

CANONICAL = ["decoy_accepted", "unverified_candidate_submission", "symbol_overtrust",
             "failed_validation_ignored", "decompiler_artifact_trust"]
SUBTYPE_TO_FAMILY = {
    "decoy_accepted": {"decoy_static_string", "decoy_dead_function"},
    "unverified_candidate_submission": {"transform_then_compare"},
    "symbol_overtrust": {"misleading_symbol_name"},
    "failed_validation_ignored": {"silent_validation_failure"},
    "decompiler_artifact_trust": {"decompiler_artifact"},
}
ARMS = ["A0", "A1", "A2"]


def load_jsonl(fp):
    recs = [json.loads(l) for l in open(fp, encoding="utf-8") if l.strip()]
    meta = next((r for r in recs if r.get("record_type") == "meta"), recs[0] if recs else {})
    steps = [r for r in recs if r.get("record_type") == "step"]
    return meta, steps


def subset_of(task_id: str) -> str:
    return "synthetic" if (task_id or "").startswith("t_") else "real"


def expected_families(repo: Path) -> dict:
    """task_id -> set(expected card families), from synthetic manifests + real manifest."""
    exp = {}
    for mf in glob.glob(str(repo / "tasks/synthetic/*/manifest.json")):
        try:
            m = json.load(open(mf, encoding="utf-8"))
        except Exception:
            continue
        fams = set()
        cf = m.get("card_families_in_scope")
        if cf:
            fams |= {x.strip() for x in (cf.split(",") if isinstance(cf, str) else cf)}
        if m.get("target_w2_subtype") in SUBTYPE_TO_FAMILY:
            fams |= SUBTYPE_TO_FAMILY[m["target_w2_subtype"]]
        if fams:
            exp[m.get("task_id", Path(mf).parent.name)] = fams
    tm = repo / "tasks/manifest.json"
    if tm.exists():
        try:
            d = json.load(open(tm, encoding="utf-8"))
            real = d.get("real", {})
            for e in (real.values() if isinstance(real, dict) else real):
                if not isinstance(e, dict):
                    continue
                tid = e.get("task_id") or e.get("id")
                fams = set()
                for k in ("expected_pattern_family", "expected_w2_family", "w2_family"):
                    v = e.get(k)
                    if v:
                        fams |= {x.strip() for x in (v.split(",") if isinstance(v, str) else v)}
                for st in (e.get("expected_w2_subtypes") or e.get("w2_subtypes") or []):
                    if st in SUBTYPE_TO_FAMILY:
                        fams |= SUBTYPE_TO_FAMILY[st]
                if tid and fams:
                    exp[tid] = fams
        except Exception:
            pass
    return exp


def per_trace(meta, steps) -> dict:
    r = {"task_id": meta.get("task_id"), "arm": meta.get("arm"),
         "attempt_id": meta.get("attempt_id"), "n_steps": meta.get("n_steps", len(steps)),
         "term": meta.get("termination_reason"),
         "n_submissions": meta.get("n_submissions", 0),
         "n_blocked": meta.get("n_blocked_submissions", 0)}
    tok = meta.get("tokens_total", {}) or {}
    r["budget_tokens"] = (tok.get("uncached_input_tokens", 0) + tok.get("cache_write_tokens", 0)
                          + tok.get("output_tokens", 0))
    r["max_tokens_term"] = (r["term"] == "max_tokens")

    rb = {}  # run_binary step_idx -> (candidate, verdict)
    for s in steps:
        tc = s.get("tool_call") or {}
        if tc.get("tool") == "run_binary":
            rb[s["step_idx"]] = (str((tc.get("args") or {}).get("candidate")),
                                 (s.get("tool_result") or {}).get("verdict"))

    subs, vals = [], []
    retrieved_ids, retrieved_fams, cited = set(), set(), set()
    for s in steps:
        if s.get("submission"):
            subs.append(s["submission"])
        for v in (s.get("validations_added") or []):
            vals.append(v)
        for h in (s.get("hypotheses_added") or []):
            for cc in (h.get("cites_card_ids") or h.get("cited_cards") or []):
                cited.add(cc)
        for c in (s.get("retrieved_cards") or []):
            if c.get("card_id") or c.get("pattern_id"):
                retrieved_ids.add(c.get("card_id") or c.get("pattern_id"))
            if c.get("family") or c.get("pattern_family"):
                retrieved_fams.add(c.get("family") or c.get("pattern_family"))

    r["solved"] = (r["term"] == "solved") or any(su.get("accepted") for su in subs)
    r["solve_step"] = next((su.get("step_idx") for su in subs if su.get("accepted")), None)
    r["retrieved_families"] = retrieved_fams
    r["any_retrieval"] = bool(retrieved_ids or retrieved_fams)
    r["card_cited_any"] = (len(cited & retrieved_ids) > 0) if retrieved_ids else None

    def backed(value):
        return any(v.get("candidate") == value and v.get("qualifies") for v in vals)
    r["ledger_complete_frac"] = (mean([1.0 if backed(su.get("value")) else 0.0 for su in subs])
                                 if subs else None)

    inv = tot = 0
    for v in vals:
        sidx = v.get("source_step_idx")
        if v.get("tool_name") == "run_binary" and sidx in rb:
            tot += 1
            if v.get("verdict") != rb[sidx][1]:
                inv += 1
    r["invalid_validation_frac"] = (inv / tot) if tot else None

    def accepted_run_before(value, before_step):
        return any(cand == str(value) and verd == "accepted"
                   for st, (cand, verd) in rb.items() if st < before_step)
    correct = decisions = 0
    if r["arm"] == "A2":
        for su in subs:
            decisions += 1
            ok = accepted_run_before(su.get("value"), su.get("step_idx", 10 ** 9))
            # correct allow iff the accept was backed by an accepting run
            if su.get("accepted"):
                correct += 1 if ok else 0
            else:
                correct += 1  # a recorded non-accepted submission is not a gate error here
        for s in steps:
            bs = s.get("blocked_submission")
            if bs:
                decisions += 1
                val = bs.get("value") or bs.get("candidate")
                correct += 0 if accepted_run_before(val, s["step_idx"]) else 1  # correct block iff no accepting run
    r["mc2_decisions"] = decisions
    r["mc2_correct"] = correct
    return r


def load_labels(globs):
    out = {}
    for g in globs:
        for fp in glob.glob(g, recursive=True):
            try:
                data = json.load(open(fp, encoding="utf-8"))
            except Exception:
                continue
            for row in (data if isinstance(data, list) else data.get("labels", [])):
                out[(row.get("task_id"), row.get("arm"), row.get("attempt_id"))] = row
    return out


def agg(values):
    vals = [v for v in values if v is not None]
    return round(mean(vals), 4) if vals else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-glob", default="runs/**/trace.jsonl")
    ap.add_argument("--labels-glob", default="annotation/manual_labels/*.json")
    ap.add_argument("--tasks-file", default="pilot_tasks.json")
    ap.add_argument("--out", default="analysis/tables")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--budget-ceiling", type=int, default=500000)
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    files = sorted(glob.glob(args.runs_glob, recursive=True))
    traces = [per_trace(*load_jsonl(f)) for f in files]
    labels = load_labels([args.labels_glob])
    exp_fam = expected_families(repo)

    for t in traces:
        lab = labels.get((t["task_id"], t["arm"], t["attempt_id"]))
        t["labeled"] = lab is not None
        if lab:
            ev = lab.get("w2_events", {})
            t["w2_events"] = sum(1 for k in CANONICAL if ev.get(k))
            for k in CANONICAL:
                t[k] = bool(ev.get(k))
            t["ctf"] = bool(lab.get("comprehend_time_fixation"))
        want = exp_fam.get(t["task_id"])
        t["mc1"] = (len(t["retrieved_families"] & want) > 0) if (t["any_retrieval"] and want) else None

    print(f"loaded {len(traces)} traces ; {sum(t['labeled'] for t in traces)} labelled ; "
          f"tasks with expected-family: {len(exp_fam)}")

    by_arm, by_arm_sub, by_task_arm = defaultdict(list), defaultdict(list), defaultdict(list)
    for t in traces:
        by_arm[t["arm"]].append(t)
        by_arm_sub[(t["arm"], subset_of(t["task_id"]))].append(t)
        by_task_arm[(t["task_id"], t["arm"])].append(t)

    prim_rows = []
    for arm in ARMS:
        for sub in ("synthetic", "real"):
            ts = by_arm_sub.get((arm, sub), [])
            if not ts:
                continue
            lab = [t for t in ts if t.get("labeled")]
            tasks = defaultdict(list)
            for t in ts:
                tasks[t["task_id"]].append(t)
            prim_rows.append({
                "arm": arm, "subset": sub, "n_attempts": len(ts), "n_tasks": len(tasks),
                "n_labeled": len(lab),
                "W2_event_rate": agg([t["w2_events"] for t in lab]) if lab else None,
                "decoy_accepted_rate": agg([1.0 if t.get("decoy_accepted") else 0.0 for t in lab]) if lab else None,
                "unverified_submission_rate": agg([1.0 if t.get("unverified_candidate_submission") else 0.0 for t in lab]) if lab else None,
                "success@1": agg([1.0 if t["solved"] else 0.0 for t in ts]),
                "success@3": agg([1.0 if any(x["solved"] for x in v) else 0.0 for v in tasks.values()]),
            })

    man_rows = []
    for arm in ARMS:
        ts = by_arm.get(arm, [])
        if not ts:
            continue
        dec = sum(t["mc2_decisions"] for t in ts)
        cor = sum(t["mc2_correct"] for t in ts)
        man_rows.append({
            "arm": arm, "n_attempts": len(ts),
            "MC1_family_match_relevance": agg([1.0 if t["mc1"] else 0.0 for t in ts if t["mc1"] is not None]),
            "MC2_scaffold_enforcement_correctness": (round(cor / dec, 4) if dec else None),
            "MC2_n_submit_decisions": dec,
            # MC3 on the budget_tokens basis: an attempt is token-exhausted iff budget_tokens
            # (cache_read excluded) reaches the ceiling. Reading termination_reason instead would
            # over-count PRE-fix traces that died on the old processed_tokens cap.
            "MC3_token_budget_exhaustion_rate": agg([1.0 if t["budget_tokens"] >= args.budget_ceiling else 0.0 for t in ts]),
            "recorded_max_tokens_rate": agg([1.0 if t["max_tokens_term"] else 0.0 for t in ts]),
            "budget_tokens_mean": int(mean([t["budget_tokens"] for t in ts])) if ts else None,
        })

    sec_rows = []
    for arm in ARMS:
        ts = by_arm.get(arm, [])
        if not ts:
            continue
        lab = [t for t in ts if t.get("labeled")]
        solved = [t for t in ts if t["solved"] and t["solve_step"] is not None]
        sec_rows.append({
            "arm": arm, "n_attempts": len(ts), "n_labeled": len(lab),
            "decompiler_artifact_trust_rate": agg([1.0 if t.get("decompiler_artifact_trust") else 0.0 for t in lab]) if lab else None,
            "comprehend_time_fixation_rate": agg([1.0 if t.get("ctf") else 0.0 for t in lab]) if lab else None,
            "blocked_submission_count": agg([t["n_blocked"] for t in ts]),
            "ledger_completeness_rate": agg([t["ledger_complete_frac"] for t in ts]),
            "card_citation_rate": agg([1.0 if t["card_cited_any"] else 0.0 for t in ts if t["card_cited_any"] is not None]),
            "card_ignored_rate": agg([0.0 if t["card_cited_any"] else 1.0 for t in ts if t["card_cited_any"] is not None]),
            "invalid_validation_rate": agg([t["invalid_validation_frac"] for t in ts]),
            "time_to_solve_steps": agg([t["solve_step"] for t in solved]) if solved else None,
            "tool_calls_per_attempt": agg([t["n_steps"] for t in ts]),
        })

    pt_rows = []
    for (task, arm), ts in sorted(by_task_arm.items()):
        lab = [t for t in ts if t.get("labeled")]
        pt_rows.append({
            "task_id": task, "arm": arm, "subset": subset_of(task), "n_attempts": len(ts),
            "success_at1": agg([1.0 if t["solved"] else 0.0 for t in ts]),
            "success_at3": 1.0 if any(t["solved"] for t in ts) else 0.0,  # task-level (H3); == solved_any as float
            "W2_event_rate": agg([t["w2_events"] for t in lab]) if lab else "",
            "decoy_accepted_rate": agg([1.0 if t.get("decoy_accepted") else 0.0 for t in lab]) if lab else "",
            "unverified_submission_rate": agg([1.0 if t.get("unverified_candidate_submission") else 0.0 for t in lab]) if lab else "",
            "comprehend_time_fixation_rate": agg([1.0 if t.get("ctf") else 0.0 for t in lab]) if lab else "",
            "max_tokens_rate": agg([1.0 if t["max_tokens_term"] else 0.0 for t in ts]),
        })

    def write(name, rows):
        if not rows:
            return
        with open(outdir / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"  wrote {outdir / name} ({len(rows)} rows)")

    write("primary.csv", prim_rows)
    write("manipulation.csv", man_rows)
    write("secondary.csv", sec_rows)
    write("per_task.csv", pt_rows)


if __name__ == "__main__":
    main()
