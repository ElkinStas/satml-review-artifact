#!/usr/bin/env python3
"""Validate a registered-card JSON against the v2 schema and run a leak-pattern scan.

Usage:  python cards/validate_cards.py cards/_schema_example.json
        python cards/validate_cards.py cards/cards_v1.0.json --strict   # the registered library (frozen)

Schema errors and leak hits are hard failures (exit 1). The leak scan is mechanical and
conservative: it flags flag-like tokens, address/constant-like hex, and a small denylist of
eval-derived tokens. It does NOT replace the human leakage audit (prereg §5.2) — it catches the
obvious instance-specific leaks before review.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

FAMILIES = {"decoy_static_string", "decoy_dead_function", "transform_then_compare",
            "misleading_symbol_name", "silent_validation_failure", "decompiler_artifact"}
WHITELIST = {"dynamic_run_with_input", "gdb_breakpoint_check", "z3_constraint_solve", "manual_trace_through"}
# Actions that require EXECUTING the target. run_binary / trace_binary were removed from the agent
# tool surface (agent/tools/registry.py::ToolRegistry.tool_names), so a card recommending one of
# these hands the agent an instruction it cannot carry out. Enum membership (WHITELIST) is unchanged;
# this is a separate, stricter gate on card ADVICE only.
NON_PERFORMABLE = {"dynamic_run_with_input", "gdb_breakpoint_check"}
GROUNDINGS = {"well_grounded", "advisory_under_exercised", "candidate_unblinded"}
SOURCE_TYPES = {"general_re_knowledge", "taxonomy_w2", "public_writeup_disjoint", "textbook",
                "non_eval_example", "candidate_unblinded"}

REQUIRED_STR = ["card_id", "family", "title", "applicability_signal", "mechanism",
                "misleading_interpretation", "better_interpretation", "validation_note"]
REQUIRED_LIST = ["retrieval_keywords", "recommended_validation_actions", "not_applicable_when",
                 "misfire_risks", "minimum_evidence_before_use"]

# leak patterns (instance-specific detail that must never appear in a registered card)
LEAK = [
    (re.compile(r"\b[A-Za-z_]{2,}\{[^}]{1,}\}"), "flag-like token (name{...})"),
    (re.compile(r"\b0x[0-9a-fA-F]{4,}\b"), "address/constant-like hex (>=4 digits)"),
    (re.compile(r"\bkalmar", re.I), "eval flag stem 'kalmar'"),
    (re.compile(r"\bjormugandr\b|\bgatta\b|\b1zwasm\b", re.I), "eval task name"),
    (re.compile(r"\bfcn\.[0-9a-f]{6,}\b", re.I), "radare2 address-named function"),
]
# eval-derived token denylist (extend as the eval set grows)
DENYLIST = {"icanrevthis", "rabbit-h0le", "n0t_wr0ng", "l00ks_f1ne"}


def card_strings(card: dict):
    """Yield every string value reachable in a card (for the leak scan)."""
    def walk(v):
        if isinstance(v, str):
            yield v
        elif isinstance(v, list):
            for x in v:
                yield from walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                yield from walk(x)
    yield from walk(card)


def load_src_registry(sources_path: Path):
    """Parse cards/authoring_sources.md -> (permitted SRC ids, prohibited SRC ids).

    Convention: SRC-X## are prohibited (eval), SRC-### are permitted (clean). Classify by the
    'X' prefix so prose mentions in either section don't misclassify.
    """
    permitted, prohibited = set(), set()
    if not sources_path.exists():
        return permitted, prohibited
    for tok in set(re.findall(r"SRC-X?\d+", sources_path.read_text(encoding="utf-8"))):
        (prohibited if tok.upper().startswith("SRC-X") else permitted).add(tok)
    return permitted, prohibited


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--strict", action="store_true",
                    help="registered-library gate: enforce c_* ids, 25-40 total, family>=3, clean provenance")
    ap.add_argument("--sources", default="cards/authoring_sources.md")
    args = ap.parse_args()
    path = Path(args.path)
    data = json.loads(path.read_text(encoding="utf-8"))
    cards = data["cards"] if isinstance(data, dict) else data
    is_example = isinstance(data, dict) and data.get("status") == "schema_example"
    strict = args.strict
    permitted_src, prohibited_src = load_src_registry(Path(args.sources))

    errors, leaks, warns = [], [], []
    seen_ids = Counter()
    fam_counts = Counter()

    for i, c in enumerate(cards):
        cid = c.get("card_id", f"<#{i}>")
        seen_ids[cid] += 1
        for f in REQUIRED_STR:
            if not isinstance(c.get(f), str) or not c.get(f, "").strip():
                errors.append(f"{cid}: missing/empty str field '{f}'")
        for f in REQUIRED_LIST:
            if not isinstance(c.get(f), list) or not c.get(f):
                errors.append(f"{cid}: missing/empty list field '{f}'")
        if c.get("family") not in FAMILIES:
            errors.append(f"{cid}: family '{c.get('family')}' not in the 7 families")
        else:
            fam_counts[c["family"]] += 1
        for a in c.get("recommended_validation_actions", []):
            if a not in WHITELIST:
                errors.append(f"{cid}: validation action '{a}' not in whitelist")
        if c.get("grounding") not in GROUNDINGS:
            errors.append(f"{cid}: grounding '{c.get('grounding')}' invalid")
        if not isinstance(c.get("requires_differential"), bool):
            errors.append(f"{cid}: requires_differential must be bool")
        prov = c.get("provenance")
        if not isinstance(prov, dict):
            errors.append(f"{cid}: provenance block missing")
        else:
            if prov.get("source_type") not in SOURCE_TYPES:
                errors.append(f"{cid}: provenance.source_type '{prov.get('source_type')}' invalid")
            if not isinstance(prov.get("source_ids"), list) or not prov.get("source_ids"):
                errors.append(f"{cid}: provenance.source_ids missing/empty")
            if prov.get("eval_overlap") not in {"none", "firewalled"}:
                errors.append(f"{cid}: provenance.eval_overlap must be 'none' or 'firewalled'")
            if prov.get("eval_overlap") != "none" and not is_example:
                errors.append(f"{cid}: eval_overlap != 'none' -> may NOT enter the registered library")
            if not isinstance(prov.get("authoring_note"), str) or not prov.get("authoring_note", "").strip():
                errors.append(f"{cid}: provenance.authoring_note missing")

        # leak scan over all card strings
        for s in card_strings(c):
            low = s.lower()
            for tok in DENYLIST:
                if tok in low:
                    leaks.append(f"{cid}: denylisted eval token '{tok}'")
            for rx, why in LEAK:
                m = rx.search(s)
                if m:
                    leaks.append(f"{cid}: {why} -> {m.group(0)!r}")

    for cid, n in seen_ids.items():
        if n > 1:
            errors.append(f"duplicate card_id '{cid}' (x{n})")

    # family-count sanity vs the plan (warn only)
    # W10c: comprehend_time_fixation removed (firewalled-source overlap); 25 cards / 6 families.
    plan = {"decoy_static_string": 4, "decoy_dead_function": 4, "transform_then_compare": 5,
            "misleading_symbol_name": 4, "silent_validation_failure": 4, "decompiler_artifact": 4}
    if not is_example:
        for fam, want in plan.items():
            got = fam_counts.get(fam, 0)
            if got != want:
                warns.append(f"family {fam}: {got} cards (plan: {want})")
        total = sum(fam_counts.values())
        if not (25 <= total <= 40):
            warns.append(f"total {total} cards (prereg §5.2 target 25-40)")

    # STRICT registered-library gate (hard fails)
    if strict:
        total = sum(fam_counts.values())
        if total == 0:
            errors.append("STRICT: registered library is empty (0 cards)")
        if not (25 <= total <= 40):
            errors.append(f"STRICT: total {total} cards outside prereg §5.2 range 25-40")
        for fam, want in plan.items():
            if fam_counts.get(fam, 0) < 3:
                errors.append(f"STRICT: family {fam} has {fam_counts.get(fam,0)} cards (<3 required by §5.2)")
        for c in cards:
            cid = c.get("card_id", "<?>")
            for a in c.get("recommended_validation_actions", []):
                if a in NON_PERFORMABLE:
                    errors.append(f"STRICT: {cid}: validation action '{a}' requires executing the target, "
                                  f"which is not in the agent tool surface")
            if "SRC-006" in (c.get("provenance") or {}).get("source_ids", []):
                errors.append(f"STRICT: {cid}: cites SRC-006 (tasks/synthetic/archetype_specs.md). "
                              f"cards/authoring_sources.md lists it as permitted, but archetype_specs.md "
                              f"1.2 forbids deriving cards and archetypes from each other. Contradiction "
                              f"is unresolved -> treat as prohibited.")
            if c.get("requires_differential") is True:
                errors.append(f"STRICT: {cid}: requires_differential is retired (the accept/reject "
                              f"differential needed run_binary)")
            if not re.match(r"^c_", str(cid)):
                errors.append(f"STRICT: {cid}: registered card_id must start with 'c_'")
            if c.get("grounding") == "candidate_unblinded":
                errors.append(f"STRICT: {cid}: grounding 'candidate_unblinded' may NOT enter the registered library")
            prov = c.get("provenance") or {}
            if prov.get("source_type") == "candidate_unblinded":
                errors.append(f"STRICT: {cid}: provenance.source_type 'candidate_unblinded' may NOT enter the registered library")
            for sid in prov.get("source_ids", []):
                if sid in prohibited_src:
                    errors.append(f"STRICT: {cid}: prohibited source {sid} (eval) cited")
                elif permitted_src and sid not in permitted_src:
                    errors.append(f"STRICT: {cid}: source {sid} not in the permitted registry")

    print(f"validated {len(cards)} card(s) from {path}" + (" [schema_example]" if is_example else ""))
    print(f"  families present: {dict(fam_counts)}")
    for w in warns:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}")
    for lk in leaks:
        print(f"  LEAK  {lk}")
    ok = not errors and not leaks
    print("\nVALIDATION: " + ("PASSED" if ok else f"FAILED (errors={len(errors)}, leaks={len(leaks)})"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
