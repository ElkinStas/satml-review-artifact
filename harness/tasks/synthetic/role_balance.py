"""Template-group balance constraint for role selection (applied at calibration, not now).

Roles (calibration / main / dev-ci reserve) are SELECTED from the frozen pool AFTER the calibration
pilot; they are deliberately not assigned here (assigning them now would invent data). This module
holds the constraint that any MAIN selection must satisfy so near-replicate clusters cannot inflate the
effective sample via pseudo-replication:

    no template_group contributes more than `max_main_per_group` MAIN tasks.

The near-replicate clusters in the frozen pool (taxonomy_version 1.0) are:
    TD-silent-validation x5 · TA-static-string x3 · TC-function-name x3 · TB-shift x2 · TE-desync x2 ·
    TE-opaque x2  (the remaining 7 groups are singletons).

`template_group` is read from the per-task manifests (the source of truth checked by test_pool_lock.py).
This is a selection-time *validator*, decoupled from difficulty/role, which remain calibration outputs.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Registered (frozen) role-selection parameter: no template_group contributes more than this many MAIN
# tasks. Mirrored in pool_manifest_v0.1.json ("registered_role_selection.max_main_per_group") and checked
# by test_role_balance.py so the two can't drift.
REGISTERED_MAX_MAIN_PER_GROUP = 2


def load_template_groups() -> dict[str, str]:
    """{task_id -> template_group} from every per-task manifest.json under tasks/synthetic/."""
    groups: dict[str, str] = {}
    for mp in sorted(HERE.glob("t_*/manifest.json")):
        man = json.loads(mp.read_text(encoding="utf-8"))
        tg = man.get("template_group")
        if tg:
            groups[man["task_id"]] = tg
    return groups


def group_histogram(task_ids) -> Counter:
    """template_group -> count over the given task_ids."""
    groups = load_template_groups()
    return Counter(groups[t] for t in task_ids)


def check_main_selection(main_task_ids, max_main_per_group: int = REGISTERED_MAX_MAIN_PER_GROUP):
    """Validate a proposed MAIN selection against the per-group cap.

    Returns (ok, violations) where violations is a list of {template_group, count, cap} for groups over
    the cap. Unknown task_ids raise KeyError; a task_id listed twice raises ValueError (a selection is a
    set of distinct tasks -- a duplicate would silently double a group's weight).
    """
    if max_main_per_group < 1:
        raise ValueError("max_main_per_group must be >= 1")
    ids = list(main_task_ids)
    dups = sorted({t for t in ids if ids.count(t) > 1})
    if dups:
        raise ValueError(f"duplicate task_ids in selection: {dups}")
    groups = load_template_groups()
    unknown = [t for t in ids if t not in groups]
    if unknown:
        raise KeyError(f"unknown task_ids (not in the frozen pool): {unknown}")
    hist = Counter(groups[t] for t in ids)
    violations = [{"template_group": g, "count": c, "cap": max_main_per_group}
                  for g, c in sorted(hist.items()) if c > max_main_per_group]
    return (len(violations) == 0), violations


if __name__ == "__main__":  # quick descriptive dump (no selection is made here)
    g = load_template_groups()
    print(f"{len(g)} tasks across {len(set(g.values()))} template groups (taxonomy_version 1.0):")
    for grp, c in sorted(Counter(g.values()).items()):
        print(f"  {grp:<22} {c}")
