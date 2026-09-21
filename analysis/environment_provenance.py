#!/usr/bin/env python3
"""Tabulate, from the traces themselves, which image and environment lock each run executed under.

The repository ships `environment_lock.json` at its root because `agent/preflight.py` compares a NEW
run against it. That single file does not describe the recorded evidence: the pools were measured
over several months and ran under several images. Rather than assert an environment, this script
recovers it from the `integration_image_digest` and `environment_lock_sha256` fields that every
trace carries, so the claim is checkable instead of stated.

    python3 scripts/environment_provenance.py [--runs DIR]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=None, help="runs tree (default: auto-detect)")
    a = ap.parse_args()

    runs = Path(a.runs) if a.runs else None
    if runs is None:
        for cand in (ROOT / "results" / "runs", ROOT / "runs"):
            if cand.is_dir():
                runs = cand
                break
    if runs is None or not runs.is_dir():
        sys.exit("could not locate the runs tree; pass --runs")

    # Hash every lock file we ship, so a recorded hash can be resolved to a file by name.
    shipped = {}
    search = [ROOT, ROOT / "locks", ROOT / "harness", ROOT / "harness" / "locks"]
    for d in search:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.json")):
            if "lock" not in p.name:
                continue
            shipped.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), os.path.relpath(p, ROOT))

    counts: collections.Counter = collections.Counter()
    for f in glob.glob(str(runs / "*" / "**" / "trace.jsonl"), recursive=True):
        try:
            m = json.loads(open(f).readline())
        except Exception:
            continue
        pool = os.path.relpath(f, runs).split(os.sep)[0]
        counts[(pool, m.get("integration_image_digest", "?"), m.get("environment_lock_sha256", "?"))] += 1

    print(f"{'pool':<18} {'image digest':<24} {'environment lock':<20} {'runs':>5}  shipped as")
    print("-" * 96)
    for (pool, img, lock), n in sorted(counts.items()):
        name = shipped.get(lock, "-- not shipped --")
        print(f"{pool:<18} {img[:24]:<24} {lock[:19]:<20} {n:>5}  {name}")

    imgs = {k[1] for k in counts}
    locks = {k[2] for k in counts}
    missing = sorted(l for l in locks if l not in shipped)
    print("-" * 96)
    print(f"{len(imgs)} distinct images, {len(locks)} distinct environment locks, "
          f"{sum(counts.values())} traces")
    if missing:
        print(f"{len(missing)} lock file(s) not shipped; recorded hash is the only record:")
        for l in missing:
            print(f"    {l}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
