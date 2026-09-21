#!/usr/bin/env python3
"""Environment-pin tests (mechanism only; real versions are captured in the target image).

Run from repo root:  python agent/test_pin_environment.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent import pin_environment as pin

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


def main() -> int:
    env = pin.capture_environment()
    expect("capture has python + platform + packages + executables",
           all(k in env for k in ("python", "platform", "packages", "executables", "image_digest")))
    expect("anthropic is tracked as a pinned package", "anthropic" in env["packages"])
    expect("bwrap is tracked as a pinned executable", "bwrap" in env["executables"])

    # scaffold detection tested via monkeypatch (NOT the live machine state), so this suite behaves the
    # same in the dev container and in the target image.
    _op, _oe, _od = pin._pkg_version, pin._exe_version, pin._image_digest
    try:
        pin._exe_version = lambda a: "installed 1.0"
        pin._image_digest = lambda: "sha256:" + "a" * 64
        pin._pkg_version = lambda n: "NOT-INSTALLED" if n == "anthropic" else "1.0"
        expect("missing SDK -> capture flagged as a scaffold",
               pin.capture_environment()["_regenerate_in_target_image"] is True)
        pin._pkg_version = lambda n: "1.0"
        pin._image_digest = lambda: "UNSET"
        expect("missing image digest -> capture flagged as a scaffold",
               pin.capture_environment()["_regenerate_in_target_image"] is True)
        pin._image_digest = lambda: "sha256:" + "a" * 64
        expect("SDK + bwrap + valid digest -> NOT a scaffold",
               pin.capture_environment()["_regenerate_in_target_image"] is False)
    finally:
        pin._pkg_version, pin._exe_version, pin._image_digest = _op, _oe, _od

    # verify against a scaffold lock -> fail closed
    d = Path(tempfile.mkdtemp(prefix="rerag_env_"))
    (d / pin.LOCK_NAME).write_text(json.dumps(env) + "\n")
    ok_s, drift_s = pin.verify(d)
    expect("a scaffold lock fails verify (fail-closed)",
           (not ok_s) and any(f == "_regenerate_in_target_image" for f, _, _ in drift_s))

    # verify against a COMPLETE lock that matches the current capture -> pass (needs a valid digest)
    complete = dict(env)
    complete["_regenerate_in_target_image"] = False
    complete["image_digest"] = "sha256:" + "a" * 64
    cur = dict(env)
    cur["image_digest"] = complete["image_digest"]
    (d / pin.LOCK_NAME).write_text(json.dumps(complete) + "\n")
    ok_c, drift_c = pin.verify(d, current=cur)
    expect("a matching complete lock (valid digest) passes verify", ok_c and not drift_c)

    # an UNSET/invalid image digest fails closed even if lock == current (Bug: UNSET was accepted)
    unset = dict(complete)
    unset["image_digest"] = "UNSET (set RERAG_IMAGE_DIGEST or bake /etc/rerag_image_digest)"
    (d / pin.LOCK_NAME).write_text(json.dumps(unset) + "\n")
    ok_u, drift_u = pin.verify(d, current=unset)
    expect("an UNSET image digest fails verify even when lock==current",
           (not ok_u) and any(f == "image_digest" for f, _, _ in drift_u))
    expect("a non-sha256 digest is rejected", not pin._digest_valid("deadbeef"))
    expect("a short sha256 digest is rejected", not pin._digest_valid("sha256:deadbeef"))
    expect("a non-hex sha256 digest is rejected", not pin._digest_valid("sha256:" + "g" * 64))
    expect("a full 64-hex sha256 digest is accepted", pin._digest_valid("sha256:" + "b" * 64))

    # drift: bump a locked package version -> detected precisely
    drifted = json.loads(json.dumps(complete))
    drifted["packages"]["anthropic"] = "9.9.9"
    (d / pin.LOCK_NAME).write_text(json.dumps(drifted) + "\n")
    ok_d, drift_d = pin.verify(d, current=env)
    expect("a bumped SDK version is detected as drift",
           (not ok_d) and any(f == "packages.anthropic" for f, _, _ in drift_d))

    # image digest drift detected
    dd = json.loads(json.dumps(complete))
    dd["image_digest"] = "sha256:" + "c" * 64
    (d / pin.LOCK_NAME).write_text(json.dumps(dd) + "\n")
    ok_i, drift_i = pin.verify(d, current=cur)
    expect("an image-digest change is detected as drift",
           (not ok_i) and any(f == "image_digest" for f, _, _ in drift_i))

    # platform drift detected (kernel/host change -> bwrap/ptrace/seccomp may differ)
    pd = json.loads(json.dumps(complete))
    cur_p = dict(cur); cur_p["platform"] = "DIFFERENT-KERNEL-HOST"
    (d / pin.LOCK_NAME).write_text(json.dumps(pd) + "\n")
    ok_p, drift_p = pin.verify(d, current=cur_p)
    expect("a platform/kernel change is detected as drift",
           (not ok_p) and any(f == "platform" for f, _, _ in drift_p))

    # a TRUNCATED lock (missing a package/executable) is not complete -> fail closed
    trunc = json.loads(json.dumps(complete))
    trunc["packages"].pop(next(iter(trunc["packages"])))
    (d / pin.LOCK_NAME).write_text(json.dumps(trunc) + "\n")
    ok_t, drift_t = pin.verify(d, current=cur)
    expect("a truncated package set fails verify (not a complete lock)",
           (not ok_t) and any(f == "packages.keys" for f, _, _ in drift_t))

    # absent / null _regenerate_in_target_image must NOT be treated as false
    for bad_flag in ("__ABSENT__", None):
        bf = json.loads(json.dumps(complete))
        if bad_flag == "__ABSENT__":
            bf.pop("_regenerate_in_target_image")
        else:
            bf["_regenerate_in_target_image"] = None
        (d / pin.LOCK_NAME).write_text(json.dumps(bf) + "\n")
        ok_b, drift_b = pin.verify(d, current=cur)
        expect(f"_regenerate_in_target_image={bad_flag!r} fails verify (must be exactly false)",
               (not ok_b) and any(f == "_regenerate_in_target_image" for f, _, _ in drift_b))

    # malformed packages (list instead of dict) -> clean drift, not an exception
    mal = json.loads(json.dumps(complete)); mal["packages"] = ["angr", "z3"]
    (d / pin.LOCK_NAME).write_text(json.dumps(mal) + "\n")
    try:
        ok_m2, drift_m2 = pin.verify(d, current=cur)
        expect("malformed packages type yields drift, not an exception",
               (not ok_m2) and any(f == "packages.type" for f, _, _ in drift_m2))
    except Exception:  # noqa: BLE001
        expect("malformed packages type yields drift, not an exception", False)

    import shutil
    shutil.rmtree(d, ignore_errors=True)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"PIN ENVIRONMENT TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"PIN ENVIRONMENT TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
