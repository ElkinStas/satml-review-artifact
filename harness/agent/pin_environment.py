"""Environment / toolchain pin (#15).

`anthropic>=0.40.0` is not acceptable before a paid canary: a silent SDK bump can change tool
serialization, cache behaviour, response blocks, or retry semantics. This module CAPTURES the actually
installed versions (SDK, bubblewrap, the RE toolchain, the analysis packages, python, the OS) plus the
container image digest, writes them to `environment_lock.json`, and VERIFIES the running environment
against that lock -- fail-closed for registered runs, so a run can only proceed in the pinned image.

The values must be captured IN THE TARGET IMAGE (the `rerag-re` container), not guessed: this build
container has neither the SDK nor the RE toolchain, so a lock generated here is a scaffold and carries
`_regenerate_in_target_image: true`. In the target image run:

    python -m agent.pin_environment --regenerate      # writes environment_lock.json for provenance
    python -m agent.pin_environment                     # verify (nonzero exit on drift)

Image digest: set RERAG_IMAGE_DIGEST in the environment (or bake /etc/rerag_image_digest) so the exact
built image is recorded.
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

LOCK_NAME = "environment_lock.json"

# python packages whose version pins the model / analysis behaviour
_PACKAGES = ("anthropic", "openai", "angr", "capstone", "z3", "z3-solver", "pwntools", "unicorn", "ropper")
# external executables: version-pin the sandbox + the RE toolchain
_EXES = {
    "bwrap": ["bwrap", "--version"],
    "radare2": ["r2", "-v"],
    "gdb": ["gdb", "--version"],
    "strace": ["strace", "--version"],
    "ltrace": ["ltrace", "--version"],
    "gcc": ["gcc", "--version"],
    "ld": ["ld", "--version"],
    "objdump": ["objdump", "--version"],
    "python3": ["python3", "--version"],
}


def _exe_version(argv) -> str:
    try:
        out = subprocess.run(argv, capture_output=True, timeout=8, text=True)
        line = (out.stdout or out.stderr or "").strip().splitlines()
        return line[0].strip() if line else "installed (no version line)"
    except FileNotFoundError:
        return "NOT-INSTALLED"
    except Exception as e:  # noqa: BLE001
        return f"error: {e!r}"


def _pkg_version(name: str) -> str:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001
        return "NOT-INSTALLED"


def _image_digest() -> str:
    import os
    d = os.environ.get("RERAG_IMAGE_DIGEST")
    if d:
        return d.strip()
    p = Path("/etc/rerag_image_digest")
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    return "UNSET (set RERAG_IMAGE_DIGEST or bake /etc/rerag_image_digest)"


def _digest_valid(d: str) -> bool:
    import re
    return bool(d) and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", d.strip().lower()))


def capture_environment() -> dict:
    """Snapshot the running environment. Values are whatever is actually installed here/now."""
    incomplete = False
    exes = {k: _exe_version(v) for k, v in _EXES.items()}
    pkgs = {k: _pkg_version(k) for k in _PACKAGES}
    digest = _image_digest()
    # a target-image lock must have the SDK + bwrap present AND a real image digest; flag a scaffold otherwise
    if pkgs.get("anthropic") == "NOT-INSTALLED" or exes.get("bwrap") == "NOT-INSTALLED" \
            or not _digest_valid(digest):
        incomplete = True
    return {
        "_regenerate_in_target_image": incomplete,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "image_digest": digest,
        "packages": pkgs,
        "executables": exes,
    }


def load_lock(repo) -> dict:
    return json.loads((Path(repo) / LOCK_NAME).read_text(encoding="utf-8"))


def verify(repo, current: dict | None = None):
    """Return (ok, drift). drift = list of (field, expected, actual). Fail-closed if the lock is a
    scaffold, is missing required structure, is truncated (not the full package/exe set), or any pinned
    value differs (python / platform / image_digest / every package + executable)."""
    cur = current or capture_environment()
    lock = load_lock(repo)
    drift: list[tuple[str, str, str]] = []
    # required top-level structure + correct types
    for k in ("python", "platform", "image_digest", "packages", "executables"):
        if k not in lock:
            drift.append((f"missing:{k}", "present", "absent"))
    if not isinstance(lock.get("packages"), dict):
        drift.append(("packages.type", "dict", type(lock.get("packages")).__name__))
    if not isinstance(lock.get("executables"), dict):
        drift.append(("executables.type", "dict", type(lock.get("executables")).__name__))
    # the scaffold flag must be exactly boolean False -- absent / null / true all mean "not a real lock"
    if lock.get("_regenerate_in_target_image") is not False:
        drift.append(("_regenerate_in_target_image", "false",
                      repr(lock.get("_regenerate_in_target_image", "<missing>"))))
    if not _digest_valid(lock.get("image_digest", "")):
        drift.append(("image_digest", "sha256:<64hex>", str(lock.get("image_digest"))))
    # a truncated lock is NOT complete: the pinned package/executable sets must be exactly the full set
    if isinstance(lock.get("packages"), dict) and set(lock["packages"]) != set(_PACKAGES):
        drift.append(("packages.keys", str(sorted(_PACKAGES)), str(sorted(lock.get("packages", {})))))
    if isinstance(lock.get("executables"), dict) and set(lock["executables"]) != set(_EXES):
        drift.append(("executables.keys", str(sorted(_EXES)), str(sorted(lock.get("executables", {})))))
    # value comparison (platform now included -- bwrap/ptrace/seccomp/user-ns depend on host+kernel, not
    # just the image)
    for field in ("python", "platform", "image_digest"):
        if lock.get(field) != cur.get(field):
            drift.append((field, str(lock.get(field)), str(cur.get(field))))
    for grp in ("packages", "executables"):
        g = lock.get(grp)
        if not isinstance(g, dict):
            continue   # already reported as a type drift above; don't call .items() on a list/str
        for k, exp in g.items():
            act = (cur.get(grp) or {}).get(k)
            if exp != act:
                drift.append((f"{grp}.{k}", str(exp), str(act)))
    return (len(drift) == 0), drift


def format_drift(drift) -> str:
    return "\n".join(f"  {f}: locked {e!r} != running {a!r}" for f, e, a in drift)


def regenerate(repo) -> dict:
    env = capture_environment()
    (Path(repo) / LOCK_NAME).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    return env


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()
    if args.regenerate:
        env = regenerate(args.repo)
        print(f"wrote {LOCK_NAME}"
              + (" (SCAFFOLD -- regenerate in the rerag-re image!)" if env["_regenerate_in_target_image"] else ""))
        print(f"  python {env['python']} | anthropic {env['packages'].get('anthropic')} "
              f"| bwrap {env['executables'].get('bwrap')} | image {env['image_digest']}")
    else:
        ok, drift = verify(args.repo)
        print("ENVIRONMENT PIN: " + ("OK" if ok else "DRIFT\n" + format_drift(drift)))
        raise SystemExit(0 if ok else 1)
