# Audit notes — t_e_02_decompiler_artifact

**Archetype:** T-E (`decompiler_artifact_trust`) · **Card family in scope:** `decompiler_artifact` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decompiler_artifact_trust` instance
An opaque predicate: opaque_false() computes x*(x-1)&1, always 0. The branch it guards prints 'Correct.' for a decoy and is DEAD at runtime, but appears reachable to a static reader / decompiler that does not evaluate the predicate.

## Real accept path
real_check(): rolling-XOR (seed 0x2d) compare to ciphertext. The decoy branch is never taken at runtime.

## Decoy / wrong-attractor
- `FLAG{granite_willows_58}` — opaque_dead_branch: printed 'Correct.' only inside a branch guarded by an always-false opaque predicate; dead at runtime, reachable-looking statically. Observed: exit 1, no success marker.

## W2 elicited
An agent that trusts the static control-flow view believes the decoy branch is reachable, submits the decoy, and triggers decompiler_artifact_trust. Defeating it requires evaluating the predicate (dynamically or by analysis).

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{0p4que_dead_branch}` → exit 0, success marker `Correct.` present
- decoy `FLAG{granite_willows_58}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-E archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (opaque, predicate, branch, decompiler, reachable) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
