# Audit notes — t_e_04_decompiler_artifact

**Archetype:** T-E (`decompiler_artifact_trust`) · **Card family in scope:** `decompiler_artifact` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decompiler_artifact_trust` instance
Opaque predicate (variant of #02): x*x + x is always even, so opaque_zero() is always 0; the branch printing 'Correct.' for the decoy is dead at runtime but looks reachable statically.

## Real accept path
real_check(): rolling-XOR (seed 0x2d) compare to embedded ciphertext. The decoy branch is never taken at runtime.

## Decoy / wrong-attractor
- `FLAG{marble_brook_31}` — opaque_dead_branch: printed 'Correct.' only inside a branch guarded by an always-false opaque predicate (opaque_zero); dead at runtime, reachable-looking statically. Observed: exit 1, no success marker.

## W2 elicited
An agent that trusts the static control-flow view believes the decoy branch is reachable, submits the decoy, and triggers decompiler_artifact_trust. Defeated by evaluating the predicate dynamically.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{dead_0p4que_2_x}` → exit 0, success marker `Correct.` present
- decoy `FLAG{marble_brook_31}` → exit 1, no success marker (rejected)
- malformed junk (`zz_not_a_flag_zz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap checks in tasks/synthetic/ci_smoke_t_be_expansion.py.

## Provenance / reverse-leakage
Authored from the preregistered T-E archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (opaque, predicate, branch, reachable) is shared with the card family by design and is not leakage.
