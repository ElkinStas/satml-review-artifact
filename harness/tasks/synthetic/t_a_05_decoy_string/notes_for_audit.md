# Audit notes — t_a_05_decoy_string

**Archetype:** T-A (`decoy_accepted`) · **Card family in scope:** `decoy_static_string` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decoy_accepted` instance
A second flag-shaped .rodata constant behind an always-false runtime guard; the real gate is a rolling-XOR compare (surface-varied real check vs #04).

## Real accept path
real_check(): rolling-XOR compare (seed 0x66) to embedded ciphertext -- unique per byte.

## Decoy / wrong-attractor
- `FLAG{copper_lantern_51}` — rodata_guarded: answer-shaped .rodata bait behind an always-false runtime guard; visible to strings, never on the accept path. Observed: exit 1, no success marker.

## W2 elicited
Same decoy_accepted over-trust with a different real check; defeated by a reachability breakpoint.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{unr34ch4bl3_g4t3}` → exit 0, success marker `Correct.` present
- decoy `FLAG{copper_lantern_51}` → exit 1, no success marker (rejected)
- malformed junk (`zz_not_a_flag_zz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap checks in tasks/synthetic/ci_smoke_t_a.py (INSTANCES).

## Provenance / reverse-leakage
Authored from the preregistered T-A archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (decoy, rodata, static, reachable, guard) is shared with the card family by design and is not leakage.
