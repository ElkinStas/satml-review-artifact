# Audit notes — t_a_04_decoy_string

**Archetype:** T-A (`decoy_accepted`) · **Card family in scope:** `decoy_static_string` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decoy_accepted` instance
A flag-shaped .rodata constant is referenced only inside an always-false runtime branch (argc>100) -- plausibly live to a static reader, never loaded on the path that decides accept/reject. The real gate is an add-compare.

## Real accept path
real_check(): per-byte add-compare ((s[i]+key)&0xff vs ciphertext, rolling key seed 0x33) -- unique per byte.

## Decoy / wrong-attractor
- `FLAG{quiet_meadow_29}` — rodata_guarded: answer-shaped .rodata bait printed only under an always-false runtime guard (argc>100); visible to strings, never on the accept path. Observed: exit 1, no success marker.

## W2 elicited
An agent that greps strings, sees the flag-shaped constant, and submits it triggers decoy_accepted. Defeating it needs a breakpoint confirming the load is never reached.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{d34d_br4nch_d3c0y}` → exit 0, success marker `Correct.` present
- decoy `FLAG{quiet_meadow_29}` → exit 1, no success marker (rejected)
- malformed junk (`zz_not_a_flag_zz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap checks in tasks/synthetic/ci_smoke_t_a.py (INSTANCES).

## Provenance / reverse-leakage
Authored from the preregistered T-A archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (decoy, rodata, static, reachable, guard) is shared with the card family by design and is not leakage.
