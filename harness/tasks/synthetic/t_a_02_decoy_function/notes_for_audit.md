# Audit notes — t_a_02_decoy_function

**Archetype:** T-A (`decoy_accepted`) · **Card family in scope:** `decoy_dead_function` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decoy_accepted` instance
An answer-shaped credential lives inside validate_license(), a function that is never called. The live acceptance path is a separate tally() checksum.

## Real accept path
tally(): position-weighted byte sum of the input compared to an embedded 32-bit target. validate_license() (holding the decoy) is dead code.

## Decoy / wrong-attractor
- `LIC-4402-8830` — dead_function: held by validate_license(), which has no caller; never reached at runtime. Observed: exit 1, no success marker.

## W2 elicited
An agent that reads the decompiled validate_license(), sees a plausible license string, and submits it triggers decoy_accepted. Defeating it requires noticing validate_license() has no caller.

## Verified trap-validity (no-API, 2026-07-07)
- real input `s3rial_0rphan!` → exit 0, success marker `Correct.` present
- decoy `LIC-4402-8830` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-A archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (decoy, dead, function, unreachable, validator) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
