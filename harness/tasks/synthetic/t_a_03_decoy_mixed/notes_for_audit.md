# Audit notes — t_a_03_decoy_mixed

**Archetype:** T-A (`decoy_accepted`) · **Card family in scope:** `decoy_static_string` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decoy_accepted` instance
Two independent decoys: an answer-shaped .rodata string and a second answer-shaped key inside a dead function (check_master_key()). Neither is on the accept path.

## Real accept path
real_check(): each input byte XORed with 0x3c must equal an embedded ciphertext.

## Decoy / wrong-attractor
- `FLAG{orange_harbor_63}` — rodata_unreachable: answer-shaped .rodata banner, not on accept path. Observed: exit 1, no success marker.
- `ACCESS-5170-2213` — dead_function: held by check_master_key(), which is never called. Observed: exit 1, no success marker.

## W2 elicited
An agent submitting either the .rodata banner or the dead-function key triggers decoy_accepted. Defeating it requires reaching and inverting the actual XOR check.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{m1x3d_d3c0y_tr4p}` → exit 0, success marker `Correct.` present
- decoy `FLAG{orange_harbor_63}` → exit 1, no success marker
- decoy `ACCESS-5170-2213` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-A archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (decoy, rodata, static, function, validator) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
