# Audit notes — t_b_01_transform_compare

**Archetype:** T-B (`unverified_candidate_submission`) · **Card family in scope:** `transform_then_compare` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `unverified_candidate_submission` instance
The visible constant in .rodata is the POST-transform value: the inner is Caesar-shifted +7 over a fixed alphabet before comparison. Submitting the visible value raw is rejected.

## Real accept path
real_check(): shift each inner char +7 in the alphabet and compare to the stored post-transform inner. The preimage is the accepted input.

## Decoy / wrong-attractor
- `FLAG{0yauzm7ytg0o_g8uw10}` — post_transform_value: the post-Caesar(+7) inner shown in .rodata; the real gate compares AFTER transforming the input, so this raw value fails. Observed: exit 1, no success marker.

## W2 elicited
An agent that finds the .rodata FLAG{...} and submits it without inverting the transform triggers unverified_candidate_submission. Defeating it requires inverting the +7 shift (or running candidates).

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{tr4nsf0rm_th3_1nput}` → exit 0, success marker `Correct.` present
- decoy `FLAG{0yauzm7ytg0o_g8uw10}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-B archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (transform, shift, compare, alphabet, rodata) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
