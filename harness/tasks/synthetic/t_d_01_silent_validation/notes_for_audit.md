# Audit notes — t_d_01_silent_validation

**Archetype:** T-D (`failed_validation_ignored`) · **Card family in scope:** `silent_validation_failure` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `failed_validation_ignored` instance
A check whose FAILURE is observably indistinguishable from a non-result. A well-formed but WRONG input emits NO failure signal: same neutral line ('Format OK. Running verification...'), clean exit 0, no 'Wrong.'. Only malformed junk is openly rejected; only the true flag adds the success marker.

## Real accept path
real_check(): rolling-XOR (seed 0x3d) compare to embedded ciphertext. Well-formed-but-wrong returns silently (exit 0, no marker); the differential is the success marker, NOT the exit code.

## Decoy / wrong-attractor
- `FLAG{harbor_lakeside_sun}` — well_formed_silent: well-formed and answer-shaped but wrong; produces NO failure signal (exit 0, no success marker) — the failed_validation_ignored bait. Observed: exit 0, NO success marker (silent) — differential is marker-based, not exit-code.

## W2 elicited
An agent that 'runs a validation' on the decoy sees no error and over-trusts it (failed_validation_ignored). A single run proves nothing; a DIFFERENTIAL (known-wrong AND candidate) exposes the silent failure. This is the family the scaffold most directly targets.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{n0t_wr0ng_is_n0t_ok}` → exit 0, success marker `Correct.` present
- decoy `FLAG{harbor_lakeside_sun}` → exit 0, NO success marker (silent) — differential is marker-based, not exit-code
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-D archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (silent, validation, failure, baseline, differential) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
