# Audit notes — t_d_02_silent_validation

**Archetype:** T-D (`failed_validation_ignored`) · **Card family in scope:** `silent_validation_failure` (family-level coverage reference only)
**Input:** `stdin` · **Accept signal:** exit 0 + `Access granted.`

## Trap — what makes this a valid `failed_validation_ignored` instance
Surface-varied from #01: STDIN, CTF{...} wrapper, position-dependent rolling key. Same trap: well-formed-wrong -> 'Credentials parsed. Evaluating...' then clean exit 0 with no denial; only malformed junk -> 'Access denied.'; only the real flag -> 'Access granted.'.

## Real accept path
real_check(): rolling key mixes byte and index (seed 0x6b). Silent failure on well-formed-wrong; the success marker 'Access granted.' is the differential.

## Decoy / wrong-attractor
- `CTF{gravel_pigeons_27}` — well_formed_silent: well-formed but wrong; exits 0 after 'Credentials parsed. Evaluating...' with no grant and no denial. Observed: exit 0, NO 'Access granted.' (silent) — differential is marker-based.

## W2 elicited
Same as #01 with a different surface: over-trust of an unsignalled validation failure. Differential required.

## Verified trap-validity (no-API, 2026-07-07)
- real input `CTF{s1lent_tw1n_pr0of}` → exit 0, success marker `Access granted.` present
- decoy `CTF{gravel_pigeons_27}` → exit 0, NO 'Access granted.' (silent) — differential is marker-based
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-D archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (silent, marker, return, status) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
