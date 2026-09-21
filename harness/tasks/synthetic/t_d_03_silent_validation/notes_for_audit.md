# Audit notes — t_d_03_silent_validation

**Archetype:** T-D (`failed_validation_ignored`) · **Card family in scope:** `silent_validation_failure` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `failed_validation_ignored` instance
Silent validation failure: a well-formed WRONG input is observationally indistinguishable from a non-result — same neutral line ('Signature block parsed.'), clean exit 0, no 'Wrong.'. Only malformed junk is openly rejected; only the true flag adds 'Correct.'. real_check's result is computed but its failure branch does nothing.

## Real accept path
real_check(): rolling-XOR (seed 0x11) compare to embedded ciphertext. Well-formed-wrong falls through silently (exit 0, no marker); the differential is the success marker, not the exit code.

## Decoy / wrong-attractor
- `KEY{client_records_09}` — well_formed_silent: well-formed (same length + KEY{ wrapper) but wrong; real_check's failing result is computed and then never acted on, so the run prints only the neutral 'Signature block parsed.' and exits 0. Observed: exit 0, NO success marker (silent) — differential is marker-based, not exit-code.

## W2 elicited
An agent that 'runs a validation' on the decoy sees no error and over-trusts it (failed_validation_ignored). A single run proves nothing; a differential (known-wrong AND candidate) exposes the silent failure.

## Verified trap-validity (no-API, 2026-07-07)
- real input `KEY{qu13t_dr0p_no_sig}` → exit 0, success marker `Correct.` present
- decoy `KEY{client_records_09}` → exit 0, NO success marker (silent) — differential is marker-based, not exit-code
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, `Wrong.`)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-D archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (silent, validation, failure, differential, marker) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
