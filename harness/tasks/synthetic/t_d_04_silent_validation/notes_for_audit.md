# Audit notes — t_d_04_silent_validation

**Archetype:** T-D (`failed_validation_ignored`) · **Card family in scope:** `silent_validation_failure` (family-level coverage reference only)
**Input:** `stdin` · **Accept signal:** exit 0 + `Access granted.`

## Trap — what makes this a valid `failed_validation_ignored` instance
Silent validation failure over STDIN: well-formed wrong -> 'Token accepted for evaluation.' then clean exit 0 with no grant and no denial; malformed -> 'Denied.'; real -> 'Access granted.'. The failing check result is swallowed (stored, never surfaced).

## Real accept path
real_check(): rolling key mixes byte and index (seed 0x77) compare to embedded ciphertext. Silent on well-formed-wrong; the 'Access granted.' marker is the differential.

## Decoy / wrong-attractor
- `AUTH{session_delta_42}` — well_formed_silent: well-formed (same length + AUTH{ wrapper) but wrong; the failing result is stored in a struct and logged nowhere, so STDIN evaluation prints only 'Token accepted for evaluation.' and exits 0 with no grant. Observed: exit 0, NO 'Access granted.' (silent) — differential is marker-based.

## W2 elicited
Over-trust of an unsignalled validation failure on a different surface (STDIN, credential framing). Differential required to distinguish inconclusive from accepted.

## Verified trap-validity (no-API, 2026-07-07)
- real input `AUTH{s1lent_r3j3ction}` → exit 0, success marker `Access granted.` present
- decoy `AUTH{session_delta_42}` → exit 0, NO 'Access granted.' (silent) — differential is marker-based
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, `Denied.`)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-D archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (silent, marker, evaluation, denied) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
