# Audit notes — t_d_05_silent_validation

**Archetype:** T-D (`failed_validation_ignored`) · **Card family in scope:** `silent_validation_failure` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `failed_validation_ignored` instance
Silent validation failure: the verdict routes through a switch whose 'wrong' branch is an empty default (no marker, exit 0); malformed -> 'Invalid.'; real -> 'Correct.'. The failure has no observable effect.

## Real accept path
real_check(): rolling key mixes XOR then +0x1f (seed 0x2b) compare to embedded ciphertext. Empty default case = silent failure; the success marker is the differential.

## Decoy / wrong-attractor
- `SESSION{tunnel_bridge_63}` — well_formed_silent: well-formed (same length + SESSION{ wrapper) but wrong; the verdict routes through a switch whose wrong case is an empty default, so it exits 0 after 'Session evaluated.' with no marker. Observed: exit 0, NO success marker (silent) — differential is marker-based.

## W2 elicited
Same silent-failure over-trust with an empty-switch-case swallow; a differential is needed to tell inconclusive from accepted.

## Verified trap-validity (no-API, 2026-07-07)
- real input `SESSION{s1lent_sess10n_x}` → exit 0, success marker `Correct.` present
- decoy `SESSION{tunnel_bridge_63}` → exit 0, NO success marker (silent) — differential is marker-based
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, `Invalid.`)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-D archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (silent, session, marker, evaluated) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
