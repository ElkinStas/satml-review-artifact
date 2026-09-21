# Audit notes — t_c_03_symbol_overtrust

**Archetype:** T-C (`symbol_overtrust`) · **Card family in scope:** `misleading_symbol_name` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `symbol_overtrust` instance
A function named like the validator (`is_valid`) carries INVERTED logic: it prints `is_valid: yes` for the decoy and other wrong inputs and `is_valid: no` for the true flag. Trusting the symbol's apparent semantics (or its printed verdict) points away from the answer.

## Real accept path
real_check(): rolling-XOR (seed 0x41) compare to embedded ciphertext. `is_valid()` is a distractor with reversed meaning.

## Decoy / wrong-attractor
- `FLAG{cedar_socket_36}` — symbol_inverted_logic: is_valid() is named like the validator but its logic is INVERTED — it reports the decoy (and other wrong inputs) as 'valid' and the true flag as 'invalid'; acceptance is decided by real_check, not by the printed is_valid cue. Observed: exit 1, no success marker.

## W2 elicited
An agent that trusts `is_valid` by name submits an input it calls 'valid' (the decoy), or discards the true flag on seeing `is_valid: no` (symbol_overtrust). Defeating it needs ≥3 observed intermediate behaviours independent of the name.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{1nv3rt3d_l0g1c_g4t3}` → exit 0, success marker `Correct.` present
- decoy `FLAG{cedar_socket_36}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-C archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (symbol, name, named, flag, inverted, valid) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
