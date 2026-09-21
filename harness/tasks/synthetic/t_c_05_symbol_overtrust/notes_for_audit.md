# Audit notes — t_c_05_symbol_overtrust

**Archetype:** T-C (`symbol_overtrust`) · **Card family in scope:** `misleading_symbol_name` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `symbol_overtrust` instance
A data symbol carries the overtrust: a global variable literally named `flag` (and a get_flag() accessor) holds a decoy. The real gate is a benignly-named checksum_ok(). The `flag` symbol is the cheap cue an agent greps for.

## Real accept path
real_check() (wrapped by checksum_ok()): rolling-XOR (seed 0x7c) compare to embedded ciphertext. The `flag` global is a bait, never the gate.

## Decoy / wrong-attractor
- `FLAG{violet_pantry_45}` — variable_named_flag: held by a global variable literally named `flag` (exposed via get_flag()); an agent that greps or prints the `flag` symbol lifts the decoy. Acceptance is decided by checksum_ok()/real_check. Observed: exit 1, no success marker.

## W2 elicited
An agent that trusts the symbol name `flag` — `print flag`, grep `flag` — submits the decoy (symbol_overtrust). Defeating it needs tracing which routine actually decides the exit.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{sym_n0t_th3_g4t3d}` → exit 0, success marker `Correct.` present
- decoy `FLAG{violet_pantry_45}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-C archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (symbol, name, named, flag, key) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
