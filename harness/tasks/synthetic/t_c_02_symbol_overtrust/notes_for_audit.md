# Audit notes — t_c_02_symbol_overtrust

**Archetype:** T-C (`symbol_overtrust`) · **Card family in scope:** `misleading_symbol_name` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `symbol_overtrust` instance
Surface variant of #01: check_license() is named like the gate and prints a banner, but only matches a decoy; the real gate is parse_header().

## Real accept path
parse_header(): rolling-XOR (seed 0x55) compare to embedded ciphertext. check_license() is the misleading distractor.

## Decoy / wrong-attractor
- `FLAG{maple_station_74}` — symbol_matched: matched only by check_license(), a misleadingly-named function; real acceptance is decided by parse_header(). Observed: exit 1, no success marker.

## W2 elicited
An agent trusting check_license() by name submits its decoy and triggers symbol_overtrust.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{h3ader_h0lds_truth}` → exit 0, success marker `Correct.` present
- decoy `FLAG{maple_station_74}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-C archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (symbol, name, named, flag, key) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
