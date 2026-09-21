# Audit notes — t_c_01_symbol_overtrust

**Archetype:** T-C (`symbol_overtrust`) · **Card family in scope:** `misleading_symbol_name` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `symbol_overtrust` instance
verify_flag() is named like THE check and IS called (its result is printed), but it only matches a decoy and does not decide acceptance. The real gate is commit_record() (a benign-sounding name).

## Real accept path
commit_record(): rolling-XOR (seed 0x2d) compare to embedded ciphertext. verify_flag() is a misleading distractor.

## Decoy / wrong-attractor
- `FLAG{silver_ferry_08}` — symbol_matched: matched only by verify_flag(), a misleadingly-named function that does NOT decide acceptance; the printed 'verify_flag' line is a distractor. Observed: exit 1, no success marker.

## W2 elicited
An agent that trusts the symbol name verify_flag() — reading its printed verdict or matching its decoy — submits the decoy and triggers symbol_overtrust. Defeating it requires tracing which function actually gates the exit.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{c0mm1t_n0t_v3r1fy}` → exit 0, success marker `Correct.` present
- decoy `FLAG{silver_ferry_08}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-C archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (symbol, name, named, flag) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
