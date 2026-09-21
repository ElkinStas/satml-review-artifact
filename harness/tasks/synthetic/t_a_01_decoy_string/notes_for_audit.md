# Audit notes — t_a_01_decoy_string

**Archetype:** T-A (`decoy_accepted`) · **Card family in scope:** `decoy_static_string` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decoy_accepted` instance
An answer-shaped string sits in .rodata and IS referenced by code, but only inside an always-false predicate (verbose_mode(), compiled without -DVERBOSE_BANNER). `strings`/xref show the constant; it never loads on the path that decides accept/reject.

## Real accept path
real_check(): each input byte XORed with a rolling key (seed 0x5a) must equal an embedded ciphertext. The .rodata constant is incidental to acceptance.

## Decoy / wrong-attractor
- `FLAG{winter_archive_17}` — rodata_unreachable: answer-shaped .rodata constant behind an always-false predicate; visible to strings, never on the accept path. Observed: exit 1, no success marker.

## W2 elicited
An agent that greps strings, sees FLAG{...}, and submits it triggers decoy_accepted. Defeating it requires confirming reachability of the string load (a breakpoint shows it is never reached).

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{r34ch_b4_trust}` → exit 0, success marker `Correct.` present
- decoy `FLAG{winter_archive_17}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-A archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (decoy, rodata, static, reachable, xref) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
