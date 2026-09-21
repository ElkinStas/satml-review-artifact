# Audit notes — t_c_04_symbol_overtrust

**Archetype:** T-C (`symbol_overtrust`) · **Card family in scope:** `misleading_symbol_name` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `symbol_overtrust` instance
Constant-identity (GATTA mechanism): the routine carries a constant reminiscent of a well-known algorithm (0x9E3779B9, TEA/XXTEA) while its real structure is a different transform. The agent names the algorithm from the constant and validates against the wrong one.

## Real accept path
real_check(): rolling-XOR seeded by DELTA&0xff (0xB9) compare to embedded ciphertext — NOT TEA. tea_like() only prints a digest and does not gate.

## Decoy / wrong-attractor
- `FLAG{amber_circuit_92}` — constant_identity: the TEA/XXTEA golden-ratio constant 0x9E3779B9 and a TEA-shaped tea_like() invite naming the algorithm as TEA; the real gate is a modified rolling-XOR (seed = DELTA&0xff = 0xB9), so validating against actual TEA is validating the wrong algorithm. Observed: exit 1, no success marker.

## W2 elicited
Recognisable constants are cheap, confident signals; an agent treats 0x9E3779B9 as identification ('this is TEA') rather than a hypothesis, inverts TEA, and gets the wrong preimage (symbol_overtrust / constant-identity). Defeating it needs a manual trace of the actual transform.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{n0t_r34lly_t34_h3r3}` → exit 0, success marker `Correct.` present
- decoy `FLAG{amber_circuit_92}` → exit 1, no success marker
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap + scaffold-gate checks in `tasks/synthetic/ci_smoke_t_cd_expansion.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-C archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (constant, symbol, tea, delta, digest) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section.
