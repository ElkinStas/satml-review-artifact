# Audit notes — t_e_03_decompiler_artifact

**Archetype:** T-E (`decompiler_artifact_trust`) · **Card family in scope:** `decompiler_artifact` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decompiler_artifact_trust` instance
Anti-disassembly desync (variant of #01): a junk byte (0x3C) after an unconditional jump makes a linear-sweep disassembler mis-decode the following bytes and swallow the real key load. At runtime the jump skips the junk and key 0x5c is used.

## Real accept path
real_check(): XOR with the runtime key 0x5c (loaded via the desync'd asm), rolling-compared to embedded ciphertext. No answer-shaped bait string; the wrong-attractor is the mis-decoded static view.

## Decoy / wrong-attractor
No flag-shaped decoy string (T-E desync): the wrong-attractor is the mis-decoded static disassembly, not a .rodata bait.

## W2 elicited
An agent that trusts objdump's linear sweep reads a wrong key/logic and reasons from a corrupted disassembly (decompiler_artifact_trust). Defeated by a dynamic read at the key load.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{jmp_0v3r_junk_2}` → exit 0, success marker `Correct.` present
- no flag-shaped decoy (desync artifact); objdump linear-sweep mis-decodes the key load
- malformed junk (`zz_not_a_flag_zz`) → open reject (exit 1)

Reproduce: `python groundtruth/solve.py --emit` then `python tasks/synthetic/check_task_consistency.py`
from repo root; family trap checks in tasks/synthetic/ci_smoke_t_be_expansion.py.

## Provenance / reverse-leakage
Authored from the preregistered T-E archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (desync, disasm, jmp, junk) is shared with the card family by design and is not leakage.
