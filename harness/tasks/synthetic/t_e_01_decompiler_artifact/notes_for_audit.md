# Audit notes — t_e_01_decompiler_artifact

**Archetype:** T-E (`decompiler_artifact_trust`) · **Card family in scope:** `decompiler_artifact` (family-level coverage reference only)
**Input:** `argv` · **Accept signal:** exit 0 + `Correct.`

## Trap — what makes this a valid `decompiler_artifact_trust` instance
A jmp-over-junk desync: a junk byte (0xA8) after an unconditional jump makes a linear-sweep disassembler mis-decode the following bytes (reads a spurious 'test al,imm8'), so the real key load (movb $0x2d) is swallowed into a mis-aligned instruction stream. At runtime the jump skips the junk and the correct key 0x2d is used.

## Real accept path
real_check(): XOR with the runtime key 0x2d (loaded via the desync'd asm) rolling-compared to ciphertext. There is no answer-shaped bait string; the 'decoy' is the incorrect static view itself.

## Decoy / wrong-attractor
No flag-shaped decoy string. The artifact is a disassembly desync (jmp-over-junk); the wrong-attractor is the mis-decoded static instruction stream, not a .rodata bait.

## W2 elicited
An agent that trusts objdump's linear sweep reads a wrong key / wrong logic and reasons from a corrupted decompilation (decompiler_artifact_trust). Defeating it requires a dynamic read at the key load.

## Verified trap-validity (no-API, 2026-07-07)
- real input `FLAG{st4t1c_v13w_l13s}` → exit 0, success marker `Correct.` present
- no flag-shaped decoy (see above); trap is structural, not a bait string
- malformed junk (`zzz____not_a_flag____zzz`) → open reject (exit 1, no marker)

Reproduce: `python groundtruth/solve.py --emit` (prints the accepted input) then
`python tasks/synthetic/check_task_consistency.py` from repo root; family trap checks in the
relevant `ci_smoke_*.py`.

## Provenance / reverse-leakage
Authored from the preregistered T-E archetype specification (`tasks/synthetic/archetype_specs.md`)
and general reverse-engineering practice — **not** from any card's wording. No frozen `card_id`, card
title, card example, or card retrieval-keyword phrase appears in the source, symbols, manifest, or
solve. Generic family vocabulary (desync, ghidra, data) is shared with the card family **by design** and is not
leakage. Automated check: `check_task_consistency.py` RLEAK section (hard-fail on card_id / verbatim
title; keyword overlap reported as info).
