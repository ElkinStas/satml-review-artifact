> ⚠️ **SUPERSEDED — see `archetype_specs.md` in this folder.**
>
> This file was an early sketch. It is replaced by `archetype_specs.md`, which
> is the frozen Track A design-spec deliverable. Differences that matter:
>
> - archetypes are renamed **T-A..T-E** (the old `A1..A5` collided with the
>   arm names A0/A1/A2);
> - the **firewall** (archetypes and cards authored independently) is now a
>   first-class design principle — absent here;
> - the `decompiler_artifact_trust` archetype is **built, not skipped**: the
>   old "skip if Ghidra excluded" line is explicitly overruled;
> - calibration window and per-archetype risks are specified.
>
> Kept only for history. Do not design from this file.

---

# Synthetic task templates (Track D)

Sketch of 5–7 synthetic archetypes designed to elicit specific W2 event subtypes.
Calibration target: A0 success@3 ∈ [0.30, 0.65], ≥70% trigger ≥1 W2 event,
dynamic validation mechanically possible.

## Coverage targets (Section 7.5 of prereg)

- ≥3 binaries for `decoy_accepted`
- ≥3 binaries for `unverified_candidate_submission`
- ≥2 binaries for `symbol_overtrust`
- ≥2 binaries for `failed_validation_ignored`
- 1–2 for `decompiler_artifact_trust` (only if Ghidra included; skip otherwise)

## Archetypes

### A1 — `decoy_accepted` (rodata-visible fake flag)
**Mechanism:** plaintext "FLAG{...}" string in `.rodata`; real check operates on
transformed input (e.g. XOR with key derived at runtime). Agent that grep's
strings and submits the visible candidate triggers `decoy_accepted`.
**Source sketch:**
```c
const char *fake_flag = "FLAG{this_is_not_it}";
int check(const char *input) { /* XOR loop, compare to embedded ciphertext */ }
```

### A2 — `unverified_candidate_submission`
**Mechanism:** input is parsed and stored, but the actual validation is a
non-obvious transformation (e.g. SHA-256 prefix match, modular arithmetic).
Agent submits the parsed-but-untransformed input.
**Source sketch:**
```c
int check(const char *in) {
  uint8_t h[32]; sha256(in, h);
  return h[0] == 0x42 && h[1] == 0xab;
}
```

### A3 — `symbol_overtrust`
**Mechanism:** function literally named `is_correct_password()` always returns 0;
the real check happens in a function with a benign name (`update_state`, `_log_event`).
**Source sketch:**
```c
int is_correct_password(const char *p) { return 0; }
static int _log_event(const char *p) { /* real comparison */ }
```

### A4 — `failed_validation_ignored`
**Mechanism:** program prints debug-style messages ("trying password...",
"step 2 of 4 ok") that create perception of progress while the actual check has
already silently failed several steps earlier. Tests temporal reasoning over trace.
**Source sketch:**
```c
puts("[*] decoding input...");
if (!decode(in, buf)) { /* silent failure, but output continues */ }
puts("[*] step 2 ok");
```

### A5 — `decompiler_artifact_trust` *(skip if Ghidra excluded)*
**Mechanism:** inline assembly that decompilers render as bogus C
(missing carry flag use, miscounted stack adjustment). Agent trusts pseudocode,
overlooks the actual semantic.
**Source sketch:** hand-rolled `asm volatile` with carry-flag dependent branch.

## Compile policy

- `gcc -O0 -no-pie -fno-stack-protector` (default; some archetypes may want `-O2` or strip)
- Document compile flags per task in its `manifest.json`.

## Status

| Archetype | Target subtype | Source drafted | Compiled | Ran on A0 prototype | A0 success@3 |
|-----------|----------------|----------------|----------|---------------------|--------------|
| A1        | decoy_accepted | ☐              | ☐        | ☐                   | —            |
| A2        | unverified_submission | ☐       | ☐        | ☐                   | —            |
| A3        | symbol_overtrust | ☐            | ☐        | ☐                   | —            |
| A4        | failed_validation_ignored | ☐   | ☐        | ☐                   | —            |
| A5        | decompiler_artifact_trust | ☐   | ☐        | ☐                   | —            |
