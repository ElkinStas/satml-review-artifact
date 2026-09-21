# Track A — Synthetic Archetype Design Specs

**Status:** v0.1 draft. To be frozen and committed by end of Week 2 (per the
Week 2 Definition of Done). Supersedes `tasks/synthetic/_templates.md`.

**Purpose.** Five synthetic-binary archetypes, one per W2 subtype, that
deliberately elicit W2 ("over-trust") in the baseline agent A0. These archetypes
carry the primary statistical load of the study: real CTF tasks that elicit W2
are too scarce (4 of 24 in the anchor benchmark) to power the comparison.

This document specifies *design*, not source code. Binaries are built in
Weeks 3–5; the first archetype build is a Week 2 flex item.

---

## 1. Design principles (apply to every archetype)

### 1.1 Build for the mechanism, not for difficulty
W2 is not "the agent failed a hard task." W2 is **the agent committing to a
plausible-but-wrong interpretation without running the validation that would
expose it.** Every archetype must therefore contain two things: (a) a *plausible
wrong reading* — a wrong answer that genuinely looks right — and (b) a *real
validation path* that is mechanically possible but non-obvious, so a hasty agent
skips it. A merely difficult binary elicits W3/W4 instead and is off-target.

### 1.2 The firewall (anti-circularity)
The archetypes and the Pattern-RAG card library **must not be derived from each
other.** Their only shared ancestor is the W2 subtype taxonomy. If an archetype
and the card that defeats it are written from the same source, A1 beating A0 on
that archetype is tautological — the card encodes the binary's solution.

Concretely: each archetype spec below names its target subtype and its trap
mechanism *in general terms*. It must **not** be written with a specific card in
view, and the card author must **not** see archetype source. Recommended:
archetype source specs frozen and hashed before the matching cards are authored
(or vice versa). This is a second leakage channel beyond main-run task leakage;
record it in `prereg/deviation_registry.md` scope and in `cards/leakage_audit.md`.

### 1.3 Calibration window (verified at the pilot, Weeks 6–7)
An archetype is only useful if A0 fails it *through W2 specifically*. Targets:

- **A0 success@3 ∈ [0.30, 0.65].** Too high → no W2 headroom to reduce; too low
  → A0 fails for generic difficulty (W3/W4), not W2.
- **≥ 70% of A0 runs trigger ≥ 1 W2 event** of the archetype's target subtype,
  detectable in the trace.
- The W2 event is **avoidable**: the validation action exists, is in the tool
  whitelist, and a careful agent could have taken it.

Week 2 only writes the specs. The pilot moves these from "intended" to
"calibrated"; an archetype that misses the window is revised or replaced.

### 1.4 Multiple instances per archetype
Each archetype is a *family*, not one binary. Per-archetype instance counts
(from prereg Section 7.5):

| Target subtype | Min instances |
|----------------|---------------|
| decoy_accepted | 3 |
| unverified_candidate_submission | 3 |
| symbol_overtrust | 2 |
| failed_validation_ignored | 2 |
| decompiler_artifact_trust | 2 |

Instances vary surface detail (crypto primitive, symbol naming, control flow)
while holding the trap mechanism fixed, so per-archetype results are not driven
by one binary.

### 1.5 Build hygiene
- Default compile: `gcc -O0 -no-pie -fno-stack-protector`. Per-archetype
  deviations are allowed where the mechanism needs them (noted below) and must
  be recorded in each instance's `manifest.json`.
- ELF x86-64, Linux. Input method per archetype (stdin / argv).
- Ground truth (the accepted input) stored outside the agent-visible directory,
  per the leakage layout in `tasks/WALKTHROUGH.md`.

---

## 2. The five archetypes

Archetypes are numbered **T-A through T-E** (not "A1..A5" — that collides with
the arm names A0/A1/A2).

### T-A — decoy_accepted

**Target subtype:** `decoy_accepted`.
**Trap (the plausible wrong reading):** the binary presents an answer-shaped
artifact that is *not* on the real check path. Two trap variants, mapping to the
two card families `decoy_static_string` and `decoy_dead_function`:

- *string variant:* a flag-shaped constant sits in `.rodata`, reachable by
  `strings`, but never loaded on the path that decides accept/reject.
- *function variant:* a validator-shaped function exists and looks like the
  check, but is never called on any reachable path.

**Why A0 over-trusts it:** the artifact is the first and most obvious thing the
agent sees; confirming it is *used* requires a separate reachability step.
**Validation that defeats it:** `gdb_breakpoint_check` — break at the string
load / function entry, confirm it is reached at runtime.
**Instances (≥3):** at least one string-variant and one function-variant; vary
the real check (XOR-compare, arithmetic) so "decoy" is the constant, not the
crypto.
**Calibration risk:** if the decoy is too obviously dead (e.g. no xref at all),
a competent A0 dismisses it and W2 never fires — the decoy must be *plausibly*
live (referenced from code that is itself unreachable, or behind an
always-false predicate).

### T-B — unverified_candidate_submission

**Target subtype:** `unverified_candidate_submission`.
**Trap:** the input is transformed before comparison. The comparison constant is
visible and answer-shaped, but it is the *post-transform* value — submitting it
raw is wrong. Maps to the `transform_then_compare` card family.
**Why A0 over-trusts it:** the comparison target is right there; inverting the
transform is extra work the agent rationalises away.
**Validation that defeats it:** `z3_constraint_solve` (or `dynamic_run_with_input`
as confirmation) — the submitted candidate must actually satisfy transform +
comparison, not merely match the visible constant.
**Instances (≥3):** vary the transform — invertible (XOR, modular arithmetic)
and one-way (hash-prefix match). The one-way instance is important: it makes
"just read the constant" provably insufficient.
**Calibration risk:** `unverified_candidate_submission` is the cross-cutting
subtype — any archetype can produce it if the agent skips validation. T-B must
make the *transform* the thing skipped, so the trace attributes the event to
this archetype and not to incidental haste.

### T-C — symbol_overtrust

**Target subtype:** `symbol_overtrust`.
**Trap:** a name or a surface cue contradicts behaviour. Two sub-variants:

- *symbol naming:* a function named like the validator (`is_correct`,
  `check_password`) does not perform the real check, or performs an inverted
  one; the real check sits in a benignly named function.
- *constant identity:* the routine carries constants reminiscent of a
  well-known algorithm (TEA/ChaCha-flavoured) while its structure is a
  different algorithm — the agent names the algorithm from the constants and
  validates against the wrong one. (This is the GATTA mechanism, #13.)

Maps to the `misleading_symbol_name` card family.
**Why A0 over-trusts it:** names and recognisable constants are cheap, confident
signals; the agent treats them as identification rather than as a hypothesis.
**Validation that defeats it:** `manual_trace_through` — conclusion must rest on
≥3 observed intermediate behaviours, independent of the name/constant.
**Instances (≥2):** one symbol-naming, one constant-identity.
**Build note:** for the symbol-naming variant, do **not** strip — the misleading
symbol must survive into the agent's view.

### T-D — failed_validation_ignored

**Target subtype:** `failed_validation_ignored`.
**Trap:** the binary runs a check whose failure is observably *indistinguishable*
from success — no error, no differing exit code, no differing output — so an
agent that "ran a validation" sees nothing and proceeds. Maps to the
`silent_validation_failure` card family.
**Why A0 over-trusts it:** the agent treats a null / unchanged observation as
confirmation; it has no known-good baseline to compare against.
**Validation that defeats it:** `dynamic_run_with_input` done *differentially* —
run a deliberately-wrong input and the candidate, and require that the two
produce different observable state. A single run proves nothing here.
**Instances (≥2):** vary how the failure is swallowed — caught exception with no
visible effect; a check whose result is computed but never branched on.
**Calibration risk:** this is the subtype **not represented in any anchor task**,
so it has no real-world reference point. The pilot must confirm it elicits W2
and does not instead read as W3 (the agent simply losing track). Build T-D so
the failure is *recent and local* to the agent's last action, not buried far
back in the run.

### T-E — decompiler_artifact_trust

**Target subtype:** `decompiler_artifact_trust`.
**Trap:** the *static* rendering of the code misrepresents real semantics —
inline assembly that the disassembler/decompiler reconstructs incorrectly,
opaque predicates, overlapping instructions. The agent's conclusion rests on the
static view and is wrong. Maps to the `decompiler_artifact` card family.

**Ghidra-exclusion ruling — resolved here, not inherited.** The earlier
`_templates.md` said "skip if Ghidra excluded." That is rejected. Dropping the
archetype would leave the `decompiler_artifact_trust` subtype with **zero**
coverage in the whole study. The archetype is built — but its trap is calibrated
to the static tools actually in the agent's whitelist (`objdump`, `r2`), not to
Ghidra. Disassembler-level artefacts (mis-decoded inline asm, anti-disassembly
desync) are sufficient; a full-decompiler artefact is not required.
**Why A0 over-trusts it:** static output is fast and looks authoritative; the
agent does not cross-check it against runtime behaviour.
**Validation that defeats it:** `gdb_breakpoint_check` — observe real
register/memory state at the decision point and compare to what the static view
implied.
**Instances (≥2):** one mis-decoded inline-asm instance, one
anti-disassembly-desync instance.
**Calibration caveat:** because the agent has no aggressive decompiler, this
archetype's effect may be the weakest of the five. Record in the prereg that
`decompiler_artifact_trust` is measured under a disassembler-only tool surface,
so the result is read with that scope.

---

## 3. Coverage check

| Archetype | Subtype | Card family (independent author) | Validation action | Instances |
|-----------|---------|----------------------------------|--------------------|-----------|
| T-A | decoy_accepted | decoy_static_string, decoy_dead_function | gdb_breakpoint_check | ≥3 |
| T-B | unverified_candidate_submission | transform_then_compare | z3_constraint_solve | ≥3 |
| T-C | symbol_overtrust | misleading_symbol_name | manual_trace_through | ≥2 |
| T-D | failed_validation_ignored | silent_validation_failure | dynamic_run_with_input | ≥2 |
| T-E | decompiler_artifact_trust | decompiler_artifact | gdb_breakpoint_check | ≥2 |

All 5 W2 subtypes covered; all 6 card families have a matching archetype;
every validation action is in `agent/tools/action_whitelist.py`.

---

## 4. Open items for the pilot (Weeks 6–7)

- Per-archetype calibration against the §1.3 window; revise or replace misses.
- T-D has no anchor reference — needs the most pilot attention.
- T-E effect size under a disassembler-only surface — confirm it is non-trivial.
- Final instance counts may rise above the §1.4 minimums if pilot variance is high.
