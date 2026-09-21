# Deviation Registry

Any deviation from the **pre-main lock** (end of Week 7) onward is logged here
and reproduced verbatim in the paper appendix on submission.

## Format

Each entry:

```
### YYYY-MM-DD — short title
**Scope:** [section / arm / metric / dataset / cards / scaffold / annotation / budget]
**Deviation:** what was changed vs the pre-main lock prereg
**Rationale:** why
**Expected impact:** on which result / claim, magnitude, direction
**Detected by:** [self / second annotator / reviewer / pipeline check]
```

## Severity tiers

- **Cosmetic** — wording, formatting, file location. No analytical impact.
- **Operational** — implementation detail (logging format, run order). Confirmed no change to outcomes.
- **Methodological** — affects what is measured, how, or on what. Must be flagged in paper main text.

---

## Entries

_Deviations are logged here from the **pre-main lock** (end of Week 7) onward. Pre-lock prereg revisions — including
v0.4→v0.6 (H4→DE1 in v0.3; the two-stage W2 framing in §6.4; the §6.1 final-submit clause; the
`comprehend_time_fixation_rate` secondary metric in §8.4; and the budget-basis change to
`budget_tokens`) — are recorded in the prereg changelog §0.x, not here._

<!-- Add entries below in reverse chronological order (newest first). -->

### 2026-09-XX — Cross-model battery restricted to the 12 reachability binaries, selected post hoc
**Scope:** dataset / secondary cross-model replication, §5.3
**Severity:** Methodological
**Deviation:** The secondary GPT-5.2 battery was run on 12 of the 24 frozen held-out binaries (the
T-E reachability replicas) rather than on the full pool. The subset was chosen **after** the Claude
held-out outcomes were available, on the basis of its A0 recurrence: 23/60 wrong submissions across
11/12 tasks, against 6/30 on polarity and 2/30 on named-checker. Binaries, card library, retrieval
policy, A2 evidence policy, scorer, prompts and run limits were reused unchanged; only the provider
API adapter differs. No full 24-task GPT battery was run.
**Rationale:** The cross-model question is whether the relation-level mechanism and the two
interventions behave the same way on a second substrate. Under a fixed budget, running it where the
baseline signal is strongest gives the most informative test. Selecting the subset on observed
outcomes is the cost of that choice and is declared rather than presented as pre-specified.
**Expected impact:** Cross-model claims apply only to the shared reachability motif, not to the
named-checker or polarity layouts. Because the subset was chosen on observed Claude outcomes, the
GPT battery is a stress test rather than a pre-specified confirmatory replication, and is reported
as such in the paper (design section, cross-model section, limitations). No Claude result is
affected: the 360 Claude trajectories were complete and frozen before the subset was chosen.
**Detected by:** self (deliberate; declared before the GPT battery was executed).

### 2026-0X-XX — T-F class dropped from the frozen held-out pool; its screen is inconclusive, not negative
**Scope:** dataset / mechanism selection, held-out pool composition
**Severity:** Methodological
**Deviation:** The held-out design specified three motif classes (T-C, T-E and a new T-F
observation-to-model binding class), 12 binaries each, with T-F gated behind a pre-specified
viability screen. The screen produced 0 errors in 15 baseline attempts and the class was not
promoted. Inspection of the screen instances afterwards showed that they **did not implement the
intended mechanism**: they gated on a 32-bit digest, which a collision search resolves without ever
engaging the observation-to-model binding relation. The screen is therefore recorded as
**inconclusive, not as a negative result** about the mechanism. Its trajectories are retained as
superseded runs and enter no aggregate.
**Rationale:** The instances failed the compiled-artifact admission criteria (no nuisance cue may
resolve the task before the target relation must be examined). Promoting them would have measured
the shortcut, not the mechanism. The alternative — re-tuning the construction until the desired
failure appeared — was rejected.
**Expected impact:** The frozen confirmatory pool contains two motif families and 24 binaries rather
than three families and 36. The observation-to-model boundary therefore carries no confirmatory
measurement and is reported qualitatively only, from the circular-validation, semantic-anchor
misbinding, public post-hoc-fitting and held-out transcription cases.
**Detected by:** self (review of the screen instances against the artifact-admission criteria).

### 2026-07-29 — Card library re-issued for a static-only tool surface, then trimmed (28 → 25 cards)
**Scope:** cards (A1 treatment definition), §5.2
**Severity:** Methodological
**Deviation:** The registered library was re-opened after the 2026-07-06 candidate-freeze and, after
several corrective passes, ended at **25 cards / 6 families**. Net changes from the frozen 28:
(a) all `recommended_validation_actions` restricted to the two actions performable without executing
the target (`manual_trace_through`, `z3_constraint_solve`); (b) `requires_differential` retired on
every card; (c) the `silent_validation_failure` family re-scoped from a runtime reading to its static
analogue; (d) four cards de-referenced from firewalled/eval-adjacent identifiers (a named cipher, two
literal example symbols, a named decompiler) with no change to the pattern taught; (e) the
`comprehend_time_fixation` family (3 cards) REMOVED. No cards were net added. Final file byte-sha
`4f060500b4d7419d5555065ea2e7d77eaeee90f23e72364c7ede57af66dd603b`, content-sha `218507978b01cdaa64bd7c0be084e0f44ea7d0a010bd90b008f90156beac29b2`.
**Rationale:** `run_binary` / `trace_binary` left the agent tool surface, so 16 cards recommended
`dynamic_run_with_input`, 12 recommended `gdb_breakpoint_check`, and 4 required an accept/reject
differential — all un-performable, i.e. a different A1 treatment, not a weaker one. During the
re-issue two contamination problems surfaced and were corrected rather than shipped: three cards
initially drafted from Week-9 A0 failure observations were reverted (selection-level leakage), and
the `comprehend_time_fixation` family was found to restate the firewalled candidates in
`cards/cards_candidates_unblinded.json` (derived from a real task's unblinded traces) and was removed.
**Expected impact:** Affects every A1/A2 result; A0 untouched (prompt surface is `system_common`
only; tool surface, task pool and run params unmodified), so the 120 A0 runs remain comparable. A1
now carries NO treatment for comprehend-time failure modes; the secondary metric
`comprehend_time_fixation_rate` (§8.4) is outcome-scored from traces and is still reported, now
without a paired treatment. Retrieval ranking is stable: 5 of 6 frozen regression vectors are
byte-identical with the 2026-07-06 lock; one permuted within the re-scoped silentval family.
**Detected by:** self (review of the Week-9 A0 battery against the post-removal tool surface;
subsequent leakage audit).

### 2026-07-29 — Card–archetype firewall: authoring_sources.md and archetype_specs.md contradict each other
**Scope:** cards, §5.2 / leakage protocol
**Severity:** Methodological
**Deviation:** `cards/authoring_sources.md` lists SRC-006 — `tasks/synthetic/archetype_specs.md` at
the abstract pattern-class level — as a PERMITTED card source, citing prereg §5.2 co-design of
abstract classes. `archetype_specs.md` §1.2 states the opposite: the archetypes and the card library
"must not be derived from each other", their only shared ancestor is the W2 taxonomy, and the card
author "must not see archetype source". No registered card had cited SRC-006 before this week; two
proposed cards did, and were reverted. `validate_cards.py --strict` now rejects SRC-006 as a hard
error, i.e. the stricter document is enforced pending resolution.
**Rationale:** The two readings differ in what A1-beats-A0 means on a synthetic archetype. Under the
permissive reading it is a legitimate treatment effect; under §1.2 it is tautological, because the
card would encode the trap the binary was built around. This has to be settled explicitly and stated
in the paper, not left to whichever document a reader happens to open.
**Expected impact:** None on any result yet — no registered card cites SRC-006 and none ever did.
If §1.2 is upheld, three cards whose families were carved close to archetype boundaries should be
re-examined for the same issue. If §5.2 is upheld, `archetype_specs.md` §1.2 must be amended and the
synthetic-stratum claims scoped accordingly.
**Detected by:** self (card audit, 2026-07-29).

### 2026-07-29 — Three proposed cards reverted; no task reclassified
**Scope:** cards / dataset
**Severity:** Operational
**Deviation:** Three cards drafted during the W10 re-issue were reverted before any run. An earlier
draft of this registry designated `t_c_01/02/04`, `t_e_01/02/04` and `ovl_11_jormugandr` as
development evidence, because those cards had been selected on the basis of failures observed on
them. With the cards reverted, nothing derived from those observations enters the treatment, and the
designation is WITHDRAWN — all seven tasks remain main-run eligible.
**Rationale:** Inspecting run outcomes does not by itself contaminate a task; feeding those outcomes
back into the treatment does. The W10 static-advice rewrite that remains in the library was driven by
the tool surface, applies to every card uniformly, and is independent of any task outcome.
**Expected impact:** None. Restores the task set to its pre-W10 state.
**Detected by:** self (PI direction: cards must be general-purpose advice, never fitted to tasks).


<!-- Example:
### 2026-MM-DD — Switched primary model from Sonnet 4.6 to Opus
**Scope:** Section 4.1, primary model
**Deviation:** The pre-main lock prereg specified Sonnet 4.6 as primary; switched to Opus after pilot.
**Rationale:** A0 success@3 = 0.18 on calibrated synthetic, below floor of 0.30.
**Expected impact:** all main-run results; cost ~$430 instead of ~$300. No claim weakened.
**Detected by:** self (pilot acceptance criteria).
-->

### 2026-07-29 — Preflight lock re-anchored to the post-W9 tree (6 keys)
**Scope:** integrity locks / preflight, all arms
**Severity:** Operational
**Deviation:** `preflight_lock.json` still carried the pre-W9 values for six anchors
(`pool_hash_sha256`, `tool_surface_sha256`, `prompts_sha256`, `run_params_sha256`,
`execution_path_sha256`, `runtime_code_sha256`); it and the two hardcoded anchors in
`agent/test_preflight.py` were re-computed against the current tree. `cards_sha256` was re-anchored
separately with the card re-issue and is not in this set. Per-key provenance is in
`preflight_lock.json` `_reanchor_log.W10e`; the drivers are the W9 oracle removal (tool surface, run
params, exec path, prompts), the W9 pool cleanup (pool hash, re-anchored to on-disk binaries that are
byte-identical to the A0-run set), and the W10 A2 gate module (runtime code, A2-only).
**Rationale:** The lock had been silently drifting since W9. Re-anchoring deliberately, with a logged
reason per key, is preferable to a blanket `--regenerate` (which would bless the drift invisibly) and
to leaving preflight red (which trains everyone to ignore it). None of the six reflects a change to
the A0 execution path: A0's prompt surface, tool surface, retrieval code and task binaries are
byte-identical to what its 120 recorded runs used (verified against the trace metadata).
**Expected impact:** None on results. Restores preflight to a green, meaningful baseline so a future
unintended change fails closed.
**Detected by:** self (full-repo regression after the W10 card/scaffold work).
