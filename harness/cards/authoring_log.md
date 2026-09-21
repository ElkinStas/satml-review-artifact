# Card authoring log

Mandatory: one entry per card -- WHEN authored, by WHOM, on what BASIS, plus a leakage
attestation. Protects against post-hoc / leakage accusations.

## Scope
Entries below are for the PILOT SEED cards (`cards_pilot_seed.json`), used only for the
Week-3 exploratory dry-run. They are **NOT** the registered library. The registered library
(`cards_draft.json` -> `cards_v1.0.json`) is authored under the blinding protocol and
frozen + hashed BEFORE any main run; its per-card entries are added at that freeze.

## Pilot seed entries (authored 2026-06-05, author: Author A)
| card_id | basis | leakage attestation |
|---|---|---|
| seed_decoy_static_string    | W2 taxonomy: decoy_accepted; Nishizaka W2 (decoy/string traps) | abstract; not from any eval binary; no addresses/constants/flags |
| seed_decoy_dead_function    | W2 taxonomy: decoy_accepted (reachability) | abstract; reachability lens only; no task specifics |
| seed_misleading_symbol_name | W2 taxonomy: symbol_overtrust | abstract; algorithm-name lens; no task specifics |
| seed_transform_then_compare | W2 taxonomy: unverified_candidate_submission (encode-then-compare) | abstract; transform lens; no task specifics |
| seed_silent_validation_failure | W2 taxonomy: failed_validation_ignored (differential) | abstract; differential lens; no task specifics |
| seed_decompiler_artifact    | W2 taxonomy: decompiler_artifact_trust | abstract; ADVISORY/under-exercised (Ghidra excluded from MVP) |

Notes: actions are strict whitelist enums (see card.recommended_validation_actions); human
explanation lives in card.validation_note. family<->subtype mapping is many-to-many.


## Registered library entries (`cards_v1.0.json`) -- transcribed from per-card `provenance` at freeze (2026-07-01)

Author: Author A (Weeks 5-6, under prereg sec.5.2 blinding). Basis/attestation below are
transcribed verbatim-in-substance from each card's `provenance` block; leakage cross-checked by
the audit (`leakage_audit.md`).

**Author confirmation (Author A): ACCEPTED — 2026-07-06** — entries confirmed against the
re-frozen `cards/cards_v1.0.json` (file byte-sha256 `34fbe4c6…`, cards content-sha256 `156460bc…`).

| card_id | family | source_type / source_ids | leakage attestation (from provenance.authoring_note) |
|---|---|---|---|
| c_transform_visible_constant_is_target | transform_then_compare | taxonomy_w2 / SRC-001,SRC-002 | Abstract encode-then-compare pattern; no task-specific constants, transforms, or symbols. |
| c_transform_xor_encode_compare | transform_then_compare | general_re_knowledge / SRC-001 | Abstract XOR-then-compare; no task-specific keys, constants, or symbols. |
| c_transform_shift_rotate_compare | transform_then_compare | general_re_knowledge / SRC-001 | Abstract shift/rotate-then-compare; no task-specific parameters. |
| c_transform_encoding_layer_compare | transform_then_compare | general_re_knowledge / SRC-001 | Abstract encoding-layer pattern; no task-specific data. |
| c_transform_oneway_digest_compare | transform_then_compare | general_re_knowledge / SRC-001,SRC-003 | Abstract one-way-digest counter-case; no task-specific hashes or constants. |
| c_decoy_string_no_accept_xref | decoy_static_string | taxonomy_w2 / SRC-001,SRC-002 | Abstract decoy-string pattern; no task-specific constants, flags, functions, or addresses. |
| c_decoy_string_among_candidates | decoy_static_string | general_re_knowledge / SRC-001 | Abstract multi-decoy selection pattern; no task specifics. |
| c_decoy_success_message_string | decoy_static_string | general_re_knowledge / SRC-001 | Abstract success-message decoy; no task specifics. |
| c_decoy_format_template_string | decoy_static_string | general_re_knowledge / SRC-001 | Abstract format/template decoy; no task specifics. |
| c_dead_function_no_call_site | decoy_dead_function | taxonomy_w2 / SRC-001,SRC-002 | Abstract dead-function pattern (reachability via call graph); no task specifics. |
| c_dead_branch_constant_guard | decoy_dead_function | general_re_knowledge / SRC-001 | Abstract constant-guard dead-branch pattern; no task specifics. Distinct from opaque-predicate (computed) which is decompiler_artifact. |
| c_dead_path_after_transfer | decoy_dead_function | general_re_knowledge / SRC-001 | Abstract control-flow-dead pattern; no task specifics. |
| c_dead_vestigial_validator | decoy_dead_function | general_re_knowledge / SRC-001 | Abstract vestigial-validator pattern; no task specifics. |
| c_symbol_misleading_function_name | misleading_symbol_name | taxonomy_w2 / SRC-001,SRC-002 | Abstract misleading-function-name pattern; no task-specific symbols. Distinct from dead_function (reachability). |
| c_symbol_crypto_constant_identity | misleading_symbol_name | general_re_knowledge / SRC-001,SRC-003 | Abstract constant-as-identity over-trust; no task-specific constants. Distinct from transform_then_compare (operation on the compare path). |
| c_symbol_variable_name_semantics | misleading_symbol_name | general_re_knowledge / SRC-001 | Abstract data-symbol-name over-trust; no task specifics. |
| c_symbol_debug_metadata_trust | misleading_symbol_name | general_re_knowledge / SRC-001 | Abstract metadata-over-trust pattern; no task specifics. |
| c_silentval_rejection_ignored | silent_validation_failure | taxonomy_w2 / SRC-001,SRC-002 | Abstract rejection-ignored pattern; no task specifics. Differential-based. |
| c_silentval_silent_output_assumed_pass | silent_validation_failure | general_re_knowledge / SRC-001 | Abstract silent-output pattern; no task specifics. Differential-based. |
| c_silentval_wrong_success_marker | silent_validation_failure | general_re_knowledge / SRC-001 | Abstract wrong-marker pattern; no task specifics. Differential-based. Distinct from decoy_success_message (string-as-answer). |
| c_silentval_no_differential_established | silent_validation_failure | general_re_knowledge / SRC-001 | Abstract no-differential pattern; no task specifics. |
| c_decompiler_pseudoc_lossy | decompiler_artifact | taxonomy_w2 / SRC-001,SRC-002 | Abstract decompiler-reconstruction artifact; no task specifics. |
| c_decompiler_opaque_predicate_reachable | decompiler_artifact | general_re_knowledge / SRC-001 | Abstract opaque-predicate artifact; no task specifics. Distinct from dead_branch_constant_guard (literal/macro guard, readable). |
| c_decompiler_disasm_desync | decompiler_artifact | general_re_knowledge / SRC-001,SRC-003 | Abstract disassembly-desync artifact; no task specifics. |
| c_decompiler_data_as_code | decompiler_artifact | general_re_knowledge / SRC-001 | Abstract data-as-code artifact; no task specifics. Distinct from desync (alignment of real code). |
| c_fixation_premature_commit | comprehend_time_fixation | general_re_knowledge / SRC-001,SRC-002 | General agent-reasoning pattern (premature commitment); authored from general practice, NOT derived from any evaluation trace. Firewalled #11 candidates are not a source. |
| c_fixation_rejected_evidence_anchoring | comprehend_time_fixation | general_re_knowledge / SRC-001,SRC-002 | General agent-reasoning pattern (failure to update on disconfirmation); authored from general practice, NOT from any evaluation trace. Firewalled #11 candidates are not a source. |
| c_fixation_deepening_not_broadening | comprehend_time_fixation | general_re_knowledge / SRC-001,SRC-002 | General agent-reasoning pattern (sunk-cost / no breadth switch); authored from general practice, NOT from any evaluation trace. Firewalled #11 candidates are not a source. |

---

## W10 re-issue (2026-07-29) — static-only validation advice. NO cards added.

The `run_binary` / `trace_binary` tools left the agent tool surface, which made submission one-shot
and terminal. That silently invalidated part of A1's informational delta: 16 cards recommended
`dynamic_run_with_input`, 12 recommended `gdb_breakpoint_check`, and 4 required an accept/reject
differential — none performable any more. Advice the agent cannot carry out is not a weaker dose of
the registered treatment, it is a different treatment.

**Applied to all 28 cards** (`cards/patch_w10_static_actions.py`, assertion-guarded per field):

- `recommended_validation_actions` restricted to `manual_trace_through` / `z3_constraint_solve`.
  `ValidationActionType` is UNCHANGED — the enum keeps all four values; only card advice narrowed.
  `agent/tools/registry.py` untouched, so the tool surface and A0's prompt are identical to the
  120-run battery.
- `validation_note`, `not_applicable_when`, `misfire_risks`, `minimum_evidence_before_use` rewritten
  wherever they told the agent to run the target or set a breakpoint. All of these reach the model
  via `retrieval.format_cards_block`, so a clean action list over an un-performable note would have
  fixed nothing.
- `requires_differential` false on every card; `validate_cards.py --strict` now hard-fails on a
  `true` value and on any non-performable action.
- `silent_validation_failure` RE-SCOPED (not deleted) from silent runtime rejection to its static
  analogue. Deleting it would have dropped the family below the `>=3` floor and voided a vector.

**This edit is not fitted to any task.** It applies uniformly to every card and is driven by the tool
surface, not by any observed run outcome.

## W10b (2026-07-29) — three proposed cards REVERTED; four repairs

Three cards proposed during W10 (`c_dead_local_check_not_terminal_accept`,
`c_decompiler_success_branch_reachability_burden`, `c_fixation_failed_derivation_reverts_to_surface`)
were **reverted before any run**. Reasons, in order of severity:

1. Their SELECTION was driven by failure modes observed in the Week-9 A0 battery. The text carried no
   instance detail, but choosing which patterns to add on the basis of eval outcomes is circular
   regardless of how general the wording is.
2. Two of them cited **SRC-006** (`tasks/synthetic/archetype_specs.md`). `cards/authoring_sources.md`
   lists SRC-006 as PERMITTED; the archetype document itself forbids it:

   > archetype_specs.md §1.2 — "The archetypes and the Pattern-RAG card library **must not be derived
   > from each other.** Their only shared ancestor is the W2 subtype taxonomy. ... the card author
   > must **not** see archetype source."

   The two documents contradict each other. Until the PI resolves it, `validate_cards.py --strict`
   rejects any card citing SRC-006.

Four repairs to the pre-existing 28, all on the same firewall basis (not on run outcomes):

| card | repair |
|---|---|
| c_symbol_crypto_constant_identity | dropped the keyword naming a specific cipher; the archetype source names that same cipher and ties the constant-identity variant to a real eval task's mechanism. Signal text generalised to "round constant / initialization value / substitution table". |
| c_symbol_misleading_function_name | dropped a literal example identifier taken verbatim from the T-C archetype spec; the signal now names the semantic category instead of example names. |
| c_symbol_variable_name_semantics | same treatment; one literal example name also occurred in eval ground truth. |
| c_decompiler_pseudoc_lossy | de-vendored (the named decompiler appears in the archetype source and is not on the agent's tool surface, so the advice was also un-performable); one incoherent `not_applicable_when` clause in c_dead_function_no_call_site fixed at the same time. |

Post-repair scans over all 28 cards, every string field, recursive: **instance-token hits NONE,
archetype-source hits NONE, cards citing SRC-006 NONE.**
