# Card schema — registered library (v2)

Schema for the **registered** Pattern-RAG library (`cards_draft.json` → `cards_v1.0.json`),
authored in Week 5a under the prereg §5.2 blinding protocol and frozen + hashed before any main
run. The pilot seed (`cards_pilot_seed.json`) uses the thin v1 schema; this v2 schema is a
**superset** — every v1 field is kept, and the new fields encode the per-card structure agreed
for the main library (observable cue / misleading vs better interpretation / validation /
counter-indications / misfire) plus an explicit `provenance` block.

Design decisions fixed before authoring:

- **The new fields are ADVISORY (prompt block) only. The A2 gate is unchanged** — final submit
  still requires an audited accepting `run_binary` on the exact candidate. In particular
  `minimum_evidence_before_use` is advisory guidance, **not** enforced by the controller
  (enforcing it would change the scaffold + prereg — out of MVP scope).
- **No new canonical family.** Reachability/control-flow traps are distributed into
  `decoy_dead_function` (dead/unreachable success branches) and `decompiler_artifact`
  (opaque predicates / control-flow lies), so the 6 canonical families are unchanged and MC1 /
  `SUBTYPE_TO_FAMILY` / manifest `expected_pattern_family` need **no** edits. The only new family
  is `comprehend_time_fixation`, which is a registered SECONDARY family (not in the canonical MC1
  map; authored from clean general RE practice and evaluated via the secondary metric — see the
  family plan).

## Fields

Required unless marked optional. Types: `str`, `[str]` (list of strings), `bool`, `enum`, `obj`.

| field | type | role |
|---|---|---|
| `card_id` | str | unique id, snake_case, prefix `c_` for registered cards |
| `family` | enum | one of the 7 families (see family plan); the pattern class |
| `title` | str | one line, human-readable |
| `applicability_signal` | str | **observable cue** — the concrete signal that should make this card retrievable / applicable. Keep it NARROW (this is what BM25 + the agent key on). |
| `retrieval_keywords` | [str] | BM25 signal terms drawn from the cue (curated; up-weighted ×3 in the ranker) |
| `mechanism` | str | why the trap works — the conflation/error it exploits |
| `misleading_interpretation` | str | **what the agent typically wrongly concludes** from the cue |
| `better_interpretation` | str | **the cautious, correct read** — what to believe instead before evidence |
| `recommended_validation_actions` | [enum] | instrumental check(s) from the whitelist (`dynamic_run_with_input`, `gdb_breakpoint_check`, `z3_constraint_solve`, `manual_trace_through`) |
| `validation_note` | str | human explanation of the validation (free text; the enum carries the machine action) |
| `requires_differential` | bool | true if the check needs a wrong-input baseline (e.g. silent-validation cards) |
| `not_applicable_when` | [str] | **counter-indications** — concrete conditions under which the card should NOT fire/apply |
| `misfire_risks` | [str] | **how the card itself can cause a new failure** (e.g. a "constants ⇒ known cipher" hint inducing symbol_overtrust if misapplied) |
| `minimum_evidence_before_use` | [str] | advisory: evidence that should exist before acting on the card (NOT gate-enforced) |
| `grounding` | enum | `well_grounded` \| `advisory_under_exercised` \| `candidate_unblinded` |
| `provenance` | obj | see below |
| `notes` | str (optional) | authoring notes (kept out of the prompt block) |

### `provenance` (obj)
| key | type | role |
|---|---|---|
| `source_type` | enum | `general_re_knowledge` \| `taxonomy_w2` \| `public_writeup_disjoint` \| `textbook` \| `non_eval_example` \| `candidate_unblinded` |
| `source_ids` | [str] | SRC-IDs from `cards/authoring_sources.md` (the source registry) |
| `eval_overlap` | enum | `none` \| `firewalled` (firewalled only for `candidate_unblinded` cards; never enters the registered library) |
| `authoring_note` | str | one line attesting abstraction; "no task-specific constants/functions/addresses/transform-params". |

## Two acceptance tests every registered card must pass (authoring gate)

1. **Counterfactual.** Is there a plausible trace where an agent **with** the card behaves
   differently from one **without** it? A card that is merely *true* but never changes behaviour
   is inert noise — cut it. (It still competes in BM25 top-k, so inert cards have a real cost.)
2. **Provenance.** Could a skeptic say "this was lifted from an eval task"? If yes, rewrite or
   drop. Clean-but-inert and strong-but-leaked both **fail**. In the trade-off "slightly stronger
   but closer to a task / slightly weaker but certainly clean" — **always clean** (a weak library
   is recoverable; a leaked one ends the study).

`validate_cards.py` checks the schema + a leak-pattern scan mechanically; the two tests above are
the human authoring gate, logged per card in `authoring_log.md`.

## EXAMPLE (schema demonstration — NOT a registered card)

`cards/_schema_example.json` holds one fully-worked example (a `decoy_static_string` card written
from general RE knowledge) so the schema and the validator have a concrete instance. It is
clearly marked `"status": "schema_example"` and is excluded from the library.
