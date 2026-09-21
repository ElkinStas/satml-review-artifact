# Synthetic Task Authoring Protocol (Task Freeze Preparation)

Phase: **Synthetic Dataset Expansion and Task Freeze Preparation** (no-API). The 28-card library is
FROZEN (`cards/cards_v1.0.json`) and PI-signed; it is NOT touched here. This document governs how
synthetic tasks are authored, checked, and staged for calibration / main runs.

## 0. Cardinal rule — authoring source (the reverse-leakage safeguard)
Cards were frozen after authoring, so the forward risk (cards derived from eval tasks) is closed.
The **reverse risk is now live**: tasks over-fitted to card wording.

- Synthetic tasks are authored **from the preregistered W2 archetype specifications T-A…T-E**, i.e.
  from the abstract W2 failure mechanisms — **not** from any card's text.
- A card may be consulted **only** as a family-level coverage reference (does this archetype have a
  card family). **No card wording, title, example, retrieval keyword, or `card_id`** may be copied
  into task source, symbol names, flags, strings, or manifests.
- Cards and tasks share abstract failure families **by design**; generic family vocabulary (xor,
  decoy, rodata, opaque predicate, …) is expected in both and is NOT leakage. What is forbidden is
  instance-level mirroring of a specific card's language.
- Reviewer answer of record: *"Tasks were authored from preregistered W2 archetypes, not from
  individual card wording. Cards and tasks share abstract failure families by design, but no task is
  derived from a card's specific language."*

Enforced by `check_task_consistency.py` (hard-fail on any `card_id` or verbatim card title in task
files/symbols; keyword overlap reported for human review).

## 1. Archetype ↔ W2 subtype ↔ card family (pinned; must match compute_metrics)
| archetype | target_w2_subtype | card family in scope |
|---|---|---|
| T-A | `decoy_accepted` | `decoy_static_string`, `decoy_dead_function` |
| T-B | `unverified_candidate_submission` | `transform_then_compare` |
| T-C | `symbol_overtrust` | `misleading_symbol_name` |
| T-D | `failed_validation_ignored` | `silent_validation_failure` |
| T-E | `decompiler_artifact_trust` | `decompiler_artifact` |

There is deliberately **no T-F**: `comprehend_time_fixation` is an agent-behaviour family, not a
binary feature. Authoring a "fixation task" re-creates Jormugandr and invites circularity. It stays
a registered SECONDARY family, observed where it arises naturally on T-B/T-C/T-E/real tasks.

## 2. Manifest schema (required fields)
`task_id` (== dir name, `t_<letter>_NN_<slug>`), `stratum: synthetic`, `archetype` (T-A…T-E),
`target_w2_subtype` (canonical, per §1), `card_families_in_scope` (**comma-separated**; must be in
the frozen family set and within the archetype's families — the metrics pipeline splits on `,`,
NOT `+`), `trap_note`, `binary` (path), `binary_sha256` (frozen fingerprint of the committed
binary), `binary_size_bytes`, `input_method` (`argv`|`stdin`), `compile` (exact gcc flags),
`ground_truth` (path to solve.py), `ground_truth_present`, `ground_truth_visible_to_agent: false`,
`difficulty` (`easy`|`medium`|`hard` — **intended/design estimate; UNMEASURED until calibration**),
`role` (`dev` | `calibration` | `main`; see §4), `calibration` block (`a0_success_at_3`,
`w2_trigger_rate`, `status` — null until the API calibration pilot fills them).

## 3. Per-task required artifacts
`binary/<name>.c` (source) · `binary/<name>` (committed binary) · `manifest.json` ·
`groundtruth/solve.py` · **negatives** (known-wrong inputs) and **decoy candidates** (declared in
manifest or a `decoys.json`) · `notes_for_audit.md` (what makes it a valid trap; provenance).

**`solve.py --emit` contract (REQUIRED, new):** `python solve.py --emit` prints **only** the
accepted input on stdout — a single bare token, no prose, no ciphertext dump. `solve.py` with no
args may print a human report. This makes the oracle single-sourced (the binary + solve.py agree
programmatically) and removes the flag being duplicated in ci_smoke hardcode.

> Existing 12 tasks lack `--emit` and are under-artifacted (no build.sh, oracle_check, explicit
> negatives/decoys, notes_for_audit). Retrofit `--emit` + missing artifacts before they enter
> calibration/main. Baseline audit: reverse-leakage CLEAN across all 12; `t_a_03` separator bug
> fixed; 7/12 oracle-verify heuristically, 5 need `--emit`.

## 4. Role split (label at authoring, VALIDATE at calibration)
Three roles, so calibration evidence and main evidence never get confused:
- `dev` — tooling/oracle exercise; never reported as evidence.
- `calibration` — used (API) to tune budget/window and check A0 difficulty; not main evidence.
- `main` — frozen, primary synthetic evaluation.

**Sequencing caveat (chicken-and-egg):** difficulty is only measured by an A0 run (API). So `role`
and `difficulty` are assigned at authoring by **design intent**; the claim that a `main` task sits
in the prereg A0 window (success@3 ∈ [0.30, 0.65]) is **validated at the calibration pilot**, not
asserted at authoring. Do NOT freeze the main set's difficulty claims before calibration.

## 5. No-API acceptance gate (must pass before a task is staged)
Per task, all green with **no API**:
1. `make`/compile from source with the manifest `compile` flags succeeds.
2. `python solve.py --emit` → accepted input; `./binary <input>` (per `input_method`) ACCEPTS.
3. `./binary <known-wrong>` REJECTS (T-D: family-specific differential via ci_smoke, not exit code).
4. committed `binary_sha256` == manifest (reproducibility fingerprint).
5. `card_families_in_scope` valid + within archetype; `target_w2_subtype` matches archetype.
6. **Reverse-leakage clean**: no `card_id`, no verbatim card title in source/manifest/solve/symbols.
7. family `ci_smoke_<family>.py` passes (trap validity: real accepted, decoys rejected, real flag
   not plaintext, decoy functions unreachable, etc.).

Run `python tasks/synthetic/check_task_consistency.py` (covers 1–6) + the relevant ci_smoke (7).

## 6. Target volume & current gap
Aim for a candidate pool of **24–29**, not a crackme factory. Current vs target:

| archetype | current | target | to author |
|---|---|---|---|
| T-A | 3 | 5–6 | +2–3 |
| T-B | 3 | 5–6 | +2–3 |
| T-C | 2 | 5–6 | +3–4 |
| T-D | 2 | 5–6 | +3–4 |
| T-E | 2 | 4–5 | +2–3 (keep minimal; decompiler_artifact is advisory / Ghidra excluded from MVP) |
| **total** | **12** | **24–29** | **+12–17** |

From the frozen pool, later select: calibration 5–8, main synthetic 15–20, dev/ci reserve remainder.

## 7. Variant coverage per archetype (author from mechanisms, not cards)
- **T-A** decoy_accepted: flag-shaped string in .rodata with no accept-path xref; several
  flag-shaped strings, one gated; success message mistaken for flag; dead validator function;
  unreachable success branch. (Not trivially "strings prints a fake flag".)
- **T-B** unverified_candidate_submission: XOR-then-compare; shift/rotate-then-compare; base64/hex
  representation layer; small arithmetic transform; one-way digest counter-case. solve.py must show
  the exact preimage; keep the crypto light.
- **T-C** symbol_overtrust: function named like the gate but not the gate; variable named `flag`
  holding transformed/decoy data; crypto constant present but algorithm modified/partial; misleading
  `is_correct`/inverted logic. Keep names plausible, not obviously fake.
- **T-D** failed_validation_ignored: same stdout for accept/reject; misleading exit code; success
  marker in both paths; checker accepts everything unless a hidden condition; easy-to-miss reject.
  Provide a known-wrong baseline (differential). Most important family for the scaffold.
- **T-E** decompiler_artifact_trust (portable, minimal): opaque predicate / computed-constant
  branch; inline data rendered as code; jump-over/junk-byte structure; pseudo-C misleading via
  types/control flow. Do NOT depend on Ghidra-specific behaviour (MVP excludes it).

## 8. One engineering smoke (AFTER pool assembled + gate green + freeze)
Not now, and not "out of curiosity". After the candidate pool passes the no-API gate and a smoke
task is chosen: run exactly one mini-trio — **one T-B or T-D task × A0/A1/A2 × one seed**. T-B
checks cards enter reasoning before submit; T-D checks scaffold/validation discipline; the A0/A1/A2
trio immediately surfaces any A0 card-retrieval leak (the standing anomaly). This is an engineering
smoke, not evidence. Everything past it (κ-pool, calibration, replica, main) awaits explicit
go + budget.
