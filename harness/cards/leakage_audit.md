# Leakage audit

## Pilot seed cards
- audit_date: 2026-06-05
- artifact: cards/cards_pilot_seed.json
- sha256: 469aee3d6300469fede1f7b89439799758165ad02d6a6713d2098e3968d5df56
- status: PILOT SEED -- exploratory Week-3 dry-run only; NOT the registered library.
- attestation: abstract analytical lenses derived from the W2 failure-mode taxonomy (the
  project's 5 subtypes / Nishizaka W2). NOT derived from any evaluation binary. No
  task-specific details, addresses, constants, or flags. Authored before the pilot-zero run.
- main-run task knowledge: none (these cards predate and are independent of any main-run
  task selection).

## Registered library (cards_v1.0.json) -- PROTOCOL (executed Weeks 8-11)
- authored blinded to main-run ground truth (no decompiler output / flags / addresses of
  main-run tasks consulted while authoring);
- frozen + sha256-hashed and committed BEFORE the first main run; this audit's table
  (date, card hash, manifest hash, per-card source) filled at freeze.
- many-to-many family<->subtype mapping recorded in prereg (see cards_pilot_seed.json _meta).
- decompiler_artifact flagged advisory/under-exercised (Ghidra excluded from MVP); no strong
  per-family claims drawn from it.


## Candidate cards (cards_candidates_unblinded.json) -- UNBLINDED, NOT registered
- artifact: cards/cards_candidates_unblinded.json (3 cards)
- status: CANDIDATE / UNBLINDED -- firewalled; NOT loaded in runs; NOT the registered library.
- provenance: derived from the UNBLINDED failure traces of ovl_11_jormugandr (#11, Week-5
  analysis): derived_candidate_unvalidated, rejected_artifact_anchoring (kalmarctf{ vs real
  kalmar{), premature_transform_commit.
- anti-circularity: MUST NOT be validated on #11. Validate only on held-out T-* synthetics
  authored independently from these cards.
- linked metric: the registered SECONDARY comprehend_time_fixation_rate (prereg sec.8.4) is
  annotated for the same comprehend-time failures; the same anti-circularity applies.
- promotion: candidate -> held-out validation -> blinded RE-authoring before any entry into the
  registered library. Promotion of a comprehend-time SUBTYPE into the primary taxonomy is a
  pre-main-lock decision (prereg sec.8.4 rationale), not yet taken.


## Registered library (cards_v1.0.json) -- AUDIT EXECUTED 2026-07-01 (at candidate-freeze)

> Supersedes the "(executed Weeks 8-11)" PROTOCOL stub above: the protocol states the audit
> table is "filled at freeze", and the candidate-freeze of the registered library was performed
> 2026-07-01 (no-API). The Weeks-8-11 calendar label is stale; the substantive audit is below.

- audit_date: 2026-07-01
- auditor: fresh Week-7 session (independent of Week-5/6 authoring); **PI sign-off recorded below (accepted 2026-07-06)**
- artifact: `cards/cards_v1.0.json` -- 28 cards / 7 families {'transform_then_compare': 5, 'decoy_static_string': 4, 'decoy_dead_function': 4, 'misleading_symbol_name': 4, 'silent_validation_failure': 4, 'decompiler_artifact': 4, 'comprehend_time_fixation': 3}
- file_byte_sha256 (drift-guard anchor): `34fbe4c65dc0729c77429aa10a23dd926902610099fcd17e20aaae633e402d32`
- cards_content_sha256 (internal fingerprint): `156460bcb76b8e0c43b83c4e0ff3ba3f45f41ebb58aeaf545ed034e30c7b5057`
- audited AGAINST full unblinded manifest state:
  - `tasks/manifest.json` sha256: `5abc27d4ae6e46df21066c9e8e55123ec1e679f6b7ef80c4a1e1a543efa0b5a7`
  - synthetic ground truth (12 manifests + 12 solve.py) combined sha256: `0d8f1be1bb4f10374d4588d3b74c2aa9683aa6029f7f80ab65f1afba90609f03`
  - `cards/cards_candidates_unblinded.json` (#11 firewall reference) sha256: `27c364270f5172ccfc3641ea8cacbcba7662fe4b8038aacdfb773be8418190d8`

### Method (four independent layers)
1. **Provenance (mechanical).** Every card cites only PERMITTED sources (SRC-001 general_re,
   SRC-002 taxonomy_w2, SRC-003 textbook); no SRC-X* (eval) cited. `validate_cards.py --strict`
   passes with 0 leaks. All `provenance.eval_overlap == none`.
2. **Exhaustive instance-token scan.** All 28 cards (every string field, recursive) scanned
   against the FULL ground-truth token set built from the unblinded manifest: 12 synthetic real
   flags + 5 decoys, inner flag substrings, instance function names (tally / validate_license /
   check_master_key / verify_flag / commit_record / check_license / parse_header), the 2-digit XOR
   keys (0x5a / 0x3c / 0x3d) and shift amounts (+7 / +19) that the mechanical "0x + 4-or-more hex
   digits" regex does NOT catch, and real-task names / flag stems (kalmar, kalmarctf, jormugandr, gatta, 1zwasm,
   cycle_of_hatred, constructor, dop, ex-cute). Result: **ZERO instance tokens across all 28
   cards.** Scanner positive-controlled (bites on a planted-token string).
3. **Semantic pass.** Distinctive trap-note phrasings checked: instance-mirroring phrases
   (`orphan caller`, `jmp-over-junk`, `rolling-xor`, `running-key`) are ABSENT. The two review
   flags (`always-false`, `desync`) are general RE vocabulary in the decompiler_artifact family
   (opaque-predicate / disassembly-desynchronization as abstract classes), not t_e instance
   mechanisms. All cards describe abstract pattern classes; per-instance mechanisms/params/flags
   are absent. Necessary family<->task conceptual overlap (a card helping its target family) is
   intended and permitted (abstract class = SRC-006/001); only instance detail would be leakage.
4. **Circularity firewall (comprehend_time_fixation vs #11 candidates).** The 3 registered
   comprehend cards vs the 3 firewalled `cards_candidates_unblinded.json` (#11-derived): keyword
   overlap 1/8, 2/9, 0/11 (shared tokens commit/anchor/rejected are general bias vocabulary); ALL
   distinctive #11 instance tokens (kalmarctf, kalmar, rabbit, r3venge, wrapper, charset, prefix,
   run_binary, forward-validation) ABSENT from the registered cards; no 1:1 rewording
   (`cand_derived_candidate_unvalidated` has NO comprehend twin -- it is submit-time / scaffold
   domain; the other two map to strictly BROADER registered cards, i.e. generalization
   specific->abstract, not narrowing from #11). Consistent with the provenance attestation:
   authored from general practice, blind to #11.

### Per-card verdict
All 28 cards: **CLEAN (no instance-specific leakage detected).** Highest-attention pair recorded
for transparency: `c_fixation_rejected_evidence_anchoring` is the closest concept-neighbour of
`cand_rejected_artifact_anchoring` (#11 candidate) -- judged clean (recognized general reasoning
bias = belief-perseverance/anchoring; zero #11 tokens; abstract 'format/structure/parameters' vs
the candidate's instance 'prefix/wrapper/charset').

### Grounding note (honest coverage)
16 well_grounded / 12 advisory_under_exercised. `comprehend_time_fixation` (3 cards) is a
registered SECONDARY family (prereg sec.8.4): no clean synthetic archetype; motivated by the
pilot-observed failure mode, but the registered cards are authored only from clean general RE
practice and are NOT derived from #11 traces; exploratory; NOT in the canonical MC1 map
(`_w2_subtype_to_family_index`). decompiler_artifact advisory/under-exercised (Ghidra excluded from MVP).

- disposition: registered library **clears leakage audit**. Blinding is now lifted (full manifest
  consulted). Authoring is frozen -- no further card authoring.

### PI SIGN-OFF
The note wording was corrected pre-signoff (removed the reviewer-hostile "real-overlap only"
phrasing across the bundle); the cards array is unchanged (content-sha256 stable), only the file
byte-hash was re-computed and re-locked. Sign-off is therefore recorded against the RE-FROZEN file.

- **PI sign-off (Author A): ACCEPTED** — 2026-07-06 — `cards/cards_v1.0.json`
  file byte-sha256 `34fbe4c65dc0729c77429aa10a23dd926902610099fcd17e20aaae633e402d32`
  (cards content-sha256 `156460bcb76b8e0c43b83c4e0ff3ba3f45f41ebb58aeaf545ed034e30c7b5057`).
- Basis: four-layer audit above (provenance / exhaustive token scan / semantic pass / circularity
  firewall), all clean; validator strict-mode hole (source_type == candidate_unblinded) closed
  and re-verified this session.


---

## Registered library (cards_v1.0.json) -- W10/W10b ADVICE RE-ISSUE, AUDIT EXECUTED 2026-07-29

> This section re-opens the "authoring is frozen" disposition of 2026-07-06. The trigger was a tool-
> surface change, not a wish to tune the cards: `run_binary` / `trace_binary` left the agent surface,
> so 16 cards recommended an action the agent cannot perform, 12 more recommended a second one, and
> 4 required a differential that no longer exists. **No cards were added or removed.** The count is
> the 2026-07-06 figure of 28 and the family distribution is unchanged.
> The 2026-07-06 PI sign-off names the old byte-hash and does **not** carry over. A new sign-off is
> required and is **NOT** recorded.

- audit_date: 2026-07-29
- artifact: `cards/cards_v1.0.json` -- 28 cards / 7 families {'transform_then_compare': 5,
  'decoy_static_string': 4, 'decoy_dead_function': 4, 'misleading_symbol_name': 4,
  'silent_validation_failure': 4, 'decompiler_artifact': 4, 'comprehend_time_fixation': 3}
- file_byte_sha256: `90c13bd4783c1f39df07bbb7009777c4979e4425b6796d536b1884c34d4e4312`
- cards_content_sha256: `33c50683d31e82807a539442be44f5acf98d68772a5714d69cde531b21e89d48`
- re-anchored in `retrieval_lock.json`, `preflight_lock.json`, `agent/test_preflight.py`,
  `tasks/synthetic/pool_manifest_v0.1.json`.

### Scope audited

All 28 cards edited in the validation-advice fields (actions, validation_note, not_applicable_when,
misfire_risks, minimum_evidence_before_use). 4 `c_silentval_*` cards additionally re-scoped from the
runtime reading to the static one. 4 cards repaired for firewall/coherence defects (below). Three
cards drafted during this session were **reverted before any run** -- see `cards/authoring_log.md`
and `prereg/deviation_registry.md`.

### Method and results

1. **Provenance (mechanical).** `validate_cards.py --strict` -> PASSED, 0 errors, 0 leak hits. All
   cards cite SRC-001/002/003 only; all `eval_overlap == none`. Three strict-mode gates were ADDED
   this session and are now the regression guard: a card may not recommend an action requiring target
   execution; `requires_differential: true` is a hard error; **citing SRC-006 is a hard error.**
2. **High-signal instance-token scan.** Token set from the full unblinded state -- 24 synthetic
   manifests (decoy values, negatives, trap-note identifiers), 24 `groundtruth/solve.py`, and
   `pilot_tasks.json` (known_flag / markers / task ids) -- restricted to instance-like tokens
   (digit-bearing or snake_case). Scanned against every string field of all 28 cards, recursively.
   **Result: NONE.**
3. **Archetype-source overlap scan (new this session).** Distinctive terms of
   `tasks/synthetic/archetype_specs.md` -- every backticked identifier plus the named algorithms and
   tools -- scanned against all 28 cards. This tests §1.2 of that document, which forbids the card
   library and the archetypes from being derived from each other. **Result after repair: NONE.**
   Before repair it found four: a named cipher in `c_symbol_crypto_constant_identity` (the archetype
   source ties that cipher to a REAL eval task's mechanism), a literal example identifier in
   `c_symbol_misleading_function_name` taken verbatim from the T-C spec, a second literal identifier
   in `c_symbol_variable_name_semantics` that also occurs in eval ground truth, and a named
   decompiler in `c_decompiler_pseudoc_lossy` that is additionally absent from the agent's tool
   surface. All four were generalised to the semantic category they stood for; the patterns are
   unchanged.
4. **Fitted-advice review.** Every card was read against the question "could this only have been
   written by someone who had seen a specific task?" No card names a mechanism at instance
   granularity (no specific modulus, transform parameter, symbol, or marker). The one edit made on
   coherence rather than firewall grounds: an incoherent `not_applicable_when` clause in
   `c_dead_function_no_call_site` ("the binary is stripped such that the call graph is reliable
   enough to confirm reachability") replaced with the condition it was evidently meant to express.

### Open finding -- REQUIRES PI RESOLUTION

`cards/authoring_sources.md` permits SRC-006 (archetype source, abstract level, citing prereg §5.2);
`tasks/synthetic/archetype_specs.md` §1.2 forbids any derivation between cards and archetypes. The
stricter document is currently enforced in the validator. Related and unresolved: the
`comprehend_time_fixation` family note in the library envelope records that the family was
"motivated by pilot observation". That is the same class of selection-level influence for which the
three W10 cards were reverted, and it predates this session. It is not a text leak -- those three
cards contain no instance detail and cite SRC-001/002 -- but if the standard is "never fitted to an
observation", the family's status should be settled explicitly rather than inherited.

### PI SIGN-OFF

- **PENDING.** The 2026-07-06 sign-off applies to byte-sha `34fbe4c6...` (28 cards, pre-re-issue) and
  is superseded, not extended, by this re-issue.
