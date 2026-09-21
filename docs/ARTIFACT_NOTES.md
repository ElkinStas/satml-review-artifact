# Artifact notes

Four things a reader of the traces will notice and should have explained before they have to ask.

## 1. `binary_build_toolchain` in the traces says `-O0`. The binaries are `-O2`.

Every recorded trace carries a `binary_build_toolchain` string ending
`gcc -O0 -no-pie -fno-stack-protector`. **It is wrong, and it is not evidence of how the binaries
were built.** `harness/run_pilot.py` stamped a single pool-level constant from `harness/pilot_tasks.json` — a
leftover describing the development pool — onto every trace, rather than reading the instance's own
manifest.

The authoritative build provenance is the per-task `manifest.json` plus `binary_sha256`:

```
12 of 24 held-out:  gcc -O2 -no-pie -fno-stack-protector -x c - -o binary/t < binary/task.c
12 of 24 held-out:  ... same, && strip --strip-all binary/t
```

`harness/tasks/validate_artifact.py` checks both against the shipped ELF — that `-O2` is declared, that the
strip state matches, and that the hash agrees with what the traces recorded. It passes 24/24.

The traces have **not** been rewritten. Editing recorded evidence after the fact to make a metadata
field agree with reality is a worse problem than the field being wrong, and the field is inert: no
analysis reads it. `harness/run_pilot.py` now derives the value per task from the manifest, so future runs
record the real line.

## 2. The A2 prompt says `only`; the gate checked more than that.

The historical A2 prompt delta tells the model its submission will be admitted **only** if it can
state the evidential relation between what it observed and the candidate. The gate also evaluated
terminality and reachability obligations that the prompt does not enumerate.

This is partial opacity by design, not a mismatch between the arm and its description. The model was
told in advance that evidential justification was required — that is the intervention, and it is
what the prompt communicates. The full authorisation predicate set was deliberately not disclosed,
so that A2 could not be satisfied by writing to a checklist. When a submission was blocked, the
controller named the unmet obligation, so the information reached the agent through the channel the
design intends: the block, not the prompt.

The word `only` is unfortunate — it reads as an exhaustive enumeration when the sentence is stating a
necessary condition. The arm was not re-run over it: the runs implement the design the paper
describes, and re-running to fix a preposition would burn the pool for nothing.

## 3. T-F is inconclusive, not a null result.

The first synthetic operationalisation of the semantic-role-misbinding family did not reproduce the
intended trace-level phenomenon. The pilot instances gated on a 32-bit digest, so the agent solved
them by collision search and never engaged the mechanism under test.

The family is therefore reported as **inconclusive**: the mechanism was never actually exercised, so
the battery says nothing about susceptibility to it. It was not tuned until it produced the error we
were looking for, which is why there is no T-F arm in the results.

Do not describe this as "0/15 errors" or as measured susceptibility. Those phrasings assert a
negative finding the data cannot support: a test that did not run is not a test that passed.

## 4. Public CTF binaries are not redistributed here.

The seven public CTF tasks were exploratory only — inspected during development, plausibly present
in the models' training data, and never part of the main metric. Their per-binary source and licence
were never recorded, so this artifact ships their names, hashes, scoring markers and analysis
metadata instead of the binaries themselves. Nothing the paper claims rests on them; see
`harness/tasks/real/README.md`.

## 5. `cards_v1.0.json` and `retrieval_lock.json` still say "lock pending".

Both carry a historical status string from the candidate-freeze period —
`formal v1.0/pre-main lock pending` — describing a state that ended before the confirmatory runs.

**These files have not been rewritten, and must not be.** The card library is identified to every run
by its byte hash; editing a status string changes that hash and breaks the link between the shipped
library and the traces that record which library they used.

The authoritative frozen treatment is the file whose SHA-256 is

```
4f060500b4d7419d5555065ea2e7d77eaeee90f23e72364c7ede57af66dd603b
```

and **all 360 confirmatory A1/A2 traces record exactly that hash** — 240 held-out Claude and 120
cross-model GPT, with no second value anywhere. Check it: `sha256sum harness/cards/cards_v1.0.json`.
The prose inside the file is stale metadata; the hash is the identity, and the hash agrees.

## 6. The card library was re-issued from 28 cards to 25 before the confirmatory freeze.

`prereg/deviation_registry.md` classifies this as a methodological deviation, and it ships here
rather than being omitted. One family (`comprehend_time_fixation`) was removed for restating
candidates derived from a real task's traces; the rest were rewritten for the static-only tool
surface after `run_binary`/`trace_binary` left the agent surface.

This happened **before** the confirmatory pool was generated and before any held-out run. Every
held-out A1/A2 and every cross-model run used the 25-card library at the hash above. The internal
authoring history — candidate cards, patch scripts, sign-off drafts — is not part of this artifact.

## See also

`docs/ENVIRONMENT_PROVENANCE.md` — the held-out pool ran under two environment locks. That split is
diagnosed (a host kernel revision), proven by hash reconstruction, and both locks ship.
