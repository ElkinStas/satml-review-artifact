# From Decoys to False Proofs

*Failure-aware retrieval for LLM reverse-engineering agents.*

An LLM agent doing reverse engineering fails in a specific, recurring way: it forms a plausible
reading of a binary — a string that looks like a flag, a function named `check_password`, a
decompiler artifact — and submits it without ever establishing that the reading is *forced* by
anything in the binary. The submission is wrong, and nothing in the agent's own account of its work
would have told it so.

This repository is the study of two interventions against that failure, measured on a frozen
held-out task pool and replicated across two model families.

| Arm    | What it adds                                                                                  |
|--------|-----------------------------------------------------------------------------------------------|
| **A0** | Baseline agent: model, RE tool surface, structured observation state. No retrieval, no gate.    |
| **A1** | A0 + **Pattern-RAG**: BM25 retrieval over a frozen library of failure-pattern cards, injected as advice at each step. Advisory only — nothing is enforced. |
| **A2** | A1 + **validation scaffold**: a hard gate on `submit_candidate` that requires the recorded evidence obligations enforced by the policy to be satisfied before terminal release. |

The headline is not that the agent gets better at reverse engineering. It is that **the agent stops
submitting answers it has not established**, at almost no cost to how many it solves.

## Results

Wrong terminal submissions, by arm. Full breakdown and provenance notes in
`analysis/recompute_all.py`.

| Pool                              | A0             | A1            | A2            |
|-----------------------------------|----------------|---------------|---------------|
| Development (24 synthetic)        | 12/120 = 10.0% | 2/118 = 1.7%  | see below     |
| **Held-out, Claude (24 tasks)**   | **31/120 = 25.8%** | **1/120 = 0.8%** | **0/120 = 0.0%** |
| Cross-model, GPT-5.2 (12 tasks)   | 8/60 = 13.3%   | 8/60 = 13.3%  | 0/60 = 0.0%   |
| Public CTF (6, exploratory only)  | 4/30           | 1/30          | 1/30          |

Development A2 is deliberately absent from that column. The finalised controller is evaluated on
**proposal states**, not on per-task solve rates, and putting its 1/120 beside the A0 and A1 columns
would silently mix units of analysis. The 120 development A2 trajectories exist and ship here as
auxiliary runs — `recompute_all.py` prints them — but they are not a row in this table.

On the held-out pool solves go 89 → 119 → 117 of 120. A0's 89 is not a capability ceiling: it fails
by *submitting a wrong candidate* on 31 runs, and those runs terminate. A1 converts almost all of
them into solves, which is why the count jumps — the same 30 runs move out of the wrong-submission
column and into the solved one. Read the two columns together rather than as independent effects.

Two results are worth stating carefully rather than as a win:

- **A1's aggregate is identical on GPT (8/60 both arms) but the paired view shows it is not inert** —
  6 repairs and 6 regressions, a reshuffle rather than an absence of effect. The mechanism is visible
  in the traces: retrieval fires on the agent's own `record_hypothesis` event, and GPT hypothesises at
  a median step of 10 where Claude fires at step 2 in all 60 runs, so the same frozen policy enters
  the trajectory after most of the analysis is already done.
- **On the held-out pool A2 demonstrates enforcement cost, not interception.** Post-hoc labels show
  that every candidate associated with the 71 blocked-submission events was correct. Of the 28
  affected trajectories, 25 later supplied sufficient evidence and were authorized to submit; all 25
  were accepted. No incorrect proposal reached the held-out gate. Direct interception is observed
  only in the development replay, where the finalized policy blocks 4 of 11 proposals later found
  to be incorrect.

Before reading the traces, see [`docs/ARTIFACT_NOTES.md`](docs/ARTIFACT_NOTES.md): four things
that look like defects and are not, including a stale `binary_build_toolchain` field that reports
`-O0` for binaries built at `-O2`.

## Validate the binaries

```bash
python3 harness/tasks/validate_artifact.py     # 24/24, 17 checks each, against the shipped ELFs
```

This is the one authoritative validator. Other scripts under `harness/tasks/synthetic/` validate the
DEVELOPMENT pool and report REVIEW on held-out instances because their layers need audit anchors the
held-out generator never emitted — they are not shipped in the review artifact.

## Recompute every number

No model call, no network, standard library only:

```bash
python3 analysis/recompute_all.py                  # every reported number, from the traces
python3 analysis/recompute_all.py --verify-oracle  # also re-executes the binaries to re-score
```

It runs directly from the repository root and probes the shipped layout rather than assuming an
external installation. Two conventions it enforces and prints: a trace counts only if its
`binary_sha256` matches the
binary shipped for that task, and runs that die at step 0 with an infrastructure error are excluded
from denominators rather than scored, with the exclusion count shown.

**Before citing the environment**, read [`docs/ENVIRONMENT_PROVENANCE.md`](docs/ENVIRONMENT_PROVENANCE.md).
The pools ran under five images and seven environment locks. The held-out split is diagnosed — a
host kernel revision, proven by hash reconstruction, with both locks shipped under `harness/locks/` — but
four development-pool locks survive only as hashes in the traces.
`python3 analysis/environment_provenance.py` regenerates that table from the traces.

## Repository layout

```
analysis/             deterministic recomputation and environment-provenance scripts
docs/                 artifact notes and environment provenance
figures/              paper figures and the script that regenerates them
harness/
  agent/               agent loop, policies, tool surface, sandboxed execution, Dockerfile
    prompts/           system prompt + per-arm deltas
  analysis/            metric computation, bootstrap CIs, level re-evaluation
  cards/               frozen Pattern-RAG library + authoring log + leakage audit
  locks/               recovered environment locks for held-out / cross-model pools
  tasks/
    synthetic/         generated development + held-out binaries, manifests, ground truth, generators
    real/              public-CTF metadata and SHA-256 identifiers only; no third-party binaries
  run_pilot.py         entry point for a new agent run
  pilot_tasks.json     registered task/run parameters
  requirements-pilot.txt
prereg/               deviation registry referenced by the paper
runs/                 curated, de-duplicated recorded trajectories used by the paper
  dev_synthetic/
  heldout_claude/
  crossmodel_gpt52/
  dev_real/            exploratory public-task traces
```

Fresh runs use `harness/runs/pilot/` by default when following the container instructions below; that path is git-ignored. The four evidence directories listed above are committed and are the inputs to `analysis/recompute_all.py`.

---

# Running it

Unless stated otherwise, commands start in the repository root. The fresh-run container is started with `/repo/harness` as its working directory; the deterministic recomputation commands run from `/repo` (the repository root).

## 0. Prerequisites

- Docker. The registered execution path runs inside the pinned image; **bubblewrap is required and
  the backend is fail-closed** — if `bwrap` is missing the run aborts rather than falling back to a
  bare subprocess.
- An API key for whichever provider you intend to drive (see step 2).
- Roughly 1 GB of disk for the image.

Running outside Docker is possible but is not a registered configuration; see
[Appendix: running without Docker](#appendix-running-without-docker).

## 1. Build the image and capture its id

The image digest is not baked in at build time — that would be circular, since baking a digest
changes the digest. You build, then read the id back out and pass it in at run time.

```bash
docker build -t rerag-re:satml -f harness/agent/docker/Dockerfile harness
IMG=$(docker image inspect --format='{{.Id}}' rerag-re:satml)
echo "$IMG"     # sha256:...
```

The SDKs and the whole analysis stack (angr, capstone, pwntools, z3, lief, pyelftools) are pinned with `==` in `harness/requirements-pilot.txt` and baked into the image. Do **not** `pip install` into a running container — that breaks the environment pin and the preflight gate will catch it.

## 2. Configure credentials

```bash
cp harness/.env.example harness/.env
```

Then edit `harness/.env`. You need the key for the policy you are actually going to run, plus `PILOT_MODEL`:

| You want to run | Set                                                    |
|-----------------|--------------------------------------------------------|
| Claude arm      | `ANTHROPIC_API_KEY=...` and `PILOT_MODEL=claude-opus-4-5` |
| GPT arm         | `OPENAI_API_KEY=...` and `PILOT_MODEL=gpt-5.2`           |

There is no `--model` flag. The model is read from `PILOT_MODEL`, and `--policy` selects which SDK
shapes the request. `harness/.env` is git-ignored; never commit it.

## 3. Start the container

```bash
docker run --rm -it \
  --cap-add=SYS_PTRACE \
  -e RERAG_IMAGE_DIGEST="$IMG" \
  --env-file harness/.env \
  -v "$PWD":/repo -w /repo/harness \
  rerag-re:satml bash
```

Two things about this command:

- **Do not pass `--network=none`.** The orchestrator needs outbound network for the model API.
  Per-tool isolation happens *inside* the container: every tool call gets its own empty network
  namespace via bubblewrap. The orchestrator holds the key and the network and never executes
  agent-controlled code itself.
- `--cap-add=SYS_PTRACE` is what lets `strace`/`ltrace`/`gdb` actually trace. Without it they fail
  with `Operation not permitted`, which surfaces as a nonzero-exit tool result rather than a crash —
  the attempt continues, so the failure is quiet. Pass the cap.

## 4. Pin the environment and pass the gates (inside the container)

Run these once per image. They capture what this specific image contains and then verify it.

```bash
python -m agent.pin_environment --regenerate
python -m agent.preflight --regenerate
python -m agent.integration_selftest --json integration_report.json   # must PASS
```

Then confirm both locks verify clean:

```bash
python -m agent.pin_environment    # -> OK
python -m agent.preflight          # -> OK
```

`integration_selftest` is the one that matters and cannot be checked in a build container: it
confirms the toolchain actually works in-sandbox (file/strings/nm/objdump/readelf/python3, angr/z3/
capstone import, r2/gdb), that caps and timeouts fire, that background children are reaped, and that
a missing bwrap or a denied namespace hard-fails instead of degrading silently. A separate
`isolation_selftest` runs automatically once per `run_pilot.py` invocation: it launches a probe
in-sandbox that must **fail** to reach the network, the orchestrator's `/proc` secret, the repo, the
groundtruth and the pristine target. If any of those is reachable, the run aborts.

## 5. Run the Claude version

The measurements in `runs/heldout_claude/` were produced with
`claude-opus-4-5-20251101`, strictness 2, differential trigger `cited`.

Start with one task, all three arms, one attempt — this is the cheap smoke test:

```bash
python3 run_pilot.py --task r_e_09_opaque --arm all --attempts 1
```

What to look for in the console line (`term / steps / subs / blocked / tok`):

1. the run completes end to end, parses tool calls and writes a trace;
2. A1 surfaces a card that is plausibly relevant;
3. A2 blocks at least one naked submission and releases it only after the evidence is supplied;
4. the agent is reasoning about the binary rather than about the gate.

Then the full held-out pool, per arm:

```bash
for t in r_c_01_named r_c_02_named r_c_03_named r_c_04_named \
         r_c_05_polarity r_c_06_polarity r_c_07_polarity r_c_08_polarity \
         r_c_13_named r_c_14_named r_c_15_polarity r_c_16_polarity \
         r_e_09_opaque r_e_10_opaque r_e_11_opaque r_e_12_opaque \
         r_e_17_opaque r_e_18_opaque r_e_19_opaque r_e_20_opaque \
         r_e_21_opaque r_e_22_opaque r_e_23_opaque r_e_24_opaque; do
  python3 run_pilot.py --task "$t" --arm A0 --attempts 5
  python3 run_pilot.py --task "$t" --arm A1 --attempts 5
  python3 run_pilot.py --task "$t" --arm A2 --attempts 5 --strictness 2
done
```

That is 360 runs. Inside the container, traces land in `runs/pilot/<task>/<arm>/<attempt>/trace.jsonl`; on the host, that is `harness/runs/pilot/<task>/<arm>/<attempt>/trace.jsonl`. Existing traces are never silently clobbered — `run_pilot.py` fails closed unless you pass `--overwrite`, so the loop is resumable: existing slots fail closed while the shell loop continues to later slots.

The development pool uses the `t_*` task ids. Six public CTF tasks have recorded exploratory trajectories; their identifiers and SHA-256 records are documented in `tasks/real/README.md`. One additional public-task SHA record is retained for provenance but has no recorded run in the reported exploratory set.

### Arm-specific flags

- `--strictness {1,2,3}` (A2 only) — `1` linkage only · `2` + card-driven differential (**the
  registered setting**) · `3` differential always.
- `--differential-trigger {cited,retrieved,always}` (A2 only) — default `cited`.
- Neither flag has any effect on A0 or A1: the scaffold is attached only when the arm is A2, so the
  A0/A1 execution path is untouched by anything in this section.

## 6. Run the GPT version

Same harness, same prompts, same cards, same tool surface, same sandbox, same scorer. The only thing
that varies is the model — which is the point, or the comparison would mean nothing.

`harness/agent/policy_openai.py` subclasses `ClaudePolicy` rather than editing it, so `harness/agent/policy.py`
stays byte-identical and every Claude measurement above still stands on its original hash anchor.
Four things differ between the two policies, all of them forced by the APIs rather than chosen: tool
schema shape, how the system prompt is passed, how a tool result is represented, and cache control
(explicit breakpoints vs automatic prefix caching).

Set `OPENAI_API_KEY` and `PILOT_MODEL=gpt-5.2` in `harness/.env`, then:

```bash
python3 run_pilot.py --task r_e_09_opaque --arm A0 --attempts 1 \
    --policy openai --reasoning-effort medium
```

The full cross-model pool — the 12 `r_e_*_opaque` reachability binaries, three arms, five attempts,
which is what `runs/crossmodel_gpt52/` contains:

```bash
for t in r_e_09_opaque r_e_10_opaque r_e_11_opaque r_e_12_opaque \
         r_e_17_opaque r_e_18_opaque r_e_19_opaque r_e_20_opaque \
         r_e_21_opaque r_e_22_opaque r_e_23_opaque r_e_24_opaque; do
  python3 run_pilot.py --task "$t" --arm A0 --attempts 5 --policy openai --reasoning-effort medium
  python3 run_pilot.py --task "$t" --arm A1 --attempts 5 --policy openai --reasoning-effort medium
  python3 run_pilot.py --task "$t" --arm A2 --attempts 5 --policy openai --reasoning-effort medium \
      --strictness 2
done
```

Four things to get right on this path:

- **`--reasoning-effort` is not optional in practice.** Leaving it to the model default is a silent
  confound between series. The recorded runs used `medium`. Accepted levels differ by model family —
  `gpt-5.2` takes `none|medium|high|xhigh` and **rejects `low`**, which fails the request rather than
  being quietly ignored.
- **One action per step is enforced, not approximated.** Anthropic uses `disable_parallel_tool_use`,
  Chat Completions uses `parallel_tool_calls=False`, so both arms share the constraint. The counter
  `n_parallel_dropped` is a tripwire and should stay at zero; if it moves, the endpoint ignored the
  flag and that run is not comparable.
- **The OpenAI API does not validate tool arguments against the declared schema.** During the
  recorded runs the model emitted calls carrying undeclared keys (`disassemble`, `executable`, once
  an empty key) in 3 of roughly 1500 calls (0.2%); those three slots were re-run. The adapter now
  drops undeclared keys and counts them.
- **`--base-url` points the same policy at any OpenAI-compatible server** (vLLM, SGLang). Note the
  context requirement: disassembly dumps routinely push a run past 100k tokens, so a 32k-context
  endpoint will not complete these tasks.

## 7. Score and analyse

Return to the repository root inside the container first:

```bash
cd /repo
```

`compute_metrics.py` reads traces and writes the metric tables. Point it at the committed evidence
set to reproduce the published numbers:

```bash
python3 harness/analysis/compute_metrics.py \
    --runs-glob 'runs/heldout_claude/**/trace.jsonl' \
    --tasks-file harness/pilot_tasks.json \
    --out results/tables

python3 harness/analysis/bootstrap_ci.py --tables results/tables --n 10000 --seed 0
python3 figures/make_figs.py
```

Swap the glob for `runs/dev_synthetic/**`, `runs/crossmodel_gpt52/**` or `runs/dev_real/**` for the other committed pools. For the paper numbers and all provenance-sensitive exclusions, use `analysis/recompute_all.py` as the authoritative recomputation entry point.

To score a run you produced yourself with the container layout above, point the glob at `harness/runs/pilot/**/trace.jsonl`.

One methodological note that is load-bearing: **de-duplication must compare each trace's
`binary_sha256`, not just `(task, arm, attempt)`.** An earlier consolidation keyed on the tuple alone
and kept the newest file by mtime, which silently admitted eight runs executed against superseded
builds and reported 28.8% where the correct figure is 25.8%.

---

## Appendix: running without Docker

Exploratory only. From the repository root, `cd harness` first. You need the RE CLIs on `PATH` —
`file strings readelf objdump nm r2 gdb strace ltrace python3` — plus
`pip install -r requirements-pilot.txt`, and bubblewrap still has to be present or
`agent/execution.py` will refuse to start.

`--unsandboxed` selects the local no-namespace backend. It is never selected automatically, is never
a registered backend, and marks its results `sandbox_ok=False`. `--allow-drift` downgrades a
preflight lock mismatch from fatal to a warning; same caveat.

## Appendix: adjudication

Adjudication is strict. A candidate is `accepted` **only** on an exact `known_flag` match or an
explicit `success_marker`; a present `fail_marker` is `rejected`; anything else is `inconclusive`.
The absence of a failure is not success — a crash, a usage message or a help string never scores as a
solve. Seven public-task SHA identifiers are retained under `harness/tasks/real/`; six have recorded
exploratory trajectories and were made scoreable by pulling markers from the binaries. Those six remain
exploratory (training-data leakage, and they were inspected during development) and never enter the main
metric.
