# From Decoys to False Proofs

Artifact for experiments on evidence-chain failures in tool-using LLM reverse-engineering agents.

This repository contains the code, task pools, traces, validation scripts, and analysis used to study two interventions against wrong terminal submissions caused by unsupported program interpretations. The evaluation uses a frozen held-out task pool and a secondary replication across two model families.

| Arm | What it adds |
|---|---|
| A0 | Baseline agent: model, RE tool surface, structured observation state. No retrieval, no gate. |
| A1 | A0 + Pattern-RAG: BM25 retrieval over a frozen library of failure-pattern cards, injected as advice at each step. Advisory only; nothing is enforced. |
| A2 | A1 + validation scaffold: a hard gate on `submit_candidate` that requires the recorded evidence obligations enforced by the policy to be satisfied before terminal release. |

## Results

Wrong terminal submissions by arm. Full breakdown and provenance notes are in `analysis/recompute_all.py`.

| Pool | A0 | A1 | A2 |
|---|---:|---:|---:|
| Development (24 synthetic) | 12/120 = 10.0% | 2/118 = 1.7% | see below |
| Held-out, Claude (24 tasks) | 31/120 = 25.8% | 1/120 = 0.8% | 0/120 = 0.0% |
| Cross-model, GPT-5.2 (12 tasks) | 8/60 = 13.3% | 8/60 = 13.3% | 0/60 = 0.0% |
| Public CTF (6, exploratory only) | 4/30 | 1/30 | 1/30 |

Development A2 is absent from that column because the finalized controller is evaluated on proposal states rather than per-task solve rates. Putting its 1/120 beside the A0 and A1 columns would mix units of analysis. The 120 development A2 trajectories are included as auxiliary runs, and `analysis/recompute_all.py` reports them.

On the held-out pool, solves are 89, 119, and 117 of 120 for A0, A1, and A2. A0 terminates with a wrong candidate on 31 runs. Under A1, 30 of those run slots move from wrong terminal submissions to solves.

Two details matter for interpreting the results:

1\) On GPT-5.2, A1 leaves the aggregate wrong-submission rate unchanged at 8/60, but the paired trajectories contain six repairs and six regressions. Retrieval fires on the agent's own `record_hypothesis` event. GPT reaches that event at a median step of 10, whereas Claude reaches it at step 2 in all 60 runs, so the same frozen retrieval policy enters the GPT trajectories later.

2\) In the held-out A2 runs, no incorrect proposal reached the gate. The 71 blocked-submission events therefore characterize the additional evidence work required before release: 25 of the 28 affected trajectories later satisfied the recorded evidence requirements and submitted correctly, while 3 ended without submission. Direct interception of incorrect proposals appears in the development replay, where the finalized policy blocks 4 of 11 proposals later found to be incorrect.

Before reading the traces, see `docs/ARTIFACT_NOTES.md`. It documents four artifact details that can otherwise look inconsistent, including a stale `binary_build_toolchain` field that reports `-O0` for binaries built at `-O2`.

## Validate the binaries

```bash
python3 harness/tasks/validate_artifact.py     # 24/24, 17 checks each, against the shipped ELFs
```

This is the authoritative validator for the shipped held-out binaries. Other scripts under `harness/tasks/synthetic/` validate the development pool and may report `REVIEW` on held-out instances because some of their checks depend on audit anchors that the held-out generator did not emit.

## Recompute every number

No model call or network access is required:

```bash
python3 analysis/recompute_all.py                  # every reported number, from the traces
python3 analysis/recompute_all.py --verify-oracle  # also re-executes the binaries to re-score
```

The script runs directly from the repository root. A trace counts only if its `binary_sha256` matches the binary shipped for that task. Runs that terminate at step 0 with an infrastructure error are excluded from denominators, and the exclusion count is reported.

Environment details are in `docs/ENVIRONMENT_PROVENANCE.md`. The pools ran under five images and seven environment locks. The held-out split is associated with a host-kernel revision that can be reconstructed from the shipped hashes; both held-out locks are included under `harness/locks/`. Four development-pool locks survive only as hashes in the traces. Run

```bash
python3 analysis/environment_provenance.py
```

to regenerate the environment table from the traces.

## Repository layout

```text
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
runs/                 curated, de-duplicated recorded trajectories used by the paper
  dev_synthetic/
  heldout_claude/
  crossmodel_gpt52/
  dev_real/            exploratory public-task traces
```

Fresh runs use `harness/runs/pilot/` by default when following the container instructions below; that path is git-ignored. The four evidence directories under `runs/` are committed and are the inputs to `analysis/recompute_all.py`.

# Running it

Unless stated otherwise, commands start in the repository root. The fresh-run container starts with `/repo/harness` as its working directory. Deterministic recomputation commands run from `/repo`.

## 0. Prerequisites

- Docker.
- Bubblewrap (`bwrap`). The registered execution backend is fail-closed: if `bwrap` is missing, the run aborts instead of falling back to a bare subprocess.
- An API key for the provider used for a fresh model run.
- Roughly 1 GB of disk for the image.

Running outside Docker is possible but is not a registered configuration; see "Appendix: running without Docker."

## 1. Build the image and capture its id

The image digest is captured after the build and passed back at run time.

```bash
docker build -t rerag-re:satml -f harness/agent/docker/Dockerfile harness
IMG=$(docker image inspect --format='{{.Id}}' rerag-re:satml)
echo "$IMG"     # sha256:...
```

The SDKs and analysis dependencies (`angr`, `capstone`, `pwntools`, `z3`, `lief`, `pyelftools`) are pinned with `==` in `harness/requirements-pilot.txt` and baked into the image. Do not install additional Python packages into the running container if you want to preserve the registered environment.

## 2. Configure credentials

```bash
cp harness/.env.example harness/.env
```

Edit `harness/.env` and set the key for the policy you want to run, together with `PILOT_MODEL`.

| Run | Set |
|---|---|
| Claude | `ANTHROPIC_API_KEY=...` and `PILOT_MODEL=claude-opus-4-5` |
| GPT | `OPENAI_API_KEY=...` and `PILOT_MODEL=gpt-5.2` |

There is no `--model` flag. The model is read from `PILOT_MODEL`, and `--policy` selects the SDK adapter. `harness/.env` is git-ignored.

## 3. Start the container

```bash
docker run --rm -it \
  --cap-add=SYS_PTRACE \
  -e RERAG_IMAGE_DIGEST="$IMG" \
  --env-file harness/.env \
  -v "$PWD":/repo -w /repo/harness \
  rerag-re:satml bash
```

Do not pass `--network=none`: the orchestrator needs outbound network access for the model API. Each tool call is isolated inside the container with bubblewrap and an empty network namespace. The orchestrator holds the API key and does not execute agent-controlled code.

`--cap-add=SYS_PTRACE` is needed for `strace`, `ltrace`, and `gdb`. Without it, those tools return `Operation not permitted`.

## 4. Pin the environment and run the self-tests

Run these once per image:

```bash
python -m agent.pin_environment --regenerate
python -m agent.preflight --regenerate
python -m agent.integration_selftest --json integration_report.json
```

Then verify the two locks:

```bash
python -m agent.pin_environment    # -> OK
python -m agent.preflight          # -> OK
```

`integration_selftest` checks the in-sandbox RE toolchain, imports for the analysis stack, caps and timeouts, child-process cleanup, and fail-closed namespace behavior. A separate `isolation_selftest` runs once per `run_pilot.py` invocation and checks that an in-sandbox probe cannot reach the network, the orchestrator's `/proc` secret, the repository, the ground truth, or the pristine target.

## 5. Run the Claude version

The measurements in `runs/heldout_claude/` were produced with `claude-opus-4-5-20251101`, strictness 2, and differential trigger `cited`.

Start with one task, all three arms, one attempt:

```bash
python3 run_pilot.py --task r_e_09_opaque --arm all --attempts 1
```

Check that the run completes, writes a trace, retrieves a plausible A1 card, and exercises the A2 submission scaffold as expected.

Then run the full held-out pool:

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

This produces 360 runs. Inside the container, fresh traces are written to `runs/pilot/<task>/<arm>/<attempt>/trace.jsonl`; on the host, the same files are under `harness/runs/pilot/`.

`run_pilot.py` does not overwrite an existing trace unless `--overwrite` is supplied. Re-running the loop therefore leaves existing slots unchanged and continues to later slots.

The development pool uses the `t_*` task ids. Six public CTF tasks have recorded exploratory trajectories; their identifiers and SHA-256 records are documented in `tasks/real/README.md`. One additional public-task SHA record is retained for provenance but has no recorded run in the reported exploratory set.

### Arm-specific flags

- `--strictness {1,2,3}` (A2 only): `1` linkage only; `2` linkage plus card-driven differential; `3` differential always. The registered setting is `2`.
- `--differential-trigger {cited,retrieved,always}` (A2 only): default `cited`.
- Neither flag affects A0 or A1 because the scaffold is attached only in A2.

## 6. Run the GPT version

The GPT comparison uses the same prompts, cards, tool surface, sandbox, and scorer. The model backend is the intended change.

`harness/agent/policy_openai.py` subclasses `ClaudePolicy` instead of modifying `harness/agent/policy.py`. The two policy adapters differ in tool-schema shape, system-prompt transport, tool-result representation, and cache control.

Set `OPENAI_API_KEY` and `PILOT_MODEL=gpt-5.2` in `harness/.env`, then run:

```bash
python3 run_pilot.py --task r_e_09_opaque --arm A0 --attempts 1 \
    --policy openai --reasoning-effort medium
```

For the full cross-model pool:

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

The recorded GPT runs use `--reasoning-effort medium`. Accepted levels for this model path are `none|medium|high|xhigh`; `low` is rejected.

Both policy adapters enforce one action per step. Anthropic uses `disable_parallel_tool_use`; Chat Completions uses `parallel_tool_calls=False`. The `n_parallel_dropped` counter is a tripwire and should remain zero.

The OpenAI API path used for these runs does not validate tool arguments against the declared schema. During the recorded runs, 3 of roughly 1500 calls contained undeclared keys. Those slots were re-run. The adapter now drops undeclared keys and counts them.

`--base-url` can point the same policy adapter at an OpenAI-compatible server such as vLLM or SGLang. These tasks can exceed 100k tokens of context, so a 32k-context endpoint will not complete them.

## 7. Score and analyse

Return to the repository root inside the container:

```bash
cd /repo
```

`compute_metrics.py` reads traces and writes metric tables:

```bash
python3 harness/analysis/compute_metrics.py \
    --runs-glob 'runs/heldout_claude/**/trace.jsonl' \
    --tasks-file harness/pilot_tasks.json \
    --out results/tables

python3 harness/analysis/bootstrap_ci.py --tables results/tables --n 10000 --seed 0
python3 figures/make_figs.py
```

Swap the glob for `runs/dev_synthetic/**`, `runs/crossmodel_gpt52/**`, or `runs/dev_real/**` for the other committed pools. For the paper numbers and provenance-sensitive exclusions, use `analysis/recompute_all.py`.

To score fresh runs produced with the container layout above, use `harness/runs/pilot/**/trace.jsonl`.

For de-duplication, compare each trace's `binary_sha256` as well as `(task, arm, attempt)`. An earlier consolidation keyed only on the tuple and kept the newest file by mtime, which admitted eight runs executed against superseded builds and reported 28.8% instead of 25.8%.

## Appendix: running without Docker

This mode is exploratory only. From the repository root, run `cd harness` first. The following RE CLIs must be on `PATH`:

```text
file strings readelf objdump nm r2 gdb strace ltrace python3
```

Install the pinned Python dependencies with:

```bash
pip install -r requirements-pilot.txt
```

Bubblewrap must still be present; otherwise `agent/execution.py` refuses to start.

`--unsandboxed` selects the local no-namespace backend. It is never selected automatically, is not a registered backend, and marks its results `sandbox_ok=False`.

`--allow-drift` downgrades a preflight-lock mismatch from fatal to a warning. Runs using it are outside the registered configuration.

## Appendix: adjudication

A candidate is `accepted` only on an exact `known_flag` match or an explicit `success_marker`. A present `fail_marker` is `rejected`; anything else is `inconclusive`. The absence of a failure is not success: a crash, usage message, or help string does not score as a solve.

Seven public-task SHA identifiers are retained under `harness/tasks/real/`. Six have recorded exploratory trajectories and were made scoreable by pulling markers from the binaries. Those six remain exploratory because of possible training-data exposure and because they were inspected during development; they are not part of the main metric.
