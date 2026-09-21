# Public CTF tasks (exploratory pool)

Six public CTF / crackme tasks were used as an exploratory boundary check. They are **never** part
of the main metric: they were inspected during development, and they may be present in model
training data, so the paper treats them as qualitative evidence only.

The third-party challenge binaries are **not redistributed in this review artifact**. This directory
contains only repository-authored metadata and SHA-256 identifiers for the external files used in the
recorded runs. The corresponding traces are under `runs/dev_real/`.

## Evaluated tasks

| task_id | external file used in the recorded run | scoring signal |
|---------|----------------------------------------|----------------|
| `ovl_10_cycle_of_hatred` | `cycle_of_hatred` | success + fail marker |
| `ovl_11_jormugandr` | `hello` | known flag + success + fail marker |
| `ovl_12_1zwasm` | `1zwasm` | success + fail marker |
| `ovl_19_constructor` | `chall` | success + fail marker |
| `ovl_22_dop` | `chall` | success + fail marker |
| `ovl_23_ex_cute` | `main` | success + fail marker |

Each evaluated task directory carries a `SHA256` file identifying the external artifact used to
produce the recorded traces. Traces also record `binary_sha256`; the analysis excludes a trace when
its recorded binary hash does not match the expected artifact hash for that task.

`ovl_13_gatta` is retained only as a hash/provenance record from the earlier candidate pool. It has
no recorded run in `runs/dev_real/` and does not enter the six-task exploratory results reported in
the paper.

## Redistribution

The external challenge executables (and the `libc.so.6` distributed with the original
`ovl_11_jormugandr` challenge) are intentionally omitted. Reviewers can reproduce all headline and
held-out results without them; the public-task pool carries no primary efficacy claim. The released
SHA-256 identifiers make the exact external artifacts used in the exploratory runs identifiable
without redistributing third-party files.

Any independently obtained challenge files remain under the terms of their original authors and
distributors and are not covered by this repository's MIT license.
