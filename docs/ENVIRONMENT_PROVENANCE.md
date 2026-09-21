# Environment provenance

`environment_lock.json` at the repository root is the target `harness/agent/preflight.py` compares a **new**
run against. It does not describe the recorded evidence. The pools were measured over several
months; recovering the actual environments from the traces — every one carries
`integration_image_digest` and `environment_lock_sha256` — gives this:

```
pool               image digest             environment lock      runs  shipped as
------------------------------------------------------------------------------------------------
crossmodel_gpt52   sha256:b9234ae12514df01f 9e29e96e0395758523b    180  locks/environment_lock.crossmodel_gpt52.json
dev_real           sha256:1a6d5cba37948c54e b2dab0b25eea75b9c72     60  -- not shipped --
dev_real           sha256:1a6d5cba37948c54e d08e3f9361f4ef9e92c     30  -- not shipped --
dev_synthetic      sha256:1a6d5cba37948c54e b2dab0b25eea75b9c72     89  -- not shipped --
dev_synthetic      sha256:1a6d5cba37948c54e d08e3f9361f4ef9e92c    120  -- not shipped --
dev_synthetic      sha256:23663ffd5e95f4e11 9c4e7e7f18bc46e9c50    120  -- not shipped --
dev_synthetic      sha256:5b02af2a762f66ce2 346713287a0bc9b2c30     30  -- not shipped --
heldout_claude     sha256:67aebd9ba58564d5b 252cda002079c2d9ce2    250  locks/environment_lock.heldout_claude.kernel-31.json
heldout_claude     sha256:67aebd9ba58564d5b f61c9fa7e3c21ab2a1f    110  locks/environment_lock.heldout_claude.kernel-30.json
superseded         sha256:1a6d5cba37948c54e d08e3f9361f4ef9e92c     15  -- not shipped --
superseded         sha256:5b02af2a762f66ce2 346713287a0bc9b2c30     10  -- not shipped --
superseded         sha256:67aebd9ba58564d5b f61c9fa7e3c21ab2a1f     17  locks/environment_lock.heldout_claude.kernel-30.json
```

Regenerate it rather than trusting the table: `python3 analysis/environment_provenance.py`.

## The held-out split, diagnosed

The confirmatory pool carries two lock hashes under one image. That is a host **kernel** revision and
nothing else:

| group | runs | arms | kernel |
|---|---|---|---|
| `f61c9fa7…` | 110 | A0 only | `7.0.0-30-generic` |
| `252cda00…` | 250 | 10 × A0, 120 × A1, 120 × A2 | `7.0.0-31-generic` |

Checked across the two groups, every other recorded field is identical: image digest, Python, gcc,
glibc, `pool_hash_sha256`, `card_library_sha256`, `tool_specs_sha256`, `retrieval_py_sha256` and the
model string. `system_prompt_sha256` takes three values, one per arm, and is constant *within* each
arm across both groups — it is arm-keyed, not drift.

**The earlier lock file has been recovered and the diagnosis is cryptographically proven.**
Substituting `7.0.0-31-generic` → `7.0.0-30-generic` in the surviving lock reproduces
`f61c9fa7e3c21ab2a1fde260a9982451aebd7673de624ae9c8ea604f8885bb6c` exactly. Since SHA-256 fixes the
whole file, the two locks provably differ in that one string and in nothing else. Both are shipped,
so a reviewer can hash them and match the traces directly:

```bash
sha256sum locks/environment_lock.heldout_claude.kernel-3*.json
```

The kernel is pinned because the lock is deliberately conservative — it records every observable
property of the host so drift surfaces instead of being absorbed. Nothing the analysis depends on
runs on it: the disassembler, the compiler that produced the binaries and the model API are all
unaffected by a minor kernel revision. The lock did its job here.

### One caveat on the restricted-baseline check

Restricting A0 to the 110 pre-upgrade trajectories gives **30/110 = 27.3%** against **31/120 = 25.8%**
for the full set; the ten later completions contribute one further wrong submission (1/10). Against
A1 (1/120) and A2 (0/120) the conclusion is identical under either denominator.

But the ten later runs are not a random subset, and a reviewer will notice. They are the completions
of exactly five tasks — `r_c_01`–`r_c_04` (`named`) and `r_c_16` (`polarity`) — and A0 fails on
those five at **1/25 = 4.0%** across both kernels, against **30/95 = 31.6%** on the other nineteen.
So restricting to the 110 also drops the easiest motifs from the denominator; the move from 25.8% to
27.3% is motif composition, not a kernel effect. State it that way rather than offering 27.3% as a
kernel-controlled baseline — the honest version is stronger, because it removes the only reading on
which the split could look like a confound.

## The unshipped locks

The script finds **seven distinct environment locks** across the recorded runs. Three ship
(`crossmodel_gpt52`, and both held-out kernels); **four exist only as hashes in the traces.** `pin_environment --regenerate` overwrites rather
than versions, so each was destroyed by the next regeneration. They cover `dev_synthetic`,
`dev_real` and part of `superseded` — the development pools, which carry no confirmatory claim. The
same substitution trick may recover them if a sibling lock survives from the same image; the
recovered file counts only if its SHA-256 matches what the traces recorded.

For cross-checking against the table above: twelve (pool, image, lock) combinations, five distinct
images, seven distinct locks, 989 analysed traces.

## Not affected

Binary provenance is on separate and sounder footing: every trace records `binary_sha256`, and
`analysis/recompute_all.py` verifies each counted trace against the binary shipped for that task —
360/360 on the held-out pool.
