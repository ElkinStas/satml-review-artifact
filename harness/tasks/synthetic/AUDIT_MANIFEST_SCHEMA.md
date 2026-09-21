# Author-only audit anchors

Consumed by the validators, NEVER rendered into any agent-visible surface. They exist because a
feasibility proof cannot pick its own target: two earlier versions guessed and both produced
confident false verdicts (a sound instance called LIVE in 0.1s; a working trap called unprovable).
The author states what the trap IS; the validator proves whether the artifact still implements it.

## Do not type addresses by hand

Mark the semantic sites in the SOURCE, then let `resolve_audit_anchors.py` fill the manifest:

```c
__asm__ volatile("__audit_decoy_cmp:");      // where the misleading comparison happens
__asm__ volatile("__audit_decoy_edge:");     // the deceptive accept edge (must be INFEASIBLE)
__asm__ volatile("__audit_terminal_gate:");  // the real gate
```

```
python3 tasks/synthetic/resolve_audit_anchors.py <task_dir>
```

It builds once, resolves the labels with `nm`, writes the addresses into the manifest, strips the
shipped binary, and refuses to ship unless BOTH hold:

* `.text` is byte-identical before and after stripping -- otherwise the anchors describe a different
  program than the agent receives;
* no `__audit_*` label is reachable through `nm`, `strings` or `readelf -s`.

### Measured, not assumed

* `strip --strip-debug` **leaves every audit label visible to `nm`** -- it would hand the agent a
  complete map of the trap. An earlier draft of this pipeline recommended exactly that.
* `strip --strip-all` removes them from all three channels AND leaves `.text` byte-identical. The
  concern that `--strip-all` might disturb layout did not reproduce.

## Fields

```jsonc
{
  "mechanism_class": "T-E",
  "mechanical_variant_id": "te_02",

  "audit": {
    "evidence_site":              "0x401102",  // bait must be REACHABLE: an invisible bait is no trap
    "guard_branch_site":          "0x401113",  // the branch whose deceptive outcome must be INFEASIBLE
    "terminal_gate_site":         "0x401162",  // often SHARED with the honest solution -- which is why
                                               // "is the success block reachable" is meaningless and a
                                               // waypoint proof is required
    "deceptive_accept_successor": null,        // set instead when the dead path has a unique successor
    "checker_symbol":             null,        // T-C only, OPTIONAL: t_c_04 showed the separate frame
    "caller_symbol":              null,        // is a SURFACE of the class, not its definition
    "expected_relation": "nonterminal_or_rejecting"
  },

  // constrains the symbolic input. Asymmetric by design:
  //   DEAD over a WIDER domain is STRONGER (no input at all works)
  //   LIVE is only meaningful INSIDE the contract -- an out-of-contract witness proves nothing
  "input_domain": { "min_len": 1, "max_len": 32, "charset": "printable_ascii" }
}
```
