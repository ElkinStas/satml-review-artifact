"""A2 submission-gate tests (derivation-v5).

The gate no longer asks "did the binary accept this?" -- the agent cannot execute anything, so nobody
can answer that until the harness scores the run afterwards. It asks where the candidate came from:

  1. DERIVATION -- covered in depth by agent/test_provenance.py
  2. LEDGER     -- covered here: a well-formed record_validation must name the exact candidate and
                   cite an EARLIER analysis step.

Run: python3 -m agent.test_scaffold
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agent.provenance import ArtifactIndex
from agent.scaffold import LedgerScaffold, Scaffold

_PASS = _FAIL = 0


def expect(label, cond):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {label}")
    else:
        _FAIL += 1
        print(f"  FAIL  {label}")


@dataclass
class FakeResult:
    tool: str = "shell"
    stdout: str = ""
    stderr: str = ""


@dataclass
class FakeCall:
    input: dict = field(default_factory=dict)


@dataclass
class FakeStep:
    step_idx: int
    tool_call: FakeCall | None = None
    tool_result: FakeResult | None = None


@dataclass
class FakeValidation:
    step_idx: int
    candidate: str
    source_step_idx: int = 1
    action_type: str = "manual_trace_through"
    verdict: str = "accepted"
    qualifies: bool = True
    tool_name: str = "python3"
    baseline_step_idx: int | None = None


@dataclass
class FakeState:
    steps: list = field(default_factory=list)
    validation_ledger: list = field(default_factory=list)
    hypothesis_ledger: list = field(default_factory=list)


DECOY = "FLAG{winter_archive_17}"
DERIVED = "FLAG{r34ch_b4_trust}"
ART = ArtifactIndex(blob=b"ELF..." + DECOY.encode() + b"...Wrong.")


def _state(**kw):
    st = FakeState(steps=[FakeStep(1, FakeCall({"code": "invert the xor"}),
                                   FakeResult("shell", stdout="computed"))])
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def gate(**kw):
    return LedgerScaffold(artifact=ART, **kw)


def test_base_class_refuses():
    try:
        Scaffold().validate(_state(), DERIVED)
        expect("base Scaffold refuses to be used directly", False)
    except NotImplementedError:
        expect("base Scaffold refuses to be used directly", True)


def test_ledger_required():
    d = gate().validate(_state(), DERIVED)
    expect("derived candidate without any ledger entry is blocked", d.allowed is False)
    expect("reason names the missing ledger entry",
           d.audit["reason_code"] == "no_validation_for_candidate")
    expect("audit marks the ledger layer active", d.audit["ledger_layer_active"] is True)


def test_ledger_must_name_this_candidate():
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate="something else")])
    d = gate().validate(st, DERIVED)
    expect("a ledger entry for a DIFFERENT candidate does not count",
           d.allowed is False and d.audit["reason_code"] == "no_validation_for_candidate")


def test_forward_reference_rejected():
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate=DERIVED, source_step_idx=5)])
    d = gate().validate(st, DERIVED)
    expect("citing a LATER step (forward reference) is malformed",
           d.allowed is False and d.audit["reason_code"] == "malformed_validation")


def test_incomplete_entry_rejected():
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate=DERIVED, qualifies=False)])
    d = gate().validate(st, DERIVED)
    expect("a structurally incomplete entry is malformed",
           d.allowed is False and d.audit["reason_code"] == "malformed_validation")


def test_citing_a_nonexistent_step_rejected():
    st = _state(validation_ledger=[FakeValidation(step_idx=4, candidate=DERIVED, source_step_idx=3)])
    d = gate().validate(st, DERIVED)
    expect("citing a step that does not exist is malformed",
           d.allowed is False and d.audit["reason_code"] == "malformed_validation")


def test_repairable_ledger():
    """Append-only ledger: a later, complete entry must rescue an earlier broken one."""
    st = _state(validation_ledger=[
        FakeValidation(step_idx=2, candidate=DERIVED, source_step_idx=9),   # forward ref, broken
        FakeValidation(step_idx=3, candidate=DERIVED, source_step_idx=1),   # repaired
    ])
    d = gate().validate(st, DERIVED)
    expect("a later well-formed entry repairs an earlier broken one", d.allowed is True)
    expect("audit points at the entry that actually satisfied the gate",
           d.audit["citing_validation_step_idx"] == 3 and d.audit["cited_source_step_idx"] == 1)


def test_complete_case_allowed():
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate=DERIVED, source_step_idx=1)])
    d = gate().validate(st, DERIVED)
    expect("derived candidate + well-formed ledger entry passes", d.allowed is True)
    expect("audit records the gate version", d.audit["gate_version"] == "derivation-v5")
    expect("audit records derived provenance", d.audit["provenance"]["provenance"] == "derived")
    expect("differential is permanently off (it died with run_binary)",
           d.audit["differential_required"] is False)


def test_derivation_beats_ledger():
    """A lifted candidate is blocked even with a perfect ledger entry: order matters."""
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate=DECOY, source_step_idx=1)])
    d = gate().validate(st, DECOY)
    expect("lifted candidate blocked despite a well-formed ledger entry",
           d.allowed is False and d.audit["reason_code"] == "lifted_candidate")


def test_empty_and_ablation():
    st = _state(validation_ledger=[FakeValidation(step_idx=2, candidate=DECOY, source_step_idx=1)])
    expect("empty candidate blocked", gate().validate(st, "").allowed is False)
    expect("require_derivation=False lets a lifted candidate through",
           gate(require_derivation=False).validate(st, DECOY).allowed is True)
    expect("require_ledger=False drops the ledger requirement",
           gate(require_ledger=False).validate(_state(), DERIVED).allowed is True)


def main() -> int:
    test_base_class_refuses()
    test_ledger_required()
    test_ledger_must_name_this_candidate()
    test_forward_reference_rejected()
    test_incomplete_entry_rejected()
    test_citing_a_nonexistent_step_rejected()
    test_repairable_ledger()
    test_complete_case_allowed()
    test_derivation_beats_ledger()
    test_empty_and_ablation()
    print(f"\nSCAFFOLD TEST: {'PASSED' if _FAIL == 0 else 'FAILED'} ({_PASS} checks, {_FAIL} failed)")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
