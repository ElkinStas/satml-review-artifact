"""Run configuration. Budgets live here, not in code.

The work plan calls for "token / step budget hooks ... so calibration becomes a
config change, not a code change." RunConfig is that surface: the pilot (Weeks 6-7)
recalibrates max_steps / max_total_tokens by editing a config, never the loop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agent.state import Arm


@dataclass
class RunConfig:
    arm: Arm
    task_id: str
    attempt_id: str
    binary_path: str

    # --- output ---
    runs_dir: str = "runs/pilot"  # trace -> {runs_dir}/{task_id}/{arm}/{attempt_id}/trace.jsonl
    overwrite: bool = False  # #12: fail closed -- refuse to overwrite an existing trace unless set

    # --- budgets (provisional; calibrated from pilot data at the pre-main lock) ---
    max_steps: int = 40
    max_total_tokens: int = 500_000  # SAFETY ceiling on budget_tokens (cache_read EXCLUDED); max_steps is the binding budget. Pilot max budget_tokens ~185k -> ~2.7x headroom. See TokenAccounting.

    # --- tool execution ---
    shell_timeout_s: int = 30
    max_tool_output_bytes: int = 8_192  # per-stream truncation
    run_binary_timeout_s: int = 20  # #9: RunBinaryTool timeout (was hard-coded); config-driven
    oracle_timeout_s: int = 20      # #9: BinaryOracle timeout (was hard-coded); config-driven

    # --- model / API ---
    per_call_max_tokens: int = 4096  # #9: model max_tokens per call (calibration = config)
    api_retry_count: int = 2         # #3/#9: transactional retries on a transient API error
    api_retry_backoff_s: float = 1.0  # #9: base backoff (exponential)

    # --- A2 scaffold (registered) ---
    scaffold_strictness: int = 2               # 1 | 2 | 3
    differential_trigger: str = "cited"        # cited | retrieved | always (effective 'always' at strictness 3)

    def __post_init__(self):
        # config validation: reject nonsensical knobs early rather than failing weirdly at runtime.
        if self.scaffold_strictness not in (1, 2, 3):
            raise ValueError(f"scaffold_strictness must be 1|2|3, got {self.scaffold_strictness}")
        if self.differential_trigger not in ("cited", "retrieved", "always"):
            raise ValueError(f"differential_trigger must be cited|retrieved|always, got {self.differential_trigger!r}")
        for name in ("max_steps", "max_total_tokens", "per_call_max_tokens",
                     "shell_timeout_s", "run_binary_timeout_s", "oracle_timeout_s", "max_tool_output_bytes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0, got {getattr(self, name)}")
        if self.api_retry_count < 0:
            raise ValueError(f"api_retry_count must be >= 0, got {self.api_retry_count}")
        if self.api_retry_backoff_s < 0:
            raise ValueError(f"api_retry_backoff_s must be >= 0, got {self.api_retry_backoff_s}")

    def trace_path(self) -> Path:
        return (
            Path(self.runs_dir)
            / self.task_id
            / str(self.arm)
            / self.attempt_id
            / "trace.jsonl"
        )

    @classmethod
    def from_dict(cls, d: dict) -> "RunConfig":
        d = dict(d)
        d["arm"] = Arm(d["arm"])
        return cls(**d)

    @classmethod
    def from_json(cls, path: Path | str) -> "RunConfig":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
