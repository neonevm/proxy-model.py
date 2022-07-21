from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class NeonTxExecCfg:
    is_underpriced_tx_without_chainid: bool
    steps_executed: int


NeonEmulatingResult = Dict[str, Any]


class NeonTxStatData:
    def __init__(self, neon_tx_hash: str, neon_income: int, tx_type: str, is_canceled: bool) -> None:
        self.neon_tx_hash = neon_tx_hash
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.instructions = []

    def add_instruction(self, sol_tx_hash: str, sol_spent: int, steps: int, bpf: int) -> None:
        self.instructions.append((sol_tx_hash, sol_spent, steps, bpf))


class Result:
    def __init__(self, reason: str = None):
        self._reason = reason

    def __bool__(self) -> bool:
        return self._reason is None

    def __str__(self) -> str:
        return self._reason if self._reason is not None else ""


@dataclass
class NeonTxPrecheckResult:
    is_underpriced_tx_without_chainid: bool
    emulating_result: NeonEmulatingResult
