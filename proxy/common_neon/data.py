from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List, Optional


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


@dataclass
class NeonTxReturn:
    exit_status: int = 0
    gas_used: int = 0
    return_value: Optional[bytes] = None


@dataclass
class NeonEvent:
    address: Optional[bytes] = None
    count_topics: int = 0
    topics: Optional[List[bytes]] = None
    log_data: Optional[bytes] = None


@dataclass
class NeonLogIx:
    neon_return: Optional[NeonTxReturn] = None
    neon_events: List[NeonEvent] = field(default_factory=list)
