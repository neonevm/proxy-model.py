from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


class NeonTxStatData:
    def __init__(self, neon_tx_hash: str, sol_spent: int, neon_income: int, tx_type: str, is_canceled: bool):
        self.neon_tx_hash = neon_tx_hash
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.sol_spent = sol_spent
        self.neon_step_cnt = 0
        self.bpf_cycle_cnt = 0
        self.sol_tx_cnt = 0


@dataclass
class NeonTxExecCfg:
    is_underpriced_tx_wo_chainid: bool
    steps_executed: int
    accounts_data: NeonAccountsData


NeonEmulatingResult = Dict[str, Any]
NeonAccountsData = Dict[str, Any]
