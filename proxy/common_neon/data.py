from __future__ import annotations

from typing import Dict, List, Any


class NeonTxStatData:
    def __init__(self, neon_tx_sig: str, sol_spent: int, neon_income: int, tx_type: str, is_canceled: bool):
        self.neon_tx_sig = neon_tx_sig
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.sol_spent = sol_spent
        self.neon_step_cnt = 0
        self.bpf_cycle_cnt = 0
        self.sol_tx_cnt = 0


class NeonTxExecCfg:
    def __init__(self):
        self._state_tx_cnt = 0
        self._evm_step_cnt = 0
        self._alt_list: List[str] = []
        self._account_dict: NeonAccountDict = {}

    @property
    def state_tx_cnt(self) -> int:
        return self._state_tx_cnt

    @property
    def evm_step_cnt(self) -> int:
        return self._evm_step_cnt

    @property
    def account_dict(self) -> NeonAccountDict:
        return self._account_dict

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        account_dict = {k: emulated_result[k] for k in ["accounts", "token_accounts", "solana_accounts"]}
        evm_step_cnt = emulated_result["steps_executed"]
        self._account_dict = account_dict
        self._evm_step_cnt = evm_step_cnt
        return self

    def set_state_tx_cnt(self, value: int) -> NeonTxExecCfg:
        self._state_tx_cnt = value
        return self


NeonEmulatedResult = Dict[str, Any]
NeonAccountDict = Dict[str, Any]
