from __future__ import annotations

from typing import Dict, Any


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


class NeonTxExecCfg:
    def __init__(self):
        self._state_tx_cnt = 0
        self._evm_step_cnt = 0
        self._is_holder_completed = False
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

    @property
    def is_holder_completed(self) -> bool:
        return self._is_holder_completed

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        account_dict = {k: emulated_result[k] for k in ["accounts", "token_accounts", "solana_accounts"]}
        evm_step_cnt = emulated_result["steps_executed"]
        self._account_dict = account_dict
        self._evm_step_cnt = evm_step_cnt
        return self

    def set_state_tx_cnt(self, value: int) -> NeonTxExecCfg:
        self._state_tx_cnt = value
        return self

    def set_holder_completed(self, value: bool) -> NeonTxExecCfg:
        self._is_holder_completed = value

    @staticmethod
    def from_emulated_result(state_tx_cnt: int, emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        return NeonTxExecCfg().set_emulated_result(emulated_result).set_state_tx_cnt(state_tx_cnt)


NeonEmulatedResult = Dict[str, Any]
NeonAccountDict = Dict[str, Any]
