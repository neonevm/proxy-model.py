from __future__ import annotations

from dataclasses import dataclass
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


@dataclass
class NeonTxExecCfg:
    evm_step_cnt: int
    additional_resize_steps: bool
    account_dict: NeonAccountDict

    @staticmethod
    def resolve_additional_resize_steps(emulated_result: NeonEmulatedResult) -> bool:
        for account in emulated_result["accounts"]:
            if bool(account["additional_resize_steps"] or False):
                return True
        return False

    @staticmethod
    def from_emulated_result(emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        account_dict = {k: emulated_result[k] for k in ["accounts", "token_accounts", "solana_accounts"]}
        evm_step_cnt = emulated_result["steps_executed"]
        additional_resize_steps = NeonTxExecCfg.resolve_additional_resize_steps(account_dict)

        return NeonTxExecCfg(
            evm_step_cnt=evm_step_cnt,
            account_dict=account_dict,
            additional_resize_steps=additional_resize_steps,
        )


NeonEmulatedResult = Dict[str, Any]
NeonAccountDict = Dict[str, Any]
