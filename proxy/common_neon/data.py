from __future__ import annotations

from typing import Dict, Any, List

from .solana_alt import ALTAddress


NeonEmulatedResult = Dict[str, Any]
NeonAccountDict = Dict[str, Any]


class NeonTxExecCfg:
    def __init__(self):
        self._state_tx_cnt = 0
        self._evm_step_cnt = 0
        self._alt_address_dict: Dict[str, ALTAddress] = dict()
        self._account_dict: NeonAccountDict = dict()
        self._resize_iter_cnt = 0

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
    def resize_iter_cnt(self) -> int:
        return self._resize_iter_cnt

    @property
    def alt_address_list(self) -> List[ALTAddress]:
        return list(self._alt_address_dict.values())

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        account_dict = {k: emulated_result[k] for k in ["accounts", "token_accounts", "solana_accounts"]}
        evm_step_cnt = emulated_result["steps_executed"]
        self._account_dict = account_dict
        self._evm_step_cnt = evm_step_cnt
        self._resize_iter_cnt = NeonTxExecCfg.resolve_resize_iter_cnt(account_dict)
        return self

    @staticmethod
    def resolve_resize_iter_cnt(emulated_result: NeonEmulatedResult) -> int:
        max_resize_iter_cnt = 0
        for account in emulated_result["accounts"]:
            max_resize_iter_cnt = max(max_resize_iter_cnt, int(account["additional_resize_steps"] or 0))
        return max_resize_iter_cnt

    def set_state_tx_cnt(self, value: int) -> NeonTxExecCfg:
        self._state_tx_cnt = value
        return self

    def add_alt_address(self, alt_address: ALTAddress) -> None:
        self._alt_address_dict[alt_address.table_account] = alt_address
