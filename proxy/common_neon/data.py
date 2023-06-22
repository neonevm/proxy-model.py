from __future__ import annotations

from typing import Dict, Any, List, Optional

from .solana_alt import ALTAddress
from .solana_tx import SolTx, SolPubKey
from .utils import str_fmt_object


NeonEmulatedResult = Dict[str, Any]
NeonAccountDict = Dict[str, Any]


class NeonTxExecCfg:
    def __init__(self):
        self._state_tx_cnt = 0
        self._evm_step_cnt = 0
        self._alt_address_dict: Dict[str, ALTAddress] = dict()
        self._account_dict: NeonAccountDict = dict()
        self._resize_iter_cnt = 0

        self._strategy_idx = 0
        self._sol_tx_cnt = 0
        self._has_completed_receipt = False
        self._holder_account: Optional[SolPubKey] = None
        self._is_resource_used = False
        self._sol_tx_list_dict: Dict[str, List[SolTx]] = dict()

    def __str__(self) -> str:
        return str_fmt_object(self, skip_underling=False)

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

    @property
    def holder_account(self) -> Optional[SolPubKey]:
        return self._holder_account

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> NeonTxExecCfg:
        account_dict = {k: emulated_result.get(k, None) for k in ['accounts', 'solana_accounts']}
        evm_step_cnt = emulated_result.get('steps_executed', 0)
        self._account_dict = account_dict
        self._evm_step_cnt = evm_step_cnt
        self._resize_iter_cnt = self._resolve_resize_iter_cnt(account_dict)
        return self

    @staticmethod
    def _resolve_resize_iter_cnt(emulated_result: NeonEmulatedResult) -> int:
        max_resize_iter_cnt = 0
        for account in emulated_result.get('accounts', list()):
            max_resize_iter_cnt = max(max_resize_iter_cnt, int(account.get('additional_resize_steps', 0) or 0))
        return max_resize_iter_cnt

    def set_state_tx_cnt(self, value: int) -> NeonTxExecCfg:
        self._state_tx_cnt = value
        return self

    def add_alt_address(self, alt_address: ALTAddress) -> None:
        self._alt_address_dict[alt_address.table_account] = alt_address

    @property
    def strategy_idx(self) -> int:
        return self._strategy_idx

    @property
    def sol_tx_cnt(self) -> int:
        self._sol_tx_cnt += 1
        return self._sol_tx_cnt

    def set_strategy_idx(self, idx: int) -> None:
        self._strategy_idx = idx

    def has_completed_receipt(self) -> bool:
        return self._has_completed_receipt

    def set_completed_receipt(self, value: bool) -> None:
        self._has_completed_receipt = value

    def set_holder_account(self, is_resource_used: bool, acct: SolPubKey) -> None:
        assert self._holder_account is None
        self._holder_account = acct
        self._is_resource_used = is_resource_used

    def is_resource_used(self) -> bool:
        return self._is_resource_used

    def has_sol_tx(self, name: str) -> bool:
        return name in self._sol_tx_list_dict

    def pop_sol_tx_list(self, tx_name_list: List[str]) -> List[SolTx]:
        sol_tx_list: List[SolTx] = list()
        for tx_name in tx_name_list:
            sol_tx_sublist = self._sol_tx_list_dict.pop(tx_name, None)
            if sol_tx_sublist is None:
                continue

            sol_tx_list.extend(sol_tx_sublist)
        return sol_tx_list

    def add_sol_tx_list(self, tx_list: List[SolTx]) -> None:
        for tx in tx_list:
            self._sol_tx_list_dict.setdefault(tx.name, list()).append(tx)
