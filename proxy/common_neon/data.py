from __future__ import annotations

from typing import Dict, Any, List, Optional, NewType

from .solana_alt import ALTAddress
from .solana_tx import SolTx, SolPubKey
from .utils import str_fmt_object, cached_property, cached_method


class NeonEmulatorExitStatus:
    Type = NewType('ExitStatus', str)

    Revert = Type('revert')
    Succeed = Type('succeed')

    @staticmethod
    def to_type(value: str) -> Type:
        return NeonEmulatorExitStatus.Type(value.lower())


class NeonEmulatorResult:
    def __init__(self, res_dict: Optional[Dict[str, Any]] = None):
        self._is_empty = (res_dict is None) or (len(res_dict) == 0)
        self._res_dict = res_dict or dict()

    @property
    def full_dict(self) -> Dict[str, Any]:
        return self._res_dict

    @cached_method
    def __str__(self):
        return str_fmt_object(self._res_dict)

    def is_empty(self) -> bool:
        return self._is_empty

    @cached_property
    def evm_step_cnt(self) -> int:
        return self._res_dict.get('steps_executed', 0)

    @cached_property
    def solana_account_list(self) -> List[Dict[str, Any]]:
        return self._res_dict.get('solana_accounts', list())

    @cached_property
    def iter_cnt(self) -> int:
        return self._res_dict.get('iterations', 1)

    @cached_property
    def used_gas(self) -> int:
        return self._res_dict.get('used_gas', 0)

    @cached_property
    def exit_status(self) -> NeonEmulatorExitStatus.Type:
        value = self._res_dict.get('exit_status', '<unknown>')
        return NeonEmulatorExitStatus.to_type(value)

    @cached_property
    def revert_data(self) -> str:
        return self._res_dict.get('result', '')

    @cached_property
    def result(self) -> str:
        return self._res_dict.get('result', '')

    @cached_property
    def exit_reason(self) -> Optional[str]:
        return self._res_dict.get('exit_reason', None)


class NeonTxExecCfg:
    def __init__(self):
        self._state_tx_cnt = 0
        self._emulator_result = NeonEmulatorResult()
        self._alt_address_dict: Dict[str, ALTAddress] = dict()

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
    def emulator_result(self) -> NeonEmulatorResult:
        return self._emulator_result

    @property
    def alt_address_list(self) -> List[ALTAddress]:
        return list(self._alt_address_dict.values())

    @property
    def holder_account(self) -> Optional[SolPubKey]:
        return self._holder_account

    def set_emulator_result(self, emulator_result: NeonEmulatorResult) -> NeonTxExecCfg:
        self._emulator_result = emulator_result
        return self

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

    def mark_good_sol_tx_receipt(self) -> None:
        self._has_completed_receipt = True

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
