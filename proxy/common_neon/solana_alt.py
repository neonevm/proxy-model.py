from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set

from .utils.utils import cached_property

from .solana_tx import SolPubKey
from .solana_tx_legacy import SolLegacyTx
from .constants import ADDRESS_LOOKUP_TABLE_ID
from .errors import ALTError
from .solana_alt_list_filter import ALTListFilter
from .layouts import ALTAccountInfo


@dataclass(frozen=True)
class ALTAddress:
    table_account: str
    recent_block_slot: int
    nonce: int


class ALTInfo:
    def __init__(self, alt_address: ALTAddress):
        self._alt_address = alt_address
        self._acct_key_set: Set[str] = set()
        self._acct_key_list: List[SolPubKey] = list()
        self._new_acct_key_list: List[SolPubKey] = list()
        self._is_exist = False

    @staticmethod
    def derive_lookup_table_address(signer_key: SolPubKey, recent_block_slot: int) -> ALTAddress:
        acct, nonce = SolPubKey.find_program_address(
            seeds=[bytes(signer_key), recent_block_slot.to_bytes(8, "little")],
            program_id=ADDRESS_LOOKUP_TABLE_ID
        )
        return ALTAddress(str(acct), recent_block_slot, nonce)

    @property
    def alt_address(self) -> ALTAddress:
        return self._alt_address

    @cached_property
    def table_account(self) -> SolPubKey:
        return SolPubKey.from_string(self._alt_address.table_account)

    @property
    def recent_block_slot(self) -> int:
        return self._alt_address.recent_block_slot

    @property
    def nonce(self) -> int:
        return self._alt_address.nonce

    @property
    def account_key_list(self) -> List[SolPubKey]:
        return self._acct_key_list

    @property
    def new_account_key_list(self) -> List[SolPubKey]:
        return self._new_acct_key_list

    @property
    def len_account_key_list(self) -> int:
        return len(self._acct_key_list)

    def is_exist(self) -> bool:
        return self._is_exist

    def init_from_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        assert not len(self._acct_key_list)

        legacy_msg = legacy_tx.message
        alt_filter = ALTListFilter(legacy_msg)

        alt_acct_set = alt_filter.filter_alt_account_key_set()
        self._acct_key_set = alt_acct_set
        self._update_account_key_list()
        self._new_acct_key_list = [acct_key for acct_key in self._acct_key_list]
        self._is_exist = False
        if not self.len_account_key_list:
            raise ALTError(f'No accounts for the lookup table {self._alt_address.table_account}')

    def _update_account_key_list(self) -> None:
        self._acct_key_list = [SolPubKey.from_string(key) for key in self._acct_key_set]

    def remove_account_key_list(self, acct_key_list: List[SolPubKey]) -> bool:
        if self._is_exist:
            raise ALTError('Trying to remove account from existing address lookup table')

        result = False
        for acct_key in acct_key_list:
            key = str(acct_key)
            if key in self._acct_key_set:
                result = True
                self._acct_key_set.remove(key)

        if result:
            self._update_account_key_list()
        return result

    def update_from_account(self, alt_acct_info: ALTAccountInfo) -> None:
        if self._alt_address.table_account != str(alt_acct_info.table_account):
            raise ALTError(
                'Trying to update account list from another lookup table: '
                f'{self._alt_address.table_account} != {str(alt_acct_info.table_account)}'
            )

        self._acct_key_list = alt_acct_info.account_key_list
        self._new_acct_key_list: List[SolPubKey] = list()
        self._acct_key_set = set([str(acct_key) for acct_key in alt_acct_info.account_key_list])
        self._is_exist = True

    def add_account_key_list(self, acct_key_list: List[SolPubKey]) -> None:
        if not self._is_exist:
            raise ALTError('Trying to add account to not-existing address lookup table')

        for acct_key in acct_key_list:
            acct_key_str = str(acct_key)
            if acct_key_str in self._acct_key_set:
                continue

            self._acct_key_set.add(acct_key_str)
            self._acct_key_list.append(acct_key)
            self._new_acct_key_list.append(acct_key)
