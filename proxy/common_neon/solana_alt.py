from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.constants import ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.errors import ALTError
from ..common_neon.solana_alt_list_filter import ALTListFilter
from ..common_neon.layouts import ALTAccountInfo


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

    @property
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
    def account_key_list_len(self) -> int:
        return len(self._acct_key_list)

    def init_from_legacy_tx(self, legacy_tx: SolLegacyTx) -> None:
        assert not len(self._acct_key_list)

        legacy_msg = legacy_tx.message
        alt_filter = ALTListFilter(legacy_msg)

        alt_acct_set = alt_filter.filter_alt_account_key_set()
        self._acct_key_set = alt_acct_set
        self._update_account_key_list()
        if not self.account_key_list_len:
            raise ALTError(f'No accounts for the lookup table {self._alt_address.table_account}')

    def _update_account_key_list(self) -> None:
        self._acct_key_list = [SolPubKey.from_string(key) for key in self._acct_key_set]

    def remove_account_key_list(self, acct_key_list: List[SolPubKey]) -> bool:
        result = False
        for acct_key in acct_key_list:
            key = str(acct_key)
            if key in self._acct_key_set:
                result = True
                self._acct_key_set.remove(key)

        if result:
            self._update_account_key_list()
        return result

    def _validate_alt_info(self, alt_acct_info: ALTAccountInfo) -> None:
        alt_acct_set: Set[str] = set([str(key) for key in alt_acct_info.account_key_list])

        if len(alt_acct_set) != len(alt_acct_info.account_key_list):
            raise ALTError(f'The lookup table {self._alt_address.table_account} has duplicates')

        if self._alt_address.table_account != str(alt_acct_info.table_account):
            raise ALTError(
                'Trying to update account list from another lookup table: '
                f'{self._alt_address.table_account} != {str(alt_acct_info.table_account)}'
            )

        if len(self._acct_key_list) == 0:
            # Init from the scratch
            return

        # Validate the content of account lists
        if len(self._acct_key_list) != len(alt_acct_info.account_key_list):
            raise ALTError(
                f'The account list from the lookup table {self._alt_address.table_account} '
                'has another length than expected: '
                f'{len(self._acct_key_list)} != {len(alt_acct_info.account_key_list)}'
            )

        for key in alt_acct_info.account_key_list:
            key = str(key)
            if key not in self._acct_key_set:
                raise ALTError(f'The unknown key {key} in the lookup table {self._alt_address.table_account}')

    def update_from_account(self, alt_acct_info: ALTAccountInfo) -> None:
        self._validate_alt_info(alt_acct_info)
        self._acct_key_list = alt_acct_info.account_key_list
        self._acct_key_set = set([str(key) for key in alt_acct_info.account_key_list])
