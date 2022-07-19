from __future__ import annotations

from typing import List, Tuple, Set

from solana.transaction import Transaction
from solana.publickey import PublicKey

from ..common_neon.solana_account_lookup_table_builder import AccountLookupTableBuilder, AccountLookupTableError
from ..common_neon.solana_interactor import AccountLookupTableAccountInfo


ADDRESS_LOOKUP_TABLE_ID: PublicKey = PublicKey('AddressLookupTab1e1111111111111111111111111')


class AccountLookupTableInfo:
    def __init__(self, table_account: PublicKey, recent_block_slot: int, nonce: int):
        self._table_acct = table_account
        self._recent_block_slot = recent_block_slot
        self._nonce = nonce
        self._acct_key_set: Set[str] = set()
        self._acct_key_list: List[PublicKey] = []

    @staticmethod
    def derive_lookup_table_address(signer_key: PublicKey, recent_block_slot: int) -> Tuple[PublicKey, int]:
        return PublicKey.find_program_address(
            seeds=[bytes(signer_key), recent_block_slot.to_bytes(8, "little")],
            program_id=ADDRESS_LOOKUP_TABLE_ID
        )

    @property
    def table_account(self) -> PublicKey:
        return self._table_acct

    @property
    def recent_block_slot(self) -> int:
        return self._recent_block_slot

    @property
    def nonce(self) -> int:
        return self._nonce

    @property
    def account_key_list(self) -> List[PublicKey]:
        return self._acct_key_list

    @property
    def account_key_list_len(self) -> int:
        return len(self._acct_key_list)

    def init_from_legacy_tx(self, tx: Transaction) -> None:
        assert not len(self._acct_key_list)

        msg = tx.compile_message()
        builder = AccountLookupTableBuilder(msg)

        alt_acct_set = builder.build_alt_account_key_set()
        self._acct_key_set = alt_acct_set
        self._acct_key_list = [PublicKey(key) for key in alt_acct_set]

    def _validate_alt_info(self, alt_info: AccountLookupTableAccountInfo) -> None:
        alt_acct_set: Set[str] = set([str(key) for key in alt_info.account_key_list])

        if len(alt_acct_set) != len(alt_info.account_key_list):
            raise AccountLookupTableError(f'The lookup table {str(self._table_acct)} has duplicates')

        if str(self._table_acct) != str(alt_info.table_account):
            raise AccountLookupTableError(
                'Trying to update account list from another lookup table: ' +
                f'{str(self._table_acct)} != {str(alt_info.table_account)}'
            )

        if not len(self._acct_key_list):
            # Init from the scratch
            return

        # Validate the content of account lists
        if len(self._acct_key_list) != len(alt_info.account_key_list):
            raise AccountLookupTableError(
                f'The account list from the lookup table {str(self._table_acct)} has another length than expected: ' +
                f'{len(self._acct_key_list)} != {len(alt_info.account_key_list)}'
            )

        for key in alt_info.account_key_list:
            if str(key) not in self._acct_key_set:
                raise AccountLookupTableError(f'The unknown key {str(key)} in the lookup table {str(self._table_acct)}')

    def update_from_account(self, alt_info: AccountLookupTableAccountInfo) -> None:
        self._validate_alt_info(alt_info)
        self._acct_key_list = alt_info.account_key_list
