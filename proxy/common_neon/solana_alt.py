from __future__ import annotations

from typing import List, Tuple, Set

from ..common_neon.solana_transaction import SolLegacyTx, SolPubKey, SolBlockhash, SolLegacyMsg
from ..common_neon.constants import ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.errors import ALTError
from ..common_neon.solana_alt_list_filter import ALTListFilter
from ..common_neon.solana_interactor import ALTAccountInfo


class ALTInfo:
    def __init__(self, table_account: SolPubKey, recent_block_slot: int, nonce: int):
        self._table_acct = table_account
        self._recent_block_slot = recent_block_slot
        self._nonce = nonce
        self._acct_key_set: Set[str] = set()
        self._acct_key_list: List[SolPubKey] = []

    @staticmethod
    def derive_lookup_table_address(signer_key: SolPubKey, recent_block_slot: int) -> Tuple[SolPubKey, int]:
        return SolPubKey.find_program_address(
            seeds=[bytes(signer_key), recent_block_slot.to_bytes(8, "little")],
            program_id=ADDRESS_LOOKUP_TABLE_ID
        )

    @property
    def table_account(self) -> SolPubKey:
        return self._table_acct

    @property
    def recent_block_slot(self) -> int:
        return self._recent_block_slot

    @property
    def nonce(self) -> int:
        return self._nonce

    @property
    def account_key_list(self) -> List[SolPubKey]:
        return self._acct_key_list

    @property
    def account_key_list_len(self) -> int:
        return len(self._acct_key_list)

    @staticmethod
    def _compile_msg(tx: SolLegacyTx) -> SolLegacyMsg:
        # Predefined blockhash is used only to compile legacy tx, the transaction won't be sent to network
        tx.recent_blockhash = SolBlockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        # Predefined public key is used only to compile legacy tx, the transaction won't be sent to network
        tx.fee_payer = SolPubKey('AdtXr9yGAsTokY75WernsmQdcBPu2LE2Bsh8Nx3ApbbR')
        return tx.compile_message()

    def init_from_legacy_tx(self, tx: SolLegacyTx) -> None:
        assert not len(self._acct_key_list)

        msg = self._compile_msg(tx)
        alt_filter = ALTListFilter(msg)

        alt_acct_set = alt_filter.filter_alt_account_key_set()
        self._acct_key_set = alt_acct_set
        self._acct_key_list = [SolPubKey(key) for key in alt_acct_set]
        if not self.account_key_list_len:
            raise ALTError(f'No accounts for the lookup table {str(self._table_acct)}')

    def _validate_alt_info(self, alt_acct_info: ALTAccountInfo) -> None:
        alt_acct_set: Set[str] = set([str(key) for key in alt_acct_info.account_key_list])

        if len(alt_acct_set) != len(alt_acct_info.account_key_list):
            raise ALTError(f'The lookup table {str(self._table_acct)} has duplicates')

        if str(self._table_acct) != str(alt_acct_info.table_account):
            raise ALTError(
                'Trying to update account list from another lookup table: ' +
                f'{str(self._table_acct)} != {str(alt_acct_info.table_account)}'
            )

        if not len(self._acct_key_list):
            # Init from the scratch
            return

        # Validate the content of account lists
        if len(self._acct_key_list) != len(alt_acct_info.account_key_list):
            raise ALTError(
                f'The account list from the lookup table {str(self._table_acct)} has another length than expected: ' +
                f'{len(self._acct_key_list)} != {len(alt_acct_info.account_key_list)}'
            )

        for key in alt_acct_info.account_key_list:
            if str(key) not in self._acct_key_set:
                raise ALTError(f'The unknown key {str(key)} in the lookup table {str(self._table_acct)}')

    def update_from_account(self, alt_account_info: ALTAccountInfo) -> None:
        self._validate_alt_info(alt_account_info)
        self._acct_key_list = alt_account_info.account_key_list
