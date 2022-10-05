from __future__ import annotations

import time

from typing import Optional, List

from ..common_neon.errors import ALTError
from ..common_neon.solana_transaction import SolLegacyTx, SolWrappedTx, SolTx, SolAccount
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.neon_instruction import NeonIxBuilder


class ALTTxSet:
    def __init__(self, create_alt_tx_list: Optional[List[SolLegacyTx]] = None,
                 extend_alt_tx_list: Optional[List[SolLegacyTx]] = None) -> None:
        self.create_alt_tx_list = create_alt_tx_list if create_alt_tx_list is not None else []
        self.extend_alt_tx_list = extend_alt_tx_list if extend_alt_tx_list is not None else []

    def extend(self, tx_list: ALTTxSet) -> ALTTxSet:
        self.create_alt_tx_list.extend(tx_list.create_alt_tx_list)
        self.extend_alt_tx_list.extend(tx_list.extend_alt_tx_list)
        return self

    def __len__(self) -> int:
        return len(self.create_alt_tx_list) + len(self.extend_alt_tx_list)

    def clear(self) -> None:
        self.create_alt_tx_list.clear()
        self.extend_alt_tx_list.clear()


class ALTTxBuilder:
    tx_account_cnt = 30

    def __init__(self, solana: SolInteractor, ix_builder: NeonIxBuilder, signer: SolAccount) -> None:
        self._solana = solana
        self._ix_builder = ix_builder
        self._signer = signer
        self._recent_block_slot: Optional[int] = None

    def _get_recent_block_slot(self) -> int:
        while True:
            recent_block_slot = self._solana.get_recent_blockslot('finalized')
            if recent_block_slot == self._recent_block_slot:
                time.sleep(0.1)  # To make unique address for Address Lookup Table
                continue
            self._recent_block_slot = recent_block_slot
            return recent_block_slot

    def build_alt_info(self, legacy_tx: SolLegacyTx) -> ALTInfo:
        recent_block_slot = self._get_recent_block_slot()
        signer_key = self._signer.public_key()
        acct, nonce = ALTInfo.derive_lookup_table_address(signer_key, recent_block_slot)
        alt_info = ALTInfo(acct, recent_block_slot, nonce)
        alt_info.init_from_legacy_tx(legacy_tx)
        return alt_info

    def build_alt_tx_set(self, alt_info: ALTInfo) -> ALTTxSet:
        # Tx to create an Account Lookup Table
        create_alt_tx = SolLegacyTx().add(self._ix_builder.make_create_lookup_table_ix(
            alt_info.table_account, alt_info.recent_block_slot, alt_info.nonce
        ))

        # List of tx to extend the Account Lookup Table
        acct_list = alt_info.account_key_list

        extend_alt_tx_list: List[SolLegacyTx] = []
        while len(acct_list):
            acct_list_part, acct_list = acct_list[:self.tx_account_cnt], acct_list[self.tx_account_cnt:]
            tx = SolLegacyTx().add(self._ix_builder.make_extend_lookup_table_ix(alt_info.table_account, acct_list_part))
            extend_alt_tx_list.append(tx)

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        create_alt_tx.add(extend_alt_tx_list[0])
        extend_alt_tx_list = extend_alt_tx_list[1:]

        return ALTTxSet(
            create_alt_tx_list=[create_alt_tx],
            extend_alt_tx_list=extend_alt_tx_list
        )

    @staticmethod
    def build_prep_alt_list(alt_tx_set: ALTTxSet) -> List[List[SolTx]]:
        tx_list_list: List[List[SolTx]] = [[
            SolWrappedTx(name='CreateLookupTable:ExtendLookupTable', tx=tx) for tx in alt_tx_set.create_alt_tx_list
        ]]

        if len(alt_tx_set.extend_alt_tx_list) > 0:
            tx_list_list.append([SolWrappedTx(name='ExtendLookupTable', tx=tx) for tx in alt_tx_set.extend_alt_tx_list])

        return tx_list_list

    def update_alt_info_list(self, alt_info_list: List[ALTInfo]) -> None:
        # Accounts in Account Lookup Table can be reordered
        for alt_info in alt_info_list:
            alt_acct_info = self._solana.get_account_lookup_table_info(alt_info.table_account)
            if alt_acct_info is None:
                raise ALTError(f'Cannot read lookup table {str(alt_info.table_account)}')
            alt_info.update_from_account(alt_acct_info)
