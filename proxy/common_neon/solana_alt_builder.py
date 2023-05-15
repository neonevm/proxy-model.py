from __future__ import annotations

import time

from typing import Optional, List

from .errors import ALTError
from .neon_instruction import NeonIxBuilder
from .solana_alt import ALTInfo
from .solana_alt_limit import ALTLimit
from .solana_interactor import SolInteractor
from .solana_tx import SolTx, SolAccount, SolCommit
from .solana_tx_legacy import SolLegacyTx


class ALTTxSet:
    def __init__(self, create_alt_tx_list: Optional[List[SolLegacyTx]] = None,
                 extend_alt_tx_list: Optional[List[SolLegacyTx]] = None) -> None:
        self.create_alt_tx_list = create_alt_tx_list if create_alt_tx_list is not None else list()
        self.extend_alt_tx_list = extend_alt_tx_list if extend_alt_tx_list is not None else list()

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
    _create_name = 'CreateLookupTable'
    _extend_name = 'ExtendLookupTable'

    def __init__(self, solana: SolInteractor, ix_builder: NeonIxBuilder, signer: SolAccount) -> None:
        self._solana = solana
        self._ix_builder = ix_builder
        self._signer = signer
        self._recent_block_slot: Optional[int] = None

    def _get_recent_block_slot(self) -> int:
        while True:
            recent_block_slot = self._solana.get_block_slot(SolCommit.Finalized)
            if recent_block_slot == self._recent_block_slot:
                time.sleep(0.1)  # To make unique address for Address Lookup Table
                continue
            self._recent_block_slot = recent_block_slot
            return recent_block_slot

    def get_tx_name_list(self) -> List[str]:
        return [self._create_name, self._extend_name]

    def build_alt_info(self, legacy_tx: SolLegacyTx) -> ALTInfo:
        recent_block_slot = self._get_recent_block_slot()
        signer_key = self._signer.pubkey()
        alt_address = ALTInfo.derive_lookup_table_address(signer_key, recent_block_slot)
        alt_info = ALTInfo(alt_address)
        alt_info.init_from_legacy_tx(legacy_tx)
        return alt_info

    def build_alt_tx_set(self, alt_info: ALTInfo) -> ALTTxSet:
        is_alt_exist = alt_info.is_exist()

        # Tx to create an Address Lookup Table
        create_alt_tx_list: List[SolLegacyTx] = list()
        if not is_alt_exist:
            create_alt_tx = SolLegacyTx(
                name=self._create_name,
                ix_list=[
                    self._ix_builder.make_create_lookup_table_ix(
                        alt_info.table_account,
                        alt_info.recent_block_slot,
                        alt_info.nonce
                    )
                ]
            )
            create_alt_tx_list.append(create_alt_tx)

        # List of accounts to write to the Address Lookup Table
        acct_list = alt_info.new_account_key_list

        # List of txs to extend the Address Lookup Table
        extend_alt_tx_list: List[SolLegacyTx] = list()
        max_tx_account_cnt = ALTLimit.max_tx_account_cnt
        while len(acct_list):
            acct_list_part, acct_list = acct_list[:max_tx_account_cnt], acct_list[max_tx_account_cnt:]
            tx = SolLegacyTx(
                name=self._extend_name,
                ix_list=[
                    self._ix_builder.make_extend_lookup_table_ix(
                        alt_info.table_account,
                        acct_list_part
                    )
                ]
            )
            extend_alt_tx_list.append(tx)

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        if not is_alt_exist:
            create_alt_tx_list[0].add(extend_alt_tx_list[0])
            extend_alt_tx_list = extend_alt_tx_list[1:]

        return ALTTxSet(
            create_alt_tx_list=create_alt_tx_list,
            extend_alt_tx_list=extend_alt_tx_list
        )

    @staticmethod
    def build_prep_alt_list(alt_tx_set: ALTTxSet) -> List[List[SolTx]]:
        tx_list_list: List[List[SolTx]] = list()

        if len(alt_tx_set.create_alt_tx_list) > 0:
            tx_list_list.append(alt_tx_set.create_alt_tx_list)

        if len(alt_tx_set.extend_alt_tx_list) > 0:
            tx_list_list.append(alt_tx_set.extend_alt_tx_list)

        return tx_list_list

    def update_alt_info_list(self, alt_info_list: List[ALTInfo]) -> None:
        # Accounts in Account Lookup Table can be reordered
        for alt_info in alt_info_list:
            alt_acct_info = self._solana.get_account_lookup_table_info(alt_info.table_account)
            if alt_acct_info is None:
                raise ALTError(f'Cannot read lookup table {str(alt_info.table_account)}')
            alt_info.update_from_account(alt_acct_info)
