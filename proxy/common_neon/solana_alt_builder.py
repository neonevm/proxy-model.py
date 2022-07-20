from __future__ import annotations

import time

from typing import Optional, List

from solana.account import Account as SolanaAccount
from solana.transaction import Transaction

from ..common_neon.errors import AccountLookupTableError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_alt import AccountLookupTableInfo
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_tx_list_sender import SolTxListSender, IConfirmWaiter


class AccountLookupTableTxList:
    def __init__(self, create_alt_tx_list: Optional[List[Transaction]] = None,
                 extend_alt_tx_list: Optional[List[Transaction]] = None,
                 deactivate_alt_tx_list: Optional[List[Transaction]] = None) -> None:
        self.create_alt_tx_list = create_alt_tx_list if create_alt_tx_list is not None else []
        self.extend_alt_tx_list = extend_alt_tx_list if extend_alt_tx_list is not None else []
        self.deactivate_alt_tx_list = deactivate_alt_tx_list if deactivate_alt_tx_list is not None else []

    def append(self, tx_list: AccountLookupTableTxList) -> AccountLookupTableTxList:
        self.create_alt_tx_list.extend(tx_list.create_alt_tx_list)
        self.extend_alt_tx_list.extend(tx_list.extend_alt_tx_list)
        self.deactivate_alt_tx_list.extend(tx_list.deactivate_alt_tx_list)
        return self

    def __len__(self) -> int:
        return len(self.create_alt_tx_list) + len(self.extend_alt_tx_list) + len(self.deactivate_alt_tx_list)

    def clear(self) -> None:
        self.create_alt_tx_list.clear()
        self.extend_alt_tx_list.clear()
        self.deactivate_alt_tx_list.clear()


class AccountLookupTableTxBuilder:
    TX_ACCOUNT_CNT = 30

    def __init__(self, solana:  SolanaInteractor, builder: NeonIxBuilder, signer: SolanaAccount) -> None:
        self._solana = solana
        self._builder = builder
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

    def build_alt_info(self, legacy_tx: Transaction) -> AccountLookupTableInfo:
        recent_block_slot = self._get_recent_block_slot()
        signer_key = self._signer.public_key()
        acct, nonce = AccountLookupTableInfo.derive_lookup_table_address(signer_key, recent_block_slot)
        alt_info = AccountLookupTableInfo(acct, recent_block_slot, nonce)
        alt_info.init_from_legacy_tx(legacy_tx)
        return alt_info

    def build_alt_tx_list(self, lookup: AccountLookupTableInfo) -> AccountLookupTableTxList:
        # Tx to create an Account Lookup Table
        create_alt_tx = Transaction().add(
            self._builder.make_create_lookup_table_instruction(
                lookup.table_account,
                lookup.recent_block_slot,
                lookup.nonce
            )
        )

        # List of tx to extend the Account Lookup Table
        acct_list = lookup.account_key_list

        extend_alt_tx_list: List[Transaction] = []
        while len(acct_list):
            acct_list_part, acct_list = acct_list[:self.TX_ACCOUNT_CNT], acct_list[self.TX_ACCOUNT_CNT:]
            tx = Transaction().add(
                self._builder.make_extend_lookup_table_instruction(lookup.table_account, acct_list_part)
            )
            extend_alt_tx_list.append(tx)

        deactivate_alt_tx = Transaction().add(
            self._builder.make_deactivate_lookup_table_instruction(lookup.table_account)
        )

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        create_alt_tx.add(extend_alt_tx_list[0])
        extend_alt_tx_list = extend_alt_tx_list[1:]

        return AccountLookupTableTxList(
            create_alt_tx_list=[create_alt_tx],
            extend_alt_tx_list=extend_alt_tx_list,
            deactivate_alt_tx_list=[deactivate_alt_tx]
        )

    def prep_alt_list(self, alt_tx_list: AccountLookupTableTxList,
                      tx_list_name: str = '', tx_list: Optional[List[Transaction]] = None,
                      waiter: Optional[IConfirmWaiter] = None) -> List[str]:
        if tx_list is None:
            tx_list: List[Transaction] = []

        cnt = len(alt_tx_list.create_alt_tx_list)
        tx_list_name = ' + '.join([tx_list_name, f'CreateLookupTable({cnt})', f'ExtendLookupTable({cnt})'])
        for tx in alt_tx_list.create_alt_tx_list:
            tx_list.append(tx)

        tx_sender = SolTxListSender(self._solana, self._signer)
        tx_sender.send(tx_list_name, tx_list, waiter=waiter)
        sig_list = tx_sender.success_sig_list

        if len(alt_tx_list.extend_alt_tx_list):
            tx_list_name = f'ExtendLookupTable({len(alt_tx_list.extend_alt_tx_list)})'
            tx_sender.send(tx_list_name, alt_tx_list.extend_alt_tx_list, waiter=waiter)
            sig_list += tx_sender.success_sig_list

        return sig_list

    def update_alt_info_list(self, alt_info_list: List[AccountLookupTableInfo]) -> None:
        # Accounts in Account Lookup Table can be reordered
        for alt_info in alt_info_list:
            alt_acct_info = self._solana.get_account_lookup_table_info(alt_info.table_account)
            if alt_acct_info is None:
                raise AccountLookupTableError(f'Cannot read lookup table {str(alt_info.table_account)}')
            alt_info.update_from_account(alt_acct_info)

    def done_alt_list(self, alt_tx_list: AccountLookupTableTxList,
                      waiter: Optional[IConfirmWaiter] = None) -> List[str]:
        tx_list_name = f'DeactivateLookupTable({len(alt_tx_list)})'
        tx_list = alt_tx_list.deactivate_alt_tx_list

        tx_sender = SolTxListSender(self._solana, self._signer)
        tx_sender.send(tx_list_name, tx_list, waiter=waiter)
        return tx_sender.success_sig_list
