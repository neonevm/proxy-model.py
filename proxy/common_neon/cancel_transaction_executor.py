from typing import List, Set

from solana.transaction import Transaction, AccountMeta
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolanaInteractor, HolderAccountInfo
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.solana_v0_transaction import V0Transaction
from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_builder import AddressLookupTableTxBuilder, AddressLookupTableTxSet
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue


class CancelTxExecutor:
    def __init__(self, solana: SolanaInteractor, signer: SolanaAccount) -> None:
        self._builder = NeonIxBuilder(signer.public_key())
        self._solana = solana
        self._signer = signer

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)
        self._alt_builder = AddressLookupTableTxBuilder(solana, self._builder, signer, self._alt_close_queue)
        self._alt_tx_set = AddressLookupTableTxSet()
        self._alt_info_list: List[AddressLookupTableInfo] = []
        self._cancel_tx_list: List[Transaction] = []
        self._holder_account_set: Set[str] = set()

    def add_blocked_holder_account(self, holder_info: HolderAccountInfo) -> bool:
        if str(holder_info.holder_account) in self._holder_account_set:
            return False

        if len(holder_info.account_list) >= self._alt_builder.TX_ACCOUNT_CNT:
            tx = self._build_alt_cancel_tx(holder_info)
        else:
            tx = self._build_cancel_tx(holder_info)
        self._cancel_tx_list.append(tx)
        return True

    def _build_cancel_tx(self, holder_info: HolderAccountInfo) -> Transaction:
        key_list: List[AccountMeta] = []
        for is_writable, acct in holder_info.account_list:
            key_list.append(AccountMeta(pubkey=PublicKey(acct), is_signer=False, is_writable=is_writable))

        return Transaction().add(
            self._builder.make_cancel_ix(
                holder_account=holder_info.holder_account,
                neon_tx_sig=bytes.fromhex(holder_info.neon_tx_sig[2:]),
                cancel_key_list=key_list
            )
        )

    def _build_alt_cancel_tx(self, holder_info: HolderAccountInfo) -> Transaction:
        legacy_tx = self._build_cancel_tx(holder_info)
        alt_info = self._alt_builder.build_alt_info(legacy_tx)
        alt_tx_set = self._alt_builder.build_alt_tx_set(alt_info)

        self._alt_info_list.append(alt_info)
        self._alt_tx_set.extend(alt_tx_set)

        return V0Transaction(address_table_lookups=[alt_info]).add(legacy_tx)

    def execute_tx_list(self) -> None:
        if not len(self._cancel_tx_list):
            return

        tx_sender = SolTxListSender(self._solana, self._signer)

        # Prepare Address Lookup Tables
        if len(self._alt_tx_set) > 0:
            tx_list_info_list = self._alt_builder.build_prep_alt_list(self._alt_tx_set)
            for tx_list_info in tx_list_info_list:
                tx_sender.send(tx_list_info)

            # Update lookups from Solana
            self._alt_builder.update_alt_info_list(self._alt_info_list)

        tx_list_info = SolTxListInfo(
            name_list=['Cancel' for _ in self._cancel_tx_list],
            tx_list=self._cancel_tx_list
        )

        # Close old Address Lookup Tables
        alt_tx_list = self._alt_close_queue.pop_tx_list(self._signer.public_key())
        if len(alt_tx_list):
            tx_list_info.name_list.extend(['CloseLookupTable' for _ in alt_tx_list])
            tx_list_info.tx_list.extend(alt_tx_list)

        try:
            tx_sender.send(tx_list_info)
        finally:
            if len(self._alt_tx_set) > 0:
                # Deactivate Address Lookup Tables
                tx_list_info_list = self._alt_builder.build_done_alt_tx_set(self._alt_tx_set)
                for tx_list_info in tx_list_info_list:
                    tx_sender.send(tx_list_info)

    def clear(self) -> None:
        self._alt_info_list.clear()
        self._alt_tx_set.clear()
        self._cancel_tx_list.clear()
