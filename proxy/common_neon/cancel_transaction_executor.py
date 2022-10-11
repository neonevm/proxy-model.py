from typing import List, Set

from logged_groups import logged_group

from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_transaction import SolLegacyTx, SolWrappedTx, SolAccountMeta, SolAccount, SolPubKey
from ..common_neon.solana_v0_transaction import SolV0Tx
from ..common_neon.solana_interactor import SolInteractor, HolderAccountInfo
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_builder import ALTTxBuilder, ALTTxSet
from ..common_neon.config import Config


@logged_group("Neon.Canceler")
class CancelTxExecutor:
    def __init__(self, config: Config, solana: SolInteractor, signer: SolAccount) -> None:
        self._ix_builder = NeonIxBuilder(signer.public_key())
        self._config = config
        self._solana = solana
        self._signer = signer

        self._alt_builder = ALTTxBuilder(solana, self._ix_builder, signer)
        self._alt_tx_set = ALTTxSet()
        self._alt_info_list: List[ALTInfo] = []
        self._cancel_tx_list: List[SolLegacyTx] = []
        self._holder_account_set: Set[str] = set()

    def add_blocked_holder_account(self, holder_info: HolderAccountInfo) -> bool:
        if str(holder_info.holder_account) in self._holder_account_set:
            return False

        if len(holder_info.account_list) >= self._alt_builder.tx_account_cnt:
            tx = self._build_alt_cancel_tx(holder_info)
        else:
            tx = self._build_cancel_tx(holder_info)
        self._cancel_tx_list.append(tx)
        return True

    def _build_cancel_tx(self, holder_info: HolderAccountInfo) -> SolLegacyTx:
        key_list: List[SolAccountMeta] = []
        for is_writable, acct in holder_info.account_list:
            key_list.append(SolAccountMeta(pubkey=SolPubKey(acct), is_signer=False, is_writable=is_writable))

        return SolLegacyTx().add(
            self._ix_builder.make_cancel_ix(
                holder_account=holder_info.holder_account,
                neon_tx_sig=bytes.fromhex(holder_info.neon_tx_sig[2:]),
                cancel_key_list=key_list
            )
        )

    def _build_alt_cancel_tx(self, holder_info: HolderAccountInfo) -> SolV0Tx:
        legacy_tx = self._build_cancel_tx(holder_info)
        alt_info = self._alt_builder.build_alt_info(legacy_tx)
        alt_tx_set = self._alt_builder.build_alt_tx_set(alt_info)

        self._alt_info_list.append(alt_info)
        self._alt_tx_set.extend(alt_tx_set)

        return SolV0Tx(address_table_lookups=[alt_info]).add(legacy_tx)

    def execute_tx_list(self) -> None:
        if not len(self._cancel_tx_list):
            return

        tx_sender = SolTxListSender(self._config, self._solana, self._signer)

        # Prepare Address Lookup Tables
        if len(self._alt_tx_set) > 0:
            tx_list_info_list = self._alt_builder.build_prep_alt_list(self._alt_tx_set)
            for tx_list_info in tx_list_info_list:
                tx_sender.send(tx_list_info)

            # Update lookups from Solana
            self._alt_builder.update_alt_info_list(self._alt_info_list)

        tx_list = [SolWrappedTx(name='CancelWithHash', tx=tx) for tx in self._cancel_tx_list]

        try:
            tx_sender.send(tx_list)
        except BaseException as exc:
            self.warning('Failed to cancel tx', exc_info=exc)

    def clear(self) -> None:
        self._alt_info_list.clear()
        self._alt_tx_set.clear()
        self._cancel_tx_list.clear()
