from typing import List, Optional, Callable, cast

from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_transaction import SolAccount, SolPubKey, SolLegacyTx, SolWrappedTx, SolTx, SolTxIx
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.constants import ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.layouts import ACCOUNT_LOOKUP_TABLE_LAYOUT
from ..common_neon.solana_interactor import ALTAccountInfo

from ..mempool.mempool_api import MPGetALTList, MPALTInfo, MPDeactivateALTListRequest, MPCloseALTListRequest
from ..mempool.mempool_api import MPALTListResult
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask


class MPExecutorFreeALTQueueTask(MPExecutorBaseTask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_offset = 0
        for sc in ACCOUNT_LOOKUP_TABLE_LAYOUT.subcons:
            if sc.name == 'authority':
                break
            self._auth_offset += sc.sizeof()

    def _get_block_height(self) -> int:
        return self._solana.get_block_height(commitment=self._config.finalized_commitment)

    def get_alt_list(self, mp_req: MPGetALTList) -> MPALTListResult:
        alt_info_list: List[MPALTInfo] = []

        for operator_key in mp_req.operator_key_list:
            operator_account = SolAccount(bytes.fromhex(operator_key))

            account_info_list = self._solana.get_program_account_info_list(
                program=ADDRESS_LOOKUP_TABLE_ID,
                offset=0,
                length=ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof(),
                data_offset=self._auth_offset,
                data=bytes(operator_account.public_key())
            )

            for account_info in account_info_list:
                try:
                    alt_info = ALTAccountInfo.from_account_info(account_info)

                    block_height = self._solana.get_block_height(
                        block_slot=(
                            alt_info.last_extended_slot if alt_info.deactivation_slot is None else
                            alt_info.deactivation_slot
                        ),
                        commitment=self._config.finalized_commitment
                    )

                    mp_alt_info = MPALTInfo(
                        last_extended_slot=alt_info.last_extended_slot,
                        deactivation_slot=alt_info.deactivation_slot,
                        block_height=block_height,
                        table_account=str(account_info.address),
                        operator_key=operator_key
                    )

                    alt_info_list.append(mp_alt_info)
                except BaseException as exc:
                    self.error('Cannot decode ALT.', exc_info=exc)

        block_height = self._get_block_height()
        return MPALTListResult(block_height=block_height, alt_info_list=alt_info_list)

    def _free_alt_list(self, alt_info_list: List[MPALTInfo], name: str,
                       make_ix: Callable[[NeonIxBuilder, SolPubKey], SolTxIx]) -> MPALTListResult:
        def _send_tx_list() -> None:
            if len(tx_list) == 0:
                return

            tx_sender = SolTxListSender(self._config, self._solana, cast(SolAccount, signer))
            try:
                tx_sender.send(tx_list)
            except BaseException as exc:
                self.debug('Failed to execute.', exc_info=exc)
            tx_list.clear()

        tx_list: List[SolTx] = []
        signer: Optional[SolAccount] = None

        alt_info_list = sorted(alt_info_list, key=lambda a: a.operator_key)
        ix_builder: Optional[NeonIxBuilder] = None
        block_height: Optional[int] = None

        for alt_info in alt_info_list:
            operator_key = bytes.fromhex(alt_info.operator_key)

            if (signer is not None) and (signer.secret_key() != operator_key):
                _send_tx_list()

            if len(tx_list) == 0:
                signer = SolAccount(operator_key)
                ix_builder = NeonIxBuilder(signer.public_key())
                block_height = self._get_block_height()

            alt_info.block_height = block_height
            tx = SolLegacyTx().add(make_ix(ix_builder, SolPubKey(alt_info.table_account)))
            tx_list.append(SolWrappedTx(name=name, tx=tx))

        _send_tx_list()
        block_height = self._get_block_height()
        return MPALTListResult(block_height=block_height, alt_info_list=alt_info_list)

    def deactivate_alt_list(self, mp_req: MPDeactivateALTListRequest) -> MPALTListResult:
        return self._free_alt_list(
            mp_req.alt_info_list,
            'DeactivateLookupTable',
            lambda ix_builder, table_account: ix_builder.make_deactivate_lookup_table_ix(table_account)
        )

    def close_alt_list(self, mp_req: MPCloseALTListRequest) -> MPALTListResult:
        return self._free_alt_list(
            mp_req.alt_info_list,
            'CloseLookupTable',
            lambda ix_builder, table_account: ix_builder.make_close_lookup_table_ix(table_account)
        )
