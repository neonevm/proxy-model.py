import logging
from typing import List, Optional, Callable, Dict, cast

from ..common_neon.constants import ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.layouts import ACCOUNT_LOOKUP_TABLE_LAYOUT, ALTAccountInfo, AccountInfo
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_tx import SolAccount, SolPubKey, SolTxIx, SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxListSender

from .mempool_api import MPALTListResult
from .mempool_api import MPGetALTList, MPALTInfo, MPDeactivateALTListRequest, MPCloseALTListRequest
from .mempool_executor_task_base import MPExecutorBaseTask


LOG = logging.getLogger(__name__)


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

    def _decode_alt_info(self, account_info: Optional[AccountInfo], secret: bytes) -> Optional[MPALTInfo]:
        try:
            if account_info is None:
                return None

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
                operator_key=secret
            )

            return mp_alt_info
        except BaseException as exc:
            LOG.error('Cannot decode ALT', exc_info=exc)
        return None

    def get_alt_list(self, mp_req: MPGetALTList) -> MPALTListResult:
        mp_alt_info_dict: Dict[str, MPALTInfo] = dict()

        for alt_address in mp_req.alt_address_list:
            account_info = self._solana.get_account_info(
                SolPubKey.from_string(alt_address.table_account),
                length=ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof(),
                commitment=self._config.finalized_commitment
            )

            mp_alt_info = self._decode_alt_info(account_info, alt_address.secret)
            if mp_alt_info is not None:
                mp_alt_info_dict[alt_address.table_account] = mp_alt_info

        for secret in mp_req.secret_list:
            operator_account = SolAccount.from_seed(secret)

            account_info_list = self._solana.get_program_account_info_list(
                program=ADDRESS_LOOKUP_TABLE_ID,
                offset=0,
                length=ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof(),
                data_offset=self._auth_offset,
                data=bytes(operator_account.pubkey()),
                commitment=self._config.finalized_commitment
            )

            for account_info in account_info_list:
                if str(account_info.address) in mp_alt_info_dict:
                    continue

                mp_alt_info = self._decode_alt_info(account_info, secret)
                if mp_alt_info is not None:
                    mp_alt_info_dict[mp_alt_info.table_account] = mp_alt_info

        block_height = self._get_block_height()
        return MPALTListResult(block_height=block_height, alt_info_list=list(mp_alt_info_dict.values()))

    def _free_alt_list(self, alt_info_list: List[MPALTInfo], name: str,
                       make_ix: Callable[[NeonIxBuilder, SolPubKey], SolTxIx]) -> MPALTListResult:
        def _send_tx_list() -> None:
            if len(tx_list) == 0:
                return

            tx_sender = SolTxListSender(self._config, self._solana, cast(SolAccount, signer))
            try:
                tx_sender.send(tx_list)
            except BaseException as exc:
                LOG.debug('Failed to execute.', exc_info=exc)
            tx_list.clear()

        tx_list: List[SolTx] = list()
        signer: Optional[SolAccount] = None

        alt_info_list = sorted(alt_info_list, key=lambda a: a.operator_key)
        ix_builder: Optional[NeonIxBuilder] = None
        block_height: Optional[int] = None

        for alt_info in alt_info_list:
            operator_key = alt_info.operator_key

            if (signer is not None) and (signer.secret() != operator_key):
                _send_tx_list()

            if len(tx_list) == 0:
                signer = SolAccount.from_seed(operator_key)
                ix_builder = NeonIxBuilder(signer.pubkey())
                block_height = self._get_block_height()

            alt_info.block_height = block_height
            tx = SolLegacyTx(
                name=name,
                instructions=[make_ix(ix_builder, SolPubKey.from_string(alt_info.table_account))]
            )
            tx_list.append(tx)

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
