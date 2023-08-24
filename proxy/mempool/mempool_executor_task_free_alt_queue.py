import logging
from typing import List, Optional, Callable, Dict, Any, cast

from .mempool_api import MPALTListResult
from .mempool_api import MPGetALTList, MPALTInfo, MPDeactivateALTListRequest, MPCloseALTListRequest
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.config import Config
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.errors import RescheduleError
from ..common_neon.layouts import ACCOUNT_LOOKUP_TABLE_LAYOUT, ALTAccountInfo
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolAccount, SolPubKey, SolTxIx, SolTx, SolCommit
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxListSender

from ..indexer.indexed_objects import NeonIndexedAltInfo
from ..indexer.solana_alt_infos_db import SolAltInfosDB

LOG = logging.getLogger(__name__)


class MPExecutorFreeALTQueueTask(MPExecutorBaseTask):
    def _get_block_height(self) -> int:
        return self._solana.get_block_height(commitment=SolCommit.Finalized)

    def _decode_alt_info(self, alt_table_acct: str,
                         secret: Optional[bytes],
                         secret_dict: Dict[SolPubKey, bytes]) -> Optional[MPALTInfo]:
        try:
            account_info = self._solana.get_account_info(
                SolPubKey.from_string(alt_table_acct),
                length=ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof(),
                commitment=SolCommit.Finalized
            )
            if account_info is None:
                return None

            alt_info = ALTAccountInfo.from_account_info(account_info)

            block_height = self._solana.get_block_height(
                block_slot=(
                    alt_info.last_extended_slot if alt_info.deactivation_slot is None else
                    alt_info.deactivation_slot
                ),
                commitment=SolCommit.Finalized
            )

            if alt_info.authority is None:
                LOG.warning(f'ALT table {str(alt_info.table_account)} is frozen')
                return None

            if secret is None:
                secret = secret_dict.get(alt_info.authority, None)

            if secret is None:
                LOG.warning(f'ALT table {str(alt_info.table_account)} has unknown owner')
                return None

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

        secret_dict: Dict[SolPubKey, bytes] = dict()
        for secret in mp_req.secret_list:
            op_acct = SolAccount.from_seed(secret)
            secret_dict[op_acct.pubkey()] = secret

        for alt_address in mp_req.alt_address_list:
            mp_alt_info = self._decode_alt_info(alt_address.table_account, alt_address.secret, secret_dict)
            if mp_alt_info is not None:
                mp_alt_info_dict[alt_address.table_account] = mp_alt_info

        block_slot = self._solana.get_confirmed_slot() - 3
        alt_dict_list = self._get_alt_list(block_slot)

        for alt_dict in alt_dict_list:
            alt_info = NeonIndexedAltInfo.from_dict(alt_dict)
            if not alt_info.is_stuck:
                continue
            elif alt_info.alt_key in mp_alt_info_dict:
                continue

            mp_alt_info = self._decode_alt_info(alt_info.alt_key, None, secret_dict)
            if mp_alt_info is not None:
                mp_alt_info_dict[alt_info.alt_key] = mp_alt_info

        block_height = self._get_block_height()
        return MPALTListResult(block_height=block_height, alt_info_list=list(mp_alt_info_dict.values()))

    def _get_alt_list(self, block_slot: int) -> List[Dict[str, Any]]:
        db_conn = DBConnection(self._config)
        alt_infos_db = SolAltInfosDB(db_conn)

        _, alt_dict_list = alt_infos_db.get_alt_list(block_slot, (2 ** 64 - 1))
        return alt_dict_list

    def _free_alt_list(self, alt_info_list: List[MPALTInfo], name: str,
                       make_ix: Callable[[NeonIxBuilder, SolPubKey], SolTxIx]) -> MPALTListResult:
        def _send_tx_list() -> None:
            if len(tx_list) == 0:
                return

            tx_sender = SolTxListSender(self._config, self._solana, cast(SolAccount, signer))
            try:
                tx_sender.send(tx_list)
            except RescheduleError:
                pass
            except BaseException as exc:
                LOG.debug('Failed to execute', exc_info=exc)
            tx_list.clear()

        tx_list: List[SolTx] = list()
        signer: Optional[SolAccount] = None

        alt_info_list = sorted(alt_info_list, key=lambda a: a.operator_key)
        ix_builder: Optional[NeonIxBuilder] = None
        block_height: Optional[int] = None

        for alt_info in alt_info_list:
            if not self._decode_alt_info(alt_info.table_account, b'hello', dict()):
                continue

            op_key = alt_info.operator_key
            if (signer is not None) and (signer.secret() != op_key):
                _send_tx_list()

            if len(tx_list) == 0:
                signer = SolAccount.from_seed(op_key)
                ix_builder = NeonIxBuilder(self._config, signer.pubkey())
                block_height = self._get_block_height()

            alt_info.block_height = block_height
            tx = SolLegacyTx(
                name=name,
                ix_list=[make_ix(ix_builder, SolPubKey.from_string(alt_info.table_account))]
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
