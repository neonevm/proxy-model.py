from __future__ import annotations

import time
import logging
from collections import deque
from typing import List, Optional, Dict, Deque, Type, Set

from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.config import Config
from ..common_neon.constants import ACTIVE_HOLDER_TAG
from ..common_neon.operator_secret_mng import OpSecretMng
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxCostInfo
from ..common_neon.solana_tx import SolPubKey, SolAccount
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.utils import SolBlockInfo
from ..common_neon.utils.json_logger import logging_context

from ..statistic.data import NeonBlockStatData
from ..statistic.indexer_client import IndexerStatClient

from ..indexer.indexed_objects import NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonTxDecoderState
from ..indexer.indexed_objects import NeonIndexedTxInfo
from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from ..indexer.neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list
from ..indexer.solana_tx_meta_collector import FinalizedSolTxMetaCollector, ConfirmedSolTxMetaCollector
from ..indexer.solana_tx_meta_collector import SolTxMetaDict, SolHistoryNotFound
from ..indexer.utils import MetricsToLogger


LOG = logging.getLogger(__name__)


class Indexer(IndexerBase):
    def __init__(self, config: Config):
        solana = SolInteractor(config, config.solana_url)
        self._db = IndexerDB(config)
        last_known_slot = self._db.get_min_receipt_block_slot()
        super().__init__(config, solana, last_known_slot)

        self._last_op_account_update_time = 0.0
        self._op_account_set: Set[str] = set()

        self._cancel_tx_executor: Optional[CancelTxExecutor] = None
        self._refresh_op_account_list()

        self._counted_logger = MetricsToLogger()
        self._stat_client = IndexerStatClient(config)
        self._stat_client.start()
        self._last_stat_time = 0.0

        sol_tx_meta_dict = SolTxMetaDict()
        collector = FinalizedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict, self._start_slot)
        self._finalized_sol_tx_collector = collector

        collector = ConfirmedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict)
        self._confirmed_sol_tx_collector = collector

        self._confirmed_block_slot: Optional[int] = None

        self._last_confirmed_block_slot = 0
        self._last_finalized_block_slot = 0
        self._neon_block_dict = NeonIndexedBlockDict()

        sol_neon_ix_decoder_list: List[Type[DummyIxDecoder]] = list()
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_list())
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_deprecated_list())

        self._sol_neon_ix_decoder_dict: Dict[int, Type[DummyIxDecoder]] = dict()
        for decoder in sol_neon_ix_decoder_list:
            ix_code = decoder.ix_code()
            assert ix_code not in self._sol_neon_ix_decoder_dict
            self._sol_neon_ix_decoder_dict[ix_code] = decoder

    def _refresh_op_account_list(self) -> None:
        now = time.time()
        if abs(now - self._last_op_account_update_time) < 5 * 60:
            return
        self._last_op_account_update_time = now

        op_secret_mng = OpSecretMng(self._config)
        secret_list = op_secret_mng.read_secret_list()
        if len(secret_list) == 0:
            return

        if self._cancel_tx_executor is None:
            signer = SolAccount.from_seed(secret_list[0])
            self._cancel_tx_executor = CancelTxExecutor(self._config, self._solana, signer)

        self._op_account_set: Set[str] = {str(SolAccount.from_seed(k).pubkey()) for k in secret_list}

    def _cancel_old_neon_txs(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> None:
        if self._cancel_tx_executor is None:
            return

        for tx in state.neon_block.iter_neon_tx():
            if tx.holder_account == '':
                continue
            if state.stop_block_slot - tx.last_block_slot > self._config.cancel_timeout:
                self._cancel_neon_tx(tx, sol_tx_meta)

        try:
            self._cancel_tx_executor.execute_tx_list()
        except BaseException as exc:
            LOG.warning('Failed to cancel neon txs', exc_info=exc)
        finally:
            self._cancel_tx_executor.clear()

    def _cancel_neon_tx(self, tx: NeonIndexedTxInfo, sol_tx_meta: SolTxMetaInfo) -> bool:
        # We've already indexed the transaction
        if tx.neon_tx_res.is_valid():
            return True

        # We've already sent Cancel and are waiting for receipt
        if tx.status != NeonIndexedTxInfo.Status.InProgress:
            return True

        if not tx.blocked_account_cnt:
            LOG.warning(f"neon tx {tx.neon_tx} hasn't blocked accounts.")
            return False

        holder_account = tx.holder_account
        holder_info = self._solana.get_holder_account_info(SolPubKey.from_string(holder_account))
        if not holder_info:
            LOG.warning(f'holder {holder_account} for neon tx {tx.neon_tx.sig} is empty')
            return False

        if holder_info.tag != ACTIVE_HOLDER_TAG:
            LOG.warning(f'holder {holder_account} for neon tx {tx.neon_tx.sig} has bad tag: {holder_info.tag}')
            return False

        if holder_info.neon_tx_sig != tx.neon_tx.sig:
            LOG.warning(
                f'storage {holder_account} has another neon tx hash: '
                f'{holder_info.neon_tx_sig} != {tx.neon_tx.sig}'
            )
            return False

        if not self._cancel_tx_executor.add_blocked_holder_account(holder_info):
            LOG.warning(
                f'neon tx {tx.neon_tx} uses the storage account {holder_account} '
                'which is already in the list on unlock'
            )
            return False

        LOG.debug(f'Neon tx is blocked: storage {holder_account}, {tx.neon_tx}, {holder_info.account_list}')
        tx.set_status(NeonIndexedTxInfo.Status.Canceled, sol_tx_meta.block_slot)
        return True

    def _save_checkpoint(self) -> None:
        cache_stat = self._neon_block_dict.stat
        self._db.set_min_receipt_block_slot(cache_stat.min_block_slot)

    def _complete_neon_block(self, state: SolNeonTxDecoderState) -> None:
        if not state.has_neon_block():
            return

        neon_block = state.neon_block
        is_finalized = state.is_neon_block_finalized
        backup_is_finalized = neon_block.is_finalized
        if backup_is_finalized:
            return

        try:
            neon_block.set_finalized(is_finalized)
            if not neon_block.is_completed:
                neon_block.fill_log_info_list()
                self._db.submit_block(neon_block)
                neon_block.calc_stat(self._config, self._op_account_set)
                neon_block.complete_block(self._config)
            elif is_finalized:
                # the confirmed block becomes finalized
                self._db.finalize_block(neon_block)

            # Add block to cache only after indexing and applying last changes to DB
            self._neon_block_dict.add_neon_block(neon_block)
            if is_finalized:
                self._neon_block_dict.finalize_neon_block(neon_block)
                self._commit_tx_stat(neon_block)
                self._save_checkpoint()

            self._commit_block_stat(neon_block)
            self._commit_status_stat()
        except (Exception,):
            # Revert finalized status
            neon_block.set_finalized(backup_is_finalized)
            raise

    def _commit_tx_stat(self, neon_block: NeonIndexedBlockInfo) -> None:
        for tx_stat in neon_block.iter_stat_neon_tx():
            self._stat_client.commit_neon_tx_result(tx_stat)

    def _commit_block_stat(self, neon_block: NeonIndexedBlockInfo) -> None:
        stat = NeonBlockStatData(
            start_block=self._start_slot,
            parsed_block=neon_block.block_slot,
            finalized_block=self._last_finalized_block_slot,
            confirmed_block=self._last_confirmed_block_slot
        )
        self._stat_client.commit_block_stat(stat)

    def _commit_status_stat(self) -> None:
        now = time.time()
        if abs(now - self._last_stat_time) < 1:
            return

        self._last_stat_time = now
        self._stat_client.commit_db_health(self._db.is_healthy())
        self._stat_client.commit_solana_rpc_health(self._solana.is_healthy())

    def _get_sol_block_deque(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> Deque[SolBlockInfo]:
        if not state.has_neon_block():
            sol_block = self._solana.get_block_info(sol_tx_meta.block_slot)
            if sol_block.is_empty():
                raise SolHistoryNotFound(f"can't get block: {sol_tx_meta.block_slot}")
            return deque([sol_block])

        start_block_slot = state.block_slot
        block_slot_list = [block_slot for block_slot in range(start_block_slot + 1, sol_tx_meta.block_slot + 1)]
        sol_block_list = self._solana.get_block_info_list(block_slot_list, state.commitment)
        result_sol_block_deque: Deque[SolBlockInfo] = deque()
        for sol_block in sol_block_list:
            if sol_block.is_empty():
                pass
            elif sol_block.parent_block_slot == start_block_slot:
                result_sol_block_deque.append(sol_block)
                start_block_slot = sol_block.block_slot

        if (len(result_sol_block_deque) == 0) or (result_sol_block_deque[-1].block_slot != sol_tx_meta.block_slot):
            raise SolHistoryNotFound(f"can't get block history: {start_block_slot + 1} -> {sol_tx_meta.block_slot}")
        return result_sol_block_deque

    def _locate_neon_block(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> NeonIndexedBlockInfo:
        # The same block
        if state.has_neon_block():
            if state.neon_block.block_slot == sol_tx_meta.block_slot:
                return state.neon_block
            # The next step, the indexer will choose another block, that is why here is saving of block in DB, cache ...
            self._complete_neon_block(state)

        neon_block = self._neon_block_dict.get_neon_block(sol_tx_meta.block_slot)
        if neon_block:
            pass  # The parsed block from cache
        else:
            # A new block with history from the Solana network
            sol_block_deque = self._get_sol_block_deque(state, sol_tx_meta)
            if state.has_neon_block():
                neon_block = state.neon_block.clone(sol_block_deque)
            else:
                neon_block = NeonIndexedBlockInfo(sol_block_deque)
        state.set_neon_block(neon_block)
        return neon_block

    def _run_sol_tx_collector(self, state: SolNeonTxDecoderState, slot_processing_delay: int) -> None:
        stop_block_slot = self._solana.get_block_slot(state.commitment) - slot_processing_delay
        state.set_stop_block_slot(stop_block_slot)
        if stop_block_slot < state.start_block_slot:
            return

        for sol_tx_meta in state.iter_sol_tx_meta():
            with logging_context(ident=sol_tx_meta.req_id):
                neon_block: NeonIndexedBlockInfo = self._locate_neon_block(state, sol_tx_meta)
                if neon_block.is_completed:
                    continue
                elif neon_block.checked_add_sol_sig(sol_tx_meta.sol_sig):
                    LOG.warning(f'Trying to parse the already parsed tx: {sol_tx_meta.sol_sig}')
                    continue

                sol_tx_cost = SolTxCostInfo.from_tx_meta(sol_tx_meta)
                neon_block.add_sol_tx_cost(sol_tx_cost)
                is_error = SolTxErrorParser(sol_tx_meta.tx).check_if_error()

            for sol_neon_ix in state.iter_sol_neon_ix():
                with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                    neon_block.add_sol_neon_ix(sol_neon_ix)
                    SolNeonIxDecoder = self._sol_neon_ix_decoder_dict.get(sol_neon_ix.program_ix, DummyIxDecoder)
                    sol_neon_ix_decoder = SolNeonIxDecoder(state)
                    if is_error:
                        if hasattr(sol_neon_ix_decoder, 'decode_failed_neon_tx_event_list'):
                            sol_neon_ix_decoder.decode_failed_neon_tx_event_list()
                        # LOG.debug('failed tx')
                        continue

                    sol_neon_ix_decoder.execute()

        sol_tx_meta = state.end_range
        with logging_context(ident=sol_tx_meta.req_id):
            if (not state.has_neon_block()) or (state.block_slot != state.stop_block_slot):
                self._locate_neon_block(state, sol_tx_meta)

            self._complete_neon_block(state)

    def _refresh_block_slots(self) -> None:
        self._last_confirmed_block_slot = self._solana.get_block_slot(self._confirmed_sol_tx_collector.commitment)
        self._last_finalized_block_slot = self._solana.get_block_slot(self._finalized_sol_tx_collector.commitment)

    def _has_new_blocks(self) -> bool:
        if self._confirmed_block_slot is None:
            return True

        return self._confirmed_block_slot != self._last_confirmed_block_slot

    def process_functions(self):
        self._refresh_block_slots()
        if not self._has_new_blocks():
            return

        start_block_slot = self._finalized_sol_tx_collector.last_block_slot + 1
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if finalized_neon_block is not None:
            start_block_slot = finalized_neon_block.block_slot + 1

        try:
            state = SolNeonTxDecoderState(self._finalized_sol_tx_collector, start_block_slot, finalized_neon_block)
            self._run_sol_tx_collector(state, 0)
        except SolHistoryNotFound as err:
            LOG.debug(f'skip parsing of finalized history: {str(err)}')
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_block_slot(state.commitment)
        if (finalized_block_slot - state.stop_block_slot) < 3:
            state.shift_to_collector(self._confirmed_sol_tx_collector)
            try:
                self._run_sol_tx_collector(state, self._config.slot_processing_delay)
            except SolHistoryNotFound as err:
                LOG.debug(f'skip parsing of confirmed history: {str(err)}')
            else:
                sol_tx_meta = state.end_range
                with logging_context(ident=sol_tx_meta.req_id):
                    # Activate branch of history
                    self._db.activate_block_list(state.iter_neon_block())
                    # Cancel stuck transactions
                    self._cancel_old_neon_txs(state, sol_tx_meta)
                    # Save confirmed block only after successfully parsing
                    self._confirmed_block_slot = state.stop_block_slot

        self._print_stat(state)
        self._commit_status_stat()
        self._refresh_op_account_list()

    def _print_stat(self, state: SolNeonTxDecoderState) -> None:
        cache_stat = self._neon_block_dict.stat

        with logging_context(ident='stat'):
            self._counted_logger.print(
                self._config,
                list_value_dict={
                    'receipts processing ms': state.process_time_ms,
                    'processed neon blocks': state.neon_block_cnt,
                    'processed solana transactions': state.sol_tx_meta_cnt,
                    'processed solana instructions': state.sol_neon_ix_cnt
                },
                latest_value_dict={
                    'neon blocks': cache_stat.neon_block_cnt,
                    'neon holders': cache_stat.neon_holder_cnt,
                    'neon transactions': cache_stat.neon_tx_cnt,
                    'solana instructions': cache_stat.sol_neon_ix_cnt,
                    'indexed block slot': state.stop_block_slot,
                    'min used block slot': cache_stat.min_block_slot
                }
            )
