from __future__ import annotations

import time

from typing import List, Optional, Dict, Deque, Type
from collections import deque
from logged_groups import logged_group, logging_context

from ..common_neon.solana_transaction import SolPubKey
from ..common_neon.data import NeonTxStatData
from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxCostInfo, SolNeonIxReceiptInfo
from ..common_neon.constants import ACTIVE_HOLDER_TAG
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.config import Config
from ..common_neon.environment_data import CANCEL_TIMEOUT

from ..indexer.i_indexer_stat_exporter import IIndexerStatExporter
from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.solana_tx_meta_collector import SolTxMetaDict, SolHistoryNotFound
from ..indexer.solana_tx_meta_collector import FinalizedSolTxMetaCollector, ConfirmedSolTxMetaCollector
from ..indexer.utils import MetricsToLogger
from ..indexer.indexed_objects import NeonIndexedTxInfo
from ..indexer.indexed_objects import NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonTxDecoderState

from ..indexer.neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from ..indexer.neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list


@logged_group("neon.Indexer")
class Indexer(IndexerBase):
    def __init__(self, config: Config, indexer_stat_exporter: IIndexerStatExporter):
        solana = SolInteractor(config, config.solana_url)
        self._db = IndexerDB()
        last_known_slot = self._db.get_min_receipt_block_slot()
        super().__init__(config, solana, last_known_slot)
        self._cancel_tx_executor = CancelTxExecutor(config, solana, get_solana_accounts()[0])
        self._counted_logger = MetricsToLogger()
        self._stat_exporter = indexer_stat_exporter
        self._last_stat_time = 0.0
        sol_tx_meta_dict = SolTxMetaDict()
        collector = FinalizedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict, self._last_slot)
        self._finalized_sol_tx_collector = collector
        collector = ConfirmedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict)
        self._confirmed_sol_tx_collector = collector
        self._confirmed_block_slot: Optional[int] = None
        self._neon_block_dict = NeonIndexedBlockDict()

        sol_neon_ix_decoder_list: List[Type[DummyIxDecoder]] = []
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_list())
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_deprecated_list())

        self._sol_neon_ix_decoder_dict: Dict[int, Type[DummyIxDecoder]] = {}
        for decoder in sol_neon_ix_decoder_list:
            ix_code = decoder.ix_code()
            assert ix_code not in self._sol_neon_ix_decoder_dict
            self._sol_neon_ix_decoder_dict[ix_code] = decoder

    def _cancel_old_neon_txs(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> None:
        for tx in state.neon_block.iter_neon_tx():
            if (tx.storage_account != '') and (state.stop_block_slot - tx.block_slot > CANCEL_TIMEOUT):
                self._cancel_neon_tx(tx, sol_tx_meta)

        try:
            self._cancel_tx_executor.execute_tx_list()
        except BaseException as exc:
            self.warning('Failed to cancel neon txs.', exc_info=exc)
        finally:
            self._cancel_tx_executor.clear()

    def _cancel_neon_tx(self, tx: NeonIndexedTxInfo, sol_tx_meta: SolTxMetaInfo) -> bool:
        # We've already indexed the transaction
        if tx.neon_tx_res.is_valid():
            return True

        # We've already sent Cancel and are waiting for receipt
        if tx.status != NeonIndexedTxInfo.Status.IN_PROGRESS:
            return True

        if not tx.blocked_account_cnt:
            self.warning(f"neon tx {tx.neon_tx} hasn't blocked accounts.")
            return False

        holder_account = tx.storage_account

        holder_info = self._solana.get_holder_account_info(SolPubKey(holder_account))
        if not holder_info:
            self.warning(f'holder {holder_account} for neon tx {tx.neon_tx.sig} is empty')
            return False

        if holder_info.tag != ACTIVE_HOLDER_TAG:
            self.warning(f'holder {holder_account} for neon tx {tx.neon_tx.sig} has bad tag: {holder_info.tag}')
            return False

        if holder_info.neon_tx_sig != tx.neon_tx.sig:
            self.warning(
                f'storage {holder_account} has another neon tx hash: '
                f'{holder_info.neon_tx_sig} != {tx.neon_tx.sig}'
            )
            return False

        if not self._cancel_tx_executor.add_blocked_holder_account(holder_info):
            self.warning(
                f'neon tx {tx.neon_tx} uses the storage account {holder_account}' +
                'which is already in the list on unlock'
            )
            return False

        self.debug(f'Neon tx is blocked: storage {holder_account}, {tx.neon_tx}, {holder_info.account_list}')
        tx.set_status(NeonIndexedTxInfo.Status.CANCELED, SolNeonIxReceiptInfo.from_tx(sol_tx_meta))
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
                self._db.submit_block(neon_block)
                neon_block.complete_block()
            elif is_finalized:
                # the confirmed block becomes finalized
                self._db.finalize_block(neon_block)

            # Add block to cache only after indexing and applying last changes to DB
            self._neon_block_dict.add_neon_block(neon_block)
            if is_finalized:
                self._neon_block_dict.finalize_neon_block(neon_block)
                self._submit_block_status(neon_block)
                self._save_checkpoint()

            self._submit_status()
        except (Exception,):
            # Revert finalized status
            neon_block.set_finalized(backup_is_finalized)
            raise

    def _submit_block_status(self, neon_block: NeonIndexedBlockInfo) -> None:
        for tx in neon_block.iter_done_neon_tx():
            # TODO: check operator of tx
            self._submit_neon_tx_status(tx)

    def _submit_status(self) -> None:
        now = time.time()
        if abs(now - self._last_stat_time) < 1:
            return
        self._last_stat_time = now
        self._stat_exporter.on_db_status(self._db.status())
        self._stat_exporter.on_solana_rpc_status(self._solana.is_healthy())

    def _submit_neon_tx_status(self, tx: NeonIndexedTxInfo) -> None:
        neon_tx_sig = tx.neon_tx.sig
        neon_income = int(tx.neon_tx_res.gas_used, 0) * int(tx.neon_tx.gas_price, 0)  # TODO: get gas usage from ixs
        if tx.holder_account != '':
            tx_type = 'holder'
        elif tx.storage_account != '':
            tx_type = 'iterative'
        else:
            tx_type = 'single'
        is_canceled = tx.neon_tx_res.status == '0x0'
        sol_spent = tx.sol_spent
        neon_tx_stat_data = NeonTxStatData(neon_tx_sig, sol_spent, neon_income, tx_type, is_canceled)
        neon_tx_stat_data.sol_tx_cnt = tx.sol_tx_cnt
        for ix in tx.iter_sol_neon_ix():
            neon_tx_stat_data.neon_step_cnt += ix.neon_step_cnt
            neon_tx_stat_data.bpf_cycle_cnt += ix.used_bpf_cycle_cnt

        self._stat_exporter.on_neon_tx_result(neon_tx_stat_data)

    def _get_sol_block_deque(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> Deque[SolanaBlockInfo]:
        if not state.has_neon_block():
            sol_block = self._solana.get_block_info(sol_tx_meta.block_slot)
            if sol_block.is_empty():
                raise SolHistoryNotFound(f"can't get block: {sol_tx_meta.block_slot}")
            return deque([sol_block])

        start_block_slot = state.block_slot
        block_slot_list = [block_slot for block_slot in range(start_block_slot + 1, sol_tx_meta.block_slot + 1)]
        sol_block_list = self._solana.get_block_info_list(block_slot_list, state.commitment)
        result_sol_block_deque: Deque[SolanaBlockInfo] = deque()
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

    def _run_sol_tx_collector(self, state: SolNeonTxDecoderState) -> None:
        stop_block_slot = self._solana.get_block_slot(state.commitment)
        state.set_stop_block_slot(stop_block_slot)
        if stop_block_slot < state.start_block_slot:
            return

        for sol_tx_meta in state.iter_sol_tx_meta():
            with logging_context(ident=sol_tx_meta.req_id):
                neon_block = self._locate_neon_block(state, sol_tx_meta)
                if neon_block.is_completed:
                    # self.debug(f'ignore parsed tx {sol_tx_meta}')
                    continue

                neon_block.add_sol_tx_cost(SolTxCostInfo(sol_tx_meta))

                if SolTxErrorParser(sol_tx_meta.tx).check_if_error():
                    # self.debug(f'ignore failed tx {sol_tx_meta}')
                    continue

            for sol_neon_ix in state.iter_sol_neon_ix():
                with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                    SolNeonIxDecoder = self._sol_neon_ix_decoder_dict.get(sol_neon_ix.program_ix, DummyIxDecoder)
                    SolNeonIxDecoder(state).execute()

        sol_tx_meta = state.end_range
        with logging_context(ident=sol_tx_meta.req_id):
            if (not state.has_neon_block()) or (state.block_slot != state.stop_block_slot):
                self._locate_neon_block(state, sol_tx_meta)

            self._complete_neon_block(state)

    def _has_new_blocks(self) -> bool:
        if self._confirmed_block_slot is None:
            return True
        confirmed_block_slot = self._solana.get_block_slot(self._confirmed_sol_tx_collector.commitment)
        return self._confirmed_block_slot != confirmed_block_slot

    def process_functions(self):
        if not self._has_new_blocks():
            return

        start_block_slot = self._finalized_sol_tx_collector.last_block_slot + 1
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if finalized_neon_block is not None:
            start_block_slot = finalized_neon_block.block_slot + 1

        try:
            state = SolNeonTxDecoderState(self._finalized_sol_tx_collector, start_block_slot, finalized_neon_block)
            self._run_sol_tx_collector(state)
        except SolHistoryNotFound as err:
            self.debug(f'skip parsing of finalized history: {str(err)}')
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_block_slot(state.commitment)
        if (finalized_block_slot - state.stop_block_slot) < 3:
            state.shift_to_collector(self._confirmed_sol_tx_collector)
            try:
                self._run_sol_tx_collector(state)
            except SolHistoryNotFound as err:
                self.debug(f'skip parsing of confirmed history: {str(err)}')
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
        self._submit_status()

    def _print_stat(self, state: SolNeonTxDecoderState) -> None:
        cache_stat = self._neon_block_dict.stat

        with logging_context(ident='stat'):
            self._counted_logger.print(
                self.debug,
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
