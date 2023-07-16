from __future__ import annotations

import logging
import time

from typing import List, Optional, Dict, Type

from .indexed_objects import NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonDecoderState, SolNeonDecoderStat
from .indexer_base import IndexerBase
from .indexer_db import IndexerDB
from .neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from .neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list
from .tracer_api_client import TracerAPIClient
from .solana_block_net_cache import SolBlockNetCache
from .indexer_validate_stuck_objs import StuckObjectValidator
from .indexer_alt_ix_collector import AltIxCollector

from ..common_neon.config import Config
from ..common_neon.metrics_logger import MetricsLogger
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolCommit
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.utils.solana_block import SolBlockInfo
from ..common_neon.errors import SolHistoryNotFound

from ..statistic.data import NeonBlockStatData
from ..statistic.indexer_client import IndexerStatClient


LOG = logging.getLogger(__name__)


class Indexer(IndexerBase):
    def __init__(self, config: Config):
        solana = SolInteractor(config, config.solana_url)
        self._db = IndexerDB(config)
        last_known_slot = self._db.get_min_receipt_block_slot()
        super().__init__(config, solana, last_known_slot)

        self._tracer_api = TracerAPIClient(config)

        self._counted_logger = MetricsLogger(config)
        self._stat_client = IndexerStatClient(config)
        self._stat_client.start()
        self._last_stat_time = 0.0

        self._confirmed_slot: Optional[int] = None

        self._last_confirmed_slot = 0
        self._last_finalized_slot = 0
        self._last_tracer_slot: Optional[int] = None
        self._neon_block_dict = NeonIndexedBlockDict()

        self._stuck_obj_validator = StuckObjectValidator(config, self._solana)
        self._alt_ix_collector = AltIxCollector(config, self._solana)
        self._sol_block_net_cache = SolBlockNetCache(config, self._solana)

        self._decoder_stat = SolNeonDecoderStat()

        sol_neon_ix_decoder_list: List[Type[DummyIxDecoder]] = list()
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_list())
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_deprecated_list())

        self._sol_neon_ix_decoder_dict: Dict[int, Type[DummyIxDecoder]] = dict()
        for decoder in sol_neon_ix_decoder_list:
            ix_code = decoder.ix_code()
            assert ix_code not in self._sol_neon_ix_decoder_dict
            self._sol_neon_ix_decoder_dict[ix_code] = decoder

    def _save_checkpoint(self, state: SolNeonDecoderState) -> None:
        if state.is_neon_block_queue_empty():
            return

        neon_block_queue = state.neon_block_queue
        neon_block = neon_block_queue[-1]
        self._alt_ix_collector.collect_in_block(neon_block)

        # validate stuck objects only on the last confirmed block
        if not neon_block.is_finalized:
            self._stuck_obj_validator.validate_block(neon_block)
        else:
            self._neon_block_dict.finalize_neon_block(neon_block)
            self._sol_block_net_cache.finalize_block(neon_block.sol_block)

        cache_stat = self._neon_block_dict.stat
        self._db.submit_block_list(cache_stat.min_block_slot, neon_block_queue)
        state.clear_neon_block_queue()

    def _complete_neon_block(self, state: SolNeonDecoderState) -> None:
        if not state.has_neon_block():
            return

        is_finalized = state.is_finalized()
        neon_block = state.neon_block
        if is_finalized:
            neon_block.mark_finalized()

        if not neon_block.is_completed:
            neon_block.complete_block()
            self._neon_block_dict.add_neon_block(neon_block)
            self._print_stat(state)
        state.complete_neon_block()

        # in confirmed mode: collect all blocks
        # in finalized mode: collect block by batches
        if is_finalized and state.is_neon_block_queue_full():
            self._save_checkpoint(state)

        self._commit_stat(neon_block)

    def _commit_stat(self, neon_block: NeonIndexedBlockInfo):
        if not self._config.gather_statistics:
            return

        if neon_block.is_finalized:
            for tx_stat in neon_block.iter_stat_neon_tx(self._config):
                self._stat_client.commit_neon_tx_result(tx_stat)

        block_stat = NeonBlockStatData(
            start_block=self._start_slot,
            parsed_block=neon_block.block_slot,
            finalized_block=self._last_finalized_slot,
            confirmed_block=self._last_confirmed_slot,
            tracer_block=self._last_tracer_slot
        )
        self._stat_client.commit_block_stat(block_stat)

        now = time.time()
        if abs(now - self._last_stat_time) < 1:
            return

        self._last_stat_time = now
        self._stat_client.commit_db_health(self._db.is_healthy())
        self._stat_client.commit_solana_rpc_health(self._solana.is_healthy())

    def _new_neon_block(self, state: SolNeonDecoderState, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        if not state.is_finalized():
            return NeonIndexedBlockInfo(sol_block)

        stuck_slot = sol_block.block_slot
        holder_slot, neon_holder_list = self._db.get_stuck_neon_holder_list(sol_block.block_slot)
        tx_slot, neon_tx_list = self._db.get_stuck_neon_tx_list(True, sol_block.block_slot)
        _, alt_info_list = self._db.get_sol_alt_info_list(sol_block.block_slot)

        if (holder_slot is not None) and (tx_slot is not None) and (holder_slot != tx_slot):
            LOG.warning(f'Holder stuck block {holder_slot} != tx stuck block {tx_slot}')
            neon_holder_list.clear()
            neon_tx_list.clear()
            alt_info_list.clear()

        elif tx_slot is not None:
            stuck_slot = tx_slot

        elif holder_slot is not None:
            stuck_slot = holder_slot

        return NeonIndexedBlockInfo.from_stuck_data(
            sol_block, stuck_slot,
            neon_holder_list, neon_tx_list, alt_info_list
        )

    def _locate_neon_block(self, state: SolNeonDecoderState, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        # The same block
        if state.has_neon_block() and (state.neon_block.block_slot == sol_block.block_slot):
            return state.neon_block

        neon_block = self._neon_block_dict.find_neon_block(sol_block.block_slot)
        if neon_block:
            pass
        elif state.has_neon_block():
            neon_block = NeonIndexedBlockInfo.from_block(state.neon_block, sol_block)
        else:
            neon_block = self._new_neon_block(state, sol_block)

        # The next step, the indexer chooses the next block and saves of the current block in DB, cache ...
        self._complete_neon_block(state)
        state.set_neon_block(neon_block)
        return neon_block

    def _collect_neon_txs(self, state: SolNeonDecoderState, sol_commit: SolCommit.Type) -> None:
        start_slot = self._start_slot
        root_neon_block = self._neon_block_dict.finalized_neon_block
        if root_neon_block:
            start_slot = root_neon_block.block_slot

        stop_slot = self._solana.get_block_slot(sol_commit)
        if self._last_tracer_slot is not None:
            stop_slot = min(stop_slot, self._last_tracer_slot)
        if stop_slot < start_slot:
            return
        state.set_slot_range(start_slot, stop_slot, sol_commit)

        for sol_block in self._sol_block_net_cache.iter_block(state):
            neon_block = self._locate_neon_block(state, sol_block)
            if neon_block.is_completed:
                continue

            for sol_tx_meta in state.iter_sol_tx_meta(sol_block):
                sol_tx_cost = state.sol_tx_cost
                neon_block.add_sol_tx_cost(sol_tx_cost)
                is_error = SolTxErrorParser(self._config.evm_program_id, sol_tx_meta.tx).check_if_error()

                for sol_neon_ix in state.iter_sol_neon_ix():
                    with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                        SolNeonIxDecoder = self._sol_neon_ix_decoder_dict.get(sol_neon_ix.ix_code, DummyIxDecoder)
                        sol_neon_ix_decoder = SolNeonIxDecoder(state)
                        if sol_neon_ix_decoder.is_stuck():
                            continue

                        neon_block.add_sol_neon_ix(sol_neon_ix)
                        if is_error:
                            sol_neon_ix_decoder.decode_failed_neon_tx_event_list()
                            # LOG.debug('failed tx')
                            continue
                        sol_neon_ix_decoder.execute()

        with logging_context(sol_neon_ix=f'end-{state.sol_commit[:3]}-{state.stop_slot}'):
            self._complete_neon_block(state)
            self._save_checkpoint(state)

    def _has_new_blocks(self) -> bool:
        self._last_confirmed_slot = self._solana.get_block_slot(SolCommit.Confirmed)
        return (self._confirmed_slot or 1) != self._last_confirmed_slot

    def process_functions(self):
        if not self._has_new_blocks():
            return

        self._last_finalized_slot = self._solana.get_block_slot(SolCommit.Finalized)
        self._last_tracer_slot = self._tracer_api.max_slot()
        try:
            self._decoder_stat.start_timer()
            self._process_solana_blocks()
        finally:
            self._decoder_stat.commit_timer()

    def _process_solana_blocks(self) -> None:
        state = SolNeonDecoderState(self._config, self._decoder_stat)
        try:
            self._collect_neon_txs(state, SolCommit.Finalized)

        except SolHistoryNotFound as err:
            first_slot = self._solana.get_first_available_block()
            LOG.warning(
                f'first slot: {first_slot}, '
                f'start slot: {state.start_slot}, '
                f'stop slot: {state.stop_slot}, '
                f'skip parsing of finalized history: {str(err)}',
                exc_info=err
            )

            first_slot += 512
            if self._start_slot < first_slot:
                self._start_slot = first_slot

            # Skip history if it was cleaned by the Solana Node
            finalized_neon_block = self._neon_block_dict.finalized_neon_block
            if (finalized_neon_block is not None) and (first_slot > finalized_neon_block.block_slot):
                self._neon_block_dict.clear()
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_block_slot(SolCommit.Finalized)
        if (finalized_block_slot - state.stop_slot) >= 3:
            return

        try:
            self._collect_neon_txs(state, SolCommit.Confirmed)

            # Save confirmed block only after successfully parsing,
            #  otherwise try to parse blocks again
            self._confirmed_slot = state.stop_slot

        except SolHistoryNotFound as err:
            LOG.debug(f'skip parsing of confirmed history: {str(err)}')

    def _print_stat(self, state: SolNeonDecoderState) -> None:
        cache_stat = self._neon_block_dict.stat
        latest_value_dict = {
            'start block slot': self._start_slot,
            'confirmed block slot': self._last_confirmed_slot,
            'finalized block slot': self._last_finalized_slot,
            'tracer block slot': self._last_tracer_slot,
            'current block slot': state.neon_block.block_slot,
            'min used block slot': cache_stat.min_block_slot,
        }

        if self._counted_logger.is_print_time():
            state_stat = state.stat
            latest_value_dict.update({
                'processing ms': state_stat.processing_time_ms,
                'processed solana blocks': state_stat.sol_block_cnt,
                'corrupted neon blocks': state_stat.neon_corrupted_block_cnt,
                'processed solana transactions': state_stat.sol_tx_meta_cnt,
                'processed neon instructions': state_stat.sol_neon_ix_cnt,
            })
            state_stat.reset()

        with logging_context(ident='stat'):
            self._counted_logger.print(
                list_value_dict={
                    'neon blocks': cache_stat.neon_block_cnt,
                    'neon holders': cache_stat.neon_holder_cnt,
                    'neon transactions': cache_stat.neon_tx_cnt,
                    'solana instructions': cache_stat.sol_neon_ix_cnt,
                    'solana alt infos': cache_stat.sol_alt_info_cnt,
                },
                latest_value_dict=latest_value_dict
            )
