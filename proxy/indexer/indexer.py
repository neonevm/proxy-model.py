from __future__ import annotations

import logging
import time

from typing import List, Optional, Dict, Type

from .indexed_objects import NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonDecoderCtx, SolNeonDecoderStat
from .indexer_db import IndexerDB
from .neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from .neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list
from .tracer_api_client import TracerAPIClient
from .solana_block_net_cache import SolBlockNetCache
from .indexer_validate_stuck_objs import StuckObjectValidator
from .indexer_alt_ix_collector import AltIxCollector

from ..common_neon.config import Config
from ..common_neon.metrics_logger import MetricsLogger
from ..common_neon.solana_not_empty_block import SolFirstBlockFinder, SolNotEmptyBlockFinder
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.utils.solana_block import SolBlockInfo
from ..common_neon.errors import SolHistoryNotFound, SolHistoryCriticalNotFound

from ..statistic.data import NeonBlockStatData, NeonDoneBlockStatData
from ..statistic.indexer_client import IndexerStatClient


LOG = logging.getLogger(__name__)


class Indexer:
    def __init__(self, config: Config, db: IndexerDB):
        self._config = config
        self._db = db
        self._solana = SolInteractor(config)

        self._tracer_api = TracerAPIClient(config)

        self._counted_logger = MetricsLogger(config)
        self._stat_client = IndexerStatClient(config)
        self._stat_client.start()

        self._last_processed_slot = 0
        self._last_confirmed_slot = 0
        self._last_finalized_slot = 0
        self._last_tracer_slot: Optional[int] = None
        self._neon_block_dict = NeonIndexedBlockDict()

        self._stuck_obj_validator = StuckObjectValidator(config, self._solana)
        self._alt_ix_collector = AltIxCollector(config, self._solana)
        self._sol_block_net_cache = SolBlockNetCache(config, self._solana)

        self._term_slot = self._db.stop_slot + self._alt_ix_collector.check_depth

        self._decoder_stat = SolNeonDecoderStat()

        sol_neon_ix_decoder_list: List[Type[DummyIxDecoder]] = list()
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_list())
        sol_neon_ix_decoder_list.extend(get_neon_ix_decoder_deprecated_list())

        self._sol_neon_ix_decoder_dict: Dict[int, Type[DummyIxDecoder]] = dict()
        for decoder in sol_neon_ix_decoder_list:
            ix_code = decoder.ix_code()
            assert ix_code not in self._sol_neon_ix_decoder_dict
            self._sol_neon_ix_decoder_dict[ix_code] = decoder

        self._check_start_slot(self._db.min_used_slot)

    def _save_checkpoint(self, dctx: SolNeonDecoderCtx) -> None:
        if dctx.is_neon_block_queue_empty():
            return

        neon_block_queue = dctx.neon_block_queue
        neon_block = neon_block_queue[-1]
        self._alt_ix_collector.collect_in_block(neon_block)

        # validate stuck objects only on the last not-finalized block
        if not neon_block.is_finalized:
            self._stuck_obj_validator.validate_block(neon_block)
        else:
            self._neon_block_dict.finalize_neon_block(neon_block)
            self._sol_block_net_cache.finalize_block(neon_block.sol_block)

        self._db.submit_block_list(self._neon_block_dict.min_block_slot, neon_block_queue)
        dctx.clear_neon_block_queue()

    def _complete_neon_block(self, dctx: SolNeonDecoderCtx) -> None:
        if not dctx.has_neon_block():
            return

        neon_block = dctx.neon_block
        self._last_processed_slot = neon_block.block_slot

        is_finalized = dctx.is_finalized()
        if is_finalized:
            neon_block.mark_finalized()

        if not neon_block.is_completed:
            neon_block.complete_block()
            self._neon_block_dict.add_neon_block(neon_block)
            self._print_progress_stat()
            self._commit_progress_stat()
        elif is_finalized:
            self._commit_block_stat(neon_block)

        dctx.complete_neon_block()

        # in not-finalize mode: collect all blocks
        # in finalized mode: collect blocks by batches
        if is_finalized and dctx.is_neon_block_queue_full():
            self._save_checkpoint(dctx)

    def _commit_block_stat(self, neon_block: NeonIndexedBlockInfo):
        """Send statistics about blocks which changed state from confirmed to finalized"""
        if not self._config.gather_statistics:
            return

        for tx_stat in neon_block.iter_stat_neon_tx(self._config):
            self._stat_client.commit_neon_tx_result(tx_stat)

    def _commit_progress_stat(self) -> None:
        """Send statistics for the current block's range"""
        if not self._config.gather_statistics:
            return

        block_stat = NeonBlockStatData(
            reindex_ident=self._db.reindex_ident,
            start_block=self._db.start_slot,
            parsed_block=self._last_processed_slot,
            stop_block=self._db.stop_slot,
            term_block=self._term_slot,
            finalized_block=self._last_finalized_slot,
            confirmed_block=self._last_confirmed_slot,
            tracer_block=self._last_tracer_slot
        )
        self._stat_client.commit_block_stat(block_stat)

    def _print_progress_stat(self) -> None:
        if not self._counted_logger.is_print_time():
            return

        value_dict = {
            'start block slot': self._db.start_slot,
            'current block slot': self._last_processed_slot,
            'min used block slot': self._neon_block_dict.min_block_slot,

            'processing ms': self._decoder_stat.processing_time_ms,
            'processed solana blocks': self._decoder_stat.sol_block_cnt,
            'corrupted neon blocks': self._decoder_stat.neon_corrupted_block_cnt,
            'processed solana transactions': self._decoder_stat.sol_tx_meta_cnt,
            'processed neon instructions': self._decoder_stat.sol_neon_ix_cnt,
        }
        self._decoder_stat.reset()

        if not self._db.is_reindexing_mode():
            value_dict.update({
                'confirmed block slot': self._last_confirmed_slot,
                'finalized block slot': self._last_finalized_slot,
            })
            if self._last_tracer_slot is not None:
                value_dict['tracer block slot'] = self._last_tracer_slot
        else:
            value_dict['stop block slot'] = self._db.stop_slot
            value_dict['terminate block slot'] = self._term_slot

        with logging_context(ident='stat'):
            self._counted_logger.print(
                list_value_dict=dict(),
                latest_value_dict=value_dict
            )

    def _new_neon_block(self, dctx: SolNeonDecoderCtx, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        if not dctx.is_finalized():
            return NeonIndexedBlockInfo(sol_block)

        stuck_slot = sol_block.block_slot
        holder_slot, neon_holder_list = self._db.get_stuck_neon_holder_list()
        tx_slot, neon_tx_list = self._db.get_stuck_neon_tx_list()
        _, alt_info_list = self._db.get_sol_alt_info_list()

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
            sol_block, stuck_slot + 1,
            neon_holder_list, neon_tx_list, alt_info_list
        )

    def _locate_neon_block(self, dctx: SolNeonDecoderCtx, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        # The same block
        if dctx.has_neon_block() and (dctx.neon_block.block_slot == sol_block.block_slot):
            return dctx.neon_block

        neon_block = self._neon_block_dict.find_neon_block(sol_block.block_slot)
        if neon_block:
            pass
        elif dctx.has_neon_block():
            neon_block = NeonIndexedBlockInfo.from_block(dctx.neon_block, sol_block)
        else:
            neon_block = self._new_neon_block(dctx, sol_block)

        # The next step, the indexer chooses the next block and saves of the current block in DB, cache ...
        self._complete_neon_block(dctx)
        dctx.set_neon_block(neon_block)
        return neon_block

    def _collect_neon_txs(self, dctx: SolNeonDecoderCtx, stop_slot: int, sol_commit: SolCommit.Type) -> None:
        start_slot = self._db.min_used_slot
        root_neon_block = self._neon_block_dict.finalized_neon_block
        if root_neon_block:
            start_slot = root_neon_block.block_slot

        if self._last_tracer_slot is not None:
            stop_slot = min(stop_slot, self._last_tracer_slot)
        if stop_slot < start_slot:
            return
        dctx.set_slot_range(start_slot, stop_slot, sol_commit)

        for sol_block in self._sol_block_net_cache.iter_block(dctx):
            neon_block = self._locate_neon_block(dctx, sol_block)
            if neon_block.is_completed:
                continue

            for sol_tx_meta in dctx.iter_sol_neon_tx_meta(sol_block):
                sol_tx_cost = sol_tx_meta.sol_tx_cost
                neon_block.add_sol_tx_cost(sol_tx_cost)

                for sol_neon_ix in dctx.iter_sol_neon_ix():
                    with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                        SolNeonIxDecoder = self._sol_neon_ix_decoder_dict.get(sol_neon_ix.ix_code, DummyIxDecoder)
                        sol_neon_ix_decoder = SolNeonIxDecoder(dctx)
                        if sol_neon_ix_decoder.is_stuck():
                            continue

                        neon_block.add_sol_neon_ix(sol_neon_ix)
                        if not sol_neon_ix.is_success:
                            sol_neon_ix_decoder.decode_failed_neon_tx_event_list()
                            # LOG.debug('failed tx')
                            continue
                        sol_neon_ix_decoder.execute()

        with logging_context(sol_neon_ix=f'end-{dctx.sol_commit[:3]}-{dctx.stop_slot}'):
            self._complete_neon_block(dctx)
            self._save_checkpoint(dctx)

    def run(self):
        try:
            self._run()
        except BaseException as exc:
            LOG.warning('Exception on run Indexer', exc_info=exc)

    def _run(self):
        check_sec = float(self._config.indexer_check_msec) / 1000
        while not self._is_done_parsing():
            time.sleep(check_sec)
            if not self._has_new_blocks():
                continue

            self._decoder_stat.start_timer()
            try:
                self._process_solana_blocks()
            except BaseException as exc:
                LOG.warning('Exception on transactions decoding', exc_info=exc)
            finally:
                self._decoder_stat.commit_timer()

        self._commit_done_block_stat()

    def _commit_done_block_stat(self):
        """Send done event to the prometheus"""
        done_stat = NeonDoneBlockStatData(
            reindex_ident=self._db.reindex_ident,
            parsed_block=self._last_processed_slot
        )
        self._stat_client.commit_done_block_stat(done_stat)

    def _has_new_blocks(self) -> bool:
        if self._db.is_reindexing_mode():
            # reindexing can't precede of indexing
            finalized_slot = self._db.finalized_slot
            # reindexing should stop on the terminated slot
            finalized_slot = min(self._term_slot, finalized_slot)
            result = self._last_processed_slot < finalized_slot
            self._last_finalized_slot = finalized_slot
        else:
            self._last_confirmed_slot = self._solana.get_confirmed_slot()
            result = self._last_processed_slot != self._last_confirmed_slot
            if result:
                self._last_finalized_slot = self._solana.get_finalized_slot()
                self._last_tracer_slot = self._tracer_api.max_slot()
        return result

    def _is_done_parsing(self) -> bool:
        """Stop parsing can happen only in reindexing mode"""
        if not self._db.is_reindexing_mode():
            return False

        if self._last_processed_slot < self._db.stop_slot:
            return False
        elif self._last_processed_slot >= self._term_slot:
            return True

        neon_block = self._neon_block_dict.finalized_neon_block
        if neon_block is None:
            return True

        neon_block.check_stuck_objs(self._config)
        return not neon_block.has_stuck_objs()

    def _process_solana_blocks(self) -> None:
        dctx = SolNeonDecoderCtx(self._config, self._decoder_stat)
        try:
            self._collect_neon_txs(dctx, self._last_finalized_slot, SolCommit.Finalized)
        except SolHistoryCriticalNotFound as err:
            LOG.warning(f'block branch: {str(dctx)}, fail to parse finalized history: {str(err)}')
            self._check_start_slot(err.slot)
            return
        except SolHistoryNotFound as err:
            LOG.debug(f'block branch: {str(dctx)}, skip parsing of finalized history: {str(err)}')
            return

        # Don't parse not-finalized blocks on reindexing of old blocks
        if self._db.is_reindexing_mode():
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_finalized_slot()
        if (finalized_block_slot - self._last_finalized_slot) >= 5:
            LOG.debug(f'skip parsing of not-finalized history: {finalized_block_slot} > {self._last_finalized_slot}')
            return

        try:
            self._collect_neon_txs(dctx, self._last_confirmed_slot, SolCommit.Confirmed)
        except SolHistoryNotFound as err:
            # There are a lot of reason for skipping not-finalized history on live systems
            # so uncomment the debug message only if you need investigate the root cause
            LOG.debug(f'skip parsing of not-finalized history: {str(err)}')
            pass

    def _check_start_slot(self, base_slot: int) -> None:
        block_finder = SolFirstBlockFinder(self._solana)
        first_slot = block_finder.find_slot()

        if first_slot < base_slot:
            first_slot = SolNotEmptyBlockFinder(self._solana, base_slot, block_finder.finalized_slot).find_slot()

        if self._db.min_used_slot < first_slot:
            LOG.debug(f'Move the min used slot from {self._db.min_used_slot} to {first_slot}')
            self._db.set_start_slot(first_slot)

        # Skip history if it was cleaned by the Solana node
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if (finalized_neon_block is not None) and (first_slot > finalized_neon_block.block_slot):
            self._neon_block_dict.clear()
