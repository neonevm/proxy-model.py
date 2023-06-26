from __future__ import annotations

import logging
import time
import base58

from typing import List, Optional, Dict, Type, Any

from .indexed_objects import (
    NeonIndexedBlockInfo, NeonIndexedBlockDict, SolNeonTxDecoderState,
    NeonIndexedHolderInfo, NeonIndexedTxInfo, NeonIndexedAltInfo
)
from .indexer_base import IndexerBase
from .indexer_db import IndexerDB
from .neon_ix_decoder import DummyIxDecoder, get_neon_ix_decoder_list
from .neon_ix_decoder_deprecate import get_neon_ix_decoder_deprecated_list
from .solana_tx_meta_collector import SolHistoryNotFound
from .tracer_api_client import TracerAPIClient

from ..common_neon.config import Config
from ..common_neon.constants import FINALIZED_HOLDER_TAG, ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.layouts import ALTAccountInfo
from ..common_neon.metrics_logger import MetricsLogger
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolAltIxInfo, SolTxMetaInfo
from ..common_neon.solana_tx import SolPubKey, SolCommit
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.utils.solana_block import SolBlockInfo

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

        self._counted_logger = MetricsLogger()
        self._stat_client = IndexerStatClient(config)
        self._stat_client.start()
        self._last_stat_time = 0.0

        self._stuck_objs_last_validate_slot = 0
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

    def _validate_stuck_objs(self, neon_block: NeonIndexedBlockInfo) -> None:
        block_slot = neon_block.block_slot
        last_block_slot = block_slot - self._config.stuck_object_validate_blockout
        if last_block_slot < self._stuck_objs_last_validate_slot:
            return
        elif self._stuck_objs_last_validate_slot == 0:
            self._stuck_objs_last_validate_slot = block_slot
            return
        elif neon_block.stuck_block_slot > neon_block.block_slot:
            self._stuck_objs_last_validate_slot = block_slot
            return

        failed_holder_list: List[NeonIndexedHolderInfo] = list()
        for holder in neon_block.iter_stuck_neon_holder():
            if holder.last_block_slot > last_block_slot:
                pass
            elif not self._is_valid_holder(holder.account, holder.neon_tx_sig):
                failed_holder_list.append(holder)

        failed_tx_list: List[NeonIndexedTxInfo] = list()
        for tx in neon_block.iter_stuck_neon_tx():
            if tx.last_block_slot > last_block_slot:
                continue
            elif not self._is_valid_holder(tx.holder_account, tx.neon_tx.sig):
                failed_tx_list.append(tx)

        neon_block.fail_neon_holder_list(failed_holder_list)
        neon_block.fail_neon_tx_list(failed_tx_list)
        self._stuck_objs_last_validate_slot = block_slot

    def _is_valid_holder(self, holder_acct: str, neon_tx_sig: str) -> bool:
        holder_info = self._solana.get_holder_account_info(SolPubKey.from_string(holder_acct))
        if holder_info is None:
            return False

        if holder_info.neon_tx_sig == neon_tx_sig:
            return holder_info.tag != FINALIZED_HOLDER_TAG
        return False

    def _collect_alt_ixs(self, neon_block: NeonIndexedBlockInfo) -> None:
        freeing_depth = self._config.alt_freeing_depth * 2
        check_slot = neon_block.block_slot - freeing_depth
        check_done_slot = neon_block.block_slot - 64
        if check_slot < 0:
            return

        for alt_info in list(neon_block.iter_alt_info()):
            if alt_info.block_slot > check_slot:
                continue
            elif alt_info.done_block_slot > check_done_slot:
                continue
            elif alt_info.done_block_slot > 0:
                pass
            elif not self._is_done_alt(neon_block, alt_info):
                continue
            else:
                # wait for transaction indexing
                alt_info.set_done_block_slot(neon_block.block_slot)
                continue

            alt_key = SolPubKey.from_string(alt_info.alt_key)
            sig_block_list = self._solana.get_sig_list_for_address(alt_key, None, 1000, SolCommit.Finalized)
            sig_list = [sig_block.get('signature', None) for sig_block in sig_block_list]
            tx_receipt_list = self._solana.get_tx_receipt_list(sig_list, SolCommit.Finalized)

            alt_ix_list = self._decode_alt_ixs(alt_info, tx_receipt_list)
            neon_block.done_alt_info(alt_info, alt_ix_list)

    def _is_done_alt(self, neon_block: NeonIndexedBlockInfo, alt_info: NeonIndexedAltInfo) -> bool:
        alt_address = SolPubKey.from_string(alt_info.alt_key)
        acct_info = self._solana.get_account_info(alt_address, commitment=SolCommit.Finalized)
        if acct_info is None:
            return True

        alt_acct_info = ALTAccountInfo.from_account_info(acct_info)
        if alt_acct_info is None:
            return True
        elif alt_acct_info.authority is None:
            LOG.warning(f'ALT {alt_info.alt_key} is frozen')
            return True

        if alt_acct_info.authority in self._config.operator_account_set:
            return False

        # don't wait for ALTs from other operators
        check_block_slot = neon_block.block_slot - self._config.alt_freeing_depth * 10
        if alt_info.block_slot < check_block_slot:
            return True
        return False

    @staticmethod
    def _decode_alt_ixs(alt_info: NeonIndexedAltInfo, tx_receipt_list: List[Dict[str, Any]]) -> List[SolAltIxInfo]:
        alt_program_key = str(ADDRESS_LOOKUP_TABLE_ID)
        alt_ix_list: List[SolAltIxInfo] = list()
        for tx_receipt in tx_receipt_list:
            if tx_receipt is None:
                continue

            has_alt_ix = False
            tx_meta = SolTxMetaInfo.from_tx_receipt(None, tx_receipt)
            for idx, ix in enumerate(tx_meta.ix_list):
                if not tx_meta.is_program(ix, alt_program_key):
                    continue

                try:
                    ix_data = base58.b58decode(ix.get('data', None))
                    ix_code = int.from_bytes(ix_data[:4], 'little')
                    has_alt_ix = True
                except BaseException as exc:
                    LOG.warning(
                        f'failed to decode ALT instruction data '
                        f'in Solana tx {tx_meta.sol_sig}:{tx_meta.block_slot}',
                        exc_info=exc
                    )
                    continue

                alt_ix_info = SolAltIxInfo.from_tx_meta(
                    tx_meta, idx, ix_code, alt_info.alt_key,
                    alt_info.neon_tx_sig
                )
                alt_ix_list.append(alt_ix_info)

            if not has_alt_ix:
                LOG.warning(f'ALT instruction does not exist in Solana tx {tx_meta.sol_sig}:{tx_meta.block_slot}')
        return alt_ix_list

    def _save_checkpoint(self) -> None:
        cache_stat = self._neon_block_dict.stat
        self._db.set_min_receipt_block_slot(cache_stat.min_block_slot)

    def _complete_neon_block(self, state: SolNeonTxDecoderState) -> None:
        if not state.has_neon_block():
            return

        neon_block = state.neon_block
        if neon_block.is_finalized:
            return

        is_last_confirmed = state.is_last_block(neon_block) and not state.is_finalized()

        is_finalized = state.is_neon_block_finalized()
        neon_block.set_finalized(is_finalized)
        if not neon_block.is_completed:
            self._collect_alt_ixs(neon_block)
            neon_block.done_block(self._config)

            if is_last_confirmed:
                self._validate_stuck_objs(neon_block)
                self._db.submit_block(neon_block, state.iter_neon_block())
            else:
                self._db.submit_block(neon_block, None)

            neon_block.complete_block()
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

    def _commit_tx_stat(self, neon_block: NeonIndexedBlockInfo) -> None:
        if not self._config.gather_statistics:
            return

        for tx_stat in neon_block.iter_stat_neon_tx():
            self._stat_client.commit_neon_tx_result(tx_stat)

    def _commit_block_stat(self, neon_block: NeonIndexedBlockInfo) -> None:
        if not self._config.gather_statistics:
            return

        stat = NeonBlockStatData(
            start_block=self._start_slot,
            parsed_block=neon_block.block_slot,
            finalized_block=self._last_finalized_block_slot,
            confirmed_block=self._last_confirmed_block_slot
        )
        self._stat_client.commit_block_stat(stat)

    def _commit_status_stat(self) -> None:
        if not self._config.gather_statistics:
            return

        now = time.time()
        if abs(now - self._last_stat_time) < 1:
            return

        self._last_stat_time = now
        self._stat_client.commit_db_health(self._db.is_healthy())
        self._stat_client.commit_solana_rpc_health(self._solana.is_healthy())

    def _new_neon_block(self, state: SolNeonTxDecoderState, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        if not state.is_finalized():
            return NeonIndexedBlockInfo(sol_block)

        stuck_block_slot = sol_block.block_slot
        holder_block_slot, neon_holder_list = self._db.get_stuck_neon_holder_list(sol_block.block_slot)
        tx_block_slot, neon_tx_list = self._db.get_stuck_neon_tx_list(True, sol_block.block_slot)
        alt_block_slot, alt_info_list = self._db.get_sol_alt_info_list(sol_block.block_slot)

        if (holder_block_slot is not None) and (tx_block_slot is not None) and (holder_block_slot != tx_block_slot):
            LOG.warning(f'Holder stuck block {holder_block_slot} != tx stuck block {tx_block_slot}')
            neon_holder_list.clear()
            neon_tx_list.clear()
        elif tx_block_slot is not None:
            stuck_block_slot = tx_block_slot
        elif holder_block_slot is not None:
            stuck_block_slot = holder_block_slot

        return NeonIndexedBlockInfo.from_stuck_data(
            sol_block, stuck_block_slot,
            neon_holder_list, neon_tx_list, alt_info_list
        )

    @staticmethod
    def _clone_neon_block(state: SolNeonTxDecoderState, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        if sol_block.parent_block_slot != state.neon_block.block_slot:
            raise SolHistoryNotFound(f'Bad child {sol_block.block_slot} for the block {state.neon_block.block_slot}')

        return NeonIndexedBlockInfo.from_block(state.neon_block, sol_block)

    def _locate_neon_block(self, state: SolNeonTxDecoderState, block_slot: int) -> Optional[NeonIndexedBlockInfo]:
        # The same block
        if state.has_neon_block():
            if state.neon_block.block_slot == block_slot:
                return state.neon_block
            # The next step, the indexer chooses another block, that is why here is saving of block in DB, cache ...
            self._complete_neon_block(state)

        neon_block = self._neon_block_dict.find_neon_block(block_slot)
        if neon_block:
            pass  # The parsed block from cache
        else:
            # A new block with history from the Solana network
            sol_block = self._solana.get_block_info(block_slot, state.sol_commit, True)
            if sol_block.is_empty():
                return None

            if state.has_neon_block():
                neon_block = self._clone_neon_block(state, sol_block)
            else:
                neon_block = self._new_neon_block(state, sol_block)

        state.set_neon_block(neon_block)
        return neon_block

    def _collect_neon_txs(self, state: SolNeonTxDecoderState, tracer_max_slot: Optional[int]) -> None:
        stop_block_slot = self._solana.get_block_slot(state.sol_commit)
        if tracer_max_slot is not None:
            stop_block_slot = max(stop_block_slot, tracer_max_slot)

        state.set_stop_block_slot(stop_block_slot)
        if stop_block_slot < state.start_block_slot:
            return

        for block_slot in range(state.start_block_slot, stop_block_slot + 1):
            neon_block: Optional[NeonIndexedBlockInfo] = self._locate_neon_block(state, block_slot)
            if (neon_block is None) or neon_block.is_completed:
                continue

            for sol_tx_meta in state.iter_sol_tx_meta(neon_block.sol_block):
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
            else:
                self._print_stat(state)

        with logging_context(ident=f'end-{state.start_block_slot}-{state.sol_commit}'):
            self._locate_neon_block(state, state.stop_block_slot)
            self._complete_neon_block(state)

    def _refresh_block_slots(self) -> None:
        self._last_confirmed_block_slot = self._solana.get_block_slot(SolCommit.Confirmed)
        self._last_finalized_block_slot = self._solana.get_block_slot(SolCommit.Finalized)

    def _has_new_blocks(self) -> bool:
        if self._confirmed_block_slot is None:
            return True

        return self._confirmed_block_slot != self._last_confirmed_block_slot

    def process_functions(self):
        self._refresh_block_slots()
        if not self._has_new_blocks():
            return

        tracer_max_slot = self._tracer_api.max_slot()
        start_block_slot = self._start_slot
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if finalized_neon_block is not None:
            start_block_slot = finalized_neon_block.block_slot + 1

        try:
            state = SolNeonTxDecoderState(self._config, SolCommit.Finalized, start_block_slot, finalized_neon_block)
            self._collect_neon_txs(state, tracer_max_slot)
        except SolHistoryNotFound as err:
            first_slot = self._solana.get_first_available_block()
            LOG.warning(f'first slot: {first_slot}, skip parsing of finalized history: {str(err)}')

            # Skip history if it was cleaned by the Solana Node
            finalized_neon_block = self._neon_block_dict.finalized_neon_block
            if finalized_neon_block is None:
                return

            if first_slot > finalized_neon_block.block_slot:
                self._neon_block_dict.clear()
                self._start_slot = first_slot + 512
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_block_slot(state.sol_commit)
        if (finalized_block_slot - state.stop_block_slot) < 3:
            state.shift_to_commit(SolCommit.Confirmed)
            try:
                self._collect_neon_txs(state, tracer_max_slot)
                # Save confirmed block only after successfully parsing
                self._confirmed_block_slot = state.stop_block_slot
            except SolHistoryNotFound as err:
                LOG.debug(f'skip parsing of confirmed history: {str(err)}')

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
