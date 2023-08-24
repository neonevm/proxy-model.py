from typing import List, Generator, Optional
import logging

from ..common_neon.utils.solana_block import SolBlockInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolCommit
from ..common_neon.config import Config
from ..common_neon.errors import SolHistoryNotFound

from .indexed_objects import SolNeonDecoderCtx

LOG = logging.getLogger(__name__)


class SolBlockNetCache:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana

        self._need_to_recache_block_list = False
        self._start_slot = -1
        self._stop_slot = -1
        self._block_list: List[SolBlockInfo] = list()

    def finalize_block(self, sol_block: SolBlockInfo) -> None:
        if sol_block.block_slot > self._stop_slot:
            LOG.debug(f'clear on finalized slot: {sol_block.block_slot}')
            self._clear_cache()
            return
        elif sol_block.block_slot <= self._start_slot:
            return

        idx = self._calc_idx(sol_block.block_slot)
        self._block_list = self._block_list[idx:]
        self._start_slot = sol_block.block_slot

    def iter_block(self, state: SolNeonDecoderCtx) -> Generator[SolBlockInfo, None, None]:
        root_block: Optional[SolBlockInfo] = None
        root_slot = state.start_slot
        start_slot = state.start_slot

        while start_slot < state.stop_slot:
            stop_slot = self._calc_stop_slot(state, start_slot)
            self._cache_block_list(state, start_slot, stop_slot)
            start_slot = stop_slot

            block_queue = self._build_block_queue(state, root_slot, stop_slot)
            if not len(block_queue):
                continue

            # skip the root-slot, include it in the next queue (like start-slot)
            root_block, block_queue = block_queue[0], block_queue[1:]
            for sol_block in reversed(block_queue):
                yield sol_block
            root_slot = root_block.block_slot

        if root_slot != state.stop_slot:
            self._raise_sol_history_error(state, f'Fail to get head {root_slot}')

        # in the loop there were the skipping of the root-slot, now return last one
        if root_block is not None:
            yield root_block

    def _build_block_queue(self, state: SolNeonDecoderCtx, root_slot: int, slot: int) -> List[SolBlockInfo]:
        block_queue: List[SolBlockInfo] = list()
        while slot >= root_slot:
            sol_block = self._get_sol_block(slot)
            if sol_block.is_empty():
                if not len(block_queue):
                    slot -= 1
                    continue
                self._raise_sol_history_error(state, f'Failed to get block {slot}')

            block_queue.append(sol_block)
            if slot == root_slot:
                return block_queue
            slot = sol_block.parent_block_slot

        self._raise_sol_history_error(state, f'Fail to get root {root_slot}')

    def _get_sol_block(self, slot: int) -> SolBlockInfo:
        idx = self._calc_idx(slot)
        sol_block = self._block_list[idx]
        assert sol_block.block_slot == slot
        return sol_block

    def _raise_sol_history_error(self, state: SolNeonDecoderCtx, msg: str) -> None:
        if state.sol_commit == SolCommit.Confirmed:
            self._need_to_recache_block_list = True
        else:
            LOG.debug(f'clear on bad branch: {str(state)}')
            self._clear_cache()
        raise SolHistoryNotFound(msg)

    def _cache_block_list(self, state: SolNeonDecoderCtx, start_slot: int, stop_slot: int) -> None:
        if self._need_to_recache_block_list:
            self._recache_block_list(state)

        if (start_slot >= self._start_slot) and (stop_slot <= self._stop_slot):
            return

        start_slot = max(start_slot, self._stop_slot + 1)
        if start_slot != self._stop_slot + 1:
            LOG.debug(f'clear on start slot: {str(state)}')
            self._clear_cache()

        if not len(self._block_list):
            self._start_slot = start_slot

        slot_list = [slot for slot in range(start_slot, stop_slot + 1)]
        assert len(slot_list)

        block_list = self._solana.get_block_info_list(slot_list, state.sol_commit, full=True)
        self._block_list.extend(block_list)
        self._stop_slot = stop_slot

    def _recache_block_list(self, state: SolNeonDecoderCtx) -> None:
        LOG.debug(f'recache: {str(state)}')
        self._need_to_recache_block_list = False

        slot_list = [block.block_slot for block in self._block_list if block.is_empty()]
        if not len(slot_list):
            return

        block_list = self._solana.get_block_info_list(slot_list, state.sol_commit, full=True)
        for block in block_list:
            if not block.is_empty():
                idx = self._calc_idx(block.block_slot)
                self._block_list[idx] = block

    def _clear_cache(self) -> None:
        self._need_to_recache_block_list = False
        self._start_slot = -1
        self._stop_slot = -1
        self._block_list.clear()

    def _calc_idx(self, slot: int) -> int:
        return slot - self._start_slot

    def _calc_stop_slot(self, state: SolNeonDecoderCtx, start_slot: int) -> int:
        if state.sol_commit != SolCommit.Finalized:
            return state.stop_slot

        return min(
            start_slot + self._config.indexer_poll_block_cnt,
            state.stop_slot
        )
