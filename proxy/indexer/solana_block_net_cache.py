from typing import List, Generator, Optional
import logging

from ..common_neon.utils.solana_block import SolBlockInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config
from ..common_neon.errors import SolHistoryNotFound, SolHistoryCriticalNotFound

from .indexed_objects import SolNeonDecoderCtx


LOG = logging.getLogger(__name__)


class SolBlockNetCache:
    def __init__(self, config: Config, solana: SolInteractor):
        self._solana = solana

        self._slot_request_len = max(config.indexer_poll_block_cnt * 4, 128)
        self._block_request_len = config.indexer_poll_block_cnt

        self._start_slot = -1
        self._stop_slot = -1
        self._block_list: List[SolBlockInfo] = list()

    def finalize_block(self, sol_block: SolBlockInfo) -> None:
        if sol_block.block_slot > self._stop_slot:
            LOG.debug(f'Clear on finalized slot: {sol_block.block_slot}')
            self._clear_cache()
            return
        elif sol_block.block_slot <= self._start_slot:
            return

        idx = self._calc_idx(sol_block.block_slot)
        self._block_list = self._block_list[idx:]
        self._start_slot = sol_block.block_slot

    def iter_block(self, ctx: SolNeonDecoderCtx) -> Generator[SolBlockInfo, None, None]:
        head_block: Optional[SolBlockInfo] = None
        root_slot = base_slot = ctx.start_slot

        while base_slot < ctx.stop_slot:
            slot_list = self._get_slot_list(ctx, base_slot)
            self._cache_block_list(ctx, base_slot, slot_list)
            base_slot = slot_list[-1]

            block_queue = self._build_block_queue(ctx, root_slot, base_slot)
            if not len(block_queue):
                continue

            # skip the root-slot, include it in the next queue (like start-slot)
            head_block, block_queue = block_queue[0], block_queue[1:]
            root_slot = head_block.block_slot
            for sol_block in reversed(block_queue):
                yield sol_block

        if root_slot != ctx.stop_slot:
            self._raise_error(ctx, ctx.stop_slot, f'Fail to get head {root_slot} (!= {ctx.stop_slot})')

        # in the loop there were the skipping of the root-slot, now return last one
        if head_block:
            yield head_block

    def _build_block_queue(self, ctx: SolNeonDecoderCtx, root_slot: int, slot: int) -> List[SolBlockInfo]:
        child_slot = 0
        block_queue: List[SolBlockInfo] = list()
        while slot >= root_slot:
            sol_block = self._get_sol_block(slot)
            if sol_block.is_empty():
                if not len(block_queue):
                    slot -= 1
                    continue

                msg = f'Fail to get block {slot} (for child {child_slot})'
                if sol_block.has_error():
                    msg = msg + ': ' + sol_block.error

                self._raise_error(ctx, slot, msg)

            block_queue.append(sol_block)
            if slot == root_slot:
                return block_queue
            slot = sol_block.parent_block_slot
            child_slot = sol_block.block_slot

        self._raise_error(ctx, root_slot, f'Fail to reach root {root_slot} (!= {slot})')

    def _get_sol_block(self, slot: int) -> SolBlockInfo:
        idx = self._calc_idx(slot)
        sol_block = self._block_list[idx]
        assert sol_block.block_slot == slot
        return sol_block

    @staticmethod
    def _raise_error(ctx: SolNeonDecoderCtx, slot: int, msg: str) -> None:
        if (not ctx.is_finalized()) or ((ctx.stop_slot - slot) < 1024):
            raise SolHistoryNotFound(msg)
        raise SolHistoryCriticalNotFound(slot, msg)

    def _cache_block_list(self, ctx: SolNeonDecoderCtx, base_slot: int, slot_list: List[int]) -> None:
        assert len(slot_list)

        self._extend_cache_with_empty_blocks(ctx, base_slot, slot_list)

        # request blocks for empty slots
        empty_slot_list = [slot for slot in slot_list if self._get_sol_block(slot).is_empty()]
        if not len(empty_slot_list):
            return

        block_list = self._solana.get_block_info_list(empty_slot_list, ctx.sol_commit, full=True)
        for block in block_list:
            if not block.is_empty():
                idx = self._calc_idx(block.block_slot)
                self._block_list[idx] = block

    def _extend_cache_with_empty_blocks(self, ctx: SolNeonDecoderCtx, base_slot: int, slot_list: List[int]) -> None:
        assert len(slot_list)
        assert slot_list[0] >= base_slot

        # if the requested range doesn't continue the range of the cached blocks
        if base_slot > self._stop_slot + 1:
            LOG.debug(f'Clear on start slot: {str(ctx)}')
            self._clear_cache()
        else:
            base_slot = self._stop_slot + 1

        # the requested range in the range of the cached blocks
        stop_slot = slot_list[-1] + 1
        if stop_slot <= base_slot:
            return

        # extend the cache with empty blocks
        empty_block_list = [SolBlockInfo(block_slot=slot) for slot in range(base_slot, stop_slot)]
        self._block_list.extend(empty_block_list)
        self._start_slot = self._block_list[0].block_slot
        self._stop_slot = self._block_list[-1].block_slot

    def _clear_cache(self) -> None:
        self._start_slot = -1
        self._stop_slot = -1
        self._block_list.clear()

    def _calc_idx(self, slot: int) -> int:
        return slot - self._start_slot

    def _get_slot_list(self, ctx: SolNeonDecoderCtx, base_slot: int) -> List[int]:
        stop_slot = self._calc_stop_slot(ctx, base_slot)
        slot_list = self._solana.get_block_slot_list(base_slot, stop_slot, ctx.sol_commit)
        if not len(slot_list):
            self._raise_error(ctx, base_slot, f'No slot after the slot {base_slot}')

        if ctx.is_finalized():
            slot_list = slot_list[:self._block_request_len]
        return slot_list

    def _calc_stop_slot(self, ctx: SolNeonDecoderCtx, base_slot: int) -> int:
        if not ctx.is_finalized():
            return ctx.stop_slot

        return min(base_slot + self._slot_request_len, ctx.stop_slot)
