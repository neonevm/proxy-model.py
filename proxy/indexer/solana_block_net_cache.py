from collections import deque
from typing import Optional, Deque

from ..common_neon.utils.solana_block import SolBlockInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolCommit
from ..common_neon.config import Config


class SolBlockNetCache:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana

        self._need_to_recache_block_list = False
        self._start_block_slot = 0
        self._stop_block_slot = 0
        self._block_list: Deque[Optional[SolBlockInfo]] = deque()

    def finalize_block(self, block_slot: int) -> None:
        assert block_slot >= self._start_block_slot
        if block_slot > self._stop_block_slot:
            self.clear()
            return

        while len(self._block_list) and (self._start_block_slot <= block_slot):
            self._block_list.popleft()
            self._start_block_slot += 1

    def get_block_info(self, block_slot: int,
                       stop_block_slot: int,
                       sol_commit: SolCommit.Type) -> Optional[SolBlockInfo]:
        if self._need_to_recache_block_list:
            self._recache_block_list(sol_commit)

        if (block_slot > self._stop_block_slot) or (not len(self._block_list)):
            assert block_slot >= self._stop_block_slot
            self._cache_block_list(block_slot, stop_block_slot, sol_commit)

        idx = block_slot - self._start_block_slot
        block_info = self._block_list[idx]
        assert block_info.block_slot == block_slot
        return block_info

    def mark_recache_block_list(self) -> None:
        self._need_to_recache_block_list = True

    def clear(self) -> None:
        self._start_block_slot = 0
        self._stop_block_slot = 0
        self._block_list.clear()

    def _cache_block_list(self, block_slot: int, stop_block_slot: int, sol_commit: SolCommit.Type) -> None:
        max_block_slot = min(
            block_slot + self._config.indexer_poll_block_cnt,
            stop_block_slot
        )

        self._stop_block_slot = max_block_slot
        if not len(self._block_list):
            self._start_block_slot = block_slot

        block_slot_list = [i for i in range(block_slot, max_block_slot + 1)]
        block_info_list = self._solana.get_block_info_list(block_slot_list, sol_commit, True)
        self._block_list.extend(block_info_list)

    def _recache_block_list(self, commitment: SolCommit.Type) -> None:
        self._need_to_recache_block_list = False

        start_slot = self._start_block_slot
        block_slot_list = [start_slot + i for i in range(len(self._block_list)) if self._block_list[i] is None]
        if not len(block_slot_list):
            return

        block_info_list = self._solana.get_block_info_list(block_slot_list, commitment, True)
        for block_info in block_info_list:
            if block_info is not None:
                self._block_list[start_slot + block_info.block_slot] = block_info
