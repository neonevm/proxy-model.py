from __future__ import annotations

import multiprocessing as mp
import ctypes
import time
import math
import pickle

from logged_groups import logged_group

from ..common_neon.utils import SolanaBlockInfo
from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class RequestSolanaBlocks:
    def __init__(self, blocks_db: BlocksDB):
        self._b = blocks_db

        self.last_time = self._b.last_time
        self.now = math.ceil(time.time_ns() / 10_000_000)
        self.block_list = []
        self.last_block = SolanaBlockInfo()
        self.first_block = SolanaBlockInfo()
        self.pending_increment = self._b.pending_increment.value

        self._init_block_list()

    def _init_block_list(self):
        if self._b.active_request_cnt > 0:
            return
        elif self._b.current_increment < self.pending_increment:
            pass
        # 10 == 0.1 sec, when 0.4 is one block time
        elif self.now < self.last_time or (self.now - self.last_time) < 40 * 3:
            return

        try:
            self._b.active_request_cnt += 1

            self.block_list = self._b.db.get_latest_block_list(10)
            if not len(self.block_list):
                raise RuntimeError('You should run indexer before proxy!')
            self.now = math.ceil(time.time_ns() / 10_000_000)
            self.first_block = self.block_list[len(self.block_list) - 1]
            self.last_block = self.block_list[0]
        finally:
            self._b.active_request_cnt -= 1


@logged_group("neon.Proxy")
class BlocksDB:
    # These variables are global for class, they will be initialized one time

    # Blocks dictionaries
    _blocks_by_hash = {}
    _blocks_by_height = {}
    _blocks_by_slot = {}

    # Last requesting time of blocks from Solana node
    last_time = 0

    current_increment = 0
    active_request_cnt = 0

    _first_block = SolanaBlockInfo()
    _last_block = SolanaBlockInfo()

    _manager = mp.Manager()

    _block_lock = _manager.Lock()
    _pending_block_by_slot = _manager.dict()
    pending_increment = mp.Value(ctypes.c_ulonglong, 0)

    def __init__(self, db: IndexerDB):
        self.db = db

    def _add_block(self, block):
        self._blocks_by_slot[block.slot] = block
        self._blocks_by_height[block.height] = block
        if block.hash:
            self._blocks_by_hash[block.hash] = block

    def _fill_blocks(self, request: RequestSolanaBlocks):
        if (request.last_time != self.last_time) or (not len(request.block_list)):
            return

        self.last_time = request.now
        self.current_increment = request.pending_increment
        self._last_block = request.last_block
        self._first_block = request.first_block

        self._blocks_by_slot.clear()
        self._blocks_by_height.clear()
        self._blocks_by_hash.clear()

        for block in request.block_list:
            self._add_block(block)

        if not len(self._pending_block_by_slot):
            return

        rm_block_slot = []
        with self._block_lock:
            for slot, data in self._pending_block_by_slot.items():
                if slot < self._last_block.slot:
                    rm_block_slot.append(slot)
                else:
                    self._add_block(pickle.loads(data))
            for slot in rm_block_slot:
                del self._pending_block_by_slot[slot]

    def _get_full_block_info(self, block: SolanaBlockInfo) -> SolanaBlockInfo:
        if block.time:
            return block

        db_block = self.db.get_full_block_by_slot(block.slot)
        if not db_block:
            return block

        block = self._blocks_by_slot.get(db_block.slot, None)
        if block and block.slot == db_block.slot:
            self._blocks_by_slot[db_block.slot] = db_block
            self._blocks_by_hash[db_block.hash] = db_block
            self._blocks_by_height[db_block.height] = db_block
        if (self._last_block.slot, self._last_block.height) == (db_block.slot, db_block.height):
            self._last_block = db_block
        if (self._first_block.slot, self._first_block.height) == (db_block.slot, db_block.height):
            self._last_block = db_block
        return db_block

    def get_latest_block(self) -> SolanaBlockInfo:
        request = RequestSolanaBlocks(self)
        self._fill_blocks(request)
        return self._last_block

    def get_full_latest_block(self) -> SolanaBlockInfo:
        return self._get_full_block_info(self.get_latest_block())

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        if block_height > self._first_block.height:
            request = RequestSolanaBlocks(self)
            self._fill_blocks(request)

            block = self._blocks_by_height.get(block_height)
            if block:
                return block

        return self.db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        if block_slot > self._first_block.slot:
            request = RequestSolanaBlocks(self)
            self._fill_blocks(request)

            block = self._blocks_by_slot.get(block_slot)
            if block:
                return self._get_full_block_info(block)

        return self.db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        request = RequestSolanaBlocks(self)
        self._fill_blocks(request)

        block = self._blocks_by_hash.get(block_hash)
        if block:
            return block

        return self.db.get_block_by_hash(block_hash)

    def submit_block(self, block):
        data = pickle.dumps(block)
        with self._block_lock:
            self._pending_block_by_slot[block.slot] = data
            self.pending_increment.value += 1
