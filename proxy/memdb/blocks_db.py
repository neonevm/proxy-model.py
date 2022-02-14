from __future__ import annotations

import multiprocessing as mp
import ctypes
import time
import math
import pickle
import os

from logged_groups import logged_group

from ..common_neon.utils import SolanaBlockInfo, NeonTxResultInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB

from ..environment import FINALIZED


@logged_group("neon.Proxy")
class RequestSolanaBlocks:
    BLOCK_CACHE_LIMIT = 32

    def __init__(self, blocks_db: BlocksDB):
        self._b = blocks_db

        self.last_time = self._b.last_time
        self.now = math.ceil(time.time_ns() / 10_000_000)
        self.block_list = []
        self.last_block = SolanaBlockInfo()
        self.first_block = SolanaBlockInfo(slot=0, height=0)
        self.pending_increment = self._b.pending_increment.value

    def execute(self) -> bool:
        # this worker already tries to get new list of blocks
        if self._b.has_active_request:
            return False
        # if the forcing of request exists
        elif self._b.current_increment < self.pending_increment:
            pass
        # 10 == 0.1 sec, when 0.4 is one block time
        elif self.now < self.last_time or (self.now - self.last_time) < 40 * 3:
            return False

        try:
            self._b.has_active_request = True

            if not self._init_db_block_list():
                if not self._init_solana_block_list():
                    return False

            self.now = math.ceil(time.time_ns() / 10_000_000)
            self.first_block = self.block_list[len(self.block_list) - 1]
            self.last_block = self.block_list[0]
            return True
        finally:
            self._b.has_active_request = False

    def _init_db_block_list(self) -> bool:
        self.block_list = self._b.db.get_latest_block_list(self.BLOCK_CACHE_LIMIT)
        return len(self.block_list) > 0

    def _init_solana_block_list(self) -> bool:
        limit = self.BLOCK_CACHE_LIMIT * 2

        slot = self._b.solana.get_recent_blockslot(commitment=FINALIZED)
        slot_list = self._b.solana.get_block_slot_list(slot - limit, limit=limit, commitment=FINALIZED)
        if not len(slot_list):
            return False

        slot_list = slot_list[:-self.BLOCK_CACHE_LIMIT]
        self.block_list = self._b.solana.get_block_info_list(slot_list, commitment=FINALIZED)
        return len(self.block_list) > 0


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
    has_active_request = False

    _first_block = SolanaBlockInfo(slot=0, height=0)
    _last_block = SolanaBlockInfo(slot=0, height=0)

    _manager = mp.Manager()

    _block_lock = _manager.Lock()
    _pending_block_by_slot = _manager.dict()
    pending_increment = mp.Value(ctypes.c_uint, 0)

    def __init__(self, solana: SolanaInteractor, db: IndexerDB):
        self.db = db
        self.solana = solana

    def _add_block(self, block):
        self._blocks_by_slot[block.slot] = block
        self._blocks_by_height[block.height] = block
        if block.hash:
            self._blocks_by_hash[block.hash] = block

    def _fill_blocks(self, request: RequestSolanaBlocks):
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
                elif slot not in self._blocks_by_slot:
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

    def _request_blocks(self):
        request = RequestSolanaBlocks(self)
        if request.execute():
            self._fill_blocks(request)

    def get_latest_block(self) -> SolanaBlockInfo:
        self._request_blocks()
        return self._last_block

    def get_full_latest_block(self) -> SolanaBlockInfo:
        return self._get_full_block_info(self.get_latest_block())

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        if block_height > self._first_block.height:
            self._request_blocks()

            block = self._blocks_by_height.get(block_height)
            if block:
                return block

        return self.db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        if block_slot > self._first_block.slot:
            self._request_blocks()

            block = self._blocks_by_slot.get(block_slot)
            if block:
                return self._get_full_block_info(block)

        return self.db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        self._request_blocks()

        block = self._blocks_by_hash.get(block_hash)
        if block:
            return block

        return self.db.get_block_by_hash(block_hash)

    @staticmethod
    def _generate_fake_block(prev_block: SolanaBlockInfo, slot: int) -> SolanaBlockInfo:
        return SolanaBlockInfo(
            slot=slot,
            height=prev_block.height + 1,
            time=prev_block.time,
            hash='0x' + os.urandom(32).hex(),
            parent_hash=prev_block.hash,
        )

    def _generate_fake_history(self, last_block: SolanaBlockInfo, new_slot: int):
        data = self._pending_block_by_slot.get(new_slot)
        if data:
            return

        start_slot = last_block.slot + 1
        block = last_block
        for slot in range(new_slot, last_block.slot, -1):
            data = self._pending_block_by_slot.get(slot)
            if data:
                start_slot = slot + 1
                block = pickle.loads(data)

        for slot in range(start_slot, new_slot + 1):
            block = self._generate_fake_block(block, slot)
            data = pickle.dumps(block)
            self._pending_block_by_slot.setdefault(slot, data)

        return block

    def submit_block(self, neon_res: NeonTxResultInfo):
        # for faster confirmation by Ethereum clients ...
        # Solana can switch to another history branch,
        #   so it isn't critical return a fake block for a not-finalized state

        last_block = self.get_full_latest_block()
        with self._block_lock:
            self._generate_fake_history(last_block, neon_res.slot + 1)
            data = self._pending_block_by_slot[neon_res.slot]
            block = pickle.loads(data)
            block.signs.append(neon_res.sol_sign)
            self._pending_block_by_slot[neon_res.slot] = pickle.dumps(block)
            self.pending_increment.value += 1
            return block
