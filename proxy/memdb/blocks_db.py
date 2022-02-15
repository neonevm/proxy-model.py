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
class RequestSolanaBlockList:
    BLOCK_CACHE_LIMIT = 200

    def __init__(self, blocks_db: MemBlocksDB):
        self._b = blocks_db

        self.last_time = self._b.last_time.value
        self.now = math.ceil(time.time_ns() / 10_000_000)
        self.block_list = []
        self.tail_block = SolanaBlockInfo(slot=0, height=0)
        self.head_block = SolanaBlockInfo(slot=0, height=0)

    def execute(self) -> bool:
        # 10 == 0.1 sec, when 0.4 is one block time
        if self.now < self.last_time or (self.now - self.last_time) < 40:
            return False

        # one of the workers already tries to get new list of blocks
        with self._b.has_active_request.get_lock():
            if self._b.has_active_request.value:
                return False
            self._b.has_active_request.value = True

        try:
            self._init_head_block()
            if not self._init_solana_block_list():
                return False

            self.now = math.ceil(time.time_ns() / 10_000_000)

            self._b.fill_blocks(self)
            return True
        except:
            return False
        finally:
            with self._b.has_active_request.get_lock():
                self._b.has_active_request.value = False

    def _init_head_block(self):
        self.head_block = self._b.db.get_latest_block()
        if self.head_block.slot:
            return
        self.head_block.slot = self._b.solana.get_recent_blockslot(commitment=FINALIZED)

    def _init_solana_block_list(self) -> bool:
        slot = self.head_block.slot
        slot_list = [s for s in range(slot, slot + self.BLOCK_CACHE_LIMIT)]
        self.block_list = self._b.solana.get_block_info_list(slot_list)
        if not len(self.block_list):
            return False

        self.tail_block = self.block_list[len(self.block_list) - 1]

        height = self.tail_block.height
        tail_height = self._b.get_tail_block_height()
        if tail_height > height:
            height = tail_height

        for block in reversed(self.block_list):
            block.height = height
            height -= 1

        if not self.head_block.height:
            self.head_block = self.block_list[0]
            self.head_block.height -= 1

        return len(self.block_list) > 0


@logged_group("neon.Proxy")
class MemBlocksDB:
    # These variables are global for class, they will be initialized one time
    _manager = mp.Manager()
    _block_lock = _manager.Lock()

    # Blocks dictionaries
    _block_by_hash = _manager.dict()
    _block_by_height = _manager.dict()
    _pending_block_by_slot = _manager.dict()

    # Head and tail of cache
    _head_block_slot = _manager.Value(ctypes.c_ulonglong, 0)
    _head_block_height = _manager.Value(ctypes.c_ulonglong, 0)

    _tail_block_data = _manager.Value(ctypes.c_void_p, b'')
    _tail_block_height = _manager.Value(ctypes.c_ulonglong, 0)

    # Last requesting time of blocks from Solana node
    last_time = _manager.Value(ctypes.c_ulonglong, 0)
    has_active_request = mp.Value(ctypes.c_bool, False)

    def __init__(self, solana: SolanaInteractor, db: IndexerDB):
        self.db = db
        self.solana = solana

    def _add_block(self, block, data=None):
        if not data:
            data = pickle.dumps(block)

        self._block_by_hash[block.hash] = data
        self._block_by_height[block.height] = data

    def fill_blocks(self, request: RequestSolanaBlockList):
        with self._block_lock:
            self._fill_blocks(request)

    def _fill_blocks(self, request: RequestSolanaBlockList):
        self.last_time.value = request.now

        self._head_block_slot.value = request.head_block.slot
        self._head_block_height.value = request.head_block.height

        self._tail_block_data.value = pickle.dumps(request.tail_block)
        self._tail_block_height.value = request.tail_block.height

        self._block_by_height.clear()
        self._block_by_hash.clear()

        for block in request.block_list:
            self._add_block(block)

        rm_block_slot_list = []
        for slot, data in self._pending_block_by_slot.items():
            if slot <= request.head_block.slot:
                rm_block_slot_list.append(slot)
            else:
                block = pickle.loads(data)
                self._add_block(block, data)

        for slot in rm_block_slot_list:
            del self._pending_block_by_slot[slot]

    def _request_blocks(self):
        RequestSolanaBlockList(self).execute()

    def _get_tail_block(self) -> SolanaBlockInfo:
        data = self._tail_block_data.value
        if len(data):
            return pickle.loads(data)
        return SolanaBlockInfo()

    def get_tail_block(self) -> SolanaBlockInfo:
        self._request_blocks()
        with self._block_lock:
            return self._get_tail_block()

    def get_tail_block_height(self) -> int:
        self._request_blocks()
        return self._tail_block_height.value

    def get_head_block_slot(self) -> int:
        self._request_blocks()
        return self._head_block_slot.value

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        self._request_blocks()
        if block_height > self._head_block_height.value:
            with self._block_lock:
                data = self._block_by_height.get(block_height)
            if data:
                return pickle.loads(data)
            else:
                return SolanaBlockInfo()

        return self.db.get_block_by_height(block_height)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        self._request_blocks()
        with self._block_lock:
            data = self._block_by_hash.get(block_hash)
        if data:
            return pickle.loads(data)

        return self.db.get_block_by_hash(block_hash)

    def _generate_fake_block(self, neon_res: NeonTxResultInfo) -> SolanaBlockInfo:
        data = self._pending_block_by_slot.get(neon_res.slot)
        if data:
            block = pickle.loads(data)
        else:
            tail_block = self._get_tail_block()
            block_height = (tail_block.height or neon_res.slot) + 1
            block_time = (tail_block.time or 1)

            block = SolanaBlockInfo(
                slot=neon_res.slot,
                height=block_height,
                time=block_time,
                hash='0x' + os.urandom(32).hex(),
                parent_hash='0x' + os.urandom(32).hex(),
            )
            self.debug(f'Generate fake block {block} for {neon_res.sol_sign}')

        block.signs.append(neon_res.sol_sign)
        return block

    def submit_block(self, neon_res: NeonTxResultInfo) -> SolanaBlockInfo:
        block_list = self.solana.get_block_info_list([neon_res.slot])
        block = block_list[0] if len(block_list) else SolanaBlockInfo()

        with self._block_lock:
            if not block.slot:
                block = self._generate_fake_block(neon_res)

            data = pickle.dumps(block)
            self._pending_block_by_slot[block.slot] = data
            self._add_block(block, data)

            return block
