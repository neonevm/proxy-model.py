from __future__ import annotations

import multiprocessing as mp
import ctypes
import pickle
import time
import math

from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient

from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB


BlocksManager = mp.Manager()


class BlockInfo:
    @classmethod
    def set(cls, block: SolanaBlockInfo):
        cls.slot.value = block.slot
        cls.height.value = block.height
        cls.hash.value = block.hash

    @classmethod
    def get(cls) -> SolanaBlockInfo:
        return SolanaBlockInfo(
            slot=cls.slot.value,
            height=cls.height.value,
            hash=cls.hash.value
        )


@logged_group("neon.Proxy")
class BlocksDB:
    # These variables are global for class, they will be initialized one time
    # Lock for blocks
    _blocks_lock = BlocksManager.Lock()

    # Blocks dictionaries
    _blocks_by_hash = BlocksManager.dict()
    _blocks_by_height = BlocksManager.dict()
    _blocks_by_slot = BlocksManager.dict()

    # Last requesting time of blocks from Solana node
    _last_time = BlocksManager.Value(ctypes.c_ulonglong, 0)

    class _DBLastBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    class _FirstBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    class _LastBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    def __init__(self, client: SolanaClient, db: IndexerDB):
        self._solana = SolanaInteractor(client)
        self._db = db

    def _request_blocks(self):
        # assert self._blocks_lock.locked()

        now = math.ceil(time.time_ns() / 10_000_000)

        # 10 == 0.1 sec, when 0.4 is one block time
        if now < self._last_time.value or (now - self._last_time.value) < 40:
            return

        db_block = self._db.get_latest_block()
        if db_block.slot < self._FirstBlockInfo.slot.value:
            return

        slot_list = self._solana.get_block_slot_list(db_block.slot, 100)
        if not len(slot_list):
            self.error('No confirmed block slots on Solana!')
            return

        # TODO: add filtering of already cached blocks
        block_list = self._solana.get_block_info_list(slot_list)
        if not len(block_list):
            self.error('No confirmed block infos on Solana!')
            return

        self._DBLastBlockInfo.set(db_block)
        self._last_time.value = now

        # TODO: the first block can stay on the same place
        self._FirstBlockInfo.set(block_list[0])
        self._LastBlockInfo.set(block_list[len(block_list) - 1])

        # TODO: add only not-existing blocks
        self._blocks_by_slot.clear()
        self._blocks_by_hash.clear()
        self._blocks_by_height.clear()

        for block in block_list:
            block.finalized = False
            data = pickle.dumps(block)
            self._blocks_by_slot[block.slot] = data
            self._blocks_by_hash[block.hash] = data
            self._blocks_by_height[block.height] = data

    def force_request_blocks(self):
        self._last_time.value = 0

    def get_db_latest_block(self) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            return self._DBLastBlockInfo.get()

    def get_latest_block(self) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            return self._LastBlockInfo.get()

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        if block_height >= self._FirstBlockInfo.height.value:
            with self._blocks_lock:
                self._request_blocks()
                data = self._blocks_by_height.get(block_height)
                if data is not None:
                    return pickle.loads(data)

        return self._db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        if block_slot > self._FirstBlockInfo.slot.value:
            with self._blocks_lock:
                self._request_blocks()
                data = self._blocks_by_slot.get(block_slot)
                if data:
                    return pickle.loads(data)

        return self._db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            data = self._blocks_by_hash.get(block_hash)
            if data:
                return pickle.loads(data)

        return self._db.get_block_by_hash(block_hash)
