from __future__ import annotations

import multiprocessing as mp
import ctypes
import time
import math

from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient

from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class RequestSolanaBlocks:
    def __init__(self, blocks_db: BlocksDB):
        self._b = blocks_db

        self.last_time = self._b.last_time
        self.now = math.ceil(time.time_ns() / 10_000_000)
        self.slot_list = []
        self.db_block = SolanaBlockInfo()
        self.last_increment = self._b.last_increment.value

        self._init_slot_list()

    def _init_slot_list(self):
        if self._b.active_request_cnt > 0:
            return
        elif self._b.current_increment < self.last_increment:
            pass
        # 10 == 0.1 sec, when 0.4 is one block time
        elif self.now < self.last_time or (self.now - self.last_time) < 40:
            return

        try:
            self._b.active_request_cnt += 1

            self._init_db_last_block()
            self.slot_list = self._b.solana.get_block_slot_list(self.db_block.slot, 10)
            if not len(self.slot_list):
                self.error('No confirmed block slots on Solana!')
                return
        finally:
            self._b.active_request_cnt -= 1

    def _init_db_last_block(self):
        self.db_block = self._b.db.get_latest_block()
        if self.db_block.slot:
            return

        # no indexer case
        slot = self._b.solana.get_recent_blockslot('finalized')
        block_list = self._b.solana.get_block_info_list([slot], 'finalized')
        self.db_block = block_list[0]


@logged_group("neon.Proxy")
class BlocksDB:
    # These variables are global for class, they will be initialized one time

    # Blocks dictionaries
    _blocks_by_hash = {}
    _blocks_by_height = {}
    _blocks_by_slot = {}

    # Last requesting time of blocks from Solana node
    last_time = 0

    last_increment = mp.Value(ctypes.c_ulonglong, 0)
    current_increment = 0
    active_request_cnt = 0

    _db_last_block = SolanaBlockInfo()
    _last_block = SolanaBlockInfo()

    def __init__(self, client: SolanaClient, db: IndexerDB):
        self.solana = SolanaInteractor(client)
        self.db = db

    def _rm_old_blocks(self, slot_list):
        exists_slot_list = [slot for slot in self._blocks_by_slot.keys()]
        rm_slot_list = [slot for slot in exists_slot_list if slot not in slot_list]

        for slot in rm_slot_list:
            del self._blocks_by_slot[slot]

        self._blocks_by_height.clear()
        self._blocks_by_hash.clear()

        return [slot for slot in slot_list if slot not in exists_slot_list]

    def _add_new_blocks(self, block_list):
        block_list = [block for block in block_list if block is not None]

        for block in self._blocks_by_slot.values():
            block_list.append(block)

        block_list = sorted(block_list, key=lambda b: b.slot)
        height = self._db_last_block.height

        self._blocks_by_slot.clear()
        for block in block_list:
            height += 1
            block.height = height
            self._blocks_by_slot[block.slot] = block
            self._blocks_by_height[block.height] = block
            if block.hash:
                self._blocks_by_hash[block.hash] = block

        self._last_block = block_list[len(block_list) - 1]

    def _fill_blocks(self, request: RequestSolanaBlocks):
        if (request.last_time != self.last_time) or (not len(request.slot_list)):
            return

        self.last_time = math.ceil(time.time_ns() / 10_000_000)
        self.current_increment = request.last_increment
        self._db_last_block = request.db_block

        slot_list = self._rm_old_blocks(request.slot_list)
        block_list = [SolanaBlockInfo(slot=slot) for slot in slot_list]
        self._add_new_blocks(block_list)

    def _get_full_block_info(self, block: SolanaBlockInfo) -> SolanaBlockInfo:
        if block.hash:
            return block

        block_list = self.solana.get_block_info_list([block.slot])
        if len(block_list) != 1:
            return block

        net_block = block_list[0]
        net_block.height = block.height

        block = self._blocks_by_height.get(net_block.height, None)
        if block and block.slot == net_block.slot:
            self._blocks_by_slot[net_block.slot] = net_block
            self._blocks_by_hash[net_block.hash] = net_block
            self._blocks_by_height[net_block.height] = net_block
        if (self._last_block.slot, self._last_block.height) == (net_block.slot, net_block.height):
            self._last_block = net_block

        return net_block

    def force_request_blocks(self):
        with self.last_increment.get_lock():
            self.last_increment.value += 1

    def get_db_latest_block(self) -> SolanaBlockInfo:
        request = RequestSolanaBlocks(self)
        self._fill_blocks(request)
        return self._db_last_block

    def get_latest_block(self) -> SolanaBlockInfo:
        request = RequestSolanaBlocks(self)
        self._fill_blocks(request)
        return self._last_block

    def get_full_latest_block(self) -> SolanaBlockInfo:
        return self._get_full_block_info(self.get_latest_block())

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        if block_height > self._db_last_block.height:
            request = RequestSolanaBlocks(self)
            self._fill_blocks(request)

            block = self._blocks_by_height.get(block_height)
            if block:
                return block
            if block_height > self._db_last_block.height:
                return SolanaBlockInfo()

        return self.db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        if block_slot > self._db_last_block.slot:
            request = RequestSolanaBlocks(self)
            self._fill_blocks(request)

            block = self._blocks_by_slot.get(block_slot)
            if block:
                return self._get_full_block_info(block)
            if block_slot > self._db_last_block.slot:
                return SolanaBlockInfo()

        return self.db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        request = RequestSolanaBlocks(self)
        self._fill_blocks(request)

        block = self._blocks_by_hash.get(block_hash)
        if block:
            return block

        return self.db.get_block_by_hash(block_hash)

