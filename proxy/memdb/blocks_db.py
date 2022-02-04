import multiprocessing
import pickle
import time
import math

from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient

from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class BlocksDB:
    # These variables are global for class, they will be initialized one time
    _manager = multiprocessing.Manager()

    _blocks_by_hash = _manager.dict()
    _blocks_by_height = _manager.dict()
    _blocks_by_slot = _manager.dict()

    _latest_time = multiprocessing.Value('Q', 0)  # Q - # unsigned long long (8 bytes)

    _latest_block_slot = multiprocessing.Value('Q', 0)
    _latest_block_height = multiprocessing.Value('Q', 0)

    _first_block_slot = multiprocessing.Value('Q', 0)
    _first_block_height = multiprocessing.Value('Q', 0)

    def __init__(self, client: SolanaClient, db: IndexerDB):
        self._solana = SolanaInteractor(client)
        self._db = db

    def _request_blocks(self):
        # assert self._latest_time.get_lock().locked()

        now = math.ceil(time.time_ns() / 10_000_000)

        # 10 == 0.1 sec, when 0.4 is one block time
        if now < self._latest_time.value or (now - self._latest_time.value) < 40:
            return

        self._latest_time.value = now

        last_block_slot = self._db.get_last_block_slot()
        slot_list = self._solana.get_block_slot_list(last_block_slot, 100)
        if not len(slot_list):
            self.error(f'No confirmed blocks on Solana!')
            return

        if slot_list[len(slot_list) - 1] == self._latest_block_slot.value:
            self.debug(f'Latest block is not changed')
            return

        block_list = self._solana.get_block_info_list(slot_list)
        self.debug(f' {block_list}')

        self._blocks_by_slot.clear()
        self._blocks_by_hash.clear()
        self._blocks_by_height.clear()

        first_block = block_list[0]
        self._first_block_slot.value = first_block.slot
        self._first_block_height.vale = first_block.height

        last_block = block_list[len(block_list) - 1]
        self._latest_block_slot.value = last_block.slot
        self._latest_block_height.value = last_block.height

        for block in block_list:
            data = pickle.dumps(block)
            self._blocks_by_slot[block.slot] = data
            self._blocks_by_hash[block.hash] = data
            self._blocks_by_height[block.height] = data

    def get_latest_block_height(self) -> int:
        with self._latest_time.get_lock():
            self._request_blocks()
            return self._latest_block_height.value

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        with self._latest_time.get_lock():
            if block_height >= self._first_block_height.value:
                self._request_blocks()
                data = self._blocks_by_height.get(block_height)
                if data is not None:
                    return pickle.loads(data)

        return self._db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        with self._latest_time.get_lock():
            if block_slot > self._first_block_slot.value:
                self._request_blocks()
                data = self._blocks_by_slot.get(block_slot)
                if data is not None:
                    return pickle.loads(data)

        return self._db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        with self._latest_time.get_lock():
            self._request_blocks()
            data = self._blocks_by_slog.get(block_hash)
            if data is not None:
                return pickle.loads(data)

        return self._db.get_block_by_hash(block_hash)
