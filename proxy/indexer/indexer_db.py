from __future__ import annotations

from typing import Optional, List, Dict, Any, Tuple

from .gas_less_usages_db import GasLessUsagesDB
from .indexed_objects import NeonIndexedBlockInfo
from .neon_tx_logs_db import NeonTxLogsDB
from .neon_txs_db import NeonTxsDB
from .solana_alt_infos_db import SolAltInfosDB
from .solana_alt_txs_db import SolAltTxsDB
from .solana_blocks_db import SolBlocksDB, SolBlockSlotRange
from .solana_neon_txs_db import SolNeonTxsDB
from .solana_tx_costs_db import SolTxCostsDB
from .stuck_neon_holders_db import StuckNeonHoldersDB
from .stuck_neon_txs_db import StuckNeonTxsDB

from ..common_neon.config import Config
from ..common_neon.db.constats_db import ConstantsDB
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo, SolAltIxInfo
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.evm_log_decoder import NeonLogTxEvent


class IndexerDB:
    _max_u64 = (2 ** 64 - 1)
    base_start_slot_name = 'starting_block_slot'
    base_min_used_slot_name = 'min_receipt_block_slot'
    finalized_slot_name = 'finalized_block_slot'

    def __init__(self, config: Config, db_conn: DBConnection, reindex_ident: str):
        self._config = config
        self._db_conn = db_conn

        self._reindex_ident = reindex_ident
        if self.is_reindexing_mode():
            reindex_ident += ':'

        self._start_slot_name = reindex_ident + self.base_start_slot_name
        self._stop_slot_name = reindex_ident + 'stop_block_slot'
        self._min_used_slot_name = reindex_ident + self.base_min_used_slot_name
        self._latest_slot_name = 'latest_block_slot'

        self._constants_db = ConstantsDB(db_conn)
        self._sol_blocks_db = SolBlocksDB(db_conn)
        self._sol_tx_costs_db = SolTxCostsDB(db_conn)
        self._neon_txs_db = NeonTxsDB(db_conn)
        self._sol_neon_txs_db = SolNeonTxsDB(db_conn)
        self._neon_tx_logs_db = NeonTxLogsDB(db_conn)
        self._gas_less_usages_db = GasLessUsagesDB(db_conn)
        self._sol_alt_txs_db = SolAltTxsDB(db_conn)
        self._stuck_neon_holders_db = StuckNeonHoldersDB(db_conn)
        self._stuck_neon_txs_db = StuckNeonTxsDB(db_conn)
        self._sol_alt_infos_db = SolAltInfosDB(db_conn)

        self._finalized_db_list = (
            self._sol_blocks_db,
            self._sol_tx_costs_db,
            self._neon_txs_db,
            self._sol_neon_txs_db,
            self._neon_tx_logs_db,
        )

        self._start_slot = 0
        self._stop_slot = self._max_u64
        self._min_used_slot = 0
        self._latest_slot = 0
        self._finalized_slot = 0

        if not self.is_reindexing_mode():
            self._latest_slot = self.latest_slot
            self._finalized_slot = self.finalized_slot

    @staticmethod
    def from_db(config: Config, db: DBConnection, reindex_ident: str = '') -> IndexerDB:
        db = IndexerDB(config, db, reindex_ident)

        db._min_used_slot = db._constants_db.get(db._min_used_slot_name, 0)
        db._start_slot = db._constants_db.get(db._start_slot_name, db._min_used_slot)
        db._stop_slot = db._constants_db.get(db._stop_slot_name, db._max_u64)

        return db

    @staticmethod
    def from_range(config: Config, db: DBConnection, start_slot: int,
                   reindex_ident: str = '', stop_slot: Optional[int] = None) -> IndexerDB:
        db = IndexerDB(config, db, reindex_ident)

        db._start_slot = start_slot
        db._min_used_slot = start_slot
        db._stop_slot = stop_slot or db._max_u64

        db._min_used_slot = db._constants_db[db._min_used_slot_name] = start_slot

        if db.is_reindexing_mode():
            db._constants_db[db._start_slot_name] = start_slot
            db._constants_db[db._stop_slot_name] = stop_slot

        if db._constants_db.get(db.base_start_slot_name, db._max_u64) > start_slot:
            db._constants_db[db.base_start_slot_name] = start_slot

        return db

    @property
    def reindex_ident(self) -> str:
        return self._reindex_ident

    @property
    def start_slot(self) -> int:
        return self._start_slot

    @property
    def stop_slot(self) -> int:
        return self._stop_slot

    def is_reindexing_mode(self) -> bool:
        return len(self._reindex_ident) > 0

    def drop_not_finalized_history(self) -> None:
        self._db_conn.run_tx(
            lambda: self._drop_not_finalized_history()
        )

    def _drop_not_finalized_history(self) -> None:
        for db_table in self._finalized_db_list:
            db_table.finalize_block_list(self._finalized_slot, self._latest_slot + 1, (self._finalized_slot,))

    def submit_block_list(self, min_used_slot: int, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        self._db_conn.run_tx(
            lambda: self._submit_block_list(min_used_slot, neon_block_queue)
        )

    def _submit_block_list(self, min_used_slot: int, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        self._submit_new_block_list(neon_block_queue)
        self._set_min_used_slot(min_used_slot)
        self._set_block_branch(neon_block_queue)

        for block in neon_block_queue:
            block.mark_done()

    def _submit_new_block_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        new_neon_block_queue = [block for block in neon_block_queue if not block.is_done]
        if not len(new_neon_block_queue):
            return

        self._sol_blocks_db.set_block_list(new_neon_block_queue)
        self._neon_txs_db.set_tx_list(new_neon_block_queue)
        self._neon_tx_logs_db.set_tx_list(new_neon_block_queue)
        self._sol_neon_txs_db.set_tx_list(new_neon_block_queue)
        self._sol_alt_txs_db.set_tx_list(new_neon_block_queue)
        self._sol_tx_costs_db.set_cost_list(new_neon_block_queue)
        self._gas_less_usages_db.set_tx_list(new_neon_block_queue)

    def _set_block_branch(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        last_neon_block = neon_block_queue[-1]

        if self.is_reindexing_mode():
            self._submit_stuck_obj_list(last_neon_block)
            return

        if last_neon_block.is_finalized:
            self._finalize_block_list(neon_block_queue)
        else:
            self._activate_block_list(neon_block_queue)
        self._set_latest_slot(last_neon_block.block_slot)

    def _finalize_block_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        block_slot_list = tuple(
            block.block_slot
            for block in neon_block_queue
            if block.is_done and (block.block_slot > self._finalized_slot)
        )

        last_neon_block = neon_block_queue[-1]
        if last_neon_block.is_finalized:
            self._submit_stuck_obj_list(last_neon_block)
            self._set_finalized_slot(last_neon_block.block_slot)

        if len(block_slot_list) == 0:
            return

        for db_table in self._finalized_db_list:
            db_table.finalize_block_list(self._finalized_slot, last_neon_block.block_slot, block_slot_list)

    def _activate_block_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        last_neon_block = neon_block_queue[-1]
        if not last_neon_block.is_done:
            last_neon_block.check_stuck_objs(self._config)
            self._stuck_neon_txs_db.set_tx_list(self._start_slot, self._stop_slot, last_neon_block)

        block_slot_list = tuple(
            block.block_slot
            for block in neon_block_queue
            if not block.is_finalized
        )
        if not len(block_slot_list):
            return

        self._sol_blocks_db.activate_block_list(self._finalized_slot, block_slot_list)

    def _submit_stuck_obj_list(self, neon_block: NeonIndexedBlockInfo) -> None:
        if self._stop_slot > neon_block.block_slot:
            neon_block.check_stuck_objs(self._config)

        self._stuck_neon_holders_db.set_holder_list(self._start_slot, self._stop_slot, neon_block)
        self._stuck_neon_txs_db.set_tx_list(self._start_slot, self._stop_slot, neon_block)
        self._sol_alt_infos_db.set_alt_list(self._start_slot, self._stop_slot, neon_block)

    def _set_finalized_slot(self, slot: int) -> None:
        if self._finalized_slot >= slot:
            return

        self._finalized_slot = slot
        self._constants_db[self.finalized_slot_name] = slot

    def _set_latest_slot(self, slot: int) -> None:
        if self._latest_slot >= slot:
            return

        self._latest_slot = slot
        self._constants_db[self._latest_slot_name] = slot

    def _set_min_used_slot(self, slot: int) -> None:
        if self._min_used_slot >= slot:
            return

        self._min_used_slot = slot
        self._constants_db[self._min_used_slot_name] = slot

    def set_start_slot(self, slot: int) -> None:
        if self._start_slot >= slot:
            return

        self._set_min_used_slot(slot)

        self._start_slot = slot
        if self.is_reindexing_mode():
            self._constants_db[self._start_slot_name] = slot

    def set_stop_slot(self, slot: int) -> None:
        assert self.is_reindexing_mode()

        if self._stop_slot > slot:
            return

        self._stop_slot = slot
        self._constants_db[self._stop_slot_name] = slot

    def done(self) -> None:
        for k in [self._start_slot_name, self._stop_slot_name, self._min_used_slot_name]:
            if k in self._constants_db:
                del self._constants_db[k]

    def get_block_by_slot(self, block_slot: int) -> SolBlockInfo:
        return self._sol_blocks_db.get_block_by_slot(block_slot, self._block_slot_range)

    def get_block_by_hash(self, block_hash: str) -> SolBlockInfo:
        return self._sol_blocks_db.get_block_by_hash(block_hash, self._block_slot_range)

    @property
    def earliest_slot(self) -> int:
        return self._constants_db.get(self._start_slot_name, 0)

    @property
    def latest_slot(self) -> int:
        return self._constants_db.get(self._latest_slot_name, 0)

    @property
    def finalized_slot(self) -> int:
        return self._constants_db.get(self.finalized_slot_name, 0)

    @property
    def min_used_slot(self) -> int:
        return self._min_used_slot

    @property
    def earliest_block(self) -> SolBlockInfo:
        slot_range = self._block_slot_range
        return self._sol_blocks_db.get_block_by_slot(slot_range.earliest_slot, slot_range)

    @property
    def latest_block(self) -> SolBlockInfo:
        slot_range = self._block_slot_range
        return self._sol_blocks_db.get_block_by_slot(slot_range.latest_slot, slot_range)

    @property
    def finalized_block(self) -> SolBlockInfo:
        slot_range = self._block_slot_range
        return self._sol_blocks_db.get_block_by_slot(slot_range.finalized_slot, slot_range)

    @property
    def _block_slot_range(self) -> SolBlockSlotRange:
        return SolBlockSlotRange(
            earliest_slot=self.earliest_slot,
            finalized_slot=self.finalized_slot,
            latest_slot=self.latest_slot
        )

    def get_event_list(self, from_block: Optional[int], to_block: Optional[int],
                       address_list: List[str], topic_list: List[List[str]]) -> List[NeonLogTxEvent]:
        return self._neon_tx_logs_db.get_event_list(from_block, to_block, address_list, topic_list)

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_list_by_block_slot(block_slot)

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_neon_sig(neon_sig)

    def get_tx_by_sender_nonce(self, sender: str, tx_nonce: int) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_sender_nonce(sender, tx_nonce)

    def get_tx_by_block_slot_tx_idx(self, block_slot: int, tx_idx: int) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_block_slot_tx_idx(block_slot, tx_idx)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        return self._sol_neon_txs_db.get_sol_sig_list_by_neon_sig(neon_sig)

    def get_alt_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        return self._sol_alt_txs_db.get_alt_sig_list_by_neon_sig(neon_sig)

    def get_sol_ix_info_list_by_neon_sig(self, neon_sig: str) -> List[SolNeonIxReceiptInfo]:
        return self._sol_neon_txs_db.get_sol_ix_info_list_by_neon_sig(neon_sig)

    def get_sol_alt_tx_list_by_neon_sig(self, neon_sig: str) -> List[SolAltIxInfo]:
        return self._sol_alt_txs_db.get_alt_ix_list_by_neon_sig(neon_sig)

    def get_stuck_neon_holder_list(self) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        return self._stuck_neon_holders_db.get_holder_list(self._start_slot, self._stop_slot)

    def get_stuck_neon_tx_list(self) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        return self._stuck_neon_txs_db.get_tx_list(True, self._start_slot, self._stop_slot)

    def get_sol_alt_info_list(self) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        return self._sol_alt_infos_db.get_alt_list(self._start_slot, self._stop_slot)
