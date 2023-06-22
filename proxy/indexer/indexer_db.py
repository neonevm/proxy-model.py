from typing import Optional, Iterator, List, Dict, Any, Tuple

from ..common_neon.utils import NeonTxReceiptInfo, SolBlockInfo
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.db.sql_dict import SQLDict
from ..common_neon.config import Config
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptShortInfo, SolTxCostInfo

from .indexed_objects import NeonIndexedBlockInfo
from .neon_tx_logs_db import NeonTxLogsDB
from .neon_txs_db import NeonTxsDB
from .solana_blocks_db import SolBlocksDB
from .solana_neon_txs_db import SolNeonTxsDB
from .solana_tx_costs_db import SolTxCostsDB
from .stuck_neon_holders_db import StuckNeonHoldersDB
from .stuck_neon_txs_db import StuckNeonTxsDB


class IndexerDB:
    def __init__(self, config: Config):
        self._db = DBConnection(config)
        self._sol_blocks_db = SolBlocksDB(self._db)
        self._sol_tx_costs_db = SolTxCostsDB(self._db)
        self._neon_txs_db = NeonTxsDB(self._db)
        self._sol_neon_txs_db = SolNeonTxsDB(self._db)
        self._neon_tx_logs_db = NeonTxLogsDB(self._db)
        self._stuck_neon_holders_db = StuckNeonHoldersDB(self._db)
        self._stuck_neon_txs_db = StuckNeonTxsDB(self._db)

        self._db_table_list = [
            self._sol_blocks_db,
            self._sol_tx_costs_db,
            self._neon_txs_db,
            self._sol_neon_txs_db,
            self._neon_tx_logs_db,
        ]

        self._constants_db = SQLDict(self._db, table_name='constants')
        for k in ['min_receipt_block_slot', 'latest_block_slot', 'starting_block_slot', 'finalized_block_slot']:
            if k not in self._constants_db:
                self._constants_db[k] = 0

        self._starting_block = SolBlockInfo(block_slot=0)
        self._latest_block_slot = self.get_latest_block_slot()
        self._finalized_block_slot = self.get_finalized_block_slot()
        self._min_receipt_block_slot = self.get_min_receipt_block_slot()

    @property
    def db_connection(self) -> DBConnection:
        return self._db

    def is_healthy(self) -> bool:
        return self._db.is_connected()

    def submit_block(self, neon_block: NeonIndexedBlockInfo,
                     iter_active_neon_block: Optional[Iterator[NeonIndexedBlockInfo]]) -> None:
        self._db.run_tx(
            lambda: self._submit_block(neon_block, iter_active_neon_block)
        )

    def finalize_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        self._db.run_tx(
            lambda: self._finalize_block(neon_block)
        )

    def _submit_block(self, neon_block: NeonIndexedBlockInfo,
                      iter_active_neon_block: Optional[Iterator[NeonIndexedBlockInfo]]) -> None:
        self._sol_blocks_db.set_block(neon_block.sol_block)
        if neon_block.is_finalized:
            self._finalize_block(neon_block)
        elif iter_active_neon_block:
            self._activate_block_list(iter_active_neon_block)
            self._stuck_neon_txs_db.set_tx_list(False, neon_block.block_slot, neon_block.iter_stuck_neon_tx())

        self._neon_txs_db.set_tx_list(neon_block.iter_done_neon_tx())
        self._neon_tx_logs_db.set_tx_list(neon_block.iter_done_neon_tx())
        self._sol_neon_txs_db.set_tx_list(neon_block.iter_sol_neon_ix())
        self._sol_tx_costs_db.set_cost_list(neon_block.iter_sol_tx_cost())

        if self.get_starting_block().block_slot == 0:
            self._constants_db['starting_block_slot'] = neon_block.block_slot

    def _finalize_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        block_slot_list = [neon_block.block_slot]
        for db_table in self._db_table_list:
            db_table.finalize_block_list(self._finalized_block_slot, block_slot_list)

        self._stuck_neon_holders_db.set_holder_list(neon_block.stuck_block_slot, neon_block.iter_stuck_neon_holder())
        self._stuck_neon_txs_db.set_tx_list(True, neon_block.stuck_block_slot, neon_block.iter_stuck_neon_tx())

        self._finalized_block_slot = neon_block.block_slot
        self._constants_db['finalized_block_slot'] = neon_block.block_slot
        self._set_latest_block_slot(neon_block.block_slot)

    def _set_latest_block_slot(self, block_slot: int) -> None:
        if self._latest_block_slot > block_slot:
            return
        self._latest_block_slot = block_slot
        self._constants_db['latest_block_slot'] = block_slot

    def _activate_block_list(self, iter_neon_block: Iterator[NeonIndexedBlockInfo]) -> None:
        block_slot_list = [b.block_slot for b in iter_neon_block if not b.is_finalized]
        if not len(block_slot_list):
            return

        self._sol_blocks_db.activate_block_list(self._finalized_block_slot, block_slot_list)
        self._set_latest_block_slot(block_slot_list[-1])

    def get_block_by_slot(self, block_slot: int) -> SolBlockInfo:
        return self._sol_blocks_db.get_block_by_slot(block_slot, self.get_latest_block_slot())

    def get_block_by_hash(self, block_hash: str) -> SolBlockInfo:
        return self._sol_blocks_db.get_block_by_hash(block_hash, self.get_latest_block_slot())

    def get_latest_block(self) -> SolBlockInfo:
        block_slot = self.get_latest_block_slot()
        if block_slot == 0:
            return SolBlockInfo(block_slot=0)
        return self.get_block_by_slot(block_slot)

    def get_latest_block_slot(self) -> int:
        return self._constants_db['latest_block_slot']

    def get_finalized_block_slot(self) -> int:
        return self._constants_db['finalized_block_slot']

    def get_finalized_block(self) -> SolBlockInfo:
        block_slot = self.get_finalized_block_slot()
        if block_slot == 0:
            return SolBlockInfo(block_slot=0)
        return self.get_block_by_slot(block_slot)

    def get_starting_block(self) -> SolBlockInfo:
        if self._starting_block.block_slot != 0:
            return self._starting_block

        block_slot = self._constants_db['starting_block_slot']
        if block_slot == 0:
            return SolBlockInfo(block_slot=0)
        self._starting_block = self.get_block_by_slot(block_slot)
        return self._starting_block

    def get_starting_block_slot(self) -> int:
        return self.get_starting_block().block_slot

    def get_min_receipt_block_slot(self) -> int:
        return self._constants_db['min_receipt_block_slot']

    def set_min_receipt_block_slot(self, block_slot: int) -> None:
        if self._min_receipt_block_slot >= block_slot:
            return

        self._min_receipt_block_slot = block_slot
        self._constants_db['min_receipt_block_slot'] = block_slot

    def get_log_list(self, from_block: Optional[int], to_block: Optional[int],
                     address_list: List[str], topic_list: List[List[str]]) -> List[Dict[str, Any]]:
        return self._neon_tx_logs_db.get_log_list(from_block, to_block, address_list, topic_list)

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_list_by_block_slot(block_slot)

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_neon_sig(neon_sig)

    def get_tx_by_block_slot_tx_idx(self, block_slot: int, tx_idx: int) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_block_slot_tx_idx(block_slot, tx_idx)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        return self._sol_neon_txs_db.get_sol_sig_list_by_neon_sig(neon_sig)

    def get_sol_ix_info_list_by_neon_sig(self, neon_sig: str) -> List[SolNeonIxReceiptShortInfo]:
        return self._sol_neon_txs_db.get_sol_ix_info_list_by_neon_sig(neon_sig)

    def get_cost_list_by_sol_sig_list(self, sol_sig_list: List[str]) -> List[SolTxCostInfo]:
        return self._sol_tx_costs_db.get_cost_list_by_sol_sig_list(sol_sig_list)

    def get_stuck_neon_holder_list(self, block_slot: int) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        return self._stuck_neon_holders_db.get_holder_list(block_slot)

    def get_stuck_neon_tx_list(self, is_finalized: bool, block_slot: int) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        return self._stuck_neon_txs_db.get_tx_list(is_finalized, block_slot)
