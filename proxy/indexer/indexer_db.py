from logged_groups import logged_group
from typing import Optional, List

from ..indexer.solana_blocks_db import SolBlocksDB, SolanaBlockInfo
from ..indexer.neon_txs_db import NeonTxsDB
from ..indexer.solana_neon_txs_db import SolNeonTxsDB
from ..indexer.neon_tx_logs_db import NeonTxLogsDB
from ..indexer.solana_tx_costs_db import SolTxCostsDB
from ..indexer.sql_dict import SQLDict
from ..indexer.indexed_objects import NeonIndexedBlockInfo

from ..common_neon.utils import NeonTxReceiptInfo


@logged_group("neon.Indexer")
class IndexerDB:
    def __init__(self):
        self._sol_blocks_db = SolBlocksDB()
        self._sol_tx_costs_db = SolTxCostsDB()
        self._neon_txs_db = NeonTxsDB()
        self._sol_neon_txs_db = SolNeonTxsDB()
        self._neon_tx_logs_db = NeonTxLogsDB()
        self._starting_block = SolanaBlockInfo(slot=0)

        self._constants_db = SQLDict(tablename="constants")
        for k in ['min_receipt_slot', 'latest_slot', 'starting_slot']:
            if k not in self._constants_db:
                self._constants_db[k] = 0

        self._latest_block_slot = self.get_latest_block_slot()

    def status(self) -> bool:
        return self._neon_tx_logs_db.is_connected()

    def submit_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if self.get_starting_block().slot > neon_block.block_slot:
            self._constants_db['starting_slot'] = neon_block.block_slot
            self._starting_block = neon_block.sol_block

        if self._latest_block_slot < neon_block.block_slot:
            self._constants_db['latest_slot'] = neon_block.block_slot
            self._latest_block_slot = neon_block.block_slot

        with self._sol_blocks_db.cursor() as cursor:
            self._sol_blocks_db.set_block(cursor, neon_block.sol_block)
            self._neon_txs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
            self._sol_neon_txs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
            self._neon_tx_logs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
            self._sol_tx_costs_db.set_cost_list(cursor, neon_block.iter_sol_tx_cost())

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._sol_blocks_db.get_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._sol_blocks_db.get_block_by_hash(block_hash)

    def get_latest_block(self) -> SolanaBlockInfo:
        block_slot = self.get_latest_block_slot()
        if block_slot == 0:
            SolanaBlockInfo(slot=0)
        return self.get_block_by_slot(block_slot)

    def get_latest_block_slot(self) -> int:
        return self._constants_db['latest_slot']

    def get_starting_block(self) -> SolanaBlockInfo:
        if self._starting_block.slot != 0:
            return self._starting_block

        block_slot = self._constants_db['starting_slot']
        if block_slot == 0:
            SolanaBlockInfo(slot=0)
        self._starting_block = self.get_block_by_slot(block_slot)
        return self._starting_block

    def get_min_receipt_slot(self) -> int:
        return self._constants_db['min_receipt_slot']

    def set_min_receipt_slot(self, block_slot: int) -> None:
        self._constants_db['min_receipt_slot'] = block_slot

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._neon_tx_logs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_list_by_block_slot(block_slot)

    def get_tx_by_neon_sign(self, neon_sign: str) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_neon_sign(neon_sign)

    def get_sol_sign_list_by_neon_sign(self, neon_sign: str) -> List[str]:
        return self._sol_neon_txs_db.get_sol_sign_list_by_neon_sign(neon_sign)
