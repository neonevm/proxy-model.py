from logged_groups import logged_group
from typing import Optional, List

from ..indexer.indexer_db import IndexerDB

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxReceiptInfo
from ..common_neon.solana_interactor import SolanaInteractor

from ..memdb.blocks_db import MemBlocksDB, SolanaBlockInfo
from ..memdb.pending_tx_db import MemPendingTxsDB, NeonPendingTxInfo
from ..memdb.transactions_db import MemTxsDB


@logged_group("neon.Proxy")
class MemDB:
    def __init__(self, solana: SolanaInteractor):
        self._solana = solana
        self._db = IndexerDB()

        self._blocks_db = MemBlocksDB(self._solana, self._db)
        self._txs_db = MemTxsDB(self._db)
        self._pending_tx_db = MemPendingTxsDB(self._db)

    def _before_slot(self) -> int:
        return self._blocks_db.get_db_block_slot() - 5

    def get_latest_block(self) -> SolanaBlockInfo:
        return self._blocks_db.get_latest_block()

    def get_latest_block_slot(self) -> int:
        return self._blocks_db.get_latest_block_slot()

    def get_finalized_block_slot(self) -> int:
        return self._blocks_db.get_finalized_block_slot()

    def get_starting_block_slot(self) -> int:
        return self._blocks_db.get_staring_block_slot()

    def get_starting_block(self) -> SolanaBlockInfo:
        return self._db.get_starting_block()

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_hash(block_hash)

    def pend_transaction(self, tx: NeonPendingTxInfo):
        self._pending_tx_db.pend_transaction(tx, self._before_slot())

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, sign_list: [str]):
        block = self._blocks_db.submit_block(neon_tx, neon_res)
        neon_res.fill_block_info(block)
        self._txs_db.submit_transaction(neon_tx, neon_res, sign_list, self._before_slot())

    def get_tx_list_by_block_slot(self, is_finalized: bool, block_slot: int) -> List[NeonTxReceiptInfo]:
        if is_finalized:
            return self._db.get_tx_list_by_block_slot(block_slot)
        neon_sign_list = self._blocks_db.get_tx_list_by_block_slot(block_slot)
        return self._txs_db.get_tx_list_by_neon_sign_list(neon_sign_list, self._before_slot())

    def get_tx_by_neon_sign(self, neon_sign: str) -> Optional[NeonTxReceiptInfo]:
        before_slot = self._before_slot()
        is_pended_tx = self._pending_tx_db.is_exist(neon_sign, before_slot)
        return self._txs_db.get_tx_by_neon_sign(neon_sign, is_pended_tx, before_slot)

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._txs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_contract_code(self, address: str) -> str:
        return self._db.get_contract_code(address)

    def get_sol_sign_list_by_neon_sign(self, neon_sign: str) -> [str]:
        before_slot = self._before_slot()
        is_pended_tx = self._pending_tx_db.is_exist(neon_sign, before_slot)
        return self._txs_db.get_sol_sign_list_by_neon_sign(neon_sign, is_pended_tx, before_slot)
