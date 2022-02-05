from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient

from ..indexer.indexer_db import IndexerDB

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo

from ..memdb.blocks_db import BlocksDB, SolanaBlockInfo
from ..memdb.pending_tx_db import PendingTxsDB, NeonPendingTxInfo, PendingTxError
from ..memdb.transactions_db import TxsDB


@logged_group("neon.Proxy")
class MemDB:
    def __init__(self, client: SolanaClient):
        self._client = client

        self._db = IndexerDB()
        self._db.set_client(self._client)

        self._blocks_db = BlocksDB(self._client, self._db)
        self._txs_db = TxsDB(self._db)
        self._pending_tx_db = PendingTxsDB(self._db)

    def get_latest_block_height(self) -> int:
        return self._blocks_db.get_latest_block_height()

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._blocks_db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_hash(block_hash)

    def pend_transaction(self, tx: NeonPendingTxInfo):
        self._pending_tx_db.pend_transaction(tx, self._blocks_db.latest_db_block_slot)

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo):
        block = self._blocks_db.get_full_block_by_slot(neon_res.slot)
        self._txs_db.submit_transaction(neon_tx, neon_res, block, self._blocks_db.latest_db_block_slot)

    def get_tx_by_sol_sign(self, sol_sign: str) -> NeonTxFullInfo:
        return self._txs_db.get_tx_by_sol_sign(sol_sign, self._blocks_db.latest_db_block_slot)

    def get_tx_by_neon_sign(self, neon_sign: str) -> NeonTxFullInfo:
        return self._txs_db.get_tx_by_neon_sign(neon_sign, self._blocks_db.latest_db_block_slot)

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._txs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_contract_code(self, address: str) -> str:
        return self._db.get_contract_code(address)
