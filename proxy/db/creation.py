from logged_groups import logged_group, logging_context

from ..common_neon.costs import SQLCost
from ..indexer.accounts_db import NeonAccountDB
from ..indexer.airdropper import AirdropReadySet, FailedAttempts
from ..indexer.blocks_db import SolanaBlocksDB
from ..indexer.logs_db import LogsDB
from ..indexer.transactions_db import NeonTxsDB
from ..indexer.trx_receipts_storage import TrxReceiptsStorage


@logged_group("neon.dbcreation")
def run_dbcreation(*, logger):
    _db_operator_cost = SQLCost()
    _db_solana_blocks = SolanaBlocksDB()
    _db_neon_txs = NeonTxsDB()
    _db_neon_account = NeonAccountDB()
    _db_airdrop_ready = AirdropReadySet()
    _db_failed_attempts = FailedAttempts()
    _db_indexer_logs = LogsDB()
    _db_transaction_receipts = TrxReceiptsStorage('transaction_receipts')


if __name__ == "__main__":
    db_operator_cost = SQLCost()
    db_solana_blocks = SolanaBlocksDB()
    db_neon_txs = NeonTxsDB()
    db_neon_account = NeonAccountDB()
    db_airdrop_ready = AirdropReadySet()
    db_failed_attempts = FailedAttempts()
    db_indexer_logs = LogsDB()
    db_transaction_receipts = TrxReceiptsStorage('transaction_receipts')
