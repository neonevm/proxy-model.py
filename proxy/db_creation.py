import sys

from ..proxy.common_neon.costs import SQLCost
from ..proxy.indexer.accounts_db import NeonAccountDB
from ..proxy.indexer.airdropper import AirdropReadySet, FailedAttempts
from ..proxy.indexer.blocks_db import SolanaBlocksDB
from ..proxy.indexer.logs_db import LogsDB
from ..proxy.indexer.transactions_db import NeonTxsDB
from ..proxy.indexer.trx_receipts_storage import TrxReceiptsStorage

db_operator_cost = SQLCost()
db_solana_blocks = SolanaBlocksDB()
db_neon_txs = NeonTxsDB()
db_neon_account = NeonAccountDB()
db_airdrop_ready = AirdropReadySet()
db_failed_attempts = FailedAttempts()
db_indexer_logs = LogsDB()
db_transaction_receipts = TrxReceiptsStorage('transaction_receipts')

