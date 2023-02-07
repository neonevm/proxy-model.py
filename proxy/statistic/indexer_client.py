from .data import NeonTxStatData, NeonBlockStatData
from .middleware import StatClient, stat_method


class IndexerStatClient(StatClient):
    @stat_method
    def commit_db_health(self, status: bool): pass

    @stat_method
    def commit_solana_rpc_health(self, status: bool): pass

    @stat_method
    def commit_neon_tx_result(self, tx_stat: NeonTxStatData): pass

    @stat_method
    def commit_block_stat(self, block_stat: NeonBlockStatData): pass
