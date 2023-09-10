from .data import NeonTxStatData, NeonBlockStatData, NeonDoneBlockStatData
from .middleware import StatClient, stat_method


class IndexerStatClient(StatClient):
    @stat_method
    def commit_neon_tx_result(self, tx_stat: NeonTxStatData): pass

    @stat_method
    def commit_block_stat(self, block_stat: NeonBlockStatData): pass

    @stat_method
    def commit_done_block_stat(self, done_block_stat: NeonDoneBlockStatData): pass
