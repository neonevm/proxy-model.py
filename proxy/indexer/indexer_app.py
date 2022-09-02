import time
from logged_groups import logged_group

from ..common_neon.statistic import StatisticMiddlewareClient
from ..common_neon.environment_data import EVM_LOADER_ID, SOLANA_URL, GATHER_STATISTICS
from ..common_neon.data import NeonTxStatData

from .indexer_statistic_service import IndexerStatisticService
from .indexer import Indexer, IIndexerUser


@logged_group("neon.Indexer")
class IndexerApp(IIndexerUser):

    def __init__(self, solana_url: str):
        self._indexer_stat_service = IndexerStatisticService() if GATHER_STATISTICS else None
        time.sleep(1)
        self._stat_middleware = StatisticMiddlewareClient(enabled=GATHER_STATISTICS)

        indexer = Indexer(solana_url, self)
        indexer.run()

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        self._stat_middleware.stat_commit_neon_tx_result(tx_stat)

    def on_db_status(self, neon_db_status: bool):
        self._stat_middleware.stat_commit_postgres_availability(neon_db_status)

    def on_solana_rpc_status(self, solana_status: bool):
        self._stat_middleware.stat_commit_solana_rpc_health(solana_status)


@logged_group("neon.Indexer")
def run_indexer(solana_url, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {EVM_LOADER_ID}""")

    IndexerApp(solana_url)


if __name__ == "__main__":
    solana_url = SOLANA_URL
    run_indexer(solana_url)
