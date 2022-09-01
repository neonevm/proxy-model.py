import time
from logged_groups import logged_group

from .indexer_statistic_service import IndexerStatisticService
from ..common_neon.statistic import StatisticMiddlewareClient
from .indexer import Indexer, IIndexerUser

from ..common_neon.config import Config
from ..common_neon.data import NeonTxStatData


@logged_group("neon.Indexer")
class IndexerApp(IIndexerUser):

    def __init__(self, config: Config):
        self._indexer_stat_service = IndexerStatisticService() if config.GATHER_STATISTICS else None
        time.sleep(1)
        self._stat_middleware = StatisticMiddlewareClient(enabled=config.GATHER_STATISTICS)

        indexer = Indexer(config, self)
        indexer.run()

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        self._stat_middleware.stat_commit_neon_tx_result(tx_stat)

    def on_db_status(self, neon_db_status: bool):
        self._stat_middleware.stat_commit_postgres_availability(neon_db_status)

    def on_solana_rpc_status(self, solana_status: bool):
        self._stat_middleware.stat_commit_solana_rpc_health(solana_status)


@logged_group("neon.Indexer")
def run_indexer(*, logger):
    config = Config()
    logger.info(f"Running indexer with params: {str(config)}")
    IndexerApp(config)


if __name__ == "__main__":
    run_indexer()
