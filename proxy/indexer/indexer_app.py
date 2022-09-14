from logged_groups import logged_group

from ..common_neon.config import Config
from ..common_neon.environment_data import GATHER_STATISTICS
from ..statistics_exporter.prometheus_indexer_exporter import IndexerStatistics
from ..common_neon.data import NeonTxStatData
from .indexer import Indexer
from .i_indexer_stat_exporter import IIndexerStatExporter


@logged_group("neon.Indexer")
class IndexerApp(IIndexerStatExporter):

    def __init__(self, config: Config):
        self.neon_statistics = IndexerStatistics(GATHER_STATISTICS)
        indexer = Indexer(config, self)
        indexer.run()

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        self.neon_statistics.on_neon_tx_result(tx_stat)

    def on_db_status(self, neon_db_status: bool):
        self.neon_statistics.stat_commit_postgres_availability(neon_db_status)

    def on_solana_rpc_status(self, solana_status: bool):
        self.neon_statistics.stat_commit_solana_rpc_health(solana_status)


@logged_group("neon.Indexer")
def run_indexer(*, logger):
    config = Config()
    logger.info(f"Running indexer with params: {str(config)}")
    IndexerApp(config)


if __name__ == "__main__":
    run_indexer()
