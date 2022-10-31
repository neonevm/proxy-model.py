import time

from logged_groups import logged_group

from .indexer import Indexer
from ..common_neon.config import Config
from ..statistic import IndexerStatService


@logged_group("neon.Indexer")
class IndexerApp:
    def __init__(self, config: Config):
        self._indexer_stat_service = IndexerStatService(config)
        self._indexer_stat_service.start()
        indexer = Indexer(config)
        indexer.run()


@logged_group("neon.Indexer")
def run_indexer(*, logger):
    config = Config()
    logger.info(f"Running indexer with params: {str(config)}")
    IndexerApp(config)


if __name__ == "__main__":
    run_indexer()
