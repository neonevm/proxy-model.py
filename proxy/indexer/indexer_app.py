import logging

from .indexer import Indexer
from ..common_neon.config import Config
from ..statistic.indexer_service import IndexerStatService
from ..common.logger import Logger


LOG = logging.getLogger(__name__)


class IndexerApp:
    def __init__(self, config: Config):
        self._indexer_stat_service = IndexerStatService(config)
        self._indexer_stat_service.start()
        indexer = Indexer(config)
        indexer.run()


def run_indexer():
    config = Config()
    Logger.setup()
    LOG.info(f"Running indexer with params: {str(config)}")
    IndexerApp(config)


if __name__ == "__main__":
    run_indexer()
