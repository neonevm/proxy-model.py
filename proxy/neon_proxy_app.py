from .proxy import entry_point
from .mempool.mempool_service import MPService

from .proxy_statistic_service import ProxyStatisticService
from .common_neon.config import Config


class NeonProxyApp:

    def __init__(self):
        self._config = Config()
        self._mempool_service = MPService(self._config)
        self._proxy_statistic_service = ProxyStatisticService()

    def start(self):

        self._mempool_service.start()
        entry_point()
