from .proxy import entry_point
from .mempool.mempool_service import MPService

from proxy.statistic.proxy_service import ProxyStatService
from .common_neon.config import Config


class NeonProxyApp:
    def __init__(self):
        self._config = Config()
        self._mempool_service = MPService(self._config)
        self._proxy_stat_service = ProxyStatService(self._config)

    def start(self) -> None:
        self._proxy_stat_service.start()
        self._mempool_service.start()
        entry_point()
