from .proxy import entry_point
from .mempool.mempool_service import MPService
from .statistic.proxy_service import ProxyStatService
from .neon_core_api.neon_core_api_service import NeonCoreApiService
from .common_neon.config import Config
from .common.logger import Logger


class NeonProxyApp:
    def __init__(self):
        Logger.setup()
        self._config = Config()
        self._proxy_stat_service = ProxyStatService(self._config)
        self._mempool_service = MPService(self._config)
        self._neon_core_service = NeonCoreApiService(self._config)

    def start(self) -> None:
        self._neon_core_service.start()
        self._proxy_stat_service.start()
        self._mempool_service.start()
        entry_point()
