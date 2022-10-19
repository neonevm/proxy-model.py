from .proxy import entry_point
from .mempool.mempool_service import MPService

from .statistics_exporter.prometheus_proxy_server import PrometheusProxyServer
from .common_neon.config import Config


class NeonProxyApp:
    def __init__(self):
        self._config = Config()
        self._mempool_service = MPService(self._config)
        self._prometheus_service = PrometheusProxyServer()

    def start(self):
        self._mempool_service.start()
        self._prometheus_service.start()
        entry_point()
