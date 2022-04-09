# from .proxy import entry_point
from .mempool.MemPollService import MemPoolService
# from .statistics_exporter.prometheus_proxy_server import PrometheusProxyServer


class NeonProxyApp:

    def __init__(self):
        self._mem_pool_service = MemPoolService()

    def start(self):
        # PrometheusProxyServer()
        self._mem_pool_service.start()
        # entry_point()

    def __del__(self):
        self._mem_pool_service.finish()
        self._mem_pool_service.join(timeout=5)
