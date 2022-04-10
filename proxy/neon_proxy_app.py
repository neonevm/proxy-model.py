from .proxy import entry_point
from .mempool.mempool_service import MemPoolService
from .statistics_exporter.prometheus_proxy_server import PrometheusProxyServer
import multiprocessing as mp


class NeonProxyApp:

    def __init__(self):
        self._mem_pool_process = mp.Process(target=NeonProxyApp.run_mempool_service)

    @staticmethod
    def run_mempool_service():
        MemPoolService().start()

    def start(self):
        PrometheusProxyServer()
        self._mem_pool_process.start()
        entry_point()
