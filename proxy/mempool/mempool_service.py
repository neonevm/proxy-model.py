from logged_groups import logged_group
from multiprocessing import Process

from .mempool_server import MemPoolServer, MemPoolServerUser
from .mem_pool import MemPool

from ..common_neon.data import NeonTxData


@logged_group("neon.MemPool")
class MemPoolService(MemPoolServerUser):

    MEMPOOL_SERVICE_PORT = 9091
    MEMPOOL_SERVICE_HOST = "127.0.0.1"

    def __init__(self):
        self._mempool_server = MemPoolServer(user=self, host=self.MEMPOOL_SERVICE_HOST, port=self.MEMPOOL_SERVICE_PORT)
        self._mempool = MemPool()
        self._mempool_proc = Process(target=self.run_mempool)

    def start(self):
        self._mempool_server.start()
        self._mempool_proc.start()

    def on_eth_send_raw_transaction(self, neon_tx_data: NeonTxData):
        self._mempool.on_eth_send_raw_transaction(neon_tx_data)

    def run_mempool(self):
        self._mempool.run()
