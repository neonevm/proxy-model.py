from logged_groups import logged_group
import asyncio
from multiprocessing import Process

from .pickable_data_server import PickableDataServer, PickableDataServerUser
from .mem_pool import MemPool

from typing import Any


@logged_group("neon.MemPool")
class MemPoolService(PickableDataServerUser):

    MEMPOOL_SERVICE_PORT = 9091
    MEMPOOL_SERVICE_HOST = "0.0.0.0"

    def __init__(self):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self._mempool_server = None
        self._mempool = None
        self._process = Process(target=self.run)

    def start(self):
        self.info("Run until complete")
        self._process.start()

    def on_data_received(self, data: Any):
        self._mempool.on_eth_send_raw_transaction(data)

    def run(self):
        self._mempool_server = PickableDataServer(user=self, host=self.MEMPOOL_SERVICE_HOST, port=self.MEMPOOL_SERVICE_PORT)
        self._mempool = MemPool()
        self.event_loop.run_until_complete(self._mempool_server.run_server())
