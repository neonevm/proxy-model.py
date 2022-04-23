from logged_groups import logged_group
import asyncio
from multiprocessing import Process

from ..common_neon.utils.pickable_data_server import AddrPickableDataSrv, PickableDataServerUser
from ..common_neon.config import IConfig

from .mem_pool import MemPool

from typing import Any


@logged_group("neon.MemPool")
class MemPoolService(PickableDataServerUser):

    MEMPOOL_SERVICE_PORT = 9091
    MEMPOOL_SERVICE_HOST = "0.0.0.0"

    def __init__(self, config: IConfig):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self._mempool_server = None
        self._mempool = None
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        self.info("Run until complete")
        self._process.start()

    async def on_data_received(self, data: Any) -> Any:
        return await self._mempool.send_raw_transaction(data)

    def run(self):
        self._mempool_server = AddrPickableDataSrv(user=self, address=(self.MEMPOOL_SERVICE_HOST, self.MEMPOOL_SERVICE_PORT))
        self._mempool = MemPool(self._config)
        self.event_loop.run_forever()
