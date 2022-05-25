from logged_groups import logged_group
import asyncio
from multiprocessing import Process
from typing import Any

from ..common_neon.utils.pickable_data_server import AddrPickableDataSrv, PickableDataServerUser
from ..common_neon.config import IConfig

from .mempool import MemPool
from .executor_mng import MPExecutorMng


@logged_group("neon.MemPool")
class MPService(PickableDataServerUser):

    MP_SERVICE_PORT = 9091
    MP_SERVICE_HOST = "0.0.0.0"
    EXECUTOR_COUNT = 8

    def __init__(self, config: IConfig):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self._mempool_server = None
        self._mempool = None
        self._mp_executor_mng = None
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        self.info("Run until complete")
        self._process.start()

    async def on_data_received(self, data: Any) -> Any:
        return await self._mempool.enqueue_mp_request(data)

    def run(self):
        self._mempool_server = AddrPickableDataSrv(user=self, address=(self.MP_SERVICE_HOST, self.MP_SERVICE_PORT))
        self._mp_executor_mng = MPExecutorMng(self.EXECUTOR_COUNT, self._config)
        self._mempool = MemPool(self._mp_executor_mng)
        self.event_loop.run_forever()
