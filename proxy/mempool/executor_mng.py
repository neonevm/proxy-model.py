import asyncio
import dataclasses
import socket
from collections import deque
from typing import List, Tuple
from logged_groups import logged_group

from ..common_neon.config import IConfig
from ..common_neon.utils import PipePickableDataClient

from .mempool_executor import MemPoolExecutor
from .mempool_api import ExecTxRequest


class MpExecutorClient(PipePickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PipePickableDataClient.__init__(self, client_sock=client_sock)

    async def send_tx_request(self, mempool_tx_request: ExecTxRequest):
        return await self.send_data_async(mempool_tx_request)


@logged_group("neon.MemPool")
class ExecutorMng:

    BRING_BACK_EXECUTOR_TIMEOUT_SEC = 120

    @dataclasses.dataclass
    class ExecutorInfo:
        executor: MemPoolExecutor
        client: MpExecutorClient
        id: int

    def __init__(self, executor_count: int, config: IConfig):
        self.info(f"Initialize executor mng with executor_count: {executor_count}")
        self._available_pool = deque()
        self._busy_pool = set()
        self._executors: List[ExecutorMng.ExecutorInfo] = list()
        for i in range(executor_count):
            executor_info = ExecutorMng._create_executor(i, config)
            self._executors.append(executor_info)
            self._available_pool.appendleft(i)
            executor_info.executor.start()

    def has_available(self) -> bool:
        return len(self._available_pool) > 0

    def get_executor(self) -> Tuple[int, MpExecutorClient]:
        executor_id = self._available_pool.pop()
        self._busy_pool.add(executor_id)
        executor_info = self._executors[executor_id]
        return executor_id, executor_info.client

    def on_no_liquidity(self, executor_id: int):
        asyncio.get_event_loop().create_task(self._release_executor_later(executor_id))

    async def _release_executor_later(self, executor_id: int):
        await asyncio.sleep(ExecutorMng.BRING_BACK_EXECUTOR_TIMEOUT_SEC)
        self.release_executor(executor_id)

    def release_executor(self, executor_id: int):
        self.debug(f"Release executor: {executor_id}")
        self._busy_pool.remove(executor_id)
        self._available_pool.appendleft(executor_id)

    @staticmethod
    def _create_executor(executor_id: int, config: IConfig) -> ExecutorInfo:
        client_sock, srv_sock = socket.socketpair()
        executor = MemPoolExecutor(executor_id, srv_sock, config)
        client = MpExecutorClient(client_sock)
        return ExecutorMng.ExecutorInfo(executor=executor, client=client, id=executor_id)

    def __del__(self):
        for executor_info in self._executors:
            executor_info.executor.kill()
        self._busy_pool.clear()
        self._available_pool.clear()
