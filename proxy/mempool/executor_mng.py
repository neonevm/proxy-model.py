import asyncio
from asyncio import Task
import dataclasses
import socket
from collections import deque
from typing import List, Tuple
from logged_groups import logged_group

from ..common_neon.config import IConfig
from ..common_neon.utils import PipePickableDataClient

from .mempool_api import MemPoolRequest, IMemPoolExecutor
from .mempool_executor import MemPoolExecutor


class MpExecutorClient(PipePickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PipePickableDataClient.__init__(self, client_sock=client_sock)

    async def send_tx_request(self, mempool_tx_request: MemPoolRequest):
        return await self.send_data_async(mempool_tx_request)


@logged_group("neon.MemPool")
class ExecutorMng(IMemPoolExecutor):

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

    def submit_mempool_request(self, mp_reqeust: MemPoolRequest) -> Tuple[int, Task]:
        executor_id, executor = self._get_executor()
        tx_hash = "0x" + mp_reqeust.neon_tx.hash_signed().hex()
        self.debug(f"Tx: {tx_hash} - scheduled on executor: {executor_id}")
        task = asyncio.get_event_loop().create_task(executor.send_data_async(mp_reqeust))
        return executor_id, task

    def is_available(self) -> bool:
        return self._has_available()

    def _has_available(self) -> bool:
        return len(self._available_pool) > 0

    def _get_executor(self) -> Tuple[int, MpExecutorClient]:
        executor_id = self._available_pool.pop()
        self.debug(f"Acquire executor: {executor_id}")
        self._busy_pool.add(executor_id)
        executor_info = self._executors[executor_id]
        return executor_id, executor_info.client

    def on_no_liquidity(self, resource_id: int):
        self.debug(f"No liquidity, executor: {resource_id} - will be unblocked in: {ExecutorMng.BRING_BACK_EXECUTOR_TIMEOUT_SEC} sec")
        asyncio.get_event_loop().create_task(self._release_executor_later(resource_id))

    async def _release_executor_later(self, executor_id: int):
        await asyncio.sleep(ExecutorMng.BRING_BACK_EXECUTOR_TIMEOUT_SEC)
        self.release_resource(executor_id)

    def release_resource(self, resource_id: int):
        self.debug(f"Release executor: {resource_id}")
        self._busy_pool.remove(resource_id)
        self._available_pool.appendleft(resource_id)

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
