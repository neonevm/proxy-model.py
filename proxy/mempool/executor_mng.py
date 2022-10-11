import asyncio
import dataclasses
import socket
from abc import ABC, abstractmethod
from collections import deque
from typing import List, Tuple, Deque, Set

from logged_groups import logged_group, logging_context
from neon_py.network import PipePickableDataClient

from ..common_neon.config import Config

from .mempool_api import MPRequest, IMPExecutor, MPTask
from .mempool_executor import MPExecutor


class MPExecutorClient(PipePickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PipePickableDataClient.__init__(self, client_sock=client_sock)


class IMPExecutorMngUser(ABC):
    @abstractmethod
    def on_executor_released(self, executor_id: int):
        assert False


@logged_group("neon.MemPool")
class MPExecutorMng(IMPExecutor):
    @dataclasses.dataclass
    class ExecutorInfo:
        executor: MPExecutor
        client: MPExecutorClient
        id: int

    def __init__(self, config: Config, user: IMPExecutorMngUser, executor_count: int):
        self.info(f"Initialize executor mng with executor_count: {executor_count}")
        self._available_executor_pool: Deque[int] = deque()
        self._busy_executor_pool: Set[int] = set()
        self._executors: List[MPExecutorMng.ExecutorInfo] = list()
        self._user = user
        for i in range(executor_count):
            executor_info = MPExecutorMng._create_executor(config, i)
            self._executors.append(executor_info)
            self._available_executor_pool.appendleft(i)
            executor_info.executor.start()

    async def async_init(self):
        for ex_info in self._executors:
            await ex_info.client.async_init()

    def submit_mp_request(self, mp_request: MPRequest) -> MPTask:
        with logging_context(req_id=mp_request.req_id):
            executor_id, executor = self._get_executor()
        task = asyncio.get_event_loop().create_task(executor.send_data_async(mp_request))
        return MPTask(executor_id=executor_id, aio_task=task, mp_request=mp_request)

    def is_available(self) -> bool:
        return self._has_available()

    def _has_available(self) -> bool:
        return len(self._available_executor_pool) > 0

    def _get_executor(self) -> Tuple[int, MPExecutorClient]:
        executor_id = self._available_executor_pool.pop()
        self.debug(f"Acquire executor: {executor_id}")
        self._busy_executor_pool.add(executor_id)
        executor_info = self._executors[executor_id]
        return executor_id, executor_info.client

    def release_executor(self, executor_id: int):
        self.debug(f"Release executor: {executor_id}")
        self._busy_executor_pool.remove(executor_id)
        self._available_executor_pool.appendleft(executor_id)
        self._user.on_executor_released(executor_id)

    @staticmethod
    def _create_executor(config: Config, executor_id: int) -> ExecutorInfo:
        client_sock, srv_sock = socket.socketpair()
        executor = MPExecutor(config, executor_id, srv_sock)
        client = MPExecutorClient(client_sock)
        return MPExecutorMng.ExecutorInfo(executor=executor, client=client, id=executor_id)

    def __del__(self):
        for executor_info in self._executors:
            executor_info.executor.kill()
        self._busy_executor_pool.clear()
        self._available_executor_pool.clear()
