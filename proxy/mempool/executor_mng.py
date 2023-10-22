import asyncio
import dataclasses
import socket
import logging

from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, Tuple, Deque, Set

from .mempool_api import MPRequest, MPTask
from .mempool_executor import MPExecutor

from ..common_neon.config import Config
from ..common_neon.pickable_data_server import PipePickableDataClient

from ..statistic.data import NeonExecutorStatData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPExecutorClient(PipePickableDataClient):
    def __init__(self, client_sock: socket.socket):
        PipePickableDataClient.__init__(self, client_sock=client_sock)


class IMPExecutorMngUser(ABC):
    @abstractmethod
    def on_executor_released(self, executor_id: int):
        assert False


class MPExecutorMng:
    @dataclasses.dataclass
    class ExecutorInfo:
        executor: MPExecutor
        client: MPExecutorClient
        id: int

    def __init__(self, config: Config, user: IMPExecutorMngUser, stat_client: ProxyStatClient):
        self._config = config
        self._stat_client = stat_client
        self._available_executor_pool: Deque[int] = deque()
        self._busy_executor_pool: Set[int] = set()
        self._executor_dict: Dict[int, MPExecutorMng.ExecutorInfo] = dict()
        self._stopped_executor_dict: Dict[int, MPExecutorMng.ExecutorInfo] = dict()
        self._user = user
        self._last_id = 0

    async def set_executor_cnt(self, executor_count: int) -> None:
        executor_count = min(max(executor_count + 1, 3), self._config.mempool_executor_limit_cnt)
        diff_count = executor_count - len(self._executor_dict)
        if diff_count > 0:
            return await self._run_executors(diff_count)
        elif diff_count < 0:
            return self._stop_executors(-diff_count)

    async def _run_executors(self, executor_count: int) -> None:
        LOG.info(f"Run executors +{executor_count} => {len(self._executor_dict) + executor_count}")
        for i in range(executor_count):
            executor_id = self._last_id
            self._last_id += 1
            executor_info = self._create_executor(executor_id)
            self._executor_dict[executor_id] = executor_info
            self._available_executor_pool.appendleft(executor_id)
            executor_info.executor.start()
            await executor_info.client.async_init()

        self._commit_stat()

    def _stop_executors(self, executor_count: int) -> None:
        LOG.info(f"Stop executors -{executor_count} => {len(self._executor_dict) - executor_count}")
        while (executor_count > 0) and self._has_available():
            executor_id, _ = self._get_executor()
            LOG.debug(f"Stop executor: {executor_id}")
            executor_info = self._executor_dict.pop(executor_id)
            executor_info.executor.kill()
            executor_count -= 1

        for i in range(executor_count):
            executor_id, executor_info = self._executor_dict.popitem()
            LOG.debug(f"Mark to stop executor: {executor_id}")
            self._stopped_executor_dict[executor_id] = executor_info

        self._commit_stat()

    def submit_mp_request(self, mp_request: MPRequest) -> MPTask:
        executor_id, executor = self._get_executor()
        task = asyncio.get_event_loop().create_task(executor.send_data_async(mp_request))
        return MPTask(executor_id=executor_id, aio_task=task, mp_request=mp_request)

    def is_available(self) -> bool:
        return self._has_available()

    def _has_available(self) -> bool:
        return len(self._available_executor_pool) > 0

    def _get_executor(self) -> Tuple[int, MPExecutorClient]:
        executor_id = self._available_executor_pool.pop()
        # LOG.debug(f"Acquire executor: {executor_id}")
        self._busy_executor_pool.add(executor_id)
        self._commit_stat()

        executor_info = self._executor_dict.get(executor_id, None)
        return executor_id, executor_info.client

    def release_executor(self, executor_id: int):
        self._busy_executor_pool.remove(executor_id)
        if executor_id in self._executor_dict:
            # LOG.debug(f"Release executor: {executor_id}")
            self._available_executor_pool.appendleft(executor_id)
            self._user.on_executor_released(executor_id)
        else:
            LOG.debug(f"Stop executor: {executor_id}")
            executor = self._stopped_executor_dict.pop(executor_id).executor
            executor.kill()

        self._commit_stat()

    def _create_executor(self, executor_id: int) -> ExecutorInfo:
        LOG.debug(f'Create executor: {executor_id}')
        client_sock, srv_sock = socket.socketpair()
        executor = MPExecutor(self._config, executor_id, srv_sock)
        client = MPExecutorClient(client_sock)
        return MPExecutorMng.ExecutorInfo(executor=executor, client=client, id=executor_id)

    def __del__(self):
        for executor_info in self._executor_dict.values():
            executor_info.executor.kill()
        for executor_info in self._stopped_executor_dict.values():
            executor_info.executor.kill()
        self._busy_executor_pool.clear()
        self._available_executor_pool.clear()

    def _commit_stat(self) -> None:
        stat = NeonExecutorStatData(
            total_cnt=len(self._executor_dict),
            free_cnt=len(self._available_executor_pool),
            used_cnt=len(self._busy_executor_pool),
            stopped_cnt=len(self._stopped_executor_dict)
        )
        self._stat_client.commit_executor_stat(stat)
