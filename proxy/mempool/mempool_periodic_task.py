import asyncio
import time
import math
import abc
from typing import Optional, TypeVar, Generic

from logged_groups import logged_group, logging_context

from ..mempool.mempool_api import MPTask, IMPExecutor


MPPeriodicTaskRequest = TypeVar('MPPeriodicTaskRequest')
MPPeriodicTaskResult = TypeVar('MPPeriodicTaskResult')


@logged_group("neon.MemPool")
class MPPeriodicTaskLoop(Generic[MPPeriodicTaskRequest, MPPeriodicTaskResult], abc.ABC):
    _check_sleep_time = 0.01

    def __init__(self, name: str, sleep_time: float, executor: IMPExecutor):
        self._name = name
        self._sleep_time = sleep_time
        self._executor = executor
        self._task: Optional[MPTask] = None
        self._task_loop = asyncio.get_event_loop().create_task(self._process_task_loop())

    def _generate_req_id(self, name: Optional[str] = None) -> str:
        now = time.time()
        now_sec = math.ceil(now)
        now_msec = math.ceil(now * 1000 % 1000)
        if name is None:
            name = self._name
        return f'{name}-{now_sec}.{now_msec:03d}'

    def _try_to_submit_request(self) -> None:
        if not self._executor.is_available():
            return
        try:
            self._submit_request()
        except BaseException as exc:
            self.error(f'Error during submitting {self._name} to executor.', exc_info=exc)

    @abc.abstractmethod
    def _submit_request(self) -> None:
        pass

    def _submit_request_to_executor(self, mp_request: MPPeriodicTaskRequest):
        assert self._task is None
        with logging_context(req_id=mp_request.req_id):
            self._task = self._executor.submit_mp_request(mp_request)

    @abc.abstractmethod
    def _process_result(self, mp_request: MPPeriodicTaskRequest, mp_result: MPPeriodicTaskResult) -> None:
        pass

    @abc.abstractmethod
    def _process_error(self, mp_request: MPPeriodicTaskRequest) -> None:
        pass

    def _check_request_status(self) -> None:
        assert self._task is not None
        if not self._task.aio_task.done():
            return

        task = self._task
        self._task = None
        with logging_context(req_id=task.mp_request.req_id):
            try:
                self._check_request_status_impl(task)
            except BaseException as exc:
                self.error(f'Error during processing {self._name} on mempool.', exc_info=exc)

    def _check_request_status_impl(self, task: MPTask) -> None:
        self._executor.release_executor(task.executor_id)

        exc = task.aio_task.exception()
        if exc is not None:
            self.error(f'Error during processing {self._name} on executor.', exc_info=exc)
            self._process_error(task.mp_request)
            return

        mp_result = task.aio_task.result()
        if mp_result is None:
            self.error(f'Empty result from the executor')
            self._process_error(task.mp_request)
            return

        self._process_result(task.mp_request, mp_result)

    async def _process_task_loop(self) -> None:
        self._try_to_submit_request()  # first request
        while True:
            if self._task is not None:
                await asyncio.sleep(self._check_sleep_time)
                self._check_request_status()
            else:
                await asyncio.sleep(self._sleep_time)
                self._try_to_submit_request()
