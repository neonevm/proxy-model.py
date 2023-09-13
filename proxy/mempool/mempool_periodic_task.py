import abc
import asyncio
import logging
from typing import Optional, TypeVar, Generic

from .mempool_api import MPTask
from .executor_mng import MPExecutorMng
from ..common_neon.utils.json_logger import logging_context


MPPeriodicTaskRequest = TypeVar('MPPeriodicTaskRequest')
MPPeriodicTaskResult = TypeVar('MPPeriodicTaskResult')


LOG = logging.getLogger(__name__)


class MPPeriodicTaskLoop(Generic[MPPeriodicTaskRequest, MPPeriodicTaskResult], abc.ABC):
    _check_sleep_sec = 0.05

    def __init__(self, name: str, sleep_sec: float, executor_mng: MPExecutorMng):
        self._name = name
        self._sleep_sec = sleep_sec
        self._executor_mng = executor_mng
        self._task_idx = 0
        self._task: Optional[MPTask] = None
        self._task_loop = asyncio.get_event_loop().create_task(self._process_task_loop())

    def _generate_req_id(self, name: Optional[str] = None) -> str:
        if name is None:
            name = self._name
        req_id = f'{name}-{self._task_idx}'
        self._task_idx += 1
        return req_id

    def _try_to_submit_request(self) -> None:
        if not self._executor_mng.is_available():
            return
        try:
            self._submit_request()
        except BaseException as exc:
            LOG.error(f'Error during submitting {self._name} to executor.', exc_info=exc)

    @abc.abstractmethod
    def _submit_request(self) -> None:
        pass

    def _submit_request_to_executor(self, mp_request: MPPeriodicTaskRequest):
        assert self._task is None
        with logging_context(req_id=mp_request.req_id):
            self._task = self._executor_mng.submit_mp_request(mp_request)

    @abc.abstractmethod
    async def _process_result(self, mp_request: MPPeriodicTaskRequest, mp_result: MPPeriodicTaskResult) -> None:
        pass

    @abc.abstractmethod
    def _process_error(self, mp_request: MPPeriodicTaskRequest) -> None:
        pass

    @staticmethod
    async def _await_task_done(task: MPTask) -> None:
        while True:
            if not task.aio_task.done():
                await asyncio.sleep(0.1)
            else:
                break

    async def _check_request_status(self) -> None:
        assert self._task is not None
        if not self._task.aio_task.done():
            return

        task = self._task
        self._task = None
        with logging_context(req_id=task.mp_request.req_id):
            try:
                await self._await_task_done(task)
                await self._check_request_status_impl(task)

            except BaseException as exc:
                LOG.error(f'Error during processing {self._name} on mempool.', exc_info=exc)

            finally:
                self._executor_mng.release_executor(task.executor_id)

    async def _check_request_status_impl(self, task: MPTask) -> None:
        exc = task.aio_task.exception()
        if exc is not None:
            LOG.error(f'Error during processing {self._name} on executor.', exc_info=exc)
            self._process_error(task.mp_request)
            return

        mp_result = task.aio_task.result()
        if mp_result is None:
            LOG.error(f'Empty result from the executor')
            self._process_error(task.mp_request)
            return

        await self._process_result(task.mp_request, mp_result)

    async def _process_task_loop(self) -> None:
        self._try_to_submit_request()  # first request
        while True:
            if self._task is not None:
                await asyncio.sleep(self._check_sleep_sec)
                await self._check_request_status()
            else:
                await asyncio.sleep(self._sleep_sec)
                self._try_to_submit_request()
