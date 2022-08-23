import asyncio
import time
import math
import traceback
import abc
from typing import Optional, Any, TypeVar, Generic, cast

from logged_groups import logged_group

from .mempool_api import MPTask, IMPExecutor


MPPeriodicTaskRequest = TypeVar('MPPeriodicTaskRequest')
MPPeriodicTaskResult = TypeVar('MPPeriodicTaskResult')


@logged_group("neon.MemPool")
class MPPeriodicTask(Generic[MPPeriodicTaskRequest, MPPeriodicTaskResult], abc.ABC):
    CHECK_TASK_TIMEOUT_SEC = 0.01

    def __init__(self, name: str, sleep_time: float, executor: IMPExecutor):
        self._name = name
        self._sleep_time = sleep_time
        self._executor = executor
        self._task: Optional[MPTask] = None
        self._task_loop = asyncio.get_event_loop().create_task(self._process_task_loop())

    def _generate_req_id(self) -> str:
        now = time.time()
        now_sec = math.ceil(now)
        now_msec = math.ceil(now * 1000 % 1000)
        return f'{self._name}-{now_sec}.{now_msec}'

    def _error(self, text: str, err: BaseException, extra: Any) -> None:
        err_tb = "".join(traceback.format_tb(err.__traceback__))
        self.error(f"{text}. Error: {err}, Traceback: {err_tb}", extra=extra)

    def _try_to_submit_request(self) -> None:
        if not self._executor.is_available():
            return
        try:
            self._submit_request()
        except Exception as err:
            self._error(f'Error during submitting {self._name} to executor', err, extra=None)

    @abc.abstractmethod
    def _submit_request(self) -> None:
        pass

    def _submit_request_to_executor(self, *args, **kwargs):
        assert self._task is None

        mp_request = MPPeriodicTaskRequest(req_id=self._generate_req_id(), *args, **kwargs)
        resource_id, aio_task = self._executor.submit_mp_request(mp_request)
        self._task = MPTask(resource_id=resource_id, aio_task=aio_task, mp_request=mp_request)

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
        try:
            self._executor.release_resource(task.resource_id)
            mp_request = cast(MPPeriodicTaskRequest, task.mp_request)

            err = task.aio_task.exception()
            if err is not None:
                self._error(f'Error during processing {self._name} on executor', err, extra=mp_request.log_req_id)
                self._process_error(mp_request)
                return

            mp_result = cast(MPPeriodicTaskResult, task.aio_task.result())
            self._process_result(mp_request, mp_result)
        except Exception as err:
            self._error(f'Error during processing {self._name} on mempool', err, extra=task.mp_request.log_req_id)

    async def _process_task_loop(self) -> None:
        self._try_to_submit_request()  # first request
        while True:
            if self._processing_task is not None:
                await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)
                self._check_request_status()
            else:
                await asyncio.sleep(self._sleep_time)
                self._try_to_submit_request()
