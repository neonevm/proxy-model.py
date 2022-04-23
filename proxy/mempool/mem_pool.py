import asyncio
import time
from typing import List, Tuple
from logged_groups import logged_group
import bisect
from ..common_neon.config import IConfig

from .mempool_api import ExecTxRequest, ExecTxResultCode, ExecTxResult
from .executor_mng import ExecutorMng


@logged_group("neon.MemPool")
class MemPool:

    EXECUTOR_COUNT = 8
    TX_QUEUE_MAX_SIZE = 5120
    TX_QUEUE_SIZE = 4096
    CHECK_TASK_TIMEOUT_SEC = 0.05

    def __init__(self, config: IConfig):
        self._executor_mng = ExecutorMng(self.EXECUTOR_COUNT, config)
        self._tx_req_queue = []
        self._lock = asyncio.Lock()
        self._tx_req_queue_cond = asyncio.Condition()
        self._processing_tasks: List[Tuple[int, asyncio.Task, ExecTxRequest]] = []
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_tx_queue_task = asyncio.get_event_loop().create_task(self.process_tx_queue())

    async def send_raw_transaction(self, exec_tx_request: ExecTxRequest) -> bool:
        try:
            #self.debug(f"Got tx {exec_tx_request.neon_tx}")
            if len(self._tx_req_queue) > MemPool.TX_QUEUE_MAX_SIZE:
                self._tx_req_queue = self._tx_req_queue[-MemPool.TX_QUEUE_SIZE:]
            bisect.insort_left(self._tx_req_queue, exec_tx_request)
            await self._kick_tx_queue()

        except Exception as err:
            self.error(f"Failed enqueue mempool_tx_request into the worker pool: {err}")
            return False
        return True

    @staticmethod
    def _send_raw_transaction_impl(mempool_tx_request: ExecTxRequest) -> bool:
        print(f"mempool_tx_request: {mempool_tx_request}")
        return True

    async def process_tx_queue(self):
        while True:
            # self.debug("Acquire condition")
            async with self._tx_req_queue_cond:
                # self.debug("Wait for condition")
                await self._tx_req_queue_cond.wait()
                if len(self._tx_req_queue) == 0:
                    # self.debug("Tx queue empty")
                    continue
                if not self._executor_mng.has_available():
                    # self.debug("No available executor")
                    continue
                # self.debug(f"Pop from queue: {len(self._tx_req_queue)}")
                request = self._tx_req_queue.pop()
                # self.debug("Poped request from queue")
                self.fulfill_request(request)

    def fulfill_request(self, request: ExecTxRequest):

        executor_id, executor = self._executor_mng.get_executor()
        self.debug(f"Fulfill request on executor: {executor_id}")
        task = asyncio.get_event_loop().create_task(executor.send_data_async(request))
        self._processing_tasks.append((executor_id, task, request))

    async def check_processing_tasks(self):
        while True:
            not_finished_tasks = []
            for executor_id, task, mp_request in self._processing_tasks:
                if not task.done():
                    not_finished_tasks.append((executor_id, task, mp_request))
                    continue
                exception = task.exception()
                if exception is not None:
                    self.error(f"Exception during processing request: {exception} - tx will be dropped away")
                    self._on_request_dropped_away(mp_request)
                    self._executor_mng.release_executor(executor_id)
                    continue

                result: ExecTxResult = task.result()
                assert isinstance(result, ExecTxResult)
                assert result.result_code != ExecTxResultCode.Dummy
                await self._process_mp_result(executor_id, result, mp_request)

            self._processing_tasks = not_finished_tasks
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)

    async def _process_mp_result(self, executor_id, result, mp_request):
        if result.result_code == ExecTxResultCode.Done:
            self.debug(f"Execution done, request: {mp_request.signature} ")
            self._on_request_done(mp_request)
            self._executor_mng.release_executor(executor_id)
            await self._kick_tx_queue()
        elif result.result_code == ExecTxResultCode.ToBeRepeat:
            self.warning(f"Request will be repeated: {mp_request.signature}")
            self._executor_mng.release_executor(executor_id)
            await self.send_raw_transaction(mp_request)
        elif result.result_code == ExecTxResultCode.NoLiquidity:
            self.warning(f"No liquidity on executor: {executor_id} - will be suspended, request: {mp_request.signature} will be repeated")
            self._executor_mng.on_no_liquidity(executor_id)
            await self.send_raw_transaction(mp_request)

    def _on_request_done(self, tx_request: ExecTxRequest):
        pass

    def _on_request_dropped_away(self, tx_request: ExecTxRequest):
        pass

    async def _kick_tx_queue(self):
        async with self._tx_req_queue_cond:
            # self.debug("Notify queue extended")
            self._tx_req_queue_cond.notify()
