import asyncio
from typing import List, Tuple, Dict
from logged_groups import logged_group
import bisect

from .mempool_api import MemPoolRequest, MemPoolResultCode, MemPoolResult, IMemPoolExecutor, MemPoolReqType, \
                         MemPoolTxRequest, MemPoolPendingTxCountReq


@logged_group("neon.MemPool")
class MemPool:

    TX_QUEUE_MAX_SIZE = 4096
    TX_QUEUE_SIZE = 4095
    CHECK_TASK_TIMEOUT_SEC = 0.05

    def __init__(self, executor: IMemPoolExecutor):
        self._req_queue = []
        self._lock = asyncio.Lock()
        self._req_queue_cond = asyncio.Condition()
        self._processing_tasks: List[Tuple[int, asyncio.Task, MemPoolRequest]] = []
        # signer -> pending_tx_counter
        self._pending_trx_counters: Dict[str, int] = {}
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_tx_queue_task = asyncio.get_event_loop().create_task(self.process_tx_queue())

        self._executor = executor

    async def enqueue_mp_request(self, mp_request: MemPoolRequest):
        if mp_request.type == MemPoolReqType.SendTransaction:
            tx_request: MemPoolTxRequest = mp_request
            return await self.on_send_tx_request(tx_request)
        elif mp_request.type == MemPoolReqType.GetTrxCount:
            pending_count_req: MemPoolPendingTxCountReq = mp_request
            return self.get_pending_trx_count(pending_count_req.sender)

    async def on_send_tx_request(self, mp_request: MemPoolTxRequest):
        await self.enqueue_mp_transaction(mp_request)
        sender = mp_request.neon_tx.sender()
        self._inc_pending_tx_counter(sender)
        sender = mp_request.neon_tx.sender()
        count = self.get_pending_trx_count(sender)
        self.debug(f"On send tx request. Sender: {sender}, , pending tx count: {count}")

    async def enqueue_mp_transaction(self, mp_request: MemPoolTxRequest):
        tx_hash = mp_request.neon_tx.hash_signed().hex()
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        try:
            self.debug(f"Got mp_tx_request: 0x{tx_hash} to be scheduled on the mempool", extra=log_ctx)
            if len(self._req_queue) > MemPool.TX_QUEUE_MAX_SIZE:
                self._req_queue = self._req_queue[-MemPool.TX_QUEUE_SIZE:]
            bisect.insort_left(self._req_queue, mp_request)
            await self._kick_tx_queue()
        except Exception as err:
            self.error(f"Failed enqueue tx: {tx_hash} into queue: {err}", extra=log_ctx)

    def get_pending_trx_count(self, sender: str):
        return self._pending_trx_counters.get(sender, 0)

    async def process_tx_queue(self):
        while True:
            async with self._req_queue_cond:
                await self._req_queue_cond.wait()
                if len(self._req_queue) == 0:
                    self.debug("Tx queue empty - continue waiting for new")
                    continue
                if not self._executor.is_available():
                    self.debug("No way to process tx - no available executor")
                    continue
                mp_request: MemPoolRequest = self._req_queue.pop()
                self.submit_request_to_executor(mp_request)

    def submit_request_to_executor(self, mp_tx_request: MemPoolRequest):
        resource_id, task = self._executor.submit_mempool_request(mp_tx_request)
        self._processing_tasks.append((resource_id, task, mp_tx_request))

    async def check_processing_tasks(self):
        while True:
            not_finished_tasks = []
            for resource_id, task, mp_request in self._processing_tasks:
                if not task.done():
                    not_finished_tasks.append((resource_id, task, mp_request))
                    self._executor.release_resource(resource_id)
                    continue
                exception = task.exception()
                if exception is not None:
                    self.error(f"Exception during processing request: {exception} - tx will be dropped away")
                    self._on_request_dropped_away(mp_request)
                    self._executor.release_resource(resource_id)
                    continue

                mp_result: MemPoolResult = task.result()
                assert isinstance(mp_result, MemPoolResult)
                assert mp_result.code != MemPoolResultCode.Dummy
                await self._process_mp_result(resource_id, mp_result, mp_request)

            self._processing_tasks = not_finished_tasks
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)

    async def _process_mp_result(self, resource_id: int, mp_result: MemPoolResult, mp_request: MemPoolTxRequest):
        tx_hash = "0x" + mp_request.neon_tx.hash_signed().hex()
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        if mp_result.code == MemPoolResultCode.Done:
            self.debug(f"Neon tx: {tx_hash} - processed on executor: {resource_id} - done", extra=log_ctx)
            self._on_request_done(mp_request)
            self._executor.release_resource(resource_id)
            await self._kick_tx_queue()
            return
        self.warning(f"Failed to process tx: {tx_hash} - on executor: {resource_id}, status: {mp_result} - reschedule", extra=log_ctx)
        if mp_result.code == MemPoolResultCode.BlockedAccount:
            self._executor.release_resource(resource_id)
            await self.enqueue_mp_request(mp_request)
            await self._kick_tx_queue()
        elif mp_result.code == MemPoolResultCode.NoLiquidity:
            self._executor.on_no_liquidity(resource_id)
            await self.enqueue_mp_request(mp_request)
            await self._kick_tx_queue()
        elif mp_result.code == MemPoolResultCode.Unspecified:
            self._executor.release_resource(resource_id)
            self._on_request_dropped_away(mp_request)
            await self._kick_tx_queue()

    def _on_request_done(self, tx_request: MemPoolTxRequest):
        sender = tx_request.neon_tx.sender()
        self._dec_pending_tx_counter(sender)
        count = self.get_pending_trx_count(sender)
        self.debug(f"Reqeust done. Sender: {sender}, pending tx count: {count}")

    def _on_request_dropped_away(self, tx_request: MemPoolTxRequest):
        sender = tx_request.neon_tx.sender()
        self._dec_pending_tx_counter(sender)
        count = self.get_pending_trx_count(sender)
        self.debug(f"Reqeust dropped away. Sender: {sender}, pending tx count: {count}")

    def _inc_pending_tx_counter(self, sender: str):
        counts = self._pending_trx_counters.get(sender, 0)
        self._pending_trx_counters.update({sender: counts + 1})

    def _dec_pending_tx_counter(self, sender: str):
        count = self._pending_trx_counters.get(sender, 0)
        assert count > 0
        count = count - 1
        if count == 0:
            del self._pending_trx_counters[sender]
        self._pending_trx_counters.update({sender: count})

    async def _kick_tx_queue(self):
        async with self._req_queue_cond:
            self._req_queue_cond.notify()
