import asyncio
from typing import List, Tuple, Dict
from logged_groups import logged_group

from .mempool_api import MPRequest, MPResultCode, MPTxResult, IMPExecutor, MPRequestType, MPTxRequest,\
                         MPPendingTxCountReq
from .mempool_schedule import MPTxSchedule


@logged_group("neon.MemPool")
class MemPool:

    TX_QUEUE_MAX_SIZE = 4096
    TX_QUEUE_SIZE = 4095
    CHECK_TASK_TIMEOUT_SEC = 0.01

    def __init__(self, executor: IMPExecutor):
        self._tx_schedule = MPTxSchedule()
        self._req_queue_cond = asyncio.Condition()
        self._processing_tasks: List[Tuple[int, asyncio.Task, MPRequest]] = []
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_tx_queue_task = asyncio.get_event_loop().create_task(self.process_tx_queue())

        self._executor = executor

    async def enqueue_mp_request(self, mp_request: MPRequest):
        if mp_request.type == MPRequestType.SendTransaction:
            tx_request: MPTxRequest = mp_request
            return await self._on_send_tx_request(tx_request)
        elif mp_request.type == MPRequestType.GetTrxCount:
            pending_count_req: MPPendingTxCountReq = mp_request
            return self.get_pending_trx_count(pending_count_req.sender)

    async def _on_send_tx_request(self, mp_request: MPTxRequest):
        await self.enqueue_mp_transaction(mp_request)
        sender = mp_request.sender_address
        count = self.get_pending_trx_count(sender)
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        self.debug(f"On send tx request processed: {mp_request.log_str}, pending tx count: {count}", extra=log_ctx)

    async def enqueue_mp_transaction(self, mp_request: MPTxRequest):
        tx_hash = mp_request.neon_tx.hash_signed().hex()
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        try:
            self.debug(f"Got mp_tx_request: {mp_request.log_str} to be scheduled on the mempool", extra=log_ctx)
            self._tx_schedule.add_tx(mp_request)
            await self._kick_tx_queue()
        except Exception as err:
            self.error(f"Failed enqueue tx: {tx_hash} into queue: {err}", extra=log_ctx)

    def get_pending_trx_count(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_trx_count(sender_addr)

    async def process_tx_queue(self):
        while True:
            async with self._req_queue_cond:
                await self._req_queue_cond.wait()
                if not self._executor.is_available():
                    self.debug("No way to process tx - no available executor")
                    continue
                mp_request: MPRequest = self._tx_schedule.get_tx_for_execution()
                if mp_request is not None:
                    self.submit_request_to_executor(mp_request)

    def submit_request_to_executor(self, mp_tx_request: MPRequest):
        resource_id, task = self._executor.submit_mp_request(mp_tx_request)
        self._processing_tasks.append((resource_id, task, mp_tx_request))

    async def check_processing_tasks(self):
        while True:
            not_finished_tasks = []
            for resource_id, task, mp_request in self._processing_tasks:
                if not task.done():
                    not_finished_tasks.append((resource_id, task, mp_request))
                    #  self._executor.release_resource(resource_id) # seems like a bug bug check it again
                    continue
                exception = task.exception()
                if exception is not None:
                    log_ctx = {"context": {"req_id": mp_request.req_id}}
                    self.error(f"Exception during processing request: {exception} - tx will be dropped away", extra=log_ctx)
                    self._on_request_dropped_away(mp_request)
                    self._executor.release_resource(resource_id)
                    continue

                mp_tx_result: MPTxResult = task.result()
                assert isinstance(mp_tx_result, MPTxResult)
                assert mp_tx_result.code != MPResultCode.Dummy
                await self._process_mp_result(resource_id, mp_tx_result, mp_request)

            self._processing_tasks = not_finished_tasks
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)

    async def _process_mp_result(self, resource_id: int, mp_tx_result: MPTxResult, mp_request: MPTxRequest):

        if mp_tx_result.code == MPResultCode.BlockedAccount:
            self._executor.release_resource(resource_id)
            await self.enqueue_mp_request(mp_request)
        elif mp_tx_result.code == MPResultCode.NoLiquidity:
            self._executor.on_no_liquidity(resource_id)
            await self.enqueue_mp_request(mp_request)
        elif mp_tx_result.code == MPResultCode.Unspecified:
            self._executor.release_resource(resource_id)
            self._on_request_dropped_away(mp_request)
        elif mp_tx_result.code == MPResultCode.Done:
            self._on_request_done(mp_request)
            self._executor.release_resource(resource_id)
        log_fn = self.warning if mp_tx_result.code != MPResultCode.Done else self.debug
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        log_fn(f"On mp tx result:  {mp_tx_result} - of: {mp_request.log_str}", extra=log_ctx)
        await self._kick_tx_queue()

    def _on_request_done(self, tx_request: MPTxRequest):
        sender = tx_request.sender_address
        self._tx_schedule.done(sender, tx_request.nonce)

        count = self.get_pending_trx_count(sender)
        log_ctx = {"context": {"req_id": tx_request.req_id}}
        self.debug(f"Reqeust done, pending tx count: {count}", extra=log_ctx)

    def _on_request_dropped_away(self, tx_request: MPTxRequest):
        sender = "0x" + tx_request.neon_tx.sender()
        count = self.get_pending_trx_count(sender)
        log_ctx = {"context": {"req_id": tx_request.req_id}}
        self.debug(f"Reqeust dropped away, pending tx count: {count}", extra=log_ctx)

    async def _kick_tx_queue(self):
        async with self._req_queue_cond:
            self._req_queue_cond.notify()
