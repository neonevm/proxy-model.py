import asyncio
import time
import math
import traceback
from typing import List, Tuple, Optional, Any, cast

from logged_groups import logged_group
from neon_py.data import Result

from ..common_neon.eth_proto import Trx as NeonTx

from .mempool_api import MPRequest, MPResultCode, MPTxResult, IMPExecutor, MPRequestType, MPTxRequest
from .mempool_api import MPPendingTxNonceReq, MPPendingTxByHashReq, MPSendTxResult, MPGasPriceReq, MPGasPriceResult
from .mempool_schedule import MPTxSchedule


@logged_group("neon.MemPool")
class MemPool:

    CHECK_TASK_TIMEOUT_SEC = 0.01
    RESCHEDULE_TIMEOUT_SEC = 0.4
    REQUEST_GAS_PRICE_TIMEOUT_SEC = 4

    def __init__(self, executor: IMPExecutor, capacity: int):
        self.info(f"Init mempool schedule with capacity: {capacity}")
        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_tasks: List[Tuple[int, asyncio.Task, MPRequest]] = []
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_schedule_task = asyncio.get_event_loop().create_task(self.process_tx_schedule())
        self._process_gas_price_task = asyncio.get_event_loop().create_task(self.request_gas_price())
        self._is_active: bool = True
        self._has_gas_price_request: bool = False
        self._gas_price: Optional[MPGasPriceResult] = None
        self._executor = executor

    async def enqueue_mp_request(self, mp_request: MPRequest):
        if mp_request.type == MPRequestType.SendTransaction:
            tx_request = cast(MPTxRequest, mp_request)
            return await self.schedule_mp_tx_request(tx_request)
        elif mp_request.type == MPRequestType.GetLastTxNonce:
            pending_nonce_req = cast(MPPendingTxNonceReq, mp_request)
            return self.get_pending_tx_nonce(pending_nonce_req.sender)
        elif mp_request.type == MPRequestType.GetTxByHash:
            pending_tx_by_hash_req = cast(MPPendingTxByHashReq, mp_request)
            return self.get_pending_tx_by_hash(pending_tx_by_hash_req.tx_hash)

    async def schedule_mp_tx_request(self, mp_request: MPTxRequest) -> MPSendTxResult:
        try:
            result: MPSendTxResult = self._tx_schedule.add_mp_tx_request(mp_request)
            self.debug(f"Got and scheduled request", extra=mp_request.log_req_id)
            return result
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(
                f"Failed to schedule request. Error: {err}. Traceback: {err_tb}", extra=mp_request.log_req_id
            )
            return MPSendTxResult(success=False, last_nonce=None)
        finally:
            await self._kick_tx_schedule()

    def get_pending_tx_count(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_count(sender_addr)

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_nonce(sender_addr)

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        return self._tx_schedule.get_pending_tx_by_hash(tx_hash)

    def get_gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    async def process_tx_schedule(self):
        while True:
            async with self._schedule_cond:
                await self._schedule_cond.wait()
                await self._schedule_cond.wait_for(self.has_gas_price)
                await self._schedule_cond.wait_for(self.is_active)
                self.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")
                while self._executor.is_available():
                    mp_request: MPTxRequest = self._tx_schedule.acquire_tx_for_execution()
                    if mp_request is None:
                        break
                    if mp_request.gas_price < self._gas_price.min_gas_price:
                        break

                    try:
                        self.debug(
                            f"Got mp_tx_request from schedule, left senders in schedule: {self._tx_schedule.len()}",
                            extra=mp_request.log_req_id
                        )
                        self._submit_request_to_executor(mp_request)
                    except Exception as err:
                        err_tb = "".join(traceback.format_tb(err.__traceback__))
                        self.error(
                            f"Failed enqueue to execute request. Error: {err}. Traceback: {err_tb}",
                            extra=mp_request.log_req_id
                        )

    def _submit_gas_price_request(self) -> None:
        if self._has_gas_price_request:
            return
        self._has_gas_price_request = True
        now = math.ceil(time.time())
        mp_req = MPGasPriceReq(req_id=str(now))
        self._submit_request_to_executor(mp_req)

    def process_mp_gas_price_result(self, mp_request: MPRequest, mp_result: Any) -> None:
        self._has_gas_price_request = False
        if mp_result is None:
            return

        if isinstance(mp_result, MPGasPriceResult):
            self._gas_price = cast(MPGasPriceResult, mp_result)
        else:
            self.error(f"Wrong type as result for gas price calculation: {mp_result}", extra=mp_request.log_req_id)

    async def request_gas_price(self) -> None:
        while True:
            if self._executor.is_available():
                self._submit_gas_price_request()
            await asyncio.sleep(self.REQUEST_GAS_PRICE_TIMEOUT_SEC)

    def _submit_request_to_executor(self, mp_request: MPRequest):
        resource_id, task = self._executor.submit_mp_request(mp_request)
        self._processing_tasks.append((resource_id, task, mp_request))

    async def check_processing_tasks(self):
        while True:
            has_processed_result = False
            not_finished_tasks = []
            for resource_id, task, mp_request in self._processing_tasks:
                if not task.done():
                    not_finished_tasks.append((resource_id, task, mp_request))
                    continue
                has_processed_result = True
                self._executor.release_resource(resource_id)
                err = task.exception()
                if err is not None:
                    err_tb = "".join(traceback.format_tb(err.__traceback__))
                    self.error(
                        f"Exception during processing request. Error: {err}, Traceback: {err_tb}",
                        extra=mp_request.log_req_id
                    )
                    if mp_request.type == MPRequestType.SendTransaction:
                        self._on_fail_tx(mp_request)
                    elif mp_request.type == MPRequestType.GetGasPrice:
                        self.process_mp_gas_price_result(mp_request, None)
                    continue

                mp_result = task.result()
                if mp_request.type == MPRequestType.SendTransaction:
                    self._process_mp_tx_result(mp_result, mp_request)
                elif mp_request.type == MPRequestType.GetGasPrice:
                    self.process_mp_gas_price_result(mp_request, mp_result)
                else:
                    self.error(f"Got unexpected request: {mp_request}: {mp_result}", extra=mp_request.log_req_id)

            self._processing_tasks = not_finished_tasks
            if has_processed_result:
                await self._kick_tx_schedule()
            await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)

    def _process_mp_tx_result(self, mp_result: Any, mp_request: MPTxRequest):
        try:
            if not isinstance(mp_result, MPTxResult):
                self.error(
                    f'Wrong type as result of tx processing {mp_request}: {mp_result}',
                    extra=mp_request.log_req_id
                )
                return

            mp_tx_result = cast(MPTxResult, mp_result)
            log_fn = self.warning if mp_tx_result.code != MPResultCode.Done else self.debug
            log_fn(f"Got mp tx result: {mp_tx_result}.", extra=mp_request.log_req_id)

            if mp_tx_result.code == MPResultCode.BlockedAccount:
                self._on_blocked_accounts_result(mp_request, mp_tx_result)
            elif mp_tx_result.code == MPResultCode.SolanaUnavailable:
                self._on_solana_unavailable_result(mp_request, mp_tx_result)
            elif mp_tx_result.code == MPResultCode.Unspecified:
                self._on_fail_tx(mp_request)
            elif mp_tx_result.code == MPResultCode.Done:
                self._on_done_tx(mp_request)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(
                f"Exception during the result processing. Error: {err}. Traceback: {err_tb}",
                extra=mp_request.log_req_id
            )

    def _on_blocked_accounts_result(self, mp_tx_request: MPTxRequest, mp_tx_result: MPTxResult):
        self.debug(f"Got blocked account transaction status: {mp_tx_result.data}. ", extra=mp_tx_request.log_req_id)
        asyncio.get_event_loop().create_task(self._reschedule_tx(mp_tx_request))

    def _on_solana_unavailable_result(self, mp_tx_request: MPTxRequest, mp_tx_result: MPTxResult):
        self.debug(f"Got solana unavailable status: {mp_tx_result.data}. ", extra=mp_tx_request.log_req_id)
        asyncio.get_event_loop().create_task(self._reschedule_tx(mp_tx_request))

    async def _reschedule_tx(self, tx_request: MPTxRequest):
        self.debug(f"Will be rescheduled in: {self.RESCHEDULE_TIMEOUT_SEC} sec.", extra=tx_request.log_req_id)
        await asyncio.sleep(self.RESCHEDULE_TIMEOUT_SEC)
        self._tx_schedule.reschedule_tx(tx_request)
        await self._kick_tx_schedule()

    def _on_done_tx(self, tx_request: MPTxRequest):
        if not self._tx_schedule.done_tx(tx_request):
            return
        self.debug(f"Request is done", extra=tx_request.log_req_id)

    def _on_fail_tx(self, tx_request: MPTxRequest):
        if not self._tx_schedule.fail_tx(tx_request):
            return
        self.error(f"Request is dropped away", extra=tx_request.log_req_id)

    async def _kick_tx_schedule(self):
        async with self._schedule_cond:
            # self.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_resource_got_available(self, resource_id: int):
        asyncio.get_event_loop().create_task(self._kick_tx_schedule())

    def suspend_processing(self) -> Result:
        if not self._is_active:
            self.warning("No need to suspend mempool, already suspended")
            return Result()
        self._is_active = False
        self.info("Transaction processing suspended")
        return Result()

    def resume_processing(self) -> Result:
        if self._is_active:
            self.warning("No need to resume mempool, not suspended")
            return Result()
        self._is_active = True
        self.info("Transaction processing resumed")
        return Result()

    def is_active(self) -> bool:
        return self._is_active

    def has_gas_price(self) -> bool:
        return self._gas_price is not None
