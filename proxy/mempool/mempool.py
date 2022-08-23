import asyncio
import traceback
from typing import List, Optional, Any, cast

from logged_groups import logged_group
from neon_py.data import Result

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg

from .mempool_api import MPRequest, MPTxExecResult, MPTxExecResultCode, IMPExecutor, MPTask, MPRequestType, MPTxRequest
from .mempool_api import MPPendingTxNonceReq, MPPendingTxByHashReq, MPTxSendResult, MPTxSendResultCode
from .mempool_api import MPGasPriceReq, MPGasPriceResult, MPSenderTxCntReq, MPSenderTxCntResult
from .mempool_schedule import MPTxSchedule
from .mempool_periodic_task import MPPeriodicTask


class MPGasPriceTask(MPPeriodicTask[MPGasPriceReq, MPGasPriceResult]):
    def __init__(self, executor: IMPExecutor):
        super().__init__(name='gas-price', sleep_time=4.0, executor=executor)
        self._gas_price: Optional[MPGasPriceResult] = None

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def _submit_request(self) -> None:
        self._submit_request_to_executor()

    def _process_error(self, mp_request: MPGasPriceReq) -> None:
        pass

    def _process_result(self, mp_request: MPGasPriceReq, mp_result: MPGasPriceResult) -> None:
        self._gas_price = mp_result


class MPSenderTxCntTask(MPPeriodicTask[MPSenderTxCntReq, MPSenderTxCntResult]):
    def __init__(self, executor: IMPExecutor, tx_schedule: MPTxSchedule):
        super().__init__(name='state-tx-cnt', sleep_time=0.4, executor=executor)
        self._tx_schedule = tx_schedule

    def _submit_request(self) -> None:
        paused_sender_list = self._tx_schedule.get_paused_sender_list()
        if len(paused_sender_list) == 0:
            return
        self._submit_request_to_executor(sender_list=paused_sender_list)

    def _process_error(self, mp_request: MPSenderTxCntReq) -> None:
        pass

    def _process_result(self, mp_request: MPSenderTxCntReq, mp_result: MPSenderTxCntResult) -> None:
        if len(mp_result.sender_tx_cnt_list) == 0:
            return
        self._tx_schedule.set_sender_state_tx_cnt_list(mp_result)


@logged_group("neon.MemPool")
class MemPool:
    CHECK_TASK_TIMEOUT_SEC = 0.01
    RESCHEDULE_TIMEOUT_SEC = 0.4

    def __init__(self, executor: IMPExecutor, capacity: int):
        self.info(f"Init mempool schedule with capacity: {capacity}")
        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_task_list: List[MPTask] = []
        self._is_active: bool = True
        self._executor = executor
        self._gas_price_task = MPGasPriceTask(executor)
        self._state_tx_cnt_task = MPSenderTxCntTask(executor, self._tx_schedule)
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_schedule_task = asyncio.get_event_loop().create_task(self.process_tx_schedule())

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price_task.gas_price

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

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        try:
            result: MPTxSendResult = self._tx_schedule.add_tx(tx)
            self.debug(f"Got and scheduled request", extra=tx.log_req_id)
            return result
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Failed to schedule request. Error: {err}. Traceback: {err_tb}", extra=tx.log_req_id)
            return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)
        finally:
            await self._kick_tx_schedule()

    def get_pending_tx_count(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_count(sender_addr)

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_nonce(sender_addr)

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        return self._tx_schedule.get_pending_tx_by_hash(tx_hash)

    def get_gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price_task.gas_price

    async def process_tx_schedule(self):
        while True:
            await self._process_tx_schedule()

    async def _process_tx_schedule(self):
        async with self._schedule_cond:
            await self._schedule_cond.wait()
            await self._schedule_cond.wait_for(self.has_gas_price)
            await self._schedule_cond.wait_for(self.is_active)
            self.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")
            while self._executor.is_available():
                tx: MPTxRequest = self._tx_schedule.acquire_tx_for_execution()
                if tx is None:
                    break
                if tx.gas_price < self._gas_price_task.gas_price.min_gas_price:
                    break

                self.debug(f"Got tx from schedule.", extra=tx.log_req_id)
                try:
                    self._submit_request_to_executor(tx)
                except Exception as err:
                    err_tb = "".join(traceback.format_tb(err.__traceback__))
                    self.error(
                        f"Failed enqueue to execute request. "
                        f"Error: {err}. Traceback: {err_tb}", extra=tx.log_req_id
                    )

    def _submit_request_to_executor(self, mp_request: MPRequest):
        mp_task = self._executor.submit_mp_request(mp_request)
        self._processing_task_list.append(mp_task)

    async def check_processing_tasks(self):
        while True:
            has_processed_result = False
            not_finished_task_list: List[MPTask] = []
            for mp_task in self._processing_task_list:
                if not mp_task.aio_task.done():
                    not_finished_task_list.append(mp_task)
                    continue
                if mp_task.mp_request.type != MPTxRequest:
                    self.error(f"Got unexpected request: {mp_task.mp_request}", extra=mp_task.mp_request.log_req_id)
                    continue

                mp_tx_request = cast(MPTxRequest, mp_task.mp_request)
                has_processed_result = True
                self._executor.release_resource(mp_task.resource_id)

                err = mp_task.aio_task.exception()
                if err is not None:
                    err_tb = "".join(traceback.format_tb(err.__traceback__))
                    self.error(
                        f"Exception during processing request. Error: {err}, Traceback: {err_tb}",
                        extra=mp_tx_request.log_req_id
                    )
                    self._on_fail_tx(mp_tx_request)
                    continue

                mp_result = mp_task.aio_task.result()
                self._process_mp_tx_result(mp_tx_request, mp_result)

            self._processing_task_list = not_finished_task_list
            if has_processed_result:
                await self._kick_tx_schedule()
            await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)

    def _process_mp_tx_result(self, tx: MPTxRequest, mp_result: Any):
        try:
            if not isinstance(mp_result, MPTxExecResult):
                self.error(f'Wrong type as result of tx processing {tx}: {mp_result}', extra=tx.log_req_id)
                return

            mp_tx_result = cast(MPTxExecResult, mp_result)
            log_fn = self.warning if mp_tx_result.code != MPTxExecResultCode.Done else self.debug
            log_fn(f"Got mp tx result: {mp_tx_result}.", extra=tx.log_req_id)

            if isinstance(mp_tx_result.data, NeonTxExecCfg):
                tx.neon_tx_exec_cfg = cast(NeonTxExecCfg, mp_tx_result.data)

            if mp_tx_result.code == MPTxExecResultCode.BlockedAccount:
                self._on_blocked_accounts_result(tx)
            elif mp_tx_result.code == MPTxExecResultCode.SolanaUnavailable:
                self._on_solana_unavailable_result(tx)
            elif mp_tx_result.code == MPTxExecResultCode.Unspecified:
                self._on_fail_tx(tx)
            elif mp_tx_result.code == MPTxExecResultCode.Done:
                self._on_done_tx(tx)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Exception on the result processing. Error: {err}. Traceback: {err_tb}", extra=tx.log_req_id)

    def _on_blocked_accounts_result(self, tx: MPTxRequest):
        self.debug(f"Got blocked account transaction status.", extra=tx.log_req_id)
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    def _on_solana_unavailable_result(self, tx: MPTxRequest):
        self.debug(f"Got solana unavailable status.", extra=tx.log_req_id)
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    async def _reschedule_tx(self, tx: MPTxRequest):
        self.debug(f"Will be rescheduled in: {self.RESCHEDULE_TIMEOUT_SEC} sec.", extra=tx.log_req_id)
        await asyncio.sleep(self.RESCHEDULE_TIMEOUT_SEC)

        try:
            self._tx_schedule.reschedule_tx(tx)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Exception on the result processing. Error: {err}. Traceback: {err_tb}", extra=tx.log_req_id)
            return

        await self._kick_tx_schedule()

    def _on_done_tx(self, tx: MPTxRequest):
        self._tx_schedule.done_tx(tx)
        self.debug(f"Request is done", extra=tx.log_req_id)

    def _on_fail_tx(self, tx: MPTxRequest):
        self._tx_schedule.fail_tx(tx)
        self.error(f"Request is failed - dropped away", extra=tx.log_req_id)

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
        return self._gas_price_task.gas_price is not None
