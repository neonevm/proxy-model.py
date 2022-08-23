import asyncio
import traceback
from typing import List, Optional, Any, cast

from logged_groups import logged_group, logging_context
from neon_py.data import Result

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg

from .mempool_api import MPRequest, MPTxExecResult, MPTxExecResultCode, IMPExecutor, MPTask, MPRequestType, MPTxRequest
from .mempool_api import MPTxSendResult, MPTxSendResultCode
from .mempool_api import MPGasPriceRequest, MPGasPriceResult, MPSenderTxCntRequest, MPSenderTxCntResult
from .mempool_schedule import MPTxSchedule
from .mempool_periodic_task import MPPeriodicTask


class MPGasPriceTask(MPPeriodicTask[MPGasPriceRequest, MPGasPriceResult]):
    def __init__(self, executor: IMPExecutor):
        super().__init__(name='gas-price', sleep_time=4.0, executor=executor)
        self._gas_price: Optional[MPGasPriceResult] = None

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def _submit_request(self) -> None:
        mp_request = MPGasPriceRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_request)

    def _process_error(self, mp_request: MPGasPriceRequest) -> None:
        pass

    def _process_result(self, mp_request: MPGasPriceRequest, mp_result: MPGasPriceResult) -> None:
        self._gas_price = mp_result


class MPSenderTxCntTask(MPPeriodicTask[MPSenderTxCntRequest, MPSenderTxCntResult]):
    def __init__(self, executor: IMPExecutor, tx_schedule: MPTxSchedule):
        super().__init__(name='state-tx-cnt', sleep_time=0.4, executor=executor)
        self._tx_schedule = tx_schedule

    def _submit_request(self) -> None:
        paused_sender_list = self._tx_schedule.get_paused_sender_list()
        if len(paused_sender_list) == 0:
            return

        mp_request = MPSenderTxCntRequest(req_id=self._generate_req_id(), sender_list=paused_sender_list)
        self._submit_request_to_executor(mp_request)

    def _process_error(self, mp_request: MPSenderTxCntRequest) -> None:
        pass

    def _process_result(self, mp_request: MPSenderTxCntRequest, mp_result: MPSenderTxCntResult) -> None:
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
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self._check_processing_task_list_loop())
        self._process_schedule_task = asyncio.get_event_loop().create_task(self._process_tx_schedule_loop())

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price_task.gas_price

    async def enqueue_mp_request(self, mp_request: MPRequest):
        assert mp_request.type == MPRequestType.SendTransaction, f'Wrong request type {mp_request}'

        tx_request = cast(MPTxRequest, mp_request)
        return await self.schedule_mp_tx_request(tx_request)

    def _error(self, text: str, err: BaseException) -> None:
        err_tb = "".join(traceback.format_tb(err.__traceback__))
        self.error(f"{text}. Error: {err}. Traceback: {err_tb}")

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        with logging_context(req_id=tx.req_id):
            try:
                result: MPTxSendResult = self._tx_schedule.add_tx(tx)
                self.debug(f"Got tx {tx.signature} and scheduled request")
                return result
            except Exception as err:
                self._error(f"Failed to schedule tx {tx.signature}", err)
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

    def _enqueue_tx_request(self) -> bool:
        try:
            tx: MPTxRequest = self._tx_schedule.acquire_tx_for_execution(self.gas_price.min_gas_price)
            if tx is None:
                return False
        except Exception as err:
            self._error(f'Failed to get tx for execution', err)
            return False

        with logging_context(req_id=tx.req_id):
            try:
                self.debug(f"Got tx {tx.signature} from schedule.")
                mp_task = self._executor.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return True
            except Exception as err:
                self._error(f'Failed to enqueue to execute {tx.signature}', err)
                return False

    async def _process_tx_schedule_loop(self):
        async with self._schedule_cond:
            await self._schedule_cond.wait_for(self.has_gas_price)

        while True:
            async with self._schedule_cond:
                await self._schedule_cond.wait()
                await self._schedule_cond.wait_for(self.is_active)
                # self.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")
                while self._executor.is_available():
                    if not self._enqueue_tx_request():
                        break

    async def _check_processing_task_list_loop(self):
        while True:
            has_processed_task = False
            not_finished_task_list: List[MPTask] = []
            for mp_task in self._processing_task_list:
                with logging_context(req_id=mp_task.mp_request.req_id):
                    if not self._complete_task(mp_task):
                        not_finished_task_list.append(mp_task)
                    else:
                        has_processed_task = True

            self._processing_task_list = not_finished_task_list
            if has_processed_task:
                await self._kick_tx_schedule()
            await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)

    def _complete_task(self, mp_task: MPTask) -> bool:
        try:
            if not mp_task.aio_task.done():
                return False
            self._executor.release_resource(mp_task.resource_id)

            if mp_task.mp_request.type != MPRequestType.SendTransaction:
                self.error(f"Got unexpected request: {mp_task.mp_request}")
                return True  # skip task
            tx = cast(MPTxRequest, mp_task.mp_request)
        except Exception as err:
            self._error(f"Exception on checking type of request.", err)
            return True

        try:
            err = mp_task.aio_task.exception()
            if err is not None:
                self._error(f'Exception during processing tx {tx.signature} on executor', err)
                self._on_fail_tx(tx)
                return True

            mp_result = mp_task.aio_task.result()
            self._process_mp_tx_result(tx, mp_result)
        except Exception as err:
            self._error(f"Exception on the result processing of tx {tx.signature}", err)
        return True

    def _process_mp_tx_result(self, tx: MPTxRequest, mp_result: Any):
        if not isinstance(mp_result, MPTxExecResult):
            self.error(f'Wrong type as result of tx processing {tx.signature}: {mp_result}')
            return

        mp_tx_result = cast(MPTxExecResult, mp_result)
        log_fn = self.warning if mp_tx_result.code != MPTxExecResultCode.Done else self.debug
        log_fn(f"For tx {tx.signature} got result: {mp_tx_result}.")

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

    def _on_blocked_accounts_result(self, tx: MPTxRequest):
        self.debug(f"Got blocked account transaction status for tx {tx.signature}.")
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    def _on_solana_unavailable_result(self, tx: MPTxRequest):
        self.debug(f"Got solana unavailable status for tx {tx.signature}.")
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    async def _reschedule_tx(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            self.debug(f"Will be rescheduled in: {self.RESCHEDULE_TIMEOUT_SEC} sec.")
        await asyncio.sleep(self.RESCHEDULE_TIMEOUT_SEC)

        with logging_context(req_id=tx.req_id):
            try:
                self._tx_schedule.reschedule_tx(tx)
            except Exception as err:
                self._error(f'Exception on the result processing of tx {tx.signature}', err)
                return

        await self._kick_tx_schedule()

    def _on_done_tx(self, tx: MPTxRequest):
        self._tx_schedule.done_tx(tx)
        self.debug(f"Request {tx.signature} is done")

    def _on_fail_tx(self, tx: MPTxRequest):
        self._tx_schedule.fail_tx(tx)
        self.error(f"Request {tx.signature} is failed - dropped away")

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
        return self.gas_price is not None
