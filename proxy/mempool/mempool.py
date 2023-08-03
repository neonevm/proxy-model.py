import asyncio
import logging
import math
import time

from collections import deque
from typing import List, Tuple, Optional, Any, Dict, cast, Generator, Union, Deque

from .executor_mng import MPExecutorMng

from .mempool_api import (
    MPRequest, MPRequestType, MPTask, MPTxRequestList,
    MPResult, MPGasPriceResult,
    MPTxExecResult, MPTxExecResultCode, MPTxRequest, MPTxExecRequest, MPStuckTxInfo,
    MPTxSendResult, MPTxSendResultCode,
    MPTxPoolContentResult
)

from .mempool_neon_tx_dict import MPTxDict
from .mempool_stuck_tx_dict import MPStuckTxDict
from .mempool_periodic_task_elf_params import MPElfParamDictTaskLoop
from .mempool_periodic_task_free_alt_queue import MPFreeALTQueueTaskLoop
from .mempool_periodic_task_gas_price import MPGasPriceTaskLoop
from .mempool_periodic_task_op_res import MPInitOpResTaskLoop
from .mempool_periodic_task_op_res_list import MPOpResGetListTaskLoop
from .mempool_periodic_task_sender_tx_cnt import MPSenderTxCntTaskLoop
from .mempool_periodic_task_stuck_tx import MPStuckTxListLoop
from .mempool_schedule import MPTxSchedule

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError, StuckTxError
from ..common_neon.operator_resource_info import OpResIdent
from ..common_neon.operator_resource_mng import OpResMng
from ..common_neon.utils.neon_tx_info import NeonTxInfo
from ..common_neon.utils.json_logger import logging_context

from ..statistic.data import NeonTxBeginCode, NeonTxBeginData, NeonTxEndCode, NeonTxEndData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MemPool:
    _one_block_sec = 0.4
    check_task_timeout_sec = 0.01
    reschedule_timeout_sec = _one_block_sec * 3

    def __init__(self, config: Config, stat_client: ProxyStatClient, op_res_mng: OpResMng, executor_mng: MPExecutorMng):
        capacity = config.mempool_capacity
        LOG.info(f'Init mempool schedule with capacity: {capacity}')
        LOG.info(f'Config: {config.as_dict()}')

        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_task_list: List[MPTask] = list()
        self._rescheduled_tx_queue: Deque[MPTxRequest] = deque()
        self._is_active: bool = True
        self._executor_mng = executor_mng
        self._op_res_mng = op_res_mng
        self._completed_tx_dict = MPTxDict(config)
        self._stuck_tx_dict = MPStuckTxDict(self._completed_tx_dict)
        self._stat_client = stat_client

        self._elf_param_dict_task_loop = MPElfParamDictTaskLoop(executor_mng)
        self._gas_price_task_loop = MPGasPriceTaskLoop(executor_mng)
        self._state_tx_cnt_task_loop = MPSenderTxCntTaskLoop(executor_mng, self._tx_schedule)

        if not config.enable_send_tx_api:
            return

        self._op_res_get_list_task_loop = MPOpResGetListTaskLoop(executor_mng, self._op_res_mng)
        self._op_res_init_task_loop = MPInitOpResTaskLoop(executor_mng, self._op_res_mng, self._stuck_tx_dict)
        self._free_alt_queue_task_loop = MPFreeALTQueueTaskLoop(config, executor_mng, self._op_res_mng)
        self._stuck_list_task_loop = MPStuckTxListLoop(executor_mng, self._stuck_tx_dict)

        self._process_tx_result_task_loop = asyncio.get_event_loop().create_task(self._process_tx_result_loop())
        self._process_tx_schedule_task_loop = asyncio.get_event_loop().create_task(self._process_tx_schedule_loop())
        self._process_tx_dict_clear_task_loop = asyncio.get_event_loop().create_task(self._process_tx_dict_clear_loop())

    @property
    def _gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price_task_loop.gas_price

    def has_gas_price(self) -> bool:
        return self._gas_price is not None

    async def enqueue_mp_request(self, mp_request: MPRequest):
        assert mp_request.type == MPRequestType.SendTransaction, f'Wrong request type {mp_request}'

        tx_request = cast(MPTxRequest, mp_request)
        return await self.schedule_mp_tx_request(tx_request)

    def _update_gas_price(self, tx: MPTxRequest) -> Optional[MPTxSendResult]:
        if not tx.has_chain_id():
            LOG.debug('Increase gas-price for wo-chain-id tx')
        elif tx.gas_price == 0:
            LOG.debug('Increase gas-price for gas-less tx')
        else:
            return None

        if not self.has_gas_price():
            LOG.debug("Mempool doesn't have gas price information")
            return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)

        tx.gas_price = self._gas_price.suggested_gas_price * 2
        return None

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        try:
            if self._completed_tx_dict.get_tx(tx.sig) is not None:
                LOG.debug('Tx is already processed')
                return MPTxSendResult(MPTxSendResultCode.AlreadyKnown, state_tx_cnt=None)

            result: Optional[MPTxSendResult] = self._update_gas_price(tx)
            if result is not None:
                return result

            result: MPTxSendResult = self._tx_schedule.add_tx(tx)
            if result.code == MPTxSendResultCode.Success:
                self._stat_client.commit_tx_add()
            LOG.debug('Got tx and scheduled request')
            return result

        except BaseException as exc:
            LOG.error('Failed to schedule tx', exc_info=exc)
            return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)

        finally:
            await self._kick_tx_schedule()

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_nonce(sender_addr)

    def get_last_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_last_tx_nonce(sender_addr)

    def get_pending_tx_by_hash(self, tx_hash: str) -> Union[NeonTxInfo, EthereumError, None]:
        neon_tx_info = self._tx_schedule.get_pending_tx_by_hash(tx_hash)
        if neon_tx_info is not None:
            return neon_tx_info
        return self._completed_tx_dict.get_tx(tx_hash)

    def get_gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    @staticmethod
    def get_elf_param_dict() -> Optional[Dict[str, str]]:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return None
        return elf_params.elf_param_dict

    def get_content(self) -> MPTxPoolContentResult:
        return self._tx_schedule.get_content()

    async def _enqueue_tx_request(self) -> NeonTxBeginCode:
        code, tx = self._acquire_tx()
        if tx is None:
            return code

        with logging_context(req_id=tx.req_id):
            try:
                mp_task = self._executor_mng.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return code

            except BaseException as exc:
                LOG.error('Failed to enqueue to execute', exc_info=exc)
                self._on_reschedule_tx(tx)
                return NeonTxBeginCode.Failed

    def _acquire_tx(self) -> Tuple[NeonTxBeginCode, Optional[MPTxExecRequest]]:
        try:
            code, tx = self._acquire_stuck_tx()
            if tx is not None:
                return code, tx

            code, tx = self._acquire_rescheduled_tx()
            if tx is not None:
                return code, tx

            return self._acquire_scheduled_tx()

        except BaseException as exc:
            LOG.error('Failed to get tx for execution', exc_info=exc)

        return NeonTxBeginCode.Failed, None

    def _acquire_stuck_tx(self) -> Tuple[NeonTxBeginCode, Optional[MPTxExecRequest]]:
        while True:
            stuck_tx = self._stuck_tx_dict.peek_tx()
            if stuck_tx is None:
                return NeonTxBeginCode.Failed, None

            if not self._tx_schedule.drop_stuck_tx(stuck_tx.sig):
                self._stuck_tx_dict.skip_tx(stuck_tx)
                continue

            tx = self._attach_resource_to_tx(stuck_tx)
            if tx is None:
                return NeonTxBeginCode.Failed, None

            with logging_context(req_id=tx.req_id):
                LOG.debug('Got tx from stuck queue')
            self._stuck_tx_dict.acquire_tx(stuck_tx)
            return NeonTxBeginCode.StuckPushed, tx

    def _acquire_rescheduled_tx(self) -> Tuple[NeonTxBeginCode, Optional[MPTxExecRequest]]:
        if len(self._rescheduled_tx_queue) == 0:
            return NeonTxBeginCode.Failed, None

        tx = self._rescheduled_tx_queue[0]
        tx = self._attach_resource_to_tx(tx)
        if tx is None:
            return NeonTxBeginCode.Failed, None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from rescheduling queue')

        self._rescheduled_tx_queue.popleft()
        return NeonTxBeginCode.Restarted, tx

    def _acquire_scheduled_tx(self, tx: Optional[MPTxRequest] = None) -> Tuple[NeonTxBeginCode, Optional[MPTxExecRequest]]:
        if tx is None:
            tx = self._tx_schedule.peek_top_tx()
            if (tx is None) or (tx.gas_price < self._gas_price.min_executable_gas_price):
                return NeonTxBeginCode.Failed, None

            tx = self._attach_resource_to_tx(tx)
            if tx is None:
                return NeonTxBeginCode.Failed, None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from schedule')
            self._tx_schedule.acquire_tx(tx)

        return NeonTxBeginCode.Started, tx

    def _attach_resource_to_tx(self, tx: Union[MPTxRequest, MPStuckTxInfo]) -> Optional[MPTxExecRequest]:
        with logging_context(req_id=tx.req_id):
            res_ident = self._op_res_mng.get_resource(tx.sig)
            if res_ident is None:
                return None

        if not isinstance(tx, MPStuckTxInfo):
            return MPTxExecRequest.from_tx_req(tx, res_ident, ElfParams().elf_param_dict)

        neon_exec_cfg = NeonTxExecCfg()
        neon_exec_cfg.set_holder_account(False, tx.holder_account)
        return MPTxExecRequest.from_stuck_tx(tx, neon_exec_cfg, res_ident, ElfParams().elf_param_dict)

    async def _process_tx_schedule_loop(self):
        while (not self.has_gas_price()) and (not ElfParams().has_params()):
            await asyncio.sleep(self.check_task_timeout_sec)

        while True:
            try:
                async with self._schedule_cond:
                    await self._schedule_cond.wait()
                    await self._schedule_cond.wait_for(self.is_active)
                    # LOG.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")

                    stat = NeonTxBeginData()
                    while self._executor_mng.is_available():
                        code = await self._enqueue_tx_request()
                        if code == NeonTxBeginCode.Failed:
                            break

                    self._fill_mempool_stat(stat)
                    self._stat_client.commit_tx_begin(stat)

            except asyncio.exceptions.CancelledError:
                LOG.debug('Normal exit')
                break

            except BaseException as exc:
                LOG.error('Fail on process schedule', exc_info=exc)

    def _fill_mempool_stat(self, stat: Union[NeonTxBeginData, NeonTxEndData]) -> None:
        stat.processing_stuck_cnt = self._stuck_tx_dict.processing_tx_cnt
        stat.processing_cnt = len(self._processing_task_list) - stat.processing_stuck_cnt
        stat.in_reschedule_queue_cnt = len(self._rescheduled_tx_queue)
        stat.in_stuck_queue_cnt = self._stuck_tx_dict.tx_cnt
        stat.in_mempool_cnt = self._tx_schedule.tx_cnt

    async def _process_tx_result_loop(self):
        while True:
            not_finished_task_list: List[MPTask] = list()
            stat = NeonTxEndData()

            for mp_task in self._processing_task_list:
                with logging_context(req_id=mp_task.mp_request.req_id):
                    code = self._complete_task(mp_task)
                    if code == NeonTxEndCode.Unfinished:
                        not_finished_task_list.append(mp_task)
                        continue

                    self._executor_mng.release_executor(mp_task.executor_id)
                    stat.add_value(code)

            self._processing_task_list = not_finished_task_list

            self._fill_mempool_stat(stat)
            self._stat_client.commit_tx_end(stat)

            await asyncio.sleep(self.check_task_timeout_sec)

    def _complete_task(self, mp_task: MPTask) -> NeonTxEndCode:
        try:
            if not mp_task.aio_task.done():
                return NeonTxEndCode.Unfinished

            if mp_task.mp_request.type != MPRequestType.SendTransaction:
                LOG.error(f'Got unexpected request: {mp_task.mp_request}')
                return NeonTxEndCode.Unspecified  # skip task

        except BaseException as exc:
            LOG.error('Exception on checking type of request', exc_info=exc)
            return NeonTxEndCode.Unspecified  # skip task

        tx = cast(MPTxExecRequest, mp_task.mp_request)
        try:
            exc = mp_task.aio_task.exception()
            if exc is not None:
                LOG.error('Exception during processing tx on executor', exc_info=exc)
                return self._on_fail_tx(tx, exc)

            mp_result = mp_task.aio_task.result()
            return self._process_mp_tx_result(tx, mp_result)

        except BaseException as exc:
            LOG.error('Exception on the result processing of tx', exc_info=exc)
        return NeonTxEndCode.Unspecified  # skip task

    def _process_mp_tx_result(self, tx: MPTxExecRequest, mp_res: Any) -> NeonTxEndCode:
        assert isinstance(mp_res, MPTxExecResult), f'Wrong type of tx result processing {tx.sig}: {mp_res}'

        mp_tx_res = cast(MPTxExecResult, mp_res)
        good_code_set = {MPTxExecResultCode.Done, MPTxExecResultCode.Reschedule}
        log_fn = LOG.warning if mp_tx_res.code not in good_code_set else LOG.debug
        log_fn(f'For tx {tx.sig} got result: {mp_tx_res}, time: {(time.time_ns() - tx.start_time) / (10 ** 6)}')

        if isinstance(mp_tx_res.data, NeonTxExecCfg):
            tx.neon_tx_exec_cfg = cast(NeonTxExecCfg, mp_tx_res.data)

        if tx.is_stuck_tx() and (mp_tx_res.code != MPTxExecResultCode.Failed):
            return self._on_done_stuck_tx(tx)
        elif mp_tx_res.code == MPTxExecResultCode.BadResource:
            return self._on_bad_resource(tx)
        elif mp_tx_res.code == MPTxExecResultCode.NonceTooHigh:
            return self._on_cancel_tx(tx)
        elif mp_tx_res.code == MPTxExecResultCode.Reschedule:
            return self._on_reschedule_tx(tx)
        elif mp_tx_res.code == MPTxExecResultCode.Failed:
            exc = cast(BaseException, mp_tx_res.data)
            return self._on_fail_tx(tx, exc)
        elif mp_tx_res.code == MPTxExecResultCode.StuckTx:
            exc = cast(StuckTxError, mp_tx_res.data)
            return self._on_stuck_tx(tx, exc)
        elif mp_tx_res.code == MPTxExecResultCode.Done:
            return self._on_done_tx(tx)

        assert False, f'Unknown result code {mp_tx_res.code}'

    def _on_bad_resource(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        resource = self._release_resource(tx)
        if resource is not None:
            self._op_res_mng.disable_resource(resource)
        self._tx_schedule.cancel_tx(tx)
        return NeonTxEndCode.Canceled

    def _on_cancel_tx(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._tx_schedule.cancel_tx(tx)
        return NeonTxEndCode.Canceled

    def _on_reschedule_tx(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        LOG.debug('Got reschedule status')
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))
        cfg = tx.neon_tx_exec_cfg
        if cfg.is_resource_used() or cfg.has_completed_receipt():
            return NeonTxEndCode.Rescheduled
        return NeonTxEndCode.Canceled

    async def _reschedule_tx(self, tx: MPTxExecRequest):
        with logging_context(req_id=tx.req_id):
            LOG.debug(f'Tx will be rescheduled in {math.ceil(self.reschedule_timeout_sec * 1000)} msec')

        await asyncio.sleep(self.reschedule_timeout_sec)

        with logging_context(req_id=tx.req_id):
            try:
                cfg = tx.neon_tx_exec_cfg
                if cfg.is_resource_used() or cfg.has_completed_receipt():
                    self._op_res_mng.update_resource(tx.sig)
                    self._rescheduled_tx_queue.append(tx)
                else:
                    self._release_resource(tx)
                    self._tx_schedule.cancel_tx(tx)
            except BaseException as exc:
                LOG.error('Exception on the result processing of tx', exc_info=exc)

        await self._kick_tx_schedule()

    def _on_done_stuck_tx(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._stuck_tx_dict.done_tx(tx.sig)
        LOG.debug(f'Stuck request {tx.sig} is done')
        return NeonTxEndCode.StuckDone

    def _on_done_tx(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._tx_schedule.done_tx(tx)
        self._completed_tx_dict.done_tx(tx.neon_tx_info, None)
        LOG.debug(f'Request {tx.sig} is done')
        return NeonTxEndCode.Done

    def _on_fail_tx(self, tx: MPTxExecRequest, exc: Optional[BaseException]) -> NeonTxEndCode:
        self._release_resource(tx)
        if tx.is_stuck_tx():
            self._stuck_tx_dict.done_tx(tx.sig)
            LOG.debug(f'Stuck request {tx.sig} is failed - dropped away')
        else:
            self._tx_schedule.fail_tx(tx)
            self._completed_tx_dict.done_tx(tx.neon_tx_info, exc)
            LOG.debug(f'Request {tx.sig} is failed - dropped away')
        return NeonTxEndCode.Failed

    def _on_stuck_tx(self, tx: MPTxExecRequest, stuck_tx_error: StuckTxError) -> NeonTxEndCode:
        self._release_resource(tx)

        self._op_res_mng.get_resource(stuck_tx_error.neon_tx_sig)
        self._stuck_tx_dict.add_own_tx(stuck_tx_error)

        return self._on_cancel_tx(tx)

    def _release_resource(self, tx: MPTxExecRequest) -> Optional[OpResIdent]:
        resource = self._op_res_mng.release_resource(tx.sig)
        if resource is None:
            return None

        alt_address_list = tx.neon_tx_exec_cfg.alt_address_list
        self._free_alt_queue_task_loop.add_alt_address_list(alt_address_list, resource.private_key)
        return resource

    async def _kick_tx_schedule(self) -> None:
        async with self._schedule_cond:
            # LOG.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_executor_got_available(self, _: int) -> None:
        self._create_kick_tx_schedule_task()

    def _create_kick_tx_schedule_task(self) -> None:
        asyncio.get_event_loop().create_task(self._kick_tx_schedule())

    def suspend_processing(self) -> MPResult:
        if not self._is_active:
            LOG.warning('No need to suspend mempool, already suspended')
            return MPResult()
        self._is_active = False
        LOG.info('Transaction processing suspended')
        return MPResult()

    def resume_processing(self) -> MPResult:
        if self._is_active:
            LOG.warning('No need to resume mempool, not suspended')
            return MPResult()
        self._is_active = True
        LOG.info('Transaction processing resumed')
        self._create_kick_tx_schedule_task()
        return MPResult()

    def is_active(self) -> bool:
        return self._is_active

    def iter_taking_out_tx_list(self) -> Generator[Tuple[str, MPTxRequestList], None, None]:
        return self._tx_schedule.iter_taking_out_tx_list

    def take_in_tx_list(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._tx_schedule.take_in_tx_list(sender_addr, mp_tx_request_list)
        self._create_kick_tx_schedule_task()

    async def _process_tx_dict_clear_loop(self) -> None:
        while True:
            self._completed_tx_dict.clear()
            await asyncio.sleep(self._completed_tx_dict.clear_time_sec)
