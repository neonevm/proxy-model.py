import asyncio
import logging
import math
import time

from collections import deque
from typing import List, Tuple, Optional, Any, Dict, cast, Iterator, Union, Deque

from .mempool_api import (
    MPRequest, MPRequestType, MPTask, MPTxRequestList,
    MPResult, MPGasPriceResult,
    MPTxExecResult, MPTxExecResultCode, MPTxRequest, MPTxExecRequest,
    MPTxSendResult, MPTxSendResultCode
)

from .executor_mng import MPExecutorMng
from .mempool_neon_tx_dict import MPTxDict
from .mempool_periodic_task_elf_params import MPElfParamDictTaskLoop
from .mempool_periodic_task_free_alt_queue import MPFreeALTQueueTaskLoop
from .mempool_periodic_task_gas_price import MPGasPriceTaskLoop
from .mempool_periodic_task_op_res import MPInitOpResTaskLoop
from .mempool_periodic_task_op_res_list import MPOpResGetListTaskLoop
from .mempool_periodic_task_sender_tx_cnt import MPSenderTxCntTaskLoop
from .mempool_schedule import MPTxSchedule
from .operator_resource_mng import OpResMng, OpResIdent

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError
from ..common_neon.utils.eth_proto import NeonTx
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
        self._stat_client = stat_client

        self._elf_param_dict_task_loop = MPElfParamDictTaskLoop(executor_mng)
        self._gas_price_task_loop = MPGasPriceTaskLoop(executor_mng)
        self._state_tx_cnt_task_loop = MPSenderTxCntTaskLoop(executor_mng, self._tx_schedule)

        if not config.enable_send_tx_api:
            return

        self._op_res_get_list_task_loop = MPOpResGetListTaskLoop(executor_mng, self._op_res_mng)
        self._op_res_init_task_loop = MPInitOpResTaskLoop(executor_mng, self._op_res_mng)
        self._free_alt_queue_task_loop = MPFreeALTQueueTaskLoop(executor_mng, self._op_res_mng)

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
            if self._completed_tx_dict.get(tx.sig) is not None:
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

    def get_pending_tx_count(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_count(sender_addr)

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_nonce(sender_addr)

    def get_last_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_last_tx_nonce(sender_addr)

    def get_pending_tx_by_hash(self, tx_hash: str) -> Union[NeonTx, EthereumError, None]:
        neon_tx = self._tx_schedule.get_pending_tx_by_hash(tx_hash)
        if neon_tx is not None:
            return neon_tx
        return self._completed_tx_dict.get(tx_hash)

    def get_gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    @staticmethod
    def get_elf_param_dict() -> Optional[Dict[str, str]]:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return None
        return elf_params.elf_param_dict

    async def _enqueue_tx_request(self) -> NeonTxBeginCode:
        code = NeonTxBeginCode.Restarted
        try:
            tx = self._acquire_rescheduled_tx()
            if tx is None:
                code = NeonTxBeginCode.Started
                tx = self._acquire_scheduled_tx()

            if tx is None:
                return NeonTxBeginCode.Failed

        except BaseException as exc:
            LOG.error('Failed to get tx for execution', exc_info=exc)
            return NeonTxBeginCode.Failed

        with logging_context(req_id=tx.req_id):
            try:
                mp_task = self._executor_mng.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return code

            except BaseException as exc:
                LOG.error('Failed to enqueue to execute', exc_info=exc)
                self._on_reschedule_tx(tx)
                return NeonTxBeginCode.Failed

    def _acquire_rescheduled_tx(self) -> Optional[MPTxExecRequest]:
        if len(self._rescheduled_tx_queue) == 0:
            return None

        tx = self._rescheduled_tx_queue[0]
        tx = self._attach_resource_to_tx(tx)
        if tx is None:
            return None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from rescheduling queue')
        self._rescheduled_tx_queue.popleft()
        return tx

    def _acquire_scheduled_tx(self) -> Optional[MPTxRequest]:
        tx = self._tx_schedule.peek_tx()
        if (tx is None) or (tx.gas_price < self._gas_price.min_gas_price):
            return None

        tx = self._attach_resource_to_tx(tx)
        if tx is None:
            return None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from schedule')
        self._tx_schedule.acquire_tx()
        return tx

    def _attach_resource_to_tx(self, tx: MPTxRequest) -> Optional[MPTxExecRequest]:
        with logging_context(req_id=tx.req_id):
            resource = self._op_res_mng.get_resource(tx.sig)
            if resource is None:
                return None

        return MPTxExecRequest.clone(tx, resource, ElfParams().elf_param_dict)

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
                        if code != NeonTxBeginCode.Failed:
                            stat.add_value(code)
                        else:
                            break

                    if stat.has_value():
                        self._stat_client.commit_tx_begin(stat)

            except asyncio.exceptions.CancelledError:
                LOG.debug('Normal exit')
                break

            except BaseException as exc:
                LOG.error('Fail on process schedule', exc_info=exc)

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

            if stat.has_value():
                self._stat_client.commit_tx_end(stat)

            self._processing_task_list = not_finished_task_list
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

        tx = cast(MPTxRequest, mp_task.mp_request)
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

    def _process_mp_tx_result(self, tx: MPTxRequest, mp_res: Any) -> NeonTxEndCode:
        assert isinstance(mp_res, MPTxExecResult), f'Wrong type of tx result processing {tx.sig}: {mp_res}'

        mp_tx_res = cast(MPTxExecResult, mp_res)
        good_code_set = {MPTxExecResultCode.Done, MPTxExecResultCode.Reschedule}
        log_fn = LOG.warning if mp_tx_res.code not in good_code_set else LOG.debug
        log_fn(f'For tx {tx.sig} got result: {mp_tx_res}, time: {(time.time_ns() - tx.start_time) / (10 ** 6)}')

        if isinstance(mp_tx_res.data, NeonTxExecCfg):
            tx.neon_tx_exec_cfg = cast(NeonTxExecCfg, mp_tx_res.data)

        if mp_tx_res.code == MPTxExecResultCode.BadResource:
            return self._on_bad_resource(tx)
        elif mp_tx_res.code == MPTxExecResultCode.NonceTooHigh:
            return self._on_cancel_tx(tx)
        elif mp_tx_res.code == MPTxExecResultCode.Reschedule:
            return self._on_reschedule_tx(tx)
        elif mp_tx_res.code == MPTxExecResultCode.Failed:
            exc = cast(BaseException, mp_tx_res.data)
            return self._on_fail_tx(tx, exc)
        elif mp_tx_res.code == MPTxExecResultCode.Done:
            return self._on_done_tx(tx)

        assert False, f'Unknown result code {mp_tx_res.code}'

    def _on_bad_resource(self, tx: MPTxRequest) -> NeonTxEndCode:
        resource = self._release_resource(tx)
        if resource is not None:
            self._op_res_mng.disable_resource(resource)
        self._tx_schedule.cancel_tx(tx)
        return NeonTxEndCode.Canceled

    def _on_cancel_tx(self, tx: MPTxRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._tx_schedule.cancel_tx(tx)
        return NeonTxEndCode.Canceled

    def _on_reschedule_tx(self, tx: MPTxRequest) -> NeonTxEndCode:
        LOG.debug('Got reschedule status')
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))
        cfg = tx.neon_tx_exec_cfg
        if cfg.is_holder_used() or cfg.has_completed_receipt():
            return NeonTxEndCode.Rescheduled
        return NeonTxEndCode.Canceled

    async def _reschedule_tx(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            LOG.debug(f'Tx will be rescheduled in {math.ceil(self.reschedule_timeout_sec * 1000)} msec')

        await asyncio.sleep(self.reschedule_timeout_sec)

        with logging_context(req_id=tx.req_id):
            try:
                cfg = tx.neon_tx_exec_cfg
                if cfg.is_holder_used() or cfg.has_completed_receipt():
                    self._op_res_mng.update_resource(tx.sig)
                    self._rescheduled_tx_queue.append(tx)
                else:
                    self._release_resource(tx)
                    self._tx_schedule.cancel_tx(tx)
            except BaseException as exc:
                LOG.error('Exception on the result processing of tx', exc_info=exc)

        await self._kick_tx_schedule()

    def _on_done_tx(self, tx: MPTxRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._tx_schedule.done_tx(tx)
        self._completed_tx_dict.add(tx.neon_tx, None)
        LOG.debug(f'Request {tx.sig} is done')
        return NeonTxEndCode.Done

    def _on_fail_tx(self, tx: MPTxRequest, exc: Optional[BaseException]) -> NeonTxEndCode:
        self._release_resource(tx)
        self._tx_schedule.fail_tx(tx)
        self._completed_tx_dict.add(tx.neon_tx, exc)
        LOG.debug(f'Request {tx.sig} is failed - dropped away')
        return NeonTxEndCode.Failed

    def _release_resource(self, tx: MPTxRequest) -> Optional[OpResIdent]:
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

    def get_taking_out_tx_list_iter(self) -> Iterator[Tuple[str, MPTxRequestList]]:
        return self._tx_schedule.taking_out_tx_list_iter

    def take_in_tx_list(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._tx_schedule.take_in_tx_list(sender_addr, mp_tx_request_list)
        self._create_kick_tx_schedule_task()

    async def _process_tx_dict_clear_loop(self) -> None:
        while True:
            self._completed_tx_dict.clear()
            await asyncio.sleep(self._completed_tx_dict.clear_time_sec)
