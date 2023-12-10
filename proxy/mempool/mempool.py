import asyncio
import dataclasses
import logging
import math
import time

from collections import deque
from typing import List, Optional, Any, cast, Union, Deque, Dict, Final, Tuple

from .executor_mng import MPExecutorMng, IMPExecutorMngUser

from .mempool_api import (
    MPRequestType, MPTask,
    MPGasPriceResult, MPGasPriceTokenResult,
    MPTxExecResult, MPTxExecResultCode, MPTxRequest, MPTxExecRequest, MPStuckTxInfo,
    MPTxSendResult, MPTxSendResultCode,
    MPTxPoolContentResult,
    MPNeonTxResult,
    MPEVMConfigResult
)

from .mempool_neon_tx_dict import MPTxDict
from .mempool_stuck_tx_dict import MPStuckTxDict
from .mempool_periodic_task_evm_config import MPEVMConfigTaskLoop, IEVMConfigUser
from .mempool_periodic_task_free_alt_queue import MPFreeALTQueueTaskLoop
from .mempool_periodic_task_gas_price import MPGasPriceTaskLoop, IGasPriceUser
from .mempool_periodic_task_op_res import MPInitOpResTaskLoop
from .mempool_periodic_task_op_res_list import MPOpResGetListTaskLoop
from .mempool_periodic_task_sender_tx_cnt import MPSenderTxCntTaskLoop
from .mempool_periodic_task_stuck_tx import MPStuckTxListLoop
from .mempool_periodic_task import MPPeriodicTaskLoop
from .mempool_schedule import MPTxSchedule
from .operator_resource_mng import OpResMng

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.evm_config import EVMConfig
from ..common_neon.errors import StuckTxError
from ..common_neon.operator_resource_info import OpResInfo
from ..common_neon.address import NeonAddress
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.constants import ONE_BLOCK_SEC

from ..statistic.data import NeonTxBeginData, NeonTxEndCode, NeonTxEndData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MemPool(IEVMConfigUser, IGasPriceUser, IMPExecutorMngUser):
    def __init__(self, config: Config, stat_client: ProxyStatClient):
        LOG.info(f'Init mempool schedule with config: {config.as_dict()}')

        self._config = config
        self._reschedule_timeout_sec: Final[float] = ONE_BLOCK_SEC * 3
        self._check_task_timeout_sec: Final[float] = 0.01

        self._has_evm_config = False
        self._gas_price: Optional[MPGasPriceResult] = None
        self._gas_price_dict: Dict[int, MPGasPriceTokenResult] = dict()

        self._tx_schedule_idx = 0
        self._tx_schedule_dict: Dict[int, MPTxSchedule] = dict()
        self._completed_tx_dict = MPTxDict(config)
        self._stuck_tx_dict = MPStuckTxDict(self._completed_tx_dict)
        self._rescheduled_tx_queue: Deque[MPTxRequest] = deque()

        self._schedule_cond = asyncio.Condition()
        self._processing_task_list: List[MPTask] = list()

        self._executor_mng = MPExecutorMng(self._config, self, stat_client)
        self._op_res_mng = OpResMng(self._config, stat_client)
        self._stat_client = stat_client

        self._async_task_list: List[Union[asyncio.Task, MPPeriodicTaskLoop]] = list()
        self._free_alt_queue_task_loop: Optional[MPFreeALTQueueTaskLoop] = None

    def start(self) -> None:
        asyncio.get_event_loop().run_until_complete(self._executor_mng.set_executor_cnt(1))
        self._async_task_list.append(MPEVMConfigTaskLoop(self._executor_mng, self))

    def _update_gas_price(self, tx: MPTxRequest) -> Optional[MPTxSendResult]:
        if not tx.has_chain_id():
            LOG.debug('Increase gas-price for wo-chain-id tx')
        elif tx.gas_price == 0:
            LOG.debug('Increase gas-price for gas-less tx')
        else:
            return None

        gas_price = self._gas_price_dict.get(tx.chain_id, None)
        if not gas_price:
            LOG.debug("Mempool doesn't have gas price information")
            return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)

        tx.gas_price = gas_price.suggested_gas_price * 2
        return None

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        try:
            if self._completed_tx_dict.get_tx_by_hash(tx.sig) is not None:
                LOG.debug('Tx is already processed')
                return MPTxSendResult(MPTxSendResultCode.AlreadyKnown, state_tx_cnt=None)

            result: Optional[MPTxSendResult] = self._update_gas_price(tx)
            if result:
                return result

            result: Optional[MPTxSendResult] = self._call_tx_schedule(tx.chain_id, MPTxSchedule.add_tx, tx)
            if not result:
                return MPTxSendResult(MPTxSendResultCode.Unspecified, state_tx_cnt=None)
            elif result.code == MPTxSendResultCode.Success:
                self._stat_client.commit_tx_add()

            LOG.debug('Got tx and scheduled request')
            return result

        except BaseException as exc:
            LOG.error('Failed to schedule tx', exc_info=exc)
            return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)

        finally:
            await self._kick_tx_schedule()

    def get_pending_tx_nonce(self, sender: NeonAddress) -> Optional[int]:
        return self._call_tx_schedule(sender.chain_id, MPTxSchedule.get_pending_tx_nonce, sender.address)

    def get_last_tx_nonce(self, sender: NeonAddress) -> Optional[int]:
        return self._call_tx_schedule(sender.chain_id, MPTxSchedule.get_last_tx_nonce, sender.address)

    def get_pending_tx_by_hash(self, tx_hash: str) -> MPNeonTxResult:
        for tx_schedule in self._tx_schedule_dict.values():
            neon_tx_info = tx_schedule.get_pending_tx_by_hash(tx_hash)
            if neon_tx_info is not None:
                return neon_tx_info
        return self._completed_tx_dict.get_tx_by_hash(tx_hash)

    def get_pending_tx_by_sender_nonce(self, sender: NeonAddress, tx_nonce: int) -> MPNeonTxResult:
        neon_tx_info = self._call_tx_schedule(
            sender.chain_id, MPTxSchedule.get_pending_tx_by_sender_nonce,
            sender.address, tx_nonce
        )
        if neon_tx_info:
            return neon_tx_info
        return self._completed_tx_dict.get_tx_by_sender_nonce(sender, tx_nonce)

    def _call_tx_schedule(self, chain_id: int, method, *args, **kwargs) -> Any:
        tx_schedule = self._tx_schedule_dict.get(chain_id)
        if tx_schedule:
            return method(tx_schedule, *args, **kwargs)
        return None

    def get_gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def get_evm_config(self) -> Optional[MPEVMConfigResult]:
        if not self._has_evm_config:
            return None
        return EVMConfig().evm_config_data

    def get_content(self) -> MPTxPoolContentResult:
        result = MPTxPoolContentResult(list(), list())
        for tx_schedule in self._tx_schedule_dict.values():
            result.extend(tx_schedule.get_content())
        return result

    async def _enqueue_tx_request(self) -> bool:
        tx = self._acquire_tx()
        if tx is None:
            return False

        with logging_context(req_id=tx.req_id):
            try:
                mp_task = self._executor_mng.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return True

            except BaseException as exc:
                LOG.error('Failed to enqueue to execute', exc_info=exc)
                self._on_reschedule_tx(tx)
                return False

    def _acquire_tx(self) -> Optional[MPTxExecRequest]:
        try:
            return (
                self._acquire_stuck_tx() or
                self._acquire_rescheduled_tx() or
                self._acquire_scheduled_tx()
            )

        except BaseException as exc:
            LOG.error('Failed to get tx for execution', exc_info=exc)

        return None

    def _acquire_stuck_tx(self) -> Optional[MPTxExecRequest]:
        while True:
            stuck_tx = self._stuck_tx_dict.peek_tx()
            if stuck_tx is None:
                return None

            result = self._call_tx_schedule(stuck_tx.chain_id, MPTxSchedule.drop_stuck_tx, stuck_tx.sig)
            if not result:
                self._stuck_tx_dict.skip_tx(stuck_tx)
                continue

            tx = self._attach_resource_to_tx(stuck_tx)
            if tx is None:
                return None

            with logging_context(req_id=tx.req_id):
                LOG.debug('Got tx from stuck queue')
            self._stuck_tx_dict.acquire_tx(stuck_tx)
            return tx

    def _acquire_rescheduled_tx(self) -> Optional[MPTxExecRequest]:
        if not len(self._rescheduled_tx_queue):
            return None

        tx = self._rescheduled_tx_queue[0]
        tx = self._attach_resource_to_tx(tx)
        if tx is None:
            return None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from rescheduling queue')

        self._rescheduled_tx_queue.popleft()
        return tx

    def _acquire_scheduled_tx(self) -> Optional[MPTxExecRequest]:
        tx_schedule, tx = self._find_tx_schedule()
        if tx_schedule is None:
            return None

        tx: Optional[MPTxExecRequest] = self._attach_resource_to_tx(tx)
        if not tx:
            return None

        with logging_context(req_id=tx.req_id):
            LOG.debug('Got tx from schedule')
            tx_schedule.acquire_tx(tx)

        return tx

    def _find_tx_schedule(self) -> Tuple[Optional[MPTxSchedule], Optional[MPTxRequest]]:
        tx_schedule_list: List[MPTxSchedule] = list(self._tx_schedule_dict.values())

        for retry in range(len(tx_schedule_list)):
            if self._tx_schedule_idx >= len(tx_schedule_list):
                self._tx_schedule_idx = 0

            tx_schedule = tx_schedule_list[self._tx_schedule_idx]
            self._tx_schedule_idx += 1

            gas_price = self._gas_price_dict.get(tx_schedule.chain_id, None)
            if not gas_price:
                continue

            tx = tx_schedule.peek_top_tx()
            if tx and (tx.gas_price >= gas_price.min_executable_gas_price):
                return tx_schedule, tx

        return None, None

    def _attach_resource_to_tx(self, tx: Union[MPTxRequest, MPStuckTxInfo]) -> Optional[MPTxExecRequest]:
        with logging_context(req_id=tx.req_id):
            res_info = self._op_res_mng.get_resource(tx.sig)
            if res_info is None:
                return None

        evm_cfg_data = EVMConfig().evm_config_data
        if not isinstance(tx, MPStuckTxInfo):
            return MPTxExecRequest.from_tx_req(tx, res_info, evm_cfg_data)

        neon_exec_cfg = NeonTxExecCfg()
        neon_exec_cfg.set_holder_account(False, tx.holder_account)
        return MPTxExecRequest.from_stuck_tx(tx, neon_exec_cfg, res_info, evm_cfg_data)

    async def _process_tx_schedule_loop(self):
        while True:
            try:
                async with self._schedule_cond:
                    await self._schedule_cond.wait()
                    # LOG.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")

                    while self._executor_mng.is_available():
                        if not await self._enqueue_tx_request():
                            break

                    stat = NeonTxBeginData()
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
        stat.in_mempool_cnt = sum([tx_schedule.tx_cnt for tx_schedule in self._tx_schedule_dict.values()])

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

            await asyncio.sleep(self._check_task_timeout_sec)

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
        self._call_tx_schedule(tx.chain_id, MPTxSchedule.cancel_tx, tx)
        return NeonTxEndCode.Canceled

    def _on_cancel_tx(self, tx: MPTxExecRequest) -> NeonTxEndCode:
        self._release_resource(tx)
        self._call_tx_schedule(tx.chain_id, MPTxSchedule.cancel_tx, tx)
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
            LOG.debug(f'Tx will be rescheduled in {math.ceil(self._reschedule_timeout_sec * 1000)} msec')

        await asyncio.sleep(self._reschedule_timeout_sec)

        with logging_context(req_id=tx.req_id):
            try:
                cfg = tx.neon_tx_exec_cfg
                if cfg.is_resource_used() or cfg.has_completed_receipt():
                    self._op_res_mng.update_resource(tx.sig)
                    self._rescheduled_tx_queue.append(tx)
                else:
                    self._release_resource(tx)
                    self._call_tx_schedule(tx.chain_id, MPTxSchedule.cancel_tx, tx)
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
        self._call_tx_schedule(tx.chain_id, MPTxSchedule.done_tx, tx)
        self._completed_tx_dict.done_tx(tx, None)
        LOG.debug(f'Request {tx.sig} is done')
        return NeonTxEndCode.Done

    def _on_fail_tx(self, tx: MPTxExecRequest, exc: Optional[BaseException]) -> NeonTxEndCode:
        self._release_resource(tx)
        if tx.is_stuck_tx():
            self._stuck_tx_dict.done_tx(tx.sig)
            LOG.debug(f'Stuck request {tx.sig} is failed - dropped away')
        else:
            self._call_tx_schedule(tx.chain_id, MPTxSchedule.fail_tx, tx)
            self._completed_tx_dict.done_tx(tx, exc)
            LOG.debug(f'Request {tx.sig} is failed - dropped away')
        return NeonTxEndCode.Failed

    def _on_stuck_tx(self, tx: MPTxExecRequest, stuck_tx_error: StuckTxError) -> NeonTxEndCode:
        self._release_resource(tx)

        self._op_res_mng.get_resource(stuck_tx_error.neon_tx_sig)
        self._stuck_tx_dict.add_own_tx(stuck_tx_error)

        return self._on_cancel_tx(tx)

    def _release_resource(self, tx: MPTxExecRequest) -> Optional[OpResInfo]:
        resource = self._op_res_mng.release_resource(tx.sig)
        if resource is None:
            return None

        alt_address_list = tx.neon_tx_exec_cfg.alt_address_list
        if self._free_alt_queue_task_loop:
            self._free_alt_queue_task_loop.add_alt_address_list(alt_address_list, resource.private_key)
        return resource

    async def _kick_tx_schedule(self) -> None:
        async with self._schedule_cond:
            # LOG.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_executor_released(self, _: int) -> None:
        self._create_kick_tx_schedule_task()

    def on_evm_config(self, evm_config: EVMConfig) -> None:
        capacity = self._config.mempool_capacity
        for token_info in evm_config.token_info_list:
            if token_info.chain_id not in self._tx_schedule_dict:
                self._tx_schedule_dict[token_info.chain_id] = MPTxSchedule(capacity, token_info.chain_id)
                LOG.info(f'Start transaction scheduler for the token {token_info.chain_id, token_info.token_name}')

        chain_id_set = set(evm_config.chain_id_list)
        for chain_id in list(self._tx_schedule_dict.keys()):
            if chain_id not in chain_id_set:
                LOG.info(f'Stop transaction scheduler for the chainId {chain_id}')
                self._tx_schedule_dict.pop(chain_id)

        if self._has_evm_config:
            return
        self._has_evm_config = True

        self._async_task_list.append(MPGasPriceTaskLoop(self._executor_mng, self))

    def on_gas_price(self, gas_price: MPGasPriceResult) -> None:
        self._gas_price = gas_price

        for token_info in self._gas_price.token_list:
            tx_schedule = self._tx_schedule_dict.get(token_info.chain_id, None)
            if tx_schedule:
                token_info.up_suggested_gas_price(tx_schedule.min_gas_price)
            self._gas_price_dict[token_info.chain_id] = token_info

        if not self._config.enable_send_tx_api:
            return
        elif self._free_alt_queue_task_loop:
            return

        LOG.info(f'Start transaction scheduler tasks')
        self._free_alt_queue_task_loop = MPFreeALTQueueTaskLoop(self._config, self._executor_mng, self._op_res_mng)

        self._async_task_list.extend([
            self._free_alt_queue_task_loop,
            MPSenderTxCntTaskLoop(self._executor_mng, self._tx_schedule_dict),
            MPOpResGetListTaskLoop(self._executor_mng, self._op_res_mng),
            MPInitOpResTaskLoop(self._executor_mng, self._op_res_mng, self._stuck_tx_dict),
            MPStuckTxListLoop(self._executor_mng, self._stuck_tx_dict),
            asyncio.get_event_loop().create_task(self._process_tx_result_loop()),
            asyncio.get_event_loop().create_task(self._process_tx_schedule_loop()),
            asyncio.get_event_loop().create_task(self._process_tx_dict_clear_loop())
        ])

    def _create_kick_tx_schedule_task(self) -> None:
        asyncio.get_event_loop().create_task(self._kick_tx_schedule())

    async def _process_tx_dict_clear_loop(self) -> None:
        while True:
            self._completed_tx_dict.clear()
            await self._completed_tx_dict.sleep()
