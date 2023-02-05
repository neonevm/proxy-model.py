import asyncio
import time
import enum
import logging
from typing import List, Tuple, Optional, Any, Dict, cast, Iterator, Union

from .executor_mng import MPExecutorMng
from .mempool_api import MPResult, MPGasPriceResult
from .mempool_api import MPRequest, MPRequestType, MPTask, MPTxRequestList
from .mempool_api import MPTxExecResult, MPTxExecResultCode, MPTxRequest, MPTxExecRequest
from .mempool_api import MPTxSendResult, MPTxSendResultCode
from .mempool_neon_tx_dict import MPTxDict
from .mempool_periodic_task_elf_params import MPElfParamDictTaskLoop
from .mempool_periodic_task_free_alt_queue import MPFreeALTQueueTaskLoop
from .mempool_periodic_task_gas_price import MPGasPriceTaskLoop
from .mempool_periodic_task_op_res import MPInitOpResTaskLoop
from .mempool_periodic_task_op_res_list import MPOpResGetListTaskLoop
from .mempool_periodic_task_sender_tx_cnt import MPSenderTxCntTaskLoop
from .mempool_schedule import MPTxSchedule
from .operator_resource_mng import OpResMng

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError
from ..common_neon.eth_proto import NeonTx
from ..common_neon.utils.json_logger import logging_context

from ..statistic.data import NeonTxBeginData, NeonTxEndData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPTxEndCode(enum.Enum):
    Unspecified = enum.auto()
    Unfinished = enum.auto()
    Done = enum.auto()
    Failed = enum.auto()
    Rescheduled = enum.auto()


class MemPool:
    check_task_timeout_sec = 0.01
    reschedule_timeout_sec = 0.4

    def __init__(self, config: Config, stat_client: ProxyStatClient, op_res_mng: OpResMng, executor_mng: MPExecutorMng):
        capacity = config.mempool_capacity
        LOG.info(f"Init mempool schedule with capacity: {capacity}")
        LOG.info(f"Config: {config.as_dict()}")
        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_task_list: List[MPTask] = []
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

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        try:
            if not tx.has_chain_id():
                if not self.has_gas_price():
                    LOG.debug("Mempool doesn't have gas price information")
                    return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)
                LOG.debug(f'Increase gas-price for wo-chain-id tx {tx.sig}')
                tx.gas_price = self._gas_price.suggested_gas_price * 2

            result: MPTxSendResult = self._tx_schedule.add_tx(tx)
            if result.code == MPTxSendResultCode.Success:
                self._stat_client.commit_tx_add()
            LOG.debug(f"Got tx {tx.sig} and scheduled request")
            return result
        except BaseException as exc:
            LOG.error(f"Failed to schedule tx {tx.sig}.", exc_info=exc)
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

    async def _enqueue_tx_request(self) -> bool:
        try:
            tx = self._tx_schedule.peek_tx()
            if (tx is None) or (tx.gas_price < self._gas_price.min_gas_price):
                return False

            with logging_context(req_id=tx.req_id):
                resource = self._op_res_mng.get_resource(tx.sig)
                if resource is None:
                    return False

            tx = self._tx_schedule.acquire_tx()
        except BaseException as exc:
            LOG.error('Failed to get tx for execution', exc_info=exc)
            return False

        with logging_context(req_id=tx.req_id):
            try:
                LOG.debug(f"Got tx {tx.sig} from schedule.")
                tx = MPTxExecRequest.clone(tx, resource, ElfParams().elf_param_dict)

                mp_task = self._executor_mng.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return True
            except BaseException as exc:
                LOG.error(f'Failed to enqueue to execute {tx.sig}', exc_info=exc)
                await self._reschedule_tx(tx)
                return False

    async def _process_tx_schedule_loop(self):
        while (not self.has_gas_price()) and (not ElfParams().has_params()):
            await asyncio.sleep(self.check_task_timeout_sec)

        while True:
            try:
                async with self._schedule_cond:
                    await self._schedule_cond.wait()
                    await self._schedule_cond.wait_for(self.is_active)
                    # LOG.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")

                    enqueued_tx_cnt = 0
                    while self._executor_mng.is_available():
                        if not await self._enqueue_tx_request():
                            break
                        enqueued_tx_cnt += 1

                    if enqueued_tx_cnt > 0:
                        self._stat_client.commit_tx_begin(NeonTxBeginData(begin_cnt=enqueued_tx_cnt))
            except asyncio.exceptions.CancelledError:
                LOG.debug(f'Normal exit')
                break
            except BaseException as exc:
                LOG.error(f'Fail on process schedule', exc_info=exc)

    async def _process_tx_result_loop(self):
        while True:
            not_finished_task_list: List[MPTask] = []

            done_cnt = 0
            failed_cnt = 0
            rescheduled_cnt = 0

            for mp_task in self._processing_task_list:
                with logging_context(req_id=mp_task.mp_request.req_id):
                    res = self._complete_task(mp_task)
                    if res == MPTxEndCode.Unfinished:
                        not_finished_task_list.append(mp_task)
                        continue

                    self._executor_mng.release_executor(mp_task.executor_id)
                    if res == MPTxEndCode.Done:
                        done_cnt += 1
                    elif res == MPTxEndCode.Failed:
                        failed_cnt += 1
                    elif res == MPTxEndCode.Rescheduled:
                        rescheduled_cnt += 1

            if (done_cnt > 0) or (failed_cnt > 0) or (rescheduled_cnt > 0):
                stat = NeonTxEndData(done_cnt=done_cnt, failed_cnt=failed_cnt, rescheduled_cnt=rescheduled_cnt)
                self._stat_client.commit_tx_end(stat)

            self._processing_task_list = not_finished_task_list
            await asyncio.sleep(self.check_task_timeout_sec)

    def _complete_task(self, mp_task: MPTask) -> MPTxEndCode:
        try:
            if not mp_task.aio_task.done():
                return MPTxEndCode.Unfinished

            if mp_task.mp_request.type != MPRequestType.SendTransaction:
                LOG.error(f"Got unexpected request: {mp_task.mp_request}")
                return MPTxEndCode.Unspecified  # skip task
        except BaseException as exc:
            LOG.error('Exception on checking type of request', exc_info=exc)
            return MPTxEndCode.Unspecified  # skip task

        tx = cast(MPTxRequest, mp_task.mp_request)
        try:
            exc = mp_task.aio_task.exception()
            if exc is not None:
                LOG.error(f'Exception during processing tx {tx.sig} on executor', exc_info=exc)
                self._on_fail_tx(tx, exc)
                return MPTxEndCode.Failed

            mp_result = mp_task.aio_task.result()
            return self._process_mp_tx_result(tx, mp_result)
        except BaseException as exc:
            LOG.error(f'Exception on the result processing of tx {tx.sig}', exc_info=exc)
        return MPTxEndCode.Unspecified  # skip task

    def _process_mp_tx_result(self, tx: MPTxRequest, mp_res: Any) -> MPTxEndCode:
        assert isinstance(mp_res, MPTxExecResult), f'Wrong type of tx result processing {tx.sig}: {mp_res}'

        mp_tx_res = cast(MPTxExecResult, mp_res)
        log_fn = LOG.warning if mp_tx_res.code != MPTxExecResultCode.Done else LOG.debug
        log_fn(f"For tx {tx.sig} got result: {mp_tx_res}, time: {(time.time_ns() - tx.start_time)/(10**6)}")

        if isinstance(mp_tx_res.data, NeonTxExecCfg):
            tx.neon_tx_exec_cfg = cast(NeonTxExecCfg, mp_tx_res.data)

        reschedule_code_set = {
            MPTxExecResultCode.BlockedAccount,
            MPTxExecResultCode.SolanaUnavailable,
            MPTxExecResultCode.NodeBehind,
        }

        if mp_tx_res.code in reschedule_code_set:
            self._on_reschedule_tx(tx)
            return MPTxEndCode.Rescheduled
        elif mp_tx_res.code == MPTxExecResultCode.BadResource:
            self._on_bad_resource(tx)
            return MPTxEndCode.Rescheduled
        elif mp_tx_res.code == MPTxExecResultCode.NonceTooLow:
            exc = RuntimeError(
                f'nonce too low: address {tx.sender_address}, '
                f'tx: {tx.nonce} state: {tx.neon_tx_exec_cfg.state_tx_cnt}'
            )
            self._on_fail_tx(tx, exc)
            return MPTxEndCode.Failed
        elif mp_tx_res.code == MPTxExecResultCode.Unspecified:
            exc = cast(BaseException, mp_tx_res.data)
            self._on_fail_tx(tx, exc)
            return MPTxEndCode.Failed
        elif mp_tx_res.code == MPTxExecResultCode.Done:
            self._on_done_tx(tx)
            return MPTxEndCode.Done
        assert False, f'Unknown result code {mp_tx_res.code}'

    def _on_reschedule_tx(self, tx: MPTxRequest) -> None:
        LOG.debug(f"Got reschedule status for tx {tx.sig}.")
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    async def _reschedule_tx(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            LOG.debug(f"Tx {tx.sig} will be rescheduled in: {self.reschedule_timeout_sec} sec.")
        await asyncio.sleep(self.reschedule_timeout_sec)
        self._reschedule_tx_impl(tx)
        await self._kick_tx_schedule()

    def _reschedule_tx_impl(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            try:
                self._op_res_mng.update_resource(tx.sig)
                self._tx_schedule.reschedule_tx(tx)
            except BaseException as exc:
                LOG.error(f'Exception on the result processing of tx {tx.sig}', exc_info=exc)
                return

    def _on_bad_resource(self, tx: MPTxRequest):
        LOG.debug(f"Disable resource for {tx.sig}")
        self._op_res_mng.disable_resource(tx.sig)
        self._reschedule_tx_impl(tx)

    def _on_done_tx(self, tx: MPTxRequest):
        resource = self._op_res_mng.release_resource(tx.sig)
        if resource is not None:
            alt_address_list = tx.neon_tx_exec_cfg.alt_address_list
            self._free_alt_queue_task_loop.add_alt_address_list(alt_address_list, resource.private_key)
        self._tx_schedule.done_tx(tx)
        self._completed_tx_dict.add(tx.sig, tx.neon_tx, None)
        LOG.debug(f"Request {tx.sig} is done")

    def _on_fail_tx(self, tx: MPTxRequest, exc: Optional[BaseException]):
        resource = self._op_res_mng.release_resource(tx.sig)
        if resource is not None:
            alt_address_list = tx.neon_tx_exec_cfg.alt_address_list
            self._free_alt_queue_task_loop.add_alt_address_list(alt_address_list, resource.private_key)
        self._tx_schedule.fail_tx(tx)
        self._completed_tx_dict.add(tx.sig, tx.neon_tx, exc)
        LOG.debug(f"Request {tx.sig} is failed - dropped away")

    async def _kick_tx_schedule(self):
        async with self._schedule_cond:
            # LOG.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_executor_got_available(self, _: int):
        self._create_kick_tx_schedule_task()

    def _create_kick_tx_schedule_task(self):
        asyncio.get_event_loop().create_task(self._kick_tx_schedule())

    def suspend_processing(self) -> MPResult:
        if not self._is_active:
            LOG.warning("No need to suspend mempool, already suspended")
            return MPResult()
        self._is_active = False
        LOG.info("Transaction processing suspended")
        return MPResult()

    def resume_processing(self) -> MPResult:
        if self._is_active:
            LOG.warning("No need to resume mempool, not suspended")
            return MPResult()
        self._is_active = True
        LOG.info("Transaction processing resumed")
        self._create_kick_tx_schedule_task()
        return MPResult()

    def is_active(self) -> bool:
        return self._is_active

    def get_taking_out_tx_list_iter(self) -> Iterator[Tuple[str, MPTxRequestList]]:
        return self._tx_schedule.get_taking_out_tx_list_iter()

    def take_in_tx_list(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._tx_schedule.take_in_tx_list(sender_addr, mp_tx_request_list)
        self._create_kick_tx_schedule_task()

    async def _process_tx_dict_clear_loop(self) -> None:
        while True:
            self._completed_tx_dict.clear()
            await asyncio.sleep(self._completed_tx_dict.clear_time_sec)
