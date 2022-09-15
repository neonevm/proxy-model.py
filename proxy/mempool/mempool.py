import asyncio
import traceback
from typing import List, Tuple, Optional, Any, Dict, cast, Iterator

from logged_groups import logged_group, logging_context
from neon_py.data import Result

from ..common_neon.eth_proto import NeonTx
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams

from .operator_resource_mng import OperatorResourceMng

from .mempool_api import MPRequest, MPRequestType, IMPExecutor, MPTask, MPTxRequestList
from .mempool_api import MPTxExecResult, MPTxExecResultCode, MPTxRequest, MPTxExecRequest
from .mempool_api import MPTxSendResult, MPTxSendResultCode
from .mempool_api import MPGasPriceRequest, MPGasPriceResult
from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult
from .mempool_api import MPElfParamDictRequest
from .mempool_api import MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_schedule import MPTxSchedule
from .mempool_periodic_task import MPPeriodicTaskLoop


class MPGasPriceTaskLoop(MPPeriodicTaskLoop[MPGasPriceRequest, MPGasPriceResult]):
    def __init__(self, executor: IMPExecutor) -> None:
        super().__init__(name='gas-price', sleep_time=4.0, executor=executor)
        self._gas_price: Optional[MPGasPriceResult] = None

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def _submit_request(self) -> None:
        mp_req = MPGasPriceRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGasPriceRequest) -> None:
        pass

    def _process_result(self, _: MPGasPriceRequest, mp_res: MPGasPriceResult) -> None:
        self._gas_price = mp_res


class MPElfParamDictTaskLoop(MPPeriodicTaskLoop[MPElfParamDictRequest, Dict[str, str]]):
    def __init__(self, executor: IMPExecutor) -> None:
        super().__init__(name='elf-params', sleep_time=4.0, executor=executor)

    def _submit_request(self) -> None:
        mp_req = MPElfParamDictRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPElfParamDictRequest) -> None:
        pass

    def _process_result(self, _: MPElfParamDictRequest, mp_res: Dict[str, str]) -> None:
        ElfParams().set_elf_param_dict(mp_res)


class MPSenderTxCntTaskLoop(MPPeriodicTaskLoop[MPSenderTxCntRequest, MPSenderTxCntResult]):
    def __init__(self, executor: IMPExecutor, tx_schedule: MPTxSchedule) -> None:
        super().__init__(name='state-tx-cnt', sleep_time=0.4, executor=executor)
        self._tx_schedule = tx_schedule

    def _submit_request(self) -> None:
        paused_sender_list = self._tx_schedule.get_paused_sender_list()
        if len(paused_sender_list) == 0:
            return

        mp_req = MPSenderTxCntRequest(req_id=self._generate_req_id(), sender_list=paused_sender_list)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPSenderTxCntRequest) -> None:
        pass

    def _process_result(self, _: MPSenderTxCntRequest, mp_res: MPSenderTxCntResult) -> None:
        self._tx_schedule.set_sender_state_tx_cnt_list(mp_res.sender_tx_cnt_list)


class MPInitOperatorResourceTaskLoop(MPPeriodicTaskLoop[MPOpResInitRequest, MPOpResInitResult]):
    _default_sleep_time = 4.0

    def __init__(self, executor: IMPExecutor, op_res_mng: OperatorResourceMng) -> None:
        super().__init__(name='op-res-init', sleep_time=self._check_sleep_time, executor=executor)
        self._op_res_mng = op_res_mng
        self._disabled_resource_list: List[str] = []

    def _submit_request(self) -> None:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return

        if len(self._disabled_resource_list) == 0:
            self._disabled_resource_list = self._op_res_mng.get_disabled_resource_list()
        if len(self._disabled_resource_list) == 0:
            return

        resource = self._disabled_resource_list.pop()
        if len(self._disabled_resource_list) == 0:
            self._sleep_time = self._default_sleep_time
        else:
            self._sleep_time = self._check_sleep_time
        mp_req = MPOpResInitRequest(
            req_id=self._generate_req_id(),
            elf_param_dict=elf_params.elf_param_dict,
            resource_ident=resource
        )
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPOpResInitRequest) -> None:
        pass

    def _process_result(self, mp_req: MPOpResInitRequest, mp_res: MPOpResInitResult) -> None:
        if mp_res.code == MPOpResInitResultCode.Success:
            self._op_res_mng.enable_resource(mp_req.resource_ident)


@logged_group("neon.MemPool")
class MemPool:
    CHECK_TASK_TIMEOUT_SEC = 0.01
    RESCHEDULE_TIMEOUT_SEC = 0.4

    def __init__(self, config: Config, op_res_mng: OperatorResourceMng, executor: IMPExecutor):
        capacity = config.mempool_capacity
        self.info(f"Init mempool schedule with capacity: {capacity}")
        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_task_list: List[MPTask] = []
        self._is_active: bool = True
        self._executor = executor
        self._op_res_mng = op_res_mng
        self._gas_price_task_loop = MPGasPriceTaskLoop(executor)
        self._elf_param_dict_task_loop = MPElfParamDictTaskLoop(executor)
        self._state_tx_cnt_task_loop = MPSenderTxCntTaskLoop(executor, self._tx_schedule)
        self._op_res_init_task_loop = MPInitOperatorResourceTaskLoop(executor, self._op_res_mng)
        self._process_tx_result_task_loop = asyncio.get_event_loop().create_task(self._process_tx_result_loop())
        self._process_tx_schedule_task_loop = asyncio.get_event_loop().create_task(self._process_tx_schedule_loop())

    @property
    def _gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price_task_loop.gas_price

    def has_gas_price(self) -> bool:
        return self._gas_price is not None

    async def enqueue_mp_request(self, mp_request: MPRequest):
        assert mp_request.type == MPRequestType.SendTransaction, f'Wrong request type {mp_request}'

        tx_request = cast(MPTxRequest, mp_request)
        return await self.schedule_mp_tx_request(tx_request)

    def _on_exception(self, text: str, err: BaseException) -> None:
        err_tb = "".join(traceback.format_tb(err.__traceback__))
        self.error(f"{text}. Error: {err}. Traceback: {err_tb}")

    async def schedule_mp_tx_request(self, tx: MPTxRequest) -> MPTxSendResult:
        with logging_context(req_id=tx.req_id):
            try:
                if not tx.has_chain_id():
                    if not self.has_gas_price():
                        self.debug("Mempool doesn't have gas price information")
                        return MPTxSendResult(code=MPTxSendResultCode.Unspecified, state_tx_cnt=None)
                    self.debug(f'Increase gas-price for wo-chain-id tx {tx.signature}')
                    tx.gas_price = self._gas_price.suggested_gas_price * 2

                result: MPTxSendResult = self._tx_schedule.add_tx(tx)
                self.debug(f"Got tx {tx.signature} and scheduled request")
                return result
            except Exception as err:
                self._on_exception(f"Failed to schedule tx {tx.signature}", err)
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
        return self._gas_price

    @staticmethod
    def get_elf_param_dict() -> Optional[Dict[str, str]]:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return None
        return elf_params.elf_param_dict

    def _enqueue_tx_request(self) -> bool:
        try:
            tx = self._tx_schedule.peek_tx()
            if (tx is None) or (tx.gas_price < self._gas_price.min_gas_price):
                return False

            with logging_context(req_id=tx.req_id):
                resource = self._op_res_mng.get_resource(tx.signature)
                if resource is None:
                    return False

            tx = self._tx_schedule.acquire_tx()
        except Exception as err:
            self._on_exception(f'Failed to get tx for execution', err)
            return False

        with logging_context(req_id=tx.req_id):
            try:
                self.debug(f"Got tx {tx.signature} from schedule.")
                tx = MPTxExecRequest.clone(tx, resource, ElfParams().elf_param_dict)

                mp_task = self._executor.submit_mp_request(tx)
                self._processing_task_list.append(mp_task)
                return True
            except Exception as err:
                self._on_exception(f'Failed to enqueue to execute {tx.signature}', err)
                return False

    async def _process_tx_schedule_loop(self):
        while (not self.has_gas_price()) and (not ElfParams().has_params()):
            await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)

        while True:
            async with self._schedule_cond:
                await self._schedule_cond.wait()
                await self._schedule_cond.wait_for(self.is_active)
                # self.debug(f"Schedule processing got awake, condition: {self._schedule_cond.__repr__()}")
                while self._executor.is_available():
                    if not self._enqueue_tx_request():
                        break

    async def _process_tx_result_loop(self):
        while True:
            not_finished_task_list: List[MPTask] = []
            for mp_task in self._processing_task_list:
                with logging_context(req_id=mp_task.mp_request.req_id):
                    if not self._complete_task(mp_task):
                        not_finished_task_list.append(mp_task)
            self._processing_task_list = not_finished_task_list

            await asyncio.sleep(self.CHECK_TASK_TIMEOUT_SEC)

    def _complete_task(self, mp_task: MPTask) -> bool:
        try:
            if not mp_task.aio_task.done():
                return False

            self._executor.release_executor(mp_task.executor_id)

            if mp_task.mp_request.type != MPRequestType.SendTransaction:
                self.error(f"Got unexpected request: {mp_task.mp_request}")
                return True  # skip task
        except Exception as err:
            self._on_exception(f"Exception on checking type of request.", err)
            return True

        tx = cast(MPTxRequest, mp_task.mp_request)
        try:
            err = mp_task.aio_task.exception()
            if err is not None:
                self._on_exception(f'Exception during processing tx {tx.signature} on executor', err)
                self._on_fail_tx(tx)
                return True

            mp_result = mp_task.aio_task.result()
            self._process_mp_tx_result(tx, mp_result)
        except Exception as err:
            self._on_exception(f"Exception on the result processing of tx {tx.signature}", err)
        return True

    def _process_mp_tx_result(self, tx: MPTxRequest, mp_result: Any):
        assert isinstance(mp_result, MPTxExecResult), f'Wrong type of tx result processing {tx.signature}: {mp_result}'

        mp_tx_result = cast(MPTxExecResult, mp_result)
        log_fn = self.warning if mp_tx_result.code != MPTxExecResultCode.Done else self.debug
        log_fn(f"For tx {tx.signature} got result: {mp_tx_result}.")

        if isinstance(mp_tx_result.data, NeonTxExecCfg):
            tx.neon_tx_exec_cfg = cast(NeonTxExecCfg, mp_tx_result.data)

        if mp_tx_result.code == MPTxExecResultCode.BlockedAccount:
            self._on_reschedule_tx(tx)
        elif mp_tx_result.code in (MPTxExecResultCode.SolanaUnavailable, MPTxExecResultCode.NodeBehind):
            self._on_reschedule_tx(tx)
        elif mp_tx_result.code == MPTxExecResultCode.BadResource:
            self._on_bad_resource(tx)
        elif mp_tx_result.code in (MPTxExecResultCode.NonceTooLow, MPTxExecResultCode.Unspecified):
            self._on_fail_tx(tx)
        elif mp_tx_result.code == MPTxExecResultCode.Done:
            self._on_done_tx(tx)
        else:
            assert False, f'Unknown result code {mp_tx_result.code}'

    def _on_reschedule_tx(self, tx: MPTxRequest) -> None:
        self.debug(f"Got reschedule status for tx {tx.signature}.")
        asyncio.get_event_loop().create_task(self._reschedule_tx(tx))

    async def _reschedule_tx(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            self.debug(f"Tx {tx.signature} will be rescheduled in: {self.RESCHEDULE_TIMEOUT_SEC} sec.")
        await asyncio.sleep(self.RESCHEDULE_TIMEOUT_SEC)
        self._reschedule_tx_impl(tx)
        await self._kick_tx_schedule()

    def _reschedule_tx_impl(self, tx: MPTxRequest):
        with logging_context(req_id=tx.req_id):
            try:
                self._op_res_mng.update_resource(tx.signature)
                self._tx_schedule.reschedule_tx(tx)
            except Exception as err:
                self._on_exception(f'Exception on the result processing of tx {tx.signature}', err)
                return

    def _on_bad_resource(self, tx: MPTxRequest):
        self.debug(f"Disable resource for {tx.signature}")
        self._op_res_mng.disable_resource(tx.signature)
        self._reschedule_tx_impl(tx)

    def _on_done_tx(self, tx: MPTxRequest):
        self._op_res_mng.release_resource(tx.signature)
        self._tx_schedule.done_tx(tx)
        self.debug(f"Request {tx.signature} is done")

    def _on_fail_tx(self, tx: MPTxRequest):
        self._op_res_mng.release_resource(tx.signature)
        self._tx_schedule.fail_tx(tx)
        self.debug(f"Request {tx.signature} is failed - dropped away")

    async def _kick_tx_schedule(self):
        async with self._schedule_cond:
            # self.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_executor_got_available(self, _: int):
        self._create_kick_tx_schedule_task()

    def _create_kick_tx_schedule_task(self):
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
        self._create_kick_tx_schedule_task()
        return Result()

    def is_active(self) -> bool:
        return self._is_active

    def get_taking_out_tx_list_iterator(self) -> Iterator[Tuple[str, MPTxRequestList]]:
        return self._tx_schedule.get_taking_out_tx_list_iterator()

    def take_in_tx_list(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._tx_schedule.take_in_tx_list(sender_addr, mp_tx_request_list)
        self._create_kick_tx_schedule_task()

