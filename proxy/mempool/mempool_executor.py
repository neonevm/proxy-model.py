import asyncio
import multiprocessing as mp
import socket
import logging
from typing import Optional, Any, cast

from .mempool_api import (
    MPGetALTList, MPDeactivateALTListRequest, MPCloseALTListRequest,
    MPOpResInitRequest, MPGasPriceRequest,
    MPRequestType, MPRequest, MPTxExecRequest, MPSenderTxCntRequest, MPElfParamDictRequest,
    MPGetStuckTxListRequest
)

from .mempool_executor_task_elf_params import MPExecutorElfParamsTask
from .mempool_executor_task_exec_neon_tx import MPExecutorExecNeonTxTask
from .mempool_executor_task_free_alt_queue import MPExecutorFreeALTQueueTask
from .mempool_executor_task_gas_price import MPExecutorGasPriceTask
from .mempool_executor_task_op_res import MPExecutorOpResTask
from .mempool_executor_task_state_tx_cnt import MPExecutorStateTxCntTask
from .mempool_executor_task_stuck_tx import MPExecutorStuckTxListTask

from ..common.logger import Logger
from ..common_neon.config import Config
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.pickable_data_server import PipePickableDataSrv, IPickableDataServerUser

from ..neon_core_api import NeonCoreApiClient

from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPExecutor(mp.Process, IPickableDataServerUser):
    def __init__(self, config: Config, executor_id: int, srv_sock: socket.socket):
        self._id = executor_id
        self._srv_sock = srv_sock
        self._config = config
        self._event_loop: asyncio.BaseEventLoop

        self._pickable_data_srv: Optional[PipePickableDataSrv] = None
        self._stat_client: Optional[ProxyStatClient] = None
        self._core_api_client: Optional[NeonCoreApiClient] = None

        mp.Process.__init__(self)

    def _init_in_proc(self):
        LOG.info(f'Init MemPoolExecutor: {self._id}')

        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)

        self._pickable_data_srv = PipePickableDataSrv(user=self, srv_sock=self._srv_sock)

        self._stat_client = ProxyStatClient(self._config)
        self._stat_client.start()

    async def on_data_received(self, data: Any) -> Any:
        try:
            mp_req = cast(MPRequest, data)
            with logging_context(req_id=mp_req.req_id, exectr=self._id):
                return self._handle_request(mp_req)
        except BaseException as exc:
            LOG.error('Exception during handle request', exc_info=exc)
        return None

    def _handle_request(self, mp_req: MPRequest) -> Any:
        if mp_req.type == MPRequestType.SendTransaction:
            mp_tx_req = cast(MPTxExecRequest, mp_req)
            if self._core_api_client is None:
                self._core_api_client = NeonCoreApiClient(self._config)
            exec_neon_tx_task = MPExecutorExecNeonTxTask(self._config, self._core_api_client)
            return exec_neon_tx_task.execute_neon_tx(mp_tx_req)

        elif mp_req.type == MPRequestType.GetGasPrice:
            mp_gas_price_req = cast(MPGasPriceRequest, mp_req)
            gas_price_task = MPExecutorGasPriceTask(self._config, self._stat_client)
            return gas_price_task.calc_gas_price(mp_gas_price_req)

        elif mp_req.type == MPRequestType.GetElfParamDict:
            mp_elf_req = cast(MPElfParamDictRequest, mp_req)
            elf_params_task = MPExecutorElfParamsTask(self._config)
            return elf_params_task.read_elf_param_dict(mp_elf_req)

        elif mp_req.type == MPRequestType.GetStateTxCnt:
            mp_state_req = cast(MPSenderTxCntRequest, mp_req)
            state_tx_cnt_task = MPExecutorStateTxCntTask(self._config)
            return state_tx_cnt_task.read_state_tx_cnt(mp_state_req)

        elif mp_req.type == MPRequestType.GetOperatorResourceList:
            return self._new_op_res_task().get_op_res_list()

        elif mp_req.type == MPRequestType.InitOperatorResource:
            mp_op_res_req = cast(MPOpResInitRequest, mp_req)
            return self._new_op_res_task().init_op_res(mp_op_res_req)

        elif mp_req.type == MPRequestType.GetALTList:
            mp_get_req = cast(MPGetALTList, mp_req)
            return self._new_free_alt_task().get_alt_list(mp_get_req)

        elif mp_req.type == MPRequestType.DeactivateALTList:
            mp_deactivate_req = cast(MPDeactivateALTListRequest, mp_req)
            return self._new_free_alt_task().deactivate_alt_list(mp_deactivate_req)

        elif mp_req.type == MPRequestType.CloseALTList:
            mp_close_req = cast(MPCloseALTListRequest, mp_req)
            return self._new_free_alt_task().close_alt_list(mp_close_req)

        elif mp_req.type == MPRequestType.GetStuckTxList:
            mp_stuck_tx_req = cast(MPGetStuckTxListRequest, mp_req)
            stuck_tx_task = MPExecutorStuckTxListTask(self._config)
            return stuck_tx_task.read_stuck_tx_list(mp_stuck_tx_req)

        LOG.error(f'Failed to process mp_request, unknown type: {mp_req.type}')

    def _new_op_res_task(self) -> MPExecutorOpResTask:
        return MPExecutorOpResTask(self._config, self._stat_client)

    def _new_free_alt_task(self) -> MPExecutorFreeALTQueueTask:
        return MPExecutorFreeALTQueueTask(self._config)

    def run(self) -> None:
        Logger.setup()
        self._config = Config()
        self._init_in_proc()
        self._event_loop.run_forever()
