import asyncio
import logging

from multiprocessing import Process
from typing import Any, Optional, cast, Union

from .executor_mng import MPExecutorMng, IMPExecutorMngUser
from .mempool import MemPool

from .mempool_api import (
    MPResult, MPRequest, MPRequestType, MPTxRequest, MPPendingTxByHashRequest,
    MPPendingTxNonceRequest, MPMempoolTxNonceRequest, MPPendingTxBySenderNonceRequest
)

from .mempool_replicator import MemPoolReplicator

from ..common.logger import Logger
from ..common_neon.config import Config
from ..common_neon.maintenance_api import MaintenanceRequest, MaintenanceCommand, ReplicationRequest, ReplicationBunch
from ..common_neon.operator_resource_mng import OpResMng
from ..common_neon.pickable_data_server import AddrPickableDataSrv, IPickableDataServerUser
from ..common_neon.utils.json_logger import logging_context

from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPService(IPickableDataServerUser, IMPExecutorMngUser):
    MP_SERVICE_ADDR = ("0.0.0.0", 9091)
    MP_MAINTENANCE_ADDR = ("0.0.0.0", 9092)

    def __init__(self, config: Config):
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._mempool_srv: Optional[AddrPickableDataSrv] = None
        self._mempool_maintenance_srv: Optional[AddrPickableDataSrv] = None
        self._mempool: Optional[MemPool] = None
        self._stat_client: Optional[ProxyStatClient] = None
        self._op_res_mng: Optional[OpResMng] = None
        self._mp_executor_mng: Optional[MPExecutorMng] = None
        self._replicator: Optional[MemPoolReplicator] = None
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        LOG.info("Run until complete")
        self._process.start()

    async def on_data_received(self, mp_request: Union[MPRequest, MaintenanceRequest]) -> Any:
        try:
            if issubclass(type(mp_request), (MPRequest,)):
                return await self.process_mp_request(cast(MPRequest, mp_request))
            elif issubclass(type(mp_request), (MaintenanceRequest,)):
                return self.process_maintenance_request(cast(MaintenanceRequest, mp_request))
            LOG.error(f"Failed to process mp_request, unknown type: {type(mp_request)}")
        except BaseException as exc:
            with logging_context(req_id=mp_request.req_id):
                LOG.error(f"Failed to process maintenance request: {mp_request.command}.", exc_info=exc)
                return MPResult("Request failed")

        return MPResult("Unexpected problem")

    async def process_mp_request(self, mp_request: MPRequest) -> Any:
        with logging_context(req_id=mp_request.req_id):
            if mp_request.type == MPRequestType.SendTransaction:
                tx_request = cast(MPTxRequest, mp_request)
                return await self._mempool.schedule_mp_tx_request(tx_request)
            elif mp_request.type == MPRequestType.GetPendingTxNonce:
                pending_nonce_req = cast(MPPendingTxNonceRequest, mp_request)
                return self._mempool.get_pending_tx_nonce(pending_nonce_req.sender)
            elif mp_request.type == MPRequestType.GetMempoolTxNonce:
                mempool_nonce_req = cast(MPMempoolTxNonceRequest, mp_request)
                return self._mempool.get_last_tx_nonce(mempool_nonce_req.sender)
            elif mp_request.type == MPRequestType.GetTxByHash:
                pending_tx_by_hash_req = cast(MPPendingTxByHashRequest, mp_request)
                return self._mempool.get_pending_tx_by_hash(pending_tx_by_hash_req.tx_hash)
            elif mp_request.type == MPRequestType.GetTxBySenderNonce:
                req = cast(MPPendingTxBySenderNonceRequest, mp_request)
                return self._mempool.get_pending_tx_by_sender_nonce(req.sender, req.tx_nonce)
            elif mp_request.type == MPRequestType.GetGasPrice:
                return self._mempool.get_gas_price()
            elif mp_request.type == MPRequestType.GetElfParamDict:
                return self._mempool.get_elf_param_dict()
            elif mp_request.type == MPRequestType.TxPoolContent:
                return self._mempool.get_content()
            LOG.error(f"Failed to process mp_request, unknown type: {mp_request.type}")

    def process_maintenance_request(self, request: MaintenanceRequest) -> MPResult:
        if request.command == MaintenanceCommand.SuspendMemPool:
            return self._mempool.suspend_processing()
        elif request.command == MaintenanceCommand.ResumeMemPool:
            return self._mempool.resume_processing()
        elif request.command == MaintenanceCommand.ReplicateRequests:
            repl_req = cast(ReplicationRequest, request)
            return self._replicator.replicate(repl_req.peers)
        elif request.command == MaintenanceCommand.ReplicateTxsBunch:
            mp_tx_bunch: ReplicationBunch = cast(ReplicationBunch, request)
            LOG.info(
                f"Got replication txs bunch, sender: {mp_tx_bunch.sender_addr}, "
                f"txs: {len(mp_tx_bunch.mp_tx_requests)}"
            )
            return self._replicator.on_mp_tx_bunch(mp_tx_bunch.sender_addr, mp_tx_bunch.mp_tx_requests)
        LOG.error(f"Failed to process maintenance mp_reqeust, unknown command: {request.command}")

    def run(self):
        try:
            Logger.setup()
            self._mempool_srv = AddrPickableDataSrv(user=self, address=self.MP_SERVICE_ADDR)
            self._mempool_maintenance_srv = AddrPickableDataSrv(user=self, address=self.MP_MAINTENANCE_ADDR)
            self._stat_client = ProxyStatClient(self._config)
            self._stat_client.start()
            self._mp_executor_mng = MPExecutorMng(self._config, self, self._stat_client)
            self._event_loop.run_until_complete(self._mp_executor_mng.async_init())
            self._op_res_mng = OpResMng(self._config, self._stat_client)
            self._mempool = MemPool(self._config, self._stat_client, self._op_res_mng, self._mp_executor_mng)
            self._replicator = MemPoolReplicator(self._mempool)
            self._event_loop.run_forever()
        except BaseException as exc:
            LOG.error('Failed to run mempool_service.', exc_info=exc)

    def on_executor_released(self, executor_id: int):
        self._mempool.on_executor_got_available(executor_id)
