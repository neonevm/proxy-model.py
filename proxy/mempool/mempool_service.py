import traceback

from logged_groups import logged_group
import asyncio
from multiprocessing import Process
from typing import Any, cast, Union

from neon_py.network import AddrPickableDataSrv, IPickableDataServerUser
from neon_py.maintenance_api import MaintenanceRequest, MaintenanceCommand, ReplicationRequest, ReplicationBunch
from neon_py.data import Result
from .mempool_replicator import MemPoolReplicator

from ..common_neon.config import IConfig

from .mempool import MemPool
from .executor_mng import MPExecutorMng, IMPExecutorMngUser

from .mempool_api import MPRequest, MPRequestType, MPTxRequest, MPPendingTxNonceReq, MPPendingTxByHashReq


@logged_group("neon.MemPool")
class MPService(IPickableDataServerUser, IMPExecutorMngUser):

    MP_SERVICE_ADDR = ("0.0.0.0", 9091)
    MP_MAINTENANCE_ADDR = ("0.0.0.0", 9092)

    EXECUTOR_COUNT = 8

    def __init__(self, config: IConfig):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self._mempool_server = None
        self._mempool: MemPool = None
        self._replicator: MemPoolReplicator = None
        self._mp_executor_mng = None
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        self.info("Run until complete")
        self._process.start()

    async def on_data_received(self, mp_request: Union[MPRequest, MaintenanceRequest]) -> Any:
        try:
            self.info(f"RequestType: {type(mp_request)}, is it subtype of MaintenanceRequest: {issubclass(type(mp_request), (MaintenanceRequest,))}")
            if issubclass(type(mp_request), (MPRequest,)):
                return await self.process_mp_request(mp_request)
            elif issubclass(type(mp_request), (MaintenanceRequest,)):
                return self.process_maintenance_request(mp_request)
            self.error(f"Failed to process mp_request, unknown type: {type(mp_request)}")
        except Exception as err:
            log_ctx = {"context": {"req_id": mp_request.req_id}}
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Failed to process maintenance request: {mp_request.command}, {err}, traceback: {err_tb}", extra=log_ctx)
            return Result("Request failed")

        return Result("Unexpected problem")

    async def process_mp_request(self, mp_request: MPRequest) -> Any:
        if mp_request.type == MPRequestType.SendTransaction:
            tx_request = cast(MPTxRequest, mp_request)
            return await self._mempool.schedule_mp_tx_request(tx_request)
        elif mp_request.type == MPRequestType.GetLastTxNonce:
            pending_nonce_req = cast(MPPendingTxNonceReq, mp_request)
            return self._mempool.get_pending_tx_nonce(pending_nonce_req.sender)
        elif mp_request.type == MPRequestType.GetTxByHash:
            pending_tx_by_hash_req = cast(MPPendingTxByHashReq, mp_request)
            return self._mempool.get_pending_tx_by_hash(pending_tx_by_hash_req.tx_hash)
        self.error(f"Failed to process mp_reqeust, unknown type: {mp_request.type}")

    def process_maintenance_request(self, request: MaintenanceRequest) -> Result:
        if request.command == MaintenanceCommand.SuspendMemPool:
            return self._mempool.suspend_processing()
        elif request.command == MaintenanceCommand.ResumeMemPool:
            return self._mempool.resume_processing()
        elif request.command == MaintenanceCommand.ReplicateRequests:
            repl_req = cast(ReplicationRequest, request)
            return self._replicator.replicate(repl_req.peers)
        elif request.command == MaintenanceCommand.ReplicateTxsBunch:
            mp_tx_bunch: ReplicationBunch = cast(ReplicationBunch, request)
            self.info(f"Got replication txs bunch, sender: {mp_tx_bunch.sender_addr}, txs: {len(mp_tx_bunch.mp_tx_requests)}")
            return self._replicator.on_mp_tx_bunch(mp_tx_bunch.sender_addr, mp_tx_bunch.mp_tx_requests)
        self.error(f"Failed to process maintenance mp_reqeust, unknown command: {request.command}")

    def run(self):
        self._mempool_maintenance_srv = AddrPickableDataSrv(user=self, address=self.MP_MAINTENANCE_ADDR)
        self._mempool_server = AddrPickableDataSrv(user=self, address=self.MP_SERVICE_ADDR)

        self._mp_executor_mng = MPExecutorMng(self, self.EXECUTOR_COUNT, self._config)
        mempool_capacity = self._config.get_mempool_capacity()
        self._mempool = MemPool(self._mp_executor_mng, mempool_capacity)
        self._replicator = MemPoolReplicator(self._mempool)

        self.event_loop.run_until_complete(self._mp_executor_mng.async_init())
        self.event_loop.run_forever()

    def on_resource_released(self, resource_id: int):
        self._mempool.on_resource_got_available(resource_id)
