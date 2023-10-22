import asyncio
import logging

from multiprocessing import Process
from typing import Any, Optional, cast

from .mempool import MemPool

from .mempool_api import (
    MPRequest, MPRequestType, MPTxRequest, MPPendingTxByHashRequest,
    MPPendingTxNonceRequest, MPMempoolTxNonceRequest, MPPendingTxBySenderNonceRequest
)

from ..common_neon.config import Config
from ..common_neon.pickable_data_server import AddrPickableDataSrv, IPickableDataServerUser
from ..common_neon.utils.json_logger import logging_context

from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPService(IPickableDataServerUser):
    MP_SERVICE_ADDR = ("0.0.0.0", 9091)

    def __init__(self, config: Config):
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._mempool_srv: Optional[AddrPickableDataSrv] = None
        self._mempool: Optional[MemPool] = None
        self._stat_client: Optional[ProxyStatClient] = None
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        LOG.info("Run until complete")
        self._process.start()

    async def on_data_received(self, mp_request: MPRequest) -> Any:
        try:
            if issubclass(type(mp_request), (MPRequest,)):
                return await self.process_mp_request(cast(MPRequest, mp_request))

            LOG.error(f"Failed to process mp_request, unknown type: {type(mp_request)}")
        except BaseException as exc:
            with logging_context(req_id=mp_request.req_id):
                LOG.error(f"Failed to process request: {mp_request}.", exc_info=exc)
        return None

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
            elif mp_request.type == MPRequestType.GetEVMConfig:
                return self._mempool.get_evm_config()
            elif mp_request.type == MPRequestType.TxPoolContent:
                return self._mempool.get_content()
            LOG.error(f"Failed to process mp_request, unknown type: {mp_request.type}")

    def run(self):
        try:
            self._mempool_srv = AddrPickableDataSrv(user=self, address=self.MP_SERVICE_ADDR)
            self._stat_client = ProxyStatClient(self._config)
            self._stat_client.start()
            self._mempool = MemPool(self._config, self._stat_client)
            self._mempool.start()
            self._event_loop.run_forever()
        except BaseException as exc:
            LOG.error('Failed to run mempool_service.', exc_info=exc)
