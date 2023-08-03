from __future__ import annotations

import threading
import logging
from typing import Callable, Optional, Dict, Any, Union

from .mempool_api import (
    MPGasPriceResult, MPGasPriceRequest, MPElfParamDictRequest, MPTxRequest,
    MPPendingTxNonceRequest, MPMempoolTxNonceRequest, MPPendingTxByHashRequest, MPTxSendResult,
    MPTxPoolContentRequest, MPTxPoolContentResult
)

from ..common_neon.data import NeonTxExecCfg
from ..common_neon.errors import EthereumError
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.utils.neon_tx_info import NeonTxInfo
from ..common_neon.pickable_data_server import AddrPickableDataClient


LOG = logging.getLogger(__name__)


def _guard_conn(method: Callable) -> Callable:
    def wrapper(self, *args, **kwargs):
        with self._mp_conn_lock:
            return method(self, *args, **kwargs)

    return wrapper


def _reconnecting(method: Callable) -> Callable:
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except (InterruptedError, Exception) as err:
            LOG.error(f"Failed to transfer data, unexpected err: {err}")
            self._reconnect_mp()
            raise
    return wrapper


class MemPoolClient:
    _reconnect_mp_time_sec = 1

    def __init__(self, address):
        LOG.debug("Init MemPoolClient")
        self._mp_conn_lock = threading.Lock()
        self._address = address
        self._is_connecting = threading.Event()
        self._connect_mp()

    def _reconnect_mp(self):
        if self._is_connecting.is_set():
            return
        self._is_connecting.set()
        LOG.debug(f"Reconnecting MemPool in: {self._reconnect_mp_time_sec} sec")
        threading.Timer(self._reconnect_mp_time_sec, self._connect_mp).start()

    @_guard_conn
    def _connect_mp(self):
        try:
            LOG.debug(f"Connect MemPool: {self._address}")
            self._pickable_data_client = AddrPickableDataClient(self._address)
        except BaseException as exc:
            LOG.error(f'Failed to connect MemPool: {self._address}.', exc_info=exc)
            self._is_connecting.clear()
            self._reconnect_mp()
        finally:
            self._is_connecting.clear()

    @_guard_conn
    @_reconnecting
    def send_raw_transaction(self, req_id: str, neon_tx: NeonTx, neon_tx_exec_cfg: NeonTxExecCfg) -> MPTxSendResult:
        mempool_tx_request = MPTxRequest.from_neon_tx(req_id, neon_tx, neon_tx_exec_cfg)
        return self._pickable_data_client.send_data(mempool_tx_request)

    @_guard_conn
    @_reconnecting
    def get_pending_tx_nonce(self, req_id: str, sender: str) -> int:
        mempool_pending_tx_nonce_req = MPPendingTxNonceRequest(req_id=req_id, sender=sender)
        return self._pickable_data_client.send_data(mempool_pending_tx_nonce_req)

    @_guard_conn
    @_reconnecting
    def get_mempool_tx_nonce(self, req_id: str, sender: str) -> int:
        mempool_tx_nonce_req = MPMempoolTxNonceRequest(req_id=req_id, sender=sender)
        return self._pickable_data_client.send_data(mempool_tx_nonce_req)

    @_guard_conn
    @_reconnecting
    def get_pending_tx_by_hash(self, req_id: str, tx_hash: str) -> Union[NeonTxInfo, EthereumError, None]:
        mempool_pending_tx_by_hash_req = MPPendingTxByHashRequest(req_id=req_id, tx_hash=tx_hash)
        return self._pickable_data_client.send_data(mempool_pending_tx_by_hash_req)

    @_guard_conn
    @_reconnecting
    def get_gas_price(self, req_id: str) -> Optional[MPGasPriceResult]:
        gas_price_req = MPGasPriceRequest(req_id=req_id)
        return self._pickable_data_client.send_data(gas_price_req)

    @_guard_conn
    @_reconnecting
    def get_elf_param_dict(self, req_id: str) -> Optional[Dict[str, Any]]:
        elf_param_dict_req = MPElfParamDictRequest(req_id=req_id, elf_param_dict={})
        return self._pickable_data_client.send_data(elf_param_dict_req)

    @_guard_conn
    @_reconnecting
    def get_content(self, req_id: str) -> MPTxPoolContentResult:
        content_req = MPTxPoolContentRequest(req_id=req_id)
        return self._pickable_data_client.send_data(content_req)

