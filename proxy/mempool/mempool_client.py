from __future__ import annotations
import threading
from typing import Callable
from logged_groups import logged_group

from ..common_neon.utils import AddrPickableDataClient

from .mempool_api import MPTxRequest, MPPendingTxCountReq

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


def _guard_conn(method: Callable):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            result = None
            try:
                result = method(self, *args, **kwargs)
            except InterruptedError as err:
                self.error(f"Transfer interrupted err: {err}, reconnect, will return None")
                self._connect_mp()
            except Exception as err:
                self.error(f"Transfer unexpected err: {err}, reconnect, will return None")
                self._connect_mp()
            finally:
                return result

    return wrapper


@logged_group("neon.Proxy")
class MemPoolClient:

    def __init__(self, host: str, port: int):
        self.debug("Init MemPoolClient")
        self._lock = threading.Lock()
        self._address = (host, port)
        self._connect_mp()

    def _connect_mp(self):
        with self._lock:
            self.debug(f"Connect MemPool: {self._address}")
            self._pickable_data_client = AddrPickableDataClient(self._address)

    @_guard_conn
    def send_raw_transaction(self, req_id: int, signature: str, neon_tx: NeonTx, neon_tx_exec_cfg: NeonTxExecCfg,
                                   emulating_result: NeonEmulatingResult):

        mempool_tx_request = MPTxRequest(req_id=req_id, signature=signature, neon_tx=neon_tx,
                                         neon_tx_exec_cfg=neon_tx_exec_cfg, emulating_result=emulating_result)
        return self._pickable_data_client.send_data(mempool_tx_request)

    @_guard_conn
    def get_pending_tx_count(self, req_id: int, sender: str):
        mempool_pending_tx_count_req = MPPendingTxCountReq(req_id=req_id, sender=sender)
        return self._pickable_data_client.send_data(mempool_pending_tx_count_req)
