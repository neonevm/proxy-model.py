from logged_groups import logged_group

from ..common_neon.utils import AddrPickableDataClient

from .mempool_api import MemPoolTxRequest, MemPoolPendingTxCountReq

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


@logged_group("neon.Proxy")
class MemPoolClient:

    def __init__(self, host: str, port: int):
        self._pickable_data_client = AddrPickableDataClient((host, port))

    def send_raw_transaction(self, req_id: int, signature: str, neon_tx: NeonTx, neon_tx_exec_cfg: NeonTxExecCfg,
                                   emulating_result: NeonEmulatingResult):
        mempool_tx_request = MemPoolTxRequest(req_id=req_id, signature=signature, neon_tx=neon_tx,
                                              neon_tx_exec_cfg=neon_tx_exec_cfg, emulating_result=emulating_result)
        return self._pickable_data_client.send_data(mempool_tx_request)

    def get_pending_tx_count(self, req_id: int, sender: str):
        mempool_pending_tx_count_req = MemPoolPendingTxCountReq(req_id=req_id, sender=sender)
        return self._pickable_data_client.send_data(mempool_pending_tx_count_req)
