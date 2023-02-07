import logging
from typing import List

from itertools import cycle

from .mempool_api import MPTxRequestList, MPResult
from .mempool import MemPool

from ..common_neon.maintenance_api import Peer, ReplicationBunch
from ..common_neon.pickable_data_server import AddrPickableDataClient


LOG = logging.getLogger(__name__)


class MemPoolReplicator:

    def __init__(self, mempool: MemPool):
        self._mempool = mempool

    def replicate(self, peers: List[Peer]) -> MPResult:
        LOG.debug(f"Replicate, peers: {peers}")
        conn_it = cycle([AddrPickableDataClient(peer.address) for peer in peers])
        tx_list_it = self._mempool.get_taking_out_tx_list_iter()
        for conn, (sender_addr, mp_tx_req_list) in zip(conn_it, tx_list_it):
            replication_bunch = ReplicationBunch(sender_addr=sender_addr, mp_tx_requests=mp_tx_req_list)
            LOG.debug(
                f"Sending replication_bunch: {replication_bunch.sender_addr},"
                f"{len(replication_bunch.mp_tx_requests)} - txs"
            )
            conn.send_data(replication_bunch)

        return MPResult()

    def on_mp_tx_bunch(self, sender_addr: str, mp_tx_request_list: MPTxRequestList) -> MPResult:
        self._mempool.take_in_tx_list(sender_addr, mp_tx_request_list)
        return MPResult()
