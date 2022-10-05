from typing import List

from logged_groups import logged_group
from neon_py.maintenance_api import Peer, ReplicationBunch
from neon_py.network import AddrPickableDataClient
from neon_py.data import Result
from itertools import cycle

from .mempool_api import MPTxRequestList
from .mempool import MemPool


@logged_group("neon.MemPool")
class MemPoolReplicator:

    def __init__(self, mempool: MemPool):
        self._mempool = mempool

    def replicate(self, peers: List[Peer]) -> Result:
        self.debug(f"Replicate, peers: {peers}")
        conn_it = cycle([AddrPickableDataClient(peer.address) for peer in peers])
        tx_list_it = self._mempool.get_taking_out_tx_list_iter()
        for conn, (sender_addr, mp_tx_req_list) in zip(conn_it, tx_list_it):
            replication_bunch = ReplicationBunch(sender_addr=sender_addr, mp_tx_requests=mp_tx_req_list)
            self.debug(
                f"Sending replication_bunch: {replication_bunch.sender_addr},"
                f"{len(replication_bunch.mp_tx_requests)} - txs"
            )
            conn.send_data(replication_bunch)

        return Result()

    def on_mp_tx_bunch(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._mempool.take_in_tx_list(sender_addr, mp_tx_request_list)
        return Result()
