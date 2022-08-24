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
        conn_it = cycle([(peer.name, AddrPickableDataClient(peer.address)) for peer in peers])
        txs_it = self._mempool.get_taking_out_txs_iterator()
        for (peer_name, conn), (sender_addr, mp_tx_req_list) in zip(conn_it, txs_it):
            replication_bunch = ReplicationBunch(sender_addr=sender_addr, mp_tx_requests=mp_tx_req_list)
            self.debug(f"Sending replication_bunch: {replication_bunch.sender_addr}, {len(replication_bunch.mp_tx_requests)} - txs")
            conn.send_data(replication_bunch)

        return Result()

    def on_mp_tx_bunch(self, sender_addr: str, mp_tx_request_list: MPTxRequestList):
        self._mempool.take_in_txs(sender_addr, mp_tx_request_list)
        return Result()
