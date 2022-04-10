from logged_groups import logged_group

from ..common_neon.utils import QueueBasedService

from .mem_pool import MemPool


@logged_group("neon")
class MemPoolService(QueueBasedService):

    MEM_POOL_SERVICE_PORT = 9091

    def __init__(self):
        QueueBasedService.__init__(self, self.MEM_POOL_SERVICE_PORT)
        self._mem_pool = MemPool()

    def on_eth_send_raw_transaction(self, *, eth_trx_hash):
        self._mem_pool.on_eth_send_raw_transaction(eth_trx_hash=eth_trx_hash)

    def do_extras(self):
        self._mem_pool.do_extras()

    def __del__(self):
        self.info("Delete Mempool service")

