from proxy.common_neon.utils import QueueBasedServiceClient
from logged_groups import logged_group
from .mempool_service import MemPoolService


@logged_group("neon")
class MemPoolClient(QueueBasedServiceClient):

    MEM_POOL_SERVICE_HOST = "127.0.0.1"

    def __init__(self):
        self.info("Construct MemPoolClient")
        QueueBasedServiceClient.__init__(self, self.MEM_POOL_SERVICE_HOST, MemPoolService.MEM_POOL_SERVICE_PORT)

    def on_eth_send_raw_transaction(self, eth_trx_signature):
        self.invoke("on_eth_send_raw_transaction", eth_trx_hash=eth_trx_signature)
