from logged_groups import logged_group

from ..common_neon.utils import QueueBasedServiceClient
from ..common_neon import Result

from . import MemPoolService


@logged_group("neon.Proxy")
class MemPoolClient(QueueBasedServiceClient):

    MEM_POOL_SERVICE_HOST = "127.0.0.1"

    def __init__(self):
        port, host = (MemPoolService.MEM_POOL_SERVICE_PORT, self.MEM_POOL_SERVICE_HOST)
        self.info(f"Initialize MemPoolClient connecting to: {port} at: {host}")
        QueueBasedServiceClient.__init__(self, host, port)

    def on_eth_send_raw_transaction(self, eth_trx_signature) -> Result:
        return self.invoke("on_eth_send_raw_transaction", eth_trx_hash=eth_trx_signature)
