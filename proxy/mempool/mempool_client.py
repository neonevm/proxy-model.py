from logged_groups import logged_group

from ..common_neon.utils import AddrPickableDataClient

from .mempool_api import MemPoolRequest


@logged_group("neon.Proxy")
class MemPoolClient:

    def __init__(self, host: str, port: int):
        self._pickable_data_client = AddrPickableDataClient((host, port))

    def send_raw_transaction(self, mempool_tx_request: MemPoolRequest):
        return self._pickable_data_client.send_data(mempool_tx_request)

    def __del__(self):
        self.debug("mempool_client garbage collected")
