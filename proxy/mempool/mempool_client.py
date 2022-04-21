from ..common_neon.utils import AddrPickableDataClient

from .mempool_api import MemPoolTxRequest


class MemPoolClient:

    def __init__(self, host: str, port: int):
        self._pickable_data_client = AddrPickableDataClient((host, port))

    def send_raw_transaction(self, mempool_tx_request: MemPoolTxRequest):
        self._pickable_data_client.send_data(mempool_tx_request)
