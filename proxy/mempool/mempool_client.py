from ..common_neon.data import NeonTxData

from ..common_neon.utils import PickableDataClient


class MemPoolClient:

    def __init__(self, host: str, port: int):
        self._pickable_data_client = PickableDataClient(host, port)

    def send_raw_transaction(self, neon_tx_data: NeonTxData):
        self._pickable_data_client.send_data(neon_tx_data)
