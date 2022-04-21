from ..common_neon.data import MemPoolTxCfg
from ..common_neon.utils import AddrPickableDataClient


class MemPoolClient:

    def __init__(self, host: str, port: int):
        self._pickable_data_client = AddrPickableDataClient((host, port))

    def send_raw_transaction(self, mempool_tx_cfg: MemPoolTxCfg):
        self._pickable_data_client.send_data(mempool_tx_cfg)
