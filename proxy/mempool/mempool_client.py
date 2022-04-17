import socket
import pickle
import struct
from logged_groups import logged_group


from ..common_neon.data import NeonTxData


@logged_group("neon.Proxy")
class MemPoolClient:

    def __init__(self, host: str, port: int):

        self.info(f"Initialize MemPoolClient connecting to: {port} at: {host}")
        self._connection = socket.create_connection((host, port))

    def on_eth_send_raw_transaction(self, neon_tx_data: NeonTxData):
        try:
            self.debug(f"Send transaction: {neon_tx_data}")
            payload = self.decode_neon_tx_data(neon_tx_data)
            self._connection.send(payload)
        except BaseException as err:
            self.error(f"Failed to enqueue raw transaction into mempool: {err}")
            raise Exception("Failed to enqueue neon tx")

    def decode_neon_tx_data(self, neon_tx_data: NeonTxData):
        data = pickle.dumps(neon_tx_data)
        data_len = len(data)
        packed_len = struct.pack("!I", data_len)
        payload = packed_len + data
        return payload

    def __del__(self):
        self._connection.close()
