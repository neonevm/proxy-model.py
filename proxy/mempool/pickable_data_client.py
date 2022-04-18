import socket
import pickle
import struct
from typing import Any
from logged_groups import logged_group


@logged_group("neon.Proxy")
class PickableDataClient:

    def __init__(self, host: str, port: int):

        self.info(f"Initialize PickableDataClient connecting to: {port} at: {host}")
        self._connection = socket.create_connection((host, port))

    def send_data(self, pickable_data: Any):
        try:
            payload = self._encode_pickable_data(pickable_data)
            self._connection.send(payload)
        except BaseException as err:
            self.error(f"Failed to send data: {err}")
            raise Exception("Failed to send pickable data")

    def _encode_pickable_data(self, pickable_data: Any):
        data = pickle.dumps(pickable_data)
        data_len = len(data)
        packed_len = struct.pack("!I", data_len)
        payload = packed_len + data
        return payload

    def __del__(self):
        self._connection.close()
