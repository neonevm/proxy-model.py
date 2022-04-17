import socket
import pickle
import struct
from logged_groups import logged_group
from typing import Any


@logged_group("neon.Proxy")
class PickableDataClient:

    def __init__(self, host: str, port: int):

        self.info(f"Initialize PickableDataClient connecting to: {port} at: {host}")
        self._connection = socket.create_connection((host, port))

    def send_data(self, pickable_data: Any):
        try:
            payload = self._encode_pickable_data(pickable_data)
            sent_bytes = self._connection.send(payload)
            # self.debug(f"Sent bytes: {sent_bytes}")
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
