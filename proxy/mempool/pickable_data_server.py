from abc import ABC, abstractmethod
import asyncio
import socket
import pickle
import struct
from typing import Any
from logged_groups import logged_group


class PickableDataServerUser(ABC):

    @abstractmethod
    def on_data_received(self, data: Any):
        """Gets neon_tx_data from the neon rpc api service worker"""


@logged_group("neon.MemPool")
class PickableDataServer(ABC):

    def __init__(self, *, user: PickableDataServerUser, host: str, port: int):
        self._user = user
        self._port = port
        self._host = host

    async def handle_client(self, client):
        loop = asyncio.get_event_loop()
        peer_name = client.getpeername()
        self.debug(f"Got new incoming connection: {peer_name}")
        while True:
            try:
                len_packed: bytes = await loop.sock_recv(client, 4)
                if len(len_packed) == 0:
                    break
                # TODO: all the data can be received by parts, handle it
                payload_len_data = struct.unpack("!I", len_packed[:4])[0]
                payload = await loop.sock_recv(client, payload_len_data)
                data = pickle.loads(payload)
                self._user.on_data_received(data)
            except ConnectionResetError:
                self.error(f"Client connection: {peer_name} - has been interrupted")
                break
            except Exception as err:
                self.error(f"Failed to receive data over: {peer_name} - err: {err}")
                continue
        client.close()

    async def run_server(self):
        self.info(f"Listen port: {self._port} on: {self._host}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self._host, self._port))
        server.listen(8)
        server.setblocking(False)

        loop = asyncio.get_event_loop()
        while True:
            client, _ = await loop.sock_accept(server)
            loop.create_task(self.handle_client(client))
