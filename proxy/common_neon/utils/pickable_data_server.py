from typing import Any, Tuple
from abc import ABC, abstractmethod

import asyncio
from asyncio import StreamReader, StreamWriter
import socket
import pickle
import struct
from logged_groups import logged_group


class PickableDataServerUser(ABC):

    @abstractmethod
    async def on_data_received(self, data: Any) -> Any:
        """Gets neon_tx_data from the neon rpc api service worker"""


def encode_pickable(object) -> bytes:
    data = pickle.dumps(object)
    len_data = struct.pack("!I", len(data))
    return len_data + data


@logged_group("neon.MemPool")
class PickableDataServer(ABC):

    def __init__(self, *, user: PickableDataServerUser):
        self._user = user
        asyncio.get_event_loop().create_task(self.run_server())

    @abstractmethod
    async def run_server(self):
        assert False

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        while True:
            try:
                data = await self._recv_pickable_data(reader)
                result = await self._user.on_data_received(data)
                result_data = encode_pickable(result)
                writer.write(result_data)
                await writer.drain()
            except ConnectionResetError:
                self.error(f"Client connection has been closed")
                break
            except asyncio.exceptions.IncompleteReadError as err:
                self.error(f"Incomplete read error: {err}")
                break
            except Exception as err:
                self.error(f"Failed to receive data err: {err}, type: {type(err)}")
                break

    async def _recv_pickable_data(self, reader: StreamReader):
        len_packed: bytes = await reader.read(4)
        if len(len_packed) == 0:
            raise ConnectionResetError()
        payload_len_data = struct.unpack("!I", len_packed)[0]
        payload = await reader.read(payload_len_data)
        data = pickle.loads(payload)

        return data


class AddrPickableDataSrv(PickableDataServer):

    def __init__(self, *, user: PickableDataServerUser, address: Tuple[str, int]):
        self._address = address
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        host, port = self._address
        self.info(f"Listen port: {port} on: {host}")
        await asyncio.start_server(self.handle_client, host, port)


class PipePickableDataSrv(PickableDataServer):

    def __init__(self, *, user: PickableDataServerUser, srv_sock: socket.socket):
        self._srv_sock = srv_sock
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        reader, writer = await asyncio.streams.open_connection(sock=self._srv_sock)
        await self.handle_client(reader, writer)


@logged_group("neon.Proxy")
class PickableDataClient:

    CONNECTION_TIMEOUT_SEC = 600

    def __init__(self):
        self._client_sock = None

    def _set_client_sock(self, client_sock: socket.socket):
        self._client_sock = client_sock

    def send_data(self, pickable_object: Any):
        try:
            payload = encode_pickable(pickable_object)
            sent = self._client_sock.send(payload)
            len_packed: bytes = self._client_sock.recv(4)
            data_len = struct.unpack("!I", len_packed)[0]
            data = self._client_sock.recv(data_len)
            if not data:
                return None
            result = pickle.loads(data)
            return result
        except BaseException as err:
            self.error(f"Failed to send data: {err}")
            raise Exception("Failed to send pickable data")

    async def send_data_async(self, pickable_object):
        reader, writer = await asyncio.streams.open_connection(sock=self._client_sock)
        try:
            payload = encode_pickable(pickable_object)
            writer.write(payload)
            await writer.drain()
            len_packed: bytes = await reader.readexactly(4)
            if not len_packed:
                return None
            data_len = struct.unpack("!I", len_packed)[0]
            data = await reader.readexactly(data_len)
            if not data:
                return None
            result = pickle.loads(data)
            return result
        except BaseException as err:
            self.error(f"Failed to send data: {err}")
            raise Exception("Failed to send pickable data")



class PipePickableDataClient(PickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PickableDataClient.__init__(self)
        self._set_client_sock(client_sock=client_sock)


class AddrPickableDataClient(PickableDataClient):

    def __init__(self, addr: Tuple[str, int]):
        PickableDataClient.__init__(self)
        host, port = addr
        client_sock = socket.create_connection((host, port))
        self._set_client_sock(client_sock=client_sock)

