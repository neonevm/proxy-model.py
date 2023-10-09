from typing import Any, Tuple, Optional
from abc import ABC, abstractmethod
import asyncio
from asyncio import StreamReader, StreamWriter
import socket
import pickle
import struct
import logging


LOG = logging.getLogger(__name__)


class IPickableDataServerUser(ABC):

    @abstractmethod
    async def on_data_received(self, data: Any) -> Any:
        """Gets neon_tx_data from the neon rpc api service worker"""


class PickableDataServer(ABC):

    def __init__(self, *, user: IPickableDataServerUser):
        self._user = user
        asyncio.get_event_loop().create_task(self.run_server())

    @abstractmethod
    async def run_server(self):
        assert False

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        while True:
            try:
                # LOG.debug("Got incoming connection. Waiting for pickable data")
                data = await self._recv_pickable_data(reader)
                result = await self._user.on_data_received(data)
                # LOG.debug(f"Encode pickable result_data: {result}")
                result_data = encode_pickable(result)
                # LOG.debug(f"Send result_data: {len(result_data)}, bytes: {result_data.hex()}")
                writer.write(result_data)
                await writer.drain()
            except ConnectionResetError as err:
                LOG.warning(f"Connection reset error: {err}")
                break
            except asyncio.exceptions.IncompleteReadError as err:
                LOG.error(f"Incomplete read error: {err}")
                break
            except Exception as err:
                LOG.error(f"Failed to receive data err: {err}", exc_info=err)
                break

    async def _recv_pickable_data(self, reader: StreamReader):
        len_packed: bytes = await read_data_async(reader, 4)
        payload_len = struct.unpack("!I", len_packed)[0]
        # LOG.debug(f"Got payload len_packed: {len_packed.hex()}, that is: {payload_len}")
        payload = await read_data_async(reader, payload_len)
        data = pickle.loads(payload)
        # LOG.debug(f"Loaded pickable of type: {type(data)}")
        return data


class AddrPickableDataSrv(PickableDataServer):

    def __init__(self, *, user: IPickableDataServerUser, address: Tuple[str, int]):
        self._address = address
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        host, port = self._address
        LOG.info(f"Listen port: {port} on: {host}")
        await asyncio.start_server(self.handle_client, host, port)


class PipePickableDataSrv(PickableDataServer):

    def __init__(self, *, user: IPickableDataServerUser, srv_sock: socket.socket):
        self._srv_sock = srv_sock
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        reader, writer = await asyncio.streams.open_connection(sock=self._srv_sock)
        await self.handle_client(reader, writer)


class PickableDataClient:

    def __init__(self):
        self._client_sock: Optional[socket.socket] = None
        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None

    def _set_client_sock(self, client_sock: socket.socket):
        self._client_sock = client_sock

    async def async_init(self):
        LOG.info("Async init pickable data client")
        reader, writer = await asyncio.open_connection(sock=self._client_sock)
        self._reader = reader
        self._writer = writer

    def send_data(self, pickable_object: Any):
        try:
            payload: bytes = encode_pickable(pickable_object)
            # LOG.debug(f"Send object of type: {type(pickable_object)}, payload: {len(payload)}, bytes: 0x{payload[:15].hex()}")
            self._client_sock.sendall(payload)
        except BaseException as err:
            LOG.error(f"Failed to send client data: {err}")
            raise
        try:
            # LOG.debug(f"Waiting for answer")
            len_packed: bytes = read_data_sync(self._client_sock, 4)
            data_len = struct.unpack("!I", len_packed)[0]
            # LOG.debug(f"Got len_packed bytes: {len_packed.hex()}, that is: {data_len} - bytes to receive")

            data = read_data_sync(self._client_sock, data_len)
            # LOG.debug(f"Got data: {len(data)}. Load pickled object")
            result = pickle.loads(data)
            # LOG.debug(f"Got result: {result}")
            return result
        except BaseException as err:
            LOG.error(f"Failed to receive answer data: {err}")
            raise

    async def send_data_async(self, pickable_object):

        try:
            # LOG.debug(f"Send pickable_object of type: {type(pickable_object)}")
            payload = encode_pickable(pickable_object)
            # LOG.debug(f"Payload: {len(payload)}, bytes: {payload[:15].hex()}")
            self._writer.write(payload)
            await self._writer.drain()

        except BaseException as err:
            LOG.error(f"Failed to send client data: {err}")
            raise

        try:
            # LOG.debug(f"Waiting for answer")
            len_packed: bytes = await read_data_async(self._reader, 4)
            data_len = struct.unpack("!I", len_packed)[0]
            data = await read_data_async(self._reader, data_len)
            # LOG.debug(f"Got data: {len(data)}. Load pickled object")
            result = pickle.loads(data)
            # LOG.debug(f"Got result: {result}")
            return result

        except BaseException as err:
            LOG.error(f"Failed to receive answer data: {err}")
            raise


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


def encode_pickable(obj) -> bytes:
    data = pickle.dumps(obj)
    len_data = struct.pack("!I", len(data))
    # LOG.debug(f"Len data: {len(len_data)} - bytes, data: {len(data)} - bytes")
    return len_data + data


async def read_data_async(reader: StreamReader, data_len: int) -> bytes:
    data = b''
    while len(data) < data_len:
        to_be_read = data_len - len(data)
        # LOG.debug(f"Reading data: {to_be_read} of: {data_len} - bytes")
        chunk = await reader.read(to_be_read)
        if not chunk:
            raise EOFError(f"Failed to read chunk of data: {data_len}")
        # LOG.debug(f"Got chunk of data: {len(chunk)}")
        data += chunk
    return data


def read_data_sync(socket: socket.socket, data_len) -> bytes:
    data = b''
    while len(data) < data_len:
        to_be_read = data_len - len(data)
        # LOG.debug(f"Reading data: {to_be_read} of: {data_len} - bytes")
        chunk: bytes = socket.recv(to_be_read)
        # LOG.debug(f"Got chunk of data: {len(chunk)}")
        data += chunk
    return data
