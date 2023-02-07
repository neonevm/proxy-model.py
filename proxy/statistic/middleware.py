from __future__ import annotations

import asyncio
import abc
import threading
import time
import math
import logging
from typing import Tuple, Optional
from multiprocessing import Process

from aioprometheus.service import Service, Registry

from ..common_neon.config import Config
from ..common_neon.pickable_data_server import encode_pickable
from ..common_neon.pickable_data_server import IPickableDataServerUser, AddrPickableDataSrv, AddrPickableDataClient


LOG = logging.getLogger(__name__)


class StatDataSrv(AddrPickableDataSrv):
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while True:
            try:
                # LOG.debug("Got incoming connection. Waiting for pickable data")
                data = await self._recv_pickable_data(reader)
                await self._user.on_data_received(data)
            except ConnectionResetError as err:
                LOG.warning(f"Connection reset error: {err}")
                break
            except asyncio.exceptions.IncompleteReadError as err:
                LOG.error(f"Incomplete read error: {err}")
                break
            except Exception as err:
                LOG.error(f"Failed to receive data err: {err}")
                break


class StatMiddlewareServer(IPickableDataServerUser):
    _stat_address = ('0.0.0.0', 9093)

    def __init__(self, stat_exporter: StatService):
        self._stat_srv = StatDataSrv(user=self, address=self._stat_address)
        self._stat_exporter = stat_exporter

    async def on_data_received(self, data: Tuple[str, ...]) -> None:
        try:
            if hasattr(self._stat_exporter, data[0]):
                m = getattr(self._stat_exporter, data[0])
                m(*data[1:])
        except Exception as err:
            LOG.error(f'Failed to process statistic data: {data}', exc_info=err)

    async def start(self):
        await self._stat_srv.run_server()


class StatService(abc.ABC):
    _prometheus_srv_address = ("0.0.0.0", 8888)

    def __init__(self, config: Config):
        self._config = config
        self._stat_middleware_srv = StatMiddlewareServer(self)
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._registry: Optional[Registry] = None
        self._prometheus_srv: Optional[Service] = None

        self._process = Process(target=self._run)

    @abc.abstractmethod
    def _init_metric_list(self) -> None:
        pass

    def start(self) -> None:
        if self._config.gather_statistics:
            self._process.start()

    def _run(self) -> None:
        try:
            self._event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._event_loop)

            self._registry = Registry()
            self._prometheus_srv = Service(registry=self._registry)
            self._init_metric_list()

            self._event_loop.run_until_complete(self._prometheus_srv.start(*self._prometheus_srv_address))
            LOG.debug(f"Serving prometheus metrics on: {self._prometheus_srv.metrics_url}")

            self._event_loop.run_until_complete(self._stat_middleware_srv.start())
            self._process_init()
            self._event_loop.run_forever()
        except Exception as err:
            LOG.error('Failed to process statistic service', exc_info=err)

    def _process_init(self) -> None:
        pass


def stat_method(method):
    def wrapper(self: StatClient, *args):
        if not self._is_enabled:
            return

        if (not self._is_connected()) and (not self._is_time_for_connect()):
            return

        with self._conn_lock:
            try:
                self._connect_middleware()
                if not self._is_connected():
                    return

                payload: bytes = encode_pickable((method.__name__, *args))
                self._stat_mng_client._client_sock.sendall(payload)
            except (InterruptedError, Exception) as exc:
                LOG.error(f'Failed to transfer data', exc_info=exc)
                self._reconnect_middleware()

    return wrapper


class StatClient:
    _reconnect_time_sec = 1
    _stat_address = ("127.0.0.1", 9093)

    def __init__(self, config: Config):
        LOG.info(f'Init statistic middleware client, enabled: {config.gather_statistics}')
        self._is_enabled = config.gather_statistics
        if not self._is_enabled:
            return

        self._stat_mng_client: Optional[AddrPickableDataClient] = None
        self._conn_lock = threading.Lock()
        self._last_connect_time_sec = 0

    @staticmethod
    def _current_time() -> int:
        return math.ceil(time.time())

    def _is_connected(self) -> bool:
        return self._stat_mng_client is not None

    def _is_time_for_connect(self) -> bool:
        if self._is_connected():
            return False

        now = self._current_time()
        if abs(self._last_connect_time_sec - now) > self._reconnect_time_sec:
            return False

        self._last_connect_time_sec = now
        return True

    def start(self) -> None:
        if self._is_enabled:
            self._connect_middleware()

    def _reconnect_middleware(self):
        LOG.debug(f'Reconnecting statistic middleware server in: {self._reconnect_time_sec} sec')
        self._stat_mng_client: Optional[AddrPickableDataClient] = None

    def _connect_middleware(self) -> bool:
        if self._is_connected():
            return True

        try:
            LOG.debug(f'Connect statistic middleware server: {self._stat_address}')
            self._stat_mng_client = AddrPickableDataClient(self._stat_address)
            return True
        except BaseException as exc:
            if not isinstance(exc, ConnectionRefusedError):
                LOG.error(f'Failed to connect statistic middleware server: {self._stat_address}', exc_info=exc)
            else:
                LOG.debug(f'Failed to connect statistic middleware server: {self._stat_address}, error: {str(exc)}')
            return False
