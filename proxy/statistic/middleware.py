from __future__ import annotations

import asyncio
import abc
import threading

from typing import Any, Tuple, Optional
from multiprocessing import Process

from aioprometheus.service import Service, Registry

from logged_groups import logged_group
from neon_py.network import IPickableDataServerUser, AddrPickableDataSrv, AddrPickableDataClient

from ..common_neon.config import Config


@logged_group("neon.Statistic")
class StatMiddlewareServer(IPickableDataServerUser):
    _stat_middleware_address = ('0.0.0.0', 9093)

    def __init__(self, stat_exporter: StatService):
        self._stat_srv = AddrPickableDataSrv(user=self, address=self._stat_middleware_address)
        self._stat_exporter = stat_exporter

    async def on_data_received(self, data: Tuple[str, ...]) -> Any:
        try:
            if hasattr(self._stat_exporter, data[0]):
                m = getattr(self._stat_exporter, data[0])
                m(*data[1:])
        except Exception as err:
            self.error(f'Failed to process statistic data: {data}', exc_info=err)

    async def start(self):
        await self._stat_srv.run_server()


@logged_group("neon.Statistic")
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
            self.debug(f"Serving prometheus metrics on: {self._prometheus_srv.metrics_url}")

            self._event_loop.run_until_complete(self._stat_middleware_srv.start())
            self._process_init()
            self._event_loop.run_forever()
        except Exception as err:
            self.error('Failed to process statistic service', exc_info=err)

    def _process_init(self) -> None:
        pass


def stat_method(method):
    def wrapper(self, *args):
        if not self._enabled:
            return

        if self._stat_mng_client is None:
            return

        with self._middleware_conn_lock:
            try:
                self._stat_mng_client.send_data((method.__name__, *args))
            except (InterruptedError, Exception) as err:
                self.error(f'Failed to transfer data', exc_info=err)
                self._reconnect_middleware()

    return wrapper


@logged_group("neon.Statistic")
class StatClient:
    _reconnect_middleware_time_sec = 1
    _stat_middleware_address = ("127.0.0.1", 9093)

    def __init__(self, config: Config):
        self.info(f'Init statistic middleware client, enabled: {config.gather_statistics}')
        self._enabled = config.gather_statistics
        if not self._enabled:
            return

        self._stat_mng_client: Optional[AddrPickableDataClient] = None
        self._middleware_conn_lock = threading.Lock()
        self._is_connecting = threading.Event()
        self._connect_middleware()

    def _reconnect_middleware(self):
        if self._is_connecting.is_set():
            return

        self._is_connecting.set()
        self.debug(f'Reconnecting statistic middleware server in: {self._reconnect_middleware_time_sec} sec')
        threading.Timer(self._reconnect_middleware_time_sec, self._connect_middleware).start()

    def _connect_middleware(self):
        try:
            self.debug(f'Connect statistic middleware server: {self._stat_middleware_address}')
            self._stat_mng_client = AddrPickableDataClient(self._stat_middleware_address)
        except ConnectionRefusedError:
            self._is_connecting.clear()
            self._reconnect_middleware()
        except BaseException as exc:
            if not isinstance(exc, ConnectionRefusedError):
                self.error(
                    f'Failed to connect statistic middleware server: {self._stat_middleware_address}',
                    exc_info=exc
                )
            else:
                self.debug(
                    f'Failed to connect statistic middleware server: {self._stat_middleware_address}, '
                    f'error: {str(exc)}'
                )
            self._is_connecting.clear()
            self._reconnect_middleware()
        finally:
            self._is_connecting.clear()
