from __future__ import annotations

import asyncio
import abc

from typing import Any, Tuple, Optional
from multiprocessing import Process

from aioprometheus.service import Service, Registry

from logged_groups import logged_group
from neon_py.network import IPickableDataServerUser, AddrPickableDataSrv

from ..common_neon.config import Config


@logged_group("neon.Statistic")
class StatMiddlewareServer(IPickableDataServerUser):
    STAT_MIDDLEWARE_ADDRESS = ('0.0.0.0', 9093)

    def __init__(self, stat_exporter: StatService):
        self._stat_srv = AddrPickableDataSrv(user=self, address=self.STAT_MIDDLEWARE_ADDRESS)
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
    PROMETHEUS_SRV_ADDRESS = ("0.0.0.0", 8888)

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

            self._event_loop.run_until_complete(self._prometheus_srv.start(
                addr=self.PROMETHEUS_SRV_ADDRESS[0], port=self.PROMETHEUS_SRV_ADDRESS[1]
            ))
            self.debug(f"Serving prometheus metrics on: {self._prometheus_srv.metrics_url}")

            self._event_loop.run_until_complete(self._stat_middleware_srv.start())
            self._process_init()
            self._event_loop.run_forever()
        except Exception as err:
            self.error('Failed to process statistic service', exc_info=err)

    def _process_init(self) -> None:
        pass

