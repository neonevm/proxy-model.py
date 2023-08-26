import abc
import asyncio
import logging

from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.config import Config

LOG = logging.getLogger(__name__)


class IHealthStatService(abc.ABC):
    @abc.abstractmethod
    def commit_solana_node_health(self, status: bool) -> None: pass

    @abc.abstractmethod
    def commit_solana_rpc_health(self, status: bool) -> None: pass

    @abc.abstractmethod
    def commit_db_health(self, status: bool) -> None: pass


class StatDataPeeker:
    def __init__(self, config: Config, stat_srv: IHealthStatService):
        self._stat_service = stat_srv
        self._solana = SolInteractor(config)
        self._db_conn = DBConnection(config)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                await self._run()
            except BaseException as err:
                LOG.warning('Error on statistic processing', exc_info=err)

    async def _run(self) -> None:
        self._stat_solana_node_health()
        self._stat_db_health()

    def _stat_solana_node_health(self) -> None:
        is_healthy = self._solana.is_healthy()
        if is_healthy is None:
            self._stat_service.commit_solana_node_health(False)
            self._stat_service.commit_solana_rpc_health(False)
        elif is_healthy:
            self._stat_service.commit_solana_node_health(True)
            self._stat_service.commit_solana_rpc_health(True)
        else:
            self._stat_service.commit_solana_node_health(False)
            self._stat_service.commit_solana_rpc_health(True)

    def _stat_db_health(self) -> None:
        self._stat_service.commit_db_health(self._db_conn.is_connected())
