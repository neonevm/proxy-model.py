from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor

from ..statistic.proxy_client import ProxyStatClient

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient


class MPExecutorBaseTask:
    def __init__(
        self, config: Config,
        solana: SolInteractor,
        core_api_client: NeonCoreApiClient,
        stat_client: ProxyStatClient
    ):
        self._config = config
        self._solana = solana
        self._core_api_client = core_api_client
        self._stat_client = stat_client
