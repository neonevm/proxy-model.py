from logged_groups import logged_group
from neon_py.network import AddrPickableDataClient

from .data import NeonTxStatData

from ..common_neon.config import Config


@logged_group("neon.Statistic")
class IndexerStatClient:
    STAT_MIDDLEWARE_ADDRESS = ("127.0.0.1", 9093)

    def __init__(self, config: Config):
        self.info(f'Init statistic middleware client, enabled: {config.gather_statistics}')
        self._enabled = config.gather_statistics
        if not self._enabled:
            return
        self._stat_mng_client = AddrPickableDataClient(self.STAT_MIDDLEWARE_ADDRESS)

    def _stat_method(method):
        def wrapper(self, *args):
            if not self._enabled:
                return
            self._stat_mng_client.send_data((method.__name__, *args))
        return wrapper

    @_stat_method
    def commit_db_health(self, status: bool): pass

    @_stat_method
    def commit_solana_rpc_health(self, status: bool): pass

    @_stat_method
    def commit_neon_tx_result(self, tx_stat: NeonTxStatData): pass
