from logged_groups import logged_group
from neon_py.network import AddrPickableDataClient

from .data import NeonMethodData, NeonGasPriceData, NeonOpListData

from ..common_neon.config import Config


@logged_group("neon.Statistic")
class ProxyStatClient:
    STAT_MIDDLEWARE_ADDRESS = ("127.0.0.1", 9093)

    def __init__(self, config: Config):
        self.info(f"Init statistic middleware client, enabled: {config.gather_statistics}")
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
    def commit_request_and_timeout(self, method_stat: NeonMethodData): pass

    @_stat_method
    def commit_tx_begin(self): pass

    @_stat_method
    def commit_tx_end_success(self): pass

    @_stat_method
    def commit_tx_end_failed(self): pass

    @_stat_method
    def commit_tx_end_reschedule(self): pass

    @_stat_method
    def commit_op_list(self, balance_stat: NeonOpListData): pass

    @_stat_method
    def commit_gas_price(self, gas_stat: NeonGasPriceData): pass
