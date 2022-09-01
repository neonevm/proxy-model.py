from decimal import Decimal
from typing import Any, Tuple

from logged_groups import logged_group
from neon_py.network import IPickableDataServerUser, AddrPickableDataSrv, AddrPickableDataClient

from ..data import NeonTxStatData

from .i_statistic_exporter import IStatisticsExporter


@logged_group("neon.Statistic")
class StatisticMiddlewareServer(IPickableDataServerUser):

    STATISTIC_MIDDLEWARE_ADDRESS = ("0.0.0.0", 9093)

    def __init__(self, stat_exporter: Any):
        self._stat_srv = AddrPickableDataSrv(user=self, address=self.STATISTIC_MIDDLEWARE_ADDRESS)
        self._stat_exporter = stat_exporter

    async def on_data_received(self, data: Tuple[str, ...]) -> Any:
        try:
            if hasattr(self._stat_exporter, data[0]):
                m = getattr(self._stat_exporter, data[0])
                m(*data[1:])
        except Exception as err:
            self.error(f"Failed to process statistic data: {data}, err: {err}")

    async def start(self):
        await self._stat_srv.run_server()


@logged_group("neon.Statistic")
class StatisticMiddlewareClient(IStatisticsExporter):

    STATISTIC_MIDDLEWARE_ADDRESS = ("127.0.0.1", 9093)

    def __init__(self, enabled: bool = True):
        self.info(f"Init statistic middleware client, enabled: {enabled}")
        self._enabled = enabled
        if not enabled:
            return
        self._stat_mng_client = AddrPickableDataClient(self.STATISTIC_MIDDLEWARE_ADDRESS)

    def _stat_method(method):
        def wrapper(self, *args):
            if not self._enabled:
                return
            self._stat_mng_client.send_data((method.__name__, *args))
        return wrapper

    @_stat_method
    def stat_commit_request_and_timeout(self, method: str, latency: float): pass

    @_stat_method
    def stat_commit_tx_begin(self): pass

    @_stat_method
    def stat_commit_tx_end_success(self): pass

    @_stat_method
    def stat_commit_tx_end_failed(self): pass

    @_stat_method
    def stat_commit_tx_sol_spent(self, *args): pass

    @_stat_method
    def stat_commit_tx_steps_bpf(self, *args): pass

    @_stat_method
    def stat_commit_tx_count(self, *args): pass

    @_stat_method
    def stat_commit_count_sol_tx_per_neon_tx(self, *args): pass

    @_stat_method
    def stat_commit_postgres_availability(self, *args): pass

    @_stat_method
    def stat_commit_solana_rpc_health(self, *args): pass

    @_stat_method
    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: Decimal): pass

    @_stat_method
    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: Decimal): pass

    @_stat_method
    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal): pass

    @_stat_method
    def stat_commit_neon_tx_result(self, tx_stat: NeonTxStatData): pass
