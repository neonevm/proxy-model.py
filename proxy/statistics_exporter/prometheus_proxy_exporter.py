from decimal import Decimal
from typing import Optional

from neon_py.network import AddrPickableDataClient

from .proxy_metrics_interface import IStatisticsExporter


class StatMiddleware:

    def __init__(self):
        self._stat_mng_client = AddrPickableDataClient(("127.0.0.1", 9093))

    def _stat_method(method):
        def wrapper(self, *args):
            self._stat_mng_client.send_data((method.__name__, * args))
        return wrapper

    @_stat_method
    def stat_commit_request_and_timeout(self, method: str, latency: float):
        pass


class PrometheusExporter():

    def stat_commit_tx_begin(self):
        from .prometheus_proxy_metrics import (
            TX_TOTAL, TX_IN_PROGRESS
        )
        TX_TOTAL.inc()
        TX_IN_PROGRESS.inc()

    def stat_commit_tx_end_success(self):
        from .prometheus_proxy_metrics import (
            TX_SUCCESS, TX_IN_PROGRESS,
        )
        TX_SUCCESS.inc()
        TX_IN_PROGRESS.dec()

    def stat_commit_tx_end_failed(self, _err: Optional[Exception]):
        from .prometheus_proxy_metrics import (
            TX_FAILED, TX_IN_PROGRESS
        )
        TX_FAILED.inc()
        TX_IN_PROGRESS.dec()

    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: Decimal):
        from .prometheus_proxy_metrics import (
            OPERATOR_SOL_BALANCE
        )
        OPERATOR_SOL_BALANCE.labels(operator).set(sol_balance)

    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: Decimal):
        from .prometheus_proxy_metrics import (
            OPERATOR_NEON_BALANCE
        )
        OPERATOR_NEON_BALANCE.labels(sol_acc, neon_acc).set(neon_balance)

    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal):
        from .prometheus_proxy_metrics import (
            USD_PRICE_NEON, USD_PRICE_SOL, OPERATOR_FEE, GAS_PRICE
        )
        USD_PRICE_NEON.set(neon_price_usd)
        USD_PRICE_SOL.set(sol_price_usd)
        OPERATOR_FEE.set(operator_fee)
        GAS_PRICE.set(gas_price)

    def stat_commit_tx_sol_spent(self, *args):
        pass

    def stat_commit_tx_steps_bpf(self, *args):
        pass

    def stat_commit_tx_count(self, *args):
        pass

    def stat_commit_count_sol_tx_per_neon_tx(self, *args):
        pass

    def stat_commit_postgres_availability(self, *args):
        pass

    def stat_commit_solana_rpc_health(self, *args):
        pass

