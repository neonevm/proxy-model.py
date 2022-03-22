from .common_metrics import StatisticsExporter


class PrometheusExporter(StatisticsExporter):
    def stat_commit_request_and_timeout(self, endpoint: str, latency: float):
        from .prometheus_metrics import (
            REQUEST_COUNT, REQUEST_LATENCY,
        )
        REQUEST_COUNT.labels(endpoint).inc()
        REQUEST_LATENCY.labels(endpoint).observe(latency)

    def stat_commit_tx_begin(self):
        from .prometheus_metrics import (
            TX_TOTAL, TX_IN_PROGRESS
        )
        TX_TOTAL.inc()
        TX_IN_PROGRESS.inc()

    def stat_commit_tx_end_success(self):
        from .prometheus_metrics import (
            TX_SUCCESS, TX_IN_PROGRESS,
        )
        TX_SUCCESS.inc()
        TX_IN_PROGRESS.dec()

    def stat_commit_tx_end_failed(self, _err: Exception):
        from .prometheus_metrics import (
            TX_FAILED, TX_IN_PROGRESS
        )
        TX_FAILED.inc()
        TX_IN_PROGRESS.dec()

    def stat_commit_tx_balance_change(self, sol_acc: str, sol_diff: int, neon_acc: str, neon_diff: int):
        from .prometheus_metrics import (
            OPERATOR_SOL_BALANCE_DIFF,
            OPERATOR_NEON_BALANCE_DIFF,
        )
        OPERATOR_SOL_BALANCE_DIFF.labels(sol_acc).set(sol_diff)
        OPERATOR_NEON_BALANCE_DIFF.labels(neon_acc).set(neon_diff)

    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: int):
        from .prometheus_metrics import (
            OPERATOR_SOL_BALANCE
        )
        OPERATOR_SOL_BALANCE.labels(operator).set(sol_balance)

    def stat_commit_operator_neon_balance(self, neon_acc: str, neon_balance: int):
        from .prometheus_metrics import (
            OPERATOR_NEON_BALANCE
        )
        OPERATOR_NEON_BALANCE.labels(neon_acc).set(neon_balance)

    def stat_commit_create_resource_account(self, account: str, rent: int):
        from .prometheus_metrics import (
            OPERATOR_ACCOUNT_RENT
        )
        OPERATOR_ACCOUNT_RENT.labels(account).set(rent)

    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: float, neon_price_usd: float, operator_fee: float):
        from .prometheus_metrics import (
            USD_PRISE_NEON, USD_PRISE_SOL, OPERATOR_FEE, GAS_PRICE
        )
        USD_PRISE_NEON.set(neon_price_usd)
        USD_PRISE_SOL.set(sol_price_usd)
        OPERATOR_FEE.set(operator_fee)
        GAS_PRICE.set(gas_price)

