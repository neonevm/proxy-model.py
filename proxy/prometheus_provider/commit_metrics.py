from typing import Union


def stat_commit_request_and_timeout(endpoint: str, latency: float):
    from .proxy_metrics import (
        REQUEST_COUNT, REQUEST_LATENCY,
    )
    REQUEST_COUNT.labels(endpoint).inc()
    REQUEST_LATENCY.labels(endpoint).observe(latency)

def stat_commit_incoming_tx():
    from .proxy_metrics import (
        TX_TOTAL, TX_IN_PROGRESS
    )
    TX_TOTAL.inc()
    TX_IN_PROGRESS.inc()

def stat_commit_success_tx(sol_acc: str, sol_diff: int, neon_acc: str, neon_diff: int):
    from .proxy_metrics import (
        TX_SUCCESS, TX_IN_PROGRESS,
        OPERATOR_SOL_BALANCE_DIFF,
        OPERATOR_NEON_BALANCE_DIFF,
    )
    TX_SUCCESS.inc()
    TX_IN_PROGRESS.dec()
    OPERATOR_SOL_BALANCE_DIFF.labels(sol_acc).set(sol_diff)
    OPERATOR_NEON_BALANCE_DIFF.labels(neon_acc).set(neon_diff)

def stat_commit_failed_tx(err: Exception):
    from .proxy_metrics import (
        TX_FAILED, TX_IN_PROGRESS
    )
    TX_FAILED.inc()
    TX_IN_PROGRESS.dec()

def stat_commit_operator_balance(operator: str, sol_balance: int):
    from .proxy_metrics import (
        OPERATOR_SOL_BALANCE
    )
    OPERATOR_SOL_BALANCE.labels(operator).set(sol_balance)

def stat_commit_operator_neon_balance(neon_acc: str, neon_balance: int):
    from .proxy_metrics import (
        OPERATOR_NEON_BALANCE
    )
    OPERATOR_NEON_BALANCE.labels(neon_acc).set(neon_balance)

def stat_commit_create_stage_account(account: str, rent: int):
    from .proxy_metrics import (
        OPERATOR_ACCOUNT_RENT
    )
    OPERATOR_ACCOUNT_RENT.labels(account).set(rent)

def stat_commit_min_gas_price(gas_price: int, sol_price_usd: float, neon_price_usd: float, operator_fee: float):
    from .proxy_metrics import (
        USD_PRISE_NEON, USD_PRISE_SOL, OPERATOR_FEE, GAS_PRICE
    )
    USD_PRISE_NEON.set(neon_price_usd)
    USD_PRISE_SOL.set(sol_price_usd)
    OPERATOR_FEE.set(operator_fee)
    GAS_PRICE.set(gas_price)

def stat_register_get_operator_balance(account, function):
    from .proxy_metrics import (
        OPERATOR_BALANCE
    )
    OPERATOR_BALANCE.labels(account).set_function(function)

def stat_register_get_operator_neon_balance(account, function):
    from .proxy_metrics import (
        OPERATOR_NEON_BALANCE
    )
    OPERATOR_NEON_BALANCE.labels(account).set_function(function)

def stat_register_get_solana_node_status():
    pass

def stat_register_get_postgres_status():
    pass
