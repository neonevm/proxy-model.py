from prometheus_client import multiprocess
from prometheus_client import generate_latest, Gauge, Counter, Summary, Histogram, REGISTRY

registry = REGISTRY
multiprocess_registry = multiprocess.MultiProcessCollector(registry)

REQUEST_COUNT = Counter(
    'request_count', 'App Request Count',
    ['endpoint'],
    registry=registry,
)
REQUEST_LATENCY = Histogram('request_latency_seconds', 'Request latency',
    ['endpoint'],
    registry=registry,
)
TX_TOTAL = Counter('tx_count', 'Incoming TX Count', registry=registry)
TX_SUCCESS = Counter('tx_success_count', 'Count Of Succeeded Txs', registry=registry)
TX_FAILED = Counter('tx_failed_count', 'Count Of Failed Txs', registry=registry)
TX_IN_PROGRESS = Gauge('tx_in_progress', 'Count Of Txs Currently Processed', registry=registry)
OPERATOR_SOL_BALANCE = Gauge(
    'operator_sol_balance', 'Operator Sol Balance',
    ['operator_sol_wallet'],
    registry=registry,
)
OPERATOR_NEON_BALANCE = Gauge(
    'operator_neon_balance', 'Operator Neon Balance',
    ['operator_neon_wallet'],
    registry=registry,
)
OPERATOR_SOL_BALANCE_DIFF = Gauge(
    'operator_sol_balance_diff', 'Operator Sol Balance Diff On TX',
    ['operator_sol_wallet'],
    registry=registry,
)
OPERATOR_NEON_BALANCE_DIFF = Gauge(
    'operator_neon_balance_diff', 'Operator Neon Balance Diff On TX',
    ['operator_neon_wallet'],
    registry=registry,
)
OPERATOR_ACCOUNT_RENT = Gauge(
    'operator_account_rent', 'Operator Account Rent',
    ['account'],
    registry=registry,
)
USD_PRISE_SOL = Gauge(
    'usd_prise_sol', 'Sol Price USD',
    registry=registry,
)
USD_PRISE_NEON = Gauge(
    'usd_prise_neon', 'Neon Price USD',
    registry=registry,
)
GAS_PRICE = Gauge(
    'gas_pice', 'Gas price',
    registry=registry,
)
OPERATOR_FEE = Gauge(
    'operator_fee', 'Operator Fee',
    registry=registry,
)
