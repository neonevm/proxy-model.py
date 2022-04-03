from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, start_http_server
from .indexer_metrics_interface import IndexerStatisticsExporter


class PrometheusExporter(IndexerStatisticsExporter):
    registry = CollectorRegistry()
    TX_SOL_SPENT = Histogram(
        'tx_sol_spent', 'How many lamports being spend in Neon transaction per iteration',
        ['neon_tx_hash', 'sol_tx_hash'],
        registry=registry
    )
    TX_BPF_PER_ITERATION = Histogram(
        'tx_bpf_per_iteration', 'How many BPF cycles was used in each iteration',
        ['neon_tx_hash', 'sol_tx_hash'],
        registry=registry
    )
    TX_STEPS_PER_ITERATION = Histogram(
        'tx_steps_per_iteration', 'How many steps was used in each iteration',
        ['neon_tx_hash', 'sol_tx_hash'],
        registry=registry
    )
    TX_COUNT = Counter('tx_count', 'Count of Neon transactions were completed (independent on status)', registry=registry)
    TX_CANCELED = Counter('tx_canceled', 'Count of Neon transactions were canceled', registry=registry)
    COUNT_TX_COUNT_BY_TYPE = Counter(
        'count_tx_count_by_type', 'Count of transactions by type(single\iter\iter w holder)',
        ['type'],
        registry=registry
    )
    COUNT_SOL_TX_PER_NEON_TX = Histogram(
        'count_sol_tx_per_neon_tx', 'Count of solana txs within by type(single\iter\iter w holder)',
        ['type'],
        registry=registry
    )
    POSTGRES_AVAILABILITY = Gauge('postgres_availability', 'Postgres availability', registry=registry)
    SOLANA_RPC_HEALTH = Gauge('solana_rpc_health', 'Solana Node status', registry=registry)

    def __init__(self):
        start_http_server(8887, registry=self.registry)
        pass

    def stat_commit_tx_sol_spent(self, neon_tx_hash: str, sol_tx_hash: str, sol_spent: int):
        self.TX_SOL_SPENT.labels(neon_tx_hash, sol_tx_hash).observe(sol_spent)
        pass

    def stat_commit_tx_steps_bpf(self, neon_tx_hash: str, sol_tx_hash: str, steps: int, bpf: int):
        if bpf:
            self.TX_BPF_PER_ITERATION.labels(neon_tx_hash, sol_tx_hash).observe(bpf)
        if steps:
            self.TX_STEPS_PER_ITERATION.labels(neon_tx_hash, sol_tx_hash).observe(steps)
        pass

    def stat_commit_tx_count(self, canceled: bool = False):
        self.TX_COUNT.inc()
        if canceled:
            self.TX_CANCELED.inc()
        pass

    def stat_commit_count_sol_tx_per_neon_tx(self, type: str, sol_tx_count: int):
        self.COUNT_TX_COUNT_BY_TYPE.labels(type).inc()
        self.COUNT_SOL_TX_PER_NEON_TX.labels(type).observe(sol_tx_count)
        pass

    def stat_commit_postgres_availability(self, status: bool):
        self.POSTGRES_AVAILABILITY.set(1 if status else 0)
        pass

    def stat_commit_solana_rpc_health(self, status: bool):
        self.SOLANA_RPC_HEALTH.set(1 if status else 0)
        pass
