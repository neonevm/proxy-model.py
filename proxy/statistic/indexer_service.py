from aioprometheus import Counter, Gauge, Histogram

from proxy.statistic.data import NeonTxStatData, NeonBlockStatData
from proxy.statistic.middleware import StatService


class IndexerStatService(StatService):
    def _init_metric_list(self):
        self._metr_tx_count = Counter(
            'tx_count', 'Count of completed Neon transactions (independent on status)', registry=self._registry
        )
        self._metr_tx_op_count = Counter(
            'tx_op_count', 'Count of completed Neon transactions (independent on status)', registry=self._registry
        )
        self._metr_tx_canceled = Counter(
            'tx_canceled', 'Count of canceled Neon transactions', registry=self._registry
        )
        self._metr_tx_op_canceled = Counter(
            'tx_op_canceled', 'Count of operator canceled Neon transactions', registry=self._registry
        )
        self._metr_tx_sol_spent = Counter(
            'tx_sol_spent', 'Number of LAMPORTs spent on tx execution', registry=self._registry
        )
        self._metr_tx_op_sol_spent = Counter(
            'tx_op_sol_spent', 'Number of LAMPORTs spent by operator on tx execution', registry=self._registry
        )
        self._metr_tx_neon_income = Counter(
            'tx_neon_income', 'Number of ALANs earned on tx execution', registry=self._registry
        )
        self._metr_tx_op_neon_income = Counter(
            'tx_op_neon_income', 'Number of ALANs earned by operator on tx execution', registry=self._registry
        )

        self._metr_tx_count_by_type = Counter(
            'tx_count_by_type', 'Count of transactions by type(single|iter|holder)', registry=self._registry
        )
        self._metr_tx_op_count_by_type = Counter(
            'tx_op_count_by_type', 'Count of transactions by type(single|iter|holder)', registry=self._registry
        )

        self._metr_tx_sol_tx_per_neon_tx = Histogram(
            'tx_sol_tx_per_neon_tx', 'Count of solana txs within by type(single|iter|holder)',
            registry=self._registry
        )
        self._metr_tx_bpf_per_iter = Histogram(
            'tx_bpf_per_iter', 'Count of BPF cycles per iteration by type(single|iter|holder)',
            registry=self._registry
        )
        self._metr_tx_step_per_iter = Histogram(
            'tx_step_per_iter', 'Count of NEON EVM steps per iteration by type(single|iter|holder)',
            registry=self._registry
        )

        self._metr_block_start = Gauge('block_start', 'Started block numer', registry=self._registry)
        self._metr_block_confirmed = Gauge('block_confirmed', 'Last confirmed block numer', registry=self._registry)
        self._metr_block_finalized = Gauge('block_finalized', 'Last finalized block numer', registry=self._registry)
        self._metr_block_parsed = Gauge('block_parsed', 'Last parsed block numer', registry=self._registry)

        self._metr_db_health = Gauge('db_health', 'DB status', registry=self._registry)
        self._metr_solana_rpc_health = Gauge('solana_rpc_health', 'Solana Node status', registry=self._registry)

    def commit_db_health(self, status: bool) -> None:
        self._metr_db_health.set({}, 1 if status else 0)

    def commit_solana_rpc_health(self, status: bool) -> None:
        self._metr_solana_rpc_health.set({}, 1 if status else 0)

    def commit_block_stat(self, block_stat: NeonBlockStatData) -> None:
        self._metr_block_start.set({}, block_stat.start_block)
        self._metr_block_confirmed.set({}, block_stat.confirmed_block)
        self._metr_block_finalized.set({}, block_stat.finalized_block)
        self._metr_block_parsed.set({}, block_stat.parsed_block)

    def commit_neon_tx_result(self, tx_stat: NeonTxStatData):
        self._metr_tx_count.add({}, tx_stat.completed_neon_tx_cnt)
        self._metr_tx_canceled.add({}, tx_stat.canceled_neon_tx_cnt)
        self._metr_tx_sol_spent.add({}, tx_stat.sol_spent)
        self._metr_tx_neon_income.add({}, tx_stat.neon_income)
        self._metr_tx_count_by_type.add({'type': tx_stat.tx_type}, tx_stat.completed_neon_tx_cnt)

        self._metr_tx_op_count_by_type.add({'type': tx_stat.tx_type}, tx_stat.op_completed_neon_tx_cnt)
        self._metr_tx_op_neon_income.add({}, tx_stat.op_neon_income)
        self._metr_tx_op_sol_spent.add({}, tx_stat.op_sol_spent)
        self._metr_tx_op_canceled.add({}, tx_stat.op_canceled_neon_tx_cnt)
        self._metr_tx_op_count.add({}, tx_stat.op_completed_neon_tx_cnt)
