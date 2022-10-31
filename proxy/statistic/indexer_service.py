from aioprometheus import Counter, Gauge, Histogram

from proxy.statistic.data import NeonTxStatData
from proxy.statistic.middleware import StatService


class IndexerStatService(StatService):
    def _init_metric_list(self):
        self._metr_tx_sol_spent = Histogram(
            'tx_sol_spent', 'How many lamports being spend in Neon transaction per iteration', registry=self._registry
        )
        self._metr_tx_neon_income = Histogram('tx_neon_income', 'Neon payed for transaction', registry=self._registry)
        self._metr_tx_bpf_per_iter = Histogram(
            'tx_bpf_per_iteration', 'How many BPF cycles was used in each iteration', registry=self._registry
        )
        self._metr_tx_steps_per_iteration = Histogram(
            'tx_steps_per_iteration', 'How many steps was used in each iteration', registry=self._registry
        )
        self._metr_tx_count = Counter(
            'tx_count', 'Count of Neon transactions were completed (independent on status)', registry=self._registry
        )
        self._metr_tx_canceled = Counter(
            'tx_canceled', 'Count of Neon transactions were canceled', registry=self._registry
        )
        self._metr_tx_count_by_type = Counter(
            'count_tx_count_by_type', 'Count of transactions by type(single|iter|holder)', registry=self._registry
        )  # type
        self._metr_count_sol_tx_per_neon_tx = Histogram(
            'count_sol_tx_per_neon_tx', 'Count of solana txs within by type(single|iter|holder)',
            registry=self._registry
        )  # type

        self._metr_db_health = Gauge('postgres_availability', 'Postgres availability', registry=self._registry)
        self._metr_solana_rpc_health = Gauge('solana_rpc_health', 'Solana Node status', registry=self._registry)

    def commit_db_health(self, status: bool):
        self._metr_db_health.set({}, 1 if status else 0)

    def commit_solana_rpc_health(self, status: bool):
        self._metr_solana_rpc_health.set({}, 1 if status else 0)

    def commit_neon_tx_result(self, tx_stat: NeonTxStatData):
        pass
        # self._commit_tx_count(tx_stat.is_canceled)
        # self._commit_tx_neon_income(tx_stat.neon_tx_hash, tx_stat.neon_income)
        # self._commit_tx_sol_spent(tx_stat.neon_tx_hash, tx_stat.sol_spent)
        # self._commit_tx_steps_bpf(tx_stat.neon_tx_hash, tx_stat.neon_step_cnt, tx_stat.bpf_cycle_cnt)
        # self._commit_count_sol_tx_per_neon_tx(tx_stat.tx_type, tx_stat.sol_tx_cnt)

        # self._metr_tx_count.inc({})
        # if canceled:
        #         self.metr_tx_canceled.inc({})

        # self._metr_tx_sol_spent.observe({}, sol_spent)
        # self._metr_tx_neon_income.observe({}, neon_income)
        # if bpf:
        #     self.metr_tx_bpf_per_iteration.observe({}, bpf)
        # if steps:
        #     self.metr_tx_steps_per_iteration.observe({}, steps)
        # self.metr_tx_count_by_type.inc({"type": type})
        # self.metr_count_sol_tx_per_neon_tx.observe({"type": type}, sol_tx_count)
