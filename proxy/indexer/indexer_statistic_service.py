import asyncio
import traceback
from multiprocessing import Process

from aioprometheus.service import Service
from logged_groups import logged_group
from aioprometheus import Counter, Gauge, Histogram

from proxy.common_neon.data import NeonTxStatData
from proxy.common_neon.statistic.statistic_middleware import StatisticMiddlewareServer


@logged_group("neon.Statistic")
class IndexerStatisticService:

    PROMETHEUS_SRV_ADDRESS = ("0.0.0.0", 8888)

    def __init__(self):
        self._stat_middleware_srv = StatisticMiddlewareServer(self)

        self._init_metrics()
        self._process = Process(target=self.run)
        self._process.start()

    def _init_metrics(self):
        self.metr_tx_sol_spent = Histogram('tx_sol_spent', 'How many lamports being spend in Neon transaction per iteration')
        self.metr_tx_neon_income = Histogram('tx_neon_income', 'Neon payed for transaction')
        self.metr_tx_bpf_per_iteration = Histogram('tx_bpf_per_iteration', 'How many BPF cycles was used in each iteration')
        self.metr_tx_steps_per_iteration = Histogram('tx_steps_per_iteration', 'How many steps was used in each iteration')
        self.metr_tx_count = Counter('tx_count', 'Count of Neon transactions were completed (independent on status)')
        self.metr_tx_canceled = Counter('tx_canceled', 'Count of Neon transactions were canceled')
        self.metr_tx_count_by_type = Counter('count_tx_count_by_type', 'Count of transactions by type(single\iter\iter w holder)') # type
        self.metr_count_sol_tx_per_neon_tx = Histogram('count_sol_tx_per_neon_tx', 'Count of solana txs within by type(single\iter\iter w holder)') # type
        self.metr_postgres_availability = Gauge('postgres_availability', 'Postgres availability')
        self.metr_solana_rpc_health = Gauge('solana_rpc_health', 'Solana Node status')

    def run(self):
        try:
            event_loop = asyncio.new_event_loop()
            self.info(f"Listen port: {self.PROMETHEUS_SRV_ADDRESS[1]} on: {self.PROMETHEUS_SRV_ADDRESS[0]}")
            event_loop.run_until_complete(Service().start(*self.PROMETHEUS_SRV_ADDRESS))
            event_loop.run_until_complete(self._stat_middleware_srv.start())
            event_loop.run_forever()
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f'Failed to process prometheus service Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def stat_commit_postgres_availability(self, status: bool):
        self.metr_postgres_availability.set({}, 1 if status else 0)

    def stat_commit_solana_rpc_health(self, status: bool):
        self.metr_solana_rpc_health.set({}, 1 if status else 0)

    def stat_commit_neon_tx_result(self, tx_stat: NeonTxStatData):
        self._commit_tx_count(tx_stat.is_canceled)
        self._commit_tx_neon_income(tx_stat.neon_tx_hash, tx_stat.neon_income)
        self._commit_tx_sol_spent(tx_stat.neon_tx_hash, tx_stat.sol_spent)
        self._commit_tx_steps_bpf(tx_stat.neon_tx_hash, tx_stat.neon_step_cnt, tx_stat.bpf_cycle_cnt)
        self._commit_count_sol_tx_per_neon_tx(tx_stat.tx_type, tx_stat.sol_tx_cnt)

    def _commit_tx_count(self, canceled: bool = False):
        self.metr_tx_count.inc({})
        if canceled:
                self.metr_tx_canceled.inc({})

    def _commit_tx_sol_spent(self, neon_tx_hash: str, sol_spent: int):
        self.metr_tx_sol_spent.observe({}, sol_spent)

    def _commit_tx_neon_income(self, neon_tx_hash: str, neon_income: int):
        self.metr_tx_neon_income.observe({}, neon_income)

    def _commit_tx_steps_bpf(self, neon_tx_hash: str, steps: int, bpf: int):
        if bpf:
            self.metr_tx_bpf_per_iteration.observe({}, bpf)
        if steps:
            self.metr_tx_steps_per_iteration.observe({}, steps)

    def _commit_count_sol_tx_per_neon_tx(self, type: str, sol_tx_count: int):
        self.metr_tx_count_by_type.inc({"type": type})
        self.metr_count_sol_tx_per_neon_tx.observe({"type": type}, sol_tx_count)
