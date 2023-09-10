from __future__ import annotations

from aioprometheus import Counter, Gauge, Histogram

from .data import NeonTxStatData, NeonBlockStatData, NeonDoneBlockStatData
from .middleware import StatService
from .stat_data_peeker import StatDataPeeker, IHealthStatService

from ..common_neon.config import Config


class IndexerStatService(StatService, IHealthStatService):
    def __init__(self, config: Config):
        super().__init__(config)
        self._data_peeker = StatDataPeeker(config, self)

    def _init_metric_list(self):
        self._metr_tx_count = Counter(
            'tx_count', 'Number of completed Neon transactions (independent on status)',
            registry=self._registry
        )
        self._metr_tx_op_count = Counter(
            'tx_op_count', 'Number of completed Neon transactions (independent on status)',
            registry=self._registry
        )
        self._metr_tx_canceled = Counter(
            'tx_canceled', 'Number of canceled Neon txs',
            registry=self._registry
        )
        self._metr_tx_op_canceled = Counter(
            'tx_op_canceled', 'Number of Neon txs canceled by Operator',
            registry=self._registry
        )
        self._metr_tx_sol_spent = Counter(
            'tx_sol_spent', 'LAMPORTs spent on tx execution',
            registry=self._registry
        )
        self._metr_tx_op_sol_spent = Counter(
            'tx_op_sol_spent', 'LAMPORTs spent by operator on tx execution',
            registry=self._registry
        )
        self._metr_tx_neon_income = Counter(
            'tx_neon_income', 'ALANs earned on tx execution',
            registry=self._registry
        )
        self._metr_tx_op_neon_income = Counter(
            'tx_op_neon_income', 'ALANs earned by operator on tx execution',
            registry=self._registry
        )

        self._metr_tx_count_by_type = Counter(
            'tx_count_by_type', 'Number of transactions by type(single|iter|holder)',
            registry=self._registry
        )
        self._metr_tx_op_count_by_type = Counter(
            'tx_op_count_by_type', 'Number of transactions by type(single|iter|holder)',
            registry=self._registry
        )

        self._metr_tx_sol_tx_per_neon_tx = Histogram(
            'tx_sol_per_neon_tx', 'Number of solana txs within by type(single|iter|holder)',
            registry=self._registry
        )
        self._metr_tx_bpf_per_iter = Histogram(
            'tx_bpf_per_iter', 'Number of BPF cycles per iteration by type(single|iter|holder)',
            registry=self._registry
        )
        self._metr_tx_step_per_iter = Histogram(
            'tx_step_per_iter', 'Number of NEON EVM steps per iteration by type(single|iter|holder)',
            registry=self._registry
        )

        self._metr_block_start = Gauge(
            'block_start', 'Started block numer',
            registry=self._registry
        )
        self._metr_block_confirmed = Gauge(
            'block_confirmed', 'Last confirmed block numer',
            registry=self._registry
        )
        self._metr_block_finalized = Gauge(
            'block_finalized', 'Last finalized block numer',
            registry=self._registry
        )
        self._metr_block_parsed = Gauge(
            'block_parsed', 'Last parsed block numer',
            registry=self._registry
        )
        self._metr_block_stop = Gauge(
            'block_stop', 'Stop block numer',
            registry=self._registry
        )
        self._metr_block_term = Gauge(
            'block_term', 'Termination block numer',
            registry=self._registry
        )
        self._metr_block_tracer = Gauge(
            'block_tracer', 'Last tracer block numer',
            registry=self._registry
        )

        self._metr_db_health = Gauge(
            'db_health', 'DB connection status',
            registry=self._registry
        )
        self._metr_solana_rpc_health = Gauge(
            'solana_rpc_health', 'Status of RPC connection to Solana',
            registry=self._registry
        )
        self._metr_solana_node_health = Gauge(
            'solana_node_health', 'Status from Solana Node',
            registry=self._registry
        )

    def _process_init(self) -> None:
        self._event_loop.create_task(self._data_peeker.run())

    def commit_db_health(self, status: bool) -> None:
        self._metr_db_health.set({}, 1 if status else 0)

    def commit_solana_rpc_health(self, status: bool) -> None:
        self._metr_solana_rpc_health.set({}, 1 if status else 0)

    def commit_solana_node_health(self, status: bool) -> None:
        self._metr_solana_node_health.set({}, 1 if status else 0)

    def commit_block_stat(self, block_stat: NeonBlockStatData) -> None:
        if len(block_stat.reindex_ident):
            label = {'reindex': block_stat.reindex_ident}
            self._metr_block_start.set(label, block_stat.start_block)
            self._metr_block_parsed.set(label, block_stat.parsed_block)
            self._metr_block_stop.set(label, block_stat.stop_block)
            self._metr_block_term.set(label, block_stat.term_block)
        else:
            self._metr_block_start.set({}, block_stat.start_block)
            self._metr_block_confirmed.set({}, block_stat.confirmed_block)
            self._metr_block_finalized.set({}, block_stat.finalized_block)
            self._metr_block_parsed.set({}, block_stat.parsed_block)
            if block_stat.tracer_block is not None:
                self._metr_block_tracer.set({}, block_stat.tracer_block)

    def commit_done_block_stat(self, done_stat: NeonDoneBlockStatData) -> None:
        label = {'reindex': done_stat.reindex_ident, 'is_done': True}
        self._metr_block_parsed.set(label, done_stat.parsed_block)

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
