from __future__ import annotations

import asyncio
import logging
from decimal import Decimal
from typing import List, Union

from aioprometheus import Counter, Histogram, Gauge

from .middleware import StatService
from .data import NeonMethodData, NeonGasPriceData, NeonTxBeginData, NeonTxEndData
from .data import NeonOpResStatData, NeonOpResListData, NeonExecutorStatData

from ..indexer.indexer_db import IndexerDB
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor


LOG = logging.getLogger(__name__)


class ProxyStatDataPeeker:
    def __init__(self, config: Config, stat_srv: ProxyStatService):
        self._stat_service = stat_srv
        self._config = config
        self._solana = SolInteractor(config, config.solana_url)
        self._db = IndexerDB(config)

        self._sol_account_list: List[str] = []
        self._neon_account_list: List[str] = []

    def set_op_account_list(self, op_list: NeonOpResListData) -> None:
        self._sol_account_list = op_list.sol_account_list
        self._neon_account_list = op_list.neon_account_list

    async def run(self):
        while True:
            await asyncio.sleep(1)
            try:
                self._stat_operator_balance()
                self._stat_solana_rpc_health()
                self._stat_db_health()
            except BaseException as err:
                LOG.warning('Exception on statistic processing', exc_info=err)

    def _stat_operator_balance(self) -> None:
        sol_balance_list = self._solana.get_sol_balance_list(self._sol_account_list)
        for sol_account, balance in zip(self._sol_account_list, sol_balance_list):
            self._stat_service.commit_op_sol_balance(sol_account, Decimal(balance) / 1_000_000_000)

        neon_layout_list = self._solana.get_neon_account_info_list(self._neon_account_list)
        for neon_account, neon_layout in zip(self._neon_account_list, neon_layout_list):
            if neon_layout is not None:
                neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
                self._stat_service.commit_op_neon_balance(neon_account, neon_balance)

    def _stat_solana_rpc_health(self) -> None:
        self._stat_service.commit_solana_rpc_health(self._solana.is_healthy())

    def _stat_db_health(self) -> None:
        self._stat_service.commit_db_health(self._db.is_healthy())


class ProxyStatService(StatService):
    def __init__(self, config: Config):
        super().__init__(config)
        self._data_peeker = ProxyStatDataPeeker(config, self)

    def _init_metric_list(self) -> None:
        self._metr_req_count = Counter('request_count', 'App Request Count', registry=self._registry)
        self._metr_req_error_count = Counter('error_count', 'App Error Answer Count', registry=self._registry)
        self._metr_req_latency = Histogram('request_latency_seconds', 'Request latency', registry=self._registry)

        self._metr_tx_total = Counter('tx_total', 'Incoming TX Count', registry=self._registry)

        self._metr_tx_in_mempool = Gauge('tx_in_mempool', 'Count of Txs in mempool', registry=self._registry)
        self._metr_tx_in_progress = Gauge('tx_in_progress', 'Count Of Processing Txs', registry=self._registry)
        self._metr_stuck_tx_in_progress = Gauge('stuck_tx_in_progress', 'Count Of Processing Stuck Txs', registry=self._registry)
        self._metr_tx_in_reschedule = Gauge('tx_in_reschedule', 'Count Of Txs in Rescheduled Queue', registry=self._registry)
        self._metr_tx_in_stuck = Gauge('tx_in_stuck', 'Count Of Txs in Stuck Queue', registry=self._registry)

        self._metr_tx_canceled = Counter('tx_canceled_count', 'Count of Canceled Txs')
        self._metr_tx_success = Counter('tx_success_count', 'Count Of Succeeded Txs', registry=self._registry)
        self._metr_tx_failed = Counter('tx_failed_count', 'Count Of Failed Txs', registry=self._registry)

        self._metr_op_sol_balance = Gauge(
            'operator_sol_balance', 'Operator Balance in Sol\'s', registry=self._registry
        )
        self._metr_op_neon_balance = Gauge(
            'operator_neon_balance', 'Operator Balance in Neon\'s', registry=self._registry
        )
        self._metr_key_total = Gauge('operator_key_count', 'Operator Keys count', registry=self._registry)
        self._metr_res_total = Gauge('operator_resource_count', 'Operator Resource count', registry=self._registry)
        self._metr_res_free = Gauge(
            'operator_resource_free_count', 'Count of free operator resources', registry=self._registry
        )
        self._metr_res_used = Gauge(
            'operator_resource_used_count', 'Count of used operator resources', registry=self._registry
        )
        self._metr_res_disabled = Gauge(
            'operator_resource_disabled_count', 'Count of disabled operator resources', registry=self._registry
        )

        self._metr_exec_total = Gauge('executor_total', 'Executors count', registry=self._registry)
        self._metr_exec_free = Gauge('executor_free_count', 'Count of free executors', registry=self._registry)
        self._metr_exec_used = Gauge('executor_used_count', 'Count of used executors', registry=self._registry)
        self._metr_exec_stopped = Gauge('executor_stopped_count', 'Count of stopped executors', registry=self._registry)

        self._metr_gas_price = Gauge('gas_price', 'Gas Price', registry=self._registry)
        self._metr_usd_price_sol = Gauge('usd_price_sol', 'Sol Price USD', registry=self._registry)
        self._metr_usd_price_neon = Gauge('usd_price_neon', 'Neon Price USD', registry=self._registry)
        self._metr_operator_fee = Gauge('operator_fee', 'Operator Fee', registry=self._registry)
        self._metr_suggested_pct = Gauge('suggested_pct', 'Suggested Percent', registry=self._registry)

        self._metr_db_health = Gauge('db_health', 'DB status', registry=self._registry)
        self._metr_solana_rpc_health = Gauge('solana_rpc_health', 'Solana Node status', registry=self._registry)

    def _process_init(self) -> None:
        self._event_loop.create_task(self._data_peeker.run())

    def commit_request_and_timeout(self, method: NeonMethodData) -> None:
        self._metr_req_count.inc({"method": method.name})
        self._metr_req_latency.observe({"method": method.name}, method.latency)
        if method.is_error:
            self._metr_req_error_count.inc({"method": method.name})

    def commit_tx_add(self) -> None:
        self._metr_tx_total.inc({})
        self._metr_tx_in_mempool.inc({})

    def commit_tx_begin(self, stat: NeonTxBeginData) -> None:
        self._commit_mempool_stat(stat)

    def commit_tx_end(self, stat: NeonTxEndData) -> None:
        self._metr_tx_canceled.add({}, stat.canceled_cnt)
        self._metr_tx_failed.add({}, stat.failed_cnt)
        self._metr_tx_success.add({}, stat.done_cnt)

        self._commit_mempool_stat(stat)

    def _commit_mempool_stat(self, stat: Union[NeonTxBeginData, NeonTxEndData]) -> None:
        self._metr_tx_in_progress.set({}, stat.processing_cnt)
        self._metr_stuck_tx_in_progress.set({}, stat.processing_stuck_cnt)
        self._metr_tx_in_reschedule.set({}, stat.in_reschedule_queue_cnt)
        self._metr_tx_in_stuck.set({}, stat.in_stuck_queue_cnt)
        self._metr_tx_in_mempool.set({}, stat.in_mempool_cnt)

    def commit_db_health(self, status: bool) -> None:
        self._metr_db_health.set({}, 1 if status else 0)

    def commit_solana_rpc_health(self, status: bool) -> None:
        self._metr_solana_rpc_health.set({}, 1 if status else 0)

    def commit_gas_price(self, gas_price: NeonGasPriceData) -> None:
        self._metr_gas_price.set({}, gas_price.min_gas_price)
        self._metr_usd_price_neon.set({}, float(gas_price.neon_price_usd))
        self._metr_usd_price_sol.set({}, float(gas_price.sol_price_usd))
        self._metr_operator_fee.set({}, float(gas_price.operator_fee))

    def commit_op_res_list(self, op_list: NeonOpResListData) -> None:
        self._data_peeker.set_op_account_list(op_list)

    def commit_op_sol_balance(self, sol_account: str, sol_balance: Decimal) -> None:
        self._metr_op_sol_balance.set({"operator_sol_wallet": sol_account}, float(sol_balance))

    def commit_op_neon_balance(self, neon_account: str, neon_balance: Decimal) -> None:
        self._metr_op_neon_balance.set({'operator_neon_wallet': neon_account}, float(neon_balance))

    def commit_op_res_stat(self, res_stat: NeonOpResStatData) -> None:
        self._metr_key_total.set({}, res_stat.secret_cnt)
        self._metr_res_total.set({}, res_stat.total_res_cnt)
        self._metr_res_free.set({}, res_stat.free_res_cnt)
        self._metr_res_used.set({}, res_stat.used_res_cnt)
        self._metr_res_disabled.set({}, res_stat.disabled_res_cnt)

    def commit_executor_stat(self, exec_stat: NeonExecutorStatData) -> None:
        self._metr_exec_total.set({}, exec_stat.total_cnt)
        self._metr_exec_free.set({}, exec_stat.free_cnt)
        self._metr_exec_used.set({}, exec_stat.used_cnt)
        self._metr_exec_stopped.set({}, exec_stat.stopped_cnt)
