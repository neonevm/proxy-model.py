from __future__ import annotations

from decimal import Decimal
from typing import List, Dict, Union

from aioprometheus import Counter, Histogram, Gauge

from .middleware import StatService
from .stat_data_peeker import StatDataPeeker, IHealthStatService
from .data import NeonMethodData, NeonGasPriceData, NeonTxBeginData, NeonTxEndData
from .data import NeonOpResStatData, NeonOpResListData, NeonExecutorStatData

from ..common_neon.config import Config
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient
from ..neon_core_api.neon_layouts import EVMTokenInfo


class ProxyStatDataPeeker(StatDataPeeker):
    def __init__(self, config: Config, stat_srv: ProxyStatService):
        super().__init__(config, stat_srv)
        self._stat_service = stat_srv
        self._core_api_client = NeonCoreApiClient(config)

        self._sol_acct_list: List[SolPubKey] = list()
        self._neon_addr_list: List[NeonAddress] = list()
        self._token_info_dict: Dict[int, EVMTokenInfo] = dict()

    def set_op_account_list(self, op_list: NeonOpResListData) -> None:
        self._sol_acct_list = list(set(op_list.sol_account_list))
        self._neon_addr_list = list(set(op_list.neon_address_list))
        self._token_info_dict = {token.chain_id: token for token in op_list.token_info_list}

    async def _run(self) -> None:
        await super()._run()
        self._stat_operator_balance()

    def _get_token_name(self, chain_id: int) -> str:
        return self._token_info_dict[chain_id].token_name

    def _stat_operator_balance(self) -> None:
        sol_total_balance = Decimal(0)
        sol_balance_list = self._solana.get_sol_balance_list(self._sol_acct_list)
        for sol_account, balance in zip(self._sol_acct_list, sol_balance_list):
            balance = Decimal(balance) / (10 ** 9)
            sol_total_balance += balance
            self._stat_service.commit_op_sol_balance(str(sol_account), balance)
        self._stat_service.commit_op_sol_balance('TOTAL', sol_total_balance)

        token_balance_dict: Dict[str, Decimal] = dict()
        neon_acct_list = self._core_api_client.get_neon_account_info_list(self._neon_addr_list)
        for neon_acct in neon_acct_list:
            if neon_acct.balance == 0:
                continue

            token_name = self._get_token_name(neon_acct.chain_id)
            balance = Decimal(neon_acct.balance) / (10 ** 18)
            token_balance_dict[token_name] = token_balance_dict.get(token_name, Decimal(0)) + balance
            self._stat_service.commit_op_neon_balance(neon_acct.neon_address.checksum_address, token_name, balance)

        for token_name, balance in token_balance_dict.items():
            self._stat_service.commit_op_neon_balance('TOTAL', token_name, balance)


class ProxyStatService(StatService, IHealthStatService):
    def __init__(self, config: Config):
        super().__init__(config)
        self._data_peeker = ProxyStatDataPeeker(config, self)

    def _init_metric_list(self) -> None:
        self._metr_req_count = Counter(
            'request_count', 'App Request Count',
            registry=self._registry
        )
        self._metr_req_error_count = Counter(
            'error_count', 'App Error Answer Count',
            registry=self._registry
        )
        self._metr_req_latency = Histogram(
            'request_latency_seconds', 'Request latency',
            registry=self._registry
        )
        self._metr_tx_total = Counter(
            'tx_total', 'Number of incoming txs',
            registry=self._registry
        )
        self._metr_tx_in_mempool = Gauge(
            'tx_in_mempool', 'Number of txs in mempool',
            registry=self._registry
        )
        self._metr_tx_in_progress = Gauge(
            'tx_in_progress', 'Number of processing txs',
            registry=self._registry
        )
        self._metr_tx_in_stuck = Gauge(
            'stuck_tx_in_mempool', 'Number of txs in Stuck Queue',
            registry=self._registry
        )
        self._metr_stuck_tx_in_progress = Gauge(
            'stuck_tx_in_progress', 'Number of processing Stuck txs',
            registry=self._registry
        )
        self._metr_tx_in_reschedule = Gauge(
            'tx_in_reschedule', 'Number of txs in Rescheduled Queue',
            registry=self._registry
        )

        self._metr_tx_canceled = Counter(
            'tx_canceled_count', 'Number of canceled txs',
            registry=self._registry
        )
        self._metr_tx_success = Counter(
            'tx_success_count', 'Number of succeeded txs',
            registry=self._registry
        )
        self._metr_tx_failed = Counter(
            'tx_failed_count', 'Number of failed txs',
            registry=self._registry
        )
        self._metr_op_sol_balance = Gauge(
            'operator_sol_balance', 'Operator Balance in SOLs',
            registry=self._registry
        )
        self._metr_op_neon_balance = Gauge(
            'operator_neon_balance', 'Operator Balance in NEONs',
            registry=self._registry
        )
        self._metr_key_total = Gauge(
            'operator_key_count', 'Number of Operator keys',
            registry=self._registry
        )
        self._metr_res_total = Gauge(
            'operator_resource_count', 'Number of Operator resources',
            registry=self._registry
        )
        self._metr_res_free = Gauge(
            'operator_resource_free_count', 'Number of free Operator resources',
            registry=self._registry
        )
        self._metr_res_used = Gauge(
            'operator_resource_used_count', 'Number of used Operator resources',
            registry=self._registry
        )
        self._metr_res_disabled = Gauge(
            'operator_resource_disabled_count', 'Number of disabled Operator resources',
            registry=self._registry
        )

        self._metr_exec_total = Gauge(
            'executor_total', 'Number of Executors',
            registry=self._registry
        )
        self._metr_exec_free = Gauge(
            'executor_free_count', 'Number of free Executors',
            registry=self._registry
        )
        self._metr_exec_used = Gauge(
            'executor_used_count', 'Number of used Executors',
            registry=self._registry
        )
        self._metr_exec_stopped = Gauge(
            'executor_stopped_count', 'Number of stopped Executors',
            registry=self._registry
        )
        self._metr_gas_price = Gauge(
            'gas_price', 'Gas Price',
            registry=self._registry
        )
        self._metr_usd_price_sol = Gauge(
            'usd_price_sol', 'Sol Price USD',
            registry=self._registry
        )
        self._metr_usd_price_token = Gauge(
            'usd_price_token', 'Token Price USD',
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

    def commit_request_and_timeout(self, method: NeonMethodData) -> None:
        label = {"method": method.name}
        self._metr_req_count.inc(label)
        self._metr_req_latency.observe(label, method.latency)
        if method.is_error:
            self._metr_req_error_count.inc(label)

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

    def commit_solana_node_health(self, status: bool) -> None:
        self._metr_solana_node_health.set({}, 1 if status else 0)

    def commit_gas_price(self, gas_price: NeonGasPriceData) -> None:
        self._metr_gas_price.set({'token_name': gas_price.token_name}, gas_price.min_gas_price)
        self._metr_usd_price_token.set({'token_name': gas_price.token_name}, float(gas_price.token_price_usd))
        self._metr_usd_price_sol.set({}, float(gas_price.sol_price_usd))

    def commit_op_res_list(self, op_list: NeonOpResListData) -> None:
        self._data_peeker.set_op_account_list(op_list)

    def commit_op_sol_balance(self, sol_account: str, sol_balance: Decimal) -> None:
        self._metr_op_sol_balance.set({"operator_sol_wallet": sol_account}, float(sol_balance))

    def commit_op_neon_balance(self, neon_account: str, token_name: str, neon_balance: Decimal) -> None:
        self._metr_op_neon_balance.set(
            {'operator_neon_wallet': neon_account, 'token': token_name},
            float(neon_balance)
        )

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
