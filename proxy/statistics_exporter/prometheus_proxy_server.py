import asyncio
import traceback
from decimal import Decimal
from typing import Any

from logged_groups import logged_group
from multiprocessing import Process

from neon_py.network import AddrPickableDataSrv, IPickableDataServerUser
from prometheus_client import start_http_server

import socket


from aioprometheus.service import Service
from aioprometheus import Counter, Histogram


from ..common_neon.address import EthereumAddress
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import SOLANA_URL, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT
from ..common_neon.gas_price_calculator import GasPriceCalculator

from .prometheus_proxy_exporter import PrometheusExporter


@logged_group("neon.Statistic")
class PrometheusProxyServer(IPickableDataServerUser):

    STATISTIC_SERVICE_ADDRESS = ("0.0.0.0", 9093)

    def __init__(self):

        self._last_gas_price_update_interval = 0
        self.update_gas_price()
        self._stat_srv = AddrPickableDataSrv(user=self, address=self.STATISTIC_SERVICE_ADDRESS)

        self._init_metrics()

        self._process = Process(target=self.run)
        self._process.start()

        # self._stat_exporter = PrometheusExporter()
        # self._solana = SolanaInteractor(SOLANA_URL)
        # if PP_SOLANA_URL == SOLANA_URL:
        #     self._gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        # else:
        #     self._gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)
        # print("What the fuck")
        #
        # try:
        #     self._gas_price_calculator.update_mapping()
        # except Exception as err:
        #     self.error(f"error: {err}")
        #
        # self._gas_price_calculator.try_update_gas_price()
        # self._operator_accounts = get_solana_accounts()
        # self._sol_accounts = []
        # self._neon_accounts = []
        # for account in self._operator_accounts:
        #     self._sol_accounts.append(str(account.public_key()))
        #     self._neon_accounts.append(EthereumAddress.from_private_key(account.secret_key()))
        #
        self.start_http_server()

        # self.run_commit_process()

    def _init_metrics(self):
        self.neon_req_count = Counter('request_count', 'App Request Count')
        self.neon_req_latency = Histogram('request_latency_seconds', 'Request latency')

    def update_gas_price(self) -> bool:
        self._last_gas_price_update_interval = 0
        # if not self._gas_price_calculator.has_price():
        #     if not self._gas_price_calculator.update_mapping():
        #         return False
        # return self._gas_price_calculator.update_gas_price()

    @staticmethod
    def start_http_server():
        from .prometheus_proxy_metrics import registry
        start_http_server(8888, registry=registry)

    def run(self):
        self.info(f"Start statistic service: {self.STATISTIC_SERVICE_ADDRESS}")
        event_loop = asyncio.new_event_loop()
        event_loop.create_task(self._stat_srv.run_server())
        event_loop.create_task(Service().start(addr="0.0.0.0", port=8889))
        event_loop.run_forever()

    async def stat_operator_balance(self):
        while True:
            await asyncio.sleep(5)
            try:
                self._stat_gas_price()
                self._stat_operator_balance()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning(f'Exception on transactions processing. Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def _stat_operator_balance(self):
        sol_balances = self._solana.get_sol_balance_list(self._sol_accounts)
        operator_sol_balance = dict(zip(self._sol_accounts, sol_balances))
        for account, balance in operator_sol_balance.items():
            self._stat_exporter.stat_commit_operator_sol_balance(str(account), Decimal(balance) / 1_000_000_000)

        neon_layouts = self._solana.get_neon_account_info_list(self._neon_accounts)
        for sol_account, neon_account, neon_layout in zip(self._operator_accounts, self._neon_accounts, neon_layouts):
            if neon_layout:
                neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
                self._stat_exporter.stat_commit_operator_neon_balance(str(sol_account), str(neon_account), neon_balance)

    def _stat_gas_price(self):
        pass
        # self._last_gas_price_update_interval += 1
        # if (self._last_gas_price_update_interval > 12) or (not self._gas_price_calculator.is_valid()):
        #     self.update_gas_price()
        #
        # if not self._gas_price_calculator.is_valid():
        #     return
        #
        # self._stat_exporter.stat_commit_gas_parameters(
        #     self._gas_price_calculator.get_suggested_gas_price(),
        #     self._gas_price_calculator.get_sol_price_usd(),
        #     self._gas_price_calculator.get_neon_price_usd(),
        #     self._gas_price_calculator.get_operator_fee(),
        # )

    async def on_data_received(self, data: Any) -> Any:
        try:
            if hasattr(self, data[0]):
                m = getattr(self, data[0])
                m(*data[1:])
        except Exception as err:
            self.error(f"Failed to process data: {data}, err: {err}")

    def stat_commit_request_and_timeout(self, method: str, latency: float):
        self.neon_req_count.inc({"method": method})
        self.neon_req_latency.observe({"method": method}, latency)
