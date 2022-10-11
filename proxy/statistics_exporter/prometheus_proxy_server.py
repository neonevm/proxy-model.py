import time
from decimal import Decimal
from logged_groups import logged_group
from multiprocessing import Process

from prometheus_client import start_http_server

from ..common_neon.address import EthereumAddress
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.config import Config
from ..common_neon.gas_price_calculator import GasPriceCalculator

from .prometheus_proxy_exporter import PrometheusExporter


@logged_group("neon.ProxyStatExporter")
class PrometheusProxyServer:
    def __init__(self):
        self._stat_exporter = PrometheusExporter()
        self._config = Config()
        self._solana = SolInteractor(self._config, self._config.solana_url)
        self._gas_price_calculator = GasPriceCalculator(
            self._config, SolInteractor(self._config, self._config.pyth_solana_url)
        )

        self._last_gas_price_update_interval = 0
        self.update_gas_price()

        self._operator_accounts = get_solana_accounts()
        self._sol_accounts = []
        self._neon_accounts = []
        for account in self._operator_accounts:
            self._sol_accounts.append(str(account.public_key()))
            self._neon_accounts.append(EthereumAddress.from_private_key(account.secret_key()))

        self.start_http_server()
        self.run_commit_process()

    def update_gas_price(self) -> bool:
        self._last_gas_price_update_interval = 0
        if not self._gas_price_calculator.has_price():
            if not self._gas_price_calculator.update_mapping():
                return False
        return self._gas_price_calculator.update_gas_price()

    @staticmethod
    def start_http_server():
        from .prometheus_proxy_metrics import registry
        start_http_server(8888, registry=registry)

    def run_commit_process(self):
        p = Process(target=self.commit_loop)
        p.start()

    def commit_loop(self):
        while True:
            time.sleep(5)
            try:
                self._stat_gas_price()
                self._stat_operator_balance()
            except BaseException as exc:
                self.error('Exception on transactions processing.', exc_info=exc)

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
        self._last_gas_price_update_interval += 1
        if (self._last_gas_price_update_interval > 12) or (not self._gas_price_calculator.is_valid()):
            self.update_gas_price()

        if not self._gas_price_calculator.is_valid():
            return

        self._stat_exporter.stat_commit_gas_parameters(
            self._gas_price_calculator.suggested_gas_price,
            self._gas_price_calculator.sol_price_usd,
            self._gas_price_calculator.neon_price_usd,
            self._gas_price_calculator.operator_fee,
        )
