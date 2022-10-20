import time
from decimal import Decimal
from multiprocessing import Process
from typing import List

from logged_groups import logged_group
from prometheus_client import start_http_server

from .prometheus_proxy_exporter import PrometheusExporter

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolAccount, SolPubKey
from ..common_neon.operator_secret_mng import OpSecretMng


@logged_group("neon.ProxyStatExporter")
class PrometheusProxyServer:
    def __init__(self):
        self._stat_exporter = PrometheusExporter()
        self._config = Config()
        self._solana = SolInteractor(self._config, self._config.solana_url)
        self._gas_price_calculator = GasPriceCalculator(
            self._config, SolInteractor(self._config, self._config.pyth_solana_url)
        )

        self._last_gas_price_update_time = 0
        self._last_operator_list_update_time = 0

        self._operator_account_list: List[SolAccount] = []
        self._sol_account_list: List[SolPubKey] = []
        self._neon_account_list: List[NeonAddress] = []

    def start(self) -> None:
        self._start_http_server()
        self._run_commit_process()

    def _update_gas_price(self) -> bool:
        self._last_gas_price_update_time = 0
        if not self._gas_price_calculator.has_price():
            if not self._gas_price_calculator.update_mapping():
                return False
        return self._gas_price_calculator.update_gas_price()

    @staticmethod
    def _start_http_server():
        from .prometheus_proxy_metrics import registry
        start_http_server(8888, registry=registry)

    def _run_commit_process(self):
        p = Process(target=self.commit_loop)
        p.start()

    def _update_operator_list(self):
        secret_list = OpSecretMng(self._config).read_secret_list()

        self._operator_account_list.clear()
        self._sol_account_list.clear()
        self._neon_account_list.clear()

        for secret in secret_list:
            sol_account = SolAccount.from_secret_key(secret)
            self._operator_account_list.append(sol_account)
            self._sol_account_list.append(sol_account.public_key)
            self._neon_account_list.append(NeonAddress.from_private_key(sol_account.secret_key))

    def commit_loop(self):
        try:
            self._update_operator_list()
            self._update_gas_price()
        except BaseException as exc:
            self.error('Exception on gathering stat', exc_info=exc)

        while True:
            time.sleep(5)
            try:
                self._stat_gas_price()
                self._stat_operator_balance()
            except BaseException as exc:
                self.error('Exception on gathering stat', exc_info=exc)

    def _stat_operator_balance(self):
        self._last_operator_list_update_time += 1
        if (self._last_operator_list_update_time > 60) or (len(self._operator_account_list) == 0):
            self._update_operator_list()

        self._last_operator_list_update_time = 0
        sol_balance_list = self._solana.get_sol_balance_list(self._sol_account_list)
        operator_sol_balance_dict = dict(zip(self._sol_account_list, sol_balance_list))
        for account, balance in operator_sol_balance_dict.items():
            self._stat_exporter.stat_commit_operator_sol_balance(str(account), Decimal(balance) / 1_000_000_000)

        neon_layout_list = self._solana.get_neon_account_info_list(self._neon_account_list)
        full_list = zip(self._operator_account_list, self._neon_account_list, neon_layout_list)
        for sol_account, neon_account, neon_layout in full_list:
            if neon_layout is None:
                continue

            neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
            self._stat_exporter.stat_commit_operator_neon_balance(str(sol_account), str(neon_account), neon_balance)

    def _stat_gas_price(self):
        self._last_gas_price_update_time += 1
        if (self._last_gas_price_update_time > 12) or (not self._gas_price_calculator.is_valid()):
            self._update_gas_price()

        if not self._gas_price_calculator.is_valid():
            return

        self._stat_exporter.stat_commit_gas_parameters(
            self._gas_price_calculator.suggested_gas_price,
            self._gas_price_calculator.sol_price_usd,
            self._gas_price_calculator.neon_price_usd,
            self._gas_price_calculator.operator_fee,
        )
