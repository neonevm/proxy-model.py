import abc
import asyncio
import traceback
from decimal import Decimal

from logged_groups import logged_group
from multiprocessing import Process

from aioprometheus.service import Service
from aioprometheus import Counter, Histogram, Gauge

from .common_neon.address import EthereumAddress
from .common_neon.solana_interactor import SolanaInteractor
from .common_neon.environment_utils import get_solana_accounts
from .common_neon.environment_data import SOLANA_URL, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT
from .common_neon.gas_price_calculator import GasPriceCalculator
from .common_neon.statistic.statistic_middleware import StatisticMiddlewareServer


class IFinanceDataPeekerUser(abc.ABC):

    @abc.abstractmethod
    def on_operator_sol_balance(self, solana_account: str, balance: Decimal): pass

    @abc.abstractmethod
    def on_operator_neon_balance(self, solana_account: str, neon_account: str, balance: Decimal): pass

    @abc.abstractmethod
    def on_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal): pass


@logged_group("neon.Statistic")
class NeonFinanceDataPeeker:

    def __init__(self, user: IFinanceDataPeekerUser):
        self._user = user
        self._solana = SolanaInteractor(SOLANA_URL)
        if PP_SOLANA_URL == SOLANA_URL:
            self._gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        else:
            self._gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)

        self._last_gas_price_update_interval = 0
        self.update_gas_price()

        self._operator_accounts = get_solana_accounts()
        self._sol_accounts = []
        self._neon_accounts = []
        for account in self._operator_accounts:
            self._sol_accounts.append(str(account.public_key()))
            self._neon_accounts.append(EthereumAddress.from_private_key(account.secret_key()))

    def update_gas_price(self) -> bool:
        self._last_gas_price_update_interval = 0
        if not self._gas_price_calculator.has_price():
            if not self._gas_price_calculator.update_mapping():
                return False
        return self._gas_price_calculator.update_gas_price()

    async def run(self):
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
            self._user.on_operator_sol_balance(str(account), Decimal(balance) / 1_000_000_000)

        neon_layouts = self._solana.get_neon_account_info_list(self._neon_accounts)
        for sol_account, neon_account, neon_layout in zip(self._operator_accounts, self._neon_accounts, neon_layouts):
            if neon_layout:
                neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
                self._user.on_operator_neon_balance(str(sol_account.public_key()), str(neon_account), neon_balance)

    def _stat_gas_price(self):

        self._last_gas_price_update_interval += 1
        if (self._last_gas_price_update_interval > 12) or (not self._gas_price_calculator.is_valid()):
            self.update_gas_price()

        if not self._gas_price_calculator.is_valid():
            return

        self._user.on_gas_parameters(self._gas_price_calculator.get_suggested_gas_price(),
                                     self._gas_price_calculator.get_sol_price_usd(),
                                     self._gas_price_calculator.get_neon_price_usd(),
                                     self._gas_price_calculator.get_operator_fee())


@logged_group("neon.Statistic")
class ProxyStatisticService(IFinanceDataPeekerUser):

    PROMETHEUS_SRV_ADDRESS = ("0.0.0.0", 8888)

    def __init__(self):
        self._stat_middleware_srv = StatisticMiddlewareServer(self)
        self._neon_fin_data_peeker = NeonFinanceDataPeeker(self)

        self._init_metrics()

        self._process = Process(target=self._run)
        self._process.start()

    def _init_metrics(self):
        self.metr_req_count = Counter('request_count', 'App Request Count')
        self.metr_req_latency = Histogram('request_latency_seconds', 'Request latency')
        self.metr_tx_total = Counter('tx_total', 'Incoming TX Count')
        self.metr_tx_in_progress = Gauge('tx_in_progress', 'Count Of Txs Currently Processed')
        self.metr_tx_success = Counter('tx_success_count', 'Count Of Succeeded Txs')
        self.metr_tx_failed = Counter('tx_failed_count', 'Count Of Failed Txs')
        self.metr_operator_sol_balance = Gauge('operator_sol_balance', 'Operator Balance in Sol\'s')
        self.metr_operator_neon_balance = Gauge('operator_neon_balance', 'Operator Balance in Neon\'s')
        self.metr_gas_price = Gauge('gas_price', 'Gas Price')
        self.metr_usd_price_sol = Gauge('usd_price_sol', 'Sol Price USD')
        self.metr_usd_price_neon = Gauge('usd_price_neon', 'Neon Price USD')
        self.metr_operator_fee = Gauge('operator_fee', 'Operator Fee')

    def _run(self):
        try:
            event_loop = asyncio.new_event_loop()
            self.info(f"Listen port: {self.PROMETHEUS_SRV_ADDRESS[1]} on: {self.PROMETHEUS_SRV_ADDRESS[0]}")
            event_loop.run_until_complete(Service().start(*self.PROMETHEUS_SRV_ADDRESS))
            event_loop.run_until_complete(self._stat_middleware_srv.start())
            event_loop.create_task(self._neon_fin_data_peeker.run())
            event_loop.run_forever()
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f'Failed to process statistic service Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def on_operator_sol_balance(self, solana_account: str, balance: Decimal):
        self.stat_commit_operator_sol_balance(solana_account, balance)

    def on_operator_neon_balance(self, solana_account: str, neon_account: str, balance: Decimal):
        self.stat_commit_operator_neon_balance(solana_account, neon_account, balance)

    def on_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal):
        self.stat_commit_gas_parameters(gas_price, sol_price_usd, neon_price_usd, operator_fee)

    def stat_commit_request_and_timeout(self, method: str, latency: float):
        self.metr_req_count.inc({"method": method})
        self.metr_req_latency.observe({"method": method}, latency)

    def stat_commit_tx_begin(self):
        self.metr_tx_total.inc({})
        self.metr_tx_in_progress.inc({})

    def stat_commit_tx_end_success(self):
        self.metr_tx_success.inc({})
        self.metr_tx_in_progress.dec({})

    def stat_commit_tx_end_failed(self):
        self.metr_tx_failed.inc({})
        self.metr_tx_in_progress.dec({})

    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: Decimal):
        self.metr_operator_sol_balance.set({"operator_sol_wallet": operator}, sol_balance)

    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal):
        self.metr_gas_price.set({}, gas_price)
        self.metr_usd_price_neon.set({}, neon_price_usd)
        self.metr_usd_price_sol.set({}, sol_price_usd)
        self.metr_operator_fee.set({}, operator_fee)

    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: Decimal):
        self.metr_operator_neon_balance.set({'operator_sol_wallet': sol_acc, 'operator_neon_wallet': neon_acc}, neon_balance)
