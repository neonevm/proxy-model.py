from typing import Optional

from .mempool_api import MPGasPriceResult
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.config import Config
from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.solana_interactor import SolInteractor

from ..statistic.data import NeonGasPriceData
from ..statistic.proxy_client import ProxyStatClient


class MPExecutorGasPriceTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor, stat_client: ProxyStatClient):
        super().__init__(config, solana)
        self._stat_client = stat_client
        self._gas_price_calculator = GasPriceCalculator(config, SolInteractor(config, config.pyth_solana_url))

    def _update_gas_price_calculator(self):
        if not self._gas_price_calculator.has_price():
            self._gas_price_calculator.update_mapping()
        self._gas_price_calculator.update_gas_price()

    def calc_gas_price(self) -> Optional[MPGasPriceResult]:
        self._update_gas_price_calculator()
        if not self._gas_price_calculator.is_valid():
            return None

        stat = NeonGasPriceData(
            min_gas_price=self._gas_price_calculator.min_gas_price,
            sol_price_usd=self._gas_price_calculator.sol_price_usd,
            neon_price_usd=self._gas_price_calculator.neon_price_usd,
            operator_fee=self._gas_price_calculator.operator_fee
        )
        self._stat_client.commit_gas_price(stat)

        gas_price = MPGasPriceResult(
            suggested_gas_price=self._gas_price_calculator.suggested_gas_price,
            min_gas_price=self._gas_price_calculator.min_gas_price
        )
        self.debug(f'{gas_price}')
        return gas_price
