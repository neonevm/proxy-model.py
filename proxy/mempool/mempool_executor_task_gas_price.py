from typing import Optional

from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config

from ..mempool.mempool_api import MPGasPriceResult
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask


class MPExecutorGasPriceTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor):
        super().__init__(config, solana)
        self._gas_price_calculator = GasPriceCalculator(config, SolInteractor(config, config.pyth_solana_url))
        self._update_gas_price_calculator()

    def _update_gas_price_calculator(self):
        if not self._gas_price_calculator.has_price():
            self._gas_price_calculator.update_mapping()
        if self._gas_price_calculator.has_price():
            self._gas_price_calculator.update_gas_price()

    def calc_gas_price(self) -> Optional[MPGasPriceResult]:
        self._update_gas_price_calculator()
        if not self._gas_price_calculator.is_valid():
            return None
        return MPGasPriceResult(
            suggested_gas_price=self._gas_price_calculator.suggested_gas_price,
            min_gas_price=self._gas_price_calculator.min_gas_price
        )
