from typing import Optional
import time
import math

from .mempool_api import MPGasPriceRequest, MPGasPriceResult
from .mempool_executor_task_base import MPExecutorBaseTask
from .gas_price_calculator import GasPriceCalculator

from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor

from ..statistic.data import NeonGasPriceData
from ..statistic.proxy_client import ProxyStatClient


class MPExecutorGasPriceTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor, stat_client: ProxyStatClient):
        super().__init__(config, solana)
        self._stat_client = stat_client
        self._last_update_mapping_sec = 0
        self._gas_price_calculator = GasPriceCalculator(config, SolInteractor(config, config.pyth_solana_url))

    def _update_gas_price_calculator(self) -> None:
        now = math.ceil(time.time())
        period_sec = abs(now - self._last_update_mapping_sec)

        if self._gas_price_calculator.has_price() and period_sec > self._config.update_pyth_mapping_period_sec:
            return

        self._last_update_mapping_sec = now
        self._gas_price_calculator.update_mapping()
        self._gas_price_calculator.update_gas_price()

    def calc_gas_price(self, mp_req: MPGasPriceRequest) -> Optional[MPGasPriceResult]:
        self._last_update_mapping_sec = mp_req.last_update_mapping_sec
        self._gas_price_calculator.set_price_account(mp_req.sol_price_account, mp_req.neon_price_account)

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
            min_gas_price=self._gas_price_calculator.min_gas_price,
            last_update_mapping_sec=self._last_update_mapping_sec,
            sol_price_account=self._gas_price_calculator.sol_price_account,
            neon_price_account=self._gas_price_calculator.neon_price_account
        )
        self.debug(f'{gas_price}')
        return gas_price
