import logging
from decimal import Decimal
from typing import Optional, List
import time
import math

from .mempool_api import MPGasPriceRequest, MPGasPriceResult, MPGasPriceTokenResult
from .mempool_executor_task_base import MPExecutorBaseTask
from .gas_price_calculator import GasPriceCalculator

from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolPubKey

from ..statistic.data import NeonGasPriceData


LOG = logging.getLogger(__name__)


class MPExecutorGasPriceTask(MPExecutorBaseTask):
    def _update_gas_price_mapping(self, gas_price_calc: GasPriceCalculator, last_update_mapping_sec: int) -> int:
        now = math.ceil(time.time())
        period_sec = abs(now - last_update_mapping_sec)

        if gas_price_calc.has_price() and period_sec < self._config.update_pyth_mapping_period_sec:
            return last_update_mapping_sec

        gas_price_calc.update_mapping()
        return now

    def calc_gas_price(self, mp_req: MPGasPriceRequest) -> Optional[MPGasPriceResult]:
        solana = SolInteractor(self._config, self._config.random_pyth_solana_url)
        gas_price_calc = GasPriceCalculator(self._config, solana)

        last_update_mapping_sec = self._update_gas_price_mapping(gas_price_calc, mp_req.last_update_mapping_sec)
        was_update = last_update_mapping_sec != mp_req.last_update_mapping_sec

        sol_price_acct: Optional[SolPubKey] = None if was_update else mp_req.sol_price_account
        sol_price_usd: Optional[Decimal] = None
        token_list: List[MPGasPriceTokenResult] = list()
        for token_info in mp_req.token_list:
            token_price_acct: Optional[SolPubKey] = None if was_update else token_info.price_account
            gas_price_calc.set_price_account(
                sol_price_acct, sol_price_usd,
                token_info.token_name, token_price_acct
            )

            gas_price_calc.update_gas_price()
            if not gas_price_calc.is_valid():
                continue

            sol_price_acct = gas_price_calc.sol_price_account
            sol_price_usd = gas_price_calc.sol_price_usd

            if gas_price_calc.has_price():
                stat = NeonGasPriceData(
                    token_name=token_info.token_name,
                    min_gas_price=gas_price_calc.min_gas_price,
                    sol_price_usd=gas_price_calc.sol_price_usd,
                    token_price_usd=gas_price_calc.token_price_usd,
                )
                self._stat_client.commit_gas_price(stat)

            token_gas_price = MPGasPriceTokenResult(
                chain_id=token_info.chain_id,
                token_name=token_info.token_name,
                token_price_usd=math.ceil(gas_price_calc.token_price_usd * 100000),
                token_price_account=gas_price_calc.token_price_account,

                operator_fee=math.ceil(self._config.operator_fee * 100000),
                gas_price_slippage=math.ceil(self._config.gas_price_slippage * 100000),

                suggested_gas_price=gas_price_calc.suggested_gas_price,
                is_const_gas_price=gas_price_calc.is_const_gas_price,
                min_executable_gas_price=gas_price_calc.min_gas_price,
                min_acceptable_gas_price=self._config.min_gas_price,
                min_wo_chainid_acceptable_gas_price=self._config.min_wo_chainid_gas_price,
                allow_underpriced_tx_wo_chainid=self._config.allow_underpriced_tx_wo_chainid,
            )
            token_list.append(token_gas_price)

        gas_price = MPGasPriceResult(
            last_update_mapping_sec=last_update_mapping_sec,
            sol_price_usd=math.ceil(sol_price_usd * 100000),
            sol_price_account=sol_price_acct,
            token_list=token_list
        )
        return gas_price
