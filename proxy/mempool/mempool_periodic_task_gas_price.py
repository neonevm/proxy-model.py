from typing import Optional

from .executor_mng import MPExecutorMng
from .mempool_api import MPGasPriceRequest, MPGasPriceResult
from .mempool_periodic_task import MPPeriodicTaskLoop

from ..common_neon.constants import ONE_BLOCK_SEC


class MPGasPriceTaskLoop(MPPeriodicTaskLoop[MPGasPriceRequest, MPGasPriceResult]):
    _default_sleep_sec = ONE_BLOCK_SEC * 16

    def __init__(self, executor_mng: MPExecutorMng) -> None:
        super().__init__(name='gas-price', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)
        self._gas_price: Optional[MPGasPriceResult] = None

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def _submit_request(self) -> None:
        req_id = self._generate_req_id()
        if self._gas_price is None:
            mp_req = MPGasPriceRequest(req_id=req_id)
        else:
            mp_req = MPGasPriceRequest(
                req_id=req_id,
                last_update_mapping_sec=self._gas_price.last_update_mapping_sec,
                sol_price_account=self._gas_price.sol_price_account,
                neon_price_account=self._gas_price.neon_price_account
            )
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGasPriceRequest) -> None:
        pass

    async def _process_result(self, _: MPGasPriceRequest, mp_res: MPGasPriceResult) -> None:
        self._gas_price = mp_res
