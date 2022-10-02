from typing import Optional
from .mempool_api import IMPExecutor, MPGasPriceRequest, MPGasPriceResult
from .mempool_periodic_task import MPPeriodicTaskLoop


class MPGasPriceTaskLoop(MPPeriodicTaskLoop[MPGasPriceRequest, MPGasPriceResult]):
    def __init__(self, executor: IMPExecutor) -> None:
        super().__init__(name='gas-price', sleep_time=4.0, executor=executor)
        self._gas_price: Optional[MPGasPriceResult] = None

    @property
    def gas_price(self) -> Optional[MPGasPriceResult]:
        return self._gas_price

    def _submit_request(self) -> None:
        mp_req = MPGasPriceRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGasPriceRequest) -> None:
        pass

    def _process_result(self, _: MPGasPriceRequest, mp_res: MPGasPriceResult) -> None:
        self._gas_price = mp_res
