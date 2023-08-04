from .executor_mng import MPExecutorMng
from .mempool_api import MPGetStuckTxListRequest, MPGetStuckTxListResponse, MPStuckTxInfo
from .mempool_periodic_task import MPPeriodicTaskLoop
from .mempool_stuck_tx_dict import MPStuckTxDict


class MPStuckTxListLoop(MPPeriodicTaskLoop[MPGetStuckTxListRequest, MPGetStuckTxListResponse]):
    def __init__(self, executor_mng: MPExecutorMng, stuck_tx_dict: MPStuckTxDict) -> None:
        super().__init__(name='stuck_tx_list', sleep_sec=self._one_block_sec, executor_mng=executor_mng)
        self._stuck_tx_dict = stuck_tx_dict

    def _submit_request(self) -> None:
        mp_req = MPGetStuckTxListRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGetStuckTxListResponse) -> None:
        pass

    async def _process_result(self, _: MPGetStuckTxListRequest, mp_res: MPGetStuckTxListResponse) -> None:
        if not len(mp_res.stuck_tx_list):
            return

        self._stuck_tx_dict.add_external_tx_list(mp_res.stuck_tx_list)
