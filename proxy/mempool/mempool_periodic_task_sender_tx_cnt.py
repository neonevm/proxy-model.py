from .executor_mng import MPExecutorMng
from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult
from .mempool_periodic_task import MPPeriodicTaskLoop
from .mempool_schedule import MPTxSchedule


class MPSenderTxCntTaskLoop(MPPeriodicTaskLoop[MPSenderTxCntRequest, MPSenderTxCntResult]):
    def __init__(self, executor_mng: MPExecutorMng, tx_schedule: MPTxSchedule) -> None:
        super().__init__(name='state-tx-cnt', sleep_sec=self._one_block_sec, executor_mng=executor_mng)
        self._tx_schedule = tx_schedule

    def _submit_request(self) -> None:
        suspended_sender_list = self._tx_schedule.suspended_sender_list
        if len(suspended_sender_list) == 0:
            return

        mp_req = MPSenderTxCntRequest(req_id=self._generate_req_id(), sender_list=suspended_sender_list)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPSenderTxCntRequest) -> None:
        pass

    async def _process_result(self, _: MPSenderTxCntRequest, mp_res: MPSenderTxCntResult) -> None:
        self._tx_schedule.set_sender_state_tx_cnt_list(mp_res.sender_tx_cnt_list)
