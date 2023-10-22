from typing import Dict, List, Optional

from .executor_mng import MPExecutorMng
from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult
from .mempool_periodic_task import MPPeriodicTaskLoop
from .mempool_schedule import MPTxSchedule

from ..common_neon.constants import ONE_BLOCK_SEC
from ..common_neon.address import NeonAddress


class MPSenderTxCntTaskLoop(MPPeriodicTaskLoop[MPSenderTxCntRequest, MPSenderTxCntResult]):
    def __init__(self, executor_mng: MPExecutorMng, tx_schedule_dict: Dict[int, MPTxSchedule]) -> None:
        super().__init__(name='state-tx-cnt', sleep_sec=ONE_BLOCK_SEC, executor_mng=executor_mng)
        self._tx_schedule_dict = tx_schedule_dict

    def _submit_request(self) -> None:
        suspended_sender_list: List[NeonAddress] = list()
        for tx_schedule in self._tx_schedule_dict.values():
            suspended_sender_list.extend(tx_schedule.suspended_sender_list)

        if not len(suspended_sender_list):
            return

        mp_req = MPSenderTxCntRequest(req_id=self._generate_req_id(), sender_list=suspended_sender_list)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPSenderTxCntRequest) -> None:
        pass

    async def _process_result(self, _: MPSenderTxCntRequest, mp_res: MPSenderTxCntResult) -> None:
        tx_schedule: Optional[MPTxSchedule] = None
        for sender_tx_cnt in mp_res.sender_tx_cnt_list:
            chain_id = sender_tx_cnt.sender.chain_id
            if (not tx_schedule) or (tx_schedule.chain_id != chain_id):
                tx_schedule = self._tx_schedule_dict.get(chain_id)
            if not tx_schedule:
                continue
            tx_schedule.set_sender_state_tx_cnt(sender_tx_cnt)
