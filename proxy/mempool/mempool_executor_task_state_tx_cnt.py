from typing import List

from ..common_neon.address import NeonAddress

from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult, MPSenderTxCntData
from .mempool_executor_task_base import MPExecutorBaseTask


class MPExecutorStateTxCntTask(MPExecutorBaseTask):
    def read_state_tx_cnt(self, mp_state_req: MPSenderTxCntRequest) -> MPSenderTxCntResult:
        neon_acct_list = self._core_api_client.get_neon_account_info_list(mp_state_req.sender_list)

        state_tx_cnt_list: List[MPSenderTxCntData] = []
        for neon_acct in neon_acct_list:
            data = MPSenderTxCntData(neon_acct.neon_address, neon_acct.tx_count)
            state_tx_cnt_list.append(data)
        return MPSenderTxCntResult(sender_tx_cnt_list=state_tx_cnt_list)
