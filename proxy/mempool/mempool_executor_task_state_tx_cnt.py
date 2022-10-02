from typing import List

from ..common_neon.address import EthereumAddress

from ..mempool.mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult, MPSenderTxCntData
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask


class MPExecutorStateTxCntTask(MPExecutorBaseTask):
    def read_state_tx_cnt(self, mp_state_req: MPSenderTxCntRequest) -> MPSenderTxCntResult:
        neon_address_list = [EthereumAddress(sender) for sender in mp_state_req.sender_list]
        neon_account_list = self._solana.get_neon_account_info_list(neon_address_list)

        state_tx_cnt_list: List[MPSenderTxCntData] = []
        for address, neon_account in zip(mp_state_req.sender_list, neon_account_list):
            data = MPSenderTxCntData(address, neon_account.tx_count if neon_account is not None else 0)
            state_tx_cnt_list.append(data)
        return MPSenderTxCntResult(sender_tx_cnt_list=state_tx_cnt_list)
