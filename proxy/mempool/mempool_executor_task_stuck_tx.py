import time

from typing import Dict, List, Any

from .mempool_api import MPGetStuckTxListRequest, MPGetStuckTxListResponse, MPStuckTxInfo
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_tx import SolCommit, SolPubKey
from ..common_neon.utils.neon_tx_info import NeonTxInfo

from ..indexer.stuck_neon_txs_db import StuckNeonTxsDB


class MPExecutorStuckTxListTask(MPExecutorBaseTask):
    def read_stuck_tx_list(self, _: MPGetStuckTxListRequest) -> MPGetStuckTxListResponse:
        block_slot = self._solana.get_block_slot(SolCommit.Confirmed) - 3
        src_tx_list = self._get_tx_list(block_slot)

        dst_tx_list = [
            MPStuckTxInfo(
                neon_tx=NeonTxInfo.from_dict(tx['neon_tx']),
                holder_account=SolPubKey.from_string(tx['holder_account']),
                alt_addr_list=list(),
                start_time=time.time_ns(),
            )
            for tx in src_tx_list
        ]
        return MPGetStuckTxListResponse(stuck_tx_list=dst_tx_list)

    def _get_tx_list(self, block_slot: int) -> List[Dict[str, Any]]:
        db = DBConnection(self._config)
        stuck_txs_db = StuckNeonTxsDB(db)
        _, src_tx_list = stuck_txs_db.get_tx_list(False, block_slot)
        return src_tx_list
