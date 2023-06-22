from typing import List, Dict, Any

import time

from .mempool_api import MPGetStuckTxListRequest, MPGetStuckTxListResponse, MPStuckTxInfo
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.config import Config
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolCommit, SolPubKey
from ..common_neon.utils.neon_tx_info import NeonTxInfo

from ..indexer.stuck_neon_txs_db import StuckNeonTxsDB


class MPExecutorStuckTxListTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor):
        super().__init__(config, solana)
        db = DBConnection(config)
        self._stuck_txs_db = StuckNeonTxsDB(db)

    def read_stuck_tx_list(self, _: MPGetStuckTxListRequest) -> MPGetStuckTxListResponse:
        block_slot = self._solana.get_block_slot(SolCommit.Finalized)
        _, src_tx_list = self._stuck_txs_db.get_tx_list(False, block_slot)
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
