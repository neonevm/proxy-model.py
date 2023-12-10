from typing import List, Any

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from .indexed_objects import NeonIndexedBlockInfo


class GasLessUsagesDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='gas_less_usages',
            column_list=(
                'address', 'block_slot', 'neon_sig', 'nonce', 'to_addr', 'operator', 'neon_total_gas_usage'
            ),
            key_list=('neon_sig', )
        )

    def set_tx_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = list()
        for neon_block in neon_block_queue:
            for tx in neon_block.iter_done_neon_tx():
                if tx.neon_tx.gas_price != 0:
                    continue

                row_list.append([
                    tx.neon_tx.addr,
                    tx.neon_tx_res.block_slot, tx.neon_tx_sig, tx.neon_tx.nonce, tx.neon_tx.to_addr,
                    tx.operator, tx.total_gas_used
                ])

        self._insert_row_list(row_list)
