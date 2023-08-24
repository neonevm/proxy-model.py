from typing import List, Any, Tuple

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from .indexed_objects import NeonIndexedBlockInfo


class SolTxCostsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_transaction_costs',
            column_list=['sol_sig', 'block_slot', 'operator', 'sol_spent'],
            key_list=['sol_sig', 'block_slot']
        )

    def set_cost_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = list()
        for neon_block in neon_block_queue:
            for cost in neon_block.iter_sol_tx_cost():
                value_list: List[Any] = list()
                for idx, column in enumerate(self._column_list):
                    if hasattr(cost, column):
                        value_list.append(getattr(cost, column))
                    else:
                        raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
                row_list.append(value_list)

        self._insert_row_list(row_list)

    def finalize_block_list(self, from_slot: int, to_slot: int, slot_list: Tuple[int, ...]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot <= %s
                    AND block_slot NOT IN %s
        '''
        self._update_row(request, (from_slot, to_slot, slot_list))
