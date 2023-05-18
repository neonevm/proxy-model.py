from typing import List, Any, Iterator

from ..common_neon.solana_neon_tx_receipt import SolTxCostInfo
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection


class SolTxCostsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_transaction_costs',
            column_list=['sol_sig', 'block_slot', 'operator', 'sol_spent'],
            key_list=['sol_sig', 'block_slot']
        )

    def set_cost_list(self, iter_sol_tx_cost: Iterator[SolTxCostInfo]) -> None:
        row_list: List[List[Any]] = list()
        for cost in iter_sol_tx_cost:
            value_list: List[Any] = list()
            for idx, column in enumerate(self._column_list):
                if hasattr(cost, column):
                    value_list.append(getattr(cost, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            row_list.append(value_list)

        self._insert_row_list(row_list)

    def finalize_block_list(self, base_block_slot: int, block_slot_list: List[int]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({', '.join(['%s' for _ in block_slot_list])})
        '''
        self._db.update_row(request, [base_block_slot, block_slot_list[-1]] + block_slot_list)
