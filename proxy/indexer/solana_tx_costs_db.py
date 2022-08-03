from typing import List, Any, Iterator

from ..common_neon.solana_neon_tx_receipt import SolTxCostInfo

from ..indexer.base_db import BaseDB

class SolTxCostsDB(BaseDB):
    def __init__(self):
        super().__init__('solana_transaction_costs')
        self._column_list = ['sol_sign', 'block_slot', 'operator', 'sol_spent']

    def set_cost_list(self, cursor: BaseDB.Cursor, iter_sol_tx_cost: Iterator[SolTxCostInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for cost in iter_sol_tx_cost:
            value_list: List[Any] = []
            for idx, column in enumerate(self._column_list):
                if hasattr(cost, column):
                    value_list.append(getattr(cost, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)
