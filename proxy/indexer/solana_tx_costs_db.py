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

    def get_cost_list_by_sol_sig_list(self, sig_list: List[str]) -> List[SolTxCostInfo]:
        request = f'''
            SELECT {', '.join(f'a.{c}' for c in self._column_list)}
              FROM {self._table_name} a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE a.sol_sig IN ({', '.join(['%s' for _ in sig_list])})
        '''

        row_list = self._db.fetch_all(request, sig_list)

        sol_cost_list: List[SolTxCostInfo] = list()
        for value_list in row_list:
            cost_info = SolTxCostInfo(
                sol_sig=self._get_column_value('sol_sig', value_list),
                block_slot=self._get_column_value('block_slot', value_list),
                operator=self._get_column_value('operator', value_list),
                sol_spent=self._get_column_value('sol_spent', value_list)
            )
            sol_cost_list.append(cost_info)
        return sol_cost_list

    def finalize_block_list(self, base_block_slot: int, block_slot_list: List[int]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({', '.join(['%s' for _ in block_slot_list])})
        '''
        self._db.update_row(request, [base_block_slot, block_slot_list[-1]] + block_slot_list)
