from typing import List, Any, Iterator

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from ..indexer.indexed_objects import SolNeonIxReceiptInfo


class SolNeonTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_neon_transactions',
            column_list=[
                'sol_sig', 'block_slot', 'idx', 'inner_idx', 'neon_sig', 'neon_step_cnt', 'neon_income',
                'neon_gas_used', 'neon_total_gas_used', 'heap_size', 'max_bpf_cycle_cnt', 'used_bpf_cycle_cnt'
            ],
            key_list=['sol_sig', 'block_slot', 'idx', 'inner_idx']
        )

    def set_tx_list(self, iter_sol_neon_ix: Iterator[SolNeonIxReceiptInfo]) -> None:
        row_list: List[List[Any]] = list()
        for ix in iter_sol_neon_ix:
            value_list: List[Any] = list()
            for idx, column in enumerate(self._column_list):
                if column == 'neon_sig':
                    value_list.append(ix.neon_tx_sig)
                elif column == 'neon_income':
                    value_list.append(None)
                elif column == 'heap_size':
                    value_list.append(ix.used_heap_size)
                elif column == 'neon_total_gas_used':
                    neon_total_gas_used = ix.neon_total_gas_used
                    if ix.neon_total_gas_used == 0:
                        neon_total_gas_used = 9199999999999999999
                    value_list.append(neon_total_gas_used)
                elif hasattr(ix, column):
                    value_list.append(getattr(ix, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            row_list.append(value_list)

        self._insert_row_list(row_list)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        request = f'''
            SELECT sol_sig, neon_total_gas_used
              FROM {self._table_name} AS a
             WHERE neon_sig = %s
          ORDER BY neon_total_gas_used
        '''

        row_list = self._db.fetch_all(request, (neon_sig,))

        prev_sol_sig = ''
        sol_sig_list: List[str] = list()
        for value_list in row_list:
            sol_sig = value_list[0]
            if prev_sol_sig == sol_sig:
                continue
            sol_sig_list.append(sol_sig)
            prev_sol_sig = sol_sig

        return sol_sig_list

    def finalize_block_list(self, base_block_slot: int, block_slot_list: List[int]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({', '.join(['%s' for _ in block_slot_list])})
            '''
        self._db.update_row(request, [base_block_slot, block_slot_list[-1]] + block_slot_list)
