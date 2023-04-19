from typing import List, Any, Iterator

from ..indexer.base_db import BaseDB
from ..indexer.indexed_objects import SolNeonIxReceiptInfo


class SolNeonTxsDB(BaseDB):
    def __init__(self):
        super().__init__(
            table_name='solana_neon_transactions',
            column_list=[
                'sol_sig', 'block_slot', 'idx', 'inner_idx', 'neon_sig', 'neon_step_cnt', 'neon_income',
                'neon_gas_used', 'neon_total_gas_used', 'heap_size', 'max_bpf_cycle_cnt', 'used_bpf_cycle_cnt'
            ]
        )

    def set_tx_list(self, cursor: BaseDB.Cursor, iter_sol_neon_ix: Iterator[SolNeonIxReceiptInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for ix in iter_sol_neon_ix:
            value_list: List[Any] = []
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
            value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        request = f'''
            SELECT sol_sig, neon_total_gas_used
              FROM {self._table_name} AS a
             WHERE neon_sig = %s
             ORDER BY neon_total_gas_used
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, [neon_sig])
            row_list = cursor.fetchall()

        prev_sol_sig = ''
        sol_sig_list: List[str] = list()
        for value_list in row_list:
            sol_sig = value_list[0]
            if prev_sol_sig == sol_sig:
                continue
            sol_sig_list.append(sol_sig)
            prev_sol_sig = sol_sig

        return sol_sig_list

    def finalize_block_list(self, cursor: BaseDB.Cursor, base_block_slot: int, block_slot_list: List[int]) -> None:
        cursor.execute(f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({','.join(["%s" for _ in block_slot_list])})
            ''',
            [base_block_slot, block_slot_list[-1]] + block_slot_list
        )
