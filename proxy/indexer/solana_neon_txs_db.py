from typing import List, Any, Iterator

from ..indexer.base_db import BaseDB
from ..indexer.indexed_objects import NeonIndexedTxInfo


class SolNeonTxsDB(BaseDB):
    def __init__(self):
        super().__init__(
            table_name='solana_neon_transactions',
            column_list=[
                'sol_sig', 'block_slot', 'idx', 'inner_idx', 'neon_sig', 'neon_step_cnt', 'neon_income',
                'heap_size', 'max_bpf_cycle_cnt', 'used_bpf_cycle_cnt'
            ]
        )

    def set_tx_list(self, cursor: BaseDB.Cursor, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for tx in iter_neon_tx:
            gas_price = int(tx.neon_tx.gas_price, 16)
            sol_neon_ix_set = set(tx.iter_sol_neon_ix())
            for ix in sol_neon_ix_set:
                value_list: List[Any] = []
                for idx, column in enumerate(self._column_list):
                    if hasattr(ix, column):
                        value_list.append(getattr(ix, column))
                    elif column == 'neon_sig':
                        value_list.append(tx.neon_tx.sig)
                    elif column == 'neon_income':
                        value_list.append(gas_price * ix.neon_gas_used)
                    else:
                        raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
                value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        request = f'''
            SELECT DISTINCT sol_sig
                       FROM {self._table_name} AS a
                      WHERE neon_sig = %s
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, [neon_sig])
            row_list = cursor.fetchall()

        if not row_list:
            return []

        return [value_list[0] for value_list in row_list]

    def finalize_block_list(self, cursor: BaseDB.Cursor, base_block_slot: int, block_slot_list: List[int]) -> None:
        cursor.execute(f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({','.join(["%s" for _ in block_slot_list])})
            ''',
            [base_block_slot, block_slot_list[-1]] + block_slot_list
        )
