from typing import List, Any, Iterator, Set

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo, SolNeonIxReceiptShortInfo


class SolNeonTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_neon_transactions',
            column_list=[
                'sol_sig', 'block_slot', 'idx', 'inner_idx', 'ix_code', 'is_success',
                'neon_sig', 'neon_step_cnt', 'neon_gas_used', 'neon_total_gas_used',
                'max_heap_size', 'used_heap_size', 'max_bpf_cycle_cnt', 'used_bpf_cycle_cnt'
            ],
            key_list=['sol_sig', 'block_slot', 'idx', 'inner_idx']
        )

    def set_tx_list(self, iter_sol_neon_ix: Iterator[SolNeonIxReceiptInfo]) -> None:
        row_list: List[List[Any]] = list()
        for ix in iter_sol_neon_ix:
            value_list: List[Any] = list()
            is_success = (ix.status == ix.Status.Success)
            for idx, column in enumerate(self._column_list):
                if column == 'neon_sig':
                    value_list.append(ix.neon_tx_sig)
                elif column == 'neon_total_gas_used':
                    neon_total_gas_used = ix.neon_total_gas_used
                    if (ix.neon_total_gas_used == 0) and (not is_success):
                        neon_total_gas_used = 9199999999999999999
                    value_list.append(neon_total_gas_used)
                elif column == 'is_success':
                    value_list.append(is_success)
                elif hasattr(ix, column):
                    value_list.append(getattr(ix, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            row_list.append(value_list)

        self._insert_row_list(row_list)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        request = f'''
            SELECT a.sol_sig, a.neon_total_gas_used
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE a.neon_sig = %s
          ORDER BY a.block_slot, a.neon_total_gas_used, a.sol_sig
        '''

        row_list = self._db.fetch_all(request, (neon_sig,))

        done_sig_set: Set[str] = set()
        sol_sig_list: List[str] = list()
        for value_list in row_list:
            sol_sig = value_list[0]
            if sol_sig in done_sig_set:
                continue

            done_sig_set.add(sol_sig)
            sol_sig_list.append(sol_sig)

        return sol_sig_list

    def get_sol_ix_info_list_by_neon_sig(self, neon_sig: str) -> List[SolNeonIxReceiptShortInfo]:
        request = f'''
            SELECT {', '.join(f'a.{c}' for c in self._column_list)}
              FROM {self._table_name} a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE a.neon_sig = %s
          ORDER BY a.block_slot, a.neon_total_gas_used
        '''

        row_list = self._db.fetch_all(request, (neon_sig,))

        sol_ix_list: List[SolNeonIxReceiptShortInfo] = list()

        for value_list in row_list:
            ix_info = SolNeonIxReceiptShortInfo(
                sol_sig=self._get_column_value('sol_sig', value_list),
                block_slot=self._get_column_value('block_slot', value_list),
                idx=self._get_column_value('idx', value_list),
                inner_idx=self._get_column_value('inner_idx', value_list),
                ix_code=self._get_column_value('ix_code', value_list),
                is_success=self._get_column_value('is_success', value_list),
                neon_step_cnt=self._get_column_value('neon_step_cnt', value_list),
                neon_gas_used=self._get_column_value('neon_gas_used', value_list),
                neon_total_gas_used=self._get_column_value('neon_total_gas_used', value_list),
                max_heap_size=self._get_column_value('max_heap_size', value_list),
                used_heap_size=self._get_column_value('used_heap_size', value_list),
                max_bpf_cycle_cnt=self._get_column_value('max_bpf_cycle_cnt', value_list),
                used_bpf_cycle_cnt=self._get_column_value('used_bpf_cycle_cnt', value_list),
            )
            sol_ix_list.append(ix_info)

        return sol_ix_list

    def finalize_block_list(self, base_block_slot: int, block_slot_list: List[int]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({', '.join(['%s' for _ in block_slot_list])})
            '''
        self._db.update_row(request, [base_block_slot, block_slot_list[-1]] + block_slot_list)
