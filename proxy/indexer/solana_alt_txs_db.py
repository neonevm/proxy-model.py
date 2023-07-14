from typing import List, Any

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_neon_tx_receipt import SolAltIxInfo, SolTxCostInfo

from .indexed_objects import NeonIndexedBlockInfo


class SolAltTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_alt_transactions',
            column_list=[
                'sol_sig', 'block_slot', 'idx', 'inner_idx', 'is_success', 'ix_code', 'alt_address', 'neon_sig'
            ],
            key_list=['sol_sig', 'block_slot', 'idx', 'inner_idx']
        )

        self._select_request = f'''
            SELECT DISTINCT {', '.join(f'a.{c}' for c in self._column_list)},
                   c.operator, c.sol_spent
              FROM {self._table_name} a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
        INNER JOIN {self._tx_costs_table_name} AS c
                ON c.sol_sig = a.sol_sig
             WHERE a.neon_sig = %s
          ORDER BY a.block_slot, a.sol_sig, a.idx, a.inner_idx
        '''

    def set_tx_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = list()
        for neon_block in neon_block_queue:
            for ix in neon_block.iter_sol_alt_ix():
                value_list: List[Any] = list()
                for idx, column in enumerate(self._column_list):
                    if column == 'inner_idx':
                        # Postgres version < 14 doesn't work correctly with NULLs in UNIQUE keys
                        value_list.append(ix.inner_idx if ix.inner_idx is not None else -1)
                    elif column == 'neon_sig':
                        value_list.append(ix.neon_tx_sig)
                    elif hasattr(ix, column):
                        value_list.append(getattr(ix, column))
                    else:
                        raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
                row_list.append(value_list)

        self._insert_row_list(row_list)

    def get_alt_ix_list_by_neon_sig(self, neon_sig: str) -> List[SolAltIxInfo]:
        row_list = self._db.fetch_all(self._select_request, (neon_sig,))

        alt_ix_list: List[SolAltIxInfo] = list()

        for value_list in row_list:
            sol_sig = self._get_column_value('sol_sig', value_list)
            block_slot = self._get_column_value('block_slot', value_list)
            inner_idx = self._get_column_value('inner_idx', value_list)
            if inner_idx == -1:
                inner_idx = None
            operator = value_list[-2]
            sol_spent = value_list[-1]
            ix_info = SolAltIxInfo(
                sol_sig=sol_sig,
                block_slot=block_slot,
                idx=self._get_column_value('idx', value_list),
                inner_idx=inner_idx,
                ix_code=self._get_column_value('ix_code', value_list),
                alt_address=self._get_column_value('alt_address', value_list),
                is_success=self._get_column_value('is_success', value_list),
                neon_tx_sig=self._get_column_value('neon_sig', value_list),
                sol_tx_cost=SolTxCostInfo(
                    sol_sig=sol_sig,
                    block_slot=block_slot,
                    operator=operator,
                    sol_spent=sol_spent
                )
            )
            alt_ix_list.append(ix_info)
        return alt_ix_list

    def get_alt_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        request = f'''
            SELECT DISTINCT a.block_slot, a.sol_sig
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE a.neon_sig = %s
          ORDER BY a.block_slot, a.sol_sig
        '''

        row_list = self._db.fetch_all(request, (neon_sig,))

        alt_sig_list: List[str] = list()
        for value_list in row_list:
            sol_sig = value_list[1]
            alt_sig_list.append(sol_sig)
        return alt_sig_list
