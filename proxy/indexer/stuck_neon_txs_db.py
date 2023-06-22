import json

from typing import List, Dict, Any, Iterator, Tuple, Optional

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from .indexed_objects import NeonIndexedTxInfo


class StuckNeonTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='stuck_neon_transactions',
            column_list=['is_finalized', 'block_slot', 'json_data_list'],
            key_list=['is_finalized', 'block_slot']
        )

        self._select_request = f'''
            SELECT {', '.join(['a.' + c for c in self._column_list])}
              FROM {self._table_name} AS a
             WHERE a.is_finalized = %s
               AND a.block_slot > %s
        '''

        self._delete_request = f'''
            DELETE FROM {self._table_name}
             WHERE is_finalized = %s
               AND block_slot != %s
        '''

    def set_tx_list(self, is_finalized: bool, block_slot: int, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        self._db.update_row(self._delete_request, (is_finalized, block_slot,))

        neon_tx_list = [tx.as_dict() for tx in iter_neon_tx]
        if not len(neon_tx_list):
            return

        json_data = json.dumps(neon_tx_list)
        self._insert_row([is_finalized, block_slot, json_data])

    def get_tx_list(self, is_finalized: bool, block_slot: int) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        value_list = self._db.fetch_one(self._select_request, (is_finalized, block_slot,))

        tx_list: List[Dict[str, Any]] = list()
        tx_block_slot: Optional[int] = None

        if len(value_list) > 0:
            tx_block_slot = self._get_column_value('block_slot', value_list)
            tx_list = json.loads(self._get_column_value('json_data_list', value_list))

        return tx_block_slot, tx_list
