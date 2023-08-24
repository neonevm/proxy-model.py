import json

from typing import List, Dict, Any, Iterator, Tuple, Optional

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from .indexed_objects import NeonIndexedBlockInfo


class StuckNeonHoldersDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='stuck_neon_holders',
            column_list=['block_slot', 'json_data_list'],
            key_list=['block_slot']
        )

        self._select_request = f'''
            SELECT {', '.join(['a.' + c for c in self._column_list])}
              FROM {self._table_name} AS a
             WHERE a.block_slot >= %s
               AND a.block_slot <= %s
        '''

        self._delete_request = f'''
            DELETE FROM {self._table_name}
             WHERE block_slot >= %s
               AND block_slot <= %s
        '''

    def set_holder_list(self, start_slot: int, stop_slot: int, neon_block: NeonIndexedBlockInfo) -> None:
        self._update_row(self._delete_request, (start_slot, stop_slot,))
        if stop_slot <= neon_block.block_slot:
            return

        neon_holder_list = [holder.as_dict() for holder in neon_block.iter_stuck_neon_holder()]
        if not len(neon_holder_list):
            return

        json_data = json.dumps(neon_holder_list)
        self._insert_row((neon_block.stuck_block_slot, json_data))

    def get_holder_list(self, start_slot: int, stop_slot: int) -> Tuple[Optional[int], List[Dict[str, Any]]]:
        value_list = self._fetch_one(self._select_request, (start_slot, stop_slot))

        holder_block_slot: Optional[int] = None
        holder_list: List[Dict[str, Any]] = list()

        if len(value_list):
            holder_block_slot = self._get_column_value('block_slot', value_list)
            holder_list = json.loads(self._get_column_value('json_data_list', value_list))

        return holder_block_slot, holder_list
