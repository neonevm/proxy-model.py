from typing import Optional, List, Any

from ..indexer.base_db import BaseDB, DBQuery
from ..common_neon.utils import SolanaBlockInfo


class SolBlocksDB(BaseDB):
    def __init__(self):
        super().__init__('solana_blocks')
        self._column_list = ['block_slot', 'block_hash', 'block_time', 'parent_block_slot', 'is_finalized']

    @staticmethod
    def _block_from_value(block_slot: Optional[int], value_list: List[Any]) -> SolanaBlockInfo:
        if not value_list:
            return SolanaBlockInfo(slot=block_slot)

        return SolanaBlockInfo(
            slot=value_list[0],
            hash=value_list[1],
            time=value_list[2],
            parent_block_slot=value_list[3],
            is_finalized=value_list[4]
        )

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        q = DBQuery(key_list=[('block_slot', block_slot)], order_list=[])
        return self._block_from_value(block_slot, self._fetchone(q))

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        q = DBQuery(key_list=[('block_hash', block_hash)], order_list=[])
        return self._block_from_value(None, self._fetchone(q))

    def set_block(self, cursor: BaseDB.Cursor, block: SolanaBlockInfo, is_finalized: bool) -> None:
        cursor.execute(
            f'''
              INSERT INTO {self._table_name}
                ({','.join(self._column_list)})
              VALUES
                ({', '.join(['%s' for _ in range(len(self._column_list))])})
              ON CONFLICT DO NOTHING;
            ''',
            (block.slot, block.hash, block.time, block.parent_block_slot, is_finalized)
        )

    def finalize_block(self, cursor: BaseDB.Cursor, block: SolanaBlockInfo, is_finalized: bool):
        cursor.execute(
            f'''
                UPDATE {self._table_name} SET
                   is_finalized = %s
                WHERE
                   block_slot = %s
            ''',
            (is_finalized, block.slot)
        )