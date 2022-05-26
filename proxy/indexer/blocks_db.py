import psycopg2
import psycopg2.extras

from typing import Optional, List, Tuple

from ..indexer.base_db import BaseDB, DBQuery
from ..common_neon.utils import SolanaBlockInfo


class SolanaBlocksDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'solana_block')
        self._column_lst = ('slot', 'hash')
        self._full_column_lst = ('slot', 'hash', 'blocktime')
        self._full_column_name_lst = '(' + ', '.join(self._full_column_lst) + ')'
        self._full_column_tmpl_lst = '(' + ', '.join(['%s' for _ in range(len(self._full_column_lst))]) + ')'

    @staticmethod
    def _block_from_value(slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            is_finalized=True,
            slot=values[0],
            hash=values[1],
        )

    @staticmethod
    def _full_block_from_value(slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            is_finalized=True,
            slot=values[0],
            hash=values[1],
            time=values[2]
        )

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._column_lst, key_list=[('slot', block_slot)], order_list=[])
        return self._block_from_value(block_slot, self._fetchone(q))

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._full_column_lst, key_list=[('slot', block_slot)], order_list=[])
        return self._full_block_from_value(block_slot, self._fetchone(q))

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._column_lst, key_list=[('hash', block_hash)], order_list=[])
        return self._block_from_value(None, self._fetchone(q))

    @staticmethod
    def _block_record(block: SolanaBlockInfo) -> Tuple[int, str, int]:
        return block.slot, block.hash, block.time

    def set_block(self, block: SolanaBlockInfo):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                {self._full_column_name_lst}
                VALUES
                {self._full_column_tmpl_lst}
                ON CONFLICT DO NOTHING;
                ''',
                self._block_record(block))

    def set_block_list(self, block_info_list: List[SolanaBlockInfo]) -> None:
        with self._conn.cursor() as cursor:
            psycopg2.extras.execute_values(cursor, f'''
                INSERT INTO {self._table_name}
                {self._full_column_name_lst}
                VALUES %s
                ON CONFLICT DO NOTHING;
                ''',
                (self._block_record(block) for block in block_info_list if block.hash),
                template=self._full_column_tmpl_lst,
                page_size=1000)
