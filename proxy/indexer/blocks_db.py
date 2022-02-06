import psycopg2
import psycopg2.extras
from ..indexer.utils import BaseDB
from ..common_neon.utils import SolanaBlockInfo


class SolanaBlocksDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._full_column_lst = ('slot', 'hash', 'parent_hash', 'blocktime', 'signatures')

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_block'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name}_heights (
                slot BIGINT,
                height BIGINT,

                UNIQUE(slot),
                UNIQUE(height)
            );
            CREATE TABLE IF NOT EXISTS {self._table_name}_hashes (
                slot BIGINT,
                hash CHAR(66),

                parent_hash CHAR(66),
                blocktime BIGINT,
                signatures BYTEA,

                UNIQUE(slot),
                UNIQUE(hash)
            );
            """

    def _fetch_block(self, slot: int, keys) -> SolanaBlockInfo:
        where_expr, where_keys = self._build_where(keys)

        request = f'''
            SELECT a.slot, a.height, b.hash
              FROM {self._table_name}_heights AS a
         LEFT JOIN {self._table_name}_hashes AS b
                ON a.slot = b.slot
             WHERE {where_expr}
             LIMIT 1
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, where_keys)
            values = cursor.fetchone()

        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            finalized=True,
            slot=values[0],
            height=values[1],
            hash=values[2],
        )

    def _fetch_full_block(self, slot: int, keys) -> SolanaBlockInfo:
        where_expr, where_keys = self._build_where(keys)

        request = f'''
            SELECT a.slot, a.height, b.hash, b.parent_hash, b.blocktime, b.signatures
              FROM {self._table_name}_heights AS a
         LEFT JOIN {self._table_name}_hashes AS b
                ON a.slot = b.slot
             WHERE {where_expr}
             LIMIT 1
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, where_keys)
            values = cursor.fetchone()

        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            finalized=True,
            slot=values[0],
            height=values[1],
            hash=values[2],
            parent_hash=values[3],
            time=values[4],
            signs=self.decode_list(values[5])
        )

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._fetch_block(block_slot, [('a.slot', block_slot)])

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        return self._fetch_full_block(block_slot, [('a.slot', block_slot)])

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        return self._fetch_block(None, [('b.hash', block_hash)])

    def get_block_by_height(self, block_num) -> SolanaBlockInfo:
        return self._fetch_block(None, [('a.height', block_num)])

    def set_block(self, block: SolanaBlockInfo):
        cursor = self._conn.cursor()
        cursor.execute(f'''
            INSERT INTO {self._table_name}_hashes
            ({', '.join(self._full_column_lst)})
            VALUES
            ({', '.join(['%s' for _ in range(len(self._full_column_lst))])})
            ON CONFLICT DO NOTHING;
            ''',
            (block.slot, block.hash, block.parent_hash, block.time, self.encode_list(block.signs)))

    def fill_block_height(self, height, slots):
        with self._conn.cursor() as cursor:
            psycopg2.extras.execute_values(cursor, f"""
                INSERT
                INTO {self._table_name}_heights (slot, height)
                VALUES %s
                ON CONFLICT DO NOTHING
            """, ((slot, height+idx) for idx, slot in enumerate(slots)), template="(%s, %s)", page_size=1000)
