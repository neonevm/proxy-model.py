import psycopg2
import psycopg2.extras
from .utils import BaseDB
from ..common_neon.utils import SolanaBlockInfo


class SolanaBlocksDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._column_lst = ('slot', 'finalized', 'height', 'hash')
        self._full_column_lst = ('slot', 'finalized', 'height', 'hash', 'parent_hash', 'blocktime', 'signatures')

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_blocks'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                slot BIGINT,
                finalized BOOLEAN,
                height BIGINT,
                hash CHAR(66),

                parent_hash CHAR(66),
                blocktime BIGINT,
                signatures BYTEA,

                UNIQUE(slot, finalized)
            );
            CREATE INDEX IF NOT EXISTS {self._table_name}_hash ON {self._table_name}(hash, finalized);
            CREATE INDEX IF NOT EXISTS {self._table_name}_height ON {self._table_name}(height, finalized);
            """

    def _block_from_value(self, value, slot=None) -> SolanaBlockInfo:
        if not value:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            slot=value[0],
            finalized=value[1],
            height=value[2],
            hash=value[3],
        )

    def _full_block_from_value(self, value, slot=None) -> SolanaBlockInfo:
        if not value:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            slot=value[0],
            finalized=value[1],
            height=value[2],
            hash=value[3],
            parent_hash=value[4],
            time=value[5],
            signs=self.decode_list(value[6])
        )

    def get_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        return self._block_from_value(
            self._fetchone(self._column_lst, [('slot', block_slot)], ['finalized desc']),
            block_slot)

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        return self._full_block_from_value(
            self._fetchone(self._full_column_lst, [('slot', block_slot)], ['finalized desc']),
            block_slot)

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        return self._block_from_value(
            self._fetchone(self._column_lst, [('hash', block_hash)], ['finalized desc']))

    def get_block_by_height(self, block_num) -> SolanaBlockInfo:
        return self._block_from_value(
            self._fetchone(self._column_lst, [('height', block_num)], ['finalized desc']))

    def get_latest_block_height(self) -> int:
        result = self._fetchone(['height'], [], ['height desc'])
        if result:
            return result[0]
        return 0

    def set_block(self, block: SolanaBlockInfo):
        cursor = self._conn.cursor()
        cursor.execute(f'''
            INSERT INTO {self._table_name}
            ({', '.join(self._full_column_lst)})
            VALUES
            ({', '.join(['%s' for _ in range(len(self._full_column_lst))])})
            ON CONFLICT (slot, finalized) DO UPDATE SET
                hash=EXCLUDED.hash,
                height=EXCLUDED.height,
                parent_hash=EXCLUDED.parent_hash,
                blocktime=EXCLUDED.blocktime,
                signatures=EXCLUDED.signatures
            ''',
            (block.slot, block.finalized, block.height, block.hash,
             block.parent_hash, block.time, self.encode_list(block.signs)))

    def _insert_execute_values(self, slot_heights) -> None:
        with self._conn.cursor() as cursor:
            psycopg2.extras.execute_values(cursor, f"""
                INSERT
                INTO {self._table_name} (slot, finalized, height)
                VALUES %s
                ON CONFLICT (slot, finalized) DO UPDATE
                SET finalized = True;
            """, (row for row in slot_heights), template="(%s, True, %s)", page_size=1000)

    def fill_block_height(self, height, slots):
        rows = []
        for slot in slots:
            rows.append((slot, height))
            height += 1

        self._insert_execute_values(rows)

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot >= %s AND slot <= %s AND finalized = false',
                       (from_slot, to_slot))
