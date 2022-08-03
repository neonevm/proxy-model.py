from typing import Optional, NamedTuple
from ..indexer.base_db import BaseDB


class SolTxSignSlotInfo(NamedTuple):
    sign: str
    slot: int


class SolSignsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'solana_transaction_signatures')

    def add_sign(self, info: SolTxSignSlotInfo) -> None:
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                (slot, signature)
                VALUES(%s, %s) ON CONFLICT DO NOTHING''',
                (info.slot, info.sign))

    def get_next_sign(self, slot: int) -> Optional[SolTxSignSlotInfo]:
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                SELECT slot, signature FROM {self._table_name}
                WHERE slot > {slot} ORDER BY slot LIMIT 1''')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSignSlotInfo(row[0], row[1])
            return None

    def get_max_sign(self) -> Optional[SolTxSignSlotInfo]:
        with self._conn.cursor() as cursor:
            cursor.execute(f'SELECT slot, signature FROM {self._table_name} ORDER BY slot DESC LIMIT 1')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSignSlotInfo(row[0], row[1])
            return None
