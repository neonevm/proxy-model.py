from typing import Optional, NamedTuple
from ..indexer.base_db import BaseDB


class SolTxSignSlotInfo(NamedTuple):
    sol_sign: str
    block_slot: int


class SolSignsDB(BaseDB):
    def __init__(self):
        super().__init__('solana_transaction_signatures')

    def add_sign(self, info: SolTxSignSlotInfo) -> None:
        with self.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                (block_slot, signature)
                VALUES(%s, %s) ON CONFLICT DO NOTHING''',
                (info.block_slot, info.sol_sign))

    def get_next_sign(self, block_slot: int) -> Optional[SolTxSignSlotInfo]:
        with self.cursor() as cursor:
            cursor.execute(f'''
                SELECT block_slot, signature FROM {self._table_name}
                WHERE block_slot > {block_slot} ORDER BY block_slot LIMIT 1''')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSignSlotInfo(sol_sign=row[0], block_slot=row[1])
            return None

    def get_max_sign(self) -> Optional[SolTxSignSlotInfo]:
        with self.cursor() as cursor:
            cursor.execute(f'SELECT signature, block_slot FROM {self._table_name} ORDER BY block_slot DESC LIMIT 1')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSignSlotInfo(sol_sign=row[0], block_slot=row[1])
            return None
