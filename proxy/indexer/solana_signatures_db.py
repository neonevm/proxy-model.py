from typing import Optional

from ..common_neon.solana_neon_tx_receipt import SolTxSigSlotInfo
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection


class SolSigsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_transaction_signatures',
            column_list=['block_slot', 'signature'],
            key_list=['block_slot', 'signature']
        )

    def add_sig(self, info: SolTxSigSlotInfo) -> None:
        self._db.run_tx(
            lambda: self._insert_row((info.block_slot, info.sol_sig))
        )

    def get_next_sig(self, block_slot: int) -> Optional[SolTxSigSlotInfo]:
        request = f'''
            SELECT signature,
                   block_slot
              FROM {self._table_name}
             WHERE block_slot > %s
          ORDER BY block_slot
             LIMIT 1
        '''
        value_list = self._fetch_one(request, (block_slot,))
        if not len(value_list):
            return None
        return SolTxSigSlotInfo(sol_sig=value_list[0], block_slot=value_list[1])

    def get_max_sig(self) -> Optional[SolTxSigSlotInfo]:
        request = f'''
            SELECT signature,
                   block_slot
              FROM {self._table_name}
          ORDER BY block_slot DESC
             LIMIT 1
        '''

        value_list = self._fetch_one(request, ())
        if not len(value_list):
            return None
        return SolTxSigSlotInfo(sol_sig=value_list[0], block_slot=value_list[1])
