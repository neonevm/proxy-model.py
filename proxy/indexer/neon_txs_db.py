from typing import Optional, List, Any, Iterator

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxReceiptInfo
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from ..indexer.indexed_objects import NeonIndexedTxInfo


class NeonTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='neon_transactions',
            column_list=[
                'neon_sig', 'from_addr', 'sol_sig', 'sol_ix_idx', 'sol_ix_inner_idx', 'block_slot',
                'tx_idx', 'nonce', 'gas_price', 'gas_limit', 'to_addr', 'contract', 'value',
                'calldata', 'v', 'r', 's', 'status', 'gas_used', 'logs'
            ],
            key_list=['neon_sig', 'block_slot']
        )

        self._base_request_hdr = f'''
            SELECT {', '.join(['a.' + c for c in self._column_list])},
                   b.block_hash
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
        '''

    def _tx_from_value(self, value_list: List[Any]) -> Optional[NeonTxReceiptInfo]:
        if not len(value_list):
            return None

        neon_tx = NeonTxInfo(
            addr=self._get_column_value('from_addr', value_list),
            sig=self._get_column_value('neon_sig', value_list),
            nonce=self._get_column_value('nonce', value_list),
            gas_price=self._get_column_value('gas_price', value_list),
            gas_limit=self._get_column_value('gas_limit', value_list),
            to_addr=self._get_column_value('to_addr', value_list),
            contract=self._get_column_value('contract', value_list),
            value=self._get_column_value('value', value_list),
            calldata=self._get_column_value('calldata', value_list),
            v=self._get_column_value('v', value_list),
            r=self._get_column_value('r', value_list),
            s=self._get_column_value('s', value_list)
        )
        neon_tx_res = NeonTxResultInfo()

        for idx, column in enumerate(self._column_list):
            if column == 'logs':
                neon_tx_res.log_list.extend(self._decode_list(value_list[idx]))
            elif hasattr(neon_tx_res, column):
                object.__setattr__(neon_tx_res, column, value_list[idx])
            else:
                pass

        object.__setattr__(neon_tx_res, 'block_hash', value_list[-1])
        return NeonTxReceiptInfo(neon_tx=neon_tx, neon_tx_res=neon_tx_res)

    def set_tx_list(self, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for tx in iter_neon_tx:
            value_list: List[Any] = []
            for idx, column in enumerate(self._column_list):
                if column == 'neon_sig':
                    value_list.append(tx.neon_tx.sig)
                elif column == 'from_addr':
                    value_list.append(tx.neon_tx.addr)
                elif column == 'logs':
                    value_list.append(self._encode_list(tx.neon_tx_res.log_list))
                elif hasattr(tx.neon_tx, column):
                    value_list.append(getattr(tx.neon_tx, column))
                elif hasattr(tx.neon_tx_res, column):
                    value_list.append(getattr(tx.neon_tx_res, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            value_list_list.append(value_list)

        self._insert_row_list(value_list_list)

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
               AND b.is_active = True
             WHERE a.neon_sig = %s
        '''
        return self._tx_from_value(self._db.fetch_one(request, (neon_sig,)))

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
             WHERE a.block_slot = %s
          ORDER BY a.tx_idx ASC
        '''
        row_list = self._db.fetch_all(request, (block_slot,))
        if not row_list:
            return list()

        return [self._tx_from_value(value_list) for value_list in row_list if value_list is not None]

    def get_tx_by_block_slot_tx_idx(self, block_slot: int, tx_idx: int) -> Optional[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
             WHERE a.block_slot = %s
               AND a.tx_idx = %s
        '''
        value_list = self._db.fetch_one(request, (block_slot, tx_idx))
        return self._tx_from_value(value_list)

    def finalize_block_list(self, base_block_slot: int, block_slot_list: List[int]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({','.join(["%s" for _ in block_slot_list])})
            '''
        self._db.update_row(request, [base_block_slot, block_slot_list[-1]] + block_slot_list)
