from typing import Optional, List, Any, Iterator

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxReceiptInfo

from ..indexer.indexed_objects import NeonIndexedTxInfo
from ..indexer.base_db import BaseDB, DBQuery


class NeonTxsDB(BaseDB):
    def __init__(self):
        super().__init__('neon_transactions')
        self._column_list = ['neon_sign', 'from_addr', 'sol_sign', 'sol_ix_idx', 'sol_ix_inner_idx', 'block_slot',
                             'block_hash', 'tx_idx', 'nonce', 'gas_price', 'gas_limit', 'to_addr', 'contract', 'value',
                             'calldata', 'v', 'r', 's', 'status', 'gas_used', 'return_value', 'logs']

    def _tx_from_value(self, value_list: List[Any]) -> Optional[NeonTxReceiptInfo]:
        if not value_list:
            return None

        neon_tx = NeonTxInfo()
        neon_tx_res = NeonTxResultInfo()

        for idx, column in enumerate(self._column_list):
            if column == 'neon_sign':
                neon_tx.sign = value_list[idx]
            elif column == 'from_addr':
                neon_tx.addr = value_list[idx]
            elif column == 'logs':
                neon_tx_res.logs = self._decode_list(value_list[idx])
            elif column == 'block_slot':
                neon_tx_res.slot = value_list[idx]
            elif hasattr(neon_tx, column):
                setattr(neon_tx, column, value_list[idx])
            elif hasattr(neon_tx_res, column):
                setattr(neon_tx_res, column, value_list[idx])
            else:
                pass

        return NeonTxReceiptInfo(neon_tx=neon_tx, neon_res=neon_tx_res)

    def set_tx_list(self, cursor: BaseDB.Cursor, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for tx in iter_neon_tx:
            value_list: List[Any] = []
            for idx, column in enumerate(self._column_list):
                if column == 'neon_sign':
                    value_list.append(tx.neon_tx.sign)
                elif column == 'from_addr':
                    value_list.append(tx.neon_tx.addr)
                elif column == 'logs':
                    value_list.append(self._encode_list(tx.neon_tx_res.logs))
                elif column == 'block_slot':
                    value_list.append(tx.neon_tx_res.slot)
                elif hasattr(tx.neon_tx, column):
                    value_list.append(getattr(tx.neon_tx, column))
                elif hasattr(tx.neon_tx_res, column):
                    value_list.append(getattr(tx.neon_tx_res, column))
                else:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
            value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)

    def get_tx_by_neon_sign(self, neon_sign) -> Optional[NeonTxReceiptInfo]:
        return self._tx_from_value(
            self._fetchone(DBQuery(
                key_list=[('neon_sign', neon_sign)],
                order_list=[],
            ))
        )

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        value_list = self._fetchall(DBQuery(
            key_list=[('block_slot', block_slot)],
            order_list=['tx_idx ASC'],
        ))

        if not value_list:
            return []

        return [self._tx_from_value(v) for v in value_list if v is not None]
