import json
import logging

from typing import Optional, List, Any, Tuple, Union

from ..common_neon.utils import NeonTxInfo
from ..common_neon.evm_log_decoder import NeonLogTxEvent
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from ..indexer.indexed_objects import NeonIndexedBlockInfo


LOG = logging.getLogger(__name__)


class NeonTxsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='neon_transactions',
            column_list=(
                'sol_sig', 'sol_ix_idx', 'sol_ix_inner_idx', 'block_slot', 'tx_idx',
                'neon_sig', 'tx_type', 'from_addr', 'nonce', 'to_addr', 'contract', 'value', 'calldata',
                'gas_price', 'gas_limit',
                'v', 'r', 's',
                'status', 'is_canceled', 'is_completed', 'gas_used', 'sum_gas_used', 'logs'
            ),
            key_list=('neon_sig', 'block_slot')
        )

        self._base_request_hdr = f'''
            SELECT {', '.join(['a.' + c for c in self._column_list])},
                   b.block_hash
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
        '''

        self._hex_tx_column_set = {'nonce', 'value', 'gas_price', 'gas_limit', 'v', 'r', 's'}
        self._hex_res_column_set = {'status', 'gas_used', 'sum_gas_used'}

    def _tx_from_value(self, value_list: List[Any]) -> Optional[NeonTxReceiptInfo]:
        if not len(value_list):
            return None

        def _decode_hex(name: str) -> int:
            value = self._get_column_value(name, value_list)
            if len(value) > 2:
                return int(value[2:], 16)
            return 0

        neon_tx = NeonTxInfo(
            addr=self._get_column_value('from_addr', value_list),
            sig=self._get_column_value('neon_sig', value_list),
            tx_type=self._get_column_value('tx_type', value_list),
            nonce=_decode_hex('nonce'),
            gas_price=_decode_hex('gas_price'),
            gas_limit=_decode_hex('gas_limit'),
            to_addr=self._get_column_value('to_addr', value_list),
            contract=self._get_column_value('contract', value_list),
            value=_decode_hex('value'),
            calldata=self._get_column_value('calldata', value_list),
            v=_decode_hex('v'),
            r=_decode_hex('r'),
            s=_decode_hex('s')
        )
        neon_tx_res = NeonTxResultInfo()

        for idx, column in enumerate(self._column_list):
            if column == 'logs':
                neon_tx_res.set_event_list(self._decode_event_list(value_list[idx]))

            elif column in self._hex_res_column_set:
                object.__setattr__(neon_tx_res, column, int(value_list[idx][2:], 16))
            elif hasattr(neon_tx_res, column):
                object.__setattr__(neon_tx_res, column, value_list[idx])
            else:
                pass

        object.__setattr__(neon_tx_res, 'block_hash', value_list[-1])
        return NeonTxReceiptInfo(neon_tx=neon_tx, neon_tx_res=neon_tx_res)

    def set_tx_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = []
        for neon_block in neon_block_queue:
            for tx in neon_block.iter_done_neon_tx():
                value_list: List[Any] = []
                for idx, column in enumerate(self._column_list):
                    if column == 'neon_sig':
                        value_list.append(tx.neon_tx.sig)
                    elif column == 'from_addr':
                        value_list.append(tx.neon_tx.addr)
                    elif column == 'logs':
                        value_list.append(self._encode_event_list(tx.neon_tx_res))
                    elif column in self._hex_tx_column_set:
                        value_list.append(hex(getattr(tx.neon_tx, column)))
                    elif column in self._hex_res_column_set:
                        value_list.append(hex(getattr(tx.neon_tx_res, column)))
                    elif hasattr(tx.neon_tx, column):
                        value_list.append(getattr(tx.neon_tx, column))
                    elif hasattr(tx.neon_tx_res, column):
                        value_list.append(getattr(tx.neon_tx_res, column))
                    else:
                        raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
                row_list.append(value_list)

        self._insert_row_list(row_list)

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
               AND b.is_active = True
             WHERE a.neon_sig = %s
        '''
        return self._tx_from_value(self._fetch_one(request, (neon_sig,)))

    def get_tx_by_sender_nonce(self, sender: str, tx_nonce: int) -> Optional[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
               AND b.is_active = True
             WHERE a.from_addr = %s
               AND a.nonce = %s
        '''
        return self._tx_from_value(self._fetch_one(request, (sender, hex(tx_nonce))))

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
             WHERE a.block_slot = %s
          ORDER BY a.tx_idx ASC
        '''
        row_list = self._fetch_all(request, (block_slot,))
        if not row_list:
            return list()

        return [self._tx_from_value(value_list) for value_list in row_list if value_list is not None]

    def get_tx_by_block_slot_tx_idx(self, block_slot: int, tx_idx: int) -> Optional[NeonTxReceiptInfo]:
        request = self._base_request_hdr + '''
             WHERE a.block_slot = %s
               AND a.tx_idx = %s
        '''
        value_list = self._fetch_one(request, (block_slot, tx_idx))
        return self._tx_from_value(value_list)

    def finalize_block_list(self, from_slot: int, to_slot: int, slot_list: Tuple[int, ...]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot <= %s
                    AND block_slot NOT IN %s
            '''
        self._update_row(request, (from_slot, to_slot, slot_list))

    @staticmethod
    def _encode_event_list(tx_res: NeonTxResultInfo) -> str:
        if not len(tx_res.event_list):
            return ''

        return json.dumps([event.as_dict() for event in tx_res.event_list])

    def _decode_event_list(self, value: Union[str, bytes, None]) -> Tuple[NeonLogTxEvent, ...]:
        try:
            if not len(value):
                return ()

            if value.startswith('['):
                value_list = json.loads(value)
                return tuple([NeonLogTxEvent.from_dict(value) for value in value_list])

            # TODO: remove after converting all records
            value_list = [] if not value else self._decode(value)
            return tuple([NeonLogTxEvent.from_rpc_dict(value) for value in value_list])

        except BaseException as exc:
            LOG.warning(f'Cannot decode event list {value}', exc_info=exc)
            return ()
