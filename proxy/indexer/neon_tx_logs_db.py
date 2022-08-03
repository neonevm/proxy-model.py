from typing import List, Any, Optional, Dict, Iterator

from ..indexer.base_db import BaseDB
from ..indexer.indexed_objects import NeonIndexedTxInfo


class NeonTxLogsDB(BaseDB):
    def __init__(self):
        super().__init__('neon_transaction_logs')
        self._column_list = ['address', 'log_data', 'block_hash', 'block_slot',
                             'tx_hash', 'tx_idx', 'tx_log_idx', 'log_idx', 'topic', 'topic_list']

        self._column2field_dict = {
            'address': 'address',
            'log_data': 'data',
            'block_hash': 'blockHash',
            'block_slot': 'blockNumber',
            'tx_hash': 'transactionHash',
            'tx_idx': 'transactionIndex',
            'tx_log_idx': 'transactionLogIndex',
            'log_idx': 'logIndex',
        }

        self._hex_field_dict = ['blockNumber', 'transactionIndex', 'transactionLogIndex', 'logIndex']

    def set_tx_list(self, cursor: BaseDB.Cursor, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        value_list_list: List[List[Any]] = []
        for tx in iter_neon_tx:
            for log in tx.neon_tx_res.logs:
                for topic in log['topics']:
                    value_list: List[Any] = []
                    for idx, column in enumerate(self._column_list):
                        if column == 'topic':
                            value_list.append(topic)
                        elif column == 'topic_list':
                            value_list.append(self._encode_list(log['topics']))
                        else:
                            key = self._column2field_dict.get(column, None)
                            if key in log:
                                value = log[key]
                                if key in self._hex_field_dict:
                                    value = int(value[2:], 16)
                                value_list.append(value)
                            else:
                                raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')
                    value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)

    def _log_from_value(self, value_list: List[Any]) -> Dict[str, Any]:
        log: Dict[str, Any] = {}
        for idx, column in enumerate(self._column_list):
            if column == 'topic':
                pass
            elif column == 'topic_list':
                log['topics'] = self._decode_list(value_list[idx])
            else:
                key = self._column2field_dict.get(column, None)
                value = value_list[idx]
                if key in self._hex_field_dict:
                    value = '0x' + hex(value)
                log[key] = value
        return log

    def get_logs(self, from_block: Optional[int],
                 to_block: Optional[int],
                 address_list: List[str],
                 topic_list: List[str],
                 block_hash: Optional[str]):
        query_list: List[str] = []
        param_list: List[Any] = []

        if from_block is not None:
            query_list.append('block_slot >= %s')
            param_list.append(from_block)

        if to_block is not None:
            query_list.append('block_slot <= %s')
            param_list.append(to_block)

        if block_hash is not None:
            block_hash = block_hash.lower()
            query_list.append('block_hash = %s')
            param_list.append(block_hash)

        if len(topic_list) > 0:
            query_placeholder = ', '.join(['%s' for _ in range(len(topic_list))])
            topics_query = f'topic IN ({query_placeholder})'

            query_list.append(topics_query)
            param_list += topic_list

        if len(address_list) > 0:
            query_placeholder = ', '.join(['%s' for _ in range(len(address_list))])
            address_query = f'address IN ({query_placeholder})'

            query_list.append(address_query)
            param_list += address_list

        query_string = f'SELECT {",".join(self._column_list)} FROM {self._table_name} WHERE 1=1'
        for query in query_list:
            query_string += ' AND ' + query

        query_string += ' ORDER BY block_slot desc LIMIT 1000'

        self.debug(query_string)
        self.debug(param_list)

        with self._conn.cursor() as cursor:
            cursor.execute(query_string, tuple(param_list))
            row_list = cursor.fetchall()

        row_list = set([row[0] for row in row_list])
        return [self._log_from_value(value_list) for value_list in row_list]
