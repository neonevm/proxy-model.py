from typing import List, Any, Optional, Dict, Iterator, Set

from ..indexer.base_db import BaseDB
from ..indexer.indexed_objects import NeonIndexedTxInfo


class NeonTxLogsDB(BaseDB):
    def __init__(self):
        super().__init__(
            table_name='neon_transaction_logs',
            column_list=[
                'log_topic1', 'log_topic2', 'log_topic3', 'log_topic4',
                'log_topic_cnt', 'log_data',
                'block_slot', 'tx_hash', 'tx_idx', 'tx_log_idx', 'log_idx', 'address',
                'event_order', 'event_level', 'sol_sig', 'idx', 'inner_idx'
            ]
        )

        self._column2field_dict = {
            'address': 'address',
            'log_data': 'data',
            'block_slot': 'blockNumber',
            'tx_hash': 'transactionHash',
            'tx_idx': 'transactionIndex',
            'tx_log_idx': 'transactionLogIndex',
            'log_idx': 'logIndex',
            'event_level': 'neonEventLevel',
            'event_order': 'neonEventOrder',
            'sol_sig': 'neonSolHash',
            'idx': 'neonIxIdx',
            'inner_idx': 'neonInnerIxIdx'
        }

        self._hex_field_dict = {
            'blockNumber', 'transactionIndex', 'transactionLogIndex', 'logIndex',
            'neonIxIdx', 'neonInnerIxIdx', 'neonEventLevel', 'neonEventOrder'
        }

        self._topic_column_list = ['log_topic1', 'log_topic2', 'log_topic3', 'log_topic4']

    def set_tx_list(self, cursor: BaseDB.Cursor, iter_neon_tx: Iterator[NeonIndexedTxInfo]) -> None:
        value_list_list: List[List[Any]] = list()
        for tx in iter_neon_tx:
            for log in tx.neon_tx_res.log_list:
                topic_list = log['topics']
                if log['neonIsHidden'] or (len(topic_list) == 0):
                    continue

                value_list: List[Any] = list()
                for key, topic_value in zip(self._topic_column_list, topic_list):
                    value_list.append(topic_value)

                while len(value_list) < len(self._topic_column_list):
                    value_list.append(None)

                for idx, column in enumerate(self._column_list):
                    if column in self._topic_column_list:
                        assert idx < len(self._topic_column_list)
                    elif column == 'log_topic_cnt':
                        value_list.append(len(topic_list))
                    else:
                        key = self._column2field_dict.get(column, None)
                        value = log.get(key, None)
                        if value is not None:
                            if key in self._hex_field_dict:
                                value = int(value[2:], 16)
                        value_list.append(value)
                value_list_list.append(value_list)

        self._insert_batch(cursor, value_list_list)

    def _log_from_value(self, value_list: List[Any]) -> Optional[Dict[str, Any]]:
        log: Dict[str, Any] = dict()
        topic_list: List[str] = list()
        for idx, column in enumerate(self._column_list):
            value = value_list[idx]
            if column in self._topic_column_list:
                topic_list.append(value)
            elif column == 'log_topic_cnt':
                log['topics'] = topic_list[:value]
            else:
                key = self._column2field_dict.get(column, None)
                if key is None:
                    raise RuntimeError(f'Wrong usage {self._table_name}: {idx} -> {column}!')

                if (value is not None) and (key in self._hex_field_dict):
                    value = hex(value)
                log[key] = value
        log['blockHash'] = value_list[-1]
        return log

    def get_log_list(self, from_block: Optional[int],
                     to_block: Optional[int],
                     address_list: List[str],
                     topic_list: List[List[str]]) -> List[Dict[str, Any]]:

        query_list: List[str] = ['1 = 1']
        param_list: List[Any] = []

        if from_block is not None:
            query_list.append('a.block_slot >= %s')
            param_list.append(from_block)

        if to_block is not None:
            query_list.append('a.block_slot <= %s')
            param_list.append(to_block)

        for topic_column_name, topic_value in zip(self._topic_column_list, topic_list):
            if len(topic_value) > 0:
                query_placeholder = ', '.join(['%s' for _ in range(len(topic_value))])
                topic_query = f'a.{topic_column_name} IN ({query_placeholder})'
                query_list.append(topic_query)
                param_list += topic_value

        if len(topic_list) > 0:
            query_list.append('a.log_topic_cnt >= %s')
            param_list.append(len(topic_list))

        if len(address_list) > 0:
            query_placeholder = ', '.join(['%s' for _ in range(len(address_list))])
            address_query = f'a.address IN ({query_placeholder})'

            query_list.append(address_query)
            param_list += address_list

        query_string = f'''
            SELECT {",".join(['a.' + c for c in self._column_list])},
                   b.block_hash
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE {' AND '.join(query_list)}
          ORDER BY a.block_slot DESC
             LIMIT 1000
         '''

        with self._conn.cursor() as cursor:
            cursor.execute(query_string, tuple(param_list))
            row_list = cursor.fetchall()

        log_list: List[Dict[str, Any]] = []
        for value_list in row_list:
            log_rec = self._log_from_value(value_list)
            log_list.append(log_rec)

        return log_list

    def finalize_block_list(self, cursor: BaseDB.Cursor, base_block_slot: int, block_slot_list: List[int]) -> None:
        cursor.execute(f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot < %s
                    AND block_slot NOT IN ({','.join(["%s" for _ in block_slot_list])})
            ''',
            [base_block_slot, block_slot_list[-1]] + block_slot_list
        )
