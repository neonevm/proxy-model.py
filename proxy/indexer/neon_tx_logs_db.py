from typing import List, Any, Optional, Dict, Tuple

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.evm_log_decoder import NeonLogTxEvent

from ..indexer.indexed_objects import NeonIndexedBlockInfo


class NeonTxLogsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='neon_transaction_logs',
            column_list=(
                'log_topic1', 'log_topic2', 'log_topic3', 'log_topic4',
                'log_topic_cnt', 'log_data',
                'block_slot', 'tx_hash', 'tx_idx', 'tx_log_idx', 'log_idx', 'address',
                'event_order', 'event_level', 'sol_sig', 'idx', 'inner_idx'
            ),
            key_list=('block_slot', 'tx_hash', 'tx_log_idx')
        )

        self._column2field_dict = {
            'address': 'address',
            'log_data': 'data',
            'block_slot': 'block_slot',
            'tx_hash': 'neon_sig',
            'tx_idx': 'neon_tx_idx',
            'tx_log_idx': 'neon_tx_log_idx',
            'log_idx': 'block_log_idx',
            'event_level': 'event_level',
            'event_order': 'event_order',
            'sol_sig': 'sol_sig',
            'idx': 'idx',
            'inner_idx': 'inner_idx'
        }

        self._topic_column_list = ('log_topic1', 'log_topic2', 'log_topic3', 'log_topic4')

    def set_tx_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = list()
        for neon_block in neon_block_queue:
            for tx in neon_block.iter_done_neon_tx():
                for event in tx.neon_tx_res.event_list:
                    if event.is_hidden or (len(event.topic_list) == 0):
                        continue

                    event_dict = event.as_dict()
                    value_list: List[Any] = list()
                    for column in self._column_list:
                        if column == 'log_topic_cnt':
                            value_list.append(len(event.topic_list))
                        elif column in self._topic_column_list:
                            idx = int(column[len('log_topic'):])
                            if idx <= len(event.topic_list):
                                value_list.append(event.topic_list[idx - 1])
                            else:
                                value_list.append(None)
                        else:
                            key = self._column2field_dict.get(column, None)
                            value = event_dict[key]
                            value_list.append(value)
                    row_list.append(value_list)

        self._insert_row_list(row_list)

    def _event_from_value(self, value_list: List[Any]) -> NeonLogTxEvent:
        event_dict: Dict[str, Any] = dict()
        topic_list = ['', '', '', '']
        for column, value in zip(self._column_list, value_list):
            if column in self._topic_column_list:
                idx = int(column[len('log_topic'):])
                topic_list[idx] = value
            elif column == 'log_topic_cnt':
                topic_list = topic_list[:value]
            else:
                key = self._column2field_dict.get(column, None)
                event_dict[key] = value
        event_dict['block_hash'] = value_list[-1]
        event_dict['topic_list'] = topic_list
        return NeonLogTxEvent.from_dict(event_dict)

    def get_event_list(self, from_block: Optional[int],
                       to_block: Optional[int],
                       address_list: List[str],
                       topic_list: List[List[str]]) -> List[NeonLogTxEvent]:

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

        request = f'''
            SELECT {', '.join(['a.' + c for c in self._column_list])},
                   b.block_hash
              FROM {self._table_name} AS a
        INNER JOIN {self._blocks_table_name} AS b
                ON b.block_slot = a.block_slot
               AND b.is_active = True
             WHERE {' AND '.join(query_list)}
          ORDER BY a.block_slot DESC, a.log_idx DESC
             LIMIT 1000
         '''

        row_list = self._fetch_all(request, tuple(param_list))

        event_list: List[NeonLogTxEvent] = list()
        for value_list in reversed(row_list):
            event = self._event_from_value(value_list)
            event_list.append(event)

        return event_list

    def finalize_block_list(self, from_slot: int, to_slot: int, slot_list: Tuple[int, ...]) -> None:
        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot <= %s
                    AND block_slot NOT IN %s
            '''
        self._update_row(request, (from_slot, to_slot, slot_list))
