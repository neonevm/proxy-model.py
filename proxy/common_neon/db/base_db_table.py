from __future__ import annotations

import logging

from pickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL
from typing import List, Tuple, Dict, Any, Optional, Union, Set

import psycopg2

from .db_connect import DBConnection


LOG = logging.getLogger(__name__)


class BaseDBTable:
    def __init__(self, db: DBConnection, table_name: str, column_list: List[str], key_list: List[str]):
        assert len(column_list) > 0

        self._db = db
        self._table_name = table_name
        self._blocks_table_name = 'solana_blocks'

        self._column_list = column_list
        self._column_dict: Dict[str, int] = {name: idx for idx, name in enumerate(column_list)}
        assert len(self._column_list) == len(self._column_dict)

        for key in key_list:
            assert key in self._column_dict
        key_set: Set[str] = set(key_list)
        assert len(key_set) == len(key_list)
        self._key_list = key_list
        self._key_set = key_set

        column_list_expr = ', '.join(column_list)
        insert_list_expr = ', '.join(['%s' for _ in column_list])

        if 0 < len(key_list) < len(column_list):
            conflict_list_expr = ', '.join(key_list)
            update_list_expr = ', '.join([f'{c} = EXCLUDED.{c}' for c in column_list if c not in key_set])
            update_expr = f'ON CONFLICT ({conflict_list_expr}) DO UPDATE SET {update_list_expr}'
        else:
            update_expr = 'ON CONFLICT DO NOTHING'

        self._insert_row_list_request = f'''
            INSERT INTO {table_name}
                ({column_list_expr})
            VALUES
                %s
            {update_expr}
        '''

        self._insert_row_request = f'''
            INSERT INTO {table_name}
                ({column_list_expr})
            VALUES
                ({insert_list_expr})
            {update_expr}
        '''

    def _get_column_value(self, column_name: str, value_list: List[Any]) -> Any:
        idx = self._column_dict.get(column_name, None)
        assert idx is not None, f'Cannot find column {self._table_name}.{column_name}'
        return value_list[idx]

    @staticmethod
    def _encode(obj: Any) -> psycopg2.Binary:
        return psycopg2.Binary(dumps(obj, protocol=PICKLE_PROTOCOL))

    @staticmethod
    def _decode(obj: Any) -> Any:
        return loads(bytes(obj))

    def _decode_list(self, v: Optional[bytes]) -> List[Any]:
        return [] if not v else self._decode(v)

    def _encode_list(self, v: List[Any]) -> Optional[bytes]:
        return None if (not v) or (len(v) == 0) else self._encode(v)

    def _insert_row(self, value_list: Union[Tuple[Any,...], List[Any]]) -> None:
        assert len(self._column_list) == len(value_list)
        self._db.update_row(self._insert_row_request, value_list)

    def _remove_dups(self, row_list: List[List[Any]]) -> List[List[Any]]:
        if not len(self._key_set):
            return row_list

        done_key_set: Set[str] = set()
        result_row_list: List[List[Any]] = list()

        # filter in reverse order to get the latest value
        for value_list in reversed(row_list):
            assert len(value_list) == len(self._column_list)
            key = ':'.join([
                str(value)
                for idx, value in enumerate(value_list)
                if self._column_list[idx] in self._key_set
            ])
            if key in done_key_set:
                continue
            done_key_set.add(key)
            result_row_list.append(value_list)
        return result_row_list

    def _insert_row_list(self, row_list: List[List[Any]]) -> None:
        if len(row_list) == 0:
            return

        row_list = self._remove_dups(row_list)
        self._db.update_row_list(self._insert_row_list_request, row_list)
