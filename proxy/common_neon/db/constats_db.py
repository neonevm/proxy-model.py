from collections.abc import MutableMapping
from typing import List, Tuple, Any

from .db_connect import DBConnection
from .base_db_table import BaseDBTable


class ConstantsDB(MutableMapping, BaseDBTable):
    def __init__(self, db_conn: DBConnection):
        super().__init__(db_conn, 'constants', ('key', 'value'), ('key',))

        self._len_request = f'SELECT COUNT(*) FROM {self._table_name}'
        self._key_list_request = f'SELECT key FROM {self._table_name}'
        self._value_list_request = f'SELECT value FROM {self._table_name}'
        self._item_list_request = f'SELECT key, value FROM {self._table_name}'
        self._exist_request = f'SELECT 1 FROM {self._table_name} WHERE key = %s'
        self._get_request = f'SELECT value FROM {self._table_name} WHERE key = %s'
        self._update_request = f'UPDATE {self._table_name} SET value = %s WHERE key = %s AND value = %s'
        self._del_request = f'DELETE FROM {self._table_name} WHERE key = %s'

    def __len__(self) -> int:
        value_list = self._fetch_one(self._len_request)
        return 0 if not len(value_list) else value_list[0]

    def _get_key_list(self) -> List[str]:
        row_list = self._fetch_all(self._key_list_request)
        return [r[0] for r in row_list]

    def _get_value_list(self) -> List[Any]:
        row_list = self._fetch_all(self._value_list_request)
        return [self._decode(r[0]) for r in row_list]

    def _get_item_list(self) -> List[Tuple[str, Any]]:
        row_list = self._fetch_all(self._item_list_request)
        return [(r[0], self._decode(r[1])) for r in row_list]

    def keys(self) -> List[str]:
        return self._get_key_list()

    def values(self) -> List[Any]:
        return self._get_value_list()

    def items(self) -> List[Tuple[str, Any]]:
        return self._get_item_list()

    def get(self, key: str, default: Any) -> Any:
        value_list = self._fetch_one(self._get_request, (key,))
        if not len(value_list):
            return default
        return self._decode(value_list[0])

    def __contains__(self, key: str) -> bool:
        value_list = self._fetch_one(self._exist_request, (key,))
        return len(value_list) > 0

    def __getitem__(self, key) -> Any:
        value_list = self._fetch_one(self._get_request, (key,))
        if not len(value_list):
            raise KeyError(key)
        return self._decode(value_list[0])

    def __setitem__(self, key: str, value: Any) -> None:
        self._db.run_tx(
            lambda: self._insert_row((key, self._encode(value)))
        )

    def __delitem__(self, key):
        if key not in self:
            raise KeyError(key)
        self._db.run_tx(
            lambda: self._update_row(self._del_request, (key,))
        )

    def __iter__(self):
        for key in self._get_key_list():
            yield key
