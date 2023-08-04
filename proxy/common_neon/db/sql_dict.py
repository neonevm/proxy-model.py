from collections.abc import MutableMapping
from typing import List, Tuple, Any

from .db_connect import DBConnection
from .base_db_table import BaseDBTable


class SQLDict(MutableMapping, BaseDBTable):
    def __init__(self, db_conn: DBConnection, table_name: str):
        super().__init__(db_conn, table_name, ['key', 'value'], ['key'])

    def __len__(self) -> int:
        request = f'SELECT COUNT(*) FROM {self._table_name}'
        value_list = self._db.fetch_one(request)
        return 0 if not len(value_list) else value_list[0]

    def _key_list(self) -> List[str]:
        request = f'SELECT key FROM {self._table_name}'
        row_list = self._db.fetch_all(request)
        return [r[0] for r in row_list]

    def _value_list(self) -> List[str]:
        request = f'SELECT value FROM {self._table_name}'
        row_list = self._db.fetch_all(request)
        return [self._decode(r[0]) for r in row_list]

    def _item_list(self) -> List[Tuple[str, Any]]:
        request = f'SELECT key, value FROM {self._table_name}'
        row_list = self._db.fetch_all(request)
        return [(r[0], self._decode(r[1])) for r in row_list]

    def keys(self) -> List[str]:
        return self._key_list()

    def values(self) -> List[str]:
        return self._value_list()

    def items(self) -> List[Tuple[str, Any]]:
        return self._item_list()

    def __contains__(self, key: str) -> bool:
        request = f'SELECT 1 FROM {self._table_name} WHERE key = %s'
        value_list = self._db.fetch_one(request, (key,))
        return len(value_list) > 0

    def __getitem__(self, key) -> Any:
        request = f'SELECT value FROM {self._table_name} WHERE key = %s'
        value_list = self._db.fetch_one(request, (key,))
        if not len(value_list):
            raise KeyError(key)
        return self._decode(value_list[0])

    def __setitem__(self, key: str, value: Any) -> None:
        self._db.run_tx(
            lambda: self._insert_row([key, self._encode(value)])
        )

    def __delitem__(self, key):
        if key not in self:
            raise KeyError(key)
        request = f'DELETE FROM {self._table_name} WHERE key = %s'
        self._db.run_tx(
            lambda: self._db.update_row(request, (key,))
        )

    def __iter__(self):
        for key in self._key_list():
            yield key
