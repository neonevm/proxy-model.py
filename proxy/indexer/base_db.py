from __future__ import annotations

import psycopg2
import psycopg2.extras
import psycopg2.extensions

from typing import NamedTuple, List, Any, Optional
from logged_groups import logged_group

from .pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from .pg_common import encode, decode


class DBQuery(NamedTuple):
    key_list: list
    order_list: list


class DBQueryExpression(NamedTuple):
    column_expr: str
    where_expr: str
    where_keys: list
    order_expr: str


@logged_group("neon.Indexer")
class BaseDB:
    Cursor = psycopg2.extensions.cursor

    def __init__(self, table_name: str):
        self._table_name = table_name
        self._column_list: List[str] = []
        self._conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def _build_expression(self, q: DBQuery) -> DBQueryExpression:
        assert len(self._column_list)
        return DBQueryExpression(
            column_expr=','.join(self._column_list),
            where_expr=' AND '.join(['1=1'] + [f'{name}=%s' for name, _ in q.key_list]),
            where_keys=[value for _, value in q.key_list],
            order_expr='ORDER BY ' + ', '.join(q.order_list) if len(q.order_list) else '',
        )

    def _fetchone(self, query: DBQuery) -> List[Any]:
        e = self._build_expression(query)

        request = f'''
            SELECT {e.column_expr}
              FROM {self._table_name} AS a
             WHERE {e.where_expr}
                   {e.order_expr}
             LIMIT 1
        '''

        with self.cursor() as cursor:
            cursor.execute(request, e.where_keys)
            return cursor.fetchone()

    def _fetchall(self, query: DBQuery) -> List[Any]:
        e = self._build_expression(query)

        request = f'''
            SELECT {e.column_expr}
              FROM {self._table_name} AS a
             WHERE {e.where_expr}
                   {e.order_expr}
             LIMIT 1
        '''

        with self.cursor() as cursor:
            cursor.execute(request, e.where_keys)
            return cursor.fetchall()

    def __del__(self):
        self._conn.close()

    @staticmethod
    def _decode_list(v: Optional[bytes]) -> List[Any]:
        return [] if not v else decode(v)

    @staticmethod
    def _encode_list(v: List[Any]) -> bytes:
        return None if (not v) or (len(v) == 0) else encode(v)

    def _insert_batch(self, cursor: BaseDB.Cursor, value_list_list: List[List[Any]]) -> None:
        assert len(self._column_list) > 0
        if len(value_list_list) == 0:
            return

        psycopg2.extras.execute_values(cursor, f'''
              INSERT INTO {self._table_name} ({','.join(self._column_list)})
                VALUES %s
              ON CONFLICT DO NOTHING;
            ''',
           value_list_list,
           template=None,
           page_size=1000)

    def cursor(self) -> BaseDB.Cursor:
        return self._conn.cursor()

    def is_connected(self) -> bool:
        try:
            with self.cursor() as cursor:
                cursor.execute('SELECT 1')
            return True
        except psycopg2.OperationalError:
            return False
