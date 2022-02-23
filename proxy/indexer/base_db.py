import multiprocessing
import psycopg2

from typing import NamedTuple
from logged_groups import logged_group

from .pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from .pg_common import encode, decode


class DBQuery(NamedTuple):
    column_list: list
    key_list: list
    order_list: list


class DBQueryExpression(NamedTuple):
    column_expr: str
    where_expr: str
    where_keys: list
    order_expr: str


@logged_group("neon.Indexer")
class BaseDB:
    _create_table_lock = multiprocessing.Lock()

    def __init__(self):
        self._conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        with self._create_table_lock:
            cursor = self._conn.cursor()
            cursor.execute(self._create_table_sql())

    def _create_table_sql(self) -> str:
        assert False, 'No script for the table'

    def _build_expression(self, q: DBQuery) -> DBQueryExpression:

        return DBQueryExpression(
            column_expr=','.join(q.column_list),
            where_expr=' AND '.join(['1=1'] + [f'{name}=%s' for name, _ in q.key_list]),
            where_keys=[value for _, value in q.key_list],
            order_expr='ORDER BY ' + ', '.join(q.order_list) if len(q.order_list) else '',
        )

    def _fetchone(self, query: DBQuery) -> []:
        e = self._build_expression(query)

        request = f'''
            SELECT {e.column_expr}
              FROM {self._table_name} AS a
             WHERE {e.where_expr}
                   {e.order_expr}
             LIMIT 1
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, e.where_keys)
            return cursor.fetchone()

    def __del__(self):
        self._conn.close()

    def decode_list(self, v):
        return [] if not v else decode(v)

    def encode_list(self, v: []):
        return None if (not v) or (len(v) == 0) else encode(v)

    def is_db_connected(self):
        try:
            cur = self._conn.cursor()
            cur.execute('SELECT 1')
            return True
        except:
            return False
