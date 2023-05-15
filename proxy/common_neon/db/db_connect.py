from __future__ import annotations

import logging
import time

from typing import List, Tuple, Union, Any, Optional, Callable

import psycopg2
import psycopg2.extensions
import psycopg2.extras

from .db_config import DBConfig


LOG = logging.getLogger(__name__)


class DBConnection:
    _PGCursor = psycopg2.extensions.cursor
    _PGConnection = psycopg2.extensions.connection

    def __init__(self, config: DBConfig):
        self._config = config
        self._conn: Optional[DBConnection._PGConnection] = None
        self._tx_conn: Optional[DBConnection._PGConnection] = None
        self._connect()

    def __del__(self):
        self._close()

    def _connect(self) -> None:
        if self._conn is not None:
            return

        self._conn = psycopg2.connect(
            dbname=self._config.postgres_db,
            user=self._config.postgres_user,
            password=self._config.postgres_password,
            host=self._config.postgres_host
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)

    def _close(self) -> None:
        if self._conn is None:
            return

        self._conn.close()
        self._clear()

    def _clear(self) -> None:
        self._conn = None
        self._tx_conn = None

    def _cursor(self) -> DBConnection._PGCursor:
        assert self._conn is not None

        if self._tx_conn is not None:
            return self._tx_conn.cursor()
        return self._conn.cursor()

    @property
    def config(self) -> DBConfig:
        return self._config

    def is_connected(self) -> bool:
        if self._conn is None:
            return False

        try:
            self._connect()
            with self._cursor() as cursor:
                cursor.execute('SELECT 1')
            return True
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            self._clear()
            return False

    def run_tx(self, action: Callable[[], None]) -> None:
        if self._tx_conn is not None:
            action()
            return

        try:
            while True:
                try:
                    self._connect()
                    with self._conn as tx_conn:
                        self._tx_conn = tx_conn

                        action()
                        self._tx_conn = None
                        return

                except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
                    LOG.debug('Fail on run TPC transaction', exc_info=exc)
                    self._clear()
                    time.sleep(1)

                except BaseException as exc:
                    LOG.error('Unknown fail on run TPC transaction', exc_info=exc)
                    raise

        finally:
            self._tx_conn = None

    def update_row(self, request: str, value_list: Union[Tuple[Any, ...], List[Any]]) -> None:
        assert self._tx_conn is not None
        with self._tx_conn.cursor() as cursor:
            cursor.execute(request, value_list)

    def update_row_list(self, request: str, row_list: List[List[Any]]):
        assert self._tx_conn is not None
        with self._tx_conn.cursor() as cursor:
            psycopg2.extras.execute_values(cursor, request, row_list, template=None, page_size=1000)

    def _fetch_cnt(self, cnt: int, request: str, *args) -> List[List[Any]]:
        while True:
            try:
                self._connect()
                with self._cursor() as cursor:
                    cursor.execute(request, *args)
                    return cursor.fetchmany(cnt)

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
                if self._tx_conn is not None:
                    raise

                LOG.debug('Fail on fetching of records', exc_info=exc)
                self._clear()
                time.sleep(1)

            except BaseException as exc:
                LOG.error('Unknown fail to fetching of records', exc_info=exc)
                raise

    def fetch_one(self, request: str, *args) -> List[Any]:
        row_list = self._fetch_cnt(1, request, *args)
        return list() if not len(row_list) else row_list[0]

    def fetch_all(self, request: str, *args) -> List[List[Any]]:
        return self._fetch_cnt(10000, request, *args)
