from __future__ import annotations

import logging
import time
import itertools

from typing import List, Tuple, Any, Optional, Callable

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
        self._tx_cursor: Optional[DBConnection._PGCursor] = None

    def _connect(self) -> None:
        if self._conn is not None:
            return

        self._config.validate_db_config()

        kwargs = dict(
            dbname=self._config.postgres_db,
            user=self._config.postgres_user,
            password=self._config.postgres_password,
            host=self._config.postgres_host,
        )

        if self._config.postgres_timeout > 0:
            wait_ms = self._config.postgres_timeout * 1000
            kwargs['options'] = (
                f'-c statement_timeout={wait_ms} ' +
                f'-c idle_in_transaction_session_timeout={wait_ms-500} '
            )
            # LOG.debug(f'add statement timeout {wait_ms}')

        self._conn = psycopg2.connect(**kwargs)
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)

    def _clear(self) -> None:
        conn = self._conn

        self._conn = None
        self._tx_cursor = None

        if conn is not None:
            conn.close()

    @property
    def config(self) -> DBConfig:
        return self._config

    def _is_tx_run(self) -> bool:
        return self._tx_cursor is not None

    def is_connected(self) -> bool:
        assert not self._is_tx_run()
        try:
            self._connect()
            with self._conn.cursor() as cursor:
                cursor.execute('SELECT 1')

            return True
        except (BaseException, ):
            self._clear()
            return False

    def run_tx(self, action: Callable[[], None]) -> None:
        if self._is_tx_run():
            action()
            return

        try:
            for retry in itertools.count():
                try:
                    self._connect()
                    with self._conn as _:
                        with self._conn.cursor() as tx_cursor:
                            self._tx_cursor = tx_cursor

                            action()
                            return

                except BaseException as exc:
                    self._on_fail_execute(retry, exc)
        finally:
            self._tx_cursor = None

    def _on_fail_execute(self, retry: int, exc: BaseException) -> None:
        self._clear()

        if isinstance(exc, (psycopg2.OperationalError, psycopg2.InterfaceError)):
            if retry > 1:
                LOG.debug(f'Fail {retry} on DB connection', exc_info=exc)
            time.sleep(1)
        else:
            LOG.error('Unknown fail on DB connection', exc_info=exc)
            raise

    def update_row(self, request: str, value_list: Tuple[Any, ...]) -> None:
        assert self._is_tx_run()
        self._tx_cursor.execute(request, value_list)

    def update_row_list(self, request: str, row_list: List[List[Any]]):
        assert self._is_tx_run()
        psycopg2.extras.execute_values(self._tx_cursor, request, row_list, template=None, page_size=1000)

    def fetch_cnt(self, cnt: int, request: str, *args) -> List[List[Any]]:
        for retry in itertools.count():
            try:
                self._connect()
                if self._is_tx_run():
                    return self._tx_cursor.fetchmany(cnt)

                with self._conn.cursor() as cursor:
                    cursor.execute(request, *args)
                    return cursor.fetchmany(cnt)

            except BaseException as exc:
                if self._is_tx_run():
                    # Got an exception during DB transaction execution
                    #   next steps happens inside run_tx()
                    raise

                self._on_fail_execute(retry, exc)
