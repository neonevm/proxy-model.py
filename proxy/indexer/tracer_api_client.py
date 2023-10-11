from clickhouse_connect import get_client as ch_get_client
from clickhouse_connect.driver import Client as CHClient

import time
import logging

from dataclasses import dataclass
from typing import Optional, List

from ..common_neon.config import Config


LOG = logging.getLogger(__name__)


@dataclass
class CHConnection:
    ch_dsn: str
    ch_client: Optional[CHClient]


class TracerAPIClient:
    def __init__(self, config: Config):
        self._config = config
        self._ch_conn_list: List[CHConnection] = list()

        for ch_dsn in config.ch_dsn_list:
            try:
                ch_conn = CHConnection(
                    ch_dsn=ch_dsn,
                    ch_client=ch_get_client(dsn=ch_dsn)
                )
                self._ch_conn_list.append(ch_conn)
            except (BaseException, ):
                LOG.error('Bad address in the clickhouse connection list')

        self._last_ch_conn_idx = 0

    def max_slot(self) -> Optional[int]:
        if not len(self._ch_conn_list):
            return None

        request = f'''
            SELECT DISTINCT slot
              FROM events.update_account_distributed
             WHERE slot >= (
            SELECT max(slot) - ({self._config.slot_processing_delay} * 4)
              FROM events.update_account_distributed
            )
             ORDER BY slot DESC
             LIMIT {self._config.slot_processing_delay}
        '''

        while True:
            self._last_ch_conn_idx += 1
            if self._last_ch_conn_idx == len(self._ch_conn_list):
                self._last_ch_conn_idx = 0

            ch_conn = self._ch_conn_list[self._last_ch_conn_idx]
            try:
                if ch_conn.ch_client is None:
                    ch_conn.ch_client = ch_get_client(dsn=ch_conn.ch_dsn)

                slot = ch_conn.ch_client.query(request).result_set[-1][0]
                return slot

            except BaseException as exc:
                LOG.error('Unknown fail to fetch slot from ClickHouse', exc_info=exc)
                time.sleep(1)
                ch_conn.ch_client = None
