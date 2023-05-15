from clickhouse_connect import get_client as ch_get_client
from clickhouse_connect.driver import Client as CHClient

from typing import Optional

from ..common_neon.config import Config


class TracerAPIClient:
    def __init__(self, config: Config):
        self._config = config
        self._conn: Optional[CHClient] = None
        self._connect()

    def _connect(self):
        if self._config.ch_host is None:
            return

        ch_connect_cfg = dict(
            host=self._config.ch_host,
            port=self._config.ch_port,
            secure=self._config.ch_secure
        )
        if self._config.ch_user is not None:
            ch_connect_cfg['user'] = self._config.ch_user
        if self._config.ch_password is not None:
            ch_connect_cfg['password'] = self._config.ch_password

        self._conn = ch_get_client(**ch_connect_cfg)

    def max_slot(self) -> Optional[int]:
        if self._conn is None:
            return None
        request = f'''
            SELECT MAX(slot)-{self._config.slot_processing_delay}
              FROM events.update_account_distributed
        '''
        slot = self._conn.query(request).result_set[0][0]
        return slot
