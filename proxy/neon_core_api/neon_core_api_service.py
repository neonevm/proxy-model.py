import os
import subprocess
import logging
import time

from typing import Dict, Any, List
from multiprocessing import Process

from ..common_neon.config import Config

from .logging_level import NeonCoreApiLoggingLevel


LOG = logging.getLogger(__name__)


class _Service:
    def __init__(self, config: Config, idx: int, solana_url: str):
        self._config = config
        port = config.neon_core_api_port + idx
        self._host = f'127.0.0.1:{port}'
        self._solana_url = solana_url

    def start(self) -> None:
        process = Process(target=self._run)
        process.start()

    def _create_env(self) -> Dict[str, Any]:
        log_level = NeonCoreApiLoggingLevel().level

        env = os.environ.copy()

        env.update(dict(
            RUST_BACKTRACE='1',
            RUST_LOG=log_level,

            SOLANA_URL=self._solana_url,
            NEON_API_LISTENER_ADDR=self._host,
            COMMITMENT='recent',
            NEON_DB_CLICKHOUSE_URLS=';'.join(self._config.ch_dsn_list),

            # TODO: remove
            KEYPAIR='',
            FEEPAIR=''
        ))

        return env

    def _run(self):
        cmd = ['neon-core-api', '-H', self._host]
        env = self._create_env()

        while True:
            self._run_host_api(cmd, env)
            time.sleep(1)

    def _run_host_api(self, cmd: List[str], env: Dict[str, Any]):
        try:
            LOG.info(f'Start Neon Core API service at the {self._host}')
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                env=env
            )
            while True:
                line = process.stdout.readline()
                if line:
                    pass
                    # TODO: wait for implementation in neon-core-api
                    # LOG.debug(line)
                elif process.poll() is not None:
                    break

        except BaseException as exc:
            LOG.warning('Neon Core API finished with error', exc_info=exc)


class NeonCoreApiService:
    def __init__(self, config: Config):
        self._service_list = [_Service(config, idx, url) for idx, url in enumerate(config.solana_url_list)]

    def start(self) -> None:
        for service in self._service_list:
            service.start()
