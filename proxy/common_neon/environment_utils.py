import subprocess
import sys
from typing import List

import logging

from .config import Config


LOG = logging.getLogger(__name__)


class CliBase:
    def __init__(self, config: Config, enable_logging: bool):
        self._config = config
        self._solana_url = config.random_solana_url
        self._enable_logging = enable_logging

    def _hide_solana_url(self, cmd: List[str]) -> str:
        if self._config.hide_solana_url:
            return ' '.join([item.replace(self._solana_url, 'XXXX') for item in cmd])
        return ' '.join(cmd)

    def run_cli(self, cmd: List[str], **kwargs) -> str:
        if self._enable_logging:
            LOG.debug(f'Calling: {self._hide_solana_url(cmd)}')

        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        if result.stderr is not None:
            print(result.stderr, file=sys.stderr)
        output = result.stdout
        if not output:
            result.check_returncode()
        return output


class SolanaCli(CliBase):
    def call(self, *args):
        try:
            cmd = [
                'solana',
                '--url', self._solana_url,
            ]
            cmd.extend(list(args))

            return self.run_cli(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: solana error {str(err)}')
            raise
