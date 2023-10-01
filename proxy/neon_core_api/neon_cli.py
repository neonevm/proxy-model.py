import logging
import subprocess
import json

from typing import Dict, Any, Union, Optional, List

from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.environment_utils import CliBase
from ..common_neon.address import NeonAddress

from .neon_layouts import NeonAccountInfo
from .logging_level import NeonCoreApiLoggingLevel


LOG = logging.getLogger(__name__)


class NeonCli(CliBase):
    def call(self, *args) -> Dict[str, Any]:
        try:
            cmd = [
                'neon-cli',
                '--commitment=recent',
                '--url', self._solana_url,
                '--evm_loader', EVM_PROGRAM_ID_STR,
                '--loglevel',  f'{NeonCoreApiLoggingLevel().level}'
            ]
            cmd.extend(list(args))
            if self._enable_logging:
                LOG.debug(f'Calling neon-cli: {self._hide_solana_url(cmd)}')

            result = subprocess.run(
                cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True
            )

            try:
                output = json.loads(result.stdout)
            except json.decoder.JSONDecodeError:
                LOG.error(f'JSON, STDERR: {result.stderr}')
                LOG.error(f'JSON, STDOUT: {result.stdout}')

                error = result.stderr
                if len(error) == 0:
                    error = result.stdout
                raise subprocess.CalledProcessError(result.returncode, cmd, stderr=error)

            if self._enable_logging:
                for log in output.get('logs', []):
                    LOG.debug(log)

            if 'error' in output:
                error = output.get('error')
                LOG.error(f'neon-cli error value f{error}')
                raise subprocess.CalledProcessError(result.returncode, cmd, stderr=error)

            return output.get('value', '')

        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: neon-cli error {str(err)}')
            raise

    def version(self):
        try:
            cmd = ['neon-cli', '--version']
            return self.run_cli(cmd, universal_newlines=True).split()[1]
        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: neon-cli error {str(err)}')
            raise

    def get_neon_account_info(self, addr: Union[str, bytes, NeonAddress]) -> Optional[NeonAccountInfo]:
        if isinstance(addr, bytes):
            addr = NeonAddress(addr)
        if isinstance(addr, NeonAddress):
            addr = str(addr)

        response = self.call('get-ether-account-data', addr)
        json_acct = response.get('value')
        if not json_acct:
            return None
        return NeonAccountInfo.from_json(json_acct)

