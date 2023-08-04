import json
import subprocess
import sys
from typing import List

import logging

from .config import Config


LOG = logging.getLogger(__name__)


class CliBase:
    def __init__(self, config: Config):
        self._config = config

    def _hide_solana_url(self, cmd: List[str]) -> str:
        return ' '.join([item.replace(self._config.solana_url, 'XXXX') for item in cmd])

    def run_cli(self, cmd: List[str], **kwargs) -> str:
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
                '--url', self._config.solana_url,
            ]
            cmd.extend(list(args))

            return self.run_cli(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: solana error {str(err)}')
            raise


class NeonCli(CliBase):
    EMULATOR_LOGLEVEL = {
        logging.CRITICAL: "off",
        logging.ERROR: "error",
        logging.WARNING: "warn",
        logging.INFO: "info",
        logging.DEBUG: "debug",
        logging.NOTSET: "warn"
    }

    def call(self, *args, data=None):
        try:
            cmd = [
                'neon-cli',
                '--commitment=recent',
                '--url', self._config.solana_url,
                '--evm_loader', f'{str(self._config.evm_program_id)}',
                '--loglevel',  f'{self._emulator_logging_level}'
            ]
            cmd.extend(['-vvv'] if self._config.neon_cli_debug_log else [])
            cmd.extend(list(args))
            LOG.info(f'Calling neon-cli: {self._hide_solana_url(cmd)}')

            if data is None:
                data = ""
            else:
                data = json.dumps(data)

            result = subprocess.run(
                cmd, input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=self._config.neon_cli_timeout
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

            for log in output.get('logs', []):
                LOG.debug(log)

            if 'error' in output:
                error = output.get('error')
                LOG.error(f'ERR: neon-cli error value f{error}')
                raise subprocess.CalledProcessError(result.returncode, cmd, stderr=error)

            return output.get('value', '')

        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: neon-cli error {str(err)}')
            raise

    @property
    def _emulator_logging_level(self):
        level = LOG.getEffectiveLevel()
        cli_level = self.EMULATOR_LOGLEVEL.get(level, 'warn')
        return cli_level

    def version(self):
        try:
            cmd = ['neon-cli', '--version']
            return self.run_cli(cmd, timeout=self._config.neon_cli_timeout, universal_newlines=True).split()[1]
        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: neon-cli error {str(err)}')
            raise
