import logging
import subprocess
import json

from typing import Dict, Any, Optional, Tuple

from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.environment_utils import CliBase
from ..common_neon.address import NeonAddress, InNeonAddress
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.elf_params import ElfParams

from .neon_layouts import NeonAccountInfo, BPFLoader2ProgramInfo, BPFLoader2ExecutableInfo
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

    def version(self) -> str:
        try:
            cmd = ['neon-cli', '--version']
            return self.run_cli(cmd, universal_newlines=True).split()[1]
        except subprocess.CalledProcessError as err:
            LOG.error(f'ERR: neon-cli error {str(err)}')
            raise

    def get_neon_account_info(self, addr: InNeonAddress) -> Optional[NeonAccountInfo]:
        addr = NeonAddress.from_raw(addr)
        chain_id = ElfParams().chain_id

        response = self.call('get-ether-account-data', str(addr))
        json_acct = response.get('value')
        if not json_acct:
            return None
        return NeonAccountInfo.from_json(addr, chain_id, json_acct)

    def read_elf_params(self, last_deployed_slot: int) -> Tuple[int, Dict[str, str]]:
        solana = SolInteractor(self._config, self._solana_url)

        account_info = solana.get_account_info(EVM_PROGRAM_ID_STR)
        program_info = BPFLoader2ProgramInfo.from_data(account_info.data)
        if program_info.executable_addr == SolPubKey.default():
            return 0, {}

        account_info = solana.get_account_info(program_info.executable_addr, BPFLoader2ExecutableInfo.minimum_size)
        exec_info = BPFLoader2ExecutableInfo.from_data(account_info.data)
        if exec_info.deployed_slot <= last_deployed_slot:
            return 0, {}

        LOG.debug(f'Read ELF params deployed on the slot {exec_info.deployed_slot}')

        src_dict = self.call('neon-elf-params')
        elf_param_dict: Dict[str, str] = dict()
        for key, value in src_dict.items():
            if key.startswith('NEON_') and (key not in elf_param_dict):
                LOG.debug(f'Read ELF param: {key}: {value}')
                elf_param_dict[key] = value

        return exec_info.deployed_slot, elf_param_dict
