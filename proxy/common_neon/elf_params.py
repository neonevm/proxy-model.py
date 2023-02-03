from __future__ import annotations

import json
import logging
from typing import Optional, Dict

from singleton_decorator import singleton

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.environment_utils import NeonCli
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.config import Config


LOG = logging.getLogger(__name__)


@singleton
class ElfParams:
    def __init__(self):
        self._elf_param_dict: Dict[str, any] = {}

    @property
    def treasury_pool_max(self) -> int:
        return int(self._elf_param_dict.get("NEON_POOL_COUNT"))

    @property
    def neon_heap_frame(self) -> int:
        return int(self._elf_param_dict.get("NEON_HEAP_FRAME"))

    @property
    def neon_compute_units(self) -> int:
        return 1_400_000  # <- for mainnet launch
        # return int(self._elf_param_dict.get("NEON_COMPUTE_UNITS"))

    @property
    def neon_evm_steps(self) -> int:
        return int(self._elf_param_dict.get("NEON_EVM_STEPS_MIN"))

    @property
    def neon_additional_fee(self):
        return int(self._elf_param_dict.get("NEON_ADDITIONAL_FEE"))

    @property
    def neon_token_mint(self) -> SolPubKey:
        return SolPubKey.from_string(self._elf_param_dict.get("NEON_TOKEN_MINT"))

    @property
    def chain_id(self) -> int:
        return int(self._elf_param_dict.get('NEON_CHAIN_ID'))

    @property
    def holder_msg_size(self) -> int:
        return int(self._elf_param_dict.get("NEON_HOLDER_MSG_SIZE"))

    @property
    def neon_evm_version(self) -> Optional[str]:
        return self._elf_param_dict.get("NEON_PKG_VERSION")

    @property
    def neon_evm_revision(self) -> Optional[str]:
        return self._elf_param_dict.get('NEON_REVISION')

    @property
    def neon_gas_limit_multiplier_no_chainid(self) -> int:
        return int(self._elf_param_dict.get('NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID'))

    @property
    def neon_minimal_client_allowance_balance(self) -> int:
        return int(self._elf_param_dict.get("NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE", 0))

    @property
    def neon_minimal_contract_allowance_balance(self) -> int:
        return int(self._elf_param_dict.get("NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE", 0))

    @property
    def allowance_token_addr(self) -> str:
        return self._elf_param_dict.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')

    @property
    def denial_token_addr(self) -> str:
        return self._elf_param_dict.get("NEON_PERMISSION_DENIAL_TOKEN", '')

    @property
    def storage_entries_in_contract_account(self) -> int:
        return int(self._elf_param_dict.get("NEON_STORAGE_ENTRIES_IN_CONTRACT_ACCOUNT", 0))

    def has_params(self) -> bool:
        return len(self._elf_param_dict) > 0

    def is_evm_compatible(self, proxy_version: str) -> bool:
        evm_version = None
        try:
            evm_version = self.neon_evm_version
            major_evm_version, minor_evm_version, _ = evm_version.split('.')
            major_proxy_version, minor_proxy_version, _ = proxy_version.split('.')
            return (major_evm_version == major_proxy_version) and (minor_evm_version == minor_proxy_version)
        except BaseException as exc:
            LOG.error(f'Cannot compare evm version {evm_version} with proxy version {proxy_version}.', exc_info=exc)
            return False

    @property
    def elf_param_dict(self) -> Dict[str: str]:
        return self._elf_param_dict

    def read_elf_param_dict_from_net(self, config: Config) -> ElfParams:
        if not self.has_params():
            LOG.debug("Read ELF params")
        elf_param_dict: Dict[str, str] = {}
        params = NeonCli(config).call("neon-elf-params")
        for param in params:
            if param.startswith('NEON_'):
                elf_param_dict.setdefault(param, params[param])

        for param, value in elf_param_dict.items():
            if self._elf_param_dict.get(param) != value:
                LOG.debug(f"new ELF param: {param}: {value}")
        self.set_elf_param_dict(elf_param_dict)
        return self

    def set_elf_param_dict(self, elf_param_dict: Dict[str, str]) -> ElfParams:
        self._elf_param_dict = elf_param_dict
        self._elf_param_dict['NEON_EVM_ID'] = EVM_LOADER_ID
        return self
