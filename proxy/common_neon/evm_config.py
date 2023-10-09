from __future__ import annotations

import logging
from typing import Optional, Dict, Any, List
from singleton_decorator import singleton

from .solana_tx import SolPubKey

from ..neon_core_api.neon_layouts import EVMConfigData


LOG = logging.getLogger(__name__)


@singleton
class EVMConfig:
    def __init__(self):
        self._data = EVMConfigData.init_empty()

    @property
    def last_deployed_slot(self) -> int:
        return self._data.last_deployed_slot

    @property
    def treasury_pool_cnt(self) -> int:
        return int(self._data.evm_param_dict.get('NEON_TREASURY_POOL_COUNT'))

    @property
    def treasury_pool_seed(self) -> bytes:
        return bytes(self._data.evm_param_dict.get('NEON_TREASURY_POOL_SEED'), 'utf8')

    @property
    def neon_evm_steps(self) -> int:
        return int(self._data.evm_param_dict.get('NEON_EVM_STEPS_MIN'))

    @property
    def neon_token_mint(self) -> SolPubKey:
        return self._data.token_mint

    @property
    def chain_id(self) -> int:
        return self._data.chain_id

    @property
    def neon_evm_version(self) -> Optional[str]:
        return self._data.version

    @property
    def neon_evm_revision(self) -> Optional[str]:
        return self._data.revision

    @property
    def neon_gas_limit_multiplier_no_chainid(self) -> int:
        return int(self._data.evm_param_dict.get('NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID'))

    def has_config(self) -> bool:
        return len(self._data.evm_param_dict) > 0

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
    def evm_param_dict(self) -> Dict[str: str]:
        return self._data.evm_param_dict

    @property
    def token_dict(self) -> Dict[int, Dict[str, Any]]:
        return self._data.token_dict

    @property
    def chain_id_list(self) -> List[int]:
        return list(self._data.token_dict.keys())

    @property
    def evm_config_data(self) -> EVMConfigData:
        return self._data

    def set_evm_config(self, evm_config_data: EVMConfigData) -> EVMConfig:
        self._data = evm_config_data
        return self
