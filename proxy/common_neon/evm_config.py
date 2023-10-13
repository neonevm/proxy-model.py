from __future__ import annotations

import logging
from typing import Optional, Dict, List
from singleton_decorator import singleton

from ..neon_core_api.neon_layouts import EVMConfigInfo, EVMTokenInfo


LOG = logging.getLogger(__name__)


@singleton
class EVMConfig:
    def __init__(self):
        self._data = data = EVMConfigInfo.init_empty()
        self._last_deployed_slot = data.last_deployed_slot
        self._evm_param_dict: Dict[str, str] = dict()
        self._token_info_dict: Dict[str, EVMTokenInfo] = dict()
        self._version = data.version
        self._revision = data.revision
        self._chain_id = data.chain_id

    @property
    def last_deployed_slot(self) -> int:
        return self._last_deployed_slot

    @property
    def treasury_pool_cnt(self) -> int:
        return int(self._evm_param_dict.get('NEON_TREASURY_POOL_COUNT'))

    @property
    def treasury_pool_seed(self) -> bytes:
        return bytes(self._evm_param_dict.get('NEON_TREASURY_POOL_SEED'), 'utf8')

    @property
    def neon_evm_steps(self) -> int:
        return int(self._evm_param_dict.get('NEON_EVM_STEPS_MIN'))

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def neon_evm_version(self) -> Optional[str]:
        return self._version

    @property
    def neon_evm_revision(self) -> Optional[str]:
        return self._revision

    @property
    def neon_gas_limit_multiplier_no_chainid(self) -> int:
        return int(self._evm_param_dict.get('NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID'))

    def has_config(self) -> bool:
        return len(self._evm_param_dict) > 0

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
        return self._evm_param_dict

    @property
    def token_info_list(self) -> List[EVMTokenInfo]:
        return list(self._token_info_dict.values())

    @property
    def chain_id_list(self) -> List[int]:
        return [token.chain_id for token in self._token_info_dict.values()]

    def get_token_info_by_name(self, token_name: str) -> Optional[EVMTokenInfo]:
        return self._token_info_dict.get(token_name, None)

    def get_token_info_by_chain_id(self, chain_id: int) -> Optional[EVMTokenInfo]:
        for token_info in self._token_info_dict.values():
            if token_info.chain_id == chain_id:
                return token_info
        return None

    @property
    def evm_config_data(self) -> EVMConfigInfo:
        return self._data

    def set_evm_config(self, data: EVMConfigInfo) -> EVMConfig:
        self._data = data

        self._last_deployed_slot = data.last_deployed_slot
        self._evm_param_dict = dict(data.evm_param_list)
        self._token_info_dict = {
            token.token_name: token
            for token in data.token_info_list
        }
        self._version = data.version
        self._revision = data.revision
        self._chain_id = data.chain_id
        return self
