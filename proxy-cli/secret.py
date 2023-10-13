from typing import List

from proxy.common_neon.config import Config
from proxy.common_neon.operator_secret_mng import OpSecretMng
from proxy.common_neon.operator_resource_info import OpKeyInfo, OpResInfo, OpResInfoBuilder
from proxy.common_neon.evm_config import EVMConfig

from proxy.neon_core_api.neon_client_base import NeonClientBase
from proxy.neon_core_api.neon_client import NeonClient


class ResConfig(Config):
    @property
    def perm_account_limit(self) -> int:
        return super().perm_account_limit + 64


def get_res_info_list() -> List[OpResInfo]:
    config = ResConfig()
    neon_client = NeonClient(config)
    key_info_list = _get_key_info_list(config, neon_client)
    return OpResInfoBuilder(config, neon_client).build_resource_list(key_info_list)


def get_key_info_list() -> List[OpKeyInfo]:
    config = ResConfig()
    neon_client = NeonClient(config)
    return _get_key_info_list(config, neon_client)


def _get_key_info_list(config: Config, neon_client: NeonClientBase) -> List[OpKeyInfo]:
    secret_list = OpSecretMng(config).read_secret_list()
    return OpResInfoBuilder(config, neon_client).build_key_list(secret_list)


def _get_evm_config() -> EVMConfig:
    evm_config = EVMConfig()
    if evm_config.has_config():
        return evm_config
    config = ResConfig()
    neon_client = NeonClient(config)
    evm_config.set_evm_config(neon_client.get_evm_config())
    return evm_config


def get_token_name(chain_id: int) -> str:
    token_info = _get_evm_config().get_token_info_by_chain_id(chain_id)
    if token_info:
        return token_info.token_name
    return '<UNKNOWN>'


def get_token_name_list() -> List[str]:
    return [token_info.token_name for token_info in _get_evm_config().token_info_list]
