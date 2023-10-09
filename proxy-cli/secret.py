from typing import List, Dict

from proxy.common_neon.config import Config
from proxy.common_neon.operator_secret_mng import OpSecretMng
from proxy.common_neon.operator_resource_info import OpKeyInfo, OpResInfo, OpResInfoBuilder


class ResConfig(Config):
    @property
    def perm_account_limit(self) -> int:
        return super().perm_account_limit + 64


def get_res_info_list() -> List[OpResInfo]:
    config = ResConfig()
    secret_list = OpSecretMng(config).read_secret_list()
    return OpResInfoBuilder(config).build_resource_list(secret_list)


def get_key_info_list() -> List[OpKeyInfo]:
    config = ResConfig()
    secret_list = OpSecretMng(config).read_secret_list()
    return OpResInfoBuilder(config).build_key_list(secret_list)


def get_token_name(chain_id: int) -> str:
    # TODO: fix token names
    return 'NEON'


def get_token_dict() -> Dict[int, str]:
    # TODO: fix token names
    return {0: 'NEON'}
