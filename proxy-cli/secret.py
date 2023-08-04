from typing import List

from proxy.common_neon.solana_tx import SolAccount
from proxy.common_neon.config import Config
from proxy.common_neon.operator_secret_mng import OpSecretMng
from proxy.common_neon.operator_resource_info import OpResIdent, OpResIdentListBuilder


class ResConfig(Config):
    @property
    def perm_account_limit(self) -> int:
        return super().perm_account_limit + 64


def get_solana_acct_list() -> List[SolAccount]:
    config = ResConfig()
    secret_list = OpSecretMng(config).read_secret_list()
    return [SolAccount.from_seed(secret) for secret in secret_list]


def get_res_ident_list() -> List[OpResIdent]:
    config = ResConfig()
    secret_list = OpSecretMng(config).read_secret_list()
    return OpResIdentListBuilder(config).build_resource_list(secret_list)
