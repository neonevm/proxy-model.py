from typing import Optional
from solana.publickey import PublicKey

from .environment_data import EVM_LOADER_ID, EVM_STEP_COUNT, MEMPOOL_CAPACITY, MIN_OPERATOR_BALANCE_TO_ERR, \
                              MIN_OPERATOR_BALANCE_TO_WARN, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, SOLANA_URL, \
                              HOLDER_SIZE, PERM_ACCOUNT_LIMIT, RECHECK_USED_RESOURCE_SEC, \
                              RECHECK_RESOURCE_AFTER_USES_CNT


class Config:
    def __init__(self):
        pass

    @staticmethod
    def get_solana_url() -> str:
        return SOLANA_URL

    @staticmethod
    def get_evm_steps_limit() -> int:
        return EVM_STEP_COUNT

    @staticmethod
    def get_mempool_capacity() -> int:
        return MEMPOOL_CAPACITY

    @staticmethod
    def get_pyth_mapping_account() -> Optional[PublicKey]:
        return PYTH_MAPPING_ACCOUNT

    @staticmethod
    def get_pyth_solana_url() -> str:
        return PP_SOLANA_URL

    @staticmethod
    def get_evm_loader_id() -> PublicKey:
        return PublicKey(EVM_LOADER_ID)

    @staticmethod
    def get_holder_size() -> int:
        return HOLDER_SIZE

    @staticmethod
    def get_min_operator_balance_to_warn() -> int:
        return MIN_OPERATOR_BALANCE_TO_WARN

    @staticmethod
    def get_min_operator_balance_to_err() -> int:
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def get_perm_account_limit() -> int:
        return PERM_ACCOUNT_LIMIT

    @staticmethod
    def get_recheck_used_resource_sec() -> int:
        return RECHECK_USED_RESOURCE_SEC

    @staticmethod
    def get_recheck_resource_after_uses_cnt() -> int:
        return RECHECK_RESOURCE_AFTER_USES_CNT

    def __str__(self):
        return '\n        '.join([
            '',
            f"SOLANA_URL: {self.get_solana_url()},",
            f"EVM_LOADER_ID: {self.get_evm_loader_id()},",
            f"PP_SOLANA_URL: {self.get_pyth_solana_url()}",
            f"PYTH_MAPPING_ACCOUNT: {self.get_pyth_mapping_account()}",
            f"EVM_STEP_LIMIT: {self.get_evm_steps_limit()},",
            f"MP_CAPACITY: {self.get_mempool_capacity()}",
            f"HOLDER_SIZE: {self.get_holder_size()}",
            f"MIN_OPERATOR_BALANCE_TO_WARN: {self.get_min_operator_balance_to_warn()}",
            f"MIN_OPERATOR_BALANCE_TO_ERR: {self.get_min_operator_balance_to_err()}",
            f"PERM_ACCOUNT_LIMIT: {self.get_perm_account_limit()}",
            f"RECHECK_USED_RESOURCE_SEC: {self.get_recheck_used_resource_sec()}",
            f"RECHECK_RESOURCE_AFTER_USES_CNT: {self.get_recheck_resource_after_uses_cnt()}",
            ""
        ])
