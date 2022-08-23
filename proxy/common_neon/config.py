from abc import ABC, abstractmethod
from typing import Optional
from solana.publickey import PublicKey

from .environment_data import EVM_LOADER_ID, EVM_STEP_COUNT, MEMPOOL_CAPACITY, MIN_OPERATOR_BALANCE_TO_ERR, \
                              MIN_OPERATOR_BALANCE_TO_WARN, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, SOLANA_URL, \
                              STORAGE_SIZE, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL


class IConfig(ABC):

    @abstractmethod
    def get_solana_url(self) -> str:
        """Gets the predefined solana url"""

    @abstractmethod
    def get_evm_steps_limit(self) -> int:
        """Gets the evm steps limitation, that is used to check steps gotten over emulating"""

    @abstractmethod
    def get_mempool_capacity(self) -> int:
        """Gets the capacity of the MemPool schedule to constrain the transactions count in there"""

    @abstractmethod
    def get_pyth_mapping_account(self) -> Optional[str]:
        """Gets pyth network account to retrieve gas price from there"""

    @abstractmethod
    def get_pyth_solana_url(self) -> str:
        """Gets solana url for GasPriceCalculator in test purposes"""

    @abstractmethod
    def get_evm_loader_id(self) -> PublicKey:
        """Gets EVM Loader ID"""

    @abstractmethod
    def get_storage_size(self) -> int:
        """Gets size for storage/holder account"""

    @abstractmethod
    def get_min_operator_balance_to_warn(self) -> int:
        """Gets minimal operators balance to warning"""

    @abstractmethod
    def get_min_operator_balance_to_err(self) -> int:
        """Gets minimal operators balance to error"""

    @abstractmethod
    def get_perm_account_limit(self) -> int:
        """Gets permanent accounts max count"""

    @abstractmethod
    def get_recheck_resource_list_interval(self) -> int:
        """Gets resource recheck interval"""


class Config(IConfig):

    def get_solana_url(self) -> str:
        return SOLANA_URL

    def get_evm_steps_limit(self) -> int:
        return EVM_STEP_COUNT

    def get_mempool_capacity(self) -> int:
        return MEMPOOL_CAPACITY

    def get_pyth_mapping_account(self) -> Optional[str]:
        return PYTH_MAPPING_ACCOUNT

    def get_pyth_solana_url(self) -> str:
        return PP_SOLANA_URL

    def get_evm_loader_id(self) -> PublicKey:
        return PublicKey(EVM_LOADER_ID)

    def get_storage_size(self) -> int:
        return STORAGE_SIZE

    def get_min_operator_balance_to_warn(self) -> int:
        return MIN_OPERATOR_BALANCE_TO_WARN

    def get_min_operator_balance_to_err(self) -> int:
        return MIN_OPERATOR_BALANCE_TO_ERR

    def get_perm_account_limit(self) -> int:
        return PERM_ACCOUNT_LIMIT

    def get_recheck_resource_list_interval(self) -> int:
        return RECHECK_RESOURCE_LIST_INTERVAL

    def __str__(self):
        return f"\n" \
               f"        SOLANA_URL: {self.get_solana_url()}, \n" \
               f"        EVM_LOADER_ID: {self.get_evm_loader_id()}, \n" \
               f"        PP_SOLANA_URL: {self.get_pyth_solana_url()}\n" \
               f"        PYTH_MAPPING_ACCOUNT: {self.get_pyth_mapping_account()}\n" \
               f"        EVM_STEP_LIMIT: {self.get_evm_steps_limit()}, \n" \
               f"        MP_CAPACITY: {self.get_mempool_capacity()}\n" \
               f"        STORAGE_SIZE: {self.get_storage_size()}\n" \
               f"        MIN_OPERATOR_BALANCE_TO_WARN: {self.get_min_operator_balance_to_warn()}\n" \
               f"        MIN_OPERATOR_BALANCE_TO_ERR: {self.get_min_operator_balance_to_err()}\n" \
               f"        PERM_ACCOUNT_LIMIT: {self.get_perm_account_limit()}\n" \
               f"        RECHECK_RESOURCE_LIST_INTERVAL: {self.get_recheck_resource_list_interval()}\n" \
               f"        "
