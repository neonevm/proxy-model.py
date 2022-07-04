from abc import ABC, abstractmethod
from typing import Optional
import os


class IConfig(ABC):

    @abstractmethod
    def get_solana_url(self) -> str:
        """Gets the predefinded solana url"""

    @abstractmethod
    def get_evm_steps_limit(self) -> int:
        """Gets the evm steps limitation, that is used to check steps gotten over emulating"""

    @abstractmethod
    def get_mempool_capacity(self) -> int:
        """Gets the capacity of the MemPool schedule to constrain the transactions count in there"""


class Config(IConfig):

    def get_solana_url(self) -> str:
        return os.environ.get("SOLANA_URL", "http://localhost:8899")

    def get_evm_steps_limit(self) -> int:
        return int(os.environ.get("EVM_STEP_COUNT", 750))

    def get_mempool_capacity(self) -> int:
        return int(os.environ.get("MEMPOOL_CAPACITY", 4096))

    def __str__(self):
        return f"SOLANA_URL: {self.get_solana_url()}, EVM_STEP_LIMIT: {self.get_evm_steps_limit()}, " \
               f"MP_CAPACITY: {self.get_mempool_capacity()}"
