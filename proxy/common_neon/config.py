from abc import ABC, abstractmethod
from typing import Optional
import os


class IConfig(ABC):

    @abstractmethod
    def get_solana_url(self) -> Optional[str]:
        """Gets the predefinded solana url"""

    @abstractmethod
    def get_evm_count(self) -> Optional[int]:
        """Gets the evm count"""


class Config(IConfig):

    def __init__(self):
        from ..environment import read_elf_params, ELF_PARAMS
        read_elf_params(ELF_PARAMS)

    def get_solana_url(self) -> Optional[str]:
        return os.environ.get("SOLANA_URL", "http://localhost:8899")

    def get_evm_count(self) -> Optional[int]:
        return int(os.environ.get("EVM_STEP_COUNT", 750))
