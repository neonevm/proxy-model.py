from abc import ABC, abstractmethod
from typing import Optional

from ..common_neon.address import NeonAddress
from ..common_neon.solana_tx import SolPubKey

from .neon_layouts import NeonAccountInfo, HolderAccountInfo


class NeonClientBase(ABC):
    @abstractmethod
    def get_neon_account_info(self, addr: NeonAddress) -> NeonAccountInfo:
        pass

    @abstractmethod
    def get_holder_account_info(self, addr: SolPubKey) -> HolderAccountInfo:
        pass
