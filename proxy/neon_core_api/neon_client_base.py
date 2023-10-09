from abc import ABC, abstractmethod
from typing import Optional

from ..common_neon.address import NeonAddress

from .neon_layouts import NeonAccountInfo


class NeonClientBase(ABC):
    @abstractmethod
    def get_neon_account_info(self, addr: NeonAddress) -> Optional[NeonAccountInfo]:
        pass
