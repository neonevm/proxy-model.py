from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .utils import str_fmt_object


@dataclass(frozen=True)
class SolBlockInfo:
    block_slot: int
    block_hash: str = None
    block_time: Optional[int] = None
    block_height: Optional[int] = None
    parent_block_slot: Optional[int] = None
    parent_block_hash: str = None
    is_finalized: bool = False
    tx_receipt_list: List[Dict[str, Any]] = None

    _str = ''

    def __str__(self) -> str:
        if self._str == '':
            object.__setattr__(self, '_str', str_fmt_object(self))
        return self._str

    def set_finalized(self, value: bool) -> None:
        object.__setattr__(self, 'is_finalized', value)
        object.__setattr__(self, '_str', '')

    def set_block_hash(self, value: str):
        object.__setattr__(self, 'block_hash', value)
        object.__setattr__(self, '_str', '')

    def is_empty(self) -> bool:
        return self.block_time is None
