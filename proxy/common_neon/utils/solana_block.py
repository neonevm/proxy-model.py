from __future__ import annotations
from typing import Optional

import dataclasses

from .utils import str_fmt_object


@dataclasses.dataclass(frozen=True)
class SolanaBlockInfo:
    block_slot: int
    block_hash: str = None
    block_time: Optional[int] = None
    block_height: Optional[int] = None
    parent_block_slot: Optional[int] = None
    parent_block_hash: str = None
    is_finalized: bool = False

    def __str__(self) -> str:
        return str_fmt_object(self)

    def replace_finalized(self, value: bool) -> SolanaBlockInfo:
        return dataclasses.replace(self, is_finalized=value)

    def replace_block_hash(self, block_hash: str) -> SolanaBlockInfo:
        return dataclasses.replace(self, block_hash=block_hash)

    def is_empty(self) -> bool:
        return self.block_time is None
