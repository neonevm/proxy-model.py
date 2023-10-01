from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .utils import str_fmt_object, cached_method
from .solana_tx import SolCommit


@dataclass(frozen=True)
class SolBlockInfo:
    block_slot: int
    sol_commit: SolCommit.Type = SolCommit.NotProcessed
    block_hash: Optional[str] = None
    block_time: Optional[int] = None
    block_height: Optional[int] = None
    parent_block_slot: Optional[int] = None
    parent_block_hash: Optional[str] = None
    is_finalized: bool = False
    tx_receipt_list: List[Dict[str, Any]] = None
    error: Optional[str] = None

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)

    def set_finalized(self, value: bool) -> None:
        object.__setattr__(self, 'is_finalized', value)
        object.__setattr__(self, 'sol_commit', SolCommit.Finalized)
        self.__str__.reset_cache(self)

    def set_block_hash(self, value: str):
        object.__setattr__(self, 'block_hash', value)
        self.__str__.reset_cache(self)

    def is_empty(self) -> bool:
        return self.block_time is None

    def has_error(self) -> bool:
        return self.error is not None
