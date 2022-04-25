from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Tuple
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


class IMemPoolExecutor(ABC):

    @abstractmethod
    def submit_mempool_request(self, mp_reqeust: MemPoolRequest) -> Tuple[int, Task]:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def on_no_liquidity(self, resource_id: int):
        pass

    @abstractmethod
    def release_resource(self, resource_id: int):
        pass


@dataclass(order=True)
class MemPoolRequest:
    signature: str
    neon_tx: NeonTx = field(compare=False)
    neon_tx_exec_cfg: NeonTxExecCfg = field(compare=False)
    emulating_result: NeonEmulatingResult = field(compare=False)
    _gas_price: int = field(compare=True, default=None)

    def __post_init__(self):
        """Calculate and store content length on init"""
        self._gas_price = self.neon_tx.gasPrice


class MemPoolResultCode(IntEnum):
    Done = 0
    ToBeRepeat = 1,
    NoLiquidity = 2,
    Dummy = -1


@dataclass
class MemPoolResult:
    code: MemPoolResultCode
    data: Any
