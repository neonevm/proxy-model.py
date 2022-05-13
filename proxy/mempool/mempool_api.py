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


class MemPoolReqType(IntEnum):
    SendTransaction = 0,
    GetTrxCount = 1,
    Dummy = -1


@dataclass(order=True)
class MemPoolRequest:
    req_id: int
    type: MemPoolReqType = field(default=MemPoolReqType.Dummy)


@dataclass
class MemPoolTxRequest(MemPoolRequest):
    signature: str = field(compare=False, default=None)
    neon_tx: NeonTx = field(compare=False, default=None)
    neon_tx_exec_cfg: NeonTxExecCfg = field(compare=False, default=None)
    emulating_result: NeonEmulatingResult = field(compare=False, default=None)
    _gas_price: int = field(compare=True, default=None)

    def __post_init__(self):
        self._gas_price = self.neon_tx.gasPrice
        self.type = MemPoolReqType.SendTransaction


@dataclass
class MemPoolPendingTxCountReq(MemPoolRequest):

    sender: str = None

    def __post_init__(self):
        self.type = MemPoolReqType.GetTrxCount


class MemPoolResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    NoLiquidity = 3,
    Unspecified = 4,
    Dummy = -1


@dataclass
class MemPoolResult:
    code: MemPoolResultCode
    data: Any
