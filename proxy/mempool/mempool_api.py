from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Tuple
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


class IMPExecutor(ABC):

    @abstractmethod
    def submit_mp_request(self, mp_reqeust: MPRequest) -> Tuple[int, Task]:
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


class MPRequestType(IntEnum):
    SendTransaction = 0,
    GetTrxCount = 1,
    Dummy = -1


@dataclass(order=True)
class MPRequest:
    req_id: int
    type: MPRequestType = field(default=MPRequestType.Dummy)


@dataclass(order=True)
class MPTxRequest(MPRequest):
    signature: str = field(compare=False, default=None)
    neon_tx: NeonTx = field(compare=False, default=None)
    neon_tx_exec_cfg: NeonTxExecCfg = field(compare=False, default=None)
    emulating_result: NeonEmulatingResult = field(compare=False, default=None)
    sender_address: str = field(compare=False, default=None)
    gas_price: int = field(compare=False, default=None)
    nonce: int = field(compare=True, default=None)

    def __post_init__(self):
        self.gas_price = self.neon_tx.gasPrice
        self.nonce = self.neon_tx.nonce
        self.sender_address = self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction

    @property
    def log_str(self):
        hash = "0x" + self.neon_tx.hash_signed().hex()
        return f"MPTxRequest(hash={hash[:10]}..., sender_address=0x{self.sender_address[:10]}..., nonce={self.nonce}, gas_price={self.gas_price})"


@dataclass
class MPPendingTxCountReq(MPRequest):

    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetTrxCount


class MPResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    NoLiquidity = 3,
    Unspecified = 4,
    Dummy = -1


@dataclass
class MPTxResult:
    code: MPResultCode
    data: Any