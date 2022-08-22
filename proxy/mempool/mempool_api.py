from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Tuple, Optional
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg


class IMPExecutor(ABC):
    @abstractmethod
    def submit_mp_request(self, mp_request: MPRequest) -> Tuple[int, Task]:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    # TODO: drop it away
    @abstractmethod
    def on_no_liquidity(self, resource_id: int):
        pass

    @abstractmethod
    def release_resource(self, resource_id: int):
        pass


class MPRequestType(IntEnum):
    SendTransaction = 0,
    GetLastTxNonce = 1,
    GetTxByHash = 2,
    GetGasPrice = 3,
    Dummy = -1


class MPRequest:
    req_id: str
    type: MPRequestType

    def __post_init__(self):
        self.log_req_id = {"context": {"req_id": self.req_id}}


@dataclass
class MPTxRequest(MPRequest):
    nonce: int
    signature: str
    neon_tx: NeonTx
    neon_tx_exec_cfg: NeonTxExecCfg
    sender_address: str
    gas_price: int

    def __post_init__(self):
        super().__post_init__()
        self.gas_price = self.neon_tx.gasPrice
        self.nonce = self.neon_tx.nonce
        self.sender_address = "0x" + self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction


@dataclass
class MPPendingTxNonceReq(MPRequest):
    sender: str = None

    def __post_init__(self):
        super().__post_init__()
        self.type = MPRequestType.GetLastTxNonce


@dataclass
class MPPendingTxByHashReq(MPRequest):
    tx_hash: str = None

    def __post_init__(self):
        super().__post_init__()
        self.type = MPRequestType.GetTxByHash


@dataclass
class MPGasPriceReq(MPRequest):
    def __post_init__(self):
        super().__post_init__()
        self.type = MPRequestType.GetGasPrice


class MPTxExecResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    NonceTooLow = 4,
    Unspecified = 255,
    Dummy = -1


@dataclass
class MPTxExecResult:
    code: MPTxExecResultCode
    data: Any


class MPTxSendResultCode(IntEnum):
    Success = 0
    NonceTooLow = 1
    Underprice = 2
    AlreadyKnown = 3
    Unspecified = 255


@dataclass
class MPTxSendResult:
    code: MPTxSendResultCode
    state_tx_cnt: Optional[int]


@dataclass
class MPGasPriceResult:
    suggested_gas_price: int
    min_gas_price: int
