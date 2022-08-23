from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional, List
from abc import ABC, abstractmethod

import asyncio

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg


@dataclass
class MPTask:
    resource_id: int
    aio_task: asyncio.Task
    mp_request: MPRequest


class IMPExecutor(ABC):
    @abstractmethod
    def submit_mp_request(self, mp_request: MPRequest) -> MPTask:
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
    GetStateTxCnt = 4,
    Dummy = -1


@dataclass
class MPRequest:
    req_id: str
    type: MPRequestType = MPRequestType.Dummy


@dataclass
class MPTxRequest(MPRequest):
    nonce: int = 0
    signature: str = None
    neon_tx: Optional[NeonTx] = None
    neon_tx_exec_cfg: Optional[NeonTxExecCfg] = None
    sender_address: str = None
    gas_price: int = 0

    def __post_init__(self):
        self.gas_price = self.neon_tx.gasPrice
        self.nonce = self.neon_tx.nonce
        self.sender_address = "0x" + self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction


@dataclass
class MPPendingTxNonceRequest(MPRequest):
    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetLastTxNonce


@dataclass
class MPPendingTxByHashRequest(MPRequest):
    tx_hash: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetTxByHash


@dataclass
class MPGasPriceRequest(MPRequest):
    def __post_init__(self):
        self.type = MPRequestType.GetGasPrice


@dataclass
class MPSenderTxCntRequest(MPRequest):
    sender_list: List[str] = None

    def __post_init__(self):
        self.type = MPRequestType.GetStateTxCnt


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


@dataclass
class MPSenderTxCntData:
    sender: str
    state_tx_cnt: int


@dataclass
class MPSenderTxCntResult:
    sender_tx_cnt_list: List[MPSenderTxCntData]
