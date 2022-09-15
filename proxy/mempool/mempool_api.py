from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from typing import Any, Optional, List, Dict
from abc import ABC, abstractmethod

import asyncio

from ..common_neon.eth_proto import NeonTx
from ..common_neon.data import NeonTxExecCfg


@dataclass
class MPTask:
    executor_id: int
    aio_task: asyncio.Task
    mp_request: MPRequest


class IMPExecutor(ABC):
    @abstractmethod
    def submit_mp_request(self, mp_request: MPRequest) -> MPTask:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def release_executor(self, executor_id: int):
        pass


class MPRequestType(IntEnum):
    SendTransaction = 0,
    GetLastTxNonce = 1,
    GetTxByHash = 2,
    GetGasPrice = 3,
    GetStateTxCnt = 4,
    InitOperatorResource = 5,
    GetElfParamDict = 6,
    Dummy = -1


@dataclass
class MPRequest:
    req_id: str
    type: MPRequestType = MPRequestType.Dummy


@dataclass
class MPTxRequest(MPRequest):
    signature: str = None
    neon_tx: Optional[NeonTx] = None
    neon_tx_exec_cfg: Optional[NeonTxExecCfg] = None
    sender_address: str = None
    gas_price: int = 0

    def __post_init__(self):
        self.gas_price = self.neon_tx.gasPrice
        self.sender_address = "0x" + self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction

    @property
    def nonce(self) -> int:
        return self.neon_tx.nonce

    def has_chain_id(self) -> bool:
        return self.neon_tx.hasChainId()


@dataclass
class MPTxExecRequest(MPTxRequest):
    elf_param_dict: Dict[str, str] = None
    resource_ident: str = None

    @staticmethod
    def clone(tx: MPTxRequest, resource_ident: str, elf_param_dict: Dict[str, str]):
        req = MPTxExecRequest(
            req_id=tx.req_id,
            signature=tx.signature,
            neon_tx=tx.neon_tx,
            neon_tx_exec_cfg=tx.neon_tx_exec_cfg,
            elf_param_dict=elf_param_dict,
            resource_ident=resource_ident
        )
        return req


MPTxRequestList = List[MPTxRequest]


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
class MPElfParamDictRequest(MPRequest):
    def __post_init__(self):
        self.type = MPRequestType.GetElfParamDict


@dataclass
class MPSenderTxCntRequest(MPRequest):
    sender_list: List[str] = None

    def __post_init__(self):
        self.type = MPRequestType.GetStateTxCnt


@dataclass
class MPOpResInitRequest(MPRequest):
    elf_param_dict: Dict[str, str] = None
    resource_ident: str = ''

    def __post_init__(self):
        self.type = MPRequestType.InitOperatorResource


class MPTxExecResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    NodeBehind = 3,
    NonceTooLow = 4,
    BadResource = 5,
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


class MPOpResInitResultCode(IntEnum):
    Success = 0
    Failed = 1
    Unspecified = 255


@dataclass
class MPOpResInitResult:
    code: MPOpResInitResultCode
