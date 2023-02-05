from __future__ import annotations

import asyncio
import time

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional, List, Dict

from ..common_neon.data import NeonTxExecCfg
from ..common_neon.eth_proto import NeonTx
from ..common_neon.solana_tx import SolPubKey


@dataclass
class MPTask:
    executor_id: int
    aio_task: asyncio.Task
    mp_request: MPRequest


class MPRequestType(IntEnum):
    SendTransaction = 0
    GetPendingTxNonce = 1
    GetMempoolTxNonce = 2
    GetTxByHash = 3
    GetGasPrice = 4
    GetStateTxCnt = 5
    GetOperatorResourceList = 6
    InitOperatorResource = 7
    GetElfParamDict = 8
    GetALTList = 9
    DeactivateALTList = 10
    CloseALTList = 11
    Unspecified = 255


@dataclass
class MPRequest:
    req_id: str
    type: MPRequestType = MPRequestType.Unspecified


@dataclass
class MPTxRequest(MPRequest):
    sig: str = None
    neon_tx: Optional[NeonTx] = None
    neon_tx_exec_cfg: Optional[NeonTxExecCfg] = None
    sender_address: str = None
    gas_price: int = 0
    start_time: int = 0

    def __post_init__(self):
        self.type = MPRequestType.SendTransaction

        self.gas_price = self.neon_tx.gasPrice
        if self.sender_address is None:
            self.sender_address = "0x" + self.neon_tx.sender()
        if self.start_time == 0:
            self.start_time = time.time_ns()

    @property
    def nonce(self) -> int:
        return self.neon_tx.nonce

    def has_chain_id(self) -> bool:
        return self.neon_tx.hasChainId()


@dataclass(frozen=True)
class OpResIdent:
    public_key: str
    private_key: bytes
    res_id: int = -1

    _str = ''
    _hash = 0

    def __str__(self) -> str:
        if self._str == '':
            _str = f'{self.public_key}:{self.res_id}'
            object.__setattr__(self, '_str', _str)
        return self._str

    def __hash__(self) -> int:
        if self._hash == 0:
            _hash = hash(str(self))
            object.__setattr__(self, '_hash', _hash)
        return self._hash


@dataclass
class MPTxExecRequest(MPTxRequest):
    elf_param_dict: Dict[str, str] = None
    res_ident: OpResIdent = None

    @staticmethod
    def clone(tx: MPTxRequest, res_ident: OpResIdent, elf_param_dict: Dict[str, str]):
        req = MPTxExecRequest(
            req_id=tx.req_id,
            sig=tx.sig,
            neon_tx=tx.neon_tx,
            neon_tx_exec_cfg=tx.neon_tx_exec_cfg,
            sender_address=tx.sender_address,
            start_time=tx.start_time,
            elf_param_dict=elf_param_dict,
            res_ident=res_ident
        )
        return req


MPTxRequestList = List[MPTxRequest]


@dataclass
class MPPendingTxNonceRequest(MPRequest):
    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetPendingTxNonce


@dataclass
class MPMempoolTxNonceRequest(MPRequest):
    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetMempoolTxNonce


@dataclass
class MPPendingTxByHashRequest(MPRequest):
    tx_hash: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetTxByHash


@dataclass
class MPGasPriceRequest(MPRequest):
    last_update_mapping_sec: int = 0
    sol_price_account: Optional[SolPubKey] = None
    neon_price_account: Optional[SolPubKey] = None

    def __post_init__(self):
        self.type = MPRequestType.GetGasPrice


@dataclass
class MPElfParamDictRequest(MPRequest):
    elf_param_dict: Dict[str, str] = None

    def __post_init__(self):
        self.type = MPRequestType.GetElfParamDict


@dataclass
class MPSenderTxCntRequest(MPRequest):
    sender_list: List[str] = None

    def __post_init__(self):
        self.type = MPRequestType.GetStateTxCnt


@dataclass
class MPOpResGetListRequest(MPRequest):
    def __post_init__(self):
        self.type = MPRequestType.GetOperatorResourceList


@dataclass
class MPOpResInitRequest(MPRequest):
    elf_param_dict: Dict[str, str] = None
    res_ident: OpResIdent = None

    def __post_init__(self):
        self.type = MPRequestType.InitOperatorResource


@dataclass
class MPALTAddress:
    table_account: str
    secret: bytes


@dataclass
class MPGetALTList(MPRequest):
    secret_list: List[bytes] = None
    alt_address_list: List[MPALTAddress] = None

    def __post_init__(self):
        self.type = MPRequestType.GetALTList


@dataclass
class MPALTInfo:
    last_extended_slot: int
    deactivation_slot: Optional[int]
    block_height: int
    table_account: str
    operator_key: bytes

    def is_deactivated(self) -> bool:
        return self.deactivation_slot is not None


@dataclass
class MPDeactivateALTListRequest(MPRequest):
    alt_info_list: List[MPALTInfo] = None

    def __post_init__(self):
        self.type = MPRequestType.DeactivateALTList


@dataclass
class MPCloseALTListRequest(MPRequest):
    alt_info_list: List[MPALTInfo] = None

    def __post_init__(self):
        self.type = MPRequestType.CloseALTList


class MPTxExecResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1
    SolanaUnavailable = 2
    NodeBehind = 3
    NonceTooLow = 4
    BadResource = 5
    Unspecified = 255


@dataclass(frozen=True)
class MPTxExecResult:
    code: MPTxExecResultCode
    data: Any


class MPTxSendResultCode(IntEnum):
    Success = 0
    NonceTooLow = 1
    Underprice = 2
    AlreadyKnown = 3
    Unspecified = 255


@dataclass(frozen=True)
class MPTxSendResult:
    code: MPTxSendResultCode
    state_tx_cnt: Optional[int]


@dataclass(frozen=True)
class MPGasPriceResult:
    suggested_gas_price: int
    min_gas_price: int
    last_update_mapping_sec: int
    sol_price_account: SolPubKey
    neon_price_account: SolPubKey


@dataclass(frozen=True)
class MPSenderTxCntData:
    sender: str
    state_tx_cnt: int


@dataclass(frozen=True)
class MPSenderTxCntResult:
    sender_tx_cnt_list: List[MPSenderTxCntData]


class MPOpResInitResultCode(IntEnum):
    Success = 0
    Failed = 1
    Unspecified = 255


@dataclass(frozen=True)
class MPOpResGetListResult:
    res_ident_list: List[OpResIdent]


@dataclass(frozen=True)
class MPOpResInitResult:
    code: MPOpResInitResultCode


@dataclass(frozen=True)
class MPALTListResult:
    block_height: int
    alt_info_list: List[MPALTInfo]


@dataclass(frozen=True)
class MPResult:
    error: Optional[str] = None

    def __bool__(self):
        return self.error is None

    def __str__(self):
        return "ok" if self.__bool__() else self.error

    def __repr__(self):
        return f"""Result({'' if self.error is None else '"' + self.error + '"'})"""
