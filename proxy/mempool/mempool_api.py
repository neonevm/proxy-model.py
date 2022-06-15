from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Tuple
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult
from .operator_resource_list import OperatorResourceInfo


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


@dataclass
class MPTxRequest(MPRequest):
    signature: str = field(compare=False, default=None)
    neon_tx: NeonTx = field(compare=False, default=None)
    neon_tx_exec_cfg: NeonTxExecCfg = field(compare=False, default=None)
    emulating_result: NeonEmulatingResult = field(compare=False, default=None)
    _gas_price: int = field(compare=True, default=None)

    def __post_init__(self):
        self._gas_price = self.neon_tx.gasPrice
        self.type = MPRequestType.SendTransaction

class MPRequestProcStage(IntEnum):
    StagePrepare = 0,
    StageExecute = 1,

@dataclass(order=True)
class MPRequestContext:
    request: MPRequest = field(compare=True, default=None)
    resource: OperatorResourceInfo = field(compare=False, default=None)
    processing_stage: MPRequestProcStage = field(compare=False, default=MPRequestProcStage.StagePrepare)

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
