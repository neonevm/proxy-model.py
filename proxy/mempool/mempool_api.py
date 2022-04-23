from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


@dataclass(order=True)
class ExecTxRequest:
    signature: str
    neon_tx: NeonTx = field(compare=False)
    neon_tx_exec_cfg: NeonTxExecCfg = field(compare=False)
    emulating_result: NeonEmulatingResult = field(compare=False)
    _gas_price: int = field(compare=True, default=None)

    def __post_init__(self):
        """Calculate and store content length on init"""
        self._gas_price = self.neon_tx.gasPrice


class ExecTxResultCode(IntEnum):
    Done = 0
    ToBeRepeat = 1,
    NoLiquidity = 2,
    Dummy = -1


@dataclass
class ExecTxResult:
    result_code: ExecTxResultCode
    data: Any
