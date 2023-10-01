from __future__ import annotations

from dataclasses import dataclass

from .utils.neon_tx_info import NeonTxInfo
from .utils.utils import str_fmt_object
from .neon_tx_result_info import NeonTxResultInfo


@dataclass(frozen=True)
class NeonTxReceiptInfo:
    neon_tx: NeonTxInfo
    neon_tx_res: NeonTxResultInfo

    def __str__(self) -> str:
        return str_fmt_object(self)

    def set_neon_tx(self, neon_tx: NeonTxInfo) -> None:
        object.__setattr__(self, 'neon_tx', neon_tx)
