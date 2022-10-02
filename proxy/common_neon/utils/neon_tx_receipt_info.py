from __future__ import annotations

import dataclasses

from .utils import str_fmt_object
from .neon_tx_info import NeonTxInfo
from .neon_tx_result_info import NeonTxResultInfo


@dataclasses.dataclass(frozen=True)
class NeonTxReceiptInfo:
    neon_tx: NeonTxInfo
    neon_tx_res: NeonTxResultInfo

    def __str__(self) -> str:
        return str_fmt_object(self)

    def replace_neon_tx(self, neon_tx: NeonTxInfo) -> NeonTxReceiptInfo:
        return dataclasses.replace(self, neon_tx=neon_tx)

    def replace_neon_tx_res(self, neon_tx_res: NeonTxResultInfo) -> NeonTxReceiptInfo:
        return dataclasses.replace(self, neon_tx_res=neon_tx_res)
