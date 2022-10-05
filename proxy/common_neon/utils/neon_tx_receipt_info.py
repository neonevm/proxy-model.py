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

    def replace(self, /, **changes) -> NeonTxReceiptInfo:
        return dataclasses.replace(self, **changes)
