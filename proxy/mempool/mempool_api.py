from dataclasses import dataclass

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxCfg, NeonEmulatingResult


@dataclass
class MemPoolTxRequest:
    neon_tx: NeonTx
    neon_tx_cfg: NeonTxCfg
    emulating_result: NeonEmulatingResult
