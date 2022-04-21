from dataclasses import dataclass

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


@dataclass
class MemPoolTxRequest:
    neon_tx: NeonTx
    neon_tx_exec_cfg: NeonTxExecCfg
    emulating_result: NeonEmulatingResult
