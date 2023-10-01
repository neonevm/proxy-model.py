from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress


@dataclass
class NeonAccountInfo:
    pda_address: SolPubKey
    neon_addr: NeonAddress
    tx_count: int
    balance: int
    code: Optional[str]
    code_size: int

    @staticmethod
    def from_json(src: Dict[str, Any]) -> NeonAccountInfo:
        code = src.get('code')
        code_size = src.get('code_size')
        if (not len(code)) or (not code_size):
            code = None

        return NeonAccountInfo(
            pda_address=src.get('solana_address'),
            neon_addr=NeonAddress(src.get('address')),
            tx_count=src.get('trx_count'),
            balance=int(src.get('balance'), 10),
            code=code,
            code_size=code_size
        )
