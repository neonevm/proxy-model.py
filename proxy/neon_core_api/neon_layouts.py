from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class BPFLoader2ProgramInfo:
    version: int
    executable_addr: SolPubKey = SolPubKey.default()

    @staticmethod
    def from_data(data: bytes) -> BPFLoader2ProgramInfo:
        if len(data) != 36:
            return BPFLoader2ProgramInfo(0)

        version = int.from_bytes(data[:4], 'little')
        if version != 2:
            return BPFLoader2ProgramInfo(version)

        return BPFLoader2ProgramInfo(
            version=version,
            executable_addr=SolPubKey.from_bytes(data[4:])
        )


@dataclass(frozen=True)
class BPFLoader2ExecutableInfo:
    version: int
    deployed_slot: int = 0
    minimum_size: int = 8

    @staticmethod
    def from_data(data: bytes) -> BPFLoader2ExecutableInfo:
        if len(data) < BPFLoader2ExecutableInfo.minimum_size:
            return BPFLoader2ExecutableInfo(0)

        version = int.from_bytes(data[:4], 'little')
        if version != 3:
            return BPFLoader2ExecutableInfo(version)

        return BPFLoader2ExecutableInfo(
            version=version,
            deployed_slot=int.from_bytes(data[4:8], 'little')
        )
