from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress


@dataclass(frozen=True)
class NeonAccountInfo:
    neon_addr: NeonAddress
    chain_id: int
    pda_address: SolPubKey
    tx_count: int
    balance: int

    def from_json(neon_addr: NeonAddress, chain_id: int, src: Dict[str, Any]) -> NeonAccountInfo:
        return NeonAccountInfo(
            neon_addr=neon_addr,
            chain_id=chain_id,
            pda_address=src.get('solana_address'),
            tx_count=src.get('trx_count'),
            balance=int(src.get('balance'), 16),
        )


@dataclass(frozen=True)
class NeonContractInfo:
    neon_addr: NeonAddress
    chain_id: int
    code: Optional[str]

    @staticmethod
    def from_json(neon_addr: NeonAddress, src: Dict[str, Any]) -> NeonContractInfo:
        code = '0x' + (src.get('code') or '')
        return NeonContractInfo(
            neon_addr=neon_addr,
            chain_id=src.get('chain_id'),
            code=code
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
