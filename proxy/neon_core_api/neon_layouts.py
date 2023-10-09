from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress


@dataclass(frozen=True)
class NeonAccountInfo:
    neon_addr: NeonAddress
    pda_address: SolPubKey
    tx_count: int
    balance: int

    @staticmethod
    def from_json(neon_addr: NeonAddress, src: Dict[str, Any]) -> NeonAccountInfo:
        return NeonAccountInfo(
            neon_addr=neon_addr,
            pda_address=SolPubKey.from_string(src.get('solana_address')),
            tx_count=src.get('trx_count'),
            balance=int(src.get('balance'), 16),
        )

    @property
    def chain_id(self) -> int:
        return self.neon_addr.chain_id


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


@dataclass(frozen=True)
class EVMConfigData:
    last_deployed_slot: int

    evm_param_dict: Dict[str, str]
    token_dict: Dict[int, Dict[str, Any]]

    version: str
    revision: str

    chain_id: int
    token_mint: SolPubKey

    @staticmethod
    def from_json(last_deployed_slot: int, json_config: Dict[str, Any]) -> EVMConfigData:
        evm_param_dict: Dict[str, str] = dict()
        token_dict: Dict[int, Dict[str, Any]] = dict()

        version = ''
        revision = ''

        for key, value in json_config.items():
            if key.upper() == 'CONFIG':
                evm_param_dict = value
            elif key.upper() == 'CHAINS':
                token_dict = {
                    token['id']: dict(
                        chain_id=token['id'],
                        token_mint=SolPubKey.from_string(token['token']),
                        token_name=token['name'].upper()
                    )
                    for token in value
                }
            elif key.upper() == 'VERSION':
                version = value
            elif key.upper() == 'REVISION':
                revision = value

        chain_id = 0
        token_mint = SolPubKey.default()
        for token in token_dict.values():
            if token['token_name'] != 'NEON':
                continue
            chain_id = token['chain_id']
            token_mint = token['token_mint']
            break

        if chain_id == 0:
            chain_id = evm_param_dict.get('NEON_CHAIN_ID', 0)
            token_mint = evm_param_dict.get('NEON_TOKEN_MINT', None)
            token_mint = SolPubKey.from_string(token_mint) if token_mint else SolPubKey.default()

        if not len(version):
            version = evm_param_dict.get('NEON_PKG_VERSION', '0.0.0-unknown'),
            revision = evm_param_dict.get('NEON_REVISION', 'unknown')

        return EVMConfigData(
            last_deployed_slot=last_deployed_slot,
            evm_param_dict=evm_param_dict,
            token_dict=token_dict,
            version=version,
            revision=revision,
            chain_id=chain_id,
            token_mint=token_mint
        )

    @staticmethod
    def init_empty() -> EVMConfigData:
        return EVMConfigData(
            last_deployed_slot=0,
            evm_param_dict=dict(),
            token_dict=dict(),
            version='0.0.0-unknown',
            revision='unknown',
            chain_id=0,
            token_mint=SolPubKey.default()
        )
