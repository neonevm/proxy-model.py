from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress


@dataclass(frozen=True)
class NeonAccountInfo:
    neon_addr: NeonAddress
    pda_address: SolPubKey
    tx_count: int
    balance: int

    @staticmethod
    def from_json(neon_addr: NeonAddress, json_data: Dict[str, Any]) -> NeonAccountInfo:
        return NeonAccountInfo(
            neon_addr=neon_addr,
            pda_address=SolPubKey.from_string(json_data.get('solana_address')),
            tx_count=json_data.get('trx_count'),
            balance=int(json_data.get('balance'), 16),
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
    def from_json(neon_addr: NeonAddress, json_data: Dict[str, Any]) -> NeonContractInfo:
        code = '0x' + (json_data.get('code') or '')
        return NeonContractInfo(
            neon_addr=neon_addr,
            chain_id=json_data.get('chain_id'),
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


@dataclass(frozen=True)
class HolderAccountMetaInfo:
    pubkey: SolPubKey
    is_writable: bool


class HolderStatus(enum.Enum):
    Empty = 'Empty'
    Error = 'Error'
    Holder = 'Holder'
    Active = 'Active'
    Finalized = 'Finalized'

    @staticmethod
    def from_string(value: str) -> HolderStatus:
        if value == 'Empty':
            return HolderStatus.Empty
        elif value == 'Holder':
            return HolderStatus.Holder
        elif value == 'Active':
            return HolderStatus.Active
        elif value == 'Finalized':
            return HolderStatus.Finalized
        return HolderStatus.Error



@dataclass(frozen=True)
class HolderAccountInfo:
    holder_account: SolPubKey

    status: HolderStatus
    data_size: int
    owner: SolPubKey

    neon_tx_sig: str
    chain_id: Optional[int]

    gas_price: Optional[int]
    gas_limit: Optional[int]
    gas_used: Optional[int]

    account_list: List[HolderAccountMetaInfo]

    @staticmethod
    def from_json(addr: SolPubKey, json_data: Dict[str, Any]) -> HolderAccountInfo:
        owner = json_data.get('owner', None)
        owner = SolPubKey.from_string(owner) if owner else SolPubKey.default()

        neon_tx_sig = json_data.get('tx', None)
        neon_tx_sig = ('0x' + neon_tx_sig) if neon_tx_sig else ''

        acct_list = json_data.get('accounts', list())
        acct_list = [
            HolderAccountMetaInfo(
                pubkey=SolPubKey.from_string(json_acct.get('key')),
                is_writable=json_acct.get('is_writeable')
            )
            for json_acct in acct_list
        ]

        def _get_int(_name: str) -> Optional[int]:
            value = json_data.get(_name, None)
            return int(value, 10) if value else None

        return HolderAccountInfo(
            holder_account=addr,

            status=HolderStatus.from_string(json_data.get('status', '')),
            data_size=json_data.get('len', None) or None,
            owner=owner,

            neon_tx_sig=neon_tx_sig,
            chain_id=json_data.get('chain_id', None),

            gas_price=_get_int('gas_price'),
            gas_limit=_get_int('gas_limit'),
            gas_used=_get_int('gas_used'),

            account_list=acct_list
        )
