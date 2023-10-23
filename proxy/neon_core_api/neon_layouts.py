from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple

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
class EVMTokenInfo:
    chain_id: int
    token_name: str
    token_mint: SolPubKey


@dataclass
class EVMChainInfo:
    id: int
    name: str
    token: str


class _EVMConfigConst(enum.Enum):
    ConfigName = 'CONFIG'
    ChainsName = 'CHAINS'
    VersionName = 'VERSION'
    RevisionName = 'REVISION'

    NeonTokenName = 'NEON'
    NeonTokenChainID = 'NEON_CHAIN_ID'
    NeonTokenMint = 'NEON_TOKEN_MINT'

    NeonPKGVersionName = 'NEON_PKG_VERSION'
    NeonPKGRevisionName = 'NEON_REVISION'

    NeonNoVersion = '0.0.0-unknown'
    NeonNoRevision = 'unknown'


@dataclass(frozen=True)
class EVMConfigInfo:
    last_deployed_slot: int

    evm_param_list: List[Tuple[str, str]]
    token_info_list: List[EVMTokenInfo]
    chain_info_list: List[EVMChainInfo]

    version: str
    revision: str

    chain_id: int

    @staticmethod
    def from_json(last_deployed_slot: int, json_config: Dict[str, Any]) -> EVMConfigInfo:
        evm_param_dict: Dict[str, str] = dict()
        token_info_list: List[EVMTokenInfo] = list()
        chain_info_list: List[EVMChainInfo] = list()

        version = ''
        revision = ''

        for key, value in json_config.items():
            if key.upper() == _EVMConfigConst.ConfigName.value:
                evm_param_dict = value
            elif key.upper() == _EVMConfigConst.ChainsName.value:
                token_info_list = [
                    EVMTokenInfo(
                        chain_id=token['id'],
                        token_mint=SolPubKey.from_string(token['token']),
                        token_name=token['name'].upper()
                    )
                    for token in value
                ]
                chain_info_list = [
                    EVMChainInfo(
                        id=token['id'],
                        name=token['name'],
                        token=token['token']
                    )
                    for token in value
                ]
            elif key.upper() == _EVMConfigConst.VersionName.value:
                version = value
            elif key.upper() == _EVMConfigConst.RevisionName.value:
                revision = value

        chain_id = 0
        for token in token_info_list:
            if token.token_name != _EVMConfigConst.NeonTokenName.value:
                continue
            chain_id = token.chain_id
            break

        # the call of neon-cli utility
        if not len(token_info_list):
            chain_id = int(evm_param_dict.get(_EVMConfigConst.NeonTokenChainID.value, '0'), 10)
            token_mint = evm_param_dict.get(_EVMConfigConst.NeonTokenMint.value, None)
            token_mint = SolPubKey.from_string(token_mint) if token_mint else SolPubKey.default()
            token_info_list = [EVMTokenInfo(chain_id, 'NEON', token_mint)]

        # the call of neon-cli utility
        if not len(version):
            version = evm_param_dict.get(
                _EVMConfigConst.NeonPKGVersionName.value,
                _EVMConfigConst.NeonNoVersion.value
            )
            revision = evm_param_dict.get(
                _EVMConfigConst.NeonPKGRevisionName.value,
                _EVMConfigConst.NeonNoRevision.value
            )

        return EVMConfigInfo(
            last_deployed_slot=last_deployed_slot,
            evm_param_list=list(evm_param_dict.items()),
            token_info_list=token_info_list,
            chain_info_list=chain_info_list,
            version=version,
            revision=revision,
            chain_id=chain_id
        )

    @staticmethod
    def init_empty() -> EVMConfigInfo:
        return EVMConfigInfo(
            last_deployed_slot=0,
            evm_param_list=list(),
            token_info_list=list(),
            chain_info_list=list(),
            version=_EVMConfigConst.NeonNoVersion.value,
            revision=_EVMConfigConst.NeonNoRevision.value,
            chain_id=0
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
                is_writable=json_acct.get('is_writable')
            )
            for json_acct in acct_list
        ]

        def _get_int(_name: str) -> Optional[int]:
            value = json_data.get(_name, None)
            return int(value[2:], 16) if value else None

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
