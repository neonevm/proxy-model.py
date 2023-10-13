from __future__ import annotations

from typing import List, Dict
from dataclasses import dataclass

from .config import Config
from .solana_tx import SolAccount, SolPubKey
from .evm_config import EVMConfig
from .utils.utils import cached_method
from .address import NeonAddress, perm_account_seed, neon_account_with_seed

from ..neon_core_api.neon_client_base import NeonClientBase
from ..neon_core_api.neon_layouts import NeonAccountInfo


@dataclass(frozen=True)
class OpHolderInfo:
    res_id: int
    seed: bytes
    public_key: SolPubKey

    @staticmethod
    def from_public_key(public_key: SolPubKey, res_id: int) -> OpHolderInfo:
        holder_seed = perm_account_seed(b'holder-', res_id)
        holder_acct = neon_account_with_seed(public_key, holder_seed)

        return OpHolderInfo(
            res_id=res_id,
            seed=holder_seed,
            public_key=holder_acct
        )


@dataclass(frozen=True)
class OpKeyInfo:
    signer: SolAccount
    neon_account_dict: Dict[int, NeonAccountInfo]
    holder_info_list: List[OpHolderInfo]

    @staticmethod
    def from_signer_account(
        signer: SolAccount,
        neon_account_list: List[NeonAccountInfo],
        holder_info_list: List[OpHolderInfo]
    ) -> OpKeyInfo:
        return OpKeyInfo(
            signer=signer,
            neon_account_dict={
                neon_acct.neon_addr.chain_id: neon_acct
                for neon_acct in neon_account_list
            },
            holder_info_list=holder_info_list
        )

    @property
    def public_key(self) -> SolPubKey:
        return self.signer.pubkey()

    @property
    def private_key(self) -> bytes:
        return self.signer.secret()


@dataclass(frozen=True)
class OpResInfo:
    key_info: OpKeyInfo
    holder_info: OpHolderInfo

    @cached_method
    def __str__(self) -> str:
        return f'{self.key_info.public_key}:{self.holder_info.res_id}'

    @cached_method
    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, OpResInfo) and
            other.res_id == self.res_id and
            other.public_key == self.public_key
        )

    @property
    def signer(self) -> SolAccount:
        return self.key_info.signer

    @property
    def neon_account_dict(self) -> Dict[int, NeonAccountInfo]:
        return self.key_info.neon_account_dict

    @property
    def public_key(self) -> SolPubKey:
        return self.key_info.public_key

    @property
    def private_key(self) -> bytes:
        return self.key_info.private_key

    @property
    def res_id(self) -> int:
        return self.holder_info.res_id

    @property
    def holder_account(self) -> SolAccount:
        return self.holder_info.public_key

    @property
    def holder_seed(self) -> bytes:
        return self.holder_info.seed


class OpResInfoBuilder:
    def __init__(self, config: Config, neon_client: NeonClientBase):
        self._config = config
        self._neon_client = neon_client

    def build_key_list(self, secret_list: List[bytes]) -> List[OpKeyInfo]:
        chain_id_list = EVMConfig().chain_id_list
        key_info_list: List[OpKeyInfo] = list()
        start_res_id = self._config.perm_account_id
        stop_res_id = self._config.perm_account_id + self._config.perm_account_limit

        for private_key in secret_list:
            signer = SolAccount.from_seed(private_key)
            neon_acct_list = [
                self._neon_client.get_neon_account_info(
                    NeonAddress.from_private_key(private_key, chain_id)
                )
                for chain_id in chain_id_list
            ]
            holder_info_list = [
                OpHolderInfo.from_public_key(signer.pubkey(), res_id)
                for res_id in range(start_res_id, stop_res_id)
            ]

            key_info_list.append(OpKeyInfo.from_signer_account(
                signer,
                neon_acct_list,
                holder_info_list
            ))
        return key_info_list

    @staticmethod
    def build_resource_list(key_info_list: List[OpKeyInfo]) -> List[OpResInfo]:
        if not len(key_info_list):
            return list()

        return [
            OpResInfo(key_info, holder_info)
            for key_info in key_info_list
            for holder_info in key_info.holder_info_list
        ]


def build_test_resource_info(neon_client: NeonClientBase, private_key: bytes, res_id: int) -> OpResInfo:
    chain_id_list = EVMConfig().chain_id_list
    signer = SolAccount.from_seed(private_key)
    neon_acct_list = [
        neon_client.get_neon_account_info(
            NeonAddress.from_private_key(private_key, chain_id)
        )
        for chain_id in chain_id_list
    ]
    holder_info = OpHolderInfo.from_public_key(signer.pubkey(), res_id)
    key_info = OpKeyInfo.from_signer_account(signer, neon_acct_list, [holder_info])
    return OpResInfo(key_info, holder_info)
