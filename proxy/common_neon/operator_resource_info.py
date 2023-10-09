from __future__ import annotations

from typing import List, Dict, Union
from dataclasses import dataclass

from .config import Config
from .solana_tx import SolAccount, SolPubKey
from .elf_params import ElfParams
from .utils.utils import cached_method
from .address import NeonAddress, perm_account_seed, neon_account_with_seed


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
    neon_address_list: List[NeonAddress]
    neon_account_dict: Dict[int, SolPubKey]
    holder_info_list: List[OpHolderInfo]

    @staticmethod
    def from_signer_account(
        signer: SolAccount,
        neon_address_list: List[NeonAddress],
        holder_info_list: List[OpHolderInfo]
    ) -> OpKeyInfo:
        return OpKeyInfo(
            signer=signer,
            neon_address_list=neon_address_list,
            neon_account_dict=dict(),
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
    def neon_address_list(self) -> List[NeonAddress]:
        return self.key_info.neon_address_list

    @property
    def neon_account_dict(self) -> Dict[int, SolPubKey]:
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
    def __init__(self, config: Config):
        self._config = config

    def build_key_list(self, secret_list: List[bytes]) -> List[OpKeyInfo]:
        chain_id_list = self._build_chain_id_list()
        key_info_list: List[OpKeyInfo] = list()
        start_res_id = self._config.perm_account_id
        stop_res_id = self._config.perm_account_id + self._config.perm_account_limit

        for private_key in secret_list:
            signer = SolAccount.from_seed(private_key)
            neon_addr_list = [
                NeonAddress.from_private_key(private_key, chain_id)
                for chain_id in chain_id_list
            ]
            holder_info_list = [
                OpHolderInfo.from_public_key(signer.pubkey(), res_id)
                for res_id in range(start_res_id, stop_res_id)
            ]

            key_info_list.append(OpKeyInfo.from_signer_account(
                signer,
                neon_addr_list,
                holder_info_list
            ))
        return key_info_list

    def build_resource_list(self, key_info_list: List[Union[bytes, OpKeyInfo]]) -> List[OpResInfo]:
        if not len(key_info_list):
            return list()
        if isinstance(key_info_list[0], bytes):
            key_info_list = self.build_key_list(key_info_list)

        return [
            OpResInfo(OpKeyInfo.from_signer_account(key_info.signer, key_info.neon_address_list, []), holder_info)
            for key_info in key_info_list
            for holder_info in key_info.holder_info_list
        ]

    def build_test_resource_info(self, private_key: bytes, res_id: int) -> OpResInfo:
        chain_id_list = self._build_chain_id_list()
        signer = SolAccount.from_seed(private_key)
        neon_addr_list = [
            NeonAddress.from_private_key(private_key, chain_id)
            for chain_id in chain_id_list
        ]
        holder_info = OpHolderInfo.from_public_key(signer.pubkey(), res_id)
        key_info = OpKeyInfo.from_signer_account(signer, neon_addr_list, [holder_info])
        return OpResInfo(key_info, holder_info)

    @staticmethod
    def _build_chain_id_list() -> List[int]:
        return [ElfParams().chain_id]
