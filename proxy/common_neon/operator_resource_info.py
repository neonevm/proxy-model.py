from __future__ import annotations

from typing import List, Set
from dataclasses import dataclass

from .config import Config
from .solana_tx import SolAccount, SolPubKey
from .address import NeonAddress, perm_account_seed, account_with_seed


@dataclass(frozen=True)
class OpResIdent:
    evm_program_id: SolPubKey
    public_key: str
    private_key: bytes
    res_id: int = -1

    _str = ''
    _hash = 0

    def __str__(self) -> str:
        if self._str == '':
            _str = f'{self.public_key}:{self.res_id}'
            object.__setattr__(self, '_str', _str)
        return self._str

    def __hash__(self) -> int:
        if self._hash == 0:
            _hash = hash(str(self))
            object.__setattr__(self, '_hash', _hash)
        return self._hash

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, OpResIdent) and
            other.res_id == self.res_id and
            other.public_key == self.public_key
        )


@dataclass(frozen=True)
class OpResInfo:
    ident: OpResIdent
    signer: SolAccount

    holder_account: SolPubKey
    holder_seed: bytes

    neon_address: NeonAddress

    @staticmethod
    def from_ident(ident: OpResIdent) -> OpResInfo:
        signer = SolAccount.from_seed(ident.private_key)
        assert ident.public_key == str(signer.pubkey())

        holder_seed = perm_account_seed(b'holder-', ident.res_id)
        holder_acct = account_with_seed(ident.evm_program_id, signer.pubkey(), holder_seed)
        neon_address = NeonAddress.from_private_key(signer.secret())

        return OpResInfo(
            ident=ident,
            signer=signer,
            holder_account=holder_acct,
            holder_seed=holder_seed,
            neon_address=neon_address
        )

    def __str__(self) -> str:
        return str(self.ident)

    @property
    def public_key(self) -> SolPubKey:
        return self.signer.pubkey()

    @property
    def secret_key(self) -> bytes:
        return self.signer.secret()


class OpResIdentListBuilder:
    def __init__(self, config: Config):
        self._config = config

    def build_resource_list(self, secret_list: List[bytes]) -> List[OpResIdent]:
        ident_set: Set[OpResIdent] = set()

        stop_perm_account_id = self._config.perm_account_id + self._config.perm_account_limit
        for res_id in range(self._config.perm_account_id, stop_perm_account_id):
            for ident in secret_list:
                sol_account = SolAccount.from_seed(ident)
                ident = OpResIdent(
                    self._config.evm_program_id,
                    public_key=str(sol_account.pubkey()),
                    private_key=sol_account.secret(),
                    res_id=res_id
                )
                ident_set.add(ident)

        return list(ident_set)
