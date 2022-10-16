from __future__ import annotations

from typing import Union, Optional

from ..common_neon.solana_transaction import SolLegacyTx, SolTxIx, SolBlockhash, SolSignature, SolAccount
from ..common_neon.solana_transaction_v0 import SolV0Tx


SolLowLevelTx = Union[SolLegacyTx, SolV0Tx]


class SolNamedTx:
    def __init__(self, name: str, tx: SolLowLevelTx):
        self._name = name
        self._tx = tx

    @property
    def name(self) -> str:
        return self._name

    @property
    def recent_blockhash(self) -> Optional[SolBlockhash]:
        return self._tx.recent_blockhash

    @recent_blockhash.setter
    def recent_blockhash(self, blockhash: Optional[SolBlockhash]) -> None:
        self._tx.recent_blockhash = blockhash

    @property
    def signature(self) -> SolSignature:
        return self._tx.signature

    def serialize(self) -> bytes:
        return self._tx.serialize()

    def sign(self, signer: SolAccount) -> None:
        self._tx.sign(signer)

    def add(self, *args: Union[SolLegacyTx, SolTxIx]) -> SolNamedTx:
        self._tx.add(*args)
        return self


SolTx = Union[SolLegacyTx, SolV0Tx, SolNamedTx]
