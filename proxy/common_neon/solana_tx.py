from __future__ import annotations

from typing import Sequence, Optional, Union, Dict, Any

import abc

import solana.transaction

import solders.hash
import solders.keypair
import solders.pubkey
import solders.instruction
import solders.signature

SolTxIx = solders.instruction.Instruction
SolAccountMeta = solana.transaction.AccountMeta
SolBlockhash = solders.hash.Hash
SolAccount = solders.keypair.Keypair
SolSignature = solders.signature.Signature
SolPubKey = solders.pubkey.Pubkey
SolTxReceipt = Dict[str, Any]


class SolTxSizeError(Exception):
    pass


class SolTx(abc.ABC):
    _empty_blockhash = SolBlockhash.default()

    def __init__(self, name: str = '', instructions: Optional[Sequence[SolTxIx]] = None):
        self._name = name
        self._tx = solana.transaction.Transaction(instructions=instructions)
        self._is_signed = False

    @property
    def name(self) -> str:
        return self._name

    def is_empty(self) -> bool:
        return len(self._tx.instructions) == 0

    @property
    def recent_blockhash(self) -> Optional[SolBlockhash]:
        blockhash = self._tx.recent_blockhash
        if blockhash == self._empty_blockhash:
            return None
        return blockhash

    @recent_blockhash.setter
    def recent_blockhash(self, blockhash: Optional[SolBlockhash]) -> None:
        self._tx.recent_blockhash = blockhash
        self._is_signed = False

    def add(self, *args: Union[SolTx, SolTxIx]) -> SolTx:
        ix_list = list(self._tx.instructions)
        for arg in args:
            if isinstance(arg, SolTxIx):
                ix_list.append(arg)
            elif isinstance(arg, SolTx):
                ix_list.extend(arg._tx.instructions)
            else:
                raise ValueError("invalid instruction:", arg)

        self._tx.instructions = ix_list
        self._is_signed = False
        return self

    def serialize(self) -> bytes:
        assert self._is_signed, "transaction has not been signed"
        result = self._serialize()
        if len(result) > solana.transaction.PACKET_DATA_SIZE:
            raise SolTxSizeError('Transaction too big')
        return result

    def sign(self, signer: SolAccount) -> None:
        self._sign(signer)
        self._is_signed = True

    @property
    def signature(self) -> SolSignature:
        assert self._is_signed, "transaction has not been signed"
        return self._signature()

    @abc.abstractmethod
    def _serialize(self) -> bytes:
        pass

    @abc.abstractmethod
    def _sign(self, signer: SolAccount) -> None:
        pass

    @abc.abstractmethod
    def _signature(self) -> SolSignature:
        pass
