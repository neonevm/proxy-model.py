from __future__ import annotations

from typing import Union, Dict, Any, Optional, Sequence

import solana.blockhash
import solana.keypair
import solana.message
import solana.publickey
import solana.transaction

import solders.hash


SolLegacyMsg = solana.message.Message
SolTxIx = solana.transaction.TransactionInstruction
SolAccountMeta = solana.transaction.AccountMeta
SolBlockhash = solana.blockhash.Blockhash
SolAccount = solana.keypair.Keypair
SolPubKey = solana.publickey.PublicKey
SolTxReceipt = Dict[str, Any]
SolSignature = solana.keypair.Signature


class SolLegacyTx:
    _empty_blockhash = SolBlockhash(str(solders.hash.Hash.default()))
    """Legacy transaction class to represent an atomic versioned transaction."""

    def __init__(self, instructions: Optional[Sequence[SolTxIx]] = None) -> None:
        self._tx = solana.transaction.Transaction(instructions=instructions)

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

    @property
    def signature(self) -> SolSignature:
        return self._tx.signature()

    @property
    def message(self) -> SolLegacyMsg:
        return self._tx.compile_message()

    def serialize(self) -> bytes:
        return self._tx.serialize()

    def sign(self, signer: SolAccount) -> None:
        self._tx.sign(signer)

    def add(self, *args: Union[SolLegacyTx, SolTxIx]) -> SolLegacyTx:
        ix_list = list(self._tx.instructions)
        for arg in args:
            if isinstance(arg, SolTxIx):
                ix_list.append(arg)
            elif isinstance(arg, SolLegacyTx):
                ix_list.extend(arg._tx.instructions)
            else:
                raise ValueError("invalid instruction:", arg)

        self._tx.instructions = ix_list
        return self
