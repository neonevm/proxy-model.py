from typing import Optional, Union, Dict, Any
from dataclasses import dataclass

from solana.transaction import Transaction, TransactionInstruction, Blockhash, AccountMeta
from solana.message import Message, MessageHeader, MessageArgs, CompiledInstruction
from solana.account import Account
from solana.publickey import PublicKey


SolLegacyTx = Transaction
SolLegacyMsg = Message
SolLegacyMsgArgs = MessageArgs
SolMsgHdr = MessageHeader
SolTxIx = TransactionInstruction
SolBlockhash = Blockhash
SolAccountMeta = AccountMeta
SolAccount = Account
SolPubKey = PublicKey
SolCompiledIx = CompiledInstruction
SolTxReceipt = Dict[str, Any]


@dataclass
class SolWrappedTx:
    name: str
    tx: SolLegacyTx

    @property
    def recent_blockhash(self) -> SolBlockhash:
        return self.tx.recent_blockhash

    @recent_blockhash.setter
    def recent_blockhash(self, blockhash: SolBlockhash) -> None:
        self.tx.recent_blockhash = blockhash

    def signature(self) -> Optional[bytes]:
        return self.tx.signature()

    def serialize(self) -> bytes:
        return self.tx.serialize()

    def sign(self, *signers: SolAccount) -> None:
        self.tx.sign(*signers)


SolTx = Union[SolLegacyTx, SolWrappedTx]
