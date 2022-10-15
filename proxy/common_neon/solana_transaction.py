from typing import Union, Dict, Any
from dataclasses import dataclass

from solana.transaction import Transaction, TransactionInstruction, Blockhash, AccountMeta, Signature
from solana.message import Message, MessageHeader, MessageArgs, CompiledInstruction
from solana.keypair import Keypair
from solana.publickey import PublicKey


SolLegacyTx = Transaction
SolLegacyMsg = Message
SolLegacyMsgArgs = MessageArgs
SolMsgHdr = MessageHeader
SolTxIx = TransactionInstruction
SolBlockhash = Blockhash
SolAccountMeta = AccountMeta
SolAccount = Keypair
SolPubKey = PublicKey
SolCompiledIx = CompiledInstruction
SolTxReceipt = Dict[str, Any]
SolSignature = Signature


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

    def signature(self) -> Signature:
        return self.tx.signature()

    def serialize(self) -> bytes:
        return self.tx.serialize()

    def sign(self, *signers: SolAccount) -> None:
        self.tx.sign(*signers)


SolTx = Union[SolLegacyTx, SolWrappedTx]
