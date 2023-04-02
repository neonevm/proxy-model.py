from __future__ import annotations

from typing import Sequence, Optional, Union, Dict, Any, Set, List, NewType

import abc

import solders.hash
import solders.keypair
import solders.pubkey
import solders.instruction
import solders.signature
import solders.transaction


SolTxIx = solders.instruction.Instruction
SolAccountMeta = solders.instruction.AccountMeta
SolBlockHash = solders.hash.Hash
SolAccount = solders.keypair.Keypair
SolSig = solders.signature.Signature
SolPubKey = solders.pubkey.Pubkey
SolTxReceipt = Dict[str, Any]

_SoldersLegacyTx = solders.transaction.Transaction
_SoldersLegacyMsg = solders.message.Message
_SolPktDataSize = 1280 - 40 - 8


class SolCommit:
    Type = NewType('SolCommit', str)

    NotProcessed = Type('not-processed')
    Processed = Type('processed')
    Confirmed = Type('confirmed')
    Safe = Type('safe')  # optimistic-finalized => 2/3 of validators
    Finalized = Type('finalized')

    Order = [NotProcessed, Processed, Confirmed, Safe, Finalized]

    @staticmethod
    def level(commitment: Type) -> int:
        for index, value in enumerate(SolCommit.Order):
            if value == commitment:
                return index

        assert False, 'Wrong commitment'

    @staticmethod
    def upper_set(commitment: Type) -> Set[Type]:
        level = SolCommit.level(commitment)
        return set(SolCommit.Order[level:])

    @staticmethod
    def lower_set(commitment: Type) -> Set[Type]:
        level = SolCommit.level(commitment)
        return set(SolCommit.Order[:level])

    @staticmethod
    def to_solana(commitment: Type) -> Type:
        if commitment == SolCommit.NotProcessed:
            return SolCommit.Processed
        elif commitment == SolCommit.Safe:
            return SolCommit.Confirmed
        elif commitment in {SolCommit.Processed, SolCommit.Confirmed, SolCommit.Finalized}:
            return commitment

        assert False, 'Wrong commitment'


class SolTxSizeError(AttributeError):
    def __init__(self):
        super().__init__('Transaction size is exceeded')


class SolTx(abc.ABC):
    _empty_block_hash = SolBlockHash.default()

    def __init__(self, name: str, ix_list: Optional[Sequence[SolTxIx]]) -> None:
        self._name = name
        self._is_signed = False
        self._is_cloned = False

        self._solders_legacy_tx = _SoldersLegacyTx.default()
        if ix_list is not None:
            self._solders_legacy_tx = self._build_legacy_tx(ix_list=ix_list)

    @property
    def name(self) -> str:
        return self._name

    def is_empty(self) -> bool:
        return len(self._solders_legacy_tx.message.instructions) == 0

    def is_cloned(self) -> bool:
        return self._is_cloned

    @property
    def recent_block_hash(self) -> Optional[SolBlockHash]:
        block_hash = self._solders_legacy_tx.message.recent_blockhash
        if block_hash == self._empty_block_hash:
            return None
        return block_hash

    @recent_block_hash.setter
    def recent_block_hash(self, block_hash: Optional[SolBlockHash]) -> None:
        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=block_hash, ix_list=self._decode_ix_list())

    @property
    def ix_list(self) -> List[SolTxIx]:
        return self._decode_ix_list()

    def add(self, *args: Union[SolTx, SolTxIx]) -> SolTx:
        ix_list = self._decode_ix_list()
        for arg in args:
            if isinstance(arg, SolTxIx):
                ix_list.append(arg)
            elif isinstance(arg, SolTx):
                ix_list.extend(arg._decode_ix_list())
            else:
                raise ValueError('invalid instruction:', arg)

        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=self.recent_block_hash, ix_list=ix_list)
        return self

    def serialize(self) -> bytes:
        assert self._is_signed, 'transaction has not been signed'
        result = self._serialize()
        if len(result) > _SolPktDataSize:
            raise SolTxSizeError()
        return result

    def sign(self, signer: SolAccount) -> None:
        self._sign(signer)
        self._is_signed = True

    def clone(self) -> SolTx:
        tx = self._clone()
        self._is_cloned = True
        return tx

    def _build_legacy_tx(self, recent_block_hash: Optional[SolBlockHash] = None,
                         ix_list: Optional[Sequence[SolTxIx]] = None) -> _SoldersLegacyTx:
        self._is_signed = False

        acct_key_list = self._solders_legacy_tx.message.account_keys
        fee_payer = acct_key_list[0] if acct_key_list else None

        if recent_block_hash is None:
            recent_block_hash = SolBlockHash.default()

        if ix_list is None:
            ix_list: List[SolTx] = list()

        msg = _SoldersLegacyMsg.new_with_blockhash(ix_list, fee_payer, recent_block_hash)
        return _SoldersLegacyTx.new_unsigned(msg)

    def _decode_ix_list(self) -> List[SolTxIx]:
        msg = self._solders_legacy_tx.message
        acct_key_list = msg.account_keys
        ix_list: List[SolTxIx] = list()
        for compiled_ix in msg.instructions:
            program_id = acct_key_list[compiled_ix.program_id_index]
            acct_meta_list = [
                SolAccountMeta(
                    acct_key_list[idx],
                    is_signer=msg.is_signer(idx),
                    is_writable=msg.is_writable(idx),
                )
                for idx in compiled_ix.accounts
            ]
            ix_list.append(SolTxIx(program_id, compiled_ix.data, acct_meta_list))
        return ix_list

    @property
    def is_signed(self) -> bool:
        return self._is_signed

    @property
    def sig(self) -> SolSig:
        assert self._is_signed, 'Transaction has not been signed'
        return self._sig()

    @abc.abstractmethod
    def _serialize(self) -> bytes:
        pass

    @abc.abstractmethod
    def _sign(self, signer: SolAccount) -> None:
        pass

    @abc.abstractmethod
    def _sig(self) -> SolSig:
        pass

    @abc.abstractmethod
    def _clone(self) -> SolTx:
        pass
