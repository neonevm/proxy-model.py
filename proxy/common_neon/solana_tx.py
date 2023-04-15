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
        super().__init__()

    def __str__(self) -> str:
        return 'Transaction size is exceeded'


class SolTx(abc.ABC):
    _empty_block_hash = SolBlockHash.default()

    def __init__(self, name: str, ix_list: Optional[Sequence[SolTxIx]]) -> None:
        self._name = name
        self._is_signed = False
        self._is_cloned = False
        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=None, ix_list=ix_list)

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
    def recent_block_hash(self, value: Optional[SolBlockHash]) -> None:
        ix_list = self._decode_ix_list()
        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=value, ix_list=ix_list)

    @property
    def ix_list(self) -> List[SolTxIx]:
        return self._decode_ix_list()

    @property
    def fee_payer(self) -> Optional[SolPubKey]:
        acct_key_list = self._solders_legacy_tx.message.account_keys
        return acct_key_list[0] if acct_key_list else None

    @fee_payer.setter
    def fee_payer(self, value: SolPubKey) -> None:
        block_hash = self.recent_block_hash
        ix_list = self._decode_ix_list(value)
        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=block_hash, ix_list=ix_list)

    def add(self, *args: Union[SolTx, SolTxIx]) -> SolTx:
        ix_list = self._decode_ix_list()
        for arg in args:
            if isinstance(arg, SolTxIx):
                ix_list.append(arg)
            elif isinstance(arg, SolTx):
                ix_list.extend(arg._decode_ix_list())
            else:
                raise ValueError('invalid instruction:', arg)

        block_hash = self.recent_block_hash
        self._solders_legacy_tx = self._build_legacy_tx(recent_block_hash=block_hash, ix_list=ix_list)
        return self

    def serialize(self) -> bytes:
        assert self._is_signed, 'transaction has not been signed'
        result = self._serialize()
        if len(result) > _SolPktDataSize:
            raise SolTxSizeError()
        return result

    def sign(self, signer: SolAccount) -> None:
        if signer.pubkey() != self.fee_payer:
            self.fee_payer = signer.pubkey()
        self._sign(signer)
        self._is_signed = True

    def has_valid_size(self, signer: SolAccount) -> bool:
        tx = self._clone()
        tx.recent_block_hash = SolBlockHash.from_string('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(signer)
        try:
            tx.serialize()  # <- there will be exception
            return True
        except SolTxSizeError:
            return False

    def clone(self) -> SolTx:
        tx = self._clone()
        self._is_cloned = True
        return tx

    def _build_legacy_tx(self, recent_block_hash: Optional[SolBlockHash],
                         ix_list: Optional[Sequence[SolTxIx]]) -> _SoldersLegacyTx:
        self._is_signed = False

        if recent_block_hash is None:
            recent_block_hash = SolBlockHash.default()

        if ix_list is None:
            ix_list: List[SolTxIx] = list()

        fee_payer: Optional[SolPubKey] = None
        for ix in ix_list:
            for acct_meta in ix.accounts:
                if acct_meta.is_signer:
                    fee_payer = acct_meta.pubkey
                    break

        msg = _SoldersLegacyMsg.new_with_blockhash(ix_list, fee_payer, recent_block_hash)
        return _SoldersLegacyTx.new_unsigned(msg)

    def _decode_ix_list(self, signer: Optional[SolPubKey] = None) -> List[SolTxIx]:
        msg = self._solders_legacy_tx.message
        acct_key_list = msg.account_keys
        ix_list: List[SolTxIx] = list()
        for compiled_ix in msg.instructions:
            ix_data = compiled_ix.data
            program_id = acct_key_list[compiled_ix.program_id_index]

            acct_meta_list: List[SolAccountMeta] = list()
            for idx in compiled_ix.accounts:
                is_signer = msg.is_signer(idx)
                if (signer is not None) and is_signer:
                    acct_meta = SolAccountMeta(signer, True, msg.is_writable(idx))
                else:
                    acct_meta = SolAccountMeta(acct_key_list[idx], is_signer, msg.is_writable(idx))
                acct_meta_list.append(acct_meta)

            ix_list.append(SolTxIx(program_id, ix_data, acct_meta_list))
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
