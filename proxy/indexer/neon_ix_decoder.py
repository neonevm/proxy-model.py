import logging
import dataclasses

from typing import Any, List, Type, Optional, Iterator

from ..common_neon.utils import NeonTxInfo
from ..common_neon.utils.evm_log_decoder import NeonLogTxEvent

from ..indexer.indexed_objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonAccountInfo, SolNeonTxDecoderState


LOG = logging.getLogger(__name__)


class DummyIxDecoder:
    _name = 'Unknown'
    _ix_code = 0xFF
    _is_deprecated = True

    def __init__(self, state: SolNeonTxDecoderState):
        self._state = state
        LOG.debug(f'{self} ...')

    @classmethod
    def ix_code(cls) -> int:
        return cls._ix_code

    @classmethod
    def is_deprecated(cls) -> bool:
        return cls._is_deprecated

    @classmethod
    def name(cls) -> str:
        return cls._name

    def __str__(self):
        if self._is_deprecated:
            return f'DEPRECATED 0x{self._ix_code:02x}:{self._name} {self.state.sol_neon_ix}'
        return f'0x{self._ix_code:02x}:{self._name} {self.state.sol_neon_ix}'

    def execute(self) -> bool:
        """ By default, skip the instruction without parsing. """
        ix = self.state.sol_neon_ix
        return self._decoding_skip(f'no logic to decode the instruction {self}({ix.ix_data.hex()[:8]})')

    @property
    def state(self) -> SolNeonTxDecoderState:
        return self._state

    @staticmethod
    def _decoding_success(indexed_obj: Any, msg: str) -> bool:
        """ The instruction has been successfully parsed. """
        LOG.debug(f'decoding success: {msg} - {indexed_obj}')
        return True

    def _decoding_done(self, indexed_obj: Any, msg: str) -> bool:
        """ Assembling of the object has been successfully finished. """
        block = self.state.neon_block
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            block.done_neon_tx(indexed_obj, self.state.sol_neon_ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            block.done_neon_holder(indexed_obj)
        LOG.debug(f'decoding done: {msg} - {indexed_obj}')
        return True

    @staticmethod
    def _decoding_skip(reason: str) -> bool:
        """ Skip decoding of the instruction. """
        LOG.warning(f'decoding skip: {reason}')
        return False


class BaseTxIxDecoder(DummyIxDecoder):
    def _add_neon_indexed_tx(self) -> Optional[NeonIndexedTxInfo]:
        neon_tx: Optional[NeonTxInfo] = self._decode_neon_tx()
        if neon_tx is None:
            return None

        ix = self.state.sol_neon_ix
        if ix.neon_tx_sig != neon_tx.sig:
            self._decoding_skip(f'NeonTx.Hash "{neon_tx.sig}" != SolIx.Log.Hash "{ix.neon_tx_sig}"')
            return None

        holder_account: Optional[str] = self._decode_holder_account()
        if holder_account is None:
            return None

        iter_blocked_account: Optional[Iterator[str]] = self._decode_iter_blocked_account()
        if iter_blocked_account is None:
            return None

        block = self.state.neon_block
        tx_type = NeonIndexedTxInfo.Type(self._ix_code)
        return block.add_neon_tx(tx_type, neon_tx, holder_account, iter_blocked_account, ix)

    def _decode_neon_tx(self) -> Optional[NeonTxInfo]:
        return NeonTxInfo.from_neon_sig(self.state.sol_neon_ix.neon_tx_sig)

    def _decode_holder_account(self) -> Optional[str]:
        raise RuntimeError('Call of not-implemented method to decode NeonHolder.Account')

    def _decode_iter_blocked_account(self) -> Optional[Iterator[str]]:
        raise RuntimeError('Call of not-implemented method to decode NeonTx.BlockedAccounts')

    def _decode_neon_tx_from_data(self, data_name: str, data: bytes) -> Optional[NeonTxInfo]:
        ix = self.state.sol_neon_ix
        neon_tx = NeonTxInfo.from_sig_data(data)
        if not neon_tx.is_valid():
            self._decoding_skip(f'{data_name}.RLP.Error: "{neon_tx.error}"')
            return None
        elif neon_tx.sig != ix.neon_tx_sig:
            # failed decoding ...
            self._decoding_skip(f'NeonTx.Hash "{neon_tx.sig}" != SolIx.Log.Hash "{ix.neon_tx_sig}"')
            return None
        return neon_tx

    def _decode_neon_tx_from_holder(self, holder: NeonIndexedHolderInfo) -> Optional[NeonTxInfo]:
        neon_tx = self._decode_neon_tx_from_data('NeonHolder.Data', holder.data)
        if neon_tx is None:
            return None
        elif holder.neon_tx_sig != neon_tx.sig[2:]:
            # failed decoding ...
            self._decoding_skip(f'NeonTx.Hash "{neon_tx.sig}" != NeonHolder.Hash "{holder.neon_tx_sig}"')
            return None

        self._decoding_done(holder, f'init NeonTx {neon_tx} from NeonHolder.Data')
        return neon_tx

    def _decode_neon_tx_sig_from_ix_data(self, offset: int, min_len: int) -> Optional[str]:
        ix = self.state.sol_neon_ix

        if len(ix.ix_data) < min_len:
            self._decoding_skip(f'no enough SolIx.Data(len={len(ix.ix_data)}) to get NeonTx.Hash')
            return None

        neon_tx_sig: str = '0x' + ix.ix_data[offset:(offset + 32)].hex().lower()
        if ix.neon_tx_sig != neon_tx_sig:
            self._decoding_skip(f'NeonTx.Hash "{neon_tx_sig}" != SolIx.Log.Hash "{ix.neon_tx_sig}"')
            return None

        return neon_tx_sig

    def _decode_neon_tx_from_holder_account(self, tx: NeonIndexedTxInfo) -> bool:
        if tx.neon_tx.is_valid():
            return False

        ix = self.state.sol_neon_ix
        block = self.state.neon_block

        holder: Optional[NeonIndexedHolderInfo] = block.find_neon_tx_holder(tx.holder_account, ix)
        if holder is None:
            return False

        neon_tx: Optional[NeonTxInfo] = self._decode_neon_tx_from_holder(holder)
        if neon_tx is None:
            return False

        tx.set_neon_tx(neon_tx, holder)
        return True

    def _decode_neon_tx_receipt(self, tx: NeonIndexedTxInfo) -> bool:
        self._decode_neon_tx_event_list(tx)
        if tx.neon_tx_res.is_completed():
            pass
        elif self._decode_neon_tx_return(tx):
            self._add_return_event(tx)
            return True

        return False

    def _decode_neon_tx_return(self, tx: NeonIndexedTxInfo) -> bool:
        ret = self.state.sol_neon_ix.neon_tx_return
        if ret is None:
            return False

        tx.neon_tx_res.set_res(status=ret.status, gas_used=ret.gas_used)
        return True

    def _add_return_event(self, tx: NeonIndexedTxInfo) -> None:
        ix = self.state.sol_neon_ix
        res = tx.neon_tx_res

        if res.is_canceled():
            event_type = NeonLogTxEvent.Type.Cancel
        elif res.is_completed():
            event_type = NeonLogTxEvent.Type.Return
        else:
            return

        res.set_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)

        event = NeonLogTxEvent(
            event_type=event_type,
            is_hidden=True,
            address=b'',
            topic_list=list(),
            data=int(res.status[2:], 16).to_bytes(1, 'little'),
            total_gas_used=int(res.gas_used[2:], 16) + 5000,  # to move event to the end of the list
            sol_sig=ix.sol_sig,
            idx=ix.idx,
            inner_idx=ix.inner_idx
        )
        tx.add_neon_event(event)

    def _decode_neon_tx_event_list(self, tx: NeonIndexedTxInfo) -> None:
        ix = self.state.sol_neon_ix

        total_gas_used = ix.neon_total_gas_used
        for event in ix.neon_tx_event_list:
            event = dataclasses.replace(
                event,
                total_gas_used=total_gas_used,
                sol_sig=ix.sol_sig,
                idx=ix.idx,
                inner_idx=ix.inner_idx
            )
            tx.add_neon_event(event)
            total_gas_used += 1


class BaseTxSimpleIxDecoder(BaseTxIxDecoder):
    def _decode_tx(self, msg: str) -> bool:
        tx: Optional[NeonIndexedTxInfo] = self._add_neon_indexed_tx()
        if tx is None:
            return False

        self._decode_neon_tx_receipt(tx)
        self._decoding_done(tx, msg)
        return True

    def _decode_iter_blocked_account(self) -> Iterator[str]:
        return iter(())

    def _decode_neon_tx_return(self, tx: NeonIndexedTxInfo) -> bool:
        if super()._decode_neon_tx_return(tx):
            return True

        ix = self.state.sol_neon_ix
        tx.neon_tx_res.set_lost_res(ix.neon_total_gas_used)
        LOG.warning(f'set lost result (is_log_truncated ?= {ix.is_log_truncated}) - {tx}')
        return True


class TxExecFromDataIxDecoder(BaseTxSimpleIxDecoder):
    _name = 'TransactionExecuteFromInstruction'
    _ix_code = 0x1f
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decode_tx('NeonTx exec from SolIx.Data')

    def _decode_holder_account(self) -> Optional[str]:
        return ''

    def _decode_neon_tx(self) -> Optional[NeonTxInfo]:
        # 1 byte  - ix
        # 4 bytes - treasury index
        # N bytes - NeonTx

        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 6:
            self._decoding_skip(f'no enough SolIx.Data(len={len(ix.ix_data)}) to decode NeonTx')
            return None

        rlp_sig_data = ix.ix_data[5:]
        return self._decode_neon_tx_from_data('SolIx.Data', rlp_sig_data)


class TxExecFromAccountIxDecoder(BaseTxSimpleIxDecoder):
    _name = 'TransactionExecFromAccount'
    _ix_code = 0x2a
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decode_tx('NeonTx exec from NeonHolder.Data')

    def _decode_holder_account(self) -> Optional[str]:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < 1:
            self._decoding_skip(f'no enough SolIx.Accounts(len={ix.account_cnt}) to get NeonHolder.Account')
            return None

        return ix.get_account(0)

    def _add_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)
        super()._add_return_event(tx)


class BaseTxStepIxDecoder(BaseTxIxDecoder):
    _first_blocked_account_idx = 6

    def _decode_tx(self, msg: str) -> bool:
        if not self._decode_neon_evm_step_cnt():
            return False

        tx: Optional[NeonIndexedTxInfo] = self._get_neon_indexed_tx()
        if tx is None:
            return False

        if self._decode_neon_tx_receipt(tx):
            return self._decoding_done(tx, msg)
        return self._decoding_success(tx, msg)

    def _get_neon_indexed_tx(self) -> Optional[NeonIndexedTxInfo]:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        return block.find_neon_tx(ix) or self._add_neon_indexed_tx()

    def _decode_neon_evm_step_cnt(self) -> bool:
        # 1 byte  - ix
        # 4 bytes - treasury index
        # 4 bytes - neon step cnt
        # 4 bytes - unique index

        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 9:
            return self._decoding_skip(f'no enough SolIx.Data(len={len(ix.ix_data)}) to get NeonTx.StepCnt')

        neon_step_cnt = int.from_bytes(ix.ix_data[5:9], 'little')
        ix.set_neon_step_cnt(neon_step_cnt)
        return True

    def _decode_holder_account(self) -> Optional[str]:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < 1:
            self._decoding_skip(f'no enough SolIx.Accounts(len={ix.account_cnt}) to get NeonHolder.Account')
            return None

        return ix.get_account(0)

    def _decode_iter_blocked_account(self) -> Optional[Iterator[str]]:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            self._decoding_skip(f'no enough SolIx.Accounts(len={ix.account_cnt}) to get NeonTx.BlockedAccounts')
            return None

        return ix.iter_account(self._first_blocked_account_idx)

    def decode_failed_neon_tx_event_list(self) -> None:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block

        tx: Optional[NeonIndexedTxInfo] = block.find_neon_tx(ix)
        if tx is None:
            return

        cnt = tx.len_neon_event_list
        for event in ix.neon_tx_event_list:
            event = dataclasses.replace(
                event,
                total_gas_used=9199999999999999999 + cnt,  # insert event to the end of the list
                is_reverted=True,
                is_hidden=True,
                sol_sig=ix.sol_sig,
                idx=ix.idx,
                inner_idx=ix.inner_idx
            )
            tx.add_neon_event(event)
            cnt += 1

        if ix.is_already_finalized and (not tx.neon_tx_res.is_valid()):
            tx.neon_tx_res.set_lost_res(1)  # unknown gas usage
            LOG.warning(f'set lost result')
            self._decoding_done(tx, 'complete by lost result')


class TxStepFromDataIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromInstruction'
    _ix_code = 0x20
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decode_tx('NeonTx step from SolIx.Data')

    def _decode_neon_tx(self) -> Optional[NeonTxInfo]:
        # 1 byte  - ix
        # 4 bytes - treasury index
        # 4 bytes - neon step cnt
        # 4 bytes - unique index
        # N bytes - NeonTx

        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 14:
            self._decoding_skip(f'no enough SolIx.Data(len={len(ix.ix_data)}) to decode NeonTx')
            return None

        rlp_sig_data = ix.ix_data[13:]
        return self._decode_neon_tx_from_data('SolIx.Data', rlp_sig_data)


class TxStepFromAccountIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromAccount'
    _ix_code = 0x21
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decode_tx('NeonTx step from NeonHolder.Data')

    def _add_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)
        super()._add_return_event(tx)


class TxStepFromAccountNoChainIdIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromAccountNoChainId'
    _ix_code = 0x22
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decode_tx('NeonTx-wo-ChainId step from NeonHolder.Data')

    def _add_return_event(self, tx: NeonIndexedTxInfo) -> None:
        self._decode_neon_tx_from_holder_account(tx)
        super()._add_return_event(tx)


class CancelWithHashIxDecoder(BaseTxStepIxDecoder):
    _name = 'CancelWithHash'
    _ix_code = 0x23
    _is_deprecated = False
    _first_blocked_account_idx = 3

    def execute(self) -> bool:
        # 1  byte  - ix
        # 32 bytes - tx hash

        neon_tx_sig = self._decode_neon_tx_sig_from_ix_data(1, 33)
        if neon_tx_sig is None:
            return False

        tx: Optional[NeonIndexedTxInfo] = self._get_neon_indexed_tx()
        if tx is None:
            return self._decoding_skip(f'cannot find NeonTx "{neon_tx_sig}"')

        if tx.neon_tx_res.is_completed():
            return self._decoding_skip(f'NeonTx {neon_tx_sig} is already has NeonReceipt')

        self._decode_neon_tx_receipt(tx)
        return self._decoding_done(tx, 'cancel NeonTx')

    def _decode_neon_tx_return(self, tx: NeonIndexedTxInfo) -> bool:
        tx.neon_tx_res.set_canceled_res(self.state.sol_neon_ix.neon_total_gas_used)
        return True


class WriteHolderAccountIx(BaseTxIxDecoder):
    _name = 'WriteHolderAccount'
    _ix_code = 0x26
    _is_deprecated = False

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block

        if ix.account_cnt < 1:
            return self._decoding_skip(f'no enough SolIx.Accounts(len={ix.account_cnt}) to get NeonHolder.Account')
        holder_account = ix.get_account(0)

        # 1  byte  - ix
        # 32 bytes - tx hash
        # 8  bytes - offset

        neon_tx_sig = self._decode_neon_tx_sig_from_ix_data(1, 42)
        if neon_tx_sig is None:
            return False

        data = ix.ix_data[41:]
        offset = int.from_bytes(ix.ix_data[33:41], 'little')
        chunk = NeonIndexedHolderInfo.DataChunk(offset=offset, length=len(data), data=data)

        tx: Optional[NeonIndexedTxInfo] = block.find_neon_tx(ix)
        if (tx is not None) and tx.neon_tx.is_valid():
            return self._decoding_success(tx, f'add surplus NeonTx.Data.Chunk to NeonTx')

        holder: Optional[NeonIndexedHolderInfo] = block.find_neon_tx_holder(holder_account, ix)
        if holder is None:
            holder = block.add_neon_tx_holder(holder_account, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        self._decoding_success(holder, f'add NeonTx.Data.Chunk {chunk}')

        if tx is None:
            return True

        neon_tx: Optional[NeonTxInfo] = self._decode_neon_tx_from_holder(holder)
        if neon_tx is not None:
            tx.set_neon_tx(neon_tx, holder)

        return True


class CreateAccount3IxDecoder(DummyIxDecoder):
    _name = 'CreateAccount3'
    _ix_code = 0x28
    _is_deprecated = False

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        if len(ix.ix_data) < 20:
            return self._decoding_skip(f'not enough data to get NeonAccount {len(ix.ix_data)}')

        neon_account = '0x' + ix.ix_data[1:][:20].hex()
        pda_account = ix.get_account(2)

        account_info = NeonAccountInfo(
            neon_account,
            pda_account,
            ix.block_slot,
            None,
            ix.sol_sig
        )
        block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create NeonAccount')


class CollectTreasureIxDecoder(DummyIxDecoder):
    _name = 'CollectTreasure'
    _ix_code = 0x1e
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decoding_success(None, 'collect NeonTreasury')


class CreateHolderAccountIx(DummyIxDecoder):
    _name = 'CreateHolderAccount'
    _ix_code = 0x24
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decoding_success(None, 'create NeonHolder')


class DeleteHolderAccountIx(DummyIxDecoder):
    _name = 'DeleteHolderAccount'
    _ix_code = 0x25
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decoding_success(None, 'delete NeonHolder')


class Deposit3IxDecoder(DummyIxDecoder):
    _name = 'Deposit3'
    _ix_code = 0x27
    _is_deprecated = False

    def execute(self) -> bool:
        return self._decoding_success(None, 'deposit NEONs')


def get_neon_ix_decoder_list() -> List[Type[DummyIxDecoder]]:
    ix_decoder_list = [
        TxExecFromDataIxDecoder,
        TxExecFromAccountIxDecoder,
        TxStepFromDataIxDecoder,
        TxStepFromAccountIxDecoder,
        TxStepFromAccountNoChainIdIxDecoder,
        CancelWithHashIxDecoder,
        WriteHolderAccountIx,
        CreateAccount3IxDecoder,
        CollectTreasureIxDecoder,
        CreateHolderAccountIx,
        DeleteHolderAccountIx,
        Deposit3IxDecoder,
    ]

    for IxDecoder in ix_decoder_list:
        assert not IxDecoder.is_deprecated(), f'{IxDecoder.name()} is deprecated!'

    return ix_decoder_list
