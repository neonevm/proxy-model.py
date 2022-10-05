from logged_groups import logged_group
from typing import Any, List, Type, Optional, Iterator

from ..common_neon.evm_log_decoder import decode_neon_tx_result, decode_neon_tx_sig, decode_cancel_gas
from ..common_neon.utils import NeonTxInfo

from ..indexer.indexed_objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonAccountInfo, SolNeonTxDecoderState


@logged_group("neon.Indexer")
class DummyIxDecoder:
    _name = 'Unknown'
    _ix_code = 0xFF
    _is_deprecated = True

    def __init__(self, state: SolNeonTxDecoderState):
        self._state = state
        self.debug(f'{self} ...')

    @classmethod
    def ix_code(cls) -> int:
        return cls._ix_code

    def __str__(self):
        if self._is_deprecated:
            return f'DEPRECATED 0x{self._ix_code:02x}:{self._name} {self.state.sol_neon_ix}'
        return f'0x{self._ix_code:02x}:{self._name} {self.state.sol_neon_ix}'

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        ix = self.state.sol_neon_ix
        return self._decoding_skip(f'no logic to decode the instruction {self}({ix.ix_data.hex()[:8]})')

    @property
    def state(self) -> SolNeonTxDecoderState:
        return self._state

    def _decoding_success(self, indexed_obj: Any, msg: str) -> bool:
        """
        The instruction has been successfully parsed:
        - Mark the instruction as used;
        - log the success message.
        """
        self.debug(f'decoding success: {msg} - {indexed_obj}')
        return True

    def _decoding_done(self, indexed_obj: Any, msg: str) -> bool:
        """
        Assembling of the object has been successfully finished.
        """
        ix = self.state.sol_neon_ix
        block = self.state.neon_block
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            block.done_neon_tx(indexed_obj, ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            block.done_neon_holder(indexed_obj)
        self.debug(f'decoding done: {msg} - {indexed_obj}')
        return True

    def _decoding_skip(self, reason: str) -> bool:
        """Skip decoding of the instruction"""
        self.debug(f'decoding skip: {reason}')
        return False

    def _decoding_fail(self, indexed_obj: Any, reason: str) -> bool:
        """
        Assembling of objects has been failed:
        - destroy the intermediate objects;
        - unmark all instructions as used.

        Show errors in warning mode because it can be a result of restarting.
        """
        block = self.state.neon_block
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            block.fail_neon_tx(indexed_obj)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            block.fail_neon_holder(indexed_obj)
        self.warning(f'decoding fail: {reason} - {indexed_obj}')
        return False

    def _decode_neon_tx_from_holder(self, tx: NeonIndexedTxInfo, holder: NeonIndexedHolderInfo) -> None:
        neon_tx = NeonTxInfo.from_sig_data(holder.data)
        if not neon_tx.is_valid():
            self.warning(f'Neon tx rlp error: {neon_tx.error}')
        elif neon_tx.sig != tx.neon_tx.sig:
            self.warning(f'Neon tx hash {neon_tx.sig} != {tx.neon_tx.sig}')
        else:
            tx.set_neon_tx(neon_tx)
            tx.set_holder_account(holder)
            self._decoding_done(holder, f'init Neon tx {tx.neon_tx} from holder')

    def _decode_tx(self, tx: NeonIndexedTxInfo, msg: str) -> bool:
        ix = self.state.sol_neon_ix
        self.state.set_neon_tx(tx)

        if not tx.neon_tx.is_valid():
            holder = self.state.neon_block.find_neon_tx_holder(tx.storage_account, tx.neon_tx.sig, ix)
            if holder is not None:
                self._decode_neon_tx_from_holder(tx, holder)

        if not tx.neon_tx_res.is_valid():
            if decode_neon_tx_result(ix.iter_log(), tx.neon_tx.sig, tx.neon_tx_res):
                tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)

        if tx.neon_tx_res.is_valid() and (tx.status != NeonIndexedTxInfo.Status.DONE):
            return self._decoding_done(tx, msg)

        return self._decoding_success(tx, msg)


class CreateAccount3IxDecoder(DummyIxDecoder):
    _name = 'CreateAccount3'
    _ix_code = 0x28
    _is_deprecated = False

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 20:
            return self._decoding_skip(f'not enough data to get Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[1:][:20].hex()
        pda_account = ix.get_account(2)

        account_info = NeonAccountInfo(
            neon_account, pda_account,
            ix.block_slot, None, ix.sol_sig
        )
        self.state.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create Neon account')


class TxExecFromDataIxDecoder(DummyIxDecoder):
    _name = 'TransactionExecuteFromInstruction'
    _ix_code = 0x1f
    _is_deprecated = False

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 6:
            return self._decoding_skip('no enough data to get Neon tx')

        # 1 byte  - ix
        # 4 bytes - treasury index

        rlp_sig_data = ix.ix_data[5:]
        neon_tx = NeonTxInfo.from_sig_data(rlp_sig_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        neon_tx_sig: str = decode_neon_tx_sig(self.state.sol_neon_ix.iter_log())
        if neon_tx_sig != neon_tx.sig:
            return self._decoding_skip(f'Neon tx hash {neon_tx.sig} != {neon_tx_sig}')

        key = NeonIndexedTxInfo.Key.from_neon_tx_sig(neon_tx_sig, '', [])
        tx = self.state.neon_block.add_neon_tx(key, neon_tx, ix)
        return self._decode_tx(tx, 'Neon tx exec from data')


class BaseTxStepIxDecoder(DummyIxDecoder):
    _first_blocked_account_idx = 6

    def _get_neon_tx(self) -> Optional[NeonIndexedTxInfo]:
        ix = self.state.sol_neon_ix

        # 1 byte  - ix
        # 4 bytes - treasury index
        # 4 bytes - neon step cnt
        # 4 bytes - unique index

        if len(ix.ix_data) < 9:
            self._decoding_skip('no enough data to get Neon step cnt')
            return None
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            self._decoding_skip('no enough accounts')
            return None

        neon_step_cnt = int.from_bytes(ix.ix_data[5:9], 'little')
        ix.set_neon_step_cnt(neon_step_cnt)

        storage_account: str = ix.get_account(0)
        iter_blocked_account: Iterator[str] = ix.iter_account(self._first_blocked_account_idx)

        neon_tx_sig: str = decode_neon_tx_sig(self.state.sol_neon_ix.iter_log())
        if len(neon_tx_sig) == 0:
            self._decoding_skip('no Neon tx hash in logs')
            return None

        key = NeonIndexedTxInfo.Key.from_neon_tx_sig(neon_tx_sig, storage_account, iter_blocked_account)
        block = self.state.neon_block
        return block.find_neon_tx(key, ix) or block.add_neon_tx(key, NeonTxInfo.from_neon_sig(neon_tx_sig), ix)


class TxStepFromDataIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromInstruction'
    _ix_code = 0x20
    _is_deprecated = False

    def execute(self) -> bool:
        tx = self._get_neon_tx()
        if tx is None:
            return False

        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get Neon tx')

        # 1 byte  - ix
        # 4 bytes - treasury index
        # 4 bytes - neon step cnt
        # 4 bytes - unique index

        if not tx.neon_tx.is_valid():
            rlp_sig_data = ix.ix_data[13:]
            neon_tx = NeonTxInfo.from_sig_data(rlp_sig_data)
            if neon_tx.error:
                return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

            if neon_tx.sig != tx.neon_tx.sig:
                return self._decoding_skip(f'Neon tx hash {neon_tx.sig} != {tx.neon_tx.sig}')
            tx.set_neon_tx(neon_tx)

        return self._decode_tx(tx, 'Neon tx step from data')


class TxStepFromAccountIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromAccount'
    _ix_code = 0x21
    _is_deprecated = False

    def execute(self) -> bool:
        tx = self._get_neon_tx()
        if tx is None:
            return False
        return self._decode_tx(tx, 'Neon tx step from account')


class TxStepFromAccountNoChainIdIxDecoder(BaseTxStepIxDecoder):
    _name = 'TransactionStepFromAccountNoChainId'
    _ix_code = 0x22
    _is_deprecated = False

    def execute(self) -> bool:
        tx = self._get_neon_tx()
        if tx is None:
            return False
        return self._decode_tx(tx, 'Neon tx wo chain-id step from account')


class CollectTreasureIxDecoder(DummyIxDecoder):
    _name = 'CollectTreasure'
    _ix_code = 0x1e
    _is_deprecated = False


class CancelWithHashIxDecoder(DummyIxDecoder):
    _name = 'CancelWithHash'
    _ix_code = 0x23
    _is_deprecated = False
    _first_blocked_account_idx = 3

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        # 1 byte   - ix
        # 32 bytes - tx hash
        if len(ix.ix_data) < 33:
            return self._decoding_skip(f'no enough data to get Neon tx hash {len(ix.ix_data)}')

        holder_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(self._first_blocked_account_idx)

        neon_tx_sig: str = '0x' + ix.ix_data[1:33].hex().lower()
        log_tx_sig: str = decode_neon_tx_sig(self.state.sol_neon_ix.iter_log())
        if log_tx_sig != neon_tx_sig:
            return self._decoding_skip(f'Neon tx hash "{log_tx_sig}" != "{neon_tx_sig}"')

        key = NeonIndexedTxInfo.Key.from_neon_tx_sig(neon_tx_sig, holder_account, iter_blocked_account)
        tx = self.state.neon_block.find_neon_tx(key, ix)
        if not tx:
            return self._decoding_skip(f'cannot find tx in the holder {holder_account}')

        gas_used = decode_cancel_gas(self.state.sol_neon_ix.iter_log())
        tx.neon_tx_res.fill_result(status='0x0', gas_used=hex(gas_used), return_value='')
        tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
        return self._decode_tx(tx, 'cancel Neon tx')


class CreateHolderAccountIx(DummyIxDecoder):
    _name = 'CreateHolderAccount'
    _ix_code = 0x24
    _is_deprecated = False


class DeleteHolderAccountIx(DummyIxDecoder):
    _name = 'DeleteHolderAccount'
    _ix_code = 0x25
    _is_deprecated = False


class WriteHolderAccountIx(DummyIxDecoder):
    _name = 'WriteHolderAccount'
    _ix_code = 0x26
    _is_deprecated = False

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < 1:
            return self._decoding_skip(f'no enough accounts {ix.account_cnt}')

        # 1  byte  - ix
        # 32 bytes - tx hash
        # 8  bytes - offset

        # No enough bytes to get length of chunk
        if len(ix.ix_data) < 42:
            return self._decoding_skip(f'no enough data to get Neon tx data chunk {len(ix.ix_data)}')

        data = ix.ix_data[41:]
        chunk = NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix.ix_data[33:41], 'little'),
            length=len(data),
            data=data,
        )

        neon_tx_sig: str = '0x' + ix.ix_data[1:33].hex().lower()
        tx_sig: str = decode_neon_tx_sig(self.state.sol_neon_ix.iter_log())
        if tx_sig != neon_tx_sig:
            return self._decoding_skip(f'Neon tx hash "{tx_sig}" != "{neon_tx_sig}"')

        block = self.state.neon_block
        account = ix.get_account(0)

        key = NeonIndexedTxInfo.Key.from_neon_tx_sig(neon_tx_sig, account, [])
        tx = block.find_neon_tx(key, ix)
        if (tx is not None) and tx.neon_tx.is_valid():
            tx.add_sol_neon_ix(ix)
            return self._decoding_success(tx, f'add Neon tx data chunk {chunk}')

        holder = block.find_neon_tx_holder(account, tx_sig, ix) or block.add_neon_tx_holder(account, tx_sig, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        self._decoding_success(holder, f'add Neon tx data chunk {chunk}')

        # decode neon tx from holder account
        if tx is not None:
            self._decode_neon_tx_from_holder(tx, holder)

        return True


class Deposit3IxDecoder(DummyIxDecoder):
    _name = 'Deposit3'
    _ix_code = 0x27
    _is_deprecated = False


def get_neon_ix_decoder_list() -> List[Type[DummyIxDecoder]]:
    return [
        CreateAccount3IxDecoder,
        CollectTreasureIxDecoder,
        TxExecFromDataIxDecoder,
        TxStepFromDataIxDecoder,
        TxStepFromAccountIxDecoder,
        TxStepFromAccountNoChainIdIxDecoder,
        CancelWithHashIxDecoder,
        CreateHolderAccountIx,
        DeleteHolderAccountIx,
        WriteHolderAccountIx,
        Deposit3IxDecoder,
    ]
