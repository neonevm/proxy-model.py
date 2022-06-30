from __future__ import annotations

import time

from typing import Iterator, List, Optional, Dict, Tuple, Any, cast
from logged_groups import logged_group, logging_context
from solana.system_program import SYS_PROGRAM_ID
from solana.publickey import PublicKey

from ..indexer.i_indexer_status import IIndexerStatus
from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.solana_tx_meta_collector import SolTxMetaCollector
from ..indexer.solana_tx_meta_collector import FinalizedSolTxMetaCollector, ConfirmedSolTxMetaCollector
from ..indexer.utils import MetricsToLogger
from ..indexer.canceller import Canceller
from ..indexer.indexed_objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonAccountInfo
from ..indexer.indexed_objects import  NeonIndexedBlockInfo, NeonIndexedBlockDict

from ..common_neon.data import NeonTxStatData
from ..common_neon.utils import NeonTxInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_receipt_parser import SolReceiptParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxReceiptInfo, SolNeonIxReceiptInfo

from ..common_neon.environment_data import CANCEL_TIMEOUT


class SolBlockRange:
    def __init__(self, collector: SolTxMetaCollector, start_block_slot: int, neon_block: Optional[NeonIndexedBlockInfo]):
        self._start_block_slot = start_block_slot
        self._sol_tx_meta_collector = collector
        self._is_neon_block_finalized = False
        self._stop_block_slot = 0
        self._neon_block_cnt = 0
        self._neon_block = neon_block

    def clone(self, collector: SolTxMetaCollector) -> SolBlockRange:
        block_state = SolBlockRange(collector, self._stop_block_slot + 1, self._neon_block)
        block_state._neon_block_cnt = self._neon_block_cnt
        block_state._is_neon_block_finalized = self._is_neon_block_finalized
        return block_state

    def set_stop_block_slot(self, block_slot: int) -> None:
        self._stop_block_slot = block_slot

    def set_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        self._neon_block_cnt += 1
        self._neon_block = neon_block
        self._is_neon_block_finalized = self._sol_tx_meta_collector.is_finalized

    @property
    def start_block_slot(self) -> int:
        return self._start_block_slot

    @property
    def stop_block_slot(self) -> int:
        return self._stop_block_slot

    @property
    def neon_block_cnt(self) -> int:
        return self._neon_block_cnt

    @property
    def commitment(self) -> str:
        return self._sol_tx_meta_collector.commitment

    @property
    def is_neon_block_finalized(self) -> bool:
        return self._is_neon_block_finalized

    def has_neon_block(self) -> bool:
        return self._neon_block is not None

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        return cast(NeonIndexedBlockInfo, self._neon_block)

    def iter_sol_tx_meta(self) -> Iterator[SolTxMetaInfo]:
        return self._sol_tx_meta_collector.iter_tx_meta(self.stop_block_slot, self.start_block_slot)


class SolNeonTxDecoderState:
    def __init__(self, sol_tx_meta: SolTxMetaInfo, neon_block: NeonIndexedBlockInfo):
        self._sol_tx = SolTxReceiptInfo(sol_tx_meta)
        self._sol_neon_ix: Optional[SolNeonIxReceiptInfo] = None
        self._neon_block = neon_block
        self._neon_tx_key_list: List[Optional[NeonIndexedTxInfo.Key]] = []

    @property
    def sol_tx(self) -> SolTxReceiptInfo:
        return self._sol_tx

    @property
    def sol_neon_ix(self) -> SolNeonIxReceiptInfo:
        assert self._sol_neon_ix is not None
        return cast(SolNeonIxReceiptInfo, self._sol_neon_ix)

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        return self._neon_block

    def has_neon_tx_key(self) -> bool:
        return (len(self._neon_tx_key_list) > 1) and (self._neon_tx_key_list[-2] is not None)

    @property
    def neon_tx_key(self) -> NeonIndexedTxInfo.Key:
        assert self.has_neon_tx_key()
        return cast(NeonIndexedTxInfo.Key, self._neon_tx_key_list[-2])

    def set_neon_tx_key(self, key: NeonIndexedTxInfo.Key) -> None:
        self._neon_tx_key_list[-1] = key

    def iter_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        for self._sol_neon_ix in self._sol_tx.iter_ix():
            if len(self._neon_tx_key_list) < self._sol_neon_ix.level:
                self._neon_tx_key_list.append(None)
            elif len(self._neon_tx_key_list) > self._sol_neon_ix.level:
                self._neon_tx_key_list.pop()
            else:
                self._neon_tx_key_list[-1] = None
            yield self._sol_neon_ix


@logged_group("neon.Indexer")
class DummyIxDecoder:
    _name = 'Unknown'

    def __init__(self, state: SolNeonTxDecoderState):
        self._state = state
        self.debug(f'{self} ...')

    def __str__(self):
        return f'{self._name} {self.sol_neon_ix}'

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        ix = self.sol_neon_ix
        return self._decoding_skip(f'no logic to decode the instruction {self}({ix.ix_data.hex()[:8]})')

    @property
    def state(self) -> SolNeonTxDecoderState:
        return self._state

    @property
    def sol_tx(self) -> SolTxReceiptInfo:
        return self.state.sol_tx

    @property
    def sol_neon_ix(self) -> SolNeonIxReceiptInfo:
        return self.state.sol_neon_ix

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        return self._state.neon_block

    @property
    def neon_tx(self) -> NeonIndexedTxInfo:
        key = self._state.neon_tx_key
        return self._state.neon_block.get_neon_tx(key, self.sol_neon_ix)

    def has_neon_tx(self) -> bool:
        return self._state.has_neon_tx_key()

    def _init_neon_tx_from_holder(self, holder_account: str,
                                  storage_account: str,
                                  iter_blocked_account: Iterator[str]) -> Optional[NeonIndexedTxInfo]:
        block = self.neon_block
        ix = self.sol_neon_ix

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = block.get_neon_tx(key, ix)
        if tx is not None:
            return tx

        holder = block.get_neon_holder(holder_account, ix)
        if holder is None:
            self._decoding_skip(f'no holder account {holder_account}')
            return None

        rlp_sign = holder.data[0:65]
        rlp_len = int.from_bytes(holder.data[65:73], 'little')
        rlp_endpos = 73 + rlp_len
        rlp_data = holder.data[73:rlp_endpos]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=bytes(rlp_data))
        if neon_tx.error:
            self.warning(f'Neon tx rlp error: {neon_tx.error}')
            return None

        tx = block.add_neon_tx(key, neon_tx, ix)
        tx.set_holder_account(holder)
        self._decoding_done(holder, f'init {tx.neon_tx} from holder')
        return tx

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
        self.debug(f'decoding done: {msg} - {indexed_obj}')
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            self.neon_block.done_neon_tx(indexed_obj, self.sol_neon_ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            self.neon_block.done_neon_holder(indexed_obj, self.sol_neon_ix)
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
        self.warning(f'decoding fail: {reason} - {indexed_obj}')

        if isinstance(indexed_obj, NeonIndexedTxInfo):
            self.neon_block.fail_neon_tx(indexed_obj, self.sol_neon_ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            self.neon_block.fail_neon_holder(indexed_obj, self.sol_neon_ix)
        return False

    def _decode_tx(self, tx: NeonIndexedTxInfo, msg: str) -> bool:
        self.state.set_neon_tx_key(tx.key)
        if tx.neon_tx_res.is_valid() and (tx.status != NeonIndexedTxInfo.Status.DONE):
            return self._decoding_done(tx, msg)
        return self._decoding_success(tx, msg)


class WriteIxDecoder(DummyIxDecoder):
    _name = 'Write'

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        ix_data = self.sol_neon_ix.ix_data
        # No enough bytes to get length of chunk
        if len(ix_data) < 17:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[4:8], 'little'),
            length=int.from_bytes(ix_data[8:16], 'little'),
            data=ix_data[16:],
        )

    def execute(self) -> bool:
        chunk = self._decode_data_chunk()
        if not chunk.is_valid():
            return self._decoding_skip(f'bad data chunk {chunk}')

        ix = self.sol_neon_ix
        if ix.account_cnt < 1:
            return self._decoding_skip(f'no enough accounts {ix.account_cnt}')

        account = ix.get_account(0)
        block = self.neon_block
        holder = block.get_neon_holder(account, ix) or block.add_neon_holder(account, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        return self._decoding_success(holder, f'add chunk {chunk}')


class WriteWithHolderIxDecoder(WriteIxDecoder):
    _name = 'WriteWithHolder'

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        # No enough bytes to get length of chunk
        ix_data = self.sol_neon_ix.ix_data
        if len(ix_data) < 22:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[9:13], 'little'),
            length=int.from_bytes(ix_data[13:21], 'little'),
            data=self.sol_neon_ix.ix_data[21:]
        )


class CreateAccountIxDecoder(DummyIxDecoder):
    _name = 'CreateAccount'

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        if len(ix.ix_data) < 41:
            return self._decoding_skip(f'not enough data to get the Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[8+8+4:][:20].hex()
        pda_account = ix.get_account(1)
        code_account = ix.get_account(3)
        if code_account == str(SYS_PROGRAM_ID) or code_account == '':
            code_account = None

        account_info = NeonAccountInfo(
            neon_account, pda_account, code_account,
            ix.block_slot, None, ix.sol_sign
        )

        self.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create account')


class CreateAccount2IxDecoder(DummyIxDecoder):
    _name = 'CreateAccount2'

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        if len(ix.ix_data) < 21:
            return self._decoding_skip(f'not enough data to get the Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[1:][:20].hex()
        pda_account = ix.get_account(2)
        code_account = ix.get_account(3)
        if code_account == '':
            code_account = None

        account_info = NeonAccountInfo(
            neon_account, pda_account, code_account,
            ix.block_slot, None, ix.sol_sign
        )
        self.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create account')


class ResizeStorageAccountIxDecoder(DummyIxDecoder):
    _name = 'ResizeStorageAccount'

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        pda_account = ix.get_account(0)
        code_account = ix.get_account(2)

        account_info = NeonAccountInfo(
            None, pda_account, code_account,
            ix.block_slot, None, ix.sol_sign
        )
        self.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'resize of account')


class CallFromRawIxDecoder(DummyIxDecoder):
    _name = 'CallFromRaw'

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        if len(ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sign = ix.ix_data[25:90]
        rlp_data = ix.ix_data[90:]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        key = NeonIndexedTxInfo.Key.from_ix(ix)
        tx = self.neon_block.add_neon_tx(key, neon_tx, ix)
        return self._decode_tx(tx, 'call raw tx')


class OnResultIxDecoder(DummyIxDecoder):
    _name = 'OnResult'

    def execute(self) -> bool:
        if not self.has_neon_tx():
            return self._decoding_skip('no transaction to add result')

        ix = self.sol_neon_ix
        tx = self.neon_tx
        log = ix.ix_data

        status = '0x1' if log[1] < 0xd0 else '0x0'
        gas_used = hex(int.from_bytes(log[2:10], 'little'))
        return_value = log[10:].hex()

        tx.neon_tx_res.set_result(ix, status, gas_used, return_value)
        return self._decode_tx(tx, 'tx result')


class OnEventIxDecoder(DummyIxDecoder):
    _name = 'OnEvent'

    def execute(self) -> bool:
        if not self.has_neon_tx():
            return self._decoding_skip('no transaction to add events')

        ix = self.sol_neon_ix
        tx = self.neon_tx
        log = ix.ix_data

        address = log[1:21]
        count_topics = int().from_bytes(log[21:29], 'little')
        topics = []
        pos = 29
        for _ in range(count_topics):
            topic_bin = log[pos:pos + 32]
            topics.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]

        tx_log_idx = len(tx.neon_tx_res.logs)
        rec = {
            'address': '0x' + address.hex(),
            'topics': topics,
            'data': '0x' + data.hex(),
            'transactionHash': tx.neon_tx.sign,
            'transactionLogIndex': hex(tx_log_idx),
            # 'logIndex': hex(tx_log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        tx.neon_tx_res.append_record(rec)
        return self._decode_tx(tx, 'tx event')


class PartialCallIxDecoder(DummyIxDecoder):
    _name = 'PartialCallFromRawEthereumTX'

    def execute(self) -> bool:
        first_block_account_idx = 7

        ix = self.sol_neon_ix
        if ix.account_cnt < first_block_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 100:
            return self._decoding_skip('no enough data to get arguments')

        rlp_sign = ix.ix_data[33:98]
        rlp_data = ix.ix_data[98:]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_block_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = self.neon_block.get_neon_tx(key, ix)
        if (tx is not None) and (tx.neon_tx.sign != neon_tx.sign):
            self._decoding_fail(tx, f'Neon tx sign {neon_tx.sign} != {tx.neon_tx.sign}')
            tx = None

        if tx is None:
            tx = self.neon_block.add_neon_tx(key, neon_tx, ix)

        step_count = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_count)
        return self._decode_tx(tx, 'partial tx call')


class PartialCallV02IxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallFromRawEthereumTXv02'


class PartialCallOrContinueIxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallOrContinueFromRawEthereumTX'


class ContinueIxDecoder(DummyIxDecoder):
    _name = 'Continue'
    _first_block_account_idx = 5

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        if ix.account_cnt < self._first_block_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(self._first_block_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = self.neon_block.get_neon_tx(key, ix)
        if not tx:
            return self._decode_skip(f'no transaction at the storage {storage_account}')

        step_count = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_count)
        return self.decode_tx(tx, 'continue tx call')


class ContinueV02IxDecoder(ContinueIxDecoder):
    _name = 'ContinueV02'
    _first_block_account_idx = 6


class ExecuteTrxFromAccountIxDecoder(DummyIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterative'
    _first_block_account_idx = 5

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        if ix.account_cnt < self._first_block_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = ix.get_account(0)
        storage_account = ix.get_account(1)
        iter_blocked_account = ix.iter_account(self._first_block_account_idx)

        tx = self._init_neon_tx_from_holder(holder_account, storage_account, iter_blocked_account)
        if not tx:
            return self._decoding_skip(f'fail to init storage {storage_account} from holder {holder_account}')

        step_count = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_count)
        return self._decode_tx(tx, 'execute/continue tx from holder')


class ExecuteTrxFromAccountV02IxDecoder(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeV02'
    _first_block_account_idx = 7


class ExecuteOrContinueIxParser(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinue'
    _first_block_account_idx = 7


class ExecuteOrContinueNoChainIdIxParser(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'
    _first_block_account_idx = 7


class CancelIxDecoder(DummyIxDecoder):
    _name = 'Cancel'

    def execute(self) -> bool:
        ix = self.sol_neon_ix
        first_block_account_idx = 3
        if ix.account_cnt < first_block_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_block_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = self.neon_block.get_neon_tx(key, ix)
        if not tx:
            return self._decoding_skip(f'cannot find tx in the storage {storage_account}')

        # TODO: get used gas
        tx.neon_tx_res.set_result(ix, status="0x0", gas_used='0x0', return_value=bytes())
        return self._decode_tx(tx, 'cancel tx')


class CancelV02IxDecoder(CancelIxDecoder):
    _name = 'CancelV02'


class ERC20CreateTokenAccountIxDecoder(DummyIxDecoder):
    _name = 'ERC20CreateTokenAccount'


class FinalizeIxDecode(DummyIxDecoder):
    _name = 'Finalize'


class CallIxDecoder(DummyIxDecoder):
    _name = 'Call'


class CreateAccountWithSeedIxDecoder(DummyIxDecoder):
    _name = 'CreateAccountWithSeed'


class DepositIxDecoder(DummyIxDecoder):
    _name = 'Deposit'


class MigrateAccountIxDecoder(DummyIxDecoder):
    _name = 'MigrateAccount'


class UpdateValidsTableIxDecoder(DummyIxDecoder):
    _name = 'UpdateValidsTable'


@logged_group("neon.Indexer")
class Indexer(IndexerBase):
    def __init__(self, solana_url, indexer_status: IIndexerStatus):
        solana = SolanaInteractor(solana_url)
        self._db = IndexerDB()
        last_known_block_slot = self._db.get_min_receipt_block_slot()
        super().__init__(solana, last_known_block_slot)
        self._canceller = Canceller(solana)
        self._blocked_storage_dict: Dict[str, Tuple[int, List[Tuple[bool, str]]]] = {}
        self._counted_logger = MetricsToLogger()
        self._status = indexer_status
        self._finalized_sol_tx_collector = FinalizedSolTxMetaCollector(self._last_slot, self._solana)
        self._confirmed_sol_tx_collector = ConfirmedSolTxMetaCollector(self._solana)
        self._neon_block_dict = NeonIndexedBlockDict()

        self._sol_neon_ix_decoder_dict: Dict[int, Any] = {
            0x00: WriteIxDecoder,
            0x01: FinalizeIxDecode,
            0x02: CreateAccountIxDecoder,
            0x03: CallIxDecoder,
            0x04: CreateAccountWithSeedIxDecoder,
            0x05: CallFromRawIxDecoder,
            0x06: OnResultIxDecoder,
            0x07: OnEventIxDecoder,
            0x09: PartialCallIxDecoder,
            0x0a: ContinueIxDecoder,
            0x0b: ExecuteTrxFromAccountIxDecoder,
            0x0c: CancelIxDecoder,
            0x0d: PartialCallOrContinueIxDecoder,
            0x0e: ExecuteOrContinueIxParser,
            0x0f: ERC20CreateTokenAccountIxDecoder,
            0x11: ResizeStorageAccountIxDecoder,
            0x12: WriteWithHolderIxDecoder,
            0x13: PartialCallV02IxDecoder,
            0x14: ContinueV02IxDecoder,
            0x15: CancelV02IxDecoder,
            0x16: ExecuteTrxFromAccountV02IxDecoder,
            0x17: UpdateValidsTableIxDecoder,
            0x18: CreateAccount2IxDecoder,
            0x19: DepositIxDecoder,
            0x1a: MigrateAccountIxDecoder,
            0x1b: ExecuteOrContinueNoChainIdIxParser
        }

    def _cancel_old_neon_txs(self, neon_block: NeonIndexedBlockInfo) -> None:
        for tx in neon_block.iter_neon_tx():
            if (tx.storage_account != '') and (abs(tx.block_slot - neon_block.block_slot) > CANCEL_TIMEOUT):
                self._cancel_neon_tx(tx)

        self._canceller.unlock_accounts(self._blocked_storage_dict)
        self._blocked_storage_dict.clear()

    def _cancel_neon_tx(self, tx: NeonIndexedTxInfo) -> bool:
        # We've already indexed the transaction
        if tx.neon_tx_res.is_valid():
            return True

        # We've already sent Cancel and are waiting for receipt
        if tx.status != NeonIndexedTxInfo.Status.IN_PROGRESS:
            return True

        if not tx.blocked_account_cnt:
            self.warning(f"Transaction {tx.neon_tx} hasn't blocked accounts.")
            return False

        storage = self._solana.get_storage_account_info(PublicKey(tx.storage_account))
        if not storage:
            self.warning(f'Storage {tx.storage_account} for tx {tx.neon_tx.sign} is empty')
            return False

        if storage.caller != tx.neon_tx.addr[2:]:
            self.warning(f'Storage {tx.storage_account} for tx {tx.neon_tx.sign} has another caller: ' +
                         f'{storage.caller} != {tx.neon_tx.addr[2:]}')
            return False

        tx_nonce = int(tx.neon_tx.nonce[2:], 16)
        if storage.nonce != tx_nonce:
            self.warning(f'Storage {tx.storage_account} for tx {tx.neon_tx.sign} has another nonce: ' +
                         f'{storage.nonce} != {tx_nonce}')
            return False

        if not len(storage.account_list):
            self.warning(f'Storage {tx.storage_account} for tx {tx.neon_tx.sign} has empty account list.')
            return False

        if len(storage.account_list) != tx.blocked_account_cnt:
            self.warning(f'Transaction {tx.neon_tx} has another list of accounts than storage.')
            return False

        for (writable, account), (idx, tx_account) in zip(storage.account_list, enumerate(tx.iter_blocked_account())):
            if account != tx_account:
                self.warning(f'Transaction {tx.neon_tx} has another list of accounts than storage: ' +
                             f'{idx}: {account} != {tx_account}')
                return False

        if tx.storage_account in self._blocked_storage_dict:
            self.warning(f'Transaction {tx.neon_tx} uses the storage account {tx.storage_account}' +
                         'which is already in the list on unlock')
            return False

        self.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}, {storage.account_list}')
        self._blocked_storage_dict[tx.storage_account] = (storage.nonce, storage.account_list)
        tx.set_status(NeonIndexedTxInfo.Status.CANCELED)
        return True

    def _complete_neon_block(self, sol_block_range: SolBlockRange, sol_tx_meta: SolTxMetaInfo) -> None:
        if not sol_block_range.has_neon_block():
            return
        neon_block = sol_block_range.neon_block
        is_neon_block_finalized = sol_block_range.is_neon_block_finalized

        self._submit_status()

        if not neon_block.is_completed:
            self._db.submit_block(neon_block, is_neon_block_finalized)
            neon_block.complete_block(sol_tx_meta)
        elif is_neon_block_finalized:
            # the confirmed block becomes finalized
            self._db.finalize_block(neon_block)
            # send status only for new finalized blocks
            self._submit_block_status(neon_block)

        # Add block to cache only after indexing and applying last changes to DB
        self._neon_block_dict.add_neon_block(neon_block, is_neon_block_finalized, sol_tx_meta)

    def _submit_block_status(self, neon_block: NeonIndexedBlockInfo):
        if not neon_block.is_finalized:
            for tx in neon_block.iter_done_neon_tx():
                # TODO: check operator of tx
                self._submit_neon_tx_status(tx)

    def _submit_status(self) -> None:
        self._status.on_db_status(self._db.status())
        self._status.on_solana_rpc_status(self._solana.is_healthy())

    def _send_neon_tx_status(self, tx: NeonIndexedTxInfo) -> None:
        neon_tx_hash = tx.neon_tx.sign
        neon_income = int(tx.neon_tx_res.gas_used, 0) * int(tx.neon_tx.gas_price, 0)  # TODO: get gas usage from ixs
        if tx.holder_account != '':
            tx_type = 'holder'
        elif tx.storage_account != '':
            tx_type = 'iterative'
        else:
            tx_type = 'single'
        is_canceled = tx.neon_tx_res.status == '0x0'
        sol_spent = tx.sol_spent
        neon_tx_stat_data = NeonTxStatData(neon_tx_hash, sol_spent, neon_income, tx_type, is_canceled)
        for ix in tx.iter_sol_neon_ix():
            neon_tx_stat_data.neon_step_cnt += ix.neon_step_cnt
            neon_tx_stat_data.bpf_cycle_cnt += ix.used_bpf_cycle_cnt

        self._status.on_neon_tx_result(neon_tx_stat_data)

    def _locate_neon_block(self, sol_tx_meta: SolTxMetaInfo, sol_block_range: SolBlockRange) -> None:
        # The same block
        if sol_block_range.has_neon_block():
            if sol_block_range.neon_block.block_slot == sol_tx_meta.block_slot:
                return
            self._complete_neon_block(sol_block_range, sol_tx_meta)

        neon_block = self._neon_block_dict.get_neon_block(sol_tx_meta.block_slot)
        if neon_block:
            pass  # the parsed block from cache
        else:
            # a new block from network
            sol_block = self._solana.get_block_info(sol_tx_meta.block_slot, sol_block_range.commitment)
            if sol_block_range.has_neon_block():
                neon_block = sol_block_range.neon_block.clone(sol_block)
            else:
                neon_block = NeonIndexedBlockInfo(sol_block)
        sol_block_range.set_neon_block(neon_block)

    def _run_sol_tx_collector(self, sol_block_range: SolBlockRange) -> None:
        sol_block_range.set_stop_block_slot(self._solana.get_slot(sol_block_range.commitment))
        for sol_tx_meta in sol_block_range.iter_sol_tx_meta():
            self._locate_neon_block(sol_tx_meta, sol_block_range)
            neon_block = sol_block_range.neon_block
            if neon_block.is_completed:
                self.debug(f'ignore parsed tx {sol_tx_meta}')
                continue

            sol_tx_state = SolNeonTxDecoderState(sol_tx_meta=sol_tx_meta, neon_block=neon_block)
            neon_block.add_sol_tx_cost(sol_tx_state.sol_tx.sol_cost)

            if SolReceiptParser(sol_tx_meta.tx).check_if_error():
                self.debug(f'ignore failed tx {sol_tx_meta}')
                continue

            for sol_neon_ix in sol_tx_state.iter_ix():
                SolNeonIxDecoder = (self._sol_neon_ix_decoder_dict.get(sol_neon_ix.program_ix) or DummyIxDecoder)
                with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                    SolNeonIxDecoder(sol_tx_state).execute()

    def process_functions(self):
        start_time = time.time()

        start_block_slot = self._finalized_sol_tx_collector.last_block_slot + 1
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if finalized_neon_block is not None:
            start_block_slot = finalized_neon_block.block_slot + 1

        sol_block_range = SolBlockRange(self._finalized_sol_tx_collector, start_block_slot, finalized_neon_block)
        self._run_sol_tx_collector(sol_block_range)

        # If there were a lot of transactions in finalized state,
        # the top of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # on next iteration there are will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_slot(self._finalized_sol_tx_collector.commitment)
        has_confirmed_blocks = (finalized_block_slot - self._finalized_sol_tx_collector.last_block_slot) < 3
        if has_confirmed_blocks:
            sol_block_range = sol_block_range.clone(self._confirmed_sol_tx_collector)
            self._run_sol_tx_collector(sol_block_range)

        if sol_block_range.neon_block_cnt > 0:
            sol_tx_meta = SolTxMetaInfo(sol_block_range.stop_block_slot, '-END-OF-BLOCK-RANGE-', {})
            self._complete_neon_block(sol_block_range, sol_tx_meta)
            if has_confirmed_blocks:
                self._cancel_old_neon_txs(sol_block_range.neon_block)

        self._print_stat(start_time, start_block_slot, sol_block_range.stop_block_slot)

    def _print_stat(self, start_time: float, start_block_slot: int, stop_block_slot: int) -> None:
        stat = self._neon_block_dict.stat
        if (start_block_slot != stop_block_slot) and (stat.min_block_slot != 0):
            self._db.set_min_receipt_slot(stat.min_block_slot)

        process_receipts_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self._counted_logger.print(
            self.debug,
            list_value_dict={
                'process receipts ms': process_receipts_ms,
                'processed block slots': stop_block_slot - start_block_slot
            },
            latest_value_dict={
                'neon blocks': stat.neon_block_cnt,
                'neon holders': stat.neon_holder_cnt,
                'neon transactions': stat.neon_tx_cnt,
                'solana instructions': stat.sol_neon_ix_cnt,
                'indexed block slot': stop_block_slot,
                'min used block slot': stat.min_block_slot
            }
        )
