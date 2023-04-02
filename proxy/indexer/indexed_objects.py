from __future__ import annotations

import copy
import time
import logging
import dataclasses

from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, List, Optional, Dict, Set, Deque, Tuple, cast

from ..common_neon.config import Config
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolNeonIxReceiptInfo, SolTxCostInfo, SolTxReceiptInfo
from ..common_neon.evm_log_decoder import NeonLogTxEvent
from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxReceiptInfo, SolBlockInfo, str_fmt_object
from ..indexer.solana_tx_meta_collector import SolTxMetaCollector

from ..statistic.data import NeonTxStatData


LOG = logging.getLogger(__name__)


class BaseNeonIndexedObjInfo:
    def __init__(self):
        self._start_block_slot = 0
        self._last_block_slot = 0

    def __str__(self) -> str:
        return str_fmt_object(self, False)

    @property
    def start_block_slot(self) -> int:
        return self._start_block_slot

    @property
    def last_block_slot(self) -> int:
        return self._last_block_slot

    def _set_start_block_slot(self, block_slot: int) -> None:
        if self._start_block_slot == 0 or block_slot < self._start_block_slot:
            self._start_block_slot = block_slot

    def _set_last_block_slot(self, block_slot: int) -> None:
        if block_slot > self._last_block_slot:
            self._last_block_slot = block_slot

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._set_start_block_slot(sol_neon_ix.block_slot)
        self._set_last_block_slot(sol_neon_ix.block_slot)


@dataclass(frozen=True)
class NeonAccountInfo:
    neon_address: Optional[str]
    pda_address: str
    block_slot: int
    code: Optional[str]
    sol_sig: Optional[str]


class NeonIndexedHolderInfo(BaseNeonIndexedObjInfo):
    @dataclass(frozen=True)
    class DataChunk:
        offset: int
        length: int
        data: bytes

        _str: str = ''

        @staticmethod
        def init_empty() -> NeonIndexedHolderInfo.DataChunk:
            return NeonIndexedHolderInfo.DataChunk(offset=0, length=0, data=bytes())

        def __str__(self):
            if self._str == '':
                _str = str_fmt_object(self)
                object.__setattr__(self, '_str', _str)
            return self._str

        def is_valid(self) -> bool:
            return (self.length > 0) and (len(self.data) == self.length)

    class Key:
        def __init__(self, account: str, neon_tx_sig: str) -> None:
            self._account = account
            if neon_tx_sig[:2] == '0x':
                neon_tx_sig = neon_tx_sig[2:]
            self._neon_tx_sig = neon_tx_sig.lower()
            self._value = f'{account}:{self._neon_tx_sig}'

        def __str__(self) -> str:
            return self._value

        @property
        def account(self) -> str:
            return self._account

        @property
        def neon_tx_sig(self) -> str:
            return self._neon_tx_sig

        @property
        def value(self) -> str:
            return self._value

    def __init__(self, key: NeonIndexedHolderInfo.Key) -> None:
        super().__init__()
        self._key = key
        self._data_size = 0
        self._data = bytes()

    @property
    def key(self) -> str:
        return self._key.value

    @property
    def neon_tx_sig(self) -> str:
        return self._key.neon_tx_sig

    @property
    def account(self) -> str:
        return self._key.account

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def data_size(self) -> int:
        return self._data_size

    def add_data_chunk(self, chunk: DataChunk) -> None:
        end_pos = chunk.offset + chunk.length
        data_len = len(self._data)
        if end_pos > data_len:
            self._data += bytes(end_pos - data_len)

        self._data = self._data[:chunk.offset] + chunk.data + self._data[end_pos:]
        self._data_size += chunk.length


class NeonIndexedTxInfo(BaseNeonIndexedObjInfo):
    class Status(Enum):
        InProgress = 1
        Canceled = 2
        Done = 3

    class Type(Enum):
        Unknown = 0
        Single = 1
        SingleFromAccount = 2
        IterFromData = 3
        IterFromAccount = 4
        IterFromAccountWoChainId = 5

    class Key:
        def __init__(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
            neon_tx_sig = sol_neon_ix.neon_tx_sig
            if neon_tx_sig[:2] == '0x':
                neon_tx_sig = neon_tx_sig[2:]
            self._value = neon_tx_sig.lower()

        def __str__(self) -> str:
            return self._value

        def is_empty(self) -> bool:
            return self._value == ''

        @property
        def value(self) -> str:
            return self._value

    def __init__(self, tx_type: NeonIndexedTxInfo.Type, key: NeonIndexedTxInfo.Key, neon_tx: NeonTxInfo,
                 storage_account: str, iter_blocked_account: Iterator[str]):
        super().__init__()
        assert not key.is_empty()

        self._key = key
        self._neon_receipt = NeonTxReceiptInfo(neon_tx, NeonTxResultInfo())
        self._tx_type = tx_type
        self._storage_account = storage_account
        self._blocked_account_list = list(iter_blocked_account)
        self._status = NeonIndexedTxInfo.Status.InProgress
        self._is_canceled = False
        self._neon_event_list: List[NeonLogTxEvent] = list()

    @property
    def storage_account(self) -> str:
        return self._storage_account

    @property
    def blocked_account_cnt(self) -> int:
        return len(self._blocked_account_list)

    def iter_blocked_account(self) -> Iterator[str]:
        return iter(self._blocked_account_list)

    @property
    def key(self) -> str:
        return self._key.value

    @property
    def tx_type(self) -> NeonIndexedTxInfo.Type:
        return self._tx_type

    @property
    def neon_tx(self) -> NeonTxInfo:
        return self._neon_receipt.neon_tx

    @property
    def neon_tx_res(self) -> NeonTxResultInfo:
        return self._neon_receipt.neon_tx_res

    @property
    def status(self) -> NeonIndexedTxInfo.Status:
        return self._status

    def set_canceled(self, value: bool) -> None:
        self._is_canceled = value

    @property
    def is_canceled(self) -> bool:
        return self._is_canceled

    def set_holder_account(self, holder: NeonIndexedHolderInfo, neon_tx: NeonTxInfo) -> None:
        self.set_neon_tx(neon_tx)
        self._set_start_block_slot(holder.start_block_slot)
        self._set_last_block_slot(holder.last_block_slot)

    def set_status(self, value: NeonIndexedTxInfo.Status, block_slot: int) -> None:
        self._status = value
        self._set_last_block_slot(block_slot)

    def set_neon_tx(self, neon_tx: NeonTxInfo) -> None:
        assert not self._neon_receipt.neon_tx.is_valid()
        assert neon_tx.is_valid()
        self._neon_receipt.set_neon_tx(neon_tx)

    def add_neon_event(self, event: NeonLogTxEvent) -> None:
        self._neon_event_list.append(event)

    def _iter_reversed_neon_event_list(self) -> Iterator[NeonLogTxEvent]:
        if len(self._neon_event_list) == 0:
            return  # no events

        # old type of event without enter/exit(revert) information ...
        if self._neon_event_list[0].total_gas_used == 0:
            neon_event_list = self._neon_event_list
        else:
            # sort events by total_gas_used, because its value increases each iteration
            neon_event_list = sorted(self._neon_event_list, key=lambda x: x.total_gas_used, reverse=False)

        for event in reversed(neon_event_list):
            yield event

    @property
    def len_neon_event_list(self) -> int:
        return len(self._neon_event_list)

    def complete_event_list(self) -> None:
        event_list_len = len(self._neon_event_list)
        if (not self.neon_tx_res.is_valid()) or (len(self.neon_tx_res.log_list) > 0) or (event_list_len == 0):
            return

        neon_event_list: List[NeonLogTxEvent] = list()
        current_level = 1
        reverted_level = -1
        current_order = event_list_len
        is_failed = (self.neon_tx_res.status == '0x0')

        for event in self._iter_reversed_neon_event_list():
            if event.is_reverted:
                is_reverted = True
                is_hidden = True
            else:
                if event.is_start_event_type():
                    current_level -= 1
                    if (reverted_level != -1) and (current_level < reverted_level):
                        reverted_level = -1
                elif event.is_exit_event_type():
                    current_level += 1
                    if (event.event_type == NeonLogTxEvent.Type.ExitRevert) and (reverted_level == -1):
                        reverted_level = current_level

                is_reverted = (reverted_level != -1) or is_failed
                is_hidden = (event.is_hidden or is_reverted)

            neon_event_list.append(dataclasses.replace(
                event,
                is_hidden=is_hidden, is_reverted=is_reverted, event_level=current_level, event_order=current_order
            ))
            current_order -= 1

        for event in reversed(neon_event_list):
            self.neon_tx_res.add_event(event)


class NeonIndexedBlockInfo:
    def __init__(self, history_block_deque: Deque[SolBlockInfo]):
        self._sol_block = history_block_deque[-1]
        self._history_block_deque = history_block_deque
        self._is_completed = False

        self._neon_holder_dict: Dict[str, NeonIndexedHolderInfo] = dict()
        self._neon_tx_dict: Dict[str, NeonIndexedTxInfo] = dict()

        self._done_neon_tx_list: List[NeonIndexedTxInfo] = list()

        self._sol_neon_ix_list: List[SolNeonIxReceiptInfo] = list()
        self._sol_tx_cost_list: List[SolTxCostInfo] = list()

        self._stat_neon_tx_dict: Dict[NeonIndexedTxInfo.Type, NeonTxStatData] = dict()

    def __str__(self) -> str:
        return str_fmt_object(self, False)

    def clone(self, history_block_deque: Deque[SolBlockInfo]) -> NeonIndexedBlockInfo:
        sol_block = history_block_deque[-1]
        assert sol_block.block_slot > self.block_slot

        new_block = NeonIndexedBlockInfo(history_block_deque)
        new_block._neon_holder_dict = copy.deepcopy(self._neon_holder_dict)
        new_block._neon_tx_dict = copy.deepcopy(self._neon_tx_dict)
        return new_block

    @property
    def block_slot(self) -> int:
        return self._sol_block.block_slot

    @property
    def block_hash(self) -> str:
        return self._sol_block.block_hash

    @property
    def is_finalized(self) -> bool:
        return self._sol_block.is_finalized

    @property
    def is_completed(self) -> bool:
        return self._is_completed

    def set_finalized(self, value: bool) -> None:
        for block in self._history_block_deque:
            block.set_finalized(value)

    def finalize_history_list(self, finalized_block_slot: int) -> int:
        removed_block_cnt = 0
        while len(self._history_block_deque) and (finalized_block_slot >= self._history_block_deque[0].block_slot):
            self._history_block_deque.popleft()
            removed_block_cnt += 1
        assert len(self._history_block_deque)
        return removed_block_cnt

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._sol_neon_ix_list.append(sol_neon_ix)

    def add_sol_tx_cost(self, sol_tx_cost: SolTxCostInfo) -> None:
        self._sol_tx_cost_list.append(sol_tx_cost)

    def find_neon_tx_holder(self, key: NeonIndexedHolderInfo.Key,
                            sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedHolderInfo]:
        holder = self._neon_holder_dict.get(key.value)
        if holder:
            holder.add_sol_neon_ix(sol_neon_ix)
        return holder

    def add_neon_tx_holder(self, key: NeonIndexedHolderInfo.Key,
                           sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedHolderInfo]:
        assert key.value not in self._neon_holder_dict, f'the holder {key} already in use!'

        holder = NeonIndexedHolderInfo(key)
        holder.add_sol_neon_ix(sol_neon_ix)
        self._neon_holder_dict[holder.key] = holder
        return holder

    def _del_neon_holder(self, holder: NeonIndexedHolderInfo) -> None:
        if not self._neon_holder_dict.pop(holder.key, None):
            LOG.warning(f'attempt to remove the not-existent {holder}')

    def fail_neon_holder(self, holder: NeonIndexedHolderInfo) -> None:
        self._del_neon_holder(holder)

    def done_neon_holder(self, holder: NeonIndexedHolderInfo) -> None:
        self._del_neon_holder(holder)

    def find_neon_tx(self, key: NeonIndexedTxInfo.Key,
                     sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedTxInfo]:
        tx = self._neon_tx_dict.get(key.value, None)
        if tx is not None:
            tx.add_sol_neon_ix(sol_neon_ix)
        return tx

    def add_neon_tx(self, tx_type: NeonIndexedTxInfo.Type, key: NeonIndexedTxInfo.Key, neon_tx: NeonTxInfo,
                    storage_account: str, iter_blocked_account: Iterator[str],
                    sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedTxInfo:
        if key.value in self._neon_tx_dict:
            raise RuntimeError(f'the tx {key} already in use!')

        tx = NeonIndexedTxInfo(tx_type, key, neon_tx, storage_account, iter_blocked_account)
        tx.add_sol_neon_ix(sol_neon_ix)
        self._neon_tx_dict[tx.key] = tx
        return tx

    def _del_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if not self._neon_tx_dict.pop(tx.key, None):
            LOG.warning(f'attempt to remove the not-existent {tx}')

    def fail_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if tx.status not in {NeonIndexedTxInfo.Status.InProgress, NeonIndexedTxInfo.Status.Canceled}:
            LOG.warning(f'attempt to fail the completed tx {tx}')
            return

        self._del_neon_tx(tx)

    def done_neon_tx(self, tx: NeonIndexedTxInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        if tx.status not in {NeonIndexedTxInfo.Status.InProgress, NeonIndexedTxInfo.Status.Canceled}:
            LOG.warning(f'attempt to done the completed tx {tx}')
            return

        tx.set_status(NeonIndexedTxInfo.Status.Done, sol_neon_ix.block_slot)
        self._done_neon_tx_list.append(tx)

    def add_neon_account(self, _: NeonAccountInfo, __: SolNeonIxReceiptInfo) -> None:
        pass

    def iter_history_block(self) -> Iterator[SolBlockInfo]:
        return iter(self._history_block_deque)

    @property
    def history_block_cnt(self):
        return len(self._history_block_deque)

    def iter_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        return iter(self._neon_tx_dict.values())

    @property
    def neon_tx_cnt(self) -> int:
        return len(self._neon_tx_dict)

    def iter_neon_holder(self) -> Iterator[NeonIndexedHolderInfo]:
        return iter(self._neon_holder_dict.values())

    @property
    def neon_holder_cnt(self) -> int:
        return len(self._neon_holder_dict)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        return iter(self._sol_neon_ix_list)

    @property
    def sol_neon_ix_cnt(self) -> int:
        return len(self._sol_neon_ix_list)

    def iter_sol_tx_cost(self) -> Iterator[SolTxCostInfo]:
        return iter(self._sol_tx_cost_list)

    def iter_done_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        return iter(self._done_neon_tx_list)

    def iter_stat_neon_tx(self) -> Iterator[NeonTxStatData]:
        return iter(self._stat_neon_tx_dict.values())

    def calc_stat(self, config: Config, op_account_set: Set[str]) -> None:
        if not config.gather_statistics:
            return

        def _new_stat(neon_tx_type: NeonIndexedTxInfo.Type) -> NeonTxStatData:
            if neon_tx_type == NeonIndexedTxInfo.Type.Single:
                type_name = 'single'
            elif neon_tx_type == NeonIndexedTxInfo.Type.SingleFromAccount:
                type_name = 'single-holder'
            elif neon_tx_type == NeonIndexedTxInfo.Type.IterFromData:
                type_name = 'iterative'
            elif neon_tx_type == NeonIndexedTxInfo.Type.IterFromAccount:
                type_name = 'holder'
            elif neon_tx_type == NeonIndexedTxInfo.Type.IterFromAccountWoChainId:
                type_name = 'wochainid'
            else:
                type_name = 'other'
            new_stat = NeonTxStatData()
            new_stat.tx_type = type_name
            return new_stat

        for sol_neon_ix in self._sol_neon_ix_list:
            tx = self._neon_tx_dict.get(NeonIndexedTxInfo.Key(sol_neon_ix).value, None)
            tx_type = tx.tx_type if tx is not None else NeonIndexedTxInfo.Type.Unknown
            is_op_sol_neon_ix = sol_neon_ix.sol_tx_cost.operator in op_account_set
            stat = self._stat_neon_tx_dict.setdefault(tx_type, _new_stat(tx_type))

            neon_income = 0
            if (tx is not None) and (tx.neon_tx.gas_price[:2] == '0x'):
                neon_income = sol_neon_ix.neon_gas_used * int(tx.neon_tx.gas_price, 16)

            sol_spent = 0
            if not sol_neon_ix.sol_tx_cost.is_calculated_stat:
                sol_spent = sol_neon_ix.sol_tx_cost.sol_spent
                sol_neon_ix.sol_tx_cost.set_calculated_stat()
                stat.sol_spent += sol_spent
                stat.sol_tx_cnt += 1

            stat.neon_income += neon_income
            stat.neon_step_cnt += sol_neon_ix.neon_step_cnt
            stat.bpf_cycle_cnt += sol_neon_ix.used_bpf_cycle_cnt

            if is_op_sol_neon_ix:
                stat.op_sol_spent += sol_spent
                stat.op_neon_income += neon_income

            if sol_neon_ix.neon_tx_return is not None:
                if sol_neon_ix.neon_tx_return.is_canceled:
                    stat.canceled_neon_tx_cnt += 1
                    if is_op_sol_neon_ix:
                        stat.op_canceled_neon_tx_cnt += 1
                else:
                    stat.completed_neon_tx_cnt += 1
                    if is_op_sol_neon_ix:
                        stat.op_completed_neon_tx_cnt += 1

    def fill_log_info_list(self) -> None:
        log_idx = 0
        tx_idx = 0
        for tx in self._done_neon_tx_list:
            tx.complete_event_list()
            log_idx = tx.neon_tx_res.set_block_info(self._sol_block, tx.neon_tx.sig, tx_idx, log_idx)
            tx_idx += 1

    def complete_block(self, config: Config) -> None:
        for tx in self._done_neon_tx_list:
            self._del_neon_tx(tx)

        self._is_completed = True
        self._done_neon_tx_list.clear()
        self._sol_tx_cost_list.clear()
        self._sol_neon_ix_list.clear()

        for tx in list(self.iter_neon_tx()):
            if abs(self.block_slot - tx.last_block_slot) > config.skip_cancel_timeout:
                LOG.debug(f'skip to cancel {tx}')
                self.fail_neon_tx(tx)

        for holder in list(self.iter_neon_holder()):
            if abs(self.block_slot - holder.last_block_slot) > config.holder_timeout:
                LOG.debug(f'skip the neon holder {holder}')
                self.fail_neon_holder(holder)


class NeonIndexedBlockDict:
    class Stat:
        def __init__(self, neon_holder_cnt: int, neon_tx_cnt: int,  history_block_cnt: int, sol_neon_ix_cnt: int):
            self._neon_block_cnt = 1
            self._neon_holder_cnt = neon_holder_cnt
            self._neon_tx_cnt = neon_tx_cnt
            self._history_block_cnt = history_block_cnt
            self._sol_neon_ix_cnt = sol_neon_ix_cnt
            self._min_block_slot = 0

        def __str__(self) -> str:
            return str_fmt_object(self, False)

        @staticmethod
        def init_empty() -> NeonIndexedBlockDict.Stat:
            return NeonIndexedBlockDict.Stat(0, 0, 0, 0)

        @staticmethod
        def from_block(neon_block: NeonIndexedBlockInfo) -> NeonIndexedBlockDict.Stat:
            return NeonIndexedBlockDict.Stat(
                neon_holder_cnt=neon_block.neon_holder_cnt,
                neon_tx_cnt=neon_block.neon_tx_cnt,
                history_block_cnt=neon_block.history_block_cnt,
                sol_neon_ix_cnt=neon_block.sol_neon_ix_cnt
            )

        @property
        def neon_block_cnt(self) -> int:
            return self._neon_block_cnt

        @property
        def neon_holder_cnt(self) -> int:
            return self._neon_holder_cnt

        @property
        def neon_tx_cnt(self) -> int:
            return self._neon_tx_cnt

        @property
        def sol_neon_ix_cnt(self) -> int:
            return self._sol_neon_ix_cnt

        @property
        def min_block_slot(self) -> int:
            return self._min_block_slot

        def set_min_block_slot(self, block_slot: int) -> None:
            self._min_block_slot = block_slot

        def dec_history_block_cnt(self, removed_block_cnt: int) -> None:
            self._history_block_cnt -= removed_block_cnt

        def add_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt += src._neon_block_cnt
            self._neon_holder_cnt += src._neon_holder_cnt
            self._neon_tx_cnt += src._neon_tx_cnt
            self._history_block_cnt += src._history_block_cnt
            self._sol_neon_ix_cnt += src._sol_neon_ix_cnt

        def del_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt -= src._neon_block_cnt
            self._neon_holder_cnt -= src._neon_holder_cnt
            self._neon_tx_cnt -= src._neon_tx_cnt
            self._history_block_cnt -= src._history_block_cnt
            self._sol_neon_ix_cnt -= src._sol_neon_ix_cnt

    def __init__(self):
        self._neon_block_dict: Dict[int, NeonIndexedBlockInfo] = dict()
        self._finalized_neon_block: Optional[NeonIndexedBlockInfo] = None
        self._stat = NeonIndexedBlockDict.Stat.init_empty()

    @property
    def finalized_neon_block(self) -> Optional[NeonIndexedBlockInfo]:
        return self._finalized_neon_block

    @property
    def stat(self) -> NeonIndexedBlockDict.Stat:
        return self._stat

    def get_neon_block(self, block_slot: int) -> Optional[NeonIndexedBlockInfo]:
        neon_block = self._neon_block_dict.get(block_slot, None)
        # Lazy cleaning of finalized history
        if (neon_block is not None) and (self._finalized_neon_block is not None):
            removed_block_cnt = neon_block.finalize_history_list(self._finalized_neon_block.block_slot)
            self._stat.dec_history_block_cnt(removed_block_cnt)
        return neon_block

    @staticmethod
    def _find_min_block_slot(neon_block: NeonIndexedBlockInfo) -> int:
        min_block_slot = neon_block.block_slot
        for holder in neon_block.iter_neon_holder():
            min_block_slot = min(min_block_slot, holder.start_block_slot)
        return min_block_slot

    def add_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if neon_block.block_slot in self._neon_block_dict:
            return

        stat = NeonIndexedBlockDict.Stat.from_block(neon_block)
        self._stat.add_stat(stat)
        self._neon_block_dict[neon_block.block_slot] = neon_block
        # LOG.debug(f'add block {neon_block.block_slot}: {stat}')

    def finalize_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        assert neon_block.block_slot in self._neon_block_dict

        if self._finalized_neon_block is not None:
            for block_slot in range(self._finalized_neon_block.block_slot, neon_block.block_slot):
                old_neon_block = self._neon_block_dict.pop(block_slot, None)
                if old_neon_block is not None:
                    stat = NeonIndexedBlockDict.Stat.from_block(old_neon_block)
                    self._stat.del_stat(stat)
                    # LOG.debug(f'delete block {old_neon_block.block_slot}: {stat}')

        # LOG.debug(f'finalize block {neon_block.block_slot}')
        self._finalized_neon_block = neon_block
        self._stat.set_min_block_slot(self._find_min_block_slot(neon_block))


class SolNeonTxDecoderState:
    # Iterate:
    #   for solana_block in block_range(start_block_slot, stop_block_slot):
    #       for solana_tx in solana_block.solana_tx_list:
    #           for solana_ix in solana_tx.solana_ix_list:
    #               solana_ix.level <- level in stack of calls
    #  ....
    def __init__(self, sol_tx_meta_collector: SolTxMetaCollector,
                 start_block_slot: int,
                 neon_block: Optional[NeonIndexedBlockInfo]):
        self._start_time = time.time()
        self._init_block_slot = start_block_slot
        self._start_block_slot = start_block_slot
        self._stop_block_slot = start_block_slot
        self._sol_tx_meta_cnt = 0
        self._sol_neon_ix_cnt = 0
        self._sol_tx_meta_collector = sol_tx_meta_collector

        self._sol_tx: Optional[SolTxReceiptInfo] = None
        self._sol_tx_meta: Optional[SolTxMetaInfo] = None
        self._sol_neon_ix: Optional[SolNeonIxReceiptInfo] = None

        self._neon_block_deque: Deque[Tuple[NeonIndexedBlockInfo, bool]] = deque()
        if neon_block is not None:
            self.set_neon_block(neon_block)

    def shift_to_collector(self, collector: SolTxMetaCollector):
        self._start_block_slot = self._stop_block_slot + 1
        self._stop_block_slot = self._start_block_slot
        self._sol_tx_meta_collector = collector

    def set_stop_block_slot(self, block_slot: int) -> None:
        self._stop_block_slot = block_slot

    def set_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if (len(self._neon_block_deque) > 0) and self._neon_block_deque[0][1]:
            self._neon_block_deque.popleft()
        is_finalized = self._sol_tx_meta_collector.is_finalized
        self._neon_block_deque.append((neon_block, is_finalized))

    @property
    def process_time_ms(self) -> float:
        return (time.time() - self._start_time) * 1000

    @property
    def start_block_slot(self) -> int:
        return self._start_block_slot

    @property
    def stop_block_slot(self) -> int:
        return self._stop_block_slot

    @property
    def commitment(self) -> str:
        return self._sol_tx_meta_collector.commitment

    @property
    def neon_block_cnt(self) -> int:
        return len(self._neon_block_deque)

    @property
    def sol_tx_meta_cnt(self) -> int:
        return self._sol_tx_meta_cnt

    @property
    def sol_neon_ix_cnt(self) -> int:
        return self._sol_neon_ix_cnt

    def has_neon_block(self) -> bool:
        return self.neon_block_cnt > 0

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][0]

    @property
    def is_neon_block_finalized(self) -> bool:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][1]

    @property
    def block_slot(self) -> int:
        return self.neon_block.block_slot

    def iter_sol_tx_meta(self) -> Iterator[SolTxMetaInfo]:
        try:
            # Solana returns transactions from the last processed one and then goes back into history
            collector = self._sol_tx_meta_collector
            for self._sol_tx_meta in collector.iter_tx_meta(self._stop_block_slot, self._start_block_slot):
                self._sol_tx_meta_cnt += 1
                yield self._sol_tx_meta
        finally:
            self._sol_tx_meta = None

    def has_sol_tx(self) -> bool:
        return self._sol_tx is not None

    @property
    def sol_tx(self) -> SolTxReceiptInfo:
        assert self.has_sol_tx()
        return cast(SolTxReceiptInfo, self._sol_tx)

    def has_sol_neon_ix(self) -> bool:
        return self._sol_neon_ix is not None

    @property
    def sol_neon_ix(self) -> SolNeonIxReceiptInfo:
        assert self.has_sol_neon_ix()
        return cast(SolNeonIxReceiptInfo, self._sol_neon_ix)

    @property
    def end_range(self) -> SolTxMetaInfo:
        return SolTxMetaInfo.from_end_range(self._stop_block_slot, self.commitment)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        assert self._sol_tx_meta is not None

        try:
            self._sol_tx = SolTxReceiptInfo.from_tx_meta(self._sol_tx_meta)
            for self._sol_neon_ix in self._sol_tx.iter_sol_neon_ix():
                self._sol_neon_ix_cnt += 1
                yield self._sol_neon_ix
        finally:
            self._sol_tx = None
            self._sol_neon_ix = None

    def iter_neon_block(self) -> Iterator[NeonIndexedBlockInfo]:
        for neon_block, _ in self._neon_block_deque:
            yield neon_block
