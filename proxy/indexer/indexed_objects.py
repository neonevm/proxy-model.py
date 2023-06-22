from __future__ import annotations

import copy
import time
import logging

from collections import deque
from dataclasses import dataclass
from typing import Iterator, Generator, List, Optional, Dict, Set, Deque, Tuple, Any, cast

from ..common_neon.config import Config
from ..common_neon.neon_instruction import EvmIxCode, EvmIxCodeName
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolNeonIxReceiptInfo, SolTxCostInfo, SolTxReceiptInfo
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils.evm_log_decoder import NeonLogTxEvent
from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxReceiptInfo, SolBlockInfo, str_fmt_object

from ..statistic.data import NeonTxStatData


LOG = logging.getLogger(__name__)


class BaseNeonIndexedObjInfo:
    def __init__(self, start_block_slot=0, last_block_slot=0, is_stuck=False) -> None:
        self._start_block_slot = start_block_slot
        self._last_block_slot = last_block_slot
        self._is_stuck = is_stuck

    def __str__(self) -> str:
        return str_fmt_object(self, False)

    @property
    def start_block_slot(self) -> int:
        return self._start_block_slot

    @property
    def last_block_slot(self) -> int:
        return self._last_block_slot

    def is_stuck(self) -> bool:
        return self._is_stuck

    def _set_start_block_slot(self, block_slot: int) -> None:
        if self._start_block_slot == 0 or block_slot < self._start_block_slot:
            self._start_block_slot = block_slot

    def _set_last_block_slot(self, block_slot: int) -> None:
        if block_slot > self._last_block_slot:
            self._last_block_slot = block_slot

    def mark_stuck(self) -> None:
        if not self._is_stuck:
            LOG.warning(f'stuck: {self}')
        self._is_stuck = True

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._set_start_block_slot(sol_neon_ix.block_slot)
        self._set_last_block_slot(sol_neon_ix.block_slot)


@dataclass(frozen=True)
class NeonAccountInfo:
    neon_address: str
    pda_address: str
    block_slot: int
    sol_sig: str


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
                _str = str_fmt_object(dict(offset=self.offset, length=self.length))
                object.__setattr__(self, '_str', _str)
            return self._str

        def is_valid(self) -> bool:
            return (self.length > 0) and (len(self.data) == self.length)

    class Key:
        def __init__(self, account: str, neon_tx_sig: str) -> None:
            self._acct = account
            self._neon_tx_sig = neon_tx_sig.lower()
            self._value = f'{self._acct}:{self._neon_tx_sig}'

        def __str__(self) -> str:
            return self.value

        @property
        def account(self) -> str:
            return self._acct

        @property
        def neon_tx_sig(self) -> str:
            return self._neon_tx_sig

        @property
        def value(self) -> str:
            return self._value

    def __init__(self, key: NeonIndexedHolderInfo.Key,
                 data: bytes = None,
                 data_size=0,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self._key = key
        self._data_size = data_size
        self._data = data if data is not None else bytes()

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonIndexedHolderInfo:
        key = NeonIndexedHolderInfo.Key(src.pop('account'), src.pop('neon_tx_sig'))
        data = bytes.fromhex(src.pop('data'))
        holder = NeonIndexedHolderInfo(key=key, data=data, **src)
        return holder

    @property
    def key(self) -> NeonIndexedHolderInfo.Key:
        return self._key

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

    def as_dict(self) -> Dict[str, Any]:
        return dict(
            start_block_slot=self._start_block_slot,
            last_block_slot=self._last_block_slot,
            is_stuck=self._is_stuck,
            neon_tx_sig=self._key.neon_tx_sig,
            account=self._key.account,
            data_size=self._data_size,
            data=self.data.hex(),
        )

    def add_data_chunk(self, chunk: DataChunk) -> None:
        end_pos = chunk.offset + chunk.length
        data_len = len(self._data)
        if end_pos > data_len:
            self._data += bytes(end_pos - data_len)

        self._data = self._data[:chunk.offset] + chunk.data + self._data[end_pos:]
        self._data_size += chunk.length


class NeonIndexedTxInfo(BaseNeonIndexedObjInfo):
    class Key:
        def __init__(self, neon_tx_sig: str) -> None:
            self._value = neon_tx_sig.lower()

        def __str__(self) -> str:
            return self._value

        def is_empty(self) -> bool:
            return self._value == ''

        @property
        def value(self) -> str:
            return self._value

    def __init__(self, ix_code: EvmIxCode,
                 key: NeonIndexedTxInfo.Key,
                 neon_tx: NeonTxInfo,
                 holder_account: str,
                 blocked_account_list: List[str],
                 neon_tx_res: NeonTxResultInfo = None,
                 neon_tx_event_list: List[NeonLogTxEvent] = None,
                 gas_used=0,
                 total_gas_used=0,
                 **kwargs):
        super().__init__(**kwargs)
        assert not key.is_empty()

        if neon_tx_res is None:
            neon_tx_res = NeonTxResultInfo()

        if neon_tx_event_list is None:
            neon_tx_event_list = list()

        self._key = key
        self._neon_receipt = NeonTxReceiptInfo(neon_tx, neon_tx_res)
        self._ix_code = ix_code
        self._holder_acct = holder_account
        self._blocked_acct_list = blocked_account_list
        self._is_done = False
        self._neon_event_list = neon_tx_event_list
        self._gas_used = gas_used
        self._total_gas_used = total_gas_used

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonIndexedTxInfo:
        key = NeonIndexedTxInfo.Key(src.pop('neon_tx_sig'))
        neon_tx = NeonTxInfo.from_dict(src.pop('neon_tx'))
        neon_res_info = NeonTxResultInfo.from_dict(src.pop('neon_tx_res'))
        neon_event_list = [NeonLogTxEvent.from_dict(s) for s in src.pop('neon_tx_event_list')]
        return NeonIndexedTxInfo(
            key=key,
            neon_tx=neon_tx,
            neon_tx_res=neon_res_info,
            neon_tx_event_list=neon_event_list,
            **src
        )

    @property
    def holder_account(self) -> str:
        return self._holder_acct

    @property
    def neon_tx_sig(self) -> str:
        return self._key.value

    @property
    def blocked_account_cnt(self) -> int:
        return len(self._blocked_acct_list)

    def iter_blocked_account(self) -> Iterator[str]:
        return iter(self._blocked_acct_list)

    @property
    def key(self) -> NeonIndexedTxInfo.Key:
        return self._key

    @property
    def ix_code(self) -> EvmIxCode:
        return self._ix_code

    @property
    def neon_tx(self) -> NeonTxInfo:
        return self._neon_receipt.neon_tx

    @property
    def neon_tx_res(self) -> NeonTxResultInfo:
        return self._neon_receipt.neon_tx_res

    @property
    def total_gas_used(self) -> int:
        return self._total_gas_used

    def is_done(self) -> bool:
        """Return true if indexer found the receipt for the tx"""
        return self._is_done

    def is_corrupted(self) -> bool:
        """Return true if indexer didn't find all instructions for the tx"""
        return self._gas_used != self._total_gas_used

    def as_dict(self) -> Dict[str, Any]:
        return dict(
            start_block_slot=self._start_block_slot,
            last_block_slot=self._last_block_slot,
            is_stuck=self._is_stuck,
            ix_code=self._ix_code,
            neon_tx_sig=self._key.value,
            holder_account=self._holder_acct,
            blocked_account_list=self._blocked_acct_list,
            gas_used=self._gas_used,
            total_gas_used=self._total_gas_used,
            neon_tx=self._neon_receipt.neon_tx.as_dict(),
            neon_tx_res=self._neon_receipt.neon_tx_res.as_dict(),
            neon_tx_event_list=[e.as_dict() for e in self._neon_event_list]
        )

    def mark_done(self, block_slot: int) -> None:
        self._is_done = True
        self._set_last_block_slot(block_slot)

    def set_neon_tx(self, neon_tx: NeonTxInfo, holder: NeonIndexedHolderInfo) -> None:
        assert not self._neon_receipt.neon_tx.is_valid()
        assert neon_tx.is_valid()

        self._neon_receipt.set_neon_tx(neon_tx)
        self._set_start_block_slot(holder.start_block_slot)
        self._set_last_block_slot(holder.last_block_slot)

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        super().add_sol_neon_ix(sol_neon_ix)
        self._gas_used += sol_neon_ix.neon_gas_used
        if sol_neon_ix.neon_total_gas_used > self._total_gas_used:
            self._total_gas_used = sol_neon_ix.neon_total_gas_used

    def add_neon_event(self, event: NeonLogTxEvent) -> None:
        self._neon_event_list.append(event)

    def _get_sorted_neon_event_list(self) -> List[NeonLogTxEvent]:
        # no events
        if len(self._neon_event_list) == 0:
            return list()

        # old type of event without enter/exit(revert) information ...
        if self._neon_event_list[0].total_gas_used == 0:
            return self._neon_event_list

        # sort events by total_gas_used, because its value increases each iteration
        return sorted(self._neon_event_list, key=lambda x: x.total_gas_used, reverse=False)

    @property
    def len_neon_event_list(self) -> int:
        return len(self._neon_event_list)

    def complete_event_list(self) -> None:
        event_list_len = len(self._neon_event_list)
        if (not self.neon_tx_res.is_valid()) or (len(self.neon_tx_res.log_list) > 0) or (event_list_len == 0):
            return

        current_level = 0
        current_order = 0

        neon_event_list = self._get_sorted_neon_event_list()
        for event in neon_event_list:
            if event.is_reverted:
                event_level = 0
            elif event.is_start_event_type():
                current_level += 1
                event_level = current_level
            elif event.is_exit_event_type():
                event_level = current_level
                current_level -= 1
            else:
                event_level = current_level

            current_order += 1
            object.__setattr__(event, 'event_level', event_level)
            object.__setattr__(event, 'event_order', current_order)

        reverted_level = -1
        is_failed = (self.neon_tx_res.status == 0)

        for event in reversed(neon_event_list):
            if event.is_reverted:
                is_reverted = True
                is_hidden = True
            else:
                if event.is_start_event_type():
                    if event.event_level == reverted_level:
                        reverted_level = -1
                elif event.is_exit_event_type():
                    if (event.event_type == NeonLogTxEvent.Type.ExitRevert) and (reverted_level == -1):
                        reverted_level = event.event_level

                is_reverted = (reverted_level != -1) or is_failed
                is_hidden = (event.is_hidden or is_reverted)

            object.__setattr__(event, 'is_reverted', is_reverted)
            object.__setattr__(event, 'is_hidden', is_hidden)

        for event in neon_event_list:
            self.neon_tx_res.add_event(event)


class NeonIndexedBlockInfo:
    def __init__(self, sol_block: SolBlockInfo):
        self._sol_block = sol_block
        self._min_block_slot = self._sol_block.block_slot
        self._stuck_block_slot = self._sol_block.block_slot
        self._is_completed = False
        self._is_cloned = True
        self._has_corrupted_tx = False

        self._neon_holder_dict: Dict[str, NeonIndexedHolderInfo] = dict()
        self._modified_neon_acct_set: Set[str] = set()
        self._stuck_neon_holder_list: List[NeonIndexedHolderInfo] = list()
        self._failed_neon_holder_set: Set[str] = set()

        self._neon_tx_dict: Dict[str, NeonIndexedTxInfo] = dict()
        self._done_neon_tx_list: List[NeonIndexedTxInfo] = list()
        self._stuck_neon_tx_list: List[NeonIndexedTxInfo] = list()
        self._failed_neon_tx_set: Set[str] = set()

        self._sol_neon_ix_list: List[SolNeonIxReceiptInfo] = list()
        self._sol_tx_cost_list: List[SolTxCostInfo] = list()

        self._stat_neon_tx_dict: Dict[EvmIxCode, NeonTxStatData] = dict()

    @staticmethod
    def from_block(src_block: NeonIndexedBlockInfo, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        assert sol_block.block_slot > src_block.block_slot

        new_block = NeonIndexedBlockInfo(sol_block)
        new_block._is_cloned = False

        if len(src_block._neon_tx_dict) or len(src_block._neon_holder_dict):
            new_block._min_block_slot = src_block._min_block_slot

        if len(src_block._stuck_neon_holder_list) or len(src_block._stuck_neon_tx_list):
            new_block._stuck_block_slot = src_block._stuck_block_slot

        new_block._neon_holder_dict = src_block._neon_holder_dict
        new_block._stuck_neon_holder_list = src_block._stuck_neon_holder_list
        new_block._failed_neon_holder_set = src_block._failed_neon_holder_set

        new_block._neon_tx_dict = src_block._neon_tx_dict
        new_block._stuck_neon_tx_list = src_block._stuck_neon_tx_list
        new_block._failed_neon_tx_set = src_block._failed_neon_tx_set

        return new_block

    @staticmethod
    def from_stuck_data(sol_block: SolBlockInfo,
                        stuck_block_slot: int,
                        neon_holder_list: List[Dict[str, Any]],
                        neon_tx_list: List[Dict[str, Any]]) -> NeonIndexedBlockInfo:
        assert sol_block.block_slot <= stuck_block_slot

        new_block = NeonIndexedBlockInfo(sol_block)
        new_block._stuck_block_slot = stuck_block_slot

        for src in neon_holder_list:
            holder = NeonIndexedHolderInfo.from_dict(src)
            new_block._neon_holder_dict[holder.key.value] = holder
            new_block._stuck_neon_holder_list.append(holder)

        for src in neon_tx_list:
            tx = NeonIndexedTxInfo.from_dict(src)
            new_block._neon_tx_dict[tx.key.value] = tx
            new_block._stuck_neon_tx_list.append(tx)

        return new_block

    def __str__(self) -> str:
        return str_fmt_object(self, False)

    @property
    def block_slot(self) -> int:
        return self._sol_block.block_slot

    @property
    def stuck_block_slot(self) -> int:
        return self._stuck_block_slot

    @property
    def block_hash(self) -> str:
        return self._sol_block.block_hash

    @property
    def is_finalized(self) -> bool:
        return self._sol_block.is_finalized

    @property
    def is_completed(self) -> bool:
        return self._is_completed

    @property
    def min_block_slot(self) -> int:
        return self._min_block_slot

    def set_finalized(self, value: bool) -> None:
        self._sol_block.set_finalized(value)

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._clone()
        self._sol_neon_ix_list.append(sol_neon_ix)

    def _clone(self) -> None:
        if self._is_cloned:
            return

        self._is_cloned = True
        self._min_block_slot = self._sol_block.block_slot
        if self._stuck_block_slot < self._sol_block.block_slot:
            self._stuck_block_slot = self._sol_block.block_slot

        self._neon_holder_dict = copy.deepcopy(self._neon_holder_dict)

        self._neon_tx_dict = copy.deepcopy(self._neon_tx_dict)

    def add_sol_tx_cost(self, sol_tx_cost: SolTxCostInfo) -> None:
        self._sol_tx_cost_list.append(sol_tx_cost)

    def find_neon_tx_holder(self, acct: str, sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedHolderInfo]:
        key = NeonIndexedHolderInfo.Key(acct, sol_neon_ix.neon_tx_sig)
        holder = self._neon_holder_dict.get(key.value, None)
        if not holder:
            return holder

        holder.add_sol_neon_ix(sol_neon_ix)
        self._modified_neon_acct_set.add(key.account)
        return holder

    def add_neon_tx_holder(self, acct: str, sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedHolderInfo]:
        key = NeonIndexedHolderInfo.Key(acct, sol_neon_ix.neon_tx_sig)
        assert key.value not in self._neon_holder_dict, f'the NeonHolder {key} already in use!'

        holder = NeonIndexedHolderInfo(key)
        holder.add_sol_neon_ix(sol_neon_ix)
        self._neon_holder_dict[key.value] = holder
        self._modified_neon_acct_set.add(key.account)
        return holder

    def _del_neon_holder(self, holder: NeonIndexedHolderInfo) -> None:
        if not self._neon_holder_dict.pop(holder.key.value, None):
            LOG.warning(f'attempt to remove the not-existent {holder}')

    def done_neon_holder(self, holder: NeonIndexedHolderInfo) -> None:
        self._del_neon_holder(holder)

    def find_neon_tx(self, sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedTxInfo]:
        key = NeonIndexedTxInfo.Key(sol_neon_ix.neon_tx_sig)
        tx = self._neon_tx_dict.get(key.value, None)
        if tx is not None:
            tx.add_sol_neon_ix(sol_neon_ix)
        return tx

    def add_neon_tx(self, ix_code: EvmIxCode, neon_tx: NeonTxInfo,
                    holder_acct: str, iter_blocked_acct: Iterator[str],
                    sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedTxInfo:
        key = NeonIndexedTxInfo.Key(sol_neon_ix.neon_tx_sig)
        assert key.value not in self._neon_tx_dict, f'the tx {key} already in use!'

        blocked_acct_list = list(iter_blocked_acct)
        tx = NeonIndexedTxInfo(ix_code, key, neon_tx, holder_acct, blocked_acct_list)
        tx.add_sol_neon_ix(sol_neon_ix)
        self._neon_tx_dict[key.value] = tx
        return tx

    def _del_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if not self._neon_tx_dict.pop(tx.key.value, None):
            LOG.warning(f'attempt to remove the not-existent {tx}')

    def done_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if tx.is_done():
            LOG.warning(f'attempt to done the completed tx {tx}')
            return

        tx.mark_done(self.block_slot)
        self._done_neon_tx_list.append(tx)

    def iter_stuck_neon_holder(self) -> Iterator[NeonIndexedHolderInfo]:
        return iter(self._stuck_neon_holder_list)

    def iter_stuck_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        return iter(self._stuck_neon_tx_list)

    def fail_neon_holder_list(self, failed_holder_list: List[NeonIndexedHolderInfo]) -> None:
        failed_holder_set: Set[str] = set()
        for holder in failed_holder_list:
            if holder.key.value not in self._failed_neon_holder_set:
                failed_holder_set.add(holder.key.value)
                continue

            # Remove holder only if it appears two times in the failed set
            LOG.warning(f'skip lost: {holder}')
            self._del_neon_holder(holder)

        # Replace old set with the new one - so it is not require to clone it
        self._failed_neon_holder_set = failed_holder_set

    def fail_neon_tx_list(self, failed_tx_list: List[NeonIndexedTxInfo]) -> None:
        failed_tx_set: Set[str] = set()
        for tx in failed_tx_list:
            if tx.key.value not in self._failed_neon_tx_set:
                failed_tx_set.add(tx.key.value)
                continue

            # Remove tx only if it appears two times in the failed set
            LOG.warning(f'skip lost: {tx}')
            self._del_neon_tx(tx)

        # Replace old set with the new one - so it is not require to clone it
        self._failed_neon_tx_set = failed_tx_set

    @property
    def sol_block(self) -> SolBlockInfo:
        return self._sol_block

    @property
    def neon_tx_cnt(self) -> int:
        return len(self._neon_tx_dict)

    @property
    def neon_holder_cnt(self) -> int:
        return len(self._neon_holder_dict)

    @property
    def sol_neon_ix_cnt(self) -> int:
        return len(self._sol_neon_ix_list)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        return iter(self._sol_neon_ix_list)

    def iter_sol_tx_cost(self) -> Iterator[SolTxCostInfo]:
        return iter(self._sol_tx_cost_list)

    def iter_done_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        if self._has_corrupted_tx:
            # don't override db with corrupted data
            return iter(())
        return iter(self._done_neon_tx_list)

    def iter_stat_neon_tx(self) -> Iterator[NeonTxStatData]:
        return iter(self._stat_neon_tx_dict.values())

    def _calc_stat(self, config: Config) -> None:
        if not config.gather_statistics:
            return

        def _new_stat(new_ix_code: EvmIxCode) -> NeonTxStatData:
            tx_type = EvmIxCodeName().get(new_ix_code)
            new_stat = NeonTxStatData(tx_type=tx_type)
            return new_stat

        def _get_ix_code() -> EvmIxCode:
            if tx is not None:
                return tx.ix_code
            elif sol_neon_ix.ix_code in {EvmIxCode.HolderWrite, EvmIxCode.CancelWithHash}:
                return EvmIxCode.TxStepFromAccount
            return EvmIxCode(sol_neon_ix.ix_code)

        prev_sol_sig = ''
        for sol_neon_ix in self._sol_neon_ix_list:
            tx = self._neon_tx_dict.get(NeonIndexedTxInfo.Key(sol_neon_ix.neon_tx_sig).value, None)
            ix_code = _get_ix_code()
            is_op_sol_neon_ix = False
            stat = self._stat_neon_tx_dict.get(ix_code)
            if stat is None:
                stat = _new_stat(ix_code)
                self._stat_neon_tx_dict[ix_code] = stat

            neon_income = 0
            if tx is not None:
                neon_income = sol_neon_ix.neon_gas_used * tx.neon_tx.gas_price

            sol_spent = 0
            sol_sig = sol_neon_ix.sol_sig
            if sol_sig != prev_sol_sig:
                prev_sol_sig = sol_sig
                is_op_sol_neon_ix = sol_neon_ix.sol_tx_cost.operator in config.operator_account_set
                sol_spent = sol_neon_ix.sol_tx_cost.sol_spent
                stat.sol_spent += sol_spent
                stat.sol_tx_cnt += 1

            stat.neon_income += neon_income
            stat.neon_step_cnt += sol_neon_ix.neon_step_cnt
            stat.bpf_cycle_cnt += sol_neon_ix.used_bpf_cycle_cnt

            if is_op_sol_neon_ix:
                stat.op_sol_spent += sol_spent
                stat.op_neon_income += neon_income

            if sol_neon_ix.neon_tx_return is None:
                continue
            elif sol_neon_ix.neon_tx_return.is_canceled:
                stat.canceled_neon_tx_cnt += 1
                if is_op_sol_neon_ix:
                    stat.op_canceled_neon_tx_cnt += 1
            else:
                stat.completed_neon_tx_cnt += 1
                if is_op_sol_neon_ix:
                    stat.op_completed_neon_tx_cnt += 1

    def done_block(self, config: Config) -> None:
        self._check_stuck_holders(config)
        self._check_stuck_txs(config)

        self._finalize_log_list()
        self._calc_stat(config)

    def complete_block(self) -> None:
        self._is_completed = True
        for tx in self._done_neon_tx_list:
            self._del_neon_tx(tx)

    def _finalize_log_list(self) -> None:
        log_idx = 0
        tx_idx = 0
        sum_gas_used = 0
        for tx in self._done_neon_tx_list:
            if tx.is_corrupted():
                LOG.warning(f'corrupted tx: {tx}')
                self._has_corrupted_tx = True
                continue

            tx.complete_event_list()
            sum_gas_used += tx.neon_tx_res.gas_used
            log_idx = tx.neon_tx_res.set_block_info(self._sol_block, tx.neon_tx.sig, tx_idx, log_idx, sum_gas_used)
            tx_idx += 1

    def _check_stuck_holders(self, config: Config) -> None:
        # there were the restart with stuck holders
        if self._stuck_block_slot > self._sol_block.block_slot:
            return
        # if was no changes
        elif not self._is_cloned:
            # if all holders are already stuck
            if len(self._stuck_neon_holder_list) == len(self._neon_holder_dict):
                return

        block_slot = self.block_slot
        stuck_block_slot = block_slot - config.stuck_object_blockout
        self._stuck_neon_holder_list = list()

        for holder in list(self._neon_holder_dict.values()):
            if (holder.last_block_slot < block_slot) and (holder.account in self._modified_neon_acct_set):
                LOG.warning(f'skip the stuck (< {block_slot}): {holder}')
                self._del_neon_holder(holder)

            elif stuck_block_slot > holder.start_block_slot:
                self._stuck_neon_holder_list.append(holder)
                holder.mark_stuck()

            elif self._min_block_slot > holder.start_block_slot:
                self._min_block_slot = holder.start_block_slot

        self._modified_neon_acct_set.clear()

    def _check_stuck_txs(self, config: Config) -> None:
        # there were the restart with stuck txs
        if self._stuck_block_slot > self._sol_block.block_slot:
            return
        # if was no changes
        elif not self._is_cloned:
            # if all txs are already stuck
            if len(self._stuck_neon_tx_list) == len(self._neon_tx_dict):
                return

        block_slot = self.block_slot
        stuck_block_slot = block_slot - config.stuck_object_blockout
        self._stuck_neon_tx_list = list()

        for tx in list(self._neon_tx_dict.values()):
            if tx.is_done():
                continue

            elif stuck_block_slot > tx.start_block_slot:
                self._stuck_neon_tx_list.append(tx)
                tx.mark_stuck()

            elif self._min_block_slot > tx.start_block_slot:
                self._min_block_slot = tx.start_block_slot


class NeonIndexedBlockDict:
    class Stat:
        def __init__(self, neon_holder_cnt: int, neon_tx_cnt: int, sol_neon_ix_cnt: int):
            self._neon_block_cnt = 1
            self._neon_holder_cnt = neon_holder_cnt
            self._neon_tx_cnt = neon_tx_cnt
            self._sol_neon_ix_cnt = sol_neon_ix_cnt
            self._min_block_slot = 0

        def __str__(self) -> str:
            return str_fmt_object(self, False)

        @staticmethod
        def init_empty() -> NeonIndexedBlockDict.Stat:
            return NeonIndexedBlockDict.Stat(0, 0, 0)

        @staticmethod
        def from_block(neon_block: NeonIndexedBlockInfo) -> NeonIndexedBlockDict.Stat:
            return NeonIndexedBlockDict.Stat(
                neon_holder_cnt=neon_block.neon_holder_cnt,
                neon_tx_cnt=neon_block.neon_tx_cnt,
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

        def add_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt += src._neon_block_cnt
            self._neon_holder_cnt += src._neon_holder_cnt
            self._neon_tx_cnt += src._neon_tx_cnt
            self._sol_neon_ix_cnt += src._sol_neon_ix_cnt

        def del_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt -= src._neon_block_cnt
            self._neon_holder_cnt -= src._neon_holder_cnt
            self._neon_tx_cnt -= src._neon_tx_cnt
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

    def clear(self):
        self._neon_block_dict.clear()
        self._finalized_neon_block = None
        self._stat = NeonIndexedBlockDict.Stat.init_empty()

    def find_neon_block(self, block_slot: int) -> Optional[NeonIndexedBlockInfo]:
        return self._neon_block_dict.get(block_slot, None)

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
        self._stat.set_min_block_slot(neon_block.min_block_slot)


class SolNeonTxDecoderState:
    # Iterate:
    #   for solana_block in block_range(start_block_slot, stop_block_slot):
    #       for solana_tx in solana_block.solana_tx_list:
    #           for solana_ix in solana_tx.solana_ix_list:
    #               solana_ix.level <- level in stack of calls
    #  ....
    def __init__(self, config: Config,
                 sol_commit: SolCommit.Type,
                 start_block_slot: int,
                 neon_block: Optional[NeonIndexedBlockInfo]):
        self._config = config
        self._start_time = time.time()
        self._init_block_slot = start_block_slot
        self._start_block_slot = start_block_slot
        self._stop_block_slot = start_block_slot
        self._sol_tx_meta_cnt = 0
        self._sol_neon_ix_cnt = 0
        self._sol_commit = sol_commit
        self._is_finalized = sol_commit == SolCommit.Finalized
        self._evm_program_id = str(self._config.evm_program_id)

        self._sol_tx: Optional[SolTxReceiptInfo] = None
        self._sol_tx_meta: Optional[SolTxMetaInfo] = None
        self._sol_tx_cost: Optional[SolTxCostInfo] = None
        self._sol_neon_ix: Optional[SolNeonIxReceiptInfo] = None

        self._neon_block_deque: Deque[Tuple[NeonIndexedBlockInfo, bool]] = deque()
        if neon_block is not None:
            self.set_neon_block(neon_block)

    def shift_to_commit(self, sol_commit: SolCommit.Type):
        self._start_block_slot = self._stop_block_slot + 1
        self._stop_block_slot = self._start_block_slot
        self._sol_commit = sol_commit
        self._is_finalized = sol_commit == SolCommit.Finalized

    def set_stop_block_slot(self, block_slot: int) -> None:
        self._stop_block_slot = block_slot

    def set_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if (len(self._neon_block_deque) > 0) and self._neon_block_deque[0][1]:
            self._neon_block_deque.popleft()
        self._neon_block_deque.append((neon_block, self._is_finalized))

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
    def sol_commit(self) -> str:
        return self._sol_commit

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

    def is_finalized(self) -> bool:
        return self._is_finalized

    def is_last_block(self, neon_block: NeonIndexedBlockInfo) -> bool:
        return neon_block.block_slot == self._stop_block_slot

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][0]

    def is_neon_block_finalized(self) -> bool:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][1]

    @property
    def block_slot(self) -> int:
        return self.neon_block.block_slot

    def iter_sol_tx_meta(self, sol_block: SolBlockInfo) -> Generator[SolTxMetaInfo, None, None]:
        try:
            # Solana returns transactions from the last processed one and then goes back into history
            for tx_receipt in sol_block.tx_receipt_list:
                if not self._has_sol_neon_ix(tx_receipt):
                    continue

                self._sol_tx_meta = SolTxMetaInfo.from_tx_receipt(sol_block.block_slot, tx_receipt)
                self._sol_tx_meta_cnt += 1
                yield self._sol_tx_meta
        finally:
            self._sol_tx_meta = None

    def _has_sol_neon_ix(self, tx_receipt: Dict[str, Any]) -> bool:
        msg = tx_receipt.get('transaction', dict()).get('message', None)
        if msg is None:
            return False

        account_key_list = msg.get('accountKeys', list())
        for account_idx, account in enumerate(account_key_list):
            if account == self._evm_program_id:
                evm_program_idx = account_idx
                break
        else:
            return False

        ix_list: List[Dict[str, Any]] = msg.get('instructions', list())
        for ix in ix_list:
            if ix.get('programIdIndex', -1) == evm_program_idx:
                return True

        meta = tx_receipt.get('meta', None)
        if meta is None:
            return False

        inner_ix_info_list: List[Dict[str, Any]] = meta.get('innerInstructions', list())
        for inner_ix_info in inner_ix_info_list:
            ix_list: List[Dict[str, Any]] = inner_ix_info.get('instructions', list())
            for ix in ix_list:
                if ix.get('programIdIndex', -1) == evm_program_idx:
                    return True
        return False

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
    def sol_tx_cost(self) -> SolTxCostInfo:
        assert self._sol_tx_meta is not None
        if self._sol_tx_cost is None:
            self._sol_tx_cost = SolTxCostInfo.from_tx_meta(self._sol_tx_meta)
        return self._sol_tx_cost

    def iter_sol_neon_ix(self) -> Generator[SolNeonIxReceiptInfo, None, None]:
        assert self._sol_tx_meta is not None

        try:
            sol_tx_cost = self.sol_tx_cost
            self._sol_tx = SolTxReceiptInfo.from_tx_meta(self._sol_tx_meta, sol_tx_cost)
            for self._sol_neon_ix in self._sol_tx.iter_sol_ix(self._evm_program_id):
                self._sol_neon_ix_cnt += 1
                yield self._sol_neon_ix
        finally:
            self._sol_tx = None
            self._sol_tx_cost = None
            self._sol_neon_ix = None

    def iter_neon_block(self) -> Generator[NeonIndexedBlockInfo, None, None]:
        for neon_block, _ in self._neon_block_deque:
            yield neon_block
