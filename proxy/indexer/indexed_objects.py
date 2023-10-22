from __future__ import annotations

import copy
import dataclasses
import logging
import time

from dataclasses import dataclass
from typing import Iterator, Generator, List, Optional, Dict, Set, Any, cast

from ..common_neon.config import Config
from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.neon_instruction import EvmIxCode, EvmIxCodeName, AltIxCodeName
from ..common_neon.solana_neon_tx_receipt import (
    SolTxMetaInfo, SolTxCostInfo, SolNeonTxReceiptInfo,
    SolNeonIxReceiptInfo,
    SolAltIxInfo
)
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils import NeonTxInfo, str_fmt_object
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.utils.evm_log_decoder import NeonLogTxEvent
from ..common_neon.utils.utils import get_from_dict, cached_method

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
    chain_id: int
    pda_address: str
    block_slot: int
    sol_sig: str


class NeonIndexedHolderInfo(BaseNeonIndexedObjInfo):
    @dataclass(frozen=True)
    class DataChunk:
        offset: int
        length: int
        data: bytes

        @staticmethod
        def init_empty() -> NeonIndexedHolderInfo.DataChunk:
            return NeonIndexedHolderInfo.DataChunk(offset=0, length=0, data=bytes())

        @cached_method
        def __str__(self):
            return str_fmt_object(dict(offset=self.offset, length=self.length))

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
                 operator: Optional[str] = None,
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
        self._is_done = False
        self._neon_event_list = neon_tx_event_list
        self._operator = operator
        self._gas_used = gas_used
        self._total_gas_used = total_gas_used

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonIndexedTxInfo:
        key = NeonIndexedTxInfo.Key(src.pop('neon_tx_sig'))
        neon_tx = NeonTxInfo.from_dict(src.pop('neon_tx'))
        neon_res_info = NeonTxResultInfo.from_dict(src.pop('neon_tx_res'))
        neon_event_list = [NeonLogTxEvent.from_dict(s) for s in src.pop('neon_tx_event_list')]
        operator = src.pop('operator', None)
        src.pop('blocked_account_list', None)
        return NeonIndexedTxInfo(
            key=key,
            neon_tx=neon_tx,
            neon_tx_res=neon_res_info,
            neon_tx_event_list=neon_event_list,
            operator=operator,
            **src
        )

    @property
    def holder_account(self) -> str:
        return self._holder_acct

    @property
    def neon_tx_sig(self) -> str:
        return self._key.value

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
    def operator(self) -> Optional[str]:
        return self._operator

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
            operator=self._operator,
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
        if self._operator is None:
            self._operator = sol_neon_ix.sol_tx_cost.operator

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


@dataclass(frozen=True)
class NeonIndexedAltInfo:
    alt_key: str
    neon_tx_sig: str
    block_slot: int
    next_check_slot: int = 0
    last_ix_slot: int = 0
    is_stuck: bool = False

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonIndexedAltInfo:
        next_check_slot = src.pop('next_check_slot', src.pop('done_block_slot', None))
        return NeonIndexedAltInfo(**src, next_check_slot=next_check_slot)

    def __str__(self) -> str:
        return str_fmt_object(self)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def set_next_check_slot(self, block_slot: int) -> None:
        if block_slot > self.next_check_slot:
            object.__setattr__(self, 'next_check_slot', block_slot)

    def set_last_ix_slot(self, block_slot: int) -> None:
        if block_slot > self.last_ix_slot:
            object.__setattr__(self, 'last_ix_slot', block_slot)

    def mark_stuck(self) -> None:
        if self.is_stuck:
            return

        object.__setattr__(self, 'is_stuck', True)
        LOG.warning(f'stuck: {self}')


class NeonIndexedBlockInfo:
    def __init__(self, sol_block: SolBlockInfo):
        self._sol_block = sol_block
        self._min_block_slot = self._sol_block.block_slot
        self._stuck_block_slot = self._sol_block.block_slot
        self._is_completed = False
        self._is_cloned = True
        self._is_done = False
        self._has_corrupted_tx = False
        self._is_stuck_completed = False

        self._neon_holder_dict: Dict[str, NeonIndexedHolderInfo] = dict()
        self._modified_neon_acct_set: Set[str] = set()
        self._stuck_neon_holder_list: List[NeonIndexedHolderInfo] = list()
        self._failed_neon_holder_set: Set[str] = set()

        self._neon_tx_dict: Dict[str, NeonIndexedTxInfo] = dict()
        self._done_neon_tx_list: List[NeonIndexedTxInfo] = list()
        self._stuck_neon_tx_list: List[NeonIndexedTxInfo] = list()
        self._failed_neon_tx_set: Set[str] = set()

        self._sol_alt_info_dict: Dict[str, NeonIndexedAltInfo] = dict()

        self._sol_neon_ix_list: List[SolNeonIxReceiptInfo] = list()
        self._sol_alt_ix_list: List[SolAltIxInfo] = list()
        self._sol_tx_cost_list: List[SolTxCostInfo] = list()

        self._stat_neon_tx_dict: Dict[int, NeonTxStatData] = dict()

    @staticmethod
    def from_block(src_block: NeonIndexedBlockInfo, sol_block: SolBlockInfo) -> NeonIndexedBlockInfo:
        assert sol_block.block_slot > src_block.block_slot

        new_block = NeonIndexedBlockInfo(sol_block)
        new_block._is_cloned = False

        if len(src_block._neon_tx_dict) or len(src_block._neon_holder_dict):
            new_block._min_block_slot = src_block._min_block_slot

        if src_block._stuck_block_slot > new_block.block_slot:
            new_block._stuck_block_slot = src_block._stuck_block_slot

        new_block._neon_holder_dict = src_block._neon_holder_dict
        new_block._stuck_neon_holder_list = src_block._stuck_neon_holder_list
        new_block._failed_neon_holder_set = src_block._failed_neon_holder_set

        new_block._neon_tx_dict = src_block._neon_tx_dict
        new_block._stuck_neon_tx_list = src_block._stuck_neon_tx_list
        new_block._failed_neon_tx_set = src_block._failed_neon_tx_set

        new_block._sol_alt_info_dict = src_block._sol_alt_info_dict

        return new_block

    @staticmethod
    def from_stuck_data(sol_block: SolBlockInfo,
                        stuck_block_slot: int,
                        neon_holder_list: List[Dict[str, Any]],
                        neon_tx_list: List[Dict[str, Any]],
                        alt_info_list: List[Dict[str, Any]]) -> NeonIndexedBlockInfo:

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

        for src in alt_info_list:
            alt = NeonIndexedAltInfo.from_dict(src)
            new_block._sol_alt_info_dict[alt.alt_key] = alt

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
    def is_finalized(self) -> bool:
        return self._sol_block.is_finalized

    @property
    def is_completed(self) -> bool:
        return self._is_completed

    @property
    def is_corrupted(self) -> bool:
        return self._has_corrupted_tx

    @property
    def is_done(self) -> bool:
        return self._is_done

    @property
    def min_block_slot(self) -> int:
        return self._min_block_slot

    def mark_finalized(self) -> None:
        self._sol_block.set_finalized(True)

    def mark_done(self) -> None:
        self._is_done = True

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
        self._sol_alt_info_dict = copy.deepcopy(self._sol_alt_info_dict)

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
            self._add_alt_info(tx, sol_neon_ix)
        return tx

    def add_neon_tx(self, ix_code: EvmIxCode, neon_tx: NeonTxInfo,
                    holder_acct: str, sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedTxInfo:
        key = NeonIndexedTxInfo.Key(sol_neon_ix.neon_tx_sig)
        assert key.value not in self._neon_tx_dict, f'the tx {key} already in use!'

        tx = NeonIndexedTxInfo(ix_code, key, neon_tx, holder_acct)
        tx.add_sol_neon_ix(sol_neon_ix)
        self._neon_tx_dict[key.value] = tx
        self._add_alt_info(tx, sol_neon_ix)
        return tx

    def _add_alt_info(self, tx: NeonIndexedTxInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        for alt_key in sol_neon_ix.iter_alt_key():
            if alt_key in self._sol_alt_info_dict:
                continue
            alt_info = NeonIndexedAltInfo(alt_key, tx.neon_tx_sig, sol_neon_ix.block_slot)
            self._sol_alt_info_dict[alt_key] = alt_info

    def _del_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if not self._neon_tx_dict.pop(tx.key.value, None):
            LOG.warning(f'attempt to remove the not-existent {tx}')

    def done_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        if tx.is_done():
            LOG.warning(f'attempt to done the completed tx {tx}')
            return

        tx.mark_done(self.block_slot)
        self._done_neon_tx_list.append(tx)

    def done_alt_info(self, alt_info: NeonIndexedAltInfo, alt_ix_list: List[SolAltIxInfo]) -> None:
        assert alt_info.alt_key in self._sol_alt_info_dict

        self.add_alt_ix_list(alt_info, alt_ix_list)
        self._sol_alt_info_dict.pop(alt_info.alt_key)

    def add_alt_ix_list(self, alt_info: NeonIndexedAltInfo, alt_ix_list: List[SolAltIxInfo]) -> None:
        assert alt_info.alt_key in self._sol_alt_info_dict

        for alt_ix in alt_ix_list:
            self._sol_tx_cost_list.append(alt_ix.sol_tx_cost)
            self._sol_alt_ix_list.append(alt_ix)
            alt_info.set_last_ix_slot(alt_ix.block_slot)

    def iter_stuck_neon_holder(self) -> Iterator[NeonIndexedHolderInfo]:
        assert self._is_stuck_completed
        return iter(self._stuck_neon_holder_list)

    def iter_stuck_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        assert self._is_stuck_completed
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

    @property
    def sol_alt_info_cnt(self) -> int:
        return len(self._sol_alt_info_dict)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        return iter(self._sol_neon_ix_list)

    def iter_sol_alt_ix(self) -> Iterator[SolAltIxInfo]:
        return iter(self._sol_alt_ix_list)

    def iter_sol_tx_cost(self) -> Iterator[SolTxCostInfo]:
        return iter(self._sol_tx_cost_list)

    def iter_done_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        if self._has_corrupted_tx:
            # don't override db with corrupted data
            return iter(())
        return iter(self._done_neon_tx_list)

    def iter_alt_info(self) -> Iterator[NeonIndexedAltInfo]:
        return iter(self._sol_alt_info_dict.values())

    def iter_stat_neon_tx(self, config: Config) -> Iterator[NeonTxStatData]:
        if not len(self._stat_neon_tx_dict):
            if len(self._sol_neon_ix_list):
                self._calc_evm_tx_stat(config)
            if len(self._sol_alt_ix_list):
                self._calc_alt_tx_stat(config)
        return iter(self._stat_neon_tx_dict.values())

    def _calc_evm_tx_stat(self, config: Config) -> None:
        prev_sol_sig = ''
        for sol_neon_ix in self._sol_neon_ix_list:
            tx = self._neon_tx_dict.get(NeonIndexedTxInfo.Key(sol_neon_ix.neon_tx_sig).value, None)
            stat = self._stat_neon_tx_dict.get(sol_neon_ix.ix_code, None)
            if stat is None:
                stat = NeonTxStatData(tx_type=EvmIxCodeName().get(sol_neon_ix.ix_code))
                self._stat_neon_tx_dict[sol_neon_ix.ix_code] = stat

            neon_income = 0
            if tx is not None:
                neon_income = sol_neon_ix.neon_gas_used * tx.neon_tx.gas_price

            sol_spent = 0
            is_op_sol_neon_ix = False

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

    def _calc_alt_tx_stat(self, config: Config) -> None:
        prev_sol_sig = ''

        for alt_ix in self._sol_alt_ix_list:
            sol_sig = alt_ix.sol_sig
            if sol_sig == prev_sol_sig:
                continue
            prev_sol_sig = sol_sig

            ix_code = 100_000 + alt_ix.ix_code
            stat = self._stat_neon_tx_dict.get(ix_code, None)
            if stat is None:
                stat = NeonTxStatData(tx_type=AltIxCodeName().get(alt_ix.ix_code))
                self._stat_neon_tx_dict[ix_code] = stat
            stat.sol_tx_cnt += 1

            sol_spent = alt_ix.sol_tx_cost.sol_spent
            if alt_ix.sol_tx_cost.operator in config.operator_account_set:
                stat.op_sol_spent += sol_spent

    def complete_block(self) -> None:
        assert not self._is_completed
        self._is_completed = True
        self._finalize_log_list()

    def _finalize_log_list(self) -> None:
        log_idx = 0
        tx_idx = 0
        sum_gas_used = 0
        for tx in self._done_neon_tx_list:
            self._del_neon_tx(tx)
            if self._has_corrupted_tx:
                continue
            elif tx.is_corrupted():
                LOG.warning(f'corrupted tx: {tx}')
                self._has_corrupted_tx = True
                continue

            tx.complete_event_list()
            sum_gas_used += tx.neon_tx_res.gas_used
            log_idx = tx.neon_tx_res.set_block_info(self._sol_block, tx.neon_tx.sig, tx_idx, log_idx, sum_gas_used)
            tx_idx += 1

    def check_stuck_objs(self, config: Config) -> None:
        if self._is_stuck_completed:
            return

        self._is_stuck_completed = True
        self._check_stuck_holders(config)
        self._check_stuck_txs(config)
        self._check_stuck_alts(config)

    def has_stuck_objs(self) -> bool:
        assert self._is_stuck_completed

        return (
            len(self._stuck_neon_tx_list) > 0 or
            len(self._stuck_neon_holder_list) > 0 or
            len(self._sol_alt_info_dict) > 0
        )

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

    def _check_stuck_alts(self, config: Config) -> None:
        block_slot = self.block_slot
        stuck_block_slot = block_slot - config.alt_freeing_depth * 4
        if stuck_block_slot < 0:
            return

        for alt_info in self._sol_alt_info_dict.values():
            if stuck_block_slot > alt_info.block_slot:
                alt_info.mark_stuck()


class NeonIndexedBlockDict:
    def __init__(self):
        self._neon_block_dict: Dict[int, NeonIndexedBlockInfo] = dict()
        self._finalized_neon_block: Optional[NeonIndexedBlockInfo] = None
        self._min_block_slot = 0

    @property
    def finalized_neon_block(self) -> Optional[NeonIndexedBlockInfo]:
        return self._finalized_neon_block

    @property
    def min_block_slot(self) -> int:
        return self._min_block_slot

    def clear(self):
        self._neon_block_dict.clear()
        self._finalized_neon_block = None
        self._min_block_slot = 0

    def find_neon_block(self, block_slot: int) -> Optional[NeonIndexedBlockInfo]:
        return self._neon_block_dict.get(block_slot, None)

    def add_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if neon_block.block_slot in self._neon_block_dict:
            return

        self._neon_block_dict[neon_block.block_slot] = neon_block
        # LOG.debug(f'add block {neon_block.block_slot}')

    def finalize_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        assert neon_block.block_slot in self._neon_block_dict

        if self._finalized_neon_block is not None:
            for block_slot in range(self._finalized_neon_block.block_slot, neon_block.block_slot):
                self._neon_block_dict.pop(block_slot, None)

        # LOG.debug(f'finalize block {neon_block.block_slot}')
        self._finalized_neon_block = neon_block
        self._min_block_slot = neon_block.min_block_slot


class SolNeonDecoderStat:
    sol_tx_meta_cnt: int = 0
    sol_neon_ix_cnt: int = 0
    sol_block_cnt: int = 0
    neon_corrupted_block_cnt: int = 0

    _in_process: bool = False
    _start_time: float = 0.0
    _total_time: float = 0.0

    def reset(self) -> None:
        self._start_time = time.time()
        self._total_time = 0.0
        self.sol_neon_ix_cnt = 0
        self.sol_tx_meta_cnt = 0
        self.sol_block_cnt = 0
        self.neon_corrupted_block_cnt = 0

    def start_timer(self) -> None:
        self.commit_timer()
        self._in_process = True
        self._start_time = time.time()

    def commit_timer(self) -> None:
        if self._in_process:
            self._total_time = self.processing_time_ms
            self._in_process = False

    @property
    def processing_time_ms(self) -> float:
        time_diff = self._total_time
        if self._in_process:
            time_diff += (time.time() - self._start_time) * 1000
        return time_diff

    def inc_sol_neon_ix_cnt(self) -> None:
        self.sol_neon_ix_cnt += 1

    def add_sol_tx_meta_cnt(self, value: int) -> None:
        self.sol_tx_meta_cnt += value

    def inc_sol_block_cnt(self) -> None:
        self.sol_block_cnt += 1

    def inc_neon_corrupted_block_cnt(self) -> None:
        self.neon_corrupted_block_cnt += 1


class SolNeonDecoderCtx:
    # Iterate:
    #   for solana_block in block_range(start_block_slot, stop_block_slot):
    #       for solana_tx in solana_block.solana_tx_list:
    #           for solana_ix in solana_tx.solana_ix_list:
    #               solana_ix.level <- level in stack of calls
    #  ....
    def __init__(self, config: Config, stat: SolNeonDecoderStat):
        self._config = config
        self._stat = stat

        self._start_slot = 0
        self._stop_slot = 0
        self._sol_commit = SolCommit.NotProcessed
        self._is_finalized = False

        self._sol_tx_meta: Optional[SolTxMetaInfo] = None
        self._sol_neon_ix: Optional[SolNeonIxReceiptInfo] = None

        self._neon_block: Optional[NeonIndexedBlockInfo] = None
        self._neon_block_queue: List[NeonIndexedBlockInfo] = list()

    def __str__(self) -> str:
        return str_fmt_object(dict(
            start_slot=self._start_slot,
            stop_slot=self._stop_slot,
            sol_commit=self._sol_commit,
            block=self._neon_block.block_slot if self.has_neon_block() else None
        ))

    def set_slot_range(self, start_slot: int, stop_slot: int, sol_commit: SolCommit.Type) -> None:
        self._start_slot = start_slot
        self._stop_slot = stop_slot
        self._sol_commit = sol_commit
        self._is_finalized = sol_commit == SolCommit.Finalized

    def set_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        self._neon_block = neon_block

    @property
    def start_slot(self) -> int:
        return self._start_slot

    @property
    def stop_slot(self) -> int:
        return self._stop_slot

    @property
    def sol_commit(self) -> SolCommit.Type:
        return self._sol_commit

    def is_finalized(self) -> bool:
        return self._is_finalized

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        assert self._neon_block is not None
        return self._neon_block

    def has_neon_block(self) -> bool:
        return self._neon_block is not None

    def complete_neon_block(self) -> None:
        def _last_neon_block_slot() -> int:
            if not len(self._neon_block_queue):
                return self._start_slot - 1
            return self._neon_block_queue[-1].block_slot

        assert self._neon_block.block_slot > _last_neon_block_slot()
        self._neon_block_queue.append(self._neon_block)

        if (not self._neon_block.is_done) and self._neon_block.is_corrupted:
            self._stat.inc_neon_corrupted_block_cnt()

        self._neon_block = None

    def is_neon_block_queue_empty(self) -> bool:
        return len(self._neon_block_queue) == 0

    def is_neon_block_queue_full(self) -> bool:
        return self._config.indexer_poll_block_cnt <= len(self._neon_block_queue)

    def clear_neon_block_queue(self) -> None:
        self._neon_block_queue.clear()

    def iter_sol_neon_tx_meta(self, sol_block: SolBlockInfo) -> Generator[SolTxMetaInfo, None, None]:
        try:
            self._stat.inc_sol_block_cnt()
            self._stat.add_sol_tx_meta_cnt(len(sol_block.tx_receipt_list))
            for tx_receipt in sol_block.tx_receipt_list:
                if not self._has_sol_neon_ix(tx_receipt):
                    continue

                self._sol_tx_meta = SolTxMetaInfo.from_tx_receipt(sol_block.block_slot, tx_receipt)
                yield self._sol_tx_meta
        finally:
            self._sol_tx_meta = None

    @staticmethod
    def _has_sol_neon_ix(tx_receipt: Dict[str, Any]) -> bool:
        """Programs can be only in the read-only part of the message:accountKeys"""
        msg = get_from_dict(tx_receipt, ('transaction', 'message'), None)
        if msg is None:
            return False

        ro_key_cnt = get_from_dict(msg, ('header', 'numReadonlyUnsignedAccounts'), 0)
        if ro_key_cnt == 0:
            return False

        acct_key_list = msg.get('accountKeys', None)
        if acct_key_list is None:
            return False

        key_list_len = len(acct_key_list)
        start_ro_pos = key_list_len - ro_key_cnt

        for acct_idx, acct in enumerate(acct_key_list[start_ro_pos:]):
            if acct == EVM_PROGRAM_ID_STR:
                return True

        return False

    @property
    def sol_neon_ix(self) -> SolNeonIxReceiptInfo:
        # assert self._sol_neon_ix is not None
        return cast(SolNeonIxReceiptInfo, self._sol_neon_ix)

    def iter_sol_neon_ix(self) -> Generator[SolNeonIxReceiptInfo, None, None]:
        # assert self._sol_tx_meta is not None

        try:
            sol_neon_tx = SolNeonTxReceiptInfo.from_tx_meta(self._sol_tx_meta)
            for self._sol_neon_ix in sol_neon_tx.iter_sol_neon_ix():
                self._stat.inc_sol_neon_ix_cnt()
                yield self._sol_neon_ix
        finally:
            self._sol_neon_ix = None

    @property
    def neon_block_queue(self) -> List[NeonIndexedBlockInfo]:
        return self._neon_block_queue
