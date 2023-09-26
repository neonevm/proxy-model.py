from __future__ import annotations

import logging
import re
import weakref

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Union, Iterator, Generator, List, Any, Tuple, cast

import base58

from .utils.evm_log_decoder import decode_log_list, NeonLogInfo, NeonLogTxReturn, NeonLogTxEvent
from .utils.utils import str_fmt_object, cached_method, cached_property, get_from_dict
from .solana_tx import SolTxReceipt, SolPubKey
from .constants import COMPUTE_BUDGET_ID, EVM_PROGRAM_ID
from .neon_instruction import ComputeBudgetIxCode


LOG = logging.getLogger(__name__)


def _def_SolPubKey() -> str:
    return str(SolPubKey.default())


@dataclass(frozen=True)
class SolTxSigSlotInfo:
    sol_sig: str
    block_slot: int

    @cached_method
    def __str__(self) -> str:
        return f'{self.block_slot}:{self.sol_sig}'

    @cached_method
    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, SolTxSigSlotInfo) and
            other.block_slot == self.block_slot and
            other.sol_sig == self.sol_sig
        )


@dataclass(frozen=True)
class SolTxMetaInfo:
    ident: SolTxSigSlotInfo

    block_slot: int
    sol_sig: str
    tx: Dict[str, Any]

    @staticmethod
    def from_tx_receipt(block_slot: Optional[int], tx_receipt: Dict[str, Any]) -> SolTxMetaInfo:
        if block_slot is None:
            block_slot = tx_receipt.get('slot', 0)
        sol_sig = get_from_dict(tx_receipt, ('transaction', 'signatures', 0), _def_SolPubKey())
        sol_sig_slot = SolTxSigSlotInfo(sol_sig=sol_sig, block_slot=block_slot)

        return SolTxMetaInfo(
            ident=sol_sig_slot,
            block_slot=block_slot,
            sol_sig=sol_sig,
            tx=tx_receipt,
        )

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self.ident)

    @cached_property
    def is_success(self) -> bool:
        return get_from_dict(self.tx, ('meta', 'err'), None) is None

    @cached_property
    def ix_meta_list(self) -> List[SolIxMetaInfo]:
        raw_ix_list = get_from_dict(self.tx, ('transaction', 'message', 'instructions'), None)
        if raw_ix_list is None:
            return list()

        return [
            SolIxMetaInfo.from_tx_meta(self, idx, None, ix)
            for idx, ix in enumerate(raw_ix_list)
        ]

    @cached_property
    def _inner_ix_meta_list(self) -> List[List[SolIxMetaInfo]]:
        raw_inner_ix_list = get_from_dict(self.tx, ('meta', 'innerInstructions'), None)
        if raw_inner_ix_list is None:
            return list()

        inner_ix_meta_list: List[List[SolIxMetaInfo]] = [list() for _ in self.ix_meta_list]
        for raw_inner_ix in raw_inner_ix_list:
            idx = raw_inner_ix.get('index', None)
            raw_ix_list = raw_inner_ix.get('instructions', None)
            if (idx is None) or (raw_ix_list is None):
                continue

            ix_meta_list = [
                SolIxMetaInfo.from_tx_meta(self, idx, inner_idx, ix)
                for inner_idx, ix in enumerate(raw_ix_list)
            ]
            inner_ix_meta_list[idx] = ix_meta_list
        return inner_ix_meta_list

    def inner_ix_meta_list(self, ix_meta: SolIxMetaInfo) -> List[SolIxMetaInfo]:
        inner_ix_meta_list = self._inner_ix_meta_list
        if ix_meta.idx >= len(inner_ix_meta_list):
            return list()

        return inner_ix_meta_list[ix_meta.idx]

    @cached_property
    def account_key_list(self) -> List[str]:
        acct_key_list = get_from_dict(self.tx, ('transaction', 'message', 'accountKeys'), None)
        if acct_key_list is None:
            return list()

        lookup_key_list = get_from_dict(self.tx, ('meta', 'loadedAddresses'), None)
        if lookup_key_list is not None:
            acct_key_list.extend(lookup_key_list.get('writable', list()))
            acct_key_list.extend(lookup_key_list.get('readonly', list()))

        return acct_key_list

    @cached_property
    def alt_key_list(self) -> List[str]:
        alt_list = get_from_dict(self.tx, ('transaction', 'message', 'addressTableLookups'), None)
        if alt_list is None:
            return list()

        return [a.get('accountKey', _def_SolPubKey()) for a in alt_list]

    @cached_property
    def signer(self) -> str:
        acct_key_list = self.account_key_list
        if not len(acct_key_list):
            return _def_SolPubKey()
        return acct_key_list[0]

    @cached_property
    def sol_tx_cost(self) -> SolTxCostInfo:
        return SolTxCostInfo.from_tx_meta(self)

    @cached_property
    def compute_budget(self) -> ComputeBudgetInfo:
        return ComputeBudgetInfo.from_tx_meta(self)


@dataclass(frozen=True)
class SolIxMetaInfo:
    tx_meta: weakref.CallableProxyType[SolTxMetaInfo]

    idx: int
    inner_idx: Optional[int]
    ix: Dict[str, Any]

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo, idx: int, inner_idx: Optional[int], ix: Dict[str, Any]) -> SolIxMetaInfo:
        return SolIxMetaInfo(weakref.proxy(tx_meta), idx, inner_idx, ix)

    @cached_method
    def __str__(self) -> str:
        return ':'.join([str(s) for s in self.ident])

    @cached_property
    def ident(self):
        if self.inner_idx is None:
            return self.tx_meta.sol_sig, self.tx_meta.block_slot, self.idx
        else:
            return self.tx_meta.sol_sig, self.tx_meta.block_slot, self.idx, cast(int, self.inner_idx)

    @property
    def sol_sig(self) -> str:
        return self.tx_meta.sol_sig

    @property
    def block_slot(self) -> int:
        return self.tx_meta.block_slot

    @cached_property
    def program_key(self) -> SolPubKey:
        program_idx = self.ix.get('programIdIndex', None)
        if program_idx is None:
            LOG.warning(f'{self.tx_meta}: fail to get program id')
            return SolPubKey.default()

        acct_key_list = self.tx_meta.account_key_list
        if program_idx > len(acct_key_list):
            LOG.warning(f'{self.tx_meta}: program index greater than the length of the list of accounts')
            return SolPubKey.default()
        return SolPubKey.from_string(acct_key_list[program_idx])

    @cached_property
    def ix_data(self) -> Optional[bytes]:
        ix_data = self.ix.get('data', None)
        return base58.b58decode(ix_data) if ix_data is not None else None

    def has_ix_data(self) -> bool:
        ix_data = self.ix.get('data', None)
        return (ix_data is not None) and (len(ix_data) > 1)

    def is_program(self, program_key: SolPubKey) -> bool:
        return program_key == self.program_key


@dataclass(frozen=True)
class _SolIxSuccessLog:
    program_key: SolPubKey


@dataclass(frozen=True)
class _SolIxFailedLog:
    program_key: SolPubKey
    error: str


@dataclass(frozen=True)
class _SolIxInvokeLog:
    program_key: SolPubKey
    level: int


@dataclass(frozen=True)
class _SolIxBFPUsageLog:
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int


@dataclass(frozen=True)
class _SolIxHeapUsageLog:
    used_heap_size: int


@dataclass(frozen=True)
class SolIxLogState:
    class Status(Enum):
        Unknown = 0
        Success = 1
        Failed = 2

    program_key: SolPubKey
    level: int

    max_bpf_cycle_cnt: int = 0
    used_bpf_cycle_cnt: int = 0
    used_heap_size: int = 0

    status: Status = Status.Unknown
    error: Optional[str] = None

    log_list: List[Union[str, SolIxLogState]] = None
    inner_log_list: List[SolIxLogState] = None

    def __post_init__(self):
        object.__setattr__(self, 'log_list', list())
        self.set_inner_log_list(list())

    def __str__(self) -> str:
        return str_fmt_object(self)

    def set_inner_log_list(self, inner_log_list: List[SolIxLogState]) -> None:
        object.__setattr__(self, 'inner_log_list', inner_log_list)

    def set_success(self, status: _SolIxSuccessLog) -> None:
        assert self.status == self.Status.Unknown
        assert self.program_key == status.program_key

        object.__setattr__(self, 'status', self.Status.Success)

    def set_failed(self, status: _SolIxFailedLog) -> None:
        assert self.status == self.Status.Unknown
        assert self.program_key == status.program_key

        object.__setattr__(self, 'status', self.Status.Failed)
        object.__setattr__(self, 'error', status.error)

    def set_bpf_cycle_usage(self, stat: _SolIxBFPUsageLog) -> None:
        assert self.max_bpf_cycle_cnt == 0
        assert self.used_bpf_cycle_cnt == 0

        object.__setattr__(self, 'max_bpf_cycle_cnt', stat.max_bpf_cycle_cnt)
        object.__setattr__(self, 'used_bpf_cycle_cnt', stat.used_bpf_cycle_cnt)

    def set_heap_usage(self, stat: _SolIxHeapUsageLog) -> None:
        assert self.used_heap_size == 0

        object.__setattr__(self, 'used_heap_size', stat.used_heap_size)

    def iter_str_log_msg(self) -> Generator[str, None, None]:
        for log_msg in self.log_list:
            if isinstance(log_msg, str):
                yield log_msg


class SolTxLogDecoder:
    _invoke_re = re.compile(r'^Program (\w+) invoke \[(\d+)]$')
    _success_re = re.compile(r'^Program (\w+) success$')
    _failed_re = re.compile(r'^Program (\w+) failed: (.+)$')
    _bpf_cycle_cnt_re = re.compile(r'^Program (\w+) consumed (\d+) of (\d+) compute units$')
    _heap_size_re = re.compile(r'^Program log: Total memory occupied: (\d+)$')

    def decode(self, log_msg_list: List[str]) -> SolIxLogState:
        log_state = SolIxLogState(SolPubKey.default(), 0)
        self._decode(log_state, iter(log_msg_list))
        return log_state

    def _decode(self, log_state: SolIxLogState, log_msg_iter: Iterator[str]) -> None:
        for log_msg in log_msg_iter:
            if self._decode_invoke(log_state, log_msg, log_msg_iter):
                continue

            if self._decode_success(log_state, log_msg):
                return

            elif self._decode_failed(log_state, log_msg):
                return

            elif self._decode_bpf_cycle_usage(log_state, log_msg):
                continue

            elif self._decode_heap_usage(log_state, log_msg):
                continue

            log_state.log_list.append(log_msg)
        return None

    def _decode_invoke(self, log_state: SolIxLogState, log_msg: str, log_msg_iter: Iterator[str]) -> bool:
        match = self._invoke_re.match(log_msg)
        if match is None:
            return False

        invoke = _SolIxInvokeLog(program_key=SolPubKey.from_string(match[1]), level=int(match[2]))
        ix_log_state = SolIxLogState(invoke.program_key, invoke.level)

        log_state.log_list.append(ix_log_state)
        log_state.inner_log_list.append(ix_log_state)

        self._decode(ix_log_state, log_msg_iter)
        log_state.inner_log_list.extend(ix_log_state.inner_log_list)

        return True

    def _decode_success(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._success_re.match(log_msg)
        if match is None:
            return False

        success = _SolIxSuccessLog(program_key=SolPubKey.from_string(match[1]))
        log_state.set_success(success)
        return True

    def _decode_failed(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._failed_re.match(log_msg)
        if match is None:
            return False

        failed = _SolIxFailedLog(program_key=SolPubKey.from_string(match[1]), error=match[2])
        log_state.set_failed(failed)
        return True

    def _decode_bpf_cycle_usage(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._bpf_cycle_cnt_re.match(log_msg)
        if match is None:
            return False

        stat = _SolIxBFPUsageLog(used_bpf_cycle_cnt=int(match[2]), max_bpf_cycle_cnt=int(match[3]))
        log_state.set_bpf_cycle_usage(stat)
        return True

    def _decode_heap_usage(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._heap_size_re.match(log_msg)
        if match is None:
            return False

        stat = _SolIxHeapUsageLog(used_heap_size=int(match[1]))
        log_state.set_heap_usage(stat)
        return True


@dataclass(frozen=True)
class ComputeBudgetInfo:
    max_heap_size: int
    max_bpf_cycle_cnt: int

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> ComputeBudgetInfo:
        max_bpf_cycle_cnt = 200_000
        max_heap_size = 32 * 1024

        for ix_meta in tx_meta.ix_meta_list:
            if not ix_meta.is_program(COMPUTE_BUDGET_ID):
                continue

            try:
                ix_data = ix_meta.ix_data
                ix_code = ix_data[0]
                ix_data = ix_data[1:]
                if ix_code == ComputeBudgetIxCode.HeapRequest:
                    max_heap_size = int.from_bytes(ix_data, 'little')
                elif ix_code == ComputeBudgetIxCode.CURequest:
                    max_bpf_cycle_cnt = int.from_bytes(ix_data, 'little')
            except BaseException as exc:
                LOG.warning(f'Exception on decode ComputeBudget ixs', exc_info=exc)
                continue

        return ComputeBudgetInfo(max_heap_size=max_heap_size, max_bpf_cycle_cnt=max_bpf_cycle_cnt)


@dataclass(frozen=True)
class SolTxCostInfo:
    sol_sig: str
    block_slot: int
    operator: str
    sol_spent: int

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> SolTxCostInfo:
        pre_balance = get_from_dict(tx_meta.tx, ('meta', 'preBalances', 0), 0)
        post_balance = get_from_dict(tx_meta.tx, ('meta', 'postBalances', 0), 0)

        return SolTxCostInfo(
            sol_sig=tx_meta.sol_sig,
            block_slot=tx_meta.block_slot,
            operator=tx_meta.signer,
            sol_spent=(pre_balance - post_balance),
        )

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)


@dataclass(frozen=True)
class SolAltIxInfo:
    block_slot: int
    sol_sig: str
    idx: int
    inner_idx: Optional[int]
    is_success: bool
    ix_code: int
    alt_address: str

    neon_tx_sig: str

    sol_tx_cost: SolTxCostInfo

    @staticmethod
    def from_ix_meta(ix_meta: SolIxMetaInfo, ix_code: int, alt_address: str, neon_tx_sig: str) -> SolAltIxInfo:
        return SolAltIxInfo(
            block_slot=ix_meta.tx_meta.block_slot,
            sol_sig=ix_meta.tx_meta.sol_sig,
            idx=ix_meta.idx,
            inner_idx=ix_meta.inner_idx,
            is_success=ix_meta.tx_meta.is_success,
            ix_code=ix_code,
            alt_address=alt_address,
            neon_tx_sig=neon_tx_sig,
            sol_tx_cost=ix_meta.tx_meta.sol_tx_cost
        )

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)


@dataclass(frozen=True)
class _SolIxData:
    ix_code: Optional[int]
    ix_data: bytes


@dataclass(frozen=True)
class SolNeonIxReceiptInfo:
    ident: Union[Tuple[str, int, int, int], Tuple[str, int, int]]

    sol_sig: str
    block_slot: int
    idx: int
    inner_idx: Optional[int]
    ix_code: int
    ix_data: bytes
    is_success: bool

    max_heap_size: int
    used_heap_size: int
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int

    neon_tx_sig: str
    neon_step_cnt: int
    neon_gas_used: int
    neon_total_gas_used: int

    sol_tx_cost: SolTxCostInfo

    _acct_list: List[int] = None
    _log_info: Optional[NeonLogInfo] = None
    _tx_meta: weakref.CallableProxyType[SolTxMetaInfo] = None

    @staticmethod
    def from_ix_meta(ix_meta: SolIxMetaInfo, log_state: SolIxLogState) -> SolNeonIxReceiptInfo:
        log_info = decode_log_list(log_state.iter_str_log_msg())

        is_success = ix_meta.tx_meta.is_success and (log_state.status == SolIxLogState.Status.Success)

        max_bpf_cycle_cnt = log_state.max_bpf_cycle_cnt
        if not max_bpf_cycle_cnt:
            max_bpf_cycle_cnt = ix_meta.tx_meta.compute_budget.max_bpf_cycle_cnt

        used_heap_size = log_state.used_heap_size
        if not used_heap_size:
            used_heap_size = ix_meta.tx_meta.compute_budget.max_heap_size

        neon_tx_sig = '0x' + log_info.neon_tx_sig.neon_sig.hex() if log_info.neon_tx_sig else ''

        neon_ix_gas_usage = 0
        neon_ix_total_gas_usage = 0
        if log_info.neon_tx_ix is not None:
            neon_ix_gas_usage = log_info.neon_tx_ix.gas_used
            neon_ix_total_gas_usage = log_info.neon_tx_ix.total_gas_used

        acct_list = ix_meta.ix.get('accounts', list())

        ix_data = SolNeonIxReceiptInfo._decode_ix_data(ix_meta)

        return SolNeonIxReceiptInfo(
            ident=ix_meta.ident,

            sol_sig=ix_meta.tx_meta.sol_sig,
            block_slot=ix_meta.tx_meta.block_slot,
            idx=ix_meta.idx,
            inner_idx=ix_meta.inner_idx,
            ix_code=ix_data.ix_code,
            ix_data=ix_data.ix_data,
            is_success=is_success,

            max_bpf_cycle_cnt=max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=log_state.used_bpf_cycle_cnt,
            used_heap_size=used_heap_size,
            max_heap_size=ix_meta.tx_meta.compute_budget.max_heap_size,

            sol_tx_cost=ix_meta.tx_meta.sol_tx_cost,

            neon_tx_sig=neon_tx_sig,
            neon_step_cnt=0,
            neon_gas_used=neon_ix_gas_usage,
            neon_total_gas_used=neon_ix_total_gas_usage,

            _acct_list=acct_list,
            _log_info=log_info,
            _tx_meta=ix_meta.tx_meta
        )

    @cached_method
    def __str__(self) -> str:
        return ':'.join([str(s) for s in self.ident])

    def __eq__(self, other: SolNeonIxReceiptInfo) -> bool:
        return self.ident == other.ident

    @cached_property
    def req_id(self) -> str:
        return '_'.join([s[:7] if isinstance(s, str) else str(s) for s in self.ident])

    @staticmethod
    def _decode_ix_data(ix_meta: SolIxMetaInfo) -> _SolIxData:
        try:
            ix_data = ix_meta.ix_data
            if len(ix_data) > 0:
                return _SolIxData(ix_code=int(ix_data[0]), ix_data=ix_data)
            else:
                return _SolIxData(ix_code=-1, ix_data=b'')
        except BaseException as exc:
            LOG.warning(f'{ix_meta}: fail to get a program instruction ', exc_info=exc)
            return _SolIxData(ix_code=-1, ix_data=b'')

    def set_neon_step_cnt(self, value: int) -> None:
        assert self.neon_step_cnt == 0
        object.__setattr__(self, 'neon_step_cnt', value)

    @property
    def neon_tx_return(self) -> Optional[NeonLogTxReturn]:
        assert self._log_info, 'Method available only on parsing data from Solana node'
        return self._log_info.neon_tx_return

    @property
    def neon_tx_event_list(self) -> List[NeonLogTxEvent]:
        assert self._log_info, 'Method available only on parsing data from Solana node'
        return self._log_info.neon_tx_event_list

    @property
    def is_log_truncated(self) -> bool:
        assert self._log_info, 'Method available only on parsing data from Solana node'
        return self._log_info.is_truncated

    @property
    def is_already_finalized(self) -> bool:
        assert self._log_info, 'Method available only on parsing data from Solana node'
        return self._log_info.is_already_finalized

    @property
    def account_cnt(self) -> int:
        assert self._tx_meta, 'Method available only on parsing data from Solana node'
        return len(self._acct_list)

    def get_account(self, acct_idx: int) -> str:
        assert self._tx_meta, 'Method available only on parsing data from Solana node'
        if len(self._acct_list) > acct_idx:
            key_idx = self._acct_list[acct_idx]
            acct_key_list = self._tx_meta.account_key_list
            if len(acct_key_list) > key_idx:
                return acct_key_list[key_idx]
        return _def_SolPubKey()

    def iter_account_key(self, start_idx: int) -> Generator[str, None, None]:
        assert self._tx_meta, 'Method available only on parsing data from Solana node'

        acct_key_list = self._tx_meta.account_key_list
        for idx in self._acct_list[start_idx:]:
            yield acct_key_list[idx]

    def iter_alt_key(self) -> Iterator[str]:
        assert self._tx_meta, 'Method available only on parsing data from Solana node'
        return iter(self._tx_meta.alt_key_list)


@dataclass(frozen=True)
class SolNeonTxReceiptInfo:
    _tx_meta: SolTxMetaInfo

    @staticmethod
    def from_tx_receipt(block_slot: int, tx: SolTxReceipt) -> SolNeonTxReceiptInfo:
        tx_meta = SolTxMetaInfo.from_tx_receipt(block_slot, tx)
        return SolNeonTxReceiptInfo.from_tx_meta(tx_meta)

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> SolNeonTxReceiptInfo:
        return SolNeonTxReceiptInfo(_tx_meta=tx_meta)

    def __str__(self) -> str:
        return self._tx_meta.__str__()

    @staticmethod
    def _add_missing_log_msgs(log_state_list: List[SolIxLogState],
                              ix_list: List[SolIxMetaInfo],
                              level: int) -> List[SolIxLogState]:
        base_level = level

        def calc_level() -> int:
            if base_level == 1:
                return 1
            return level + 1

        result_log_state_list: List[SolIxLogState] = list()

        iter_log = iter(log_state_list)
        log = next(iter_log) if len(log_state_list) > 0 else None
        for ix_meta in ix_list:
            if (log is None) or (log.program_key != ix_meta.program_key):
                result_log_state_list.append(SolIxLogState(ix_meta.program_key, calc_level()))
            else:
                level = log.level
                result_log_state_list.append(log)
                log = next(iter_log, None)

        assert len(result_log_state_list) == len(ix_list), f'{len(result_log_state_list)} == {len(ix_list)}'
        assert log is None
        return result_log_state_list

    @cached_property
    def _ix_log_msg_list(self) -> List[SolIxLogState]:
        raw_log_msg_list = get_from_dict(self._tx_meta.tx, ('meta', 'logMessages'), list())
        ix_log_msg_list: List[SolIxLogState] = list()

        log_state = SolTxLogDecoder().decode(raw_log_msg_list)
        ix_log_msg_list.extend(self._add_missing_log_msgs(log_state.log_list, self._tx_meta.ix_meta_list, 1))
        for ix_meta in self._tx_meta.ix_meta_list:
            inner_ix_meta_list = self._tx_meta.inner_ix_meta_list(ix_meta)
            if len(inner_ix_meta_list) == 0:
                continue

            log_state = ix_log_msg_list[ix_meta.idx]
            inner_log_msg_list = log_state.inner_log_list
            inner_log_msg_list = self._add_missing_log_msgs(inner_log_msg_list, inner_ix_meta_list, 2)
            log_state.set_inner_log_list(inner_log_msg_list)
        return ix_log_msg_list

    def get_ix_log_state(self, idx: int, inner_idx: Optional[int]) -> Optional[SolIxLogState]:
        ix_log_msg_list = self._ix_log_msg_list
        if idx >= len(ix_log_msg_list):
            LOG.warning(f'{self}: cannot find logs for instruction {idx} > {len(ix_log_msg_list)}')
            return None

        ix_log_list = ix_log_msg_list[idx]
        if inner_idx is None:
            return ix_log_list

        if inner_idx >= len(ix_log_list.inner_log_list):
            LOG.warning(
                f'{self}: cannot find logs for instruction'
                f' {idx}:{inner_idx} > {len(ix_log_list.inner_log_list)}'
            )
            return None
        return ix_log_list.inner_log_list[inner_idx]

    def iter_sol_neon_ix(self) -> Generator[SolNeonIxReceiptInfo, None, None]:
        def _init_sol_neon_ix(_ix_meta: SolIxMetaInfo) -> Optional[SolNeonIxReceiptInfo]:
            if not _ix_meta.is_program(EVM_PROGRAM_ID) or not _ix_meta.has_ix_data():
                return None

            log_state = self.get_ix_log_state(_ix_meta.idx, _ix_meta.inner_idx)
            if log_state is None:
                return None

            return SolNeonIxReceiptInfo.from_ix_meta(_ix_meta, log_state)

        for ix_meta in self._tx_meta.ix_meta_list:
            sol_neon_ix = _init_sol_neon_ix(ix_meta)
            if sol_neon_ix:
                yield sol_neon_ix

            for inner_ix_meta in self._tx_meta.inner_ix_meta_list(ix_meta):
                sol_neon_ix = _init_sol_neon_ix(inner_ix_meta)
                if sol_neon_ix:
                    yield sol_neon_ix
