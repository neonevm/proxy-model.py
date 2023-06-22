from __future__ import annotations

import logging
import re

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Union, Iterator, Generator, List, Any, Tuple, cast

import base58

from .utils.evm_log_decoder import decode_log_list, NeonLogTxReturn, NeonLogTxEvent
from .utils.utils import str_fmt_object
from .solana_tx import SolTxReceipt
from .constants import COMPUTE_BUDGET_ID


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolTxSigSlotInfo:
    sol_sig: str
    block_slot: int

    _str: str = ''
    _hash: int = 0

    def __str__(self) -> str:
        if self._str == '':
            _str = f'{self.block_slot}:{self.sol_sig}'
            object.__setattr__(self, '_str', _str)
        return self._str

    def __hash__(self) -> int:
        if self._hash == 0:
            object.__setattr__(self, '_hash', hash(str(self)))
        return self._hash

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

    _ix_list: Optional[List[Dict[str, Any]]]
    _inner_ix_list: Optional[List[Dict[str, Any]]]
    _account_key_list: Optional[List[str]]
    _signer: str

    _str: str
    _req_id: str

    @staticmethod
    def from_tx_receipt(block_slot: int, tx_receipt: Dict[str, Any]) -> SolTxMetaInfo:
        sol_sig = tx_receipt['transaction']['signatures'][0]
        sol_sig_slot = SolTxSigSlotInfo(sol_sig=sol_sig, block_slot=block_slot)
        return SolTxMetaInfo(sol_sig_slot, block_slot, sol_sig, tx_receipt, None, None, None, '', '', '')

    def __str__(self) -> str:
        if not len(self._str):
            _str = str_fmt_object(self.ident)
            object.__setattr__(self, '_str', _str)
        return self._str

    @property
    def req_id(self) -> str:
        if not len(self._req_id):
            req_id = f'{self.sol_sig[:7]}_{self.block_slot}'
            object.__setattr__(self, '_req_id', req_id)
        return self._req_id

    @property
    def ix_list(self) -> List[Dict[str, Any]]:
        if self._ix_list is None:
            object.__setattr__(self, '_ix_list', self.tx['transaction']['message']['instructions'])
        return self._ix_list

    @property
    def inner_ix_list(self) -> List[Dict[str, Any]]:
        if self._inner_ix_list is None:
            object.__setattr__(self, '_inner_ix_list', self.tx['meta']['innerInstructions'])
        return self._inner_ix_list

    @property
    def account_key_list(self) -> List[str]:
        if self._account_key_list is not None:
            return self._account_key_list

        msg = self.tx['transaction']['message']
        meta = self.tx['meta']

        account_key_list: List[str] = msg['accountKeys']
        lookup_key_list: Optional[Dict[str, List[str]]] = meta.get('loadedAddresses', None)
        if lookup_key_list is not None:
            account_key_list.extend(lookup_key_list['writable'])
            account_key_list.extend(lookup_key_list['readonly'])

        object.__setattr__(self, '_account_key_list', account_key_list)
        return account_key_list

    @property
    def signer(self) -> str:
        if not len(self._signer):
            object.__setattr__(self, '_signer', self.account_key_list[0])
        return self._signer

    def get_program_key(self, ix: Dict[str, Any]) -> str:
        program_idx = ix.get('programIdIndex', None)
        if program_idx is None:
            LOG.warning(f'{self} error: fail to get program id')
            return ''
        elif program_idx > len(self.account_key_list):
            LOG.warning(f'{self} error: program index greater than list of accounts')
            return ''

        return self.account_key_list[program_idx]

    def is_program(self, ix: Dict[str, Any], program_id: str) -> bool:
        return self.get_program_key(ix) == program_id


@dataclass(frozen=True)
class _SolIxSuccessLog:
    program: str


@dataclass(frozen=True)
class _SolIxFailedLog:
    program: str
    error: str


@dataclass(frozen=True)
class _SolIxInvokeLog:
    program: str
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

    program: str
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
        assert self.program == status.program

        object.__setattr__(self, 'status', self.Status.Success)

    def set_failed(self, status: _SolIxFailedLog) -> None:
        assert self.status == self.Status.Unknown
        assert self.program == status.program

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
        log_state = SolIxLogState('', 0)
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

        invoke = _SolIxInvokeLog(program=match[1], level=int(match[2]))
        ix_log_state = SolIxLogState(invoke.program, invoke.level)

        log_state.log_list.append(ix_log_state)
        log_state.inner_log_list.append(ix_log_state)

        self._decode(ix_log_state, log_msg_iter)
        log_state.inner_log_list.extend(ix_log_state.inner_log_list)

        return True

    def _decode_success(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._success_re.match(log_msg)
        if match is None:
            return False

        success = _SolIxSuccessLog(program=match[1])
        log_state.set_success(success)
        return True

    def _decode_failed(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._failed_re.match(log_msg)
        if match is None:
            return False

        failed = _SolIxFailedLog(program=match[1], error=match[2])
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
        compute_budget_id = str(COMPUTE_BUDGET_ID)

        for ix_idx, ix in enumerate(tx_meta.ix_list):
            if not tx_meta.is_program(ix, compute_budget_id):
                continue

            try:
                ix_data = base58.b58decode(ix.get('data', None))
                ix_code = ix_data[0]
                ix_data = ix_data[1:]
                if ix_code == 0x1:
                    max_heap_size = int.from_bytes(ix_data, 'little')
                elif ix_code == 0x2:
                    max_bpf_cycle_cnt = int.from_bytes(ix_data, 'little')
            except BaseException as exc:
                LOG.warning(f'Exception on decode ComputeBudget ixs', exc_info=exc)
                continue

        return ComputeBudgetInfo(max_heap_size=max_heap_size, max_bpf_cycle_cnt=max_bpf_cycle_cnt)


@dataclass(frozen=True)
class SolIxMetaInfo:
    class Status(Enum):
        Unknown = 0
        Success = 1
        Failed = 2

    ix: Dict[str, Any]
    idx: int
    inner_idx: Optional[int]

    program: str
    level: int
    status: Status
    error: Optional[str]

    used_heap_size: int
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int

    neon_tx_sig: str
    neon_gas_used: int
    neon_total_gas_used: int

    neon_tx_return: Optional[NeonLogTxReturn]
    neon_tx_event_list: List[NeonLogTxEvent]
    is_log_truncated: bool
    is_already_finalized: bool

    @staticmethod
    def from_log_state(ix: Dict[str, Any], idx: int,
                       inner_idx: Optional[int],
                       log_state: SolIxLogState) -> SolIxMetaInfo:
        log_info = decode_log_list(log_state.iter_str_log_msg())

        neon_tx_sig = ''
        if log_info.neon_tx_sig is not None:
            neon_tx_sig = '0x' + log_info.neon_tx_sig.neon_sig.hex()

        neon_ix_gas_usage = 0
        neon_ix_total_gas_usage = 0
        if log_info.neon_tx_ix is not None:
            neon_ix_gas_usage = log_info.neon_tx_ix.gas_used
            neon_ix_total_gas_usage = log_info.neon_tx_ix.total_gas_used

        status = SolIxMetaInfo.Status.Unknown
        if log_state.status == SolIxLogState.Status.Failed:
            status = SolIxMetaInfo.Status.Failed
        elif log_state.status == SolIxLogState.Status.Success:
            status = SolIxMetaInfo.Status.Success

        return SolIxMetaInfo(
            ix=ix,
            idx=idx,
            inner_idx=inner_idx,

            program=log_state.program,
            level=log_state.level,
            status=status,
            error=log_state.error,

            max_bpf_cycle_cnt=log_state.max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=log_state.used_bpf_cycle_cnt,
            used_heap_size=log_state.used_heap_size,

            neon_tx_sig=neon_tx_sig,
            neon_gas_used=neon_ix_gas_usage,
            neon_total_gas_used=neon_ix_total_gas_usage,
            neon_tx_return=log_info.neon_tx_return,
            neon_tx_event_list=log_info.neon_tx_event_list,
            is_log_truncated=log_info.is_truncated,
            is_already_finalized=log_info.is_already_finalized
        )


@dataclass(frozen=True)
class SolTxCostInfo:
    sol_sig: str
    block_slot: int
    operator: str
    sol_spent: int

    _str: str = ''

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> SolTxCostInfo:
        meta = tx_meta.tx['meta']

        return SolTxCostInfo(
            sol_sig=tx_meta.sol_sig,
            block_slot=tx_meta.block_slot,
            operator=tx_meta.signer,
            sol_spent=(meta['preBalances'][0] - meta['postBalances'][0]),
        )

    def __str__(self) -> str:
        if self._str == '':
            _str = str_fmt_object(self)
            object.__setattr__(self, '_str', _str)
        return self._str


@dataclass(frozen=True)
class SolNeonIxReceiptShortInfo:
    sol_sig: str
    block_slot: int
    idx: int
    inner_idx: Optional[int]
    ix_code: int
    is_success: bool
    neon_step_cnt: int
    neon_gas_used: int
    neon_total_gas_used: int
    max_heap_size: int
    used_heap_size: int
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int


@dataclass(frozen=True)
class _SolIxData:
    ix_code: Optional[int]
    ix_data: bytes


@dataclass(frozen=True)
class SolNeonIxReceiptInfo(SolIxMetaInfo):
    sol_sig: str
    block_slot: int

    ix_code: int
    ix_data: bytes

    max_heap_size: int
    neon_step_cnt: int

    sol_tx_cost: SolTxCostInfo

    ident: Union[Tuple[str, int, int, int], Tuple[str, int, int]]

    _str: str
    _req_id: str
    _account_list: List[int]
    _account_key_list: List[str]

    @staticmethod
    def from_ix(tx_meta: SolTxMetaInfo,
                tx_cost: SolTxCostInfo,
                compute_budget: ComputeBudgetInfo,
                ix_meta: SolIxMetaInfo) -> SolNeonIxReceiptInfo:
        account_list = ix_meta.ix['accounts']

        if ix_meta.inner_idx is None:
            ident = tx_meta.sol_sig, tx_meta.block_slot, ix_meta.idx
        else:
            ident = tx_meta.sol_sig, tx_meta.block_slot, ix_meta.idx, cast(int, ix_meta.inner_idx)

        ix_data = SolNeonIxReceiptInfo._decode_ix_data(ix_meta.ix)

        max_bpf_cycle_cnt = ix_meta.max_bpf_cycle_cnt
        if not max_bpf_cycle_cnt:
            max_bpf_cycle_cnt = compute_budget.max_bpf_cycle_cnt

        used_heap_size = ix_meta.used_heap_size
        if not used_heap_size:
            used_heap_size = compute_budget.max_heap_size

        return SolNeonIxReceiptInfo(
            ident=ident,

            sol_sig=tx_meta.sol_sig,
            block_slot=tx_meta.block_slot,

            ix=ix_meta.ix,
            idx=ix_meta.idx,
            inner_idx=ix_meta.inner_idx,

            program=ix_meta.program,
            level=ix_meta.level,
            status=ix_meta.status,
            error=ix_meta.error,
            ix_code=ix_data.ix_code,
            ix_data=ix_data.ix_data,

            max_bpf_cycle_cnt=max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=ix_meta.used_bpf_cycle_cnt,
            used_heap_size=used_heap_size,

            sol_tx_cost=tx_cost,

            neon_tx_sig=ix_meta.neon_tx_sig,
            neon_gas_used=ix_meta.neon_gas_used,
            neon_total_gas_used=ix_meta.neon_total_gas_used,
            neon_tx_return=ix_meta.neon_tx_return,
            neon_tx_event_list=ix_meta.neon_tx_event_list,
            is_log_truncated=ix_meta.is_log_truncated,
            is_already_finalized=ix_meta.is_already_finalized,
            neon_step_cnt=0,
            max_heap_size=compute_budget.max_heap_size,

            _str='',
            _req_id='',
            _account_list=account_list,
            _account_key_list=tx_meta.account_key_list,
        )

    def __str__(self) -> str:
        if self._str == '':
            _str = ':'.join([str(s) for s in self.ident])
            object.__setattr__(self, '_str', _str)
        return self._str

    def __eq__(self, other: SolNeonIxReceiptInfo) -> bool:
        return self.ident == other.ident

    @staticmethod
    def _decode_ix_data(ix: Dict[str, Any]) -> _SolIxData:
        ix_data = ix.get('data', None)
        try:
            if len(ix_data) > 0:
                ix_data = base58.b58decode(ix_data)
                return _SolIxData(ix_code=int(ix_data[0]), ix_data=ix_data)
            else:
                return _SolIxData(ix_code=None, ix_data=b'')
        except BaseException as exc:
            LOG.warning(f'Fail to get a program instruction', exc_info=exc)
            return _SolIxData(ix_code=int(ix_data[0]), ix_data=ix_data[1:])

    def set_neon_step_cnt(self, value: int) -> None:
        assert self.neon_step_cnt == 0
        object.__setattr__(self, 'neon_step_cnt', value)

    @property
    def account_cnt(self) -> int:
        return len(self._account_list)

    @property
    def req_id(self) -> str:
        if self._req_id == '':
            req_id = '_'.join([s[:7] if isinstance(s, str) else str(s) for s in self.ident])
            object.__setattr__(self, '_req_id', req_id)
        return self._req_id

    def get_account(self, account_idx: int) -> str:
        if len(self._account_list) > account_idx:
            key_idx = self._account_list[account_idx]
            if len(self._account_key_list) > key_idx:
                return self._account_key_list[key_idx]
        return ''

    def iter_account(self, start_idx: int) -> Generator[str, None, None]:
        for idx in self._account_list[start_idx:]:
            yield self._account_key_list[idx]


@dataclass(frozen=True)
class SolTxReceiptInfo(SolTxMetaInfo):
    _sol_tx_cost: Optional[SolTxCostInfo]
    _compute_budget: Optional[ComputeBudgetInfo]
    _ix_log_msg_list: Optional[List[SolIxLogState]]

    @staticmethod
    def from_tx_receipt(block_slot: int, tx: SolTxReceipt) -> SolTxReceiptInfo:
        tx_meta = SolTxMetaInfo.from_tx_receipt(block_slot, tx)
        return SolTxReceiptInfo.from_tx_meta(tx_meta, None)

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo, sol_tx_cost: Optional[SolTxCostInfo]) -> SolTxReceiptInfo:
        result = SolTxReceiptInfo(
            ident=tx_meta.ident,

            block_slot=tx_meta.block_slot,
            sol_sig=tx_meta.sol_sig,
            tx=tx_meta.tx,
            _ix_list=None,
            _inner_ix_list=None,
            _account_key_list=None,
            _str='',
            _req_id='',
            _signer='',

            _sol_tx_cost=sol_tx_cost,
            _compute_budget=None,
            _ix_log_msg_list=None,
        )

        return result

    @property
    def operator(self) -> str:
        return self.signer

    @property
    def sol_tx_cost(self) -> SolTxCostInfo:
        if self._sol_tx_cost is None:
            sol_tx_cost = SolTxCostInfo.from_tx_meta(self)
            object.__setattr__(self, '_sol_tx_cost', sol_tx_cost)
        return self._sol_tx_cost

    @property
    def compute_budget(self) -> ComputeBudgetInfo:
        if self._compute_budget is None:
            object.__setattr__(self, '_compute_budget', ComputeBudgetInfo.from_tx_meta(self))
        return self._compute_budget

    def _add_missing_log_msgs(self, log_state_list: List[SolIxLogState],
                              ix_list: List[Dict[str, Any]],
                              level: int) -> List[SolIxLogState]:
        base_level = level

        def calc_level() -> int:
            if base_level == 1:
                return 1
            return level + 1

        result_log_state_list: List[SolIxLogState] = list()

        log_iter = iter(log_state_list)
        log = next(log_iter) if len(log_state_list) > 0 else None
        for idx, ix in enumerate(ix_list):
            ix_program_key = self.get_program_key(ix)
            if (log is None) or (log.program != ix_program_key):
                result_log_state_list.append(SolIxLogState(ix_program_key, calc_level()))
            else:
                level = log.level
                result_log_state_list.append(log)
                log = next(log_iter, None)

        assert len(result_log_state_list) == len(ix_list), f'{len(result_log_state_list)} == {len(ix_list)}'
        assert log is None
        return result_log_state_list

    def _parse_log_msg_list(self, raw_log_msg_list: List[str]) -> None:
        log_state = SolTxLogDecoder().decode(raw_log_msg_list)
        self._ix_log_msg_list.extend(self._add_missing_log_msgs(log_state.log_list, self.ix_list, 1))
        for ix_idx, ix in enumerate(self.ix_list):
            inner_ix_list = self._get_inner_ix_list(ix_idx)
            if len(inner_ix_list) == 0:
                continue

            log_state = self._ix_log_msg_list[ix_idx]
            inner_log_msg_list = log_state.inner_log_list
            inner_log_msg_list = self._add_missing_log_msgs(inner_log_msg_list, inner_ix_list, 2)
            log_state.set_inner_log_list(inner_log_msg_list)

    @staticmethod
    def _has_ix_data(ix: Dict[str, Any]) -> bool:
        ix_data = ix.get('data', None)
        return (ix_data is not None) and (len(ix_data) > 1)

    def get_log_state(self, ix_idx: int, inner_ix_idx: Optional[int]) -> Optional[SolIxLogState]:
        if self._ix_log_msg_list is None:
            log_msg_list = self.tx['meta'].get('logMessages', list())
            object.__setattr__(self, '_ix_log_msg_list', list())
            self._parse_log_msg_list(log_msg_list)

        if ix_idx >= len(self._ix_log_msg_list):
            LOG.warning(f'{self} error: cannot find logs for instruction {ix_idx} > {len(self._ix_log_msg_list)}')
            return None

        ix_log_list = self._ix_log_msg_list[ix_idx]
        if inner_ix_idx is None:
            return ix_log_list

        if inner_ix_idx >= len(ix_log_list.inner_log_list):
            LOG.warning(
                f'{self} error: cannot find logs for instruction'
                f' {ix_idx}:{inner_ix_idx} > {len(ix_log_list.inner_log_list)}'
            )
            return None
        return ix_log_list.inner_log_list[inner_ix_idx]

    def _get_inner_ix_list(self, ix_idx: int) -> List[Dict[str, Any]]:
        for inner_ix in self.inner_ix_list:
            if inner_ix['index'] == ix_idx:
                return inner_ix['instructions']
        return list()

    def iter_sol_ix(self, evm_program_id: str) -> Generator[SolNeonIxReceiptInfo, None, None]:
        for ix_idx, ix in enumerate(self.ix_list):
            if self.is_program(ix, evm_program_id) and self._has_ix_data(ix):
                log_state = self.get_log_state(ix_idx, None)
                if log_state is not None:
                    ix_meta = SolIxMetaInfo.from_log_state(ix, ix_idx, None, log_state)
                    yield SolNeonIxReceiptInfo.from_ix(self, self.sol_tx_cost, self.compute_budget, ix_meta)

            inner_ix_list = self._get_inner_ix_list(ix_idx)
            for inner_idx, inner_ix in enumerate(inner_ix_list):
                if self.is_program(inner_ix, evm_program_id) and self._has_ix_data(inner_ix):
                    log_state = self.get_log_state(ix_idx, inner_idx)
                    if log_state is not None:
                        ix_meta = SolIxMetaInfo.from_log_state(inner_ix, ix_idx, inner_idx, log_state)
                        yield SolNeonIxReceiptInfo.from_ix(self, self.sol_tx_cost, self.compute_budget, ix_meta)
