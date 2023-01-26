from __future__ import annotations

import re

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Union, Iterator, List, Any, Tuple, cast
import logging
import base58

from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.evm_log_decoder import decode_log_list, NeonLogTxReturn, NeonLogTxEvent
from ..common_neon.utils import str_fmt_object


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


@dataclass(frozen=True)
class SolTxMetaInfo:
    ident: SolTxSigSlotInfo

    block_slot: int
    sol_sig: str
    tx: Dict[str, Any]

    _str: str
    _req_id: str

    @staticmethod
    def from_end_range(block_slot: int, postfix: str) -> SolTxMetaInfo:
        ident = SolTxSigSlotInfo(block_slot=block_slot, sol_sig=f'end-{postfix}')
        return SolTxMetaInfo(ident, block_slot, ident.sol_sig, {}, '', '')

    @staticmethod
    def from_response(sig_slot: SolTxSigSlotInfo, response: Dict[str, Any]) -> SolTxMetaInfo:
        return SolTxMetaInfo(sig_slot, sig_slot.block_slot, sig_slot.sol_sig, response, '', '')

    def __str__(self) -> str:
        if self._str == '':
            _str = str_fmt_object(self.ident)
            object.__setattr__(self, '_str', _str)
        return self._str

    @property
    def req_id(self) -> str:
        if self._req_id == '':
            req_id = f'{self.sol_sig[:7]}_{self.block_slot}'
            object.__setattr__(self, '_req_id', req_id)
        return self._req_id


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


_SolIxStatusLog = Union[None, _SolIxSuccessLog, _SolIxFailedLog]


@dataclass
class _SolIxLogList:
    class Status(Enum):
        UNKNOWN = 0
        SUCCESS = 1
        FAILED = 2

    program: str
    level: int

    status: Status = Status.UNKNOWN
    error: Optional[str] = None

    log_list: List[Union[str, _SolIxLogList]] = None
    inner_log_list: List[_SolIxLogList] = None

    def __post_init__(self):
        self.log_list = []
        self.inner_log_list = []

    def __str__(self) -> str:
        return str_fmt_object(self)

    def set_status(self, status: _SolIxStatusLog) -> None:
        assert self.status == self.status.UNKNOWN
        if isinstance(status, _SolIxSuccessLog):
            assert status.program == self.program
            self.status = self.Status.SUCCESS
        elif isinstance(status, _SolIxFailedLog):
            assert status.program == self.program
            self.status = self.Status.FAILED
            self.error = status.error
        else:
            assert False, f'unknown status {status}'

    def iter_str_log_msg(self) -> str:
        for log_msg in self.log_list:
            if isinstance(log_msg, str):
                yield log_msg


class _SolTxLogDecoder:
    _invoke_re = re.compile(r'^Program (\w+) invoke \[(\d+)]$')
    _success_re = re.compile(r'^Program (\w+) success$')
    _failed_re = re.compile(r'^Program (\w+) failed: (.+)$')

    def decode(self, log_msg_list: List[str]) -> List[_SolIxLogList]:
        log_state = _SolIxLogList('', 0)
        self._decode(iter(log_msg_list), log_state)
        return log_state.inner_log_list

    def _decode(self, log_msg_iter: Iterator[str], log_state: _SolIxLogList) -> _SolIxStatusLog:
        for log_msg in log_msg_iter:
            invoke = self._get_invoke(log_msg)
            if invoke:
                ix_log_state = _SolIxLogList(invoke.program, invoke.level)

                log_state.log_list.append(ix_log_state)
                log_state.inner_log_list.append(ix_log_state)

                next_log_state = _SolIxLogList(invoke.program, invoke.level)
                next_log_state.log_list = ix_log_state.log_list
                if invoke.level > 1:
                    next_log_state.inner_log_list = log_state.inner_log_list
                else:
                    next_log_state.inner_log_list = ix_log_state.inner_log_list

                status = self._decode(log_msg_iter, next_log_state)
                if status is not None:
                    ix_log_state.set_status(status)
                continue

            success = self._get_success(log_msg)
            if success:
                return success

            failed = self._get_failed(log_msg)
            if failed:
                return failed

            log_state.log_list.append(log_msg)
        return None

    def _get_invoke(self, log_msg: str) -> Optional[_SolIxInvokeLog]:
        match = self._invoke_re.match(log_msg)
        if match is not None:
            return _SolIxInvokeLog(program=match[1], level=int(match[2]))
        return None

    def _get_success(self, log_msg: str) -> Optional[_SolIxSuccessLog]:
        match = self._success_re.match(log_msg)
        if match is not None:
            return _SolIxSuccessLog(program=match[1])
        return None

    def _get_failed(self, log_msg: str) -> Optional[_SolIxFailedLog]:
        match = self._failed_re.match(log_msg)
        if match is not None:
            return _SolIxFailedLog(program=match[1], error=match[2])
        return None


@dataclass(frozen=True)
class SolIxMetaInfo:
    class Status(Enum):
        UNKNOWN = 0
        SUCCESS = 1
        FAILED = 2

    ix: Dict[str, Any]
    idx: int
    inner_idx: Optional[int]

    program: str
    level: int
    status: Status
    error: Optional[str]

    heap_size: int
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int

    neon_tx_sig: str
    neon_gas_used: int
    neon_total_gas_used: int

    neon_tx_return: Optional[NeonLogTxReturn]
    neon_tx_event_list: List[NeonLogTxEvent]

    @staticmethod
    def from_log_list(ix: Dict[str, Any], idx: int, inner_idx: Optional[int], log_list: _SolIxLogList) -> SolIxMetaInfo:
        log_info = decode_log_list(log_list.iter_str_log_msg())

        max_bpf_cycle_cnt = 0
        used_bpf_cycle_cnt = 0
        if log_info.sol_bpf_cycle_usage is not None:
            max_bpf_cycle_cnt = log_info.sol_bpf_cycle_usage.max_bpf_cycle_cnt
            used_bpf_cycle_cnt = log_info.sol_bpf_cycle_usage.used_bpf_cycle_cnt

        heap_size = 0
        if log_info.sol_heap_usage is not None:
            heap_size = log_info.sol_heap_usage

        neon_tx_sig = ''
        if log_info.neon_tx_sig is not None:
            neon_tx_sig = '0x' + log_info.neon_tx_sig.neon_sig.hex()

        neon_ix_gas_usage = 0
        neon_ix_total_gas_usage = 0
        if log_info.neon_tx_ix is not None:
            neon_ix_gas_usage = log_info.neon_tx_ix.gas_used
            neon_ix_total_gas_usage = log_info.neon_tx_ix.total_gas_used

        status = SolIxMetaInfo.Status.UNKNOWN
        if log_list.status == _SolIxLogList.Status.FAILED:
            status = SolIxMetaInfo.Status.FAILED
        elif log_list.status == _SolIxLogList.Status.SUCCESS:
            status = SolIxMetaInfo.Status.SUCCESS

        return SolIxMetaInfo(
            ix=ix,
            idx=idx,
            inner_idx=inner_idx,

            program=log_list.program,
            level=log_list.level,
            status=status,
            error=log_list.error,

            max_bpf_cycle_cnt=max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=used_bpf_cycle_cnt,
            heap_size=heap_size,

            neon_tx_sig=neon_tx_sig,
            neon_gas_used=neon_ix_gas_usage,
            neon_total_gas_used=neon_ix_total_gas_usage,
            neon_tx_return=log_info.neon_tx_return,
            neon_tx_event_list=log_info.neon_tx_event_list
        )


@dataclass(frozen=True)
class SolTxCostInfo:
    sol_sig: str
    block_slot: int
    operator: str
    sol_spent: int

    _str: str
    _calculated_stat: bool

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> SolTxCostInfo:
        msg = tx_meta.tx['transaction']['message']
        meta = tx_meta.tx['meta']

        return SolTxCostInfo(
            sol_sig=tx_meta.sol_sig,
            block_slot=tx_meta.block_slot,
            operator=msg['accountKeys'][0],
            sol_spent=(meta['preBalances'][0] - meta['postBalances'][0]),
            _str='',
            _calculated_stat=False,
        )

    def __str__(self) -> str:
        if self._str == '':
            _str = str_fmt_object(self)
            object.__setattr__(self, '_str', _str)
        return self._str

    def set_calculated_stat(self) -> None:
        object.__setattr__(self, '_calculated_stat', True)

    @property
    def is_calculated_stat(self) -> bool:
        return self._calculated_stat


@dataclass(frozen=True)
class _SolIxData:
    program_ix: Optional[int]
    ix_data: bytes


@dataclass(frozen=True)
class SolNeonIxReceiptInfo(SolIxMetaInfo):
    sol_sig: str
    block_slot: int

    program_ix: int
    ix_data: bytes

    neon_step_cnt: int

    sol_tx_cost: SolTxCostInfo

    ident: Union[Tuple[str, int, int, int], Tuple[str, int, int]]

    _str: str
    _account_list: List[int]
    _account_key_list: List[str]

    @staticmethod
    def from_ix(tx_meta: SolTxMetaInfo, tx_cost: SolTxCostInfo, ix_meta: SolIxMetaInfo) -> SolNeonIxReceiptInfo:
        _account_list = ix_meta.ix['accounts']

        _account_key_list: List[str] = tx_meta.tx['transaction']['message']['accountKeys']
        lookup_key_list: Optional[Dict[str, List[str]]] = tx_meta.tx['meta'].get('loadedAddresses', None)
        if lookup_key_list is not None:
            _account_key_list.extend(lookup_key_list['writable'])
            _account_key_list.extend(lookup_key_list['readonly'])

        if ix_meta.inner_idx is None:
            ident = tx_meta.sol_sig, tx_meta.block_slot, ix_meta.idx
        else:
            ident = tx_meta.sol_sig, tx_meta.block_slot, ix_meta.idx, cast(int, ix_meta.inner_idx)

        ix_data = SolNeonIxReceiptInfo._decode_ix_data(ix_meta.ix)

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
            program_ix=ix_data.program_ix,
            ix_data=ix_data.ix_data,

            max_bpf_cycle_cnt=ix_meta.max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=ix_meta.used_bpf_cycle_cnt,
            heap_size=ix_meta.heap_size,

            sol_tx_cost=tx_cost,

            neon_tx_sig=ix_meta.neon_tx_sig,
            neon_gas_used=ix_meta.neon_gas_used,
            neon_total_gas_used=ix_meta.neon_total_gas_used,
            neon_tx_return=ix_meta.neon_tx_return,
            neon_tx_event_list=ix_meta.neon_tx_event_list,
            neon_step_cnt=0,

            _str='',
            _account_list=_account_list,
            _account_key_list=_account_key_list,
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
            ix_data = base58.b58decode(ix_data)
            return _SolIxData(program_ix=int(ix_data[0]), ix_data=ix_data)
        except BaseException as exc:
            LOG.warning(f'Fail to get a program instruction', exc_info=exc)
            return _SolIxData(program_ix=int(ix_data[0]), ix_data=b'')

    def set_neon_step_cnt(self, value: int) -> None:
        assert self.neon_step_cnt == 0
        object.__setattr__(self, 'neon_step_cnt', value)

    @property
    def account_cnt(self) -> int:
        return len(self._account_list)

    @property
    def req_id(self) -> str:
        return '_'.join([s[:7] if isinstance(s, str) else str(s) for s in self.ident])

    def get_account(self, account_idx: int) -> str:
        if len(self._account_list) > account_idx:
            key_idx = self._account_list[account_idx]
            if len(self._account_key_list) > key_idx:
                return self._account_key_list[key_idx]
        return ''

    def iter_account(self, start_idx: int) -> Iterator[str]:
        for idx in self._account_list[start_idx:]:
            yield self._account_key_list[idx]


@dataclass(frozen=True)
class SolTxReceiptInfo(SolTxMetaInfo):
    sol_cost: SolTxCostInfo
    operator: str

    _ix_list: List[Dict[str, Any]]
    _inner_ix_list: List[Dict[str, Any]]
    _account_key_list: List[str]
    _ix_log_msg_list: List[_SolIxLogList]

    @staticmethod
    def from_tx(tx: Dict[str, Any]) -> SolTxReceiptInfo:
        block_slot = tx['slot']
        sol_sig = tx['transaction']['signatures'][0]
        sol_sig_slot = SolTxSigSlotInfo(sol_sig=sol_sig, block_slot=block_slot)
        tx_meta = SolTxMetaInfo.from_response(sol_sig_slot, tx)
        return SolTxReceiptInfo.from_tx_meta(tx_meta)

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo) -> SolTxReceiptInfo:
        sol_cost = SolTxCostInfo.from_tx_meta(tx_meta)

        msg = tx_meta.tx['transaction']['message']
        operator = msg['accountKeys'][0]
        _ix_list = msg['instructions']

        meta = tx_meta.tx['meta']
        log_msg_list = meta.get('logMessages', [])
        _inner_ix_list = meta['innerInstructions']

        _account_key_list: List[str] = msg['accountKeys']
        lookup_key_list: Optional[Dict[str, List[str]]] = meta.get('loadedAddresses', None)
        if lookup_key_list is not None:
            _account_key_list.extend(lookup_key_list['writable'])
            _account_key_list.extend(lookup_key_list['readonly'])

        _ix_log_msg_list: List[_SolIxLogList] = []

        result = SolTxReceiptInfo(
            ident=tx_meta.ident,

            block_slot=tx_meta.block_slot,
            sol_sig=tx_meta.sol_sig,
            tx=tx_meta.tx,
            _str='',
            _req_id='',

            sol_cost=sol_cost,
            operator=operator,

            _ix_list=_ix_list,
            _inner_ix_list=_inner_ix_list,
            _account_key_list=_account_key_list,
            _ix_log_msg_list=[],
        )
        result._parse_log_msg_list(log_msg_list)
        return result

    def _add_missing_log_msgs(self, log_list_list: List[_SolIxLogList],
                              ix_list: List[Dict[str, Any]],
                              level: int) -> List[_SolIxLogList]:
        base_level = level

        def calc_level() -> int:
            if base_level == 1:
                return 1
            return level + 1

        result_log_list_list: List[_SolIxLogList] = []

        log_iter = iter(log_list_list)
        log = next(log_iter) if len(log_list_list) > 0 else None
        for idx, ix in enumerate(ix_list):
            ix_program_key = self._get_program_key(ix)
            if (log is None) or (log.program != ix_program_key):
                result_log_list_list.append(_SolIxLogList(ix_program_key, calc_level()))
            else:
                level = log.level
                result_log_list_list.append(log)
                log = next(log_iter, None)

        assert len(result_log_list_list) == len(ix_list), f'{len(result_log_list_list)} == {len(ix_list)}'
        assert log is None
        return result_log_list_list

    def _parse_log_msg_list(self, log_msg_list: List[str]) -> None:
        log_list_list: List[_SolIxLogList] = _SolTxLogDecoder().decode(log_msg_list)
        self._ix_log_msg_list.extend(self._add_missing_log_msgs(log_list_list, self._ix_list, 1))
        for ix_idx, ix in enumerate(self._ix_list):
            inner_ix_list = self._get_inner_ix_list(ix_idx)
            if len(inner_ix_list) == 0:
                continue

            log_list = self._ix_log_msg_list[ix_idx]
            inner_log_msg_list = log_list.inner_log_list
            log_list.inner_log_list = self._add_missing_log_msgs(inner_log_msg_list, inner_ix_list, 2)

    def _get_program_key(self, ix: Dict[str, Any]) -> str:
        program_idx = ix.get('programIdIndex', None)
        if program_idx is None:
            LOG.warning(f'{self} error: fail to get program id')
            return ''
        elif program_idx > len(self._account_key_list):
            LOG.warning(f'{self} error: program index greater than list of accounts')
            return ''

        return self._account_key_list[program_idx]

    def _has_ix_data(self, ix: Dict[str, Any]) -> bool:
        ix_data = ix.get('data', None)
        return (ix_data is not None) and (len(ix_data) > 1)

    def _is_neon_program(self, ix: Dict[str, Any]) -> bool:
        return self._get_program_key(ix) == EVM_LOADER_ID

    def _get_log_list(self, ix_idx: int, inner_ix_idx: Optional[int]) -> Optional[_SolIxLogList]:
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
        for inner_ix in self._inner_ix_list:
            if inner_ix['index'] == ix_idx:
                return inner_ix['instructions']
        return []

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        for ix_idx, ix in enumerate(self._ix_list):
            if self._is_neon_program(ix) and self._has_ix_data(ix):
                log_list = self._get_log_list(ix_idx, None)
                if log_list is not None:
                    ix_meta = SolIxMetaInfo.from_log_list(ix, ix_idx, None, log_list)
                    yield SolNeonIxReceiptInfo.from_ix(self, self.sol_cost, ix_meta)

            inner_ix_list = self._get_inner_ix_list(ix_idx)
            for inner_idx, inner_ix in enumerate(inner_ix_list):
                if self._is_neon_program(inner_ix) and self._has_ix_data(inner_ix):
                    log_list = self._get_log_list(ix_idx, inner_idx)
                    if log_list is not None:
                        ix_meta = SolIxMetaInfo.from_log_list(inner_ix, ix_idx, inner_idx, log_list)
                        yield SolNeonIxReceiptInfo.from_ix(self, self.sol_cost, ix_meta)
