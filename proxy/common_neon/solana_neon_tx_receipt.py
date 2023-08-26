from __future__ import annotations

import logging
import re

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Union, Iterator, Generator, List, Any, Tuple, cast

import base58

from .utils.evm_log_decoder import decode_log_list, NeonLogTxReturn, NeonLogTxEvent
from .utils.utils import str_fmt_object
from .solana_tx import SolTxReceipt, SolPubKey
from .constants import COMPUTE_BUDGET_ID_STR, EVM_PROGRAM_ID_STR


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
    is_success: bool

    _ix_meta_list: Optional[List[SolIxMetaInfo]]
    _inner_ix_meta_list: Optional[List[List[SolIxMetaInfo]]]
    _account_key_list: Optional[List[str]]
    _alt_key_list: Optional[List[str]]
    _signer: str

    _sol_tx_cost: Optional[SolTxCostInfo]
    _compute_budget: Optional[ComputeBudgetInfo]

    _str: str
    _req_id: str

    @staticmethod
    def from_tx_receipt(block_slot: Optional[int], tx_receipt: Dict[str, Any]) -> SolTxMetaInfo:
        if block_slot is None:
            block_slot = tx_receipt['slot']
        sol_sig = tx_receipt['transaction']['signatures'][0]
        sol_sig_slot = SolTxSigSlotInfo(sol_sig=sol_sig, block_slot=block_slot)
        return SolTxMetaInfo(
            ident=sol_sig_slot,
            block_slot=block_slot,
            sol_sig=sol_sig,
            tx=tx_receipt,
            is_success=tx_receipt.get('meta').get('err', None) is None,
            _ix_meta_list=None,
            _inner_ix_meta_list=None,
            _account_key_list=None,
            _alt_key_list=None,
            _signer='',
            _sol_tx_cost=None,
            _compute_budget=None,
            _str='',
            _req_id=''
        )

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
    def ix_meta_list(self) -> List[SolIxMetaInfo]:
        if self._ix_meta_list is None:
            raw_ix_list = self.tx['transaction']['message']['instructions']
            ix_meta_list = [
                SolIxMetaInfo.from_tx_meta(self, idx, None, ix)
                for idx, ix in enumerate(raw_ix_list)
            ]
            object.__setattr__(self, '_ix_meta_list', ix_meta_list)
        return self._ix_meta_list

    def inner_ix_meta_list(self, ix_meta: SolIxMetaInfo) -> List[SolIxMetaInfo]:
        if self._inner_ix_meta_list is None:
            raw_inner_ix_list = self.tx['meta']['innerInstructions']
            inner_ix_meta_list: List[List[SolIxMetaInfo]] = [list() for _ in self.ix_meta_list]
            for raw_inner_ix in raw_inner_ix_list:
                idx = raw_inner_ix['index']
                raw_ix_list = raw_inner_ix['instructions']
                ix_meta_list = [
                    SolIxMetaInfo.from_tx_meta(self, idx, inner_idx, ix)
                    for inner_idx, ix in enumerate(raw_ix_list)
                ]
                inner_ix_meta_list[idx] = ix_meta_list

            object.__setattr__(self, '_inner_ix_meta_list', inner_ix_meta_list)
        return self._inner_ix_meta_list[ix_meta.idx]

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
    def alt_key_list(self) -> List[str]:
        if self._alt_key_list is not None:
            return self._alt_key_list

        msg = self.tx['transaction']['message']
        alt_key_list: List[str] = list()
        alt_info_list: List[Dict[str, Any]] = msg.get('addressTableLookups', list())
        for alt_info in alt_info_list:
            alt_key_list.append(alt_info.get('accountKey'))

        object.__setattr__(self, '_alt_key_list', alt_key_list)
        return alt_key_list

    @property
    def signer(self) -> str:
        if not len(self._signer):
            object.__setattr__(self, '_signer', self.account_key_list[0])
        return self._signer

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


@dataclass(frozen=True)
class SolIxMetaInfo:
    sol_sig: str
    block_slot: int
    is_success: bool
    idx: int
    inner_idx: Optional[int]
    ix: Dict[str, Any]
    program_key: SolPubKey
    sol_tx_cost: SolTxCostInfo
    _str: str = ''

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo, idx: int, inner_idx: Optional[int], ix: Dict[str, Any]) -> SolIxMetaInfo:
        program_idx = ix.get('programIdIndex', None)
        if program_idx is None:
            LOG.warning(f'{tx_meta} error: fail to get program id')
            program_key = SolPubKey.default()
        elif program_idx > len(tx_meta.account_key_list):
            LOG.warning(f'{tx_meta} error: program index greater than list of accounts')
            program_key = SolPubKey.default()
        else:
            program_key = SolPubKey.from_string(tx_meta.account_key_list[program_idx])

        return SolIxMetaInfo(
            tx_meta.sol_sig, tx_meta.block_slot, tx_meta.is_success,
            idx, inner_idx, ix, program_key,
            tx_meta.sol_tx_cost
        )

    @property
    def ident(self):
        if self.inner_idx is None:
            return self.sol_sig, self.block_slot, self.idx
        else:
            return self.sol_sig, self.block_slot, self.idx, cast(int, self.inner_idx)

    def __str__(self) -> str:
        if not len(self._str):
            _str = ':'.join([str(s) for s in self.ident])
            object.__setattr__(self, '_str', _str)
        return self._str

    @property
    def ix_data(self) -> Optional[bytes]:
        ix_data = self.ix.get('data', None)
        return base58.b58decode(ix_data) if ix_data is not None else None

    def has_ix_data(self) -> bool:
        ix_data = self.ix.get('data', None)
        return (ix_data is not None) and (len(ix_data) > 1)

    def is_program(self, program_id: Union[str, SolPubKey]) -> bool:
        if isinstance(program_id, str):
            program_id = SolPubKey.from_string(program_id)
        return program_id == self.program_key


@dataclass(frozen=True)
class _SolIxSuccessLog:
    program: SolPubKey


@dataclass(frozen=True)
class _SolIxFailedLog:
    program: SolPubKey
    error: str


@dataclass(frozen=True)
class _SolIxInvokeLog:
    program: SolPubKey
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

    program: SolPubKey
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

        invoke = _SolIxInvokeLog(program=SolPubKey.from_string(match[1]), level=int(match[2]))
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

        success = _SolIxSuccessLog(program=SolPubKey.from_string(match[1]))
        log_state.set_success(success)
        return True

    def _decode_failed(self, log_state: SolIxLogState, log_msg: str) -> bool:
        match = self._failed_re.match(log_msg)
        if match is None:
            return False

        failed = _SolIxFailedLog(program=SolPubKey.from_string(match[1]), error=match[2])
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
            if not ix_meta.is_program(COMPUTE_BUDGET_ID_STR):
                continue

            try:
                ix_data = ix_meta.ix_data
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

    _str: str = ''

    @staticmethod
    def from_ix_meta(ix_meta: SolIxMetaInfo, ix_code: int, alt_address: str, neon_tx_sig: str) -> SolAltIxInfo:
        return SolAltIxInfo(
            block_slot=ix_meta.block_slot,
            sol_sig=ix_meta.sol_sig,
            idx=ix_meta.idx,
            inner_idx=ix_meta.inner_idx,
            is_success=ix_meta.is_success,
            ix_code=ix_code,
            alt_address=alt_address,
            neon_tx_sig=neon_tx_sig,
            sol_tx_cost=ix_meta.sol_tx_cost
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

    sol_tx_cost: SolTxCostInfo


@dataclass(frozen=True)
class _SolIxData:
    ix_code: Optional[int]
    ix_data: bytes


@dataclass(frozen=True)
class SolNeonIxReceiptInfo:
    class Status(Enum):
        Unknown = 0
        Success = 1
        Failed = 2

    sol_sig: str
    block_slot: int

    ix: Dict[str, Any]
    idx: int
    inner_idx: Optional[int]

    program: SolPubKey
    level: int
    status: Status
    error: Optional[str]

    ix_code: int
    ix_data: bytes

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

    max_heap_size: int
    neon_step_cnt: int

    sol_tx_cost: SolTxCostInfo

    ident: Union[Tuple[str, int, int, int], Tuple[str, int, int]]

    _str: str
    _req_id: str
    _account_list: List[int]
    _account_key_list: List[str]
    _alt_key_list: List[str]

    @staticmethod
    def from_tx_meta(tx_meta: SolTxMetaInfo,
                     ix_meta: SolIxMetaInfo,
                     log_state: SolIxLogState) -> SolNeonIxReceiptInfo:
        log_info = decode_log_list(log_state.iter_str_log_msg())

        neon_tx_sig = ''
        if log_info.neon_tx_sig is not None:
            neon_tx_sig = '0x' + log_info.neon_tx_sig.neon_sig.hex()

        neon_ix_gas_usage = 0
        neon_ix_total_gas_usage = 0
        if log_info.neon_tx_ix is not None:
            neon_ix_gas_usage = log_info.neon_tx_ix.gas_used
            neon_ix_total_gas_usage = log_info.neon_tx_ix.total_gas_used

        status = SolNeonIxReceiptInfo.Status.Unknown
        if log_state.status == SolIxLogState.Status.Failed:
            status = SolNeonIxReceiptInfo.Status.Failed
        elif log_state.status == SolIxLogState.Status.Success:
            status = SolNeonIxReceiptInfo.Status.Success

        account_list = ix_meta.ix['accounts']

        ix_data = SolNeonIxReceiptInfo._decode_ix_data(ix_meta.ix)

        max_bpf_cycle_cnt = log_state.max_bpf_cycle_cnt
        if not max_bpf_cycle_cnt:
            max_bpf_cycle_cnt = tx_meta.compute_budget.max_bpf_cycle_cnt

        used_heap_size = log_state.used_heap_size
        if not used_heap_size:
            used_heap_size = tx_meta.compute_budget.max_heap_size

        return SolNeonIxReceiptInfo(
            ident=ix_meta.ident,

            sol_sig=ix_meta.sol_sig,
            block_slot=ix_meta.block_slot,

            ix=ix_meta.ix,
            idx=ix_meta.idx,
            inner_idx=ix_meta.inner_idx,

            program=log_state.program,
            level=log_state.level,
            status=status,
            error=log_state.error,
            ix_code=ix_data.ix_code,
            ix_data=ix_data.ix_data,

            max_bpf_cycle_cnt=max_bpf_cycle_cnt,
            used_bpf_cycle_cnt=log_state.used_bpf_cycle_cnt,
            used_heap_size=used_heap_size,

            sol_tx_cost=tx_meta.sol_tx_cost,

            neon_tx_sig=neon_tx_sig,
            neon_gas_used=neon_ix_gas_usage,
            neon_total_gas_used=neon_ix_total_gas_usage,
            neon_tx_return=log_info.neon_tx_return,
            neon_tx_event_list=log_info.neon_tx_event_list,
            is_log_truncated=log_info.is_truncated,
            is_already_finalized=log_info.is_already_finalized,
            neon_step_cnt=0,
            max_heap_size=tx_meta.compute_budget.max_heap_size,

            _str='',
            _req_id='',
            _account_list=account_list,
            _account_key_list=tx_meta.account_key_list,
            _alt_key_list=tx_meta.alt_key_list
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

    def iter_account_key(self, start_idx: int) -> Generator[str, None, None]:
        for idx in self._account_list[start_idx:]:
            yield self._account_key_list[idx]

    def iter_alt_key(self) -> Iterator[str]:
        return iter(self._alt_key_list)


@dataclass(frozen=True)
class SolTxReceiptInfo(SolTxMetaInfo):
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
            is_success=tx_meta.is_success,
            _ix_meta_list=None,
            _inner_ix_meta_list=None,
            _account_key_list=None,
            _alt_key_list=None,
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
            if (log is None) or (log.program != ix_meta.program_key):
                result_log_state_list.append(SolIxLogState(ix_meta.program_key, calc_level()))
            else:
                level = log.level
                result_log_state_list.append(log)
                log = next(iter_log, None)

        assert len(result_log_state_list) == len(ix_list), f'{len(result_log_state_list)} == {len(ix_list)}'
        assert log is None
        return result_log_state_list

    def _parse_log_msg_list(self, raw_log_msg_list: List[str]) -> None:
        log_state = SolTxLogDecoder().decode(raw_log_msg_list)
        self._ix_log_msg_list.extend(self._add_missing_log_msgs(log_state.log_list, self.ix_meta_list, 1))
        for ix_meta in self.ix_meta_list:
            inner_ix_meta_list = self.inner_ix_meta_list(ix_meta)
            if len(inner_ix_meta_list) == 0:
                continue

            log_state = self._ix_log_msg_list[ix_meta.idx]
            inner_log_msg_list = log_state.inner_log_list
            inner_log_msg_list = self._add_missing_log_msgs(inner_log_msg_list, inner_ix_meta_list, 2)
            log_state.set_inner_log_list(inner_log_msg_list)

    def get_log_state(self, ix_meta: SolIxMetaInfo) -> Optional[SolIxLogState]:
        if self._ix_log_msg_list is None:
            log_msg_list = self.tx['meta'].get('logMessages', list())
            object.__setattr__(self, '_ix_log_msg_list', list())
            self._parse_log_msg_list(log_msg_list)

        if ix_meta.idx >= len(self._ix_log_msg_list):
            LOG.warning(f'{self}: cannot find logs for instruction {ix_meta.idx} > {len(self._ix_log_msg_list)}')
            return None

        ix_log_list = self._ix_log_msg_list[ix_meta.idx]
        if ix_meta.inner_idx is None:
            return ix_log_list

        if ix_meta.inner_idx >= len(ix_log_list.inner_log_list):
            LOG.warning(
                f'{self}: cannot find logs for instruction'
                f' {ix_meta.idx}:{ix_meta.inner_idx} > {len(ix_log_list.inner_log_list)}'
            )
            return None
        return ix_log_list.inner_log_list[ix_meta.inner_idx]

    def iter_sol_ix(self) -> Generator[SolNeonIxReceiptInfo, None, None]:
        for ix_meta in self.ix_meta_list:
            if ix_meta.is_program(EVM_PROGRAM_ID_STR) and ix_meta.has_ix_data():
                log_state = self.get_log_state(ix_meta)
                if log_state is not None:
                    yield SolNeonIxReceiptInfo.from_tx_meta(self, ix_meta, log_state)

            for inner_ix_meta in self.inner_ix_meta_list(ix_meta):
                if inner_ix_meta.is_program(EVM_PROGRAM_ID_STR) and inner_ix_meta.has_ix_data():
                    log_state = self.get_log_state(inner_ix_meta)
                    if log_state is not None:
                        yield SolNeonIxReceiptInfo.from_tx_meta(self, inner_ix_meta, log_state)
