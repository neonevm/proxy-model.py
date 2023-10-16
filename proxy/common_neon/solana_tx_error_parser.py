from __future__ import annotations

import json
import re
import enum
from typing import Union, Optional, Any, Tuple, List, cast

from .solana_tx import SolTxReceipt, SolPubKey
from .utils import get_from_dict, cached_method
from .solana_neon_tx_receipt import SolTxLogDecoder, SolIxLogState
from .constants import (
    ADDRESS_LOOKUP_TABLE_ID, COMPUTE_BUDGET_ID, SYS_PROGRAM_ID, METAPLEX_PROGRAM_ID, TOKEN_PROGRAM_ID,
    EVM_PROGRAM_ID
)


class SolTxError(BaseException):
    def __init__(self, receipt: SolTxReceipt):
        super().__init__(receipt)

        self._receipt = receipt

        log_list = self._filter_raw_log_list(receipt)
        if len(log_list) == 0:
            self._error = json.dumps(receipt)
        else:
            self._error = '. '.join(log_list)

    def _filter_raw_log_list(self, receipt: SolTxReceipt) -> List[str]:
        log_msg_list: List[str] = list()
        raw_log_msg_list = get_log_list(receipt)
        if len(raw_log_msg_list) == 0:
            return log_msg_list

        ix_log_state = SolTxLogDecoder().decode(raw_log_msg_list)
        self._filter_log_msg_list(ix_log_state, log_msg_list)
        return log_msg_list

    @staticmethod
    def _get_program_name(uid: SolPubKey) -> str:
        if uid == COMPUTE_BUDGET_ID:
            return 'ComputeBudget'
        elif uid == SYS_PROGRAM_ID:
            return 'System'
        elif uid == ADDRESS_LOOKUP_TABLE_ID:
            return 'AddressLookupTable'
        elif uid == METAPLEX_PROGRAM_ID:
            return 'Metaplex'
        elif uid == TOKEN_PROGRAM_ID:
            return 'Token'
        elif uid == EVM_PROGRAM_ID:
            return 'NeonEVM'
        return str(uid)

    class _LevelChangeType(enum.Enum):
        Up = 1,
        Down = -1
        Same = 0

    def _get_level_msg(self, level: int, level_change: _LevelChangeType, status: SolIxLogState.Status) -> str:
        if status == SolIxLogState.Status.Success:
            status_str = '+'
        elif status == SolIxLogState.Status.Failed:
            status_str = '-'
        else:
            status_str = '?'

        if level_change == self._LevelChangeType.Up:
            level_change_str = '>'
        elif level_change == self._LevelChangeType.Down:
            level_change_str = '<'
        else:
            level_change_str = '='

        return f'[{level}]{level_change_str}{status_str}'

    def _add_subrange_log_msg_list(self, level: int,
                                   status: SolIxLogState.Status,
                                   subrange_log_msg_list: List[str],
                                   log_msg_list: List[str]) -> None:
        level_msg = self._get_level_msg(level, self._LevelChangeType.Same, status)

        for log_msg in subrange_log_msg_list:
            for prefix in ('Program log: ', 'Program failed to complete: '):
                if not log_msg.startswith(prefix):
                    continue

                log_msg = f'{level_msg} {log_msg[len(prefix):]}'
                log_msg_list.append(log_msg)
                break

            else:
                log_msg = f'{level_msg} {log_msg}'
                log_msg_list.append(log_msg)

        subrange_log_msg_list.clear()

    def _filter_log_msg_list(self, ix_log_state: SolIxLogState, log_msg_list: List[str]) -> None:
        status = SolIxLogState.Status
        subrange_log_msg_list: List[str] = list()
        if ix_log_state.level > 0:
            level_msg = self._get_level_msg(ix_log_state.level - 1, self._LevelChangeType.Up, status.Success)
            invoke_msg = f'{level_msg} {self._get_program_name(ix_log_state.program_key)}'
            log_msg_list.append(invoke_msg)

        for ix_log_rec in ix_log_state.log_list:
            if isinstance(ix_log_rec, SolIxLogState):
                self._add_subrange_log_msg_list(ix_log_state.level, status.Success, subrange_log_msg_list, log_msg_list)
                self._filter_log_msg_list(ix_log_rec, log_msg_list)

            elif isinstance(ix_log_rec, str):
                if ix_log_rec.startswith('Program data:'):
                    continue
                subrange_log_msg_list.append(ix_log_rec)

        self._add_subrange_log_msg_list(ix_log_state.level, ix_log_state.status, subrange_log_msg_list, log_msg_list)
        if ix_log_state.status == status.Failed:
            level_msg = self._get_level_msg(ix_log_state.level, self._LevelChangeType.Down, ix_log_state.status)
            failed_msg = f'{level_msg} {ix_log_state.error}'
            log_msg_list.append(failed_msg)

    @property
    def receipt(self) -> SolTxReceipt:
        return self._receipt

    @property
    def error_msg(self) -> str:
        return self._error

    def __str__(self) -> str:
        return self._error


def get_log_list(receipt: SolTxReceipt) -> List[str]:
    log_from_receipt = get_from_dict(receipt, ('result', 'meta', 'logMessages'), None)
    if log_from_receipt is not None:
        return log_from_receipt

    log_from_receipt_result = get_from_dict(receipt, ('meta', 'logMessages'), None)
    if log_from_receipt_result is not None:
        return log_from_receipt_result

    log_from_receipt_result_meta = get_from_dict(receipt, ('logMessages', ), None)
    if log_from_receipt_result_meta is not None:
        return log_from_receipt_result_meta

    log_from_send_trx_error = get_from_dict(receipt, ('data', 'logs'), None)
    if log_from_send_trx_error is not None:
        return log_from_send_trx_error

    log_from_prepared_receipt = get_from_dict(receipt, ('logs', ), None)
    if log_from_prepared_receipt is not None:
        return log_from_prepared_receipt

    return list()


class SolTxErrorParser:
    _neon_evm_ix_idx = 2
    _simulation_failed_hdr = f'Transaction simulation failed: Error processing Instruction {_neon_evm_ix_idx}: '

    _computation_budget_exceeded_type = 'ComputationalBudgetExceeded'

    _invalid_ix_data_msg = _simulation_failed_hdr + 'invalid instruction data'
    _program_failed_msg = _simulation_failed_hdr + 'Program failed to complete'
    _alt_invalid_idx_msg = 'invalid transaction: Transaction address table lookup uses an invalid index'
    _already_process_msg = 'AlreadyProcessed'

    _alt_already_exist_msg = [0, 'AccountAlreadyInitialized']
    _alt_already_exist_log_msg = (
        f'Program {ADDRESS_LOOKUP_TABLE_ID} failed: instruction requires an uninitialized account'
    )

    _exceeded_cu_number_log = 'Program failed to complete: exceeded maximum number of instructions allowed'
    _exceeded_cu_number_re = re.compile(
        r'Program (\w+) failed: exceeded CUs meter at BPF instruction #(\d+)$'
    )
    _read_write_blocked_log = 'trying to execute transaction on rw locked account'
    _already_finalized_log_vold = 'Program log: Storage Account is finalized'
    _already_finalized_log = 'Program log: Transaction already finalized'


    _log_truncated_log = 'Log truncated'
    _require_resize_iter_log = 'Deployment of contract which needs more than 10kb of account space needs several'

    _block_hash_notfound_err = 'BlockhashNotFound'
    _numslots_behind_data = 'numSlotsBehind'

    _rw_locked_account_re_vold = re.compile(
        r'Program log: [a-zA-Z/._]+:\d+ : trying to execute transaction on rw locked account \w+'
    )

    _rw_locked_account_re = re.compile(
        r'Program log: Account [a-zA-Z0-9]+ - blocked, trying to execute transaction on rw locked account'
    )

    _create_account_re = re.compile(
        r'Create Account: account Address { address: \w+, base: Some\(\w+\) } already in use'
    )

    _create_neon_account_re = re.compile(
        r'Program log: [a-zA-Z_/.]+:\d+ : Account \w+ - expected system owned'
    )

    _nonce_re = re.compile(
        r'Program log: Invalid Nonce, origin \w+ nonce (\d+) != Transaction nonce (\d+)'
    )

    _out_of_gas_re = re.compile(
        r'Program log: Out of Gas, limit = (\d+), required = (\d+)'
    )

    def __init__(self, receipt: Union[SolTxReceipt, BaseException, str]):
        assert isinstance(receipt, dict) or isinstance(receipt, BaseException) or isinstance(receipt, str)

        if isinstance(receipt, SolTxError):
            self._receipt = cast(SolTxError, receipt).receipt
        else:
            self._receipt = receipt

    def _get_value(self, path: Tuple[Any, ...]) -> Any:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return None

        return get_from_dict(self._receipt, path, None)

    @cached_method
    def _get_error(self) -> Union[str, list, None]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return str(self._receipt)

        err_from_receipt = self._get_value(('result', 'meta', 'err', 'InstructionError'))
        if err_from_receipt is not None:
            return err_from_receipt

        err_from_receipt_result = self._get_value(('meta', 'err', 'InstructionError'))
        if err_from_receipt_result is not None:
            return err_from_receipt_result

        err_from_send_trx_error = self._get_value(('data', 'err', 'InstructionError'))
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_send_trx_error = self._get_value(('data', 'err'))
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_prepared_receipt = self._get_value(('err', 'InstructionError'))
        if err_from_prepared_receipt is not None:
            return err_from_prepared_receipt

        return None

    @cached_method
    def _get_error_code_msg(self) -> Optional[Tuple[int, str]]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return None

        code = self._get_value(('code', ))
        msg = self._get_value(('message', ))

        if (code is None) or (msg is None):
            return None
        return code, msg

    @cached_method
    def _get_log_list(self) -> List[str]:
        if not self._receipt:
            return list()
        if isinstance(self._receipt, BaseException):
            return list()

        return get_log_list(self._receipt)

    @cached_method
    def _get_evm_log_list(self) -> List[str]:
        log_list: List[str] = list()
        if not self._receipt:
            return log_list
        if isinstance(self._receipt, BaseException):
            return log_list

        raw_log_msg_list = self._get_log_list()
        ix_log_state = SolTxLogDecoder().decode(raw_log_msg_list)
        for ix_log_msg in ix_log_state.inner_log_list:
            if ix_log_msg.program_key != EVM_PROGRAM_ID:
                continue
            log_list.extend(ix_log_msg.iter_str_log_msg())
        return log_list

    @cached_method
    def check_if_error(self) -> bool:
        return (self._get_error() is not None) or (self._get_error_code_msg() is not None)

    @cached_method
    def check_if_invalid_ix_data(self) -> bool:
        return self._get_error_code_msg() == (-32002, self._invalid_ix_data_msg)

    @cached_method
    def check_if_budget_exceeded(self) -> bool:
        error_type = self._get_error()
        if not error_type:
            return False

        if isinstance(error_type, list):
            error_type = error_type[1]
        if not isinstance(error_type, str):
            return False

        if error_type == self._computation_budget_exceeded_type:
            return True

        log_list = self._get_log_list()
        for log_rec in reversed(log_list):
            if log_rec.startswith(self._exceeded_cu_number_log):
                return True
            elif self._exceeded_cu_number_re.match(log_rec) is not None:
                return True
            elif log_rec == self._log_truncated_log:
                return True

        return False

    @cached_method
    def check_if_require_resize_iter(self) -> bool:
        if self._get_error_code_msg() != (-32002, self._program_failed_msg):
            return False

        log_list = self._get_evm_log_list()
        for log_rec in reversed(log_list):
            if log_rec.find(self._require_resize_iter_log) != -1:
                return True
        return False

    @cached_method
    def check_if_account_already_exists(self) -> bool:
        evm_log_list = self._get_evm_log_list()
        for log_rec in evm_log_list:
            if self._create_neon_account_re.match(log_rec) is not None:
                return True

        raw_log_list = self._get_log_list()
        for log_rec in raw_log_list:
            if self._create_account_re.match(log_rec) is not None:
                return True

        return False

    @cached_method
    def check_if_already_finalized(self) -> bool:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if log_rec == self._already_finalized_log:
                return True
            elif log_rec == self._already_finalized_log_vold:
                return True
        return False

    @cached_method
    def check_if_accounts_blocked(self) -> bool:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if self._rw_locked_account_re.match(log_rec) is not None:
                return True
            elif self._rw_locked_account_re_vold.match(log_rec) is not None:
                return True
        return False

    @cached_method
    def check_if_block_hash_notfound(self) -> bool:
        if self._receipt is None:
            return True
        return self._get_error() == self._block_hash_notfound_err

    @cached_method
    def check_if_alt_uses_invalid_index(self) -> bool:
        return self._get_error_code_msg() == (-32602, self._alt_invalid_idx_msg)

    @cached_method
    def check_if_alt_already_exists(self) -> bool:
        if self._get_value(('meta', 'err', 'InstructionError')) != self._alt_already_exist_msg:
            return False
        for log_msg in self._get_log_list():
            if log_msg == self._alt_already_exist_log_msg:
                return True
        return False

    @cached_method
    def check_if_already_processed(self) -> bool:
        return self._get_value(('data', 'err')) == self._already_process_msg

    @cached_method
    def get_slots_behind(self) -> Optional[int]:
        return self._get_value(('data', self._numslots_behind_data))

    @cached_method
    def get_nonce_error(self) -> Tuple[Optional[int], Optional[int]]:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            match = self._nonce_re.match(log_rec)
            if match is not None:
                state_tx_cnt, tx_nonce = match[1], match[2]
                return int(state_tx_cnt), int(tx_nonce)
        return None, None

    @cached_method
    def get_out_of_gas_error(self) -> Tuple[Optional[int], Optional[int]]:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            match = self._out_of_gas_re.match(log_rec)
            if match is not None:
                has_gas_limit, req_gas_limit = match[1], match[2]
                return int(has_gas_limit), int(req_gas_limit)
        return None, None
