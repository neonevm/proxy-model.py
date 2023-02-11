from __future__ import annotations

import json
import logging
import re
from typing import Union, Optional, Any, Tuple

from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.solana_tx import SolTxReceipt
from ..common_neon.utils import get_from_dict


LOG = logging.getLogger(__name__)


class SolTxError(Exception):
    def __init__(self, receipt: SolTxReceipt):
        self.result = receipt

        log_list = SolTxErrorParser(receipt).get_log_list()
        self.error = '. '.join([log for log in log_list if self._is_program_log(log)])
        if not len(self.error):
            self.error = json.dumps(receipt)

        super().__init__(self.error)

    @staticmethod
    def _is_program_log(log: str) -> bool:
        if log.startswith('Program log: Total memory occupied: '):
            return False

        prefix_list = (
            'Program log: ',
            'Program failed to complete: '
        )
        for prefix in prefix_list:
            if log.startswith(prefix):
                return True
        return False


class SolTxErrorParser:
    _neon_evm_ix_idx = 2
    _simulation_failed_hdr = f'Transaction simulation failed: Error processing Instruction {_neon_evm_ix_idx}: '

    _computation_budget_exceeded_type = 'ComputationalBudgetExceeded'
    _program_failed_to_complete_type = 'ProgramFailedToComplete'

    _invalid_ix_data_msg = _simulation_failed_hdr + 'invalid instruction data'
    _program_failed_msg = _simulation_failed_hdr + 'Program failed to complete'
    _alt_invalid_idx_msg = 'invalid transaction: Transaction address table lookup uses an invalid index'

    _exceeded_cu_number_log = 'Program failed to complete: exceeded maximum number of instructions allowed'
    _read_only_blocked_log = 'trying to execute transaction on ro locked account'
    _read_write_blocked_log = 'trying to execute transaction on rw locked account'
    _already_finalized_log = f'Program {EVM_LOADER_ID} failed: custom program error: 0x4'
    _log_truncated_log = 'Log truncated'
    _require_resize_iter_log = 'Deployment of contract which needs more than 10kb of account space needs several'

    _blockhash_notfound_err = 'BlockhashNotFound'
    _numslots_behind_data = 'numSlotsBehind'

    _create_account_re = re.compile(
        r'Program log: program/src/instruction/account_create.rs:\d+ : Account (\w+) - expected system owned'
    )

    _nonce_re = re.compile(
        f'Program log: {EVM_LOADER_ID}' + r':\d+ : Invalid Ethereum transaction nonce: acc (\d+), trx (\d+)'
    )

    def __init__(self, receipt: Union[SolTxReceipt, BaseException, str]):
        assert isinstance(receipt, dict) or isinstance(receipt, BaseException) or isinstance(receipt, str)

        if isinstance(receipt, SolTxError):
            self._receipt = receipt.result
        else:
            self._receipt = receipt
        self._log_list = []
        self._is_log_list_init = False
        self._error: Union[str, list, None] = None
        self._is_error_init = False
        self._error_code_msg: Optional[Tuple[int, str]] = None
        self._is_error_code_msg_init = False

    @property
    def receipt(self) -> Union[SolTxReceipt, BaseException, str]:
        return self._receipt

    def raise_budget_exceeded(self) -> None:
        if self.check_if_budget_exceeded():
            raise SolTxError(self._receipt)

        raise SolTxError({
            'err': {
                'InstructionError': [1, SolTxErrorParser._computation_budget_exceeded_type]
            }
        })

    def _get_value(self, *path) -> Any:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return None

        return get_from_dict(self._receipt, *path)

    def _get_error(self) -> Union[str, list, None]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return str(self._receipt)

        err_from_receipt = self._get_value('result', 'meta', 'err', 'InstructionError')
        if err_from_receipt is not None:
            return err_from_receipt

        err_from_receipt_result = self._get_value('meta', 'err', 'InstructionError')
        if err_from_receipt_result is not None:
            return err_from_receipt_result

        err_from_send_trx_error = self._get_value('data', 'err', 'InstructionError')
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_send_trx_error = self._get_value('data', 'err')
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_prepared_receipt = self._get_value('err', 'InstructionError')
        if err_from_prepared_receipt is not None:
            return err_from_prepared_receipt

        return None

    def get_error(self) -> Union[str, list, None]:
        if not self._is_error_init:
            self._is_error_init = True
            self._error = self._get_error()
        return self._error

    def _get_error_code_msg(self) -> Optional[Tuple[int, str]]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, BaseException):
            return None

        code = self._get_value('code')
        msg = self._get_value('message')

        if (code is None) or (msg is None):
            return None
        return code, msg

    def get_error_code_msg(self) -> Optional[Tuple[int, str]]:
        if not self._is_error_code_msg_init:
            self._is_error_code_msg_init = True
            self._error_code_msg = self._get_error_code_msg()
        return self._error_code_msg

    def _get_log_list(self) -> [str]:
        if not self._receipt:
            return []
        if isinstance(self._receipt, BaseException):
            return []

        log_from_receipt = self._get_value('result', 'meta', 'logMessages')
        if log_from_receipt is not None:
            return log_from_receipt

        log_from_receipt_result = self._get_value('meta', 'logMessages')
        if log_from_receipt_result is not None:
            return log_from_receipt_result

        log_from_receipt_result_meta = self._get_value('logMessages')
        if log_from_receipt_result_meta is not None:
            return log_from_receipt_result_meta

        log_from_send_trx_error = self._get_value('data', 'logs')
        if log_from_send_trx_error is not None:
            return log_from_send_trx_error

        log_from_prepared_receipt = self._get_value('logs')
        if log_from_prepared_receipt is not None:
            return log_from_prepared_receipt

        return []

    def get_log_list(self):
        if not self._is_log_list_init:
            self._is_log_list_init = True
            self._log_list = self._get_log_list()

            if len(self._log_list) == 0:
                LOG.error(f"Can't get logs from receipt: {self._receipt}")

        return self._log_list

    def check_if_error(self) -> bool:
        return (self.get_error() is not None) or (self.get_error_code_msg() is not None)

    def check_if_invalid_ix_data(self) -> bool:
        return self.get_error_code_msg() == (-32002, self._invalid_ix_data_msg)

    def check_if_big_transaction(self) -> bool:
        """This exception is generated by solana python library"""
        if isinstance(self._receipt, BaseException):
            return str(self._receipt).startswith("transaction too large:")
        return False

    def check_if_budget_exceeded(self) -> bool:
        """Error can be received as receipt or can be result of throwing an Exception"""
        error_type = self.get_error()
        if not error_type:
            return False
        if isinstance(error_type, list):
            error_type = error_type[1]

        if not isinstance(error_type, str):
            return False

        if error_type == self._computation_budget_exceeded_type:
            return True

        if error_type == self._program_failed_to_complete_type:
            log_list = self.get_log_list()
            for log in reversed(log_list):
                if log.startswith(self._exceeded_cu_number_log):
                    return True
                if log == self._log_truncated_log:
                    if self.get_error_code_msg() == (-32002, self._program_failed_msg):
                        return True

        return False

    def check_if_require_resize_iter(self) -> bool:
        if self.get_error_code_msg() != (-32002, self._program_failed_msg):
            return False

        log_list = self.get_log_list()
        for log in reversed(log_list):
            if log.find(self._require_resize_iter_log) != -1:
                return True
        return False

    def check_if_account_already_exists(self) -> bool:
        log_list = self.get_log_list()
        for log in log_list:
            m = self._create_account_re.search(log)
            if m is not None:
                return True
        return False

    def check_if_already_finalized(self) -> bool:
        log_list = self.get_log_list()
        for log in log_list:
            if log == self._already_finalized_log:
                return True
        return False

    def check_if_accounts_blocked(self) -> bool:
        log_list = self.get_log_list()
        for log in log_list:
            if (log.find(self._read_only_blocked_log) >= 0) or (log.find(self._read_write_blocked_log) >= 0):
                return True
        return False

    def check_if_blockhash_notfound(self) -> bool:
        if not self._receipt:
            return True
        return self.get_error() == self._blockhash_notfound_err

    def check_if_alt_uses_invalid_index(self) -> bool:
        return self.get_error_code_msg() == (-32602, self._alt_invalid_idx_msg)

    def check_if_already_processed(self) -> bool:
        return self._get_value('data', 'err') == 'AlreadyProcessed'

    def get_slots_behind(self) -> Optional[int]:
        return self._get_value('data', self._numslots_behind_data)

    def get_nonce_error(self) -> Tuple[Optional[int], Optional[int]]:
        log_list = self._get_log_list()
        for log in log_list:
            s = self._nonce_re.search(log)
            if s is not None:
                state_tx_cnt, tx_nonce = s.groups()
                return int(state_tx_cnt), int(tx_nonce)
        return None, None
