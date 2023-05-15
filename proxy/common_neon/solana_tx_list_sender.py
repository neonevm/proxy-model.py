import enum
import logging
import random
import time

from dataclasses import dataclass
from typing import Optional, List, Dict, Set

from .errors import (
    BlockHashNotFound, NonceTooLowError,
    CUBudgetExceededError, InvalidIxDataError, RequireResizeIterError,
    CommitLevelError, NodeBehindError, NoMoreRetriesError, BlockedAccountError,
    RescheduleError, WrongStrategyError
)

from .config import Config
from .solana_interactor import SolInteractor
from .solana_tx import SolTx, SolBlockHash, SolTxReceipt, SolAccount, SolCommit
from .solana_tx_error_parser import SolTxErrorParser, SolTxError
from .utils import str_enum


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolTxSendState:
    class Status(enum.Enum):
        # Good receipts
        WaitForReceipt = enum.auto()
        GoodReceipt = enum.auto()

        # Skipped errors
        AccountAlreadyExistsError = enum.auto()
        AlreadyFinalizedError = enum.auto()

        # Resubmitted errors
        NoReceiptError = enum.auto()
        BlockHashNotFoundError = enum.auto()
        AltInvalidIndexError = enum.auto()

        # Rescheduling errors
        NodeBehindError = enum.auto()
        BlockedAccountError = enum.auto()
        BlockedAccountPrepError = enum.auto()

        # Wrong strategy error
        CUBudgetExceededError = enum.auto()
        InvalidIxDataError = enum.auto()
        RequireResizeIterError = enum.auto()

        # Fail errors
        BadNonceError = enum.auto()
        UnknownError = enum.auto()

    status: Status
    tx: SolTx
    valid_block_height: int
    receipt: Optional[SolTxReceipt]
    error: Optional[BaseException]

    @property
    def sig(self) -> str:
        return str(self.tx.sig)

    @property
    def block_slot(self) -> Optional[int]:
        if self.receipt is None:
            return None
        return self.receipt.get('slot')

    @property
    def name(self) -> str:
        return self.tx.name


class SolTxListSender:
    _commit_set = SolCommit.upper_set(SolCommit.Confirmed)
    _big_block_height = 2 ** 64 - 1
    _big_block_slot = 2 ** 64 - 1

    _completed_tx_status_set = {
        SolTxSendState.Status.WaitForReceipt,
        SolTxSendState.Status.GoodReceipt,
        SolTxSendState.Status.AccountAlreadyExistsError,
        SolTxSendState.Status.AlreadyFinalizedError,
    }

    _resubmitted_tx_status_set = {
        SolTxSendState.Status.NoReceiptError,
        SolTxSendState.Status.BlockHashNotFoundError,
        SolTxSendState.Status.AltInvalidIndexError,
        SolTxSendState.Status.BlockedAccountPrepError,
    }

    def __init__(self, config: Config, solana: SolInteractor, signer: SolAccount):
        self._config = config
        self._solana = solana
        self._signer = signer
        self._block_hash: Optional[SolBlockHash] = None
        self._valid_block_height = self._big_block_height
        self._block_hash_dict: Dict[SolBlockHash, int] = dict()
        self._bad_block_hash_set: Set[SolBlockHash] = set()
        self._tx_list: List[SolTx] = list()
        self._tx_state_dict: Dict[str, SolTxSendState] = dict()
        self._tx_state_list_dict: Dict[SolTxSendState.Status, List[SolTxSendState]] = dict()

    def send(self, tx_list: List[SolTx]) -> bool:
        self.clear()
        if len(tx_list) == 0:
            return False

        self._tx_list = tx_list
        return self._send()

    def recheck(self, tx_list: List[SolTx]) -> bool:
        self.clear()
        if len(tx_list) == 0:
            return False

        # We should check all (failed too) txs again, because the state can be changed
        tx_sig_list = [str(tx.sig) for tx in tx_list]
        self._get_tx_receipt_list(tx_sig_list, tx_list)

        if not self._get_tx_list_for_lock_account():
            self._get_tx_list_for_send()

        return self._send()

    @property
    def tx_state_list(self) -> List[SolTxSendState]:
        return list(self._tx_state_dict.values())

    def has_completed_receipt(self) -> bool:
        for status in self._completed_tx_status_set:
            if status in self._tx_state_list_dict:
                return True
        return False

    def clear(self) -> None:
        self._block_hash = None
        self._tx_list.clear()
        self._tx_state_dict.clear()
        self._tx_state_list_dict.clear()

    def _get_tx_list_for_lock_account(self) -> bool:
        if self.has_completed_receipt():
            return False

        status = SolTxSendState.Status
        tx_state_list = self._tx_state_list_dict.get(status.BlockedAccountError, list())
        for tx_state in tx_state_list:
            tx = tx_state.tx
            if not tx.is_cloned():
                self._tx_list.append(tx.clone())
                return True

        return False

    def _send(self) -> bool:
        try:
            self._send_impl()
            self._validate_commit_level()
            return True  # always True, because we send txs

        except (WrongStrategyError, RescheduleError):
            raise

        except (BaseException,):
            self._validate_commit_level()
            raise

    def _send_impl(self) -> None:
        retry_on_fail = self._config.retry_on_fail

        for retry_idx in range(retry_on_fail):
            if len(self._tx_list) == 0:
                break

            self._sign_tx_list()
            self._send_tx_list()
            LOG.debug(f'retry {retry_idx} sending stat: {self._fmt_stat()}')

            # get txs with preflight check errors for resubmitting
            self._get_tx_list_for_send()
            if len(self._tx_list) != 0:
                continue

            # get receipts from network
            self._wait_for_tx_receipt_list()
            LOG.debug(f'retry {retry_idx} waiting stat: {self._fmt_stat()}')

            self._get_tx_list_for_send()

        if len(self._tx_list) > 0:
            raise NoMoreRetriesError()

    def _validate_commit_level(self) -> None:
        commit_level = self._config.commit_level
        if commit_level == SolCommit.Confirmed:
            return

        # find minimal block slot
        min_block_slot = self._big_block_slot
        for tx_state in self._tx_state_dict.values():
            tx_block_slot = tx_state.block_slot
            if tx_block_slot is not None:
                min_block_slot = min(min_block_slot, tx_block_slot)

        if min_block_slot == self._big_block_slot:
            LOG.debug('Tx list does not contain a block - skip validating of the commit level')
            return

        min_block_status = self._solana.get_block_status(min_block_slot)
        if SolCommit.level(min_block_status.commitment) < SolCommit.level(commit_level):
            raise CommitLevelError(commit_level, min_block_status.commitment)

    def _fmt_stat(self) -> str:
        if not LOG.isEnabledFor(logging.DEBUG):
            return ''

        result = ''
        for tx_status in list(SolTxSendState.Status):
            if tx_status not in self._tx_state_list_dict:
                continue

            name = str_enum(tx_status)
            cnt = len(self._tx_state_list_dict[tx_status])

            if len(result) > 0:
                result += ', '
            result += f'{name} {cnt}'
        return result

    def _get_fuzz_block_hash(self) -> SolBlockHash:
        block_slot = max(self._solana.get_recent_block_slot() - random.randint(525, 1025), 2)
        block_hash = self._solana.get_block_hash(block_slot)
        LOG.debug(f'fuzzing block hash: {block_hash}')
        return block_hash

    def _get_block_hash(self) -> SolBlockHash:
        if self._block_hash in self._bad_block_hash_set:
            self._block_hash = None

        if self._block_hash is not None:
            return self._block_hash

        resp = self._solana.get_recent_block_hash()
        if resp.block_hash in self._bad_block_hash_set:
            raise BlockHashNotFound()

        self._block_hash = resp.block_hash
        self._block_hash_dict[resp.block_hash] = resp.last_valid_block_height

        return self._block_hash

    def _sign_tx_list(self) -> None:
        fuzz_fail_pct = self._config.fuzz_fail_pct
        block_hash = self._get_block_hash()

        for tx in self._tx_list:
            if tx.is_signed:
                tx_sig = str(tx.sig)
                self._tx_state_dict.pop(tx_sig, None)
                if tx.recent_block_hash in self._bad_block_hash_set:
                    LOG.debug(f'Flash bad block hash: {tx.recent_block_hash} for tx {str(tx.sig)}')
                    tx.recent_block_hash = None

            if tx.recent_block_hash is not None:
                LOG.debug(f'Skip signing, tx {str(tx.sig)} has block hash {tx.recent_block_hash}')
                continue

            # Fuzz testing of bad blockhash
            if fuzz_fail_pct > 0 and (random.randint(1, 100) <= fuzz_fail_pct):
                tx.recent_block_hash = self._get_fuzz_block_hash()
            # <- Fuzz testing
            else:
                tx.recent_block_hash = block_hash
            tx.sign(self._signer)

    def _send_tx_list(self) -> None:
        fuzz_fail_pct = self._config.fuzz_fail_pct

        # Fuzz testing of skipping of txs by Solana node
        skipped_tx_list: List[SolTx] = list()
        if fuzz_fail_pct and (len(self._tx_list) > 1):
            flag_list = [random.randint(1, 100) <= fuzz_fail_pct for _ in self._tx_list]
            skipped_tx_list = [tx for tx, flag in zip(self._tx_list, flag_list) if flag]
            self._tx_list = [tx for tx, flag in zip(self._tx_list, flag_list) if not flag]
        # <- Fuzz testing

        LOG.debug(f'send transactions: {self._fmt_tx_name_stat()}')
        send_result_list = self._solana.send_tx_list(self._tx_list, skip_preflight=False)

        no_receipt_status = SolTxSendState.Status.WaitForReceipt
        for tx, send_result in zip(self._tx_list, send_result_list):
            tx_receipt = send_result.error if send_result.result is None else None
            self._add_tx_state(tx, tx_receipt, no_receipt_status)

        # Fuzz testing of skipping of txs by Solana node
        for tx in skipped_tx_list:
            self._add_tx_state(tx, None, no_receipt_status)
        # <- Fuzz testing

    def _fmt_tx_name_stat(self) -> str:
        if not LOG.isEnabledFor(logging.DEBUG):
            return ''

        tx_name_dict: Dict[str, int] = dict()
        for tx in self._tx_list:
            tx_name = tx.name if len(tx.name) > 0 else 'Unknown'
            tx_name_dict[tx_name] = tx_name_dict.get(tx_name, 0) + 1

        return ' + '.join([f'{name}({cnt})' for name, cnt in tx_name_dict.items()])

    def _get_tx_list_for_send(self) -> None:
        self._tx_list.clear()
        status = SolTxSendState.Status

        # the Neon tx is finalized in another Solana tx
        if status.AlreadyFinalizedError in self._tx_state_list_dict:
            return

        remove_tx_status_set: Set[SolTxSendState.Status] = set()
        for tx_status in list(status):
            if not self._check_tx_status_for_send(tx_status):
                continue

            remove_tx_status_set.add(tx_status)
            tx_state_list = self._tx_state_list_dict.get(tx_status)
            for tx_state in tx_state_list:
                if tx_state.tx.is_cloned():
                    continue

                tx = tx_state.tx
                if tx_state.status == status.BlockedAccountError:
                    tx = tx.clone()
                self._tx_list.append(tx)

        for tx_status in remove_tx_status_set:
            self._tx_state_list_dict.pop(tx_status)

    def _check_tx_status_for_send(self, tx_status: SolTxSendState.Status) -> bool:
        if tx_status in self._completed_tx_status_set:
            return False

        tx_state_list = self._tx_state_list_dict.get(tx_status, None)
        if tx_state_list is None:
            return False

        if tx_status == tx_status.AltInvalidIndexError:
            time.sleep(self._config.one_block_sec)

        if tx_status in self._resubmitted_tx_status_set:
            return True

        # The first few txs failed on blocked accounts, but the subsequent tx successfully locked the accounts.
        if tx_status == tx_status.BlockedAccountError:
            if self.has_completed_receipt():
                return True

        tx_state = tx_state_list[0]
        error = tx_state.error or SolTxError(self._config.evm_program_id, tx_state.receipt)
        raise error

    def _wait_for_tx_receipt_list(self) -> None:
        tx_state_list = self._tx_state_list_dict.pop(SolTxSendState.Status.WaitForReceipt, None)
        if tx_state_list is None:
            LOG.debug('No new receipts, because transaction list is empty')
            return

        tx_sig_list: List[str] = list()
        tx_list: List[SolTx] = list()
        valid_block_height = self._big_block_height
        for tx_state in tx_state_list:
            tx_sig_list.append(tx_state.sig)
            tx_list.append(tx_state.tx)
            valid_block_height = min(valid_block_height, tx_state.valid_block_height)

        self._wait_for_confirm_of_tx_list(tx_sig_list, valid_block_height)
        self._get_tx_receipt_list(tx_sig_list, tx_list)

    def _get_tx_receipt_list(self, tx_sig_list: Optional[List[str]], tx_list: List[SolTx]) -> None:
        tx_receipt_list = self._solana.get_tx_receipt_list(tx_sig_list, SolCommit.Confirmed)
        for tx, tx_receipt in zip(tx_list, tx_receipt_list):
            self._add_tx_state(tx, tx_receipt, SolTxSendState.Status.NoReceiptError)

    def _wait_for_confirm_of_tx_list(self, tx_sig_list: List[str], valid_block_height: int) -> None:
        confirm_timeout = self._config.confirm_timeout_sec
        confirm_check_delay = float(self._config.confirm_check_msec) / 1000
        elapsed_time = 0.0
        commit_set = self._commit_set

        while elapsed_time < confirm_timeout:
            is_confirmed = self._solana.check_confirm_of_tx_sig_list(tx_sig_list, commit_set, valid_block_height)
            if is_confirmed:
                return

            time.sleep(confirm_check_delay)
            elapsed_time += confirm_check_delay

    @dataclass(frozen=True)
    class _DecodeResult:
        tx_status: SolTxSendState.Status
        error: Optional[BaseException]

    def _decode_tx_status(self, tx: SolTx, tx_receipt: Optional[SolTxReceipt]) -> _DecodeResult:
        status = SolTxSendState.Status
        tx_error_parser = SolTxErrorParser(self._config.evm_program_id, tx_receipt)

        slots_behind = tx_error_parser.get_slots_behind()
        if slots_behind is not None:
            return self._DecodeResult(status.NodeBehindError, NodeBehindError(slots_behind))
        elif tx_error_parser.check_if_block_hash_notfound():
            if tx.recent_block_hash not in self._bad_block_hash_set:
                LOG.debug(f'bad block hash: {tx.recent_block_hash}')
                self._bad_block_hash_set.add(tx.recent_block_hash)
            # no exception: reset blockhash on tx signing
            return self._DecodeResult(status.BlockHashNotFoundError, None)
        elif tx_error_parser.check_if_alt_uses_invalid_index():
            # no exception: sleep on 1 block before getting receipt
            return self._DecodeResult(status.AltInvalidIndexError, None)
        elif tx_error_parser.check_if_already_finalized():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif tx_error_parser.check_if_accounts_blocked():
            if tx_error_parser.check_if_preprocessed_error():
                return self._DecodeResult(status.BlockedAccountPrepError, None)
            return self._DecodeResult(status.BlockedAccountError, BlockedAccountError())
        elif tx_error_parser.check_if_account_already_exists():
            # no exception: account exists - the goal is reached
            return self._DecodeResult(status.AccountAlreadyExistsError, None)
        elif tx_error_parser.check_if_invalid_ix_data():
            return self._DecodeResult(status.InvalidIxDataError, InvalidIxDataError())
        elif tx_error_parser.check_if_budget_exceeded():
            return self._DecodeResult(status.CUBudgetExceededError, CUBudgetExceededError())
        elif tx_error_parser.check_if_require_resize_iter():
            return self._DecodeResult(status.RequireResizeIterError, RequireResizeIterError())

        state_tx_cnt, tx_nonce = tx_error_parser.get_nonce_error()
        if state_tx_cnt is not None:
            # sender is unknown - should be replaced on upper stack level
            return self._DecodeResult(status.BadNonceError, NonceTooLowError.init_no_sender(tx_nonce, state_tx_cnt))
        elif tx_error_parser.check_if_error():
            LOG.debug(f'unknown error receipt {str(tx.sig)}: {tx_receipt}')
            # no exception: will be converted to DEFAULT EXCEPTION
            return self._DecodeResult(status.UnknownError, None)

        return self._DecodeResult(status.GoodReceipt, None)

    def _add_tx_state(self, tx: SolTx, tx_receipt: Optional[SolTxReceipt], no_receipt_status: SolTxSendState.Status):
        if tx_receipt is None:
            res = self._DecodeResult(no_receipt_status, None)
        else:
            res = self._decode_tx_status(tx, tx_receipt)
        valid_block_height = self._block_hash_dict.get(tx.recent_block_hash, self._big_block_height)

        tx_send_state = SolTxSendState(
            status=res.tx_status,
            tx=tx,
            receipt=tx_receipt,
            error=res.error,
            valid_block_height=valid_block_height
        )

        status = SolTxSendState.Status
        if tx_send_state.status not in {status.WaitForReceipt, status.UnknownError}:
            log_fn = LOG.warning if tx_receipt is None else LOG.debug
            log_fn(f'tx status {tx_send_state.sig}: {str_enum(tx_send_state.status)}')

        self._tx_state_dict[tx_send_state.sig] = tx_send_state
        self._tx_state_list_dict.setdefault(tx_send_state.status, list()).append(tx_send_state)
