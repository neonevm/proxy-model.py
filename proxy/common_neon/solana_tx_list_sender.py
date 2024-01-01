import enum
import logging
import random
import dataclasses

from typing import Optional, List, Dict, Set

from .errors import (
    BlockHashNotFound, NonceTooLowError, NonceTooHighError,
    CUBudgetExceededError, InvalidIxDataError, RequireResizeIterError,
    CommitLevelError, NodeBehindError, NoMoreRetriesError, BlockedAccountError, ALTAlreadyExistError,
    RescheduleError, WrongStrategyError, OutOfGasError, ALTInvalidIndexError
)

from .config import Config
from .solana_interactor import SolInteractor
from .solana_tx import SolTx, SolBlockHash, SolTxReceipt, SolAccount, SolCommit
from .solana_tx_error_parser import SolTxErrorParser, SolTxError


LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
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

        # Rescheduling errors
        NodeBehindError = enum.auto()
        BlockedAccountError = enum.auto()
        AltInvalidIndexError = enum.auto()
        AltAlreadyExistError = enum.auto()

        # Wrong strategy error
        CUBudgetExceededError = enum.auto()
        InvalidIxDataError = enum.auto()
        RequireResizeIterError = enum.auto()

        # Fail errors
        BadNonceError = enum.auto()
        OutOfGasError = enum.auto()
        UnknownError = enum.auto()

    status: Status
    tx: SolTx
    receipt: Optional[SolTxReceipt]
    error: Optional[BaseException]

    @property
    def sig(self) -> str:
        return str(self.tx.sig)

    @property
    def block_slot(self) -> Optional[int]:
        return self.receipt.get('slot') if self.receipt else None

    @property
    def name(self) -> str:
        return self.tx.name

    def clear_error(self) -> None:
        object.__setattr__(self, 'error', None)


class SolTxListSender:
    _confirmed_level = SolCommit.to_level(SolCommit.Confirmed)

    _good_tx_status_list = (
        SolTxSendState.Status.WaitForReceipt,
        SolTxSendState.Status.GoodReceipt,
        SolTxSendState.Status.AccountAlreadyExistsError,
        SolTxSendState.Status.AlreadyFinalizedError,
    )

    _resubmitted_tx_status_list = (
        SolTxSendState.Status.NoReceiptError,
        SolTxSendState.Status.BlockHashNotFoundError,
        SolTxSendState.Status.NodeBehindError,
    )

    def __init__(self, config: Config, solana: SolInteractor, signer: SolAccount):
        self._config = config
        self._solana = solana
        self._signer = signer
        self._block_hash: Optional[SolBlockHash] = None
        self._bad_block_hash_set: Set[SolBlockHash] = set()
        self._tx_list: List[SolTx] = list()
        self._rescheduled_tx_list: List[SolTx] = list()
        self._tx_state_dict: Dict[str, SolTxSendState] = dict()
        self._tx_state_list_dict: Dict[SolTxSendState.Status, List[SolTxSendState]] = dict()

    def send(self, tx_list: List[SolTx]) -> bool:
        assert not len(self._tx_list)
        if len(tx_list) == 0:
            return False

        self._tx_list = tx_list
        return self._send()

    def recheck(self, tx_list: List[SolTx]) -> bool:
        assert not len(self._tx_list)
        if len(tx_list) == 0:
            return False

        for tx in self._tx_list:
            LOG.debug(f'Recheck {tx.name}: {str(tx.sig)}')

        # The Sender should check all (failed too) txs again, because the state may have changed
        tx_sig_list = [str(tx.sig) for tx in tx_list]
        self._get_tx_receipt_list(tx_sig_list, tx_list)

        # If the Neon tx is finalized - no retries
        if self._is_already_finalized():
            self._validate_commit_level()
            return True

        # On the last attempt the Sender faced the blocked accounts error,
        # so try to send just 1! solana tx to get the control on the accounts.
        # But just do it for not-started tx
        if not self.has_good_sol_tx_receipt():
            self._get_tx_list_to_block_account()

        # This is the new sending attempt,
        # so prevent the raising of rescheduling errors
        self._clear_errors()

        # If there were no problems with blocked accounts, do it in the direct way
        if not len(self._tx_list):
            self._get_tx_list_for_send()

        return self._send()

    @property
    def tx_state_list(self) -> List[SolTxSendState]:
        return list(self._tx_state_dict.values())

    def has_good_sol_tx_receipt(self) -> bool:
        for status in self._good_tx_status_list:
            if status in self._tx_state_list_dict:
                return True
        return False

    def clear(self) -> None:
        self._block_hash = None
        self._tx_list.clear()
        self._tx_state_dict.clear()
        self._tx_state_list_dict.clear()

    def _get_tx_list_to_block_account(self) -> None:
        """
        - Try to find the non-cloned txs with the blocked account error
        - Create a cloned tx from the first found tx
        - Save other non-cloned txs for the second send
        - Keep sent txs in the state map for future rechecks"""

        tx_state_list = self._tx_state_list_dict.get(SolTxSendState.Status.BlockedAccountError, None)
        if not tx_state_list:
            return

        for tx_state in tx_state_list:
            if tx_state.tx.is_cloned():
                continue

            if not len(self._tx_list):
                self._tx_list.append(tx_state.tx.clone())
            else:
                self._rescheduled_tx_list.append(tx_state.tx)

    def _clear_errors(self) -> None:
        """Clear rescheduled errors to prevent raising of errors on check status."""
        for tx_state_list in self._tx_state_list_dict.values():
            for tx_state in tx_state_list:
                if tx_state.error:
                    LOG.debug(f'Clear error for {tx_state.sig} with the status: {tx_state.status.name}')
                    tx_state.clear_error()

    def _send(self) -> bool:
        try:
            self._send_impl()
            self._validate_commit_level()
            return True  # always True, because we send all txs

        except (WrongStrategyError, RescheduleError):
            raise

        except BaseException:
            self._validate_commit_level()
            raise

    def _send_impl(self) -> None:
        retry_on_fail = self._config.retry_on_fail
        for retry_idx in range(retry_on_fail):
            if len(self._tx_list) == 0:
                return

            self._sign_tx_list()
            self._send_tx_list()
            LOG.debug(f'retry {retry_idx} sending stat: {self._fmt_stat()}')

            # get txs with preflight check errors for resubmitting
            self._get_tx_list_for_send()
            if len(self._tx_list) != 0:
                continue

            # get receipts from the network
            self._wait_for_tx_receipt_list()
            LOG.debug(f'retry {retry_idx} waiting stat: {self._fmt_stat()}')

            # at this point the Sender has all receipts from the network,
            #  some txs (blockhash errors for example) can require the resending
            self._get_tx_list_for_send()
            self._get_rescheduled_tx_list_for_send()

        if len(self._tx_list) > 0:
            raise NoMoreRetriesError()

    def _validate_commit_level(self) -> None:
        """ Find the maximum block slot in the receipt list,
        and check the commitment level of the block."""
        commit_level = self._config.commit_level
        if commit_level <= self._confirmed_level:
            return

        # find maximum block slot
        max_block_slot = 0
        for tx_state in self._tx_state_dict.values():
            if tx_state.block_slot:
                max_block_slot = max(max_block_slot, tx_state.block_slot)

        if max_block_slot == 0:
            LOG.debug('Tx list does not contain a block - skip validating of the commit level')
            return

        max_block_status = self._solana.get_block_status(max_block_slot)
        if SolCommit.to_level(max_block_status.commitment) < commit_level:
            raise CommitLevelError(self._config.commit_type, max_block_status.commitment)

    def _fmt_stat(self) -> str:
        if not LOG.isEnabledFor(logging.DEBUG):
            return ''

        result = ''
        for tx_status in list(SolTxSendState.Status):
            if tx_status not in self._tx_state_list_dict:
                continue

            cnt = len(self._tx_state_list_dict[tx_status])

            if len(result) > 0:
                result += ', '
            result += f'{tx_status.name} {cnt}'
        return result

    def _get_fuzz_block_hash(self) -> SolBlockHash:
        block_slot = max(self._solana.get_recent_block_slot() - random.randint(525, 1025), 2)
        block_hash = self._solana.get_block_hash(block_slot)
        LOG.debug(f'fuzzing block hash: {block_hash}')
        return block_hash

    def _get_block_hash(self) -> SolBlockHash:
        if self._block_hash in self._bad_block_hash_set:
            self._block_hash = None

        if self._block_hash:
            return self._block_hash

        resp = self._solana.get_recent_block_hash()
        if resp.block_hash in self._bad_block_hash_set:
            raise BlockHashNotFound()

        self._block_hash = resp.block_hash

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

            if tx.recent_block_hash:
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
            tx_receipt = send_result.error if not send_result.result else None
            self._add_tx_receipt(tx, tx_receipt, no_receipt_status)

        if not fuzz_fail_pct:
            return

        # Fuzz testing of skipping of txs by Solana node
        for tx in skipped_tx_list:
            self._add_tx_receipt(tx, None, no_receipt_status)
        # <- Fuzz testing

    def _fmt_tx_name_stat(self) -> str:
        if not LOG.isEnabledFor(logging.DEBUG):
            return ''

        tx_name_dict: Dict[str, int] = dict()
        for tx in self._tx_list:
            tx_name = tx.name if len(tx.name) > 0 else 'Unknown'
            tx_name_dict[tx_name] = tx_name_dict.get(tx_name, 0) + 1

        return ' + '.join([f'{name}({cnt})' for name, cnt in tx_name_dict.items()])

    def _is_already_finalized(self) -> bool:
        """The Neon tx is finalized"""
        result = SolTxSendState.Status.AlreadyFinalizedError in self._tx_state_list_dict
        if result:
            LOG.debug('Neon tx is already finalized')
        return result

    def _get_tx_list_for_send(self) -> None:
        self._tx_list.clear()

        # no errors and resending, because the Neon tx is finalized
        if self._is_already_finalized():
            return

        # Raise error if
        for tx_status_list in self._tx_state_list_dict.values():
            error = tx_status_list[0].error
            if error:
                raise error

        # Resend txs with the resubmitted status
        for tx_status in self._resubmitted_tx_status_list:
            tx_state_list = self._tx_state_list_dict.pop(tx_status, None)
            if not tx_state_list:
                continue

            self._tx_list.extend([tx_state.tx for tx_state in tx_state_list])

    def _get_rescheduled_tx_list_for_send(self) -> None:
        """If we are here, the accounts are blocked, and we can send the bulk of txs"""
        if not len(self._rescheduled_tx_list):
            return

        self._tx_list.extend([tx.clone() for tx in self._rescheduled_tx_list])
        self._rescheduled_tx_list.clear()

    def _wait_for_tx_receipt_list(self) -> None:
        tx_state_list = self._tx_state_list_dict.pop(SolTxSendState.Status.WaitForReceipt, None)
        if not tx_state_list:
            LOG.debug('no new receipts, because the transaction list is empty')
            return

        tx_sig_list: List[str] = list()
        tx_list: List[SolTx] = list()
        for tx_state in tx_state_list:
            tx_sig_list.append(tx_state.sig)
            tx_list.append(tx_state.tx)

        self._solana.check_confirm_of_tx_sig_list(
            tx_sig_list,
            SolCommit.Confirmed,
            self._config.confirm_timeout_sec
        )

        self._get_tx_receipt_list(tx_sig_list, tx_list)

    def _get_tx_receipt_list(self, tx_sig_list: Optional[List[str]], tx_list: List[SolTx]) -> None:
        no_receipt_status = SolTxSendState.Status.NoReceiptError
        tx_receipt_list = self._solana.get_tx_receipt_list(tx_sig_list, SolCommit.Confirmed)
        for tx, tx_receipt in zip(tx_list, tx_receipt_list):
            self._add_tx_receipt(tx, tx_receipt, no_receipt_status)

    @dataclasses.dataclass(frozen=True)
    class _DecodeResult:
        tx_status: SolTxSendState.Status
        error: Optional[BaseException]

    def _decode_tx_status(self, tx: SolTx, tx_receipt: Optional[SolTxReceipt]) -> _DecodeResult:
        status = SolTxSendState.Status
        tx_error_parser = SolTxErrorParser(tx_receipt)

        slots_behind = tx_error_parser.get_slots_behind()
        if slots_behind:
            return self._DecodeResult(status.NodeBehindError, NodeBehindError(slots_behind))
        elif tx_error_parser.check_if_block_hash_notfound():
            if tx.recent_block_hash not in self._bad_block_hash_set:
                LOG.debug(f'bad block hash: {tx.recent_block_hash}')
                self._bad_block_hash_set.add(tx.recent_block_hash)
            # no exception: reset blockhash on the next tx signing
            return self._DecodeResult(status.BlockHashNotFoundError, None)
        elif tx_error_parser.check_if_alt_uses_invalid_index():
            return self._DecodeResult(status.AltInvalidIndexError, ALTInvalidIndexError())
        elif tx_error_parser.check_if_alt_already_exists():
            return self._DecodeResult(status.AltAlreadyExistError, ALTAlreadyExistError())
        elif tx_error_parser.check_if_already_finalized():
            # no exception: receipt exists - the goal is reached
            return self._DecodeResult(status.AlreadyFinalizedError, None)
        elif tx_error_parser.check_if_accounts_blocked():
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

        has_gas_limit, req_gas_limit = tx_error_parser.get_out_of_gas_error()
        if has_gas_limit is not None:
            return self._DecodeResult(status.OutOfGasError, OutOfGasError(has_gas_limit, req_gas_limit))

        state_tx_cnt, tx_nonce = tx_error_parser.get_nonce_error()
        if state_tx_cnt is not None:
            if tx_nonce < state_tx_cnt:
                # sender is unknown - should be replaced on upper stack level
                return self._DecodeResult(status.BadNonceError, NonceTooLowError.init_no_sender(tx_nonce, state_tx_cnt))
            else:
                return self._DecodeResult(status.BadNonceError, NonceTooHighError(state_tx_cnt))

        elif tx_error_parser.check_if_error():
            LOG.debug(f'unknown error receipt {str(tx.sig)}: {tx_receipt}')
            # no exception: will be converted to DEFAULT EXCEPTION
            return self._DecodeResult(status.UnknownError, SolTxError(tx_receipt))

        return self._DecodeResult(status.GoodReceipt, None)

    def _add_tx_receipt(self, tx: SolTx, tx_receipt: Optional[SolTxReceipt], no_receipt_status: SolTxSendState.Status):
        if not tx_receipt:
            res = self._DecodeResult(no_receipt_status, None)
        else:
            res = self._decode_tx_status(tx, tx_receipt)

        tx_state = SolTxSendState(
            status=res.tx_status,
            tx=tx,
            receipt=tx_receipt,
            error=res.error,
        )

        status = SolTxSendState.Status
        if tx_state.status not in (status.WaitForReceipt, status.UnknownError):
            LOG.debug(f'tx status {tx_state.sig} ({tx_state.name}): {tx_state.status.name}')

        self._tx_state_dict[tx_state.sig] = tx_state
        self._tx_state_list_dict.setdefault(tx_state.status, list()).append(tx_state)
