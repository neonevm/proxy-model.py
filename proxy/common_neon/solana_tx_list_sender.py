from __future__ import annotations

import time
import abc

from logged_groups import logged_group
from typing import Optional, List, Dict, Any
from base58 import b58encode

from solana.transaction import Transaction
from solana.account import Account as SolanaAccount

from .solana_receipt_parser import SolReceiptParser, SolTxError
from .solana_interactor import SolanaInteractor
from .errors import EthereumError

from .environment_data import SKIP_PREFLIGHT, CONFIRMATION_CHECK_DELAY, RETRY_ON_FAIL, CONFIRM_TIMEOUT


class IConfirmWaiter(abc.ABC):
    def __init__(self):
        pass

    @abc.abstractmethod
    def on_wait_confirm(self, elapsed_time: int, block_slot: int, is_confirmed: bool) -> None:
        """Event on waiting of tx confirmation from Solana"""


@logged_group("neon.Proxy")
class SolTxListSender:
    def __init__(self, solana: SolanaInteractor, signer: SolanaAccount):
        self._solana = solana
        self._signer = signer

        self._blockhash = None
        self._retry_idx = 0
        self._slots_behind = 0
        self.success_sign_list: List[str] = []
        self._tx_list: List[Transaction] = []
        self._node_behind_list: List[Transaction] = []
        self._bad_block_list: List[Transaction] = []
        self._blocked_account_list: List[Transaction] = []
        self._pending_list: List[Transaction] = []
        self._budget_exceeded_list: List[Transaction] = []
        self._budget_exceeded_receipt: Optional[Dict[str, Any]] = None
        self._unknown_error_list: List[Transaction] = []
        self._unknown_error_receipt: Optional[Dict[str, Any]] = None

        self._all_tx_list = [
            self._node_behind_list,
            self._bad_block_list,
            self._blocked_account_list,
            self._budget_exceeded_list,
            self._pending_list
        ]

    def clear(self):
        self._tx_list.clear()
        for lst in self._all_tx_list:
            lst.clear()
        self._budget_exceeded_receipt = None
        self._unknown_error_receipt = None

    def _get_full_tx_list(self):
        return [tx for lst in self._all_tx_list for tx in lst]

    def send(self, name: str, tx_list: List[Transaction],
             skip_preflight=SKIP_PREFLIGHT, preflight_commitment='processed',
             waiter: Optional[IConfirmWaiter] = None) -> SolTxListSender:
        self.debug(f'start transactions sending: {name}')

        self.clear()
        self._tx_list = tx_list

        while (self._retry_idx < RETRY_ON_FAIL) and len(self._tx_list):
            self._retry_idx += 1
            self._slots_behind = 0

            receipt_list = self._send_tx_list(skip_preflight, preflight_commitment, waiter)

            success_sign_list = []
            for receipt, tx in zip(receipt_list, self._tx_list):
                receipt_parser = SolReceiptParser(receipt)
                slots_behind = receipt_parser.get_slots_behind()
                if slots_behind:
                    self._slots_behind = slots_behind
                    self._node_behind_list.append(tx)
                elif receipt_parser.check_if_blockhash_notfound():
                    self._bad_block_list.append(tx)
                elif receipt_parser.check_if_accounts_blocked():
                    self._blocked_account_list.append(tx)
                elif receipt_parser.check_if_budget_exceeded():
                    self._budget_exceeded_list.append(tx)
                    self._budget_exceeded_receipt = receipt
                elif receipt_parser.check_if_error():
                    self._unknown_error_list.append(tx)
                    self._unknown_error_receipt = receipt
                else:
                    success_sign_list.append(b58encode(tx.signature()).decode("utf-8"))
                    self._retry_idx = 0
                    self._on_success_send(tx, receipt)

            self.debug(
                f'retry {self._retry_idx}, ' +
                f'total receipts {len(receipt_list)}, ' +
                f'success receipts {len(self.success_sign_list)}(+{len(success_sign_list)}), ' +
                f'node behind {len(self._node_behind_list)}, '
                f'bad blocks {len(self._bad_block_list)}, ' +
                f'blocked accounts {len(self._blocked_account_list)}, ' +
                f'budget exceeded {len(self._budget_exceeded_list)}, ' +
                f'unknown error: {len(self._unknown_error_list)}'
            )

            self.success_sign_list += success_sign_list
            self._on_post_send()

        if len(self._tx_list):
            raise EthereumError(message='No more retries to complete transaction!')
        return self

    def _on_success_send(self, tx: Transaction, receipt: Dict[str, Any]) -> bool:
        """Store the last successfully blockhash and set it in _set_tx_blockhash"""
        self._blockhash = tx.recent_blockhash
        return False

    def _on_post_send(self):
        if len(self._unknown_error_list):
            raise SolTxError(self._unknown_error_receipt)
        elif len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            time.sleep(1)
        elif len(self._budget_exceeded_list):
            raise SolTxError(self._budget_exceeded_receipt)

        if len(self._blocked_account_list):
            time.sleep(0.4)  # one block time

        # force changing of recent_blockhash if Solana doesn't accept the current one
        if len(self._bad_block_list):
            self._blockhash = None

        # resend not-accepted transactions
        self._move_tx_list()

    def _set_tx_blockhash(self, tx: Transaction) -> None:
        """Try to keep the branch of block history"""
        tx.recent_blockhash = self._blockhash
        tx.signatures.clear()

    def _move_tx_list(self) -> None:
        full_tx_list = self._get_full_tx_list()
        self.clear()
        for tx in full_tx_list:
            self._set_tx_blockhash(tx)
            self._tx_list.append(tx)
        if len(self._tx_list):
            self.debug(f' Resend Solana transactions: {len(self._tx_list)}')

    def raise_budget_exceeded(self) -> None:
        if self._budget_exceeded_receipt is not None:
            raise SolTxError(self._budget_exceeded_receipt)
        SolReceiptParser.raise_budget_exceeded()

    def _send_tx_list(self, skip_preflight: bool, preflight_commitment: str,
                      waiter: Optional[IConfirmWaiter]) -> List[Dict[str, Any]]:

        send_result_list = self._solana.send_multiple_transactions(
            self._signer, self._tx_list, skip_preflight, preflight_commitment
        )
        # Filter good transactions and wait the confirmations for them
        sign_list = [s.result for s in send_result_list if s.result]
        self._confirm_tx_list(sign_list, waiter)

        # Get receipts for good transactions
        confirmed_list = self._solana.get_multiple_receipts(sign_list)
        # Mix errors with receipts for good transactions
        receipt_list = []
        for s in send_result_list:
            if s.error:
                receipt_list.append(s.error)
            else:
                receipt_list.append(confirmed_list.pop(0))

        return receipt_list

    def _confirm_tx_list(self, sign_list: List[str], waiter: Optional[IConfirmWaiter]) -> None:
        """Confirm a transaction."""
        if not len(sign_list):
            self.debug('No confirmations, because transaction list is empty')
            return

        elapsed_time = 0
        while elapsed_time < CONFIRM_TIMEOUT:
            if elapsed_time > 0:
                time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY

            block_slot, is_confirmed = self._solana.get_confirmed_slot_for_multiple_transactions(sign_list)
            if waiter is not None:
                waiter.on_wait_confirm(elapsed_time, block_slot, is_confirmed)

            if is_confirmed:
                self.debug(f'Got confirmed status for transactions: {sign_list}')
                return

        self.warning(f'No confirmed status for transactions: {sign_list}')
