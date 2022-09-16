from __future__ import annotations

import time
import json
import base58

from logged_groups import logged_group
from typing import Optional, List, Dict, Any, NamedTuple, Union
from enum import Enum

from solana.transaction import Transaction, Blockhash
from solana.account import Account as SolanaAccount

from .solana_tx_error_parser import SolTxErrorParser, SolTxError
from .solana_interactor import SolanaInteractor
from .errors import EthereumError, BlockedAccountsError, NodeBehindError

from .environment_data import SKIP_PREFLIGHT, CONFIRMATION_CHECK_DELAY, RETRY_ON_FAIL, CONFIRM_TIMEOUT
from .environment_data import FUZZING_BLOCKHASH


class NamedTransaction(NamedTuple):
    name: str
    tx: Transaction

    @property
    def recent_blockhash(self) -> Blockhash:
        return self.tx.recent_blockhash

    @recent_blockhash.setter
    def set_recent_blockhash(self, blockhash: Blockhash) -> None:
        self.tx.recent_blockhash = blockhash

    def signature(self) -> Optional[bytes]:
        return self.tx.signature()

    def serialize(self) -> bytes:
        return self.tx.serialize()

    def sign(self, *signers: SolanaAccount) -> None:
        self.tx.sign(*signers)


class SolTxState(NamedTuple):
    class Status(Enum):
        Undefined = 0
        GoodReceipt = 1
        BehindClusterError = 2
        BlockhashNotFoundError = 3
        AltInvalidIndexError = 4
        BlockedAccountError = 5
        BudgetExceededError = 6
        BadNonceError = 7
        UnknownError = 255

    status: Status
    name: str
    sig: str
    tx: Union[Transaction, NamedTransaction]
    receipt: Dict[str, Any]


@logged_group("neon.Proxy")
class SolTxListSender:
    ONE_BLOCK_TIME = 0.4

    def __init__(self, solana: SolanaInteractor, signer: SolanaAccount):
        self._solana = solana
        self._signer = signer
        self._retry_idx = 0
        self._blockhash: Optional[Blockhash] = None
        self._tx_state_dict: Dict[SolTxState.Status, List[SolTxState]] = {}

    def clear(self) -> None:
        self._retry_idx = 0
        self._blockhash = None
        self._tx_state_dict.clear()

    def send(self, tx_list: List[Union[Transaction, NamedTransaction]],
             skip_preflight=SKIP_PREFLIGHT, preflight_commitment='processed') -> SolTxListSender:
        self.

        while (self._retry_idx < RETRY_ON_FAIL) and len(self._tx_list):
            self._retry_idx += 1
            self._slots_behind = 0

            self.debug(
                f'retry {self._retry_idx}, ' +
                f'total receipts {len(receipt_list)}, ' +
                f'success receipts {len(self.success_sig_list)}(+{len(success_sig_list)}), ' +
                f'node behind {len(self._node_behind_list)}, ' +
                f'bad blocks {len(self._bad_block_list)}, ' +
                f'alt invalid idx {len(self._alt_invalid_index_list)}, ' +
                f'blocked accounts {len(self._blocked_account_list)}, ' +
                f'budget exceeded {len(self._budget_exceeded_list)}, ' +
                f'unknown error: {len(self._unknown_error_list)}'
            )

            self.success_sig_list += success_sig_list
            self._on_post_send()

        if len(self._tx_list):
            raise EthereumError(message='No more retries to complete transaction!')
        return self

    def _get_tx_status(self, tx_receipt: Optional[Dict[str, Any]]) -> SolTxState.Status:
        if tx_receipt is None:
            return SolTxState.Status.Undefined

        error_parser = SolTxErrorParser(tx_receipt)
        slots_behind = error_parser.get_slots_behind()
        state_tx_cnt, tx_nonce = error_parser.get_nonce_error()

        if slots_behind is not None:
            self.warning(f'Node is behind by {self._slots_behind} slots')
            return SolTxState.Status.BehindClusterError
        elif state_tx_cnt is not None:
            self.debug(f'tx nonce {tx_nonce} != state tx count {state_tx_cnt}')
            return SolTxState.Status.BadNonceError
        elif error_parser.check_if_alt_uses_invalid_index():
            return SolTxState.Status.AltInvalidIndexError
        elif error_parser.check_if_blockhash_notfound():
            return SolTxState.Status.BlockhashNotFoundError
        elif error_parser.check_if_accounts_blocked():
            return SolTxState.Status.BlockedAccountError
        elif error_parser.check_if_account_already_exists():
            self.debug(f'skip create account error')
            return SolTxState.Status.GoodReceipt
        elif error_parser.check_if_budget_exceeded():
            return SolTxState.Status.BudgetExceededError
        elif error_parser.check_if_error():
            self.debug(f'unknown_error_receipt: {json.dumps(tx_receipt, sort_keys=True)}')
            return SolTxState.Status.UnknownError
        return SolTxState.Status.GoodReceipt

    def _add_tx_state(self, tx: Union[Transaction, NamedTransaction], tx_receipt: Optional[Dict[str, Any]]) -> None:
        tx_status = self._get_tx_status(tx_receipt)
        self._tx_state_dict.setdefault(tx_status, []).append(
            SolTxState(
                status=tx_status,
                name=tx.name if isinstance(tx, NamedTransaction) else "Unknown",
                sig=base58.b58encode(tx.signature()).decode("utf-8"),
                tx=tx,
                receipt=tx_receipt
            )
        )

    def _on_success_send(self, tx: Transaction, receipt: Dict[str, Any]) -> bool:
        """Store the last successfully blockhash and set it in _set_tx_blockhash"""
        self._blockhash = tx.recent_blockhash
        return False

    def _on_post_send(self):
        if len(self._unknown_error_list):
            raise SolTxError(self._unknown_error_receipt)
        elif len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            raise NodeBehindError()

        elif len(self._budget_exceeded_list):
            raise SolTxError(self._budget_exceeded_receipt)

        if len(self._alt_invalid_index_list):
            time.sleep(self.ONE_BLOCK_TIME)
        elif len(self._blocked_account_list):
            raise BlockedAccountsError()

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
        SolTxErrorParser.raise_budget_exceeded()

    def _get_fuzzing_blockhash(self) -> Blockhash:
        block_slot = max(self._solana.get_recent_blockslot() - 525, 10)
        return self._solana.get_blockhash(block_slot)

    def _send_tx_list(self, tx_list: List[Union[NamedTransaction, Transaction]],
                     skip_preflight: bool, preflight_commitment: str) -> None:
        if self._blockhash is None:
            self._blockhash = self._solana.get_recent_blockhash()

        fuzzing_blockhash = self._get_fuzzing_blockhash() if FUZZING_BLOCKHASH else None

        for idx, tx in enumerate(tx_list):
            if FUZZING_BLOCKHASH and (idx % 2) == 0:
                tx.recent_blockhash = fuzzing_blockhash
            else:
                tx.recent_blockhash = self._blockhash
            tx.sign(self._signer)

        send_result_list = self._solana.send_tx_list(
            self._signer, tx_list, skip_preflight, preflight_commitment
        )

        for tx, tx_receipt in zip(tx_list, send_result_list):
            self._add_tx_state(tx, tx_receipt.error if tx_receipt.error is not None else None)

    def _confirm_tx_list(self, tx_sig_list: List[str]) -> None:
        """Confirm a transaction."""
        if not len(tx_sig_list):
            self.debug('No confirmations, because transaction list is empty')
            return

        elapsed_time = 0
        while elapsed_time < CONFIRM_TIMEOUT:
            if elapsed_time > 0:
                time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY

            block_slot, is_confirmed = self._solana.get_confirmed_slot_for_tx_sig_list(tx_sig_list)

            if is_confirmed:
                self.debug(f'Got confirmed status for transactions: {tx_sig_list}')
                return

        self.warning(f'No confirmed status for transactions: {tx_sig_list}')
