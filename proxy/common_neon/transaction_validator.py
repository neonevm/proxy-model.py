from __future__ import annotations

from logged_groups import logged_group
from .eth_proto import Trx as EthTx
from .address import EthereumAddress
from .errors import EthereumError
from .account_whitelist import AccountWhitelist
from .solana_receipt_parser import SolReceiptParser

from ..environment import ACCOUNT_PERMISSION_UPDATE_INT


@logged_group("neon.Proxy")
class NeonTxValidator:
    MAX_U64 = pow(2, 64)

    def __init__(self, solana, tx: EthTx):
        self._solana = solana
        self._tx = tx

        self._sender = '0x' + tx.sender()
        self._account_info = self._solana.get_account_info_layout(EthereumAddress(self._sender))

        self._deployed_contract = tx.contract()
        if self._deployed_contract:
            self._deployed_contract = '0x' + self._deployed_contract

    def prevalidate_tx(self, signer):
        self._prevalidate_tx_nonce()
        self._prevalidate_sender_balance()
        self._prevalidate_whitelist(signer)

    def extract_ethereum_error(self, e: Exception):
        receipt_parser = SolReceiptParser(e)
        nonce_error = receipt_parser.get_nonce_error()
        if nonce_error:
            self._raise_nonce_error(nonce_error[0], nonce_error[1])

    def _prevalidate_whitelist(self, signer):
        w = AccountWhitelist(self._solana, ACCOUNT_PERMISSION_UPDATE_INT, signer)
        if not w.has_client_permission(self._sender[2:]):
            self.warning(f'Sender account {self._sender} is not allowed to execute transactions')
            raise RuntimeError(f'Sender account {self._sender} is not allowed to execute transactions')

        if (self._deployed_contract is not None) and (not w.has_contract_permission(self._deployed_contract[2:])):
            self.warning(f'Contract account {self._deployed_contract} is not allowed for deployment')
            raise RuntimeError(f'Contract account {self._deployed_contract} is not allowed for deployment')

    def _prevalidate_tx_nonce(self):
        if not self._account_info:
            return

        tx_nonce = int(self._tx.nonce)
        if self.MAX_U64 not in (self._account_info.trx_count, tx_nonce):
            if tx_nonce == self._account_info.trx_count:
                return

        self._raise_nonce_error(self._account_info.trx_count, tx_nonce)

    def _prevalidate_sender_balance(self):
        if self._account_info:
            user_balance = self._account_info.balance
        else:
            user_balance = 0

        required_balance = self._tx.gasPrice * self._tx.gasLimit + self._tx.value

        if required_balance < user_balance:
            return

        self._raise_balance_error(user_balance, required_balance)

    def _raise_balance_error(self, user_balance: int, required_balance: int):
        message = 'insufficient funds for gas * price + value'
        raise EthereumError(f"{message}: address {self._sender} have {user_balance} want {required_balance}")

    def _raise_nonce_error(self, account_tx_count: int, tx_nonce: int):
        if self.MAX_U64 in (account_tx_count, tx_nonce):
            message = 'nonce has max value'
        elif account_tx_count > tx_nonce:
            message = 'nonce too low'
        else:
            message = 'nonce too high'

        raise EthereumError(code=-32002,
                            message=f'{message}: address {self._sender}, tx: {tx_nonce} state: {account_tx_count}')



