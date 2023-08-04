from __future__ import annotations

from decimal import Decimal

import math
import sys
import os

from typing import Optional

from web3 import Web3
from eth_typing import Address
from eth_account import Account

from proxy.common_neon.address import NeonAddress

from .secret import get_solana_acct_list


class NeonHandler:
    def __init__(self):
        self.command = 'neon-account'

    @staticmethod
    def init_args_parser(parsers) -> NeonHandler:
        n = NeonHandler()
        n.root_parser = parsers.add_parser(n.command)
        n.sub_parser = n.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')

        n.list_parser = n.sub_parser.add_parser('list')

        n.withdraw_parser = n.sub_parser.add_parser('withdraw')
        n.withdraw_parser.add_argument('dest_address', type=str, help='destination address for withdraw')
        n.withdraw_parser.add_argument('amount', type=int, help='withdrawing amount')
        n.withdraw_parser.add_argument(
            'type', type=str, default='PERCENT', nargs='?',
            help='type of amount <PERCENT|NEON>'
        )
        return n

    def execute(self, args) -> None:
        if args.subcommand == 'withdraw':
            self._withdraw_neon(args)
        else:
            print(f'Unknown command {args.subcommand} for account', file=sys.stderr)
            return

    @staticmethod
    def _get_neon_amount(amount: int) -> Decimal:
        return Decimal(amount) / 1_000_000_000 / 1_000_000_000

    def _get_neon_addr_dict(self) -> dict:
        op_acct_list = get_solana_acct_list()
        neon_acct_list = [NeonAddress.from_private_key(op.secret()) for op in op_acct_list]
        neon_acct_dict = {
            neon_addr: self._proxy.get_balance(Address(bytes(neon_addr)))
            for neon_addr in neon_acct_list
        }
        return neon_acct_dict

    def _connect_to_proxy(self) -> None:
        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        self._proxy = Web3(Web3.HTTPProvider(proxy_url)).eth
        self._gas_price = self._proxy.gas_price
        self._chain_id = self._proxy.chain_id

    def _create_tx(self, from_addr: NeonAddress, to_addr: Address, amount: int) -> dict:
        signer = Account.from_key(from_addr.private)
        tx = dict(
            chainId=self._chain_id,
            gasPrice=self._gas_price,
            nonce=self._proxy.get_transaction_count(signer.address, 'pending'),
            to=to_addr,
            value=amount
        )
        tx['from'] = signer.address
        return tx

    def _send_tx(self, from_addr: NeonAddress, to_addr: Address, amount: int, gas: int) -> None:
        signer = Account.from_key(from_addr.private)
        tx = self._create_tx(from_addr, to_addr, amount)
        tx['gas'] = gas

        tx_signed = self._proxy.account.sign_transaction(tx, signer.key)
        tx_hash = self._proxy.send_raw_transaction(tx_signed.rawTransaction)
        amount = self._get_neon_amount(amount)

        print(f'send {amount:,.18} NEON from {str(from_addr)} to 0x{to_addr.hex()}: 0x{tx_hash.hex()}')

    def _estimate_tx(self, from_addr: NeonAddress, to_addr: Address) -> int:
        tx = self._create_tx(from_addr, to_addr, 1)
        return self._proxy.estimate_gas(tx)

    @staticmethod
    def _normalize_address(raw_addr: str) -> Optional[Address]:
        try:
            address = raw_addr.lower()
            assert address[:2] == '0x'
            address = address[2:]

            bin_address = bytes.fromhex(address)
            assert len(bin_address) == 20

            return Address(bin_address)
        except (Exception,):
            print(f'wrong destination address', file=sys.stderr)
            return None

    def _withdraw_neon(self, args) -> None:
        dest_addr = self._normalize_address(args.dest_address)
        if dest_addr is None:
            return

        amount = args.amount
        a_type = args.type.upper()
        if a_type not in {'PERCENT', 'NEON'}:
            print(f'wrong type of amount type {a_type}, should be PERCENT or NEON', file=sys.stderr)
            return
        elif amount <= 0:
            print(f'amount {amount} should be more than 0', file=sys.stderr)
            return
        elif amount > 100 and a_type == 'PERCENT':
            print(f'amount {amount} is too big, should be less or equal 100', file=sys.stderr)
            return

        self._connect_to_proxy()

        neon_acct_dict = self._get_neon_addr_dict()

        total_balance = 0
        for balance in neon_acct_dict.values():
            total_balance += balance

        if a_type == 'NEON':
            check_balance = math.ceil(total_balance / 1_000_000_000 / 1_000_000_000)
            if check_balance < amount:
                print(f'amount {amount} is too big, should be less than {check_balance}', file=sys.stderr)
                return

            amount = amount * 1_000_000_000 * 1_000_000_000
        elif a_type == 'PERCENT':
            amount = math.floor(total_balance * amount / 100)

        total_amount = 0
        for neon_addr, balance in neon_acct_dict.items():
            if balance <= 0:
                continue

            gas = self._estimate_tx(neon_addr, dest_addr)
            tx_cost = gas * self._gas_price
            balance -= tx_cost
            if balance <= 0:
                continue

            balance = min(balance, amount)
            self._send_tx(neon_addr, dest_addr, balance, gas)

            amount -= balance
            total_amount += balance

            if amount <= 0:
                break

        total_amount = self._get_neon_amount(total_amount)
        print(f'successfully send {total_amount:,.18} NEON to 0x{dest_addr.hex()}')
