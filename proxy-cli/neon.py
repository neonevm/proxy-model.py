from __future__ import annotations

from decimal import Decimal

import math
import sys
import os

from typing import Optional, Dict

from web3 import Web3
from web3.eth import Eth
from web3.types import Wei
from eth_typing import Address
from eth_account import Account

from proxy.common_neon.address import NeonAddress

from .secret import get_key_info_list, get_token_name, get_token_name_list


class NeonHandler:
    _percent = 'PERCENT'
    _percent_postfix = '_PERCENT'

    def __init__(self):
        self.command = 'neon-account'
        self._proxy_dict: Dict[int, Eth] = dict()
        self._gas_price_dict: Dict[int, Wei] = dict()

    @staticmethod
    def init_args_parser(parsers) -> NeonHandler:
        n = NeonHandler()
        n.root_parser = parsers.add_parser(n.command)
        n.sub_parser = n.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')

        n.list_parser = n.sub_parser.add_parser('list')

        n.withdraw_parser = n.sub_parser.add_parser('withdraw')
        n.withdraw_parser.add_argument('dest_address', type=str, help='destination address for withdraw')
        n.withdraw_parser.add_argument('amount', type=int, help='withdrawing amount')

        token_name_list = get_token_name_list()

        token_list = '|'.join(token_name_list + [name + NeonHandler._percent_postfix for name in token_name_list])
        n.withdraw_parser.add_argument(
            'type', type=str, default=NeonHandler._percent, nargs='?',
            help=f'type of amount <{NeonHandler._percent}|{token_list}>'
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
        return Decimal(amount) / (10 ** 18)

    def _get_neon_addr_dict(self) -> Dict[NeonAddress, Wei]:
        key_info_list = get_key_info_list()

        neon_acct_dict = {
            neon_acct.neon_addr: self._proxy(neon_acct.chain_id).get_balance(Address(bytes(neon_acct.neon_addr)))
            for key_info in key_info_list
            for neon_acct in key_info.neon_account_dict.values()
        }
        return neon_acct_dict

    def _proxy(self, chain_id: int) -> Eth:
        proxy = self._proxy_dict.get(chain_id)
        if proxy:
            return proxy

        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        # TODO: fix chain-id URL
        # token_name = get_token_name(chain_id)
        # proxy_url = proxy_url + '/' + token_name

        proxy = Web3(Web3.HTTPProvider(proxy_url)).eth
        self._proxy_dict[chain_id] = proxy
        return proxy

    def _gas_price(self, chain_id: int) -> Wei:
        gas_price = self._gas_price_dict.get(chain_id)
        if gas_price:
            return gas_price

        gas_price = self._proxy(chain_id).gas_price
        self._gas_price_dict[chain_id] = gas_price
        return gas_price

    def _create_tx(self, from_addr: NeonAddress, to_addr: Address, amount: int) -> dict:
        signer = Account.from_key(from_addr.private_key)
        tx = dict(
            chainId=from_addr.chain_id,
            gasPrice=self._gas_price(from_addr.chain_id),
            nonce=self._proxy(from_addr.chain_id).get_transaction_count(signer.address, 'pending'),
            to=to_addr,
            value=amount
        )
        tx['from'] = signer.address
        return tx

    def _send_tx(self, from_addr: NeonAddress, to_addr: Address, amount: Wei, gas: int) -> None:
        signer = Account.from_key(from_addr.private_key)
        tx = self._create_tx(from_addr, to_addr, amount)
        tx['gas'] = gas

        proxy = self._proxy(from_addr.chain_id)
        tx_signed = proxy.account.sign_transaction(tx, signer.key)
        tx_hash = proxy.send_raw_transaction(tx_signed.rawTransaction)
        amount = self._get_neon_amount(amount)
        token_name = get_token_name(from_addr.chain_id)

        print(f'send {amount:,.18} {token_name} from {str(from_addr)} to 0x{to_addr.hex()}: 0x{tx_hash.hex()}')

    def _estimate_tx(self, from_addr: NeonAddress, to_addr: Address) -> int:
        tx = self._create_tx(from_addr, to_addr, 1)
        return self._proxy(from_addr.chain_id).estimate_gas(tx)

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

        token_name_list = get_token_name_list()
        token_set = set(token_name_list + [name + self._percent_postfix for name in token_name_list] + [self._percent])

        amount = Wei(args.amount)
        a_type: str = args.type.upper()
        if a_type not in token_set:
            print(f'wrong type of amount type {a_type}, should be {", ".join(sorted(token_set))}', file=sys.stderr)
            return
        elif amount <= 0:
            print(f'amount {amount} should be more than 0', file=sys.stderr)
            return
        elif amount > 100 and (a_type == self._percent or a_type.endswith(self._percent_postfix)):
            print(f'amount {amount} is too big, should be less or equal 100', file=sys.stderr)
            return

        neon_acct_dict = self._get_neon_addr_dict()

        total_balance = 0
        token_balance_dict: Dict[str, int] = dict()
        for neon_addr, balance in neon_acct_dict.items():
            total_balance += balance
            token_name = get_token_name(neon_addr.chain_id)
            token_balance_dict[token_name] = token_balance_dict.get(token_name, 0) + balance

        if a_type == self._percent:
            amount = Wei(math.floor(total_balance * amount / 100))
        elif a_type.endswith(self._percent_postfix):
            a_type = a_type[:-len(self._percent_postfix)]
            token_balance = token_balance_dict.get(a_type, 0)
            amount = Wei(math.floor(token_balance * amount / 100))
        else:
            token_balance = token_balance_dict.get(a_type, 0)
            check_balance = math.ceil(token_balance / (10 ** 18))
            if check_balance < amount:
                print(f'amount {amount} is too big, should be less than {check_balance}', file=sys.stderr)
                return
            amount = Wei(amount * (10 ** 18))

        sent_amount_dict: Dict[str, int] = dict()
        for neon_addr, balance in neon_acct_dict.items():
            if balance <= 0:
                continue
            token_name = get_token_name(neon_addr.chain_id)
            if a_type not in {self._percent, token_name}:
                continue

            gas = self._estimate_tx(neon_addr, dest_addr)
            tx_cost = gas * self._gas_price(neon_addr.chain_id)
            balance -= tx_cost
            if balance <= 0:
                continue

            balance = min(balance, amount)
            self._send_tx(neon_addr, dest_addr, balance, gas)

            amount -= balance
            sent_amount_dict[token_name] = sent_amount_dict.get(token_name, 0) + balance

            if amount <= 0:
                break

        for token_name, balance in sent_amount_dict:
            balance = self._get_neon_amount(balance)
            print(f'successfully send {balance:,.18} {token_name} to 0x{dest_addr.hex()}')
