from __future__ import annotations

import sys
import json
import base58

from decimal import Decimal
from typing import Dict, List, Any

from proxy.common_neon.address import NeonAddress
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.solana_tx import SolPubKey
from proxy.common_neon.config import Config
from proxy.neon_core_api.neon_client import NeonClient

from .secret import get_key_info_list, get_res_info_list, get_token_name


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class InfoHandler:
    def __init__(self):
        self._config = Config()
        self._solana = SolInteractor(self._config)
        self._neon_client = NeonClient(self._config)
        self.command = 'info'

    @staticmethod
    def init_args_parser(parsers) -> InfoHandler:
        h = InfoHandler()
        h.root_parser = parsers.add_parser(h.command)
        h.sub_parser = h.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')
        h.holder_parser = h.sub_parser.add_parser('holder-accounts')
        h.solana_pk_parser = h.sub_parser.add_parser('solana-private-keys')
        h.neon_pk_parser = h.sub_parser.add_parser('neon-private-keys')
        h.neon_parser = h.sub_parser.add_parser('neon-accounts')
        h.solana_parser = h.sub_parser.add_parser('solana-accounts')
        h.full_parser = h.sub_parser.add_parser('full')
        return h

    def execute(self, args) -> None:
        if args.subcommand == 'holder-accounts':
            self._holder_accounts_info(args)
        elif args.subcommand == 'solana-private-keys':
            self._solana_private_key_info(args)
        elif args.subcommand == 'neon-private-keys':
            self._neon_private_key_info(args)
        elif args.subcommand == 'neon-accounts':
            self._neon_address_info(args)
        elif args.subcommand == 'solana-accounts':
            self._solana_accounts_info(args)
        elif args.subcommand == 'full' or args.subcommand is None:
            self._all_info(args)
        else:
            print(f'Unknown command {args.subcommand} for info', file=sys.stderr)
            return

    def _holder_accounts_info(self, _) -> None:
        res_info_list = get_res_info_list()
        for res_info in res_info_list:
            acct_info = self._solana.get_account_info(res_info.holder_account)
            if acct_info is None:
                continue

            balance = Decimal(acct_info.lamports) / 1_000_000_000
            holder_address = str(res_info.holder_account)
            print(f'{ holder_address }\t { str(res_info) }\t { balance:,.9f} SOL')

    @staticmethod
    def _solana_private_key_info(_) -> None:
        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            address = str(key_info.public_key)
            private = base58.b58encode(key_info.private_key).decode('utf-8')

            print(f'{ address }\t { private }')

    @staticmethod
    def _neon_private_key_info(_) -> None:
        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            for neon_addr in key_info.neon_address_list:
                print(
                    f'{ get_token_name(neon_addr.chain_id) }\t '
                    f'{ neon_addr.checksum_address }\t '
                    f'{ str(neon_addr.private_key) }'
                )

    def _neon_address_info(self, _) -> None:
        total_balance_dict: Dict[str, Decimal] = dict()
        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            print(f'{ str(key_info.public_key) }:')
            for neon_addr in key_info.neon_address_list:
                token_name = get_token_name(neon_addr.chain_id)
                balance = self._get_neon_balance(neon_addr)
                total_balance_dict[token_name] = total_balance_dict.get(token_name, Decimal(0)) + balance

                print(f'\t { neon_addr.checksum_address }\t { balance:,.18f} { token_name }')

        print('total_balance:')
        for token_name, balance in total_balance_dict.items():
            print(f' { balance:,.18f} { token_name }')

    def _solana_accounts_info(self, _) -> None:
        total_balance = Decimal(0)
        resource_balance = Decimal(0)

        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            balance = self._get_sol_balance(key_info.public_key)
            total_balance += balance

            print(f'{ str(key_info.public_key) }\t {balance:,.9f} SOL')
            print('holders:')
            for holder_info in key_info.holder_info_list:
                balance = self._get_sol_balance(holder_info.public_key)
                if balance == Decimal(0):
                    continue
                resource_balance += balance
                print(f'\t { str(holder_info.public_key) }\t { balance:,.9f} SOL')

        print(f'total_balance\t { total_balance:,.9f} SOL')
        print(f'resource_balance\t { resource_balance:,.9f} SOL')

    def _all_info(self, _) -> None:
        op_acct_list: List[Dict[str, Any]] = list()
        neon_balance_dict: Dict[str, Decimal] = dict()
        sol_balance = Decimal(0)
        resource_balance = Decimal(0)

        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            holder_list: List[Dict[str, Any]] = list()
            for holder_info in key_info.holder_info_list:
                balance = self._get_sol_balance(holder_info.public_key)
                if balance == Decimal(0):
                    continue

                holder_list.append(dict(
                    address=str(holder_info.public_key),
                    res_id=holder_info.res_id,
                    balance=balance
                ))

            resource_balance += sum([holder_info['balance'] for holder_info in holder_list])

            neon_acct_dict: Dict[str, Dict[str, Any]] = {
                get_token_name(neon_addr.chain_id): dict(
                    neon_address=neon_addr.checksum_address,
                    neon_private=str(neon_addr.private_key),
                    chain_id=neon_addr.chain_id,
                    balance=self._get_neon_balance(neon_addr)
                )
                for neon_addr in key_info.neon_address_list
            }
            for token_name, neon_addr_info in neon_acct_dict.items():
                neon_balance = neon_addr_info['balance']
                neon_balance_dict[token_name] = neon_balance_dict.get(token_name, Decimal(0)) + neon_balance

            sol_balance = self._get_sol_balance(key_info.public_key)

            op_acct_list.append(dict(
                address=str(key_info.public_key),
                balance=sol_balance,
                private=base58.b58encode(key_info.private_key).decode('utf-8'),
                holders=holder_list,
                neon_balances=neon_acct_dict
            ))

        res_js = dict(
            total_sol_balance=sol_balance,
            total_resource_balance=resource_balance,
            total_neon_balance=neon_balance_dict,
            accounts=op_acct_list
        )

        print(json.dumps(res_js, cls=DecimalEncoder))

    def _get_neon_balance(self, neon_address: NeonAddress) -> Decimal:
        neon_layout = self._neon_client.get_neon_account_info(neon_address)
        return Decimal(neon_layout.balance) / (10 ** 18) if neon_layout else 0

    def _get_sol_balance(self, sol_pubkey: SolPubKey) -> Decimal:
        balance = self._solana.get_sol_balance(sol_pubkey)
        return Decimal(balance) / (10 ** 9)
