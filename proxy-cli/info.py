from __future__ import annotations
from decimal import Decimal

import sys
import json
import base58
from typing import List, Dict, Any

from proxy.common_neon.address import NeonAddress, account_with_seed, perm_account_seed
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.operator_secret_mng import OpSecretMng
from proxy.common_neon.solana_tx import SolAccount, SolPubKey
from proxy.common_neon.config import Config


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class InfoHandler:
    def __init__(self):
        self._config = Config()
        self._solana = SolInteractor(self._config, self._config.solana_url)
        self.command = 'info'

    def _get_solana_accounts(self) -> List[SolAccount]:
        secret_list = OpSecretMng(self._config).read_secret_list()
        return [SolAccount.from_seed(secret) for secret in secret_list]

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
            ret_js = self._all_info(args)
            print(json.dumps(ret_js, cls=DecimalEncoder))
        else:
            print(f'Unknown command {args.subcommand} for account', file=sys.stderr)
            return

    def _holder_accounts_info(self, _) -> None:
        stop_perm_account_id = self._config.perm_account_id + self._config.perm_account_limit
        for sol_account in self._get_solana_accounts():
            for rid in range(self._config.perm_account_id, stop_perm_account_id):
                holder_address = self._generate_holder_address(sol_account.pubkey(), rid)

                print(f'{ str(holder_address) }')

    def _solana_private_key_info(self, _) -> None:
        for sol_account in self._get_solana_accounts():
            address = str(sol_account.pubkey())
            private = base58.b58encode(sol_account.secret()).decode('utf-8')

            print(f'{ address }\t { private }')

    def _neon_private_key_info(self, _) -> None:
        neon_accounts = [
            NeonAddress.from_private_key(operator.secret())
            for operator in self._get_solana_accounts()
        ]

        for neon_account in neon_accounts:
            address = str(neon_account)
            private = str(neon_account.private)

            print(f'{ address }\t { private }')

    def _neon_address_info(self, _) -> None:
        total_balance = Decimal(0)
        operator_accounts = self._get_solana_accounts()
        neon_accounts = [NeonAddress.from_private_key(operator.secret()) for operator in operator_accounts]

        for neon_account in neon_accounts:
            address = str(neon_account)
            balance = self._get_neon_balance(neon_account)
            total_balance += balance

            print(f'{ address }\t { balance:,.18f}')

        print(f'total_balance\t { total_balance:,.18f}')

    def _solana_accounts_info(self, _) -> None:
        total_balance = Decimal(0)
        resource_balance = Decimal(0)

        operator_accounts = self._get_solana_accounts()

        for sol_account in operator_accounts:
            acc_info_js = self._get_solana_account_info(sol_account)

            address = acc_info_js['address']
            balance = acc_info_js['balance']
            holder_account_list = acc_info_js['holder']

            total_balance += balance

            print(f'{ address }\t { balance:,.9f}')
            print('holder:')

            for holder_account in holder_account_list:
                address = holder_account['address']
                balance = holder_account['balance']
                resource_balance += balance

                print(f'\t { address }\t { balance:,.9f}')

        print(f'total_balance\t { total_balance:,.9f}')
        print(f'resource_balance\t { resource_balance:,.9f}')

    def _all_info(self, _) -> Dict[str, Any]:
        ret_js = {
            'accounts': [],
            'total_balance': Decimal(0),
            'resource_balance': Decimal(0),
            'total_neon_balance': Decimal(0)
        }

        operator_accounts = self._get_solana_accounts()
        neon_accounts = [NeonAddress.from_private_key(operator.secret()) for operator in operator_accounts]

        for sol_account, neon_account in zip(operator_accounts, neon_accounts):
            acc_info_js = self._get_solana_account_info(sol_account)
            acc_info_js['private'] = base58.b58encode(sol_account.secret()).decode('utf-8')

            ret_js['total_balance'] += acc_info_js['balance']

            for holder_account in acc_info_js['holder']:
                ret_js['resource_balance'] += holder_account['balance']

            acc_info_js['neon_address'] = str(neon_account)
            acc_info_js['neon_private'] = str(neon_account.private)
            acc_info_js['neon_balance'] = self._get_neon_balance(neon_account)

            ret_js['total_neon_balance'] += acc_info_js['neon_balance']

            ret_js['accounts'].append(acc_info_js)

        return ret_js

    def _generate_holder_address(self, base_address: SolPubKey, rid: int) -> SolPubKey:
        return self._generate_resource_address(base_address, b'holder-', rid)

    def _generate_resource_address(self, base_address: SolPubKey, prefix: bytes, rid: int) -> SolPubKey:
        seed = perm_account_seed(prefix, rid)
        return account_with_seed(self._config.evm_program_id, base_address, seed)

    def _get_neon_balance(self, neon_address: NeonAddress) -> Decimal:
        neon_layout = self._solana.get_neon_account_info(neon_address)
        return Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000 if neon_layout else 0

    def _get_solana_account_info(self, sol_account: SolAccount) -> Dict[str, Any]:
        resource_tags = {
            0: 'EMPTY',
            11: 'NEON_ACCOUNT',
            21: 'ACTIVE_HOLDER_ACCOUNT',
            31: 'FINALIZED_HOLDER_ACCOUNT',
            4: 'ERC20_ALLOWANCE',
        }

        acc_info_js = {
            'address': str(sol_account.pubkey()),
            'balance': Decimal(self._solana.get_sol_balance(sol_account.pubkey())) / 1_000_000_000,
            'holder': []
        }

        stop_perm_account_id = self._config.perm_account_id + self._config.perm_account_limit
        for rid in range(self._config.perm_account_id, stop_perm_account_id):
            holder_address = self._generate_holder_address(sol_account.pubkey(), rid)
            holder_info = self._solana.get_account_info(holder_address)

            if holder_info:
                holder_account = {
                    'address': str(holder_address),
                    'status': resource_tags.get(holder_info.tag, 'UNKNOWN'),
                    'balance': Decimal(holder_info.lamports) / 1_000_000_000,
                }
                acc_info_js['holder'].append(holder_account)

        return acc_info_js
