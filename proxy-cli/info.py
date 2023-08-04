from __future__ import annotations
from decimal import Decimal

import sys
import json
import base58
from typing import Dict, Any, List

from proxy.common_neon.address import NeonAddress, account_with_seed, perm_account_seed
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.operator_resource_info import OpResInfo, OpResIdent
from proxy.common_neon.solana_tx import SolAccount, SolPubKey
from proxy.common_neon.config import Config
from proxy.common_neon.constants import HOLDER_TAG, EMPTY_HOLDER_TAG, ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG

from .secret import get_res_ident_list, get_solana_acct_list


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
            print(f'Unknown command {args.subcommand} for info', file=sys.stderr)
            return

    def _holder_accounts_info(self, _) -> None:
        op_res_ident_list = get_res_ident_list()
        for op_res_ident in op_res_ident_list:
            op_res_info = OpResInfo.from_ident(op_res_ident)
            holder_info = self._solana.get_holder_account_info(op_res_info.holder_account)
            if holder_info is None:
                continue

            balance = Decimal(holder_info.lamports) / 1_000_000_000
            holder_address = str(op_res_info.holder_account)
            op_key = op_res_ident.public_key
            print(f'{ holder_address }\t { op_key }:{ op_res_ident.res_id }\t { balance:,.9f} SOL')

    @staticmethod
    def _solana_private_key_info(_) -> None:
        for sol_account in get_solana_acct_list():
            address = str(sol_account.pubkey())
            private = base58.b58encode(sol_account.secret()).decode('utf-8')

            print(f'{ address }\t { private }')

    @staticmethod
    def _neon_private_key_info(_) -> None:
        neon_accounts = [
            NeonAddress.from_private_key(operator.secret())
            for operator in get_solana_acct_list()
        ]

        for neon_account in neon_accounts:
            address = str(neon_account)
            private = str(neon_account.private)

            print(f'{ address }\t { private }')

    def _neon_address_info(self, _) -> None:
        total_balance = Decimal(0)
        op_acct_list = get_solana_acct_list()
        neon_acct_list = [NeonAddress.from_private_key(operator.secret()) for operator in op_acct_list]

        for sol_acct, neon_acct in zip(op_acct_list, neon_acct_list):
            address = str(neon_acct)
            balance = self._get_neon_balance(neon_acct)
            total_balance += balance

            print(f'{ address }\t { str(sol_acct.pubkey()) }\t { balance:,.18f} NEON')

        print(f'total_balance\t { total_balance:,.18f} NEON')

    def _solana_accounts_info(self, _) -> None:
        total_balance = Decimal(0)
        resource_balance = Decimal(0)

        op_acct_list = get_solana_acct_list()
        op_res_ident_list = get_res_ident_list()

        for sol_acct in op_acct_list:
            acc_info_js = self._get_solana_account_info(sol_acct, op_res_ident_list)

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

        op_acct_list = get_solana_acct_list()
        op_res_ident_list = get_res_ident_list()
        neon_acct_list = [NeonAddress.from_private_key(operator.secret()) for operator in op_acct_list]

        for sol_acct, neon_acct in zip(op_acct_list, neon_acct_list):
            acc_info_js = self._get_solana_account_info(sol_acct, op_res_ident_list)
            acc_info_js['private'] = base58.b58encode(sol_acct.secret()).decode('utf-8')

            ret_js['total_balance'] += acc_info_js['balance']

            for holder_account in acc_info_js['holder']:
                ret_js['resource_balance'] += holder_account['balance']

            acc_info_js['neon_address'] = str(neon_acct)
            acc_info_js['neon_private'] = str(neon_acct.private)
            acc_info_js['neon_balance'] = self._get_neon_balance(neon_acct)

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

    def _get_solana_account_info(self, sol_acct: SolAccount, op_res_ident_list: List[OpResIdent]) -> Dict[str, Any]:
        res_tag_dict = {
            EMPTY_HOLDER_TAG: 'EMPTY',
            HOLDER_TAG: 'HOLDER_ACCOUNT',
            ACTIVE_HOLDER_TAG: 'ACTIVE_HOLDER_ACCOUNT',
            FINALIZED_HOLDER_TAG: 'FINALIZED_HOLDER_ACCOUNT',
        }

        acc_info_js = {
            'address': str(sol_acct.pubkey()),
            'balance': Decimal(self._solana.get_sol_balance(sol_acct.pubkey())) / 1_000_000_000,
            'holder': []
        }

        op_key = str(sol_acct.pubkey())

        stop_perm_account_id = self._config.perm_account_id + self._config.perm_account_limit
        for op_res_ident in op_res_ident_list:
            if op_res_ident.res_id >= stop_perm_account_id:
                continue
            if op_res_ident.public_key != op_key:
                continue

            op_res_info = OpResInfo.from_ident(op_res_ident)
            holder_info = self._solana.get_account_info(op_res_info.holder_account)

            if holder_info:
                holder_account = {
                    'address': str(op_res_info.holder_account),
                    'status': res_tag_dict.get(holder_info.tag, 'UNKNOWN'),
                    'balance': Decimal(holder_info.lamports) / 1_000_000_000,
                }
                acc_info_js['holder'].append(holder_account)

        return acc_info_js
