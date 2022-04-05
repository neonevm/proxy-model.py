from __future__ import annotations
from argparse import _SubParsersAction, ArgumentParser

import sys
import os
import math
import json
from coincurve import PublicKey
import sha3

from proxy.common_neon.keys_storage import KeyStorage

from proxy.common_neon.address import EthereumAddress, accountWithSeed
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.environment import PERM_ACCOUNT_LIMIT, SOLANA_URL, get_solana_accounts


class InfoHandler:
    def __init__(self):
        self._solana = SolanaInteractor(SOLANA_URL)
        self.command = 'info'
        self._storage = None

    @staticmethod
    def init_args_parser(parsers: _SubParsersAction[ArgumentParser]) -> InfoHandler:
        h = InfoHandler()
        h.root_parser = parsers.add_parser(h.command)
        h.subparsers = h.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')
        h.holder_parser = h.subparsers.add_parser('holder-accounts')
        h.storage_parser = h.subparsers.add_parser('storage-accounts')
        h.solana_pk_parser = h.subparsers.add_parser('solana-private-key')
        h.neon_pk_parser = h.subparsers.add_parser('neon-private-key')
        h.neon_parser = h.subparsers.add_parser('neon-address')
        h.solana_parser = h.subparsers.add_parser('solana-accounts')
        return h

    def execute(self, args):
        if args.subcommand == 'holder-accounts':
            ret_js = self._holder_accounts_info(args)
        elif args.subcommand == 'storage-accounts':
            ret_js = self._storage_accounts_info(args)
        elif args.subcommand == 'solana-private-key':
            ret_js = self._solana_private_key_info(args)
        elif args.subcommand == 'neon-private-key':
            ret_js = self._neon_private_key_info(args)
        elif args.subcommand == 'neon-address':
            ret_js = self._neon_address_info(args)
        elif args.subcommand == 'solana-accounts':
            ret_js = self._solana_accounts_info(args)
        elif args.subcommand == None:
            ret_js = self._all_info(args)
        else:
            print(f'Unknown command {args.subcommand} for account', file=sys.stderr)
            return
        print(json.dumps(ret_js))

    def _holder_accounts_info(self, args):
        ret_js = {}
        ret_js['holder-accounts'] = []

        for sol_account in get_solana_accounts():
            for rid in range(max(PERM_ACCOUNT_LIMIT, 16)):
                holder_address = self._generate_holder_address(sol_account.public_key(), rid)
                ret_js['holder-accounts'].append(str(holder_address))

        return ret_js

    def _storage_accounts_info(self, args):
        ret_js = {}
        ret_js['storage-accounts'] = []

        for sol_account in get_solana_accounts():
            for rid in range(max(PERM_ACCOUNT_LIMIT, 16)):
                storage_address = self._generate_storage_address(sol_account.public_key(), rid)
                ret_js['storage-accounts'].append(str(storage_address))

        return ret_js

    def _solana_private_key_info(self, args):
        ret_js = {}
        ret_js['solana-accounts'] = []

        for sol_account in get_solana_accounts():
            acc_info_js = {}
            acc_info_js['address'] = str(sol_account.public_key())
            acc_info_js['private'] = list(sol_account.keypair())

            ret_js['solana-accounts'].append(acc_info_js)

        return ret_js

    def _neon_private_key_info(self, args):
        ret_js = {}
        ret_js['neon-accounts'] = []

        neon_accounts = [EthereumAddress.from_private_key(operator.secret_key()) for operator in get_solana_accounts()]

        for neon_account in neon_accounts:
            acc_info_js = {}
            acc_info_js['address'] = str(neon_account)
            acc_info_js['private'] = str(neon_account.private)

            ret_js['neon-accounts'].append(acc_info_js)

        return ret_js

    def _neon_address_info(self, args):
        ret_js = {}
        ret_js['neon-accounts'] = []
        ret_js['total_balance'] = 0

        operator_accounts = get_solana_accounts()
        neon_accounts = [EthereumAddress.from_private_key(operator.secret_key()) for operator in operator_accounts]

        for neon_account in neon_accounts:
            acc_info_js = {}
            acc_info_js['address'] = str(neon_account)
            acc_info_js['balance'] = self._get_neon_balance(neon_account)

            ret_js['total_balance'] += acc_info_js['balance']
            ret_js['neon-accounts'].append(acc_info_js)

        return ret_js

    def _solana_accounts_info(self, args):
        ret_js = {}
        ret_js['accounts'] = []
        ret_js['total_balance'] = 0
        ret_js['resource_balance'] = 0

        operator_accounts = get_solana_accounts()

        for sol_account in operator_accounts:
            acc_info_js = self._get_solana_accounts(sol_account)

            ret_js['total_balance'] += acc_info_js['balance']
            for holder_account in acc_info_js['holder']:
                ret_js['resource_balance'] += holder_account['balance']
            for storage_account in acc_info_js['storage']:
                ret_js['resource_balance'] += storage_account['balance']

            ret_js['accounts'].append(acc_info_js)

        return ret_js

    def _all_info(self, args):
        ret_js = {}
        ret_js['accounts'] = []
        ret_js['total_balance'] = 0
        ret_js['resource_balance'] = 0
        ret_js['total_neon_balance'] = 0

        operator_accounts = get_solana_accounts()
        neon_accounts = [EthereumAddress.from_private_key(operator.secret_key()) for operator in operator_accounts]

        for sol_account, neon_account in zip(operator_accounts, neon_accounts):
            acc_info_js = self._get_solana_accounts(sol_account)

            ret_js['total_balance'] += acc_info_js['balance']

            for holder_account in acc_info_js['holder']:
                ret_js['resource_balance'] += holder_account['balance']
            for storage_account in acc_info_js['storage']:
                ret_js['resource_balance'] += storage_account['balance']

            acc_info_js['neon_address'] = str(neon_account)
            acc_info_js['neon_balance'] = self._get_neon_balance(neon_account)

            ret_js['total_neon_balance'] += acc_info_js['neon_balance']

            ret_js['accounts'].append(acc_info_js)

        return ret_js

    def _generate_storage_address(self, base_address: PublicKey, rid: int) -> PublicKey:
        return self._generate_resource_address(base_address, rid, b'storage')

    def _generate_holder_address(self, base_address: PublicKey, rid: int) -> PublicKey:
        return self._generate_resource_address(base_address, rid, b'holder')

    def _generate_resource_address(self, base_address: PublicKey, rid: int, prefix: bytes) -> PublicKey:
        aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
        seed_base = prefix + aid
        seed = sha3.keccak_256(seed_base).hexdigest()[:32]
        seed = bytes(seed, 'utf8')
        account = accountWithSeed(base_address, seed)
        return account

    def _get_neon_balance(self, neon_address: EthereumAddress):
        neon_layout = self._solana.get_account_info_layout(neon_address)
        return neon_layout.balance if neon_layout else 0

    def _get_solana_accounts(self, sol_account):
        resource_tags = {
            0: 'EMPTY',
            1: 'ACCOUNT_V1',
            10: 'ACCOUNT',
            2: 'CONTRACT',
            3: 'STORAGE_V1',
            30: 'STORAGE',
            4: 'ERC20_ALLOWANCE',
            5: 'FINALIZED_STORAGE',
        }

        acc_info_js = {}
        acc_info_js['address'] = str(sol_account.public_key())
        acc_info_js['balance'] = self._solana.get_sol_balance(sol_account.public_key())

        acc_info_js['storage'] = []
        acc_info_js['holder'] = []

        for rid in range(max(PERM_ACCOUNT_LIMIT, 16)):
            storage_address = self._generate_storage_address(sol_account.public_key(), rid)
            holder_address = self._generate_holder_address(sol_account.public_key(), rid)
            [storage_info, holder_info] = self._solana.get_account_info_list([storage_address, holder_address])

            if storage_info:
                storage_account = {}
                storage_account['address'] = str(storage_address)
                storage_account['status'] = resource_tags.get(storage_info.tag, 'UNKNOWN')
                storage_account['balance'] = storage_info.lamports
                acc_info_js['storage'].append(storage_account)
            if holder_info:
                holder_account = {}
                holder_account['address'] = str(holder_address)
                holder_account['status'] = resource_tags.get(holder_info.tag, 'UNKNOWN')
                holder_account['balance'] = holder_info.lamports
                acc_info_js['holder'].append(holder_account)

        return acc_info_js
