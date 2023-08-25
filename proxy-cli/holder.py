from __future__ import annotations

import sys
from typing import Optional

from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.operator_resource_info import OpResIdent, OpResInfo
from proxy.common_neon.neon_tx_stages import NeonTxStage, NeonCreateHolderAccountStage, NeonDeleteHolderAccountStage
from proxy.common_neon.solana_tx_list_sender import SolTxListSender
from proxy.common_neon.neon_instruction import NeonIxBuilder
from proxy.common_neon.constants import FINALIZED_HOLDER_TAG, HOLDER_TAG
from proxy.common_neon.solana_tx import SolPubKey
from proxy.common_neon.config import Config

from .secret import get_res_ident_list


class HolderHandler:
    def __init__(self):
        self._config = Config()
        self._solana = SolInteractor(self._config)
        self.command = 'holder-account'

    @staticmethod
    def init_args_parser(parsers) -> HolderHandler:
        h = HolderHandler()
        h.root_parser = parsers.add_parser(h.command)
        h.sub_parser = h.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')
        h.list_parser = h.sub_parser.add_parser('list')
        h.create_parser = h.sub_parser.add_parser('create')
        h.create_parser.add_argument('operator_key', type=str, help='operator public key')
        h.create_parser.add_argument('holder_id', type=int, help='id of the holder account')
        h.delete_parser = h.sub_parser.add_parser('delete')
        h.delete_parser.add_argument('holder_address', type=str, help='id of the holder account')
        return h

    def execute(self, args) -> None:
        if args.subcommand == 'create':
            self._create_holder_account(args)
        elif args.subcommand == 'delete':
            self._delete_holder_account(args)
        else:
            print(f'Unknown command {args.subcommand} for account', file=sys.stderr)
            return

    def _create_holder_account(self, args) -> None:
        op_key = SolPubKey.from_string(args.operator_key)
        res_ident = self._find_op_res_by_holder_id(op_key, args.holder_id)
        if res_ident is None:
            return

        res_info = OpResInfo.from_ident(res_ident)
        holder_info = self._solana.get_holder_account_info(res_info.holder_account)
        if holder_info is not None:
            print(f'Holder account {res_ident.public_key}:{res_ident.res_id} already exist', file=sys.stderr)
            return

        size = self._config.holder_size
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([size])[0]
        builder = NeonIxBuilder(self._config, res_info.public_key)
        stage = NeonCreateHolderAccountStage(builder, res_info.holder_seed, size, balance)
        self._execute_stage(stage, res_info)
        print(
            f'Holder account {str(res_info.holder_account)} '
            f'{res_ident.public_key}:{res_ident.res_id} is successfully created',
            file=sys.stderr
        )

    def _delete_holder_account(self, args) -> None:
        holder_address = SolPubKey.from_string(args.holder_address)
        res_ident = self._find_op_res_by_holder_address(holder_address)
        if res_ident is None:
            return

        holder_info = self._solana.get_holder_account_info(holder_address)
        if holder_info is None:
            print(f'Holder account {res_ident.public_key}:{res_ident.res_id} does not exist', file=sys.stderr)
            return

        if holder_info.tag not in {FINALIZED_HOLDER_TAG, HOLDER_TAG}:
            print(f'Holder account {res_ident.public_key}:{res_ident.res_id} has wrong tag', file=sys.stderr)
            return

        res_info = OpResInfo.from_ident(res_ident)
        builder = NeonIxBuilder(self._config, res_info.public_key)
        stage = NeonDeleteHolderAccountStage(builder, res_info.holder_seed)
        self._execute_stage(stage, res_info)
        print(
            f'Holder account {str(res_info.holder_account)} '
            f'{res_ident.public_key}:{res_ident.res_id} is successfully deleted',
            file=sys.stderr
        )

    @staticmethod
    def _find_op_res_by_holder_address(holder_address: SolPubKey) -> Optional[OpResIdent]:
        res_ident_list = get_res_ident_list()
        for res_ident in res_ident_list:
            res_info = OpResInfo.from_ident(res_ident)
            if res_info.holder_account == holder_address:
                return res_ident

        print(f'Unknown holder account: {str(holder_address)}', file=sys.stderr)
        return None

    @staticmethod
    def _find_op_res_by_holder_id(op_key: SolPubKey, res_id: int) -> Optional[OpResIdent]:
        op_key = str(op_key)

        res_ident_list = get_res_ident_list()
        for res_ident in res_ident_list:
            if res_ident.public_key == op_key and res_ident.res_id == res_id:
                return res_ident

        print(f'Unknown holder account: {op_key}:{res_id}', file=sys.stderr)
        return None

    def _execute_stage(self, stage: NeonTxStage, op_res_info: OpResInfo) -> None:
        stage.build()
        tx_sender = SolTxListSender(self._config, self._solana, op_res_info.signer)
        tx_sender.send([stage.tx])
