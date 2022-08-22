from typing import List, Dict, Any

from logged_groups import logged_group

from solana.transaction import AccountMeta as SolanaAccountMeta, PublicKey

from ..common_neon.solana_tx_list_sender import SolTxListInfo
from ..common_neon.data import NeonTxExecCfg, NeonAccountDict
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue

from .neon_tx_stages import NeonTxStage, NeonCreateAccountTxStage, NeonCreateERC20TxStage, NeonCreateContractTxStage
from .neon_tx_stages import NeonResizeContractTxStage

from .operator_resource_list import OperatorResourceInfo


@logged_group("neon.MemPool")
class AccountTxListBuilder:
    def __init__(self, solana: SolanaInteractor, builder: NeonIxBuilder):
        self._solana = solana
        self._builder = builder
        self._resize_contract_stage_list: List[NeonTxStage] = []
        self._create_account_stage_list: List[NeonTxStage] = []
        self._eth_meta_dict: Dict[str, SolanaAccountMeta] = dict()

    def build_tx(self, emulated_account_dict: NeonAccountDict) -> None:
        self._resize_contract_stage_list.clear()
        self._create_account_stage_list.clear()
        self._eth_meta_dict.clear()

        # Parse information from the emulator output
        self._parse_accounts_list(emulated_account_dict['accounts'])
        self._parse_token_list(emulated_account_dict['token_accounts'])
        self._parse_solana_list(emulated_account_dict['solana_accounts'])

        eth_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in eth_meta_list]))
        self._builder.init_eth_accounts(eth_meta_list)

        # Build all instructions
        self._build_account_stage_list()

    def _add_meta(self, pubkey: PublicKey, is_writable: bool) -> None:
        key = str(pubkey)
        if key in self._eth_meta_dict:
            self._eth_meta_dict[key].is_writable |= is_writable
        else:
            self._eth_meta_dict[key] = SolanaAccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _parse_accounts_list(self, emulated_result_account_list: List[Dict[str, Any]]) -> None:
        for account_desc in emulated_result_account_list:
            if account_desc['new']:
                if account_desc['code_size']:
                    stage = NeonCreateContractTxStage(self._builder, account_desc)
                    self._create_account_stage_list.append(stage)
                elif account_desc['writable']:
                    stage = NeonCreateAccountTxStage(self._builder, account_desc)
                    self._create_account_stage_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_stage_list.append(NeonResizeContractTxStage(self._builder, account_desc))

            self._add_meta(account_desc['account'], True)
            if account_desc['contract']:
                self._add_meta(account_desc['contract'], account_desc['writable'])

    def _parse_token_list(self, emulated_result_token_accounts: List[Dict[str, Any]]) -> None:
        for token_account in emulated_result_token_accounts:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_stage_list.append(NeonCreateERC20TxStage(self._builder, token_account))

    def _parse_solana_list(self, emulated_result_solana_account_list: List[Dict[str, Any]]) -> None:
        for account_desc in emulated_result_solana_account_list:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

    def _build_account_stage_list(self) -> None:
        if not self.has_tx_list():
            return

        all_stage_list = self._create_account_stage_list + self._resize_contract_stage_list
        size_list = list(set([s.size for s in all_stage_list]))
        balance_list = self._solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        for s in all_stage_list:
            s.set_balance(balance_map[s.size])
            s.build()

    def has_tx_list(self) -> bool:
        return len(self._resize_contract_stage_list) > 0 or len(self._create_account_stage_list) > 0

    def get_tx_list_info(self) -> SolTxListInfo:
        all_stage_list = self._create_account_stage_list + self._resize_contract_stage_list

        return SolTxListInfo(
            name_list=[s.NAME for s in all_stage_list],
            tx_list=[s.tx for s in all_stage_list]
        )

    def clear_tx_list(self) -> None:
        self._resize_contract_stage_list.clear()
        self._create_account_stage_list.clear()


class NeonTxSendCtx:
    def __init__(self, solana: SolanaInteractor, resource: OperatorResourceInfo,
                 neon_tx: NeonTx, neon_tx_exec_cfg: NeonTxExecCfg):
        self._neon_tx_exec_cfg = neon_tx_exec_cfg
        self._neon_tx = neon_tx
        self._sender = '0x' + neon_tx.sender()
        self._neon_sig = '0x' + neon_tx.hash_signed().hex()
        self._solana = solana
        self._resource = resource
        self._builder = NeonIxBuilder(resource.public_key)

        self._account_tx_list_builder = AccountTxListBuilder(solana, self._builder)

        self._builder.init_operator_ether(self._resource.ether)
        self._builder.init_eth_tx(self._neon_tx)
        self._builder.init_iterative(self._resource.storage, self._resource.holder, self._resource.rid)

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)

    def init(self):
        self._account_tx_list_builder.build_tx(self._neon_tx_exec_cfg.account_dict)

    @property
    def neon_sig(self) -> str:
        return self._neon_sig

    @property
    def sender(self) -> str:
        return self._sender

    @property
    def neon_tx(self) -> NeonTx:
        return self._neon_tx

    @property
    def resource(self) -> OperatorResourceInfo:
        return self._resource

    @property
    def builder(self) -> NeonIxBuilder:
        return self._builder

    @property
    def solana(self) -> SolanaInteractor:
        return self._solana

    @property
    def account_tx_list_builder(self) -> AccountTxListBuilder:
        return self._account_tx_list_builder

    @property
    def alt_close_queue(self) -> AddressLookupTableCloseQueue:
        return self._alt_close_queue

    @property
    def neon_tx_exec_cfg(self) -> NeonTxExecCfg:
        return self._neon_tx_exec_cfg

    @property
    def emulated_evm_step_cnt(self) -> int:
        assert self._neon_tx_exec_cfg.evm_step_cnt >= 0
        return self._neon_tx_exec_cfg.evm_step_cnt

    @property
    def state_tx_cnt(self) -> int:
        assert self._neon_tx_exec_cfg.state_tx_cnt >= 0
        return self._neon_tx_exec_cfg.state_tx_cnt

    @property
    def is_holder_completed(self):
        return self._neon_tx_exec_cfg.is_holder_completed

    def set_holder_completed(self, value=True) -> None:
        self._neon_tx_exec_cfg.set_holder_completed(value)
