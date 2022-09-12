from typing import List, Dict, Any

from logged_groups import logged_group

from solana.transaction import AccountMeta as SolanaAccountMeta, PublicKey

from ..common_neon.solana_tx_list_sender import SolTxListInfo
from ..common_neon.data import NeonTxExecCfg, NeonAccountDict, NeonEmulatedResult
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue
from ..common_neon.errors import BadResourceError
from ..common_neon.constants import ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, HOLDER_TAG

from .neon_tx_stages import NeonTxStage, NeonCreateAccountTxStage, NeonCreateContractTxStage
from .neon_tx_stages import NeonResizeContractTxStage

from .operator_resource_mng import OperatorResourceInfo


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
        self._parse_solana_list(emulated_account_dict['solana_accounts'])

        neon_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in neon_meta_list]))
        self._builder.init_neon_account_list(neon_meta_list)

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
        self._bin_neon_sig: bytes = neon_tx.hash_signed()
        self._neon_sig = '0x' + self._bin_neon_sig.hex().lower()
        self._solana = solana
        self._resource = resource
        self._builder = NeonIxBuilder(resource.public_key)

        self._account_tx_list_builder = AccountTxListBuilder(solana, self._builder)
        self._account_tx_list_builder.build_tx(self._neon_tx_exec_cfg.account_dict)

        self._builder.init_operator_neon(self._resource.ether)
        self._builder.init_neon_tx(self._neon_tx)
        self._builder.init_iterative(self._resource.holder)

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)

        self._is_holder_completed = False

        self._decode_holder_account()

    def _decode_holder_account(self) -> None:
        holder_info = self._solana.get_holder_account_info(self._resource.holder)
        if holder_info is None:
            raise BadResourceError(f'Bad holder account {str(self._resource.holder)}')

        if holder_info.tag == ACTIVE_STORAGE_TAG:
            if holder_info.neon_tx_sig != self._neon_sig:
                raise BadResourceError(
                    f'Holder account {str(self._resource.holder)} '
                    f' has another neon tx: {holder_info.neon_tx_sig}'
                )
            self._is_holder_completed = True
        elif holder_info.tag == FINALIZED_STORAGE_TAG:
            pass
        elif holder_info.tag == HOLDER_TAG:
            holder_msg_len = len(self._builder.holder_msg)
            self._is_holder_completed = (self._builder.holder_msg == holder_info.neon_tx_data[:holder_msg_len])
        else:
            raise BadResourceError(f'Holder account has bad tag: {holder_info.tag}')

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> None:
        self._neon_tx_exec_cfg.set_emulated_result(emulated_result)
        self._account_tx_list_builder.build_tx(self._neon_tx_exec_cfg.account_dict)

    def set_state_tx_cnt(self, value: int) -> None:
        self._neon_tx_exec_cfg.set_state_tx_cnt(value)

    @property
    def neon_sig(self) -> str:
        return self._neon_sig

    @property
    def bin_neon_sig(self) -> bytes:
        return self._bin_neon_sig

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
    def is_holder_completed(self) -> bool:
        return self._is_holder_completed

    def set_holder_completed(self, value=True) -> None:
        self._is_holder_completed = value
