from typing import Dict

from logged_groups import logged_group

from ..common_neon.solana_transaction import SolPubKey, SolAccountMeta, SolAccount
from ..common_neon.data import NeonTxExecCfg, NeonAccountDict, NeonEmulatedResult
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.eth_proto import NeonTx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.errors import BadResourceError
from ..common_neon.constants import ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG

from .operator_resource_mng import OpResInfo


@logged_group("neon.MemPool")
class NeonTxSendCtx:
    def __init__(self, config: Config, solana: SolInteractor, resource: OpResInfo,
                 neon_tx: NeonTx, neon_tx_exec_cfg: NeonTxExecCfg):
        self._config = config
        self._neon_tx_exec_cfg = neon_tx_exec_cfg
        self._neon_tx = neon_tx
        self._sender = '0x' + neon_tx.sender()
        self._bin_neon_sig: bytes = neon_tx.hash_signed()
        self._neon_sig = '0x' + self._bin_neon_sig.hex().lower()
        self._solana = solana
        self._resource = resource
        self._ix_builder = NeonIxBuilder(resource.public_key)
        self._neon_meta_dict: Dict[str, SolAccountMeta] = {}

        self._ix_builder.init_operator_neon(self._resource.ether)
        self._ix_builder.init_neon_tx(self._neon_tx)
        self._ix_builder.init_iterative(self._resource.holder)

        self._build_account_list(self._neon_tx_exec_cfg.account_dict)

        self._is_holder_completed = False

        self._decode_holder_account()

    def _decode_holder_account(self) -> None:
        holder_info = self._solana.get_holder_account_info(self._resource.holder)
        if holder_info is None:
            raise BadResourceError(f'Bad holder account {str(self._resource.holder)}')

        if holder_info.tag == ACTIVE_HOLDER_TAG:
            if holder_info.neon_tx_sig != self._neon_sig:
                raise BadResourceError(
                    f'Holder account {str(self._resource.holder)} '
                    f'has another neon tx: {holder_info.neon_tx_sig}'
                )
            self._is_holder_completed = True
        elif holder_info.tag == FINALIZED_HOLDER_TAG:
            pass
        elif holder_info.tag == HOLDER_TAG:
            holder_msg_len = len(self._ix_builder.holder_msg)
            self._is_holder_completed = (self._ix_builder.holder_msg == holder_info.neon_tx_data[:holder_msg_len])
        else:
            raise BadResourceError(f'Holder account has bad tag: {holder_info.tag}')

    def _add_meta(self, pubkey: SolPubKey, is_writable: bool) -> None:
        key = str(pubkey)
        if key in self._neon_meta_dict:
            self._neon_meta_dict[key].is_writable |= is_writable
        else:
            self._neon_meta_dict[key] = SolAccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _build_account_list(self, emulated_account_dict: NeonAccountDict) -> None:
        self._neon_meta_dict.clear()

        # Parse information from the emulator output
        for account_desc in emulated_account_dict['accounts']:
            self._add_meta(account_desc['account'], True)

        for account_desc in emulated_account_dict['solana_accounts']:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

        neon_meta_list = list(self._neon_meta_dict.values())
        self.debug(
            f'metas ({len(neon_meta_list)}): '
            ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in neon_meta_list])
        )

        contract = self._neon_tx.contract()
        if contract is not None:
            self.debug(f'contract 0x{contract}: {len(neon_meta_list) + 6} accounts')

        self._ix_builder.init_neon_account_list(neon_meta_list)

    def set_emulated_result(self, emulated_result: NeonEmulatedResult) -> None:
        self._neon_tx_exec_cfg.set_emulated_result(emulated_result)
        self._build_account_list(self._neon_tx_exec_cfg.account_dict)

    def set_state_tx_cnt(self, value: int) -> None:
        self._neon_tx_exec_cfg.set_state_tx_cnt(value)

    @property
    def config(self) -> Config:
        return self._config

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
    def signer(self) -> SolAccount:
        return self._resource.signer

    @property
    def ix_builder(self) -> NeonIxBuilder:
        return self._ix_builder

    @property
    def solana(self) -> SolInteractor:
        return self._solana

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
