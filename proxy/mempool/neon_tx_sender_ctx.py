import logging

from typing import Dict, List, Union

from ..common_neon.config import Config
from ..common_neon.data import NeonEmulatorResult
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_alt import ALTAddress
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolTx, SolPubKey, SolAccountMeta, SolAccount
from ..common_neon.utils.neon_tx_info import NeonTxInfo
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.evm_config import EVMConfig
from ..common_neon.address import NeonAddress

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient

from .mempool_api import MPTxExecRequest


LOG = logging.getLogger(__name__)


class NeonTxSendCtx:
    def __init__(
        self, config: Config,
        solana: SolInteractor,
        core_api_client: NeonCoreApiClient,
        mp_tx_req: MPTxExecRequest
    ):
        self._config = config
        self._mp_tx_req = mp_tx_req
        self._neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        self._solana = solana
        self._core_api_client = core_api_client
        self._resource = mp_tx_req.res_info

        self._ix_builder = NeonIxBuilder(self._resource.public_key)
        self._ix_builder.init_operator_neon(self._resource.neon_account_dict[mp_tx_req.chain_id].pda_address)
        self._ix_builder.init_iterative(self.holder_account)
        if not mp_tx_req.is_stuck_tx():
            self._ix_builder.init_neon_tx(mp_tx_req.neon_tx)
        else:
            self._ix_builder.init_neon_tx_sig(mp_tx_req.sig)

        self._neon_meta_dict: Dict[SolPubKey, SolAccountMeta] = dict()
        if not mp_tx_req.is_stuck_tx():
            self._build_account_list()

    @property
    def sender_address(self) -> NeonAddress:
        return NeonAddress(self.neon_tx_info.addr, self._mp_tx_req.chain_id)

    def _add_meta(self, pubkey: Union[str, SolPubKey], is_writable: bool) -> None:
        if isinstance(pubkey, str):
            pubkey = SolPubKey.from_string(pubkey)
        meta = self._neon_meta_dict.get(pubkey, None)
        if meta is not None:
            is_writable |= meta.is_writable
        self._neon_meta_dict[pubkey] = SolAccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _build_account_list(self) -> None:
        self._neon_meta_dict.clear()

        # Parse information from the emulator output
        for account_desc in self._neon_tx_exec_cfg.emulator_result.account_list:
            self._add_meta(account_desc['account'], True)

        for account_desc in self._neon_tx_exec_cfg.emulator_result.solana_account_list:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

        neon_meta_list = list(self._neon_meta_dict.values())
        LOG.debug(
            f'metas ({len(neon_meta_list)}): ' +
            ', '.join([f'{str(m.pubkey), m.is_signer, m.is_writable}' for m in neon_meta_list])
        )

        contract = self._mp_tx_req.neon_tx_info.contract
        if contract is not None:
            LOG.debug(f'contract {contract}: {len(neon_meta_list) + 6} accounts')

        self._ix_builder.init_neon_account_list(neon_meta_list)

    @property
    def len_account_list(self) -> int:
        return len(self._neon_meta_dict)

    def has_emulator_result(self) -> bool:
        return not self._neon_tx_exec_cfg.emulator_result.is_empty()

    def emulate(self) -> None:
        emulator_result = self._core_api_client.emulate_neon_tx(self.neon_tx, self._mp_tx_req.chain_id)
        self.set_emulator_result(emulator_result)

    def set_emulator_result(self, emulator_result: NeonEmulatorResult) -> None:
        self._neon_tx_exec_cfg.set_emulator_result(emulator_result)
        self._build_account_list()

    def set_state_tx_cnt(self, value: int) -> None:
        self._neon_tx_exec_cfg.set_state_tx_cnt(value)

    @property
    def config(self) -> Config:
        return self._config

    def is_stuck_tx(self) -> bool:
        return self._mp_tx_req.is_stuck_tx()

    @property
    def neon_tx(self) -> NeonTx:
        assert self._mp_tx_req.neon_tx is not None
        return self._mp_tx_req.neon_tx

    @property
    def neon_tx_info(self) -> NeonTxInfo:
        return self._mp_tx_req.neon_tx_info

    @property
    def signer(self) -> SolAccount:
        return self._resource.signer

    @property
    def holder_account(self) -> SolPubKey:
        if self._neon_tx_exec_cfg.holder_account is not None:
            return self._neon_tx_exec_cfg.holder_account
        return self._resource.holder_account

    @property
    def ix_builder(self) -> NeonIxBuilder:
        return self._ix_builder

    @property
    def solana(self) -> SolInteractor:
        return self._solana

    @property
    def core_api_client(self) -> NeonCoreApiClient:
        return self._core_api_client

    @property
    def resize_iter_cnt(self) -> int:
        resize_iter_cnt = self._neon_tx_exec_cfg.emulator_result.resize_iter_cnt
        assert resize_iter_cnt >= 0
        return resize_iter_cnt

    @property
    def emulated_evm_step_cnt(self) -> int:
        evm_step_cnt = self._neon_tx_exec_cfg.emulator_result.evm_step_cnt
        assert evm_step_cnt >= 0
        return evm_step_cnt

    @property
    def state_tx_cnt(self) -> int:
        assert self._neon_tx_exec_cfg.state_tx_cnt >= 0
        return self._neon_tx_exec_cfg.state_tx_cnt

    @property
    def alt_address_list(self) -> List[ALTAddress]:
        return self._neon_tx_exec_cfg.alt_address_list

    def add_alt_address(self, alt_address: ALTAddress) -> None:
        self._neon_tx_exec_cfg.add_alt_address(alt_address)

    @property
    def strategy_idx(self) -> int:
        return self._neon_tx_exec_cfg.strategy_idx

    def set_strategy_idx(self, idx: int) -> None:
        self._neon_tx_exec_cfg.set_strategy_idx(idx)

    @property
    def sol_tx_cnt(self) -> int:
        return self._neon_tx_exec_cfg.sol_tx_cnt

    def has_good_sol_tx_receipt(self) -> bool:
        return self._neon_tx_exec_cfg.has_completed_receipt()

    def mark_good_sol_tx_receipt(self) -> None:
        self._neon_tx_exec_cfg.mark_good_sol_tx_receipt()

    def mark_resource_use(self) -> None:
        if self._neon_tx_exec_cfg.holder_account is None:
            self._neon_tx_exec_cfg.set_holder_account(True, self._resource.holder_account)

    def has_sol_tx(self, name: str) -> bool:
        return self._neon_tx_exec_cfg.has_sol_tx(name)

    def pop_sol_tx_list(self, tx_name_list: List[str]) -> List[SolTx]:
        return self._neon_tx_exec_cfg.pop_sol_tx_list(tx_name_list)

    def add_sol_tx_list(self, tx_list: List[SolTx]) -> None:
        self._neon_tx_exec_cfg.add_sol_tx_list(tx_list)
