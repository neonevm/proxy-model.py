from __future__ import annotations

import logging
from enum import IntEnum
from typing import Optional, List, Dict, cast

from singleton_decorator import singleton
from rlp import encode as rlp_encode

from solders.system_program import CreateAccountWithSeedParams, create_account_with_seed

from .constants import COMPUTE_BUDGET_ID, ADDRESS_LOOKUP_TABLE_ID, SYS_PROGRAM_ID, EVM_PROGRAM_ID
from .evm_config import EVMConfig
from .utils.eth_proto import NeonTx
from .utils.utils import str_enum
from .solana_tx import SolTxIx, SolPubKey, SolAccountMeta

from ..neon_core_api.neon_layouts import NeonAccountInfo


LOG = logging.getLogger(__name__)


class EvmIxCode(IntEnum):
    Unknown = -1
    CollectTreasure = 0x1e              # 30
    TxExecFromData = 0x1f               # 31
    TxExecFromAccount = 0x2a            # 42
    TxStepFromData = 0x20               # 32
    TxStepFromAccount = 0x21            # 33
    TxStepFromAccountNoChainId = 0x22   # 34
    CancelWithHash = 0x23               # 35
    HolderCreate = 0x24                 # 36
    HolderDelete = 0x25                 # 37
    HolderWrite = 0x26                  # 38
    DepositV03 = 0x27                   # 39
    CreateAccountV03 = 0x28             # 40
    CreateBalance = 0x2D                # 45


@singleton
class EvmIxCodeName:
    def __init__(self):
        self._ix_code_dict: Dict[int, str] = dict()
        for ix_code in list(EvmIxCode):
            self._ix_code_dict[ix_code.value] = str_enum(ix_code)

    def get(self, ix_code: int, default=None) -> str:
        value = self._ix_code_dict.get(ix_code, default)
        if value is None:
            return hex(ix_code)
        return value


class AltIxCode(IntEnum):
    Create = 0
    Freeze = 1
    Extend = 2
    Deactivate = 3
    Close = 4


@singleton
class AltIxCodeName:
    def __init__(self):
        self._ix_code_dict: Dict[int, str] = dict()
        for ix_code in list(AltIxCode):
            self._ix_code_dict[ix_code.value] = str_enum(ix_code)

    def get(self, ix_code: int, default=None) -> str:
        value = self._ix_code_dict.get(ix_code, default)
        if value is None:
            return hex(ix_code)
        return value


class ComputeBudgetIxCode(IntEnum):
    HeapRequest = 1
    CURequest = 2


@singleton
class ComputeBudgetIxCodeName:
    def __init__(self):
        self._ix_code_dict: Dict[int, str] = dict()
        for ix_code in list(ComputeBudgetIxCode):
            self._ix_code_dict[ix_code.value] = str_enum(ix_code)

    def get(self, ix_code: int, default=None) -> str:
        value = self._ix_code_dict.get(ix_code, default)
        if value is None:
            return hex(ix_code)
        return value


class NeonIxBuilder:
    def __init__(self, operator: SolPubKey):
        self._operator_account = operator
        self._operator_neon_address: Optional[SolPubKey] = None
        self._simple_neon_acct_list: List[SolAccountMeta] = list()
        self._iter_neon_acct_list: List[SolAccountMeta] = list()
        self._neon_tx: Optional[NeonTx] = None
        self._neon_tx_sig: Optional[bytes] = None
        self._msg: Optional[bytes] = None
        self._holder_msg: Optional[bytes] = None
        self._treasury_pool_index_buf: Optional[bytes] = None
        self._treasury_pool_address: Optional[SolPubKey] = None
        self._holder: Optional[SolPubKey] = None

    @property
    def operator_account(self) -> SolPubKey:
        return self._operator_account

    @property
    def holder_msg(self) -> bytes:
        assert self._holder_msg is not None
        return cast(bytes, self._holder_msg)

    def init_operator_neon(self, operator_neon_account: SolPubKey) -> NeonIxBuilder:
        self._operator_neon_address = operator_neon_account
        return self

    def init_neon_tx(self, neon_tx: NeonTx) -> NeonIxBuilder:
        self._neon_tx = neon_tx

        self._msg = rlp_encode(self._neon_tx)
        self._holder_msg = self._msg
        return self.init_neon_tx_sig(self._neon_tx.hex_tx_sig)

    def init_neon_tx_sig(self, neon_tx_sig: str) -> NeonIxBuilder:
        self._neon_tx_sig = bytes.fromhex(neon_tx_sig[2:])
        evm_config = EVMConfig()
        treasury_pool_cnt = evm_config.treasury_pool_cnt
        treasury_pool_seed = evm_config.treasury_pool_seed
        treasury_pool_index = int().from_bytes(self._neon_tx_sig[:4], 'little') % treasury_pool_cnt
        self._treasury_pool_index_buf = treasury_pool_index.to_bytes(4, 'little')
        self._treasury_pool_address = SolPubKey.find_program_address(
            [treasury_pool_seed, self._treasury_pool_index_buf],
            EVM_PROGRAM_ID
        )[0]

        return self

    def init_neon_account_list(self, neon_account_list: List[SolAccountMeta]) -> NeonIxBuilder:
        self._simple_neon_acct_list = neon_account_list
        self._iter_neon_acct_list = [
            SolAccountMeta(pubkey=src.pubkey, is_writable=True, is_signer=src.is_signer)
            for src in neon_account_list
        ]
        return self

    def init_iterative(self, holder: SolPubKey):
        self._holder = holder
        return self

    def make_create_account_with_seed_ix(self, account: SolPubKey, seed: bytes, lamports: int, space: int) -> SolTxIx:
        seed_str = str(seed, 'utf8')
        LOG.debug(f'createAccountWithSeedIx {self._operator_account} account({account} seed({seed_str})')

        return create_account_with_seed(
            CreateAccountWithSeedParams(
                from_pubkey=self._operator_account,
                to_pubkey=account,
                base=self._operator_account,
                seed=seed_str,
                lamports=lamports,
                space=space,
                owner=EVM_PROGRAM_ID
            )
        )

    def make_delete_holder_ix(self, holder_account: SolPubKey) -> SolTxIx:
        LOG.debug(f'deleteHolderIx {self._operator_account} refunded account({holder_account})')
        return SolTxIx(
            accounts=[
                SolAccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_PROGRAM_ID,
            data=EvmIxCode.HolderDelete.value.to_bytes(1, byteorder='little'),
        )

    def create_holder_ix(self, holder: SolPubKey, seed: bytes) -> SolTxIx:
        LOG.debug(f'createHolderIx {self._operator_account} account({holder})')
        return SolTxIx(
            accounts=[
                SolAccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_PROGRAM_ID,
            data=(
                EvmIxCode.HolderCreate.value.to_bytes(1, byteorder='little') +
                len(seed).to_bytes(8, 'little') + seed
            )
        )

    def make_create_neon_account_ix(self, neon_account_info: NeonAccountInfo) -> SolTxIx:
        LOG.debug(
            f'Create neon account: {str(neon_account_info.neon_address)}, '
            f'sol account: {neon_account_info.solana_address}'
        )

        ix_data = b''.join([
            EvmIxCode.CreateBalance.value.to_bytes(1, byteorder='little'),
            neon_account_info.neon_address.to_bytes(),
            neon_account_info.chain_id.to_bytes(8, byteorder='little')
        ])

        return SolTxIx(
            program_id=EVM_PROGRAM_ID,
            data=ix_data,
            accounts=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=neon_account_info.solana_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=neon_account_info.contract_solana_address, is_signer=False, is_writable=True),
            ]
        )

    def make_write_ix(self, offset: int, data: bytes) -> SolTxIx:
        ix_data = b''.join([
            EvmIxCode.HolderWrite.value.to_bytes(1, byteorder='little'),
            self._neon_tx_sig,
            offset.to_bytes(8, byteorder='little'),
            data
        ])
        return SolTxIx(
            program_id=EVM_PROGRAM_ID,
            data=ix_data,
            accounts=[
                SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),
            ]
        )

    def make_tx_exec_from_data_ix(self) -> SolTxIx:
        ix_data = b''.join([
            EvmIxCode.TxExecFromData.value.to_bytes(1, byteorder='little'),
            self._treasury_pool_index_buf,
            self._msg
        ])
        return SolTxIx(
            program_id=EVM_PROGRAM_ID,
            data=ix_data,
            accounts=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ] + self._simple_neon_acct_list
        )

    def make_tx_exec_from_account_ix(self) -> SolTxIx:
        ix_data = b''.join([
            EvmIxCode.TxExecFromAccount.value.to_bytes(1, byteorder='little'),
            self._treasury_pool_index_buf,
        ])
        return self._make_holder_ix(ix_data, self._simple_neon_acct_list)

    def make_cancel_ix(self) -> SolTxIx:
        return SolTxIx(
            program_id=EVM_PROGRAM_ID,
            data=EvmIxCode.CancelWithHash.value.to_bytes(1, byteorder='little') + self._neon_tx_sig,
            accounts=[
                SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
            ] + self._iter_neon_acct_list
        )

    def make_tx_step_from_data_ix(self, step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(
            EvmIxCode.TxStepFromData.value.to_bytes(1, byteorder='little'),
            step_cnt, index, self._msg
        )

    def _make_tx_step_ix(self, ix_id_byte: bytes, neon_step_cnt: int, index: int,
                         data: Optional[bytes]) -> SolTxIx:
        ix_data = b''.join([
            ix_id_byte,
            self._treasury_pool_index_buf,
            neon_step_cnt.to_bytes(4, byteorder='little'),
            index.to_bytes(4, byteorder="little")
        ])

        if data is not None:
            ix_data += data

        return self._make_holder_ix(ix_data, self._iter_neon_acct_list)

    def _make_holder_ix(self, ix_data: bytes, neon_acct_list: List[SolAccountMeta]):
        return SolTxIx(
            program_id=EVM_PROGRAM_ID,
            data=ix_data,
            accounts=[
                 SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                 SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
             ] + neon_acct_list
        )

    def make_tx_step_from_account_ix(self, neon_step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(
            EvmIxCode.TxStepFromAccount.value.to_bytes(1, byteorder='little'),
            neon_step_cnt, index, None
        )

    def make_tx_step_from_account_no_chainid_ix(self, neon_step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(
            EvmIxCode.TxStepFromAccountNoChainId.value.to_bytes(1, byteorder='little'),
            neon_step_cnt, index, None
        )

    def make_create_lookup_table_ix(self, table_account: SolPubKey,
                                    recent_block_slot: int,
                                    seed: int) -> SolTxIx:
        data = b''.join([
            int(AltIxCode.Create).to_bytes(4, byteorder='little'),
            recent_block_slot.to_bytes(8, byteorder='little'),
            seed.to_bytes(1, byteorder='little')
        ])
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),   # payer
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_extend_lookup_table_ix(self, table_account: SolPubKey,
                                    account_list: List[SolPubKey]) -> SolTxIx:
        data = b"".join([
            int(AltIxCode.Extend).to_bytes(4, byteorder='little'),
            len(account_list).to_bytes(8, byteorder='little')
        ] + [
            bytes(pubkey) for pubkey in account_list
        ])

        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),   # payer
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_deactivate_lookup_table_ix(self, table_account: SolPubKey) -> SolTxIx:
        data = int(AltIxCode.Deactivate).to_bytes(4, byteorder='little')
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
            ]
        )

    def make_close_lookup_table_ix(self, table_account: SolPubKey) -> SolTxIx:
        data = int(AltIxCode.Close).to_bytes(4, byteorder='little')
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                SolAccountMeta(pubkey=self._operator_account, is_signer=False, is_writable=True),  # refund
            ]
        )

    @staticmethod
    def make_compute_budget_heap_ix() -> SolTxIx:
        heap_frame_size = 256 * 1024
        ix_data = (
            int(ComputeBudgetIxCode.HeapRequest).to_bytes(1, 'little') +
            heap_frame_size.to_bytes(4, 'little')
        )
        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            accounts=[],
            data=ix_data
        )

    @staticmethod
    def make_compute_budget_cu_ix() -> SolTxIx:
        compute_unit_cnt = 1_400_000
        ix_data = (
            int(ComputeBudgetIxCode.CURequest).to_bytes(1, 'little') +
            compute_unit_cnt.to_bytes(4, 'little')
        )
        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            accounts=[],
            data=ix_data
        )
