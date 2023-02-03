from __future__ import annotations

import logging
from enum import Enum
from typing import Optional, List, cast

from rlp import encode as rlp_encode
from sha3 import keccak_256

from solders.system_program import CreateAccountWithSeedParams, create_account_with_seed

from ..common_neon.address import neon_2program, NeonAddress
from ..common_neon.constants import INCINERATOR_ID, COMPUTE_BUDGET_ID, ADDRESS_LOOKUP_TABLE_ID, SYS_PROGRAM_ID
from ..common_neon.elf_params import ElfParams
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.eth_proto import NeonTx
from ..common_neon.layouts import CREATE_ACCOUNT_LAYOUT
from ..common_neon.solana_tx import SolTxIx, SolPubKey, SolAccountMeta


LOG = logging.getLogger(__name__)


class EvmInstruction(Enum):
    TransactionExecuteFromData = b'\x1f'            # 31,
    TransactionExecuteFromAccount = b'\x2a'         # 42
    TransactionStepFromData = b'\x20'               # 32
    TransactionStepFromAccount = b'\x21'            # 33
    TransactionStepFromAccountNoChainId = b'\x22'   # 34
    CancelWithHash = b'\x23'                        # 35
    HolderCreate = b'\x24'                          # 36
    HolderDelete = b'\x25'                          # 37
    HolderWrite = b'\x26'                           # 38
    DepositV03 = b'\x27'                            # 39
    CreateAccountV03 = b'\x28'                      # 40


def create_account_layout(ether):
    return EvmInstruction.CreateAccountV03.value + CREATE_ACCOUNT_LAYOUT.build(dict(ether=ether))


class NeonIxBuilder:
    def __init__(self, operator: SolPubKey):
        self._evm_program_id = SolPubKey.from_string(EVM_LOADER_ID)
        self._operator_account = operator
        self._operator_neon_address: Optional[SolPubKey] = None
        self._neon_account_list: List[SolAccountMeta] = []
        self._neon_tx: Optional[NeonTx] = None
        self._msg: Optional[bytes] = None
        self._holder_msg: Optional[bytes] = None
        self._treasury_pool_index_buf: Optional[bytes] = None
        self._treasury_pool_address: Optional[SolPubKey] = None
        self._holder: Optional[SolPubKey] = None
        self._elf_params = ElfParams()

    @property
    def operator_account(self) -> SolPubKey:
        return self._operator_account

    @property
    def holder_msg(self) -> bytes:
        assert self._holder_msg is not None
        return cast(bytes, self._holder_msg)

    def init_operator_neon(self, operator_ether: NeonAddress) -> NeonIxBuilder:
        self._operator_neon_address = neon_2program(operator_ether)[0]
        return self

    def init_neon_tx(self, neon_tx: NeonTx) -> NeonIxBuilder:
        self._neon_tx = neon_tx

        self._msg = rlp_encode(self._neon_tx)
        self._holder_msg = self._msg

        keccak_result = self._neon_tx.hash_signed()
        treasury_pool_index = int().from_bytes(keccak_result[:4], "little") % ElfParams().treasury_pool_max
        self._treasury_pool_index_buf = treasury_pool_index.to_bytes(4, 'little')
        self._treasury_pool_address = SolPubKey.find_program_address(
            [b'treasury_pool', self._treasury_pool_index_buf],
            self._evm_program_id
        )[0]

        return self

    def init_neon_account_list(self, neon_account_list: List[SolAccountMeta]) -> NeonIxBuilder:
        self._neon_account_list = neon_account_list
        return self

    def init_iterative(self, holder: SolPubKey):
        self._holder = holder
        return self

    def make_create_account_with_seed_ix(self, account: SolPubKey, seed: bytes, lamports: int, space: int) -> SolTxIx:
        seed_str = str(seed, 'utf8')
        LOG.debug(f"createAccountWithSeedIx {self._operator_account} account({account} seed({seed_str})")

        return create_account_with_seed(
            CreateAccountWithSeedParams(
                from_pubkey=self._operator_account,
                to_pubkey=account,
                base=self._operator_account,
                seed=seed_str,
                lamports=lamports,
                space=space,
                owner=self._evm_program_id
            )
        )

    def make_delete_holder_ix(self, holder_account: SolPubKey) -> SolTxIx:
        LOG.debug(f"deleteHolderIx {self._operator_account} refunded account({holder_account})")
        return SolTxIx(
            accounts=[
                SolAccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=self._evm_program_id,
            data=EvmInstruction.HolderDelete.value,
        )

    def create_holder_ix(self, holder: SolPubKey) -> SolTxIx:
        LOG.debug(f"createHolderIx {self._operator_account} account({holder})")
        return SolTxIx(
            accounts=[
                SolAccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=self._evm_program_id,
            data=EvmInstruction.HolderCreate.value,
        )

    def make_create_neon_account_ix(self, eth_address: NeonAddress) -> SolTxIx:
        if isinstance(eth_address, str):
            eth_address = NeonAddress(eth_address)
        pda_account, nonce = neon_2program(eth_address)
        LOG.debug(f'Create eth account: {str(eth_address)}, sol account: {pda_account}, nonce: {nonce}')

        data = create_account_layout(bytes(eth_address))
        return SolTxIx(
            program_id=self._evm_program_id,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=pda_account, is_signer=False, is_writable=True),
            ])

    def make_write_ix(self, neon_tx_sig: bytes, offset: int, data: bytes) -> SolTxIx:
        ix_data = b"".join([
            EvmInstruction.HolderWrite.value,
            neon_tx_sig,
            offset.to_bytes(8, byteorder='little'),
            data
        ])
        return SolTxIx(
            program_id=self._evm_program_id,
            data=ix_data,
            accounts=[
                SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),
            ]
        )

    def make_tx_exec_from_data_ix(self) -> SolTxIx:
        ix_data = b"".join([
            EvmInstruction.TransactionExecuteFromData.value,
            self._treasury_pool_index_buf,
            self._msg
        ])
        return SolTxIx(
            program_id=self._evm_program_id,
            data=ix_data,
            accounts=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=self._evm_program_id, is_signer=False, is_writable=False),
            ] + self._neon_account_list
        )

    def make_tx_exec_from_account_ix(self) -> SolTxIx:
        ix_data = b"".join([
            EvmInstruction.TransactionExecuteFromAccount.value,
            self._treasury_pool_index_buf,
        ])
        return self._make_holder_ix(ix_data)

    def make_cancel_ix(self, holder_account: Optional[SolPubKey] = None,
                       neon_tx_sig: Optional[bytes] = None,
                       cancel_key_list: Optional[List[SolAccountMeta]] = None) -> SolTxIx:
        append_key_list: List[SolAccountMeta] = self._neon_account_list if cancel_key_list is None else cancel_key_list

        if neon_tx_sig is None:
            neon_tx_sig = keccak_256(self._msg).digest()

        if holder_account is None:
            holder_account = self._holder

        return SolTxIx(
            program_id=self._evm_program_id,
            data=EvmInstruction.CancelWithHash.value + neon_tx_sig,
            accounts=[
                SolAccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=INCINERATOR_ID, is_signer=False, is_writable=True),
            ] + append_key_list
        )

    def make_tx_step_from_data_ix(self, step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(EvmInstruction.TransactionStepFromData.value, step_cnt, index, self._msg)

    def _make_tx_step_ix(self, ix_id_byte: bytes, neon_step_cnt: int, index: int,
                         data: Optional[bytes]) -> SolTxIx:
        ix_data = b"".join([
            ix_id_byte,
            self._treasury_pool_index_buf,
            neon_step_cnt.to_bytes(4, byteorder='little'),
            index.to_bytes(4, byteorder="little")
        ])

        if data is not None:
            ix_data = ix_data + data

        return self._make_holder_ix(ix_data)

    def _make_holder_ix(self, ix_data: bytes):
        return SolTxIx(
            program_id=self._evm_program_id,
            data=ix_data,
            accounts=[
                 SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                 SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                 SolAccountMeta(pubkey=self._evm_program_id, is_signer=False, is_writable=False),
             ] + self._neon_account_list
        )

    def make_tx_step_from_account_ix(self, neon_step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(EvmInstruction.TransactionStepFromAccount.value, neon_step_cnt, index, None)

    def make_tx_step_from_account_no_chainid_ix(self, neon_step_cnt: int, index: int) -> SolTxIx:
        return self._make_tx_step_ix(
            EvmInstruction.TransactionStepFromAccountNoChainId.value,
            neon_step_cnt, index, None
        )

    def make_create_lookup_table_ix(self, table_account: SolPubKey,
                                    recent_block_slot: int,
                                    seed: int) -> SolTxIx:
        data = b"".join([
            int(0).to_bytes(4, byteorder="little"),
            recent_block_slot.to_bytes(8, byteorder="little"),
            seed.to_bytes(1, byteorder="little")
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
        data = b"".join(
            [
                int(2).to_bytes(4, byteorder="little"),
                len(account_list).to_bytes(8, byteorder="little")
            ] +
            [bytes(pubkey) for pubkey in account_list]
        )

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
        data = int(3).to_bytes(4, byteorder="little")
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
            ]
        )

    def make_close_lookup_table_ix(self, table_account: SolPubKey) -> SolTxIx:
        data = int(4).to_bytes(4, byteorder="little")
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            accounts=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                SolAccountMeta(pubkey=self._operator_account, is_signer=False, is_writable=True),  # refund
            ]
        )

    def make_compute_budget_heap_ix(self) -> SolTxIx:
        heap_frame_size = self._elf_params.neon_heap_frame
        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            accounts=[],
            data=bytes.fromhex("01") + heap_frame_size.to_bytes(4, "little")
        )

    def make_compute_budget_cu_ix(self) -> SolTxIx:
        compute_unit_cnt = self._elf_params.neon_compute_units
        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            accounts=[],
            data=bytes.fromhex("02") + compute_unit_cnt.to_bytes(4, "little")
        )
