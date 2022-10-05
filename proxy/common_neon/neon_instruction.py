from __future__ import annotations

import rlp

from enum import Enum
from typing import Optional, List, cast
from logged_groups import logged_group
from sha3 import keccak_256

from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType

from ..common_neon.elf_params import ElfParams
from ..common_neon.solana_transaction import SolTxIx, SolPubKey, SolAccountMeta
from ..common_neon.address import accountWithSeed, ether2program, EthereumAddress
from ..common_neon.constants import INCINERATOR_ID, COMPUTE_BUDGET_ID, ADDRESS_LOOKUP_TABLE_ID, SYS_PROGRAM_ID
from ..common_neon.constants import TREASURY_POOL_MAX
from ..common_neon.layouts import CREATE_ACCOUNT_LAYOUT
from ..common_neon.eth_proto import NeonTx
from ..common_neon.environment_data import EVM_LOADER_ID


class EvmInstruction(Enum):
    TransactionExecuteFromData = b'\x1f'            # 31,
    TransactionStepFromData = b'\x20'               # 32
    TransactionStepFromAccount = b'\x21'            # 33
    TransactionStepFromAccountNoChainId = b'\x22'   # 34
    CancelWithHash = b'\x23'                        # 35
    HolderCreate = b'\x24'                          # 36
    HolderDelete = b'\x25'                          # 37
    HolderWrite = b'\x26'                           # 38
    DepositV03 = b'\x27'                            # 39
    CreateAccountV03 = b'\x28'                      # 40

def create_account_with_seed_layout(base: SolPubKey, seed: str, lamports: int, space: int):
    return SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type=InstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed), chars=seed),
                lamports=lamports,
                space=space,
                program_id=bytes(SolPubKey(EVM_LOADER_ID))
            )
        )
    )


def create_account_layout(ether):
    return EvmInstruction.CreateAccountV03.value + CREATE_ACCOUNT_LAYOUT.build(dict(ether=ether))


@logged_group("neon.Proxy")
class NeonIxBuilder:
    def __init__(self, operator: SolPubKey):
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

    def init_operator_neon(self, operator_ether: EthereumAddress) -> NeonIxBuilder:
        self._operator_neon_address = ether2program(operator_ether)[0]
        return self

    def init_neon_tx(self, neon_tx: NeonTx) -> NeonIxBuilder:
        self._neon_tx = neon_tx

        self._msg = rlp.encode(self._neon_tx)
        self._holder_msg = self._msg

        keccak_result = keccak_256(self._neon_tx.unsigned_msg()).digest()
        treasury_pool_index = int().from_bytes(keccak_result[:4], "little") % TREASURY_POOL_MAX
        self._treasury_pool_index_buf = treasury_pool_index.to_bytes(4, 'little')
        self._treasury_pool_address = self.create_treasury_pool_address(treasury_pool_index)

        return self

    def init_neon_account_list(self, neon_account_list: List[SolAccountMeta]) -> NeonIxBuilder:
        self._neon_account_list = neon_account_list
        return self

    def init_iterative(self, holder: SolPubKey):
        self._holder = holder
        return self

    @staticmethod
    def create_treasury_pool_address(treasury_pool_index):
        TREASURY_SEED_PREFIX = "collateral_seed_"
        seed = TREASURY_SEED_PREFIX + str(treasury_pool_index)
        collateral_pool_base = SolPubKey(ElfParams().collateral_pool_base)
        return accountWithSeed(collateral_pool_base, str.encode(seed))

    def make_create_account_with_seed_ix(self, account: SolPubKey, seed: bytes, lamports: int, space: int) -> SolTxIx:
        seed_str = str(seed, 'utf8')
        self.debug(f"createAccountWithSeedTrx {self._operator_account} account({account} seed({seed_str})")
        return SolTxIx(
            keys=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),
            ],
            program_id=SYS_PROGRAM_ID,
            data=create_account_with_seed_layout(self._operator_account, seed_str, lamports, space)
        )

    def make_delete_holder_ix(self, holder_account: SolPubKey) -> SolTxIx:
        self.debug(f"deleteHolderTrx {self._operator_account} refunded account({holder_account})")
        return SolTxIx(
            keys=[
                SolAccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.HolderDelete.value,
        )

    def create_holder_ix(self, holder: SolPubKey) -> SolTxIx:
        self.debug(f"createHolderTrx {self._operator_account} account({holder})")
        return SolTxIx(
            keys=[
                SolAccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.HolderCreate.value,
        )

    def make_create_eth_account_ix(self, eth_address: EthereumAddress) -> SolTxIx:
        if isinstance(eth_address, str):
            eth_address = EthereumAddress(eth_address)
        pda_account, nonce = ether2program(eth_address)
        self.debug(f'Create eth account: {str(eth_address)}, sol account: {pda_account}, nonce: {nonce}')

        base = self._operator_account
        data = create_account_layout(bytes(eth_address))
        return SolTxIx(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                SolAccountMeta(pubkey=base, is_signer=True, is_writable=True),
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
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
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
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
            ] + self._neon_account_list
        )

    def make_cancel_ix(self, holder_account: Optional[SolPubKey] = None,
                       neon_tx_sig: Optional[bytes] = None,
                       cancel_key_list: Optional[List[SolAccountMeta]] = None) -> SolTxIx:
        append_key_list: List[SolAccountMeta] = self._neon_account_list if cancel_key_list is None else cancel_key_list

        if neon_tx_sig is None:
            neon_tx_sig = keccak_256(self._msg).digest()

        if holder_account is None:
            holder_account = self._holder

        return SolTxIx(
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.CancelWithHash.value + neon_tx_sig,
            keys=[
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

        return SolTxIx(
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
                 SolAccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                 SolAccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                 SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                 SolAccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
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
            keys=[
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
            keys=[
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
            keys=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
            ]
        )

    def make_close_lookup_table_ix(self, table_account: SolPubKey) -> SolTxIx:
        data = int(4).to_bytes(4, byteorder="little")
        return SolTxIx(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                SolAccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                SolAccountMeta(pubkey=self._operator_account, is_signer=False, is_writable=True),  # refund
            ]
        )

    def make_compute_budget_heap_ix(self) -> SolTxIx:
        heap_frame_size = self._elf_params.neon_heap_frame
        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("01") + heap_frame_size.to_bytes(4, "little")
        )

    def make_compute_budget_cu_ix(self, compute_unit_cnt: Optional[int] = None) -> SolTxIx:
        if compute_unit_cnt is None:
            compute_unit_cnt = self._elf_params.neon_compute_units

        return SolTxIx(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("02") + compute_unit_cnt.to_bytes(4, "little")
        )
