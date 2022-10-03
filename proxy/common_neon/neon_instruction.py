import rlp

from enum import Enum
from typing import Optional, List, cast

from sha3 import keccak_256
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from solana.transaction import AccountMeta, TransactionInstruction
from logged_groups import logged_group

from .layouts import CREATE_ACCOUNT_LAYOUT
from ..common_neon.elf_params import ElfParams

from .address import accountWithSeed, ether2program, EthereumAddress
from .constants import INCINERATOR_PUBKEY, COLLATERALL_POOL_MAX
from .eth_proto import Trx as NeonTx
from .environment_data import EVM_LOADER_ID
from ..common_neon.solana_alt import ADDRESS_LOOKUP_TABLE_ID


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

def create_account_with_seed_layout(base, seed, lamports, space):
    return SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type=InstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed), chars=seed),
                lamports=lamports,
                space=space,
                program_id=bytes(PublicKey(EVM_LOADER_ID))
            )
        )
    )


def create_account_layout(ether):
    return EvmInstruction.CreateAccountV03.value + CREATE_ACCOUNT_LAYOUT.build(dict(ether=ether))


@logged_group("neon.Proxy")
class NeonIxBuilder:
    def __init__(self, operator: PublicKey):
        self._operator_account = operator
        self._operator_neon_address: Optional[PublicKey] = None
        self._neon_account_list: List[AccountMeta] = []
        self._neon_tx: Optional[NeonTx] = None
        self._msg: Optional[bytes] = None
        self._holder_msg: Optional[bytes] = None
        self._treasury_pool_index_buf: Optional[bytes] = None
        self._treasury_pool_address: Optional[PublicKey] = None
        self._holder: Optional[PublicKey] = None

    @property
    def operator_account(self) -> PublicKey:
        return self._operator_account

    @property
    def holder_msg(self) -> bytes:
        assert self._holder_msg is not None
        return cast(bytes, self._holder_msg)

    def init_operator_neon(self, operator_ether: EthereumAddress):
        self._operator_neon_address = ether2program(operator_ether)[0]

    def init_neon_tx(self, neon_tx: NeonTx):
        self._neon_tx = neon_tx

        self._msg = rlp.encode(self._neon_tx)
        self._holder_msg = self._msg

        keccak_result = keccak_256(self._neon_tx.unsigned_msg()).digest()
        treasury_pool_index = int().from_bytes(keccak_result[:4], "little") % COLLATERALL_POOL_MAX
        self._treasury_pool_index_buf = treasury_pool_index.to_bytes(4, 'little')
        self._treasury_pool_address = self.create_collateral_pool_address(treasury_pool_index)

        return self

    def init_neon_account_list(self, neon_account_list: List[AccountMeta]):
        self._neon_account_list = neon_account_list

    def init_iterative(self, holder: PublicKey):
        self._holder = holder
        return self

    @staticmethod
    def create_collateral_pool_address(collateral_pool_index):
        COLLATERAL_SEED_PREFIX = "collateral_seed_"
        seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
        collateral_pool_base = PublicKey(ElfParams().collateral_pool_base)
        return accountWithSeed(collateral_pool_base, str.encode(seed))

    def make_create_account_with_seed_ix(self, account, seed, lamports, space) -> TransactionInstruction:
        seed_str = str(seed, 'utf8')
        self.debug(f"createAccountWithSeedTrx {self._operator_account} account({account} seed({seed_str})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),
            ],
            program_id=SYS_PROGRAM_ID,
            data=create_account_with_seed_layout(self._operator_account, seed_str, lamports, space)
        )

    def make_delete_holder_ix(self, holder_account: PublicKey) -> TransactionInstruction:
        self.debug(f"deleteHolderTrx {self._operator_account} refunded account({holder_account})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.HolderDelete.value,
        )

    def create_holder_ix(self, holder: PublicKey) -> TransactionInstruction:
        self.debug(f"createHolderTrx {self._operator_account} account({holder})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.HolderCreate.value,
        )

    def make_create_eth_account_ix(self, eth_address: EthereumAddress) -> TransactionInstruction:
        if isinstance(eth_address, str):
            eth_address = EthereumAddress(eth_address)
        pda_account, nonce = ether2program(eth_address)
        self.debug(f'Create eth account: {str(eth_address)}, sol account: {pda_account}, nonce: {nonce}')

        base = self._operator_account
        data = create_account_layout(bytes(eth_address))
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=pda_account, is_signer=False, is_writable=True),
            ])

    def make_write_ix(self, neon_tx_sig: bytes, offset: int, data: bytes) -> TransactionInstruction:
        ix_data = b"".join([
            EvmInstruction.HolderWrite.value,
            neon_tx_sig,
            offset.to_bytes(8, byteorder='little'),
            data
        ])
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
                AccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),
            ]
        )

    def make_tx_exec_from_data_ix(self) -> TransactionInstruction:
        ix_data = b"".join([
            EvmInstruction.TransactionExecuteFromData.value,
            self._treasury_pool_index_buf,
            self._msg
        ])
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
            ] + self._neon_account_list
        )

    def make_cancel_ix(self, holder_account: Optional[PublicKey] = None,
                       neon_tx_sig: Optional[bytes] = None,
                       cancel_key_list: Optional[List[AccountMeta]] = None) -> TransactionInstruction:
        append_key_list: List[AccountMeta] = self._neon_account_list if cancel_key_list is None else cancel_key_list

        if neon_tx_sig is None:
            neon_tx_sig = keccak_256(self._msg).digest()

        if holder_account is None:
            holder_account = self._holder

        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.CancelWithHash.value + neon_tx_sig,
            keys=[
                AccountMeta(pubkey=holder_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
            ] + append_key_list
        )

    def make_tx_step_from_data_ix(self, step_cnt: int, index: int) -> TransactionInstruction:
        return self._make_tx_step_ix(EvmInstruction.TransactionStepFromData.value, step_cnt, index, self._msg)

    def _make_tx_step_ix(self, ix_id_byte: bytes, neon_step_cnt: int, index: int,
                         data: Optional[bytes]) -> TransactionInstruction:
        ix_data = b"".join([
            ix_id_byte,
            self._treasury_pool_index_buf,
            neon_step_cnt.to_bytes(4, byteorder='little'),
            index.to_bytes(4, byteorder="little")
        ])

        if data is not None:
            ix_data = ix_data + data

        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=ix_data,
            keys=[
                 AccountMeta(pubkey=self._holder, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),
                 AccountMeta(pubkey=self._treasury_pool_address, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=self._operator_neon_address, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                 AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
             ] + self._neon_account_list
        )

    def make_tx_step_from_account_ix(self, neon_step_cnt: int, index: int) -> TransactionInstruction:
        return self._make_tx_step_ix(EvmInstruction.TransactionStepFromAccount.value, neon_step_cnt, index, None)

    def make_tx_step_from_account_no_chainid_ix(self, neon_step_cnt: int, index: int) -> TransactionInstruction:
        return self._make_tx_step_ix(
            EvmInstruction.TransactionStepFromAccountNoChainId.value,
            neon_step_cnt, index, None
        )

    def make_create_lookup_table_ix(self, table_account: PublicKey,
                                    recent_block_slot: int,
                                    seed: int) -> TransactionInstruction:
        data = b"".join([
            int(0).to_bytes(4, byteorder="little"),
            recent_block_slot.to_bytes(8, byteorder="little"),
            seed.to_bytes(1, byteorder="little")
        ])
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),   # payer
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_extend_lookup_table_ix(self, table_account: PublicKey,
                                    account_list: List[PublicKey]) -> TransactionInstruction:
        data = b"".join(
            [
                int(2).to_bytes(4, byteorder="little"),
                len(account_list).to_bytes(8, byteorder="little")
            ] +
            [bytes(pubkey) for pubkey in account_list]
        )

        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=True),   # payer
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_deactivate_lookup_table_ix(self, table_account: PublicKey) -> TransactionInstruction:
        data = int(3).to_bytes(4, byteorder="little")
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
            ]
        )

    def make_close_lookup_table_ix(self, table_account: PublicKey) -> TransactionInstruction:
        data = int(4).to_bytes(4, byteorder="little")
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self._operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self._operator_account, is_signer=False, is_writable=True),  # refund
            ]
        )
