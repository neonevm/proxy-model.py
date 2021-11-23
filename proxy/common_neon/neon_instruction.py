import logging
import struct
from construct import Bytes, Int8ul, Int64ul
from construct import Struct as cStruct
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from spl.token.constants import ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID
from sha3 import keccak_256

from proxy.environment import evm_loader_id as EVM_LOADER_ID, ETH_TOKEN_MINT_ID , COLLATERAL_POOL_BASE
from .constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM, COLLATERALL_POOL_MAX
from .address import accountWithSeed, ether2program, getTokenAddr


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


CREATE_ACCOUNT_LAYOUT = cStruct(
    "lamports" / Int64ul,
    "space" / Int64ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul
)


obligatory_accounts = [
    AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=SYSVAR_CLOCK_PUBKEY, is_signer=False, is_writable=False),
]


def create_account_layout(lamports, space, ether, nonce):
    return bytes.fromhex("02000000")+CREATE_ACCOUNT_LAYOUT.build(dict(
        lamports=lamports,
        space=space,
        ether=ether,
        nonce=nonce
    ))


def write_holder_layout(nonce, offset, data):
    return (bytes.fromhex('12')+
            nonce.to_bytes(8, byteorder='little')+
            offset.to_bytes(4, byteorder='little')+
            len(data).to_bytes(8, byteorder='little')+
            data)


def make_keccak_instruction_data(check_instruction_index, msg_len, data_start):
    if check_instruction_index > 255 and check_instruction_index < 0:
        raise Exception("Invalid index for instruction - {}".format(check_instruction_index))

    check_count = 1
    eth_address_size = 20
    signature_size = 65
    eth_address_offset = data_start
    signature_offset = eth_address_offset + eth_address_size
    message_data_offset = signature_offset + signature_size

    data = struct.pack("B", check_count)
    data += struct.pack("<H", signature_offset)
    data += struct.pack("B", check_instruction_index)
    data += struct.pack("<H", eth_address_offset)
    data += struct.pack("B", check_instruction_index)
    data += struct.pack("<H", message_data_offset)
    data += struct.pack("<H", msg_len)
    data += struct.pack("B", check_instruction_index)

    return data


class NeonInstruction:
    def __init__(self, operator, eth_trx = None):
        self.operator = operator
        self.operator_token = getTokenAddr(self.operator)

        self.caller_token = None

        self.eth_accounts = None

        self.storage = None
        self.holder = None
        self.perm_accs_id = None

        self.eth_trx = eth_trx

        if eth_trx is not None:
            self.msg = bytes.fromhex(self.eth_trx.sender()) + self.eth_trx.signature() + self.eth_trx.unsigned_msg()

            hash = keccak_256(self.eth_trx.unsigned_msg()).digest()
            collateral_pool_index = int().from_bytes(hash[:4], "little") % COLLATERALL_POOL_MAX
            self.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')
            self.collateral_pool_address = self.create_collateral_pool_address(collateral_pool_index)
        else:
            self.msg = None
            self.collateral_pool_index_buf = None
            self.collateral_pool_address = None


    def set_accounts(self, eth_accounts, caller_token):
        self.eth_accounts = eth_accounts
        self.caller_token = caller_token


    def set_storage_and_holder(self, storage, holder, perm_accs_id):
        self.storage = storage
        self.holder = holder
        self.perm_accs_id = perm_accs_id


    def create_collateral_pool_address(self, collateral_pool_index):
        COLLATERAL_SEED_PREFIX = "collateral_seed_"
        seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
        return accountWithSeed(PublicKey(COLLATERAL_POOL_BASE), str.encode(seed), PublicKey(EVM_LOADER_ID))


    def create_account_with_seed_trx(self, seed, lamports, space):
        seed_str = str(seed, 'utf8')
        data = SYSTEM_INSTRUCTIONS_LAYOUT.build(
            dict(
                instruction_type = InstructionType.CREATE_ACCOUNT_WITH_SEED,
                args=dict(
                    base=bytes(self.operator),
                    seed=dict(length=len(seed_str), chars=seed_str),
                    lamports=lamports,
                    space=space,
                    program_id=bytes(PublicKey(EVM_LOADER_ID))
                )
            )
        )
        logger.debug("createAccountWithSeedTrx %s %s %s", type(self.operator), self.operator, data.hex())
        created = accountWithSeed(self.operator, seed, PublicKey(EVM_LOADER_ID))
        logger.debug("created %s", created)
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=created, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=False),
            ],
            program_id=SYS_PROGRAM_ID,
            data=data
        )


    def createEtherAccountTrx(self, ether, code_acc=None):
        if isinstance(ether, str):
            if ether.startswith('0x'): ether = ether[2:]
        else: ether = ether.hex()
        (sol, nonce) = ether2program(ether)
        associated_token = getTokenAddr(PublicKey(sol))
        logger.debug('createEtherAccount: {} {} => {}'.format(ether, nonce, sol))
        logger.debug('associatedTokenAccount: {}'.format(associated_token))
        base = self.operator
        data=create_account_layout(0, 0, bytes.fromhex(ether), nonce)
        trx = Transaction()
        if code_acc is None:
            trx.add(TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=associated_token, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
                ]))
        else:
            trx.add(TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=associated_token, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
                ]))
        return (trx, sol, associated_token)


    def createERC20TokenAccountTrx(self, token_info):
        trx = Transaction()
        trx.add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["key"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["owner"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["contract"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["mint"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        ))

        return trx


    def make_write_transaction(self, offset: int, data: bytes):
        return Transaction().add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=write_holder_layout(self.perm_accs_id, offset, data),
            keys=[
                AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=False),
            ]
        ))


    def make_keccak_instruction(self, check_instruction_index, msg_len, data_start):
        return TransactionInstruction(
            program_id=KECCAK_PROGRAM,
            data=make_keccak_instruction_data(check_instruction_index, msg_len, data_start),
            keys=[
                AccountMeta(pubkey=KECCAK_PROGRAM, is_signer=False, is_writable=False),
            ]
        )


    def make_05_call_instruction(self):
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("05") + self.collateral_pool_index_buf + self.msg,
            keys = [
                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + obligatory_accounts
        )


    def make_noniterative_call_transaction(self, length_before: int = 0) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 5))
        trx.add(self.make_05_call_instruction())
        return trx


    def make_partial_call_instruction(self):
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("13") + self.collateral_pool_index_buf + int(0).to_bytes(8, byteorder="little") + self.msg,
            keys = [
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
            )


    def make_iterative_call_transaction(self, length_before: int = 0) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 13))
        trx.add(self.make_partial_call_instruction())
        return trx


    def make_call_from_account_instruction(self) -> Transaction:
        return Transaction().add(TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("16") + self.collateral_pool_index_buf + int(0).to_bytes(8, byteorder="little"),
            keys = [
                AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        ))


    def make_continue_instruction(self, steps, index=None):
        data = bytearray.fromhex("14") + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder="little")
        if index:
            data = data + index.to_bytes(8, byteorder="little")

        return Transaction().add(TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = data,
            keys = [
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        ))


    def make_cancel_instruction(self):
        return Transaction().add(TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("15") + self.eth_trx.nonce.to_bytes(8, 'little'),
            keys = [
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        ))
