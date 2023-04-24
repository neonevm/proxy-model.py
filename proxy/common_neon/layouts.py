from __future__ import annotations

import math

from dataclasses import dataclass
from typing import Optional, List, Tuple

from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64ul
from construct import Struct

from .constants import ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG, LOOKUP_ACCOUNT_TAG, NEON_ACCOUNT_TAG
from .elf_params import ElfParams
from .solana_tx import SolPubKey

HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "owner" / Bytes(32),
    "neon_tx_sig" / Bytes(32)
)

ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "owner" / Bytes(32),
    "neon_tx_sig" / Bytes(32),
    "caller" / Bytes(20),
    "gas_limit" / Bytes(32),
    "gas_price" / Bytes(32),
    "gas_used" / Bytes(32),
    "operator" / Bytes(32),
    "block_slot" / Int64ul,
    "account_list_len" / Int64ul,
    "evm_state_len" / Int64ul,
    "evm_machine_len" / Int64ul,
)

FINALIZED_HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "owner" / Bytes(32),
    "neon_tx_sig" / Bytes(32)
)

ACCOUNT_INFO_LAYOUT = Struct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "tx_count" / Bytes(8),
    "balance" / Bytes(32),
    "generation" / Int32ul,
    "code_size" / Int32ul,
    "is_rw_blocked" / Int8ul,
)

CREATE_ACCOUNT_LAYOUT = Struct(
    "ether" / Bytes(20),
)

ACCOUNT_LOOKUP_TABLE_LAYOUT = Struct(
    "type" / Int32ul,
    "deactivation_slot" / Int64ul,
    "last_extended_slot" / Int64ul,
    "last_extended_slot_start_index" / Int8ul,
    "has_authority" / Int8ul,
    "authority" / Bytes(32),
    "padding" / Int16ul
)


@dataclass
class AccountInfo:
    address: SolPubKey
    tag: int
    lamports: int
    owner: SolPubKey
    data: bytes


@dataclass
class NeonAccountInfo:
    pda_address: SolPubKey
    ether: str
    nonce: int
    tx_count: int
    balance: int
    generation: int
    code_size: int
    is_rw_blocked: bool
    code: Optional[str]

    @staticmethod
    def from_account_info(info: AccountInfo) -> NeonAccountInfo:
        if len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(
                f"Wrong data length for account data {str(info.address)}: "
                f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}"
            )
        elif info.tag != NEON_ACCOUNT_TAG:
            raise RuntimeError(f"Wrong tag {info.tag} for neon account info {str(info.address)}")

        cont = ACCOUNT_INFO_LAYOUT.parse(info.data)

        base_size = ACCOUNT_INFO_LAYOUT.sizeof()
        storage_size = ElfParams().storage_entries_in_contract_account * 32
        code_offset = base_size + storage_size

        code = None
        if cont.code_size > 0 and len(info.data) >= code_offset:
            code = '0x' + info.data[code_offset:][:cont.code_size].hex()

        return NeonAccountInfo(
            pda_address=info.address,
            ether=cont.ether.hex(),
            nonce=cont.nonce,
            tx_count=int.from_bytes(cont.tx_count, "little"),
            balance=int.from_bytes(cont.balance, "little"),
            generation=cont.generation,
            code_size=cont.code_size,
            is_rw_blocked=(cont.is_rw_blocked != 0),
            code=code,
        )


@dataclass
class HolderAccountInfo:
    holder_account: SolPubKey
    tag: int
    owner: SolPubKey
    neon_tx_sig: str
    neon_tx_data: Optional[bytes]
    caller: Optional[str]
    gas_limit: Optional[int]
    gas_price: Optional[int]
    gas_used: Optional[int]
    operator: Optional[SolPubKey]
    block_slot: Optional[int]
    account_list_len: Optional[int]
    account_list: Optional[List[Tuple[bool, bool, str]]]

    @staticmethod
    def from_account_info(info: AccountInfo) -> Optional[HolderAccountInfo]:
        if len(info.data) < 1:
            return None
        if info.tag == ACTIVE_HOLDER_TAG:
            return HolderAccountInfo._decode_active_holder_account(info)
        elif info.tag == FINALIZED_HOLDER_TAG:
            return HolderAccountInfo._decode_finalized_holder_account(info)
        elif info.tag == HOLDER_TAG:
            return HolderAccountInfo._decode_holder_account(info)
        else:
            return None

    @staticmethod
    def _decode_active_holder_account(info: AccountInfo) -> Optional[HolderAccountInfo]:
        if len(info.data) < ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        storage = ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT.parse(info.data)

        account_list: List[Tuple[bool, bool, str]] = []
        offset = ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.account_list_len):
            writable = (info.data[offset] > 0)
            offset += 1

            exists = (info.data[offset] > 0)
            offset += 1

            some_pubkey = SolPubKey.from_bytes(info.data[offset:offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH

            account_list.append((writable, exists, str(some_pubkey)))

        return HolderAccountInfo(
            holder_account=info.address,
            tag=storage.tag,
            owner=SolPubKey.from_bytes(storage.owner),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller=storage.caller.hex(),
            gas_limit=int.from_bytes(storage.gas_limit, "little"),
            gas_price=int.from_bytes(storage.gas_price, "little"),
            gas_used=int.from_bytes(storage.gas_used, "little"),
            operator=SolPubKey.from_bytes(storage.operator),
            block_slot=storage.block_slot,
            account_list_len=storage.account_list_len,
            account_list=account_list
        )

    @staticmethod
    def _decode_finalized_holder_account(info: AccountInfo) -> Optional[HolderAccountInfo]:
        if len(info.data) < FINALIZED_HOLDER_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        storage = FINALIZED_HOLDER_ACCOUNT_INFO_LAYOUT.parse(info.data)

        return HolderAccountInfo(
            holder_account=info.address,
            tag=storage.tag,
            owner=SolPubKey.from_bytes(storage.owner),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            operator=None,
            block_slot=None,
            account_list_len=None,
            account_list=None
        )

    @staticmethod
    def _decode_holder_account(info: AccountInfo) -> Optional[HolderAccountInfo]:
        if len(info.data) < HOLDER_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        holder = HOLDER_ACCOUNT_INFO_LAYOUT.parse(info.data)
        offset = HOLDER_ACCOUNT_INFO_LAYOUT.sizeof()

        neon_tx_data = info.data[offset:]

        return HolderAccountInfo(
            holder_account=info.address,
            tag=holder.tag,
            owner=SolPubKey.from_bytes(holder.owner),
            neon_tx_sig='0x' + holder.neon_tx_sig.hex().lower(),
            neon_tx_data=neon_tx_data,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            operator=None,
            block_slot=None,
            account_list_len=None,
            account_list=None
        )


@dataclass
class ALTAccountInfo:
    type: int
    table_account: SolPubKey
    deactivation_slot: Optional[int]
    last_extended_slot: int
    last_extended_slot_start_index: int
    authority: Optional[SolPubKey]
    account_key_list: List[SolPubKey]

    @staticmethod
    def from_account_info(info: AccountInfo) -> Optional[ALTAccountInfo]:
        if len(info.data) < ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof():
            raise RuntimeError(
                f"Wrong data length for lookup table data {str(info.address)}: "
                f"{len(info.data)} < {ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()}"
            )

        lookup = ACCOUNT_LOOKUP_TABLE_LAYOUT.parse(info.data)
        if lookup.type != LOOKUP_ACCOUNT_TAG:
            return None

        offset = ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()
        if (len(info.data) - offset) % SolPubKey.LENGTH:
            return None

        account_key_list = []
        account_key_list_len = math.ceil((len(info.data) - offset) / SolPubKey.LENGTH)
        for _ in range(account_key_list_len):
            some_pubkey = SolPubKey.from_bytes(info.data[offset:offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH
            account_key_list.append(some_pubkey)

        authority = SolPubKey.from_bytes(lookup.authority) if lookup.has_authority else None

        u64_max = 2 ** 64 - 1

        return ALTAccountInfo(
            type=lookup.type,
            table_account=info.address,
            deactivation_slot=None if lookup.deactivation_slot == u64_max else lookup.deactivation_slot,
            last_extended_slot=lookup.last_extended_slot,
            last_extended_slot_start_index=lookup.last_extended_slot_start_index,
            authority=authority,
            account_key_list=account_key_list
        )
