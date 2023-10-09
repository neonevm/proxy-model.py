from __future__ import annotations

import math
import logging

from dataclasses import dataclass
from typing import Optional, List

from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64ul
from construct import Struct

from .constants import (
    ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG,
    LOOKUP_ACCOUNT_TAG, ADDRESS_LOOKUP_TABLE_ID
)

from .solana_tx import SolPubKey


LOG = logging.getLogger(__name__)


HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "operator" / Bytes(32),
    "neon_tx_sig" / Bytes(32)
)

ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "operator" / Bytes(32),
    "neon_tx_sig" / Bytes(32),
    "caller" / Bytes(20),
    "gas_limit" / Bytes(32),
    "gas_price" / Bytes(32),
    "gas_used" / Bytes(32),
    "last_operator" / Bytes(32),
    "block_slot" / Int64ul,
    "account_list_len" / Int64ul,
    "evm_state_len" / Int64ul,
    "evm_machine_len" / Int64ul,
)

FINALIZED_HOLDER_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "operator" / Bytes(32),
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


@dataclass(frozen=True)
class HolderMetaAccountInfo:
    pubkey: SolPubKey
    is_writable: bool
    is_exists: bool


@dataclass
class HolderAccountInfo:
    holder_account: SolPubKey
    lamports: int
    owner: SolPubKey
    tag: int
    data_size: int
    operator: SolPubKey
    neon_tx_sig: str
    neon_tx_data: Optional[bytes]
    caller: Optional[str]
    gas_limit: Optional[int]
    gas_price: Optional[int]
    gas_used: Optional[int]
    last_operator: Optional[SolPubKey]
    block_slot: Optional[int]
    account_list_len: Optional[int]
    account_list: Optional[List[HolderMetaAccountInfo]]

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

        account_list: List[HolderMetaAccountInfo] = list()
        offset = ACTIVE_HOLDER_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.account_list_len):
            is_writable = (info.data[offset] > 0)
            offset += 1

            is_exists = (info.data[offset] > 0)
            offset += 1

            some_pubkey = SolPubKey.from_bytes(info.data[offset:offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH

            account_list.append(HolderMetaAccountInfo(
                pubkey=some_pubkey,
                is_exists=is_exists,
                is_writable=is_writable
            ))

        return HolderAccountInfo(
            holder_account=info.address,
            lamports=info.lamports,
            owner=info.owner,
            tag=storage.tag,
            data_size=len(info.data),
            operator=SolPubKey.from_bytes(storage.operator),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller='0x' + storage.caller.hex(),
            gas_limit=int.from_bytes(storage.gas_limit, "little"),
            gas_price=int.from_bytes(storage.gas_price, "little"),
            gas_used=int.from_bytes(storage.gas_used, "little"),
            last_operator=SolPubKey.from_bytes(storage.last_operator),
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
            lamports=info.lamports,
            owner=info.owner,
            tag=storage.tag,
            data_size=len(info.data),
            operator=SolPubKey.from_bytes(storage.operator),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            last_operator=None,
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
            lamports=info.lamports,
            owner=info.owner,
            tag=holder.tag,
            data_size=len(info.data),
            operator=SolPubKey.from_bytes(holder.operator),
            neon_tx_sig='0x' + holder.neon_tx_sig.hex().lower(),
            neon_tx_data=neon_tx_data,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            last_operator=None,
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
        if info.owner != ADDRESS_LOOKUP_TABLE_ID:
            LOG.warning(f'Wrong owner {str(info.owner)} of account {str(info.address)}')
            return None
        elif len(info.data) < ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof():
            LOG.warning(
                f'Wrong data length for lookup table data {str(info.address)}: '
                f'{len(info.data)} < {ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()}'
            )
            return None

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
