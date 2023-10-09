from __future__ import annotations

import math
import logging

from dataclasses import dataclass
from typing import Optional, List

from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64ul
from construct import Struct

from .constants import LOOKUP_ACCOUNT_TAG, ADDRESS_LOOKUP_TABLE_ID

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
