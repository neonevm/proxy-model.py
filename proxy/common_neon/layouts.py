from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64ul
from construct import Struct


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
