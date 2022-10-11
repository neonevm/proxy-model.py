from __future__ import annotations

from typing import NamedTuple, List, Union

from ..common_neon.solana_transaction import SolBlockhash, SolPubKey, SolLegacyMsg, SolLegacyMsgArgs, SolMsgHdr
from ..common_neon.solana_transaction import SolCompiledIx

from solana.utils import shortvec_encoding as shortvec
from solana.utils import helpers


class SolMsgALT(NamedTuple):
    """Address table lookups describe an on-chain address lookup table to use
    for loading more readonly and writable accounts in a single tx."""

    account_key: Union[str, SolPubKey]
    """Address lookup table account key pub """
    writable_indexes: List[int]
    """List of indexes used to load writable account addresses"""
    readonly_indexes: List[int]
    """// / List of indexes used to load readonly account addresses"""


class SolV0MsgArgs(NamedTuple):
    """V0 Message constructor arguments."""

    header: SolMsgHdr
    """The message header, identifying signed and read-only `accountKeys`."""
    account_keys: List[str]
    """All the account keys used by this transaction."""
    recent_blockhash: SolBlockhash
    """The hash of a recent ledger block."""
    instructions: List[SolCompiledIx]
    """Instructions that will be executed in sequence and committed in one atomic transaction if all succeed."""
    address_table_lookups: List[SolMsgALT]


class SolV0Msg(SolLegacyMsg):
    def __init__(self, args: SolV0MsgArgs) -> None:
        super().__init__(
            SolLegacyMsgArgs(
                header=args.header,
                account_keys=args.account_keys,
                recent_blockhash=args.recent_blockhash,
                instructions=args.instructions
            )
        )
        self.address_table_lookups = [
            SolMsgALT(
                account_key=SolPubKey(lookup.account_key),
                writable_indexes=lookup.writable_indexes,
                readonly_indexes=lookup.readonly_indexes,
            )
            for lookup in args.address_table_lookups
        ]

    @staticmethod
    def __encode_address_table_lookup(alt_msg_info: SolMsgALT) -> bytes:
        MessageAddressTableLookupFormat = NamedTuple(
            "MessageAddressTableLookupFormat", [
                ("account_key", bytes),
                ("writable_indexes_length", bytes),
                ("writable_indexes", bytes),
                ("readonly_indexes_length", bytes),
                ("readonly_indexes", bytes),
            ],
        )
        return b"".join(
            MessageAddressTableLookupFormat(
                account_key=bytes(alt_msg_info.account_key),
                writable_indexes_length=shortvec.encode_length(len(alt_msg_info.writable_indexes)),
                writable_indexes=b"".join([helpers.to_uint8_bytes(idx) for idx in alt_msg_info.writable_indexes]),
                readonly_indexes_length=shortvec.encode_length(len(alt_msg_info.readonly_indexes)),
                readonly_indexes=b"".join([helpers.to_uint8_bytes(idx) for idx in alt_msg_info.readonly_indexes]),
            )
        )

    def serialize(self) -> bytes:
        message_buffer = bytearray.fromhex("80")
        message_buffer.extend(super().serialize())
        message_buffer.extend(shortvec.encode_length(len(self.address_table_lookups)))
        for alt_msg_info in self.address_table_lookups:
            message_buffer.extend(self.__encode_address_table_lookup(alt_msg_info))
        return bytes(message_buffer)

    @staticmethod
    def deserialize(raw_message: bytes) -> Union[SolLegacyMsg, SolV0Msg]:
        raise NotImplementedError("deserialize of v0 message is not implemented!")
