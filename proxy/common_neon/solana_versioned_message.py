from __future__ import annotations
from typing import NamedTuple, List, Union

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.message import Message, MessageArgs, MessageHeader, CompiledInstruction
from solana.utils import shortvec_encoding as shortvec
from solana.utils import helpers


class MessageAddressTableLookup(NamedTuple):
    """Address table lookups describe an on-chain address lookup table to use
    for loading more readonly and writable accounts in a single tx."""

    account_key: Union[str, PublicKey]
    """Address lookup table account key pub """
    writable_indexes: List[int]
    """List of indexes used to load writable account addresses"""
    readonly_indexes: List[int]
    """// / List of indexes used to load readonly account addresses"""


class V0MessageArgs(NamedTuple):
    """V0 Message constructor arguments."""

    header: MessageHeader
    """The message header, identifying signed and read-only `accountKeys`."""
    account_keys: List[str]
    """All the account keys used by this transaction."""
    recent_blockhash: Blockhash
    """The hash of a recent ledger block."""
    instructions: List[CompiledInstruction]
    """Instructions that will be executed in sequence and committed in one atomic transaction if all succeed."""
    address_table_lookups: List[MessageAddressTableLookup]


class V0Message(Message):
    def __init__(self, args: V0MessageArgs) -> None:
        super().__init__(MessageArgs(
            header=args.header,
            account_keys=args.account_keys,
            recent_blockhash=args.recent_blockhash,
            instructions=args.instructions
        ))
        self.address_table_lookups = [
            MessageAddressTableLookup(
                account_key=PublicKey(lookup.account_key),
                writable_indexes=lookup.writable_indexes,
                readonly_indexes=lookup.readonly_indexes,
            )
            for lookup in args.address_table_lookups
        ]

    @staticmethod
    def __encode_address_table_lookup(lookup: MessageAddressTableLookup) -> bytes:
        MessageAddressTableLookupFormat = NamedTuple(
            "MessageAddressTableLookupFormat",
            [
                ("account_key", bytes),
                ("writable_indexes_length", bytes),
                ("writable_indexes", bytes),
                ("readonly_indexes_length", bytes),
                ("readonly_indexes", bytes),
            ],
        )
        return b"".join(
            MessageAddressTableLookupFormat(
                account_key=bytes(lookup.account_key),
                writable_indexes_length=shortvec.encode_length(len(lookup.writable_indexes)),
                writable_indexes=b"".join([helpers.to_uint8_bytes(idx) for idx in lookup.writable_indexes]),
                readonly_indexes_length=shortvec.encode_length(len(lookup.readonly_indexes)),
                readonly_indexes=b"".join([helpers.to_uint8_bytes(idx) for idx in lookup.readonly_indexes]),
            )
        )

    def serialize(self) -> bytes:
        self.header.num_required_signatures |= 0b_1000_0000  # set the highest bit
        try:
            message_buffer = bytearray(super().serialize())
        finally:
            self.header.num_required_signatures &= 0b_0111_1111  # reset the highest bit
        message_buffer.extend(shortvec.encode_length(len(self.address_table_lookups)))
        for lookup in self.address_table_lookups:
            message_buffer.extend(self.__encode_address_table_lookup(lookup))
        return bytes(message_buffer)

    @staticmethod
    def deserialize(raw_message: bytes) -> Union[Message, V0Message]:
        raise NotImplementedError("deserialize of versioned message is not implemented!")
