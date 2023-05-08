from construct import (
    Struct,
    Bytes, PascalString, PrefixedArray,
    Const, Flag, Byte,
    Int32ul, Int16ul, Int64ul,
    Subconstruct, Enum
)

from solders.pubkey import Pubkey
from solana.transaction import AccountMeta, Instruction

import enum
import base64
import base58


METADATA_PROGRAM_ID = Pubkey.from_string('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')
SYSTEM_PROGRAM_ID = Pubkey.from_string('11111111111111111111111111111111')
SYSVAR_RENT_PUBKEY = Pubkey.from_string('SysvarRent111111111111111111111111111111111')
ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID = Pubkey.from_string('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
TOKEN_PROGRAM_ID = Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')


class MetadataLimit(enum.IntEnum):
    MaxNameLen = 32
    MaxSymbolLen = 10
    MaxUriLen = 200
    MaxCreatorLen = 34
    MaxCreatorCnt = 5


class UseMethodType(enum.IntEnum):
    Burn = 0
    Multiple = 1
    Single = 2


class TokenStandardType(enum.IntEnum):
    NonFungible = 0
    FungibleAsset = 1
    Fungible = 2
    NonFungibleEdition = 3
    ProgrammableNonFungible = 4


class PrintSupplyType(enum.IntEnum):
    Zero = 0
    Limited = 1  # TODO: Int64ul
    Unlimited = 2


class MetadataKeyType(enum.IntEnum):
    Uninitialized = 0
    EditionV1 = 1
    MasterEditionV1 = 2
    ReservationListV1 = 3
    MetadataV1 = 4
    ReservationListV2 = 5
    MasterEditionV2 = 6
    EditionMarker = 7
    UseAuthorityRecord = 8
    CollectionAuthorityRecord = 9
    TokenOwnedEscrow = 10
    TokenRecord = 11
    MetadataDelegate = 12


class Option(Subconstruct):
    def __init__(self, subcon):
        super().__init__(subcon)
        self._flag = Flag

    def _parse(self, stream, context, path):
        has_value = self._flag._parsereport(stream, context, path)
        if not has_value:
            return None
        return self.subcon._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        has_value = obj is not None
        self._flag._build(has_value, stream, context, path)

        if not has_value:
            return
        self.subcon._build(obj, stream, context, path)


Utf8String = PascalString(Int32ul, "utf8")
Address = Bytes(32)
Base58Address = Utf8String  # TODO: deserialize as base58

Creator = Struct(
    "address" / Address,
    "verified" / Flag,
    "share" / Byte
)

Collection = Struct(
    "verified" / Flag,
    "key" / Address
)

Uses = Struct(
    "use_method" / Enum(Byte, UseMethodType),
    "remaining" / Int64ul,
    "total" / Int64ul
)

CollectionDetails = Struct(
    "ver" / Const(b'\x00'),
    "size" / Int64ul
)

AssetData = Struct(
    "name" / Utf8String,
    "symbol" / Utf8String,
    "uri" / Utf8String,
    "seller_fee_basis_points" / Int16ul,
    "creators" / Option(PrefixedArray(Int32ul, Creator)),
    "primary_sale_happened" / Flag,
    "is_mutable" / Flag,
    "token_standard" / Enum(Byte, TokenStandardType),
    "collection" / Option(Collection),
    "uses" / Option(Uses),
    "collection_details" / Option(CollectionDetails),
    "rule_set" / Option(Base58Address)
)

ProgrammableConfig = Struct(
    "ver" / Const(b'\x00'),
    "rule_set" / Option(Base58Address)
)

Data = Struct(
    "name" / Utf8String,
    "symbol" / Utf8String,
    "uri" / Utf8String,
    "seller_fee_basis_points" / Int16ul,
    "creators" / Option(PrefixedArray(Int32ul, Creator))
)

DataV2 = Struct(
    "name" / Utf8String,
    "symbol" / Utf8String,
    "uri" / Utf8String,
    "seller_fee_basis_points" / Int16ul,
    "creators" / Option(PrefixedArray(Int32ul, Creator)),
    "collection" / Option(Collection),
    "uses" / Option(Uses)
)

MetadataAccount = Struct(
    "key" / Enum(Byte, MetadataKeyType),
    "update_authority" / Address,
    "mint" / Address,
    "data" / Data,
    "primary_sale_happened" / Flag,
    "is_mutable" / Flag,
    "edition_nonce" / Option(Byte),
    "token_standard" / Option(Enum(Byte, TokenStandardType)),
    "collection" / Option(Collection),
    "uses" / Option(Uses),
    "collection_details" / Option(CollectionDetails),
    "programmable_config" / Option(ProgrammableConfig),
)

CreateMetadataV3Args = Struct(
    "data" / DataV2,
    "is_mutable" / Flag,
    "collection_details" / Option(CollectionDetails)
)

CreateMetadataV3Instruction = Struct(
    "instruction" / Const(b'\x21'),
    "args" / CreateMetadataV3Args
)

CreateArgs = Struct(
    "ver" / Const(b'\x00'),
    "asset_data" / AssetData,
    "decimals" / Option(Byte),
    "print_supply" / Option(Enum(Byte, PrintSupplyType))
)

CreateInstruction = Struct(
    "instruction" / Const(b'\x2a'),
    "args" / CreateArgs
)


def get_metadata_account(mint_key: Pubkey):
    return Pubkey.find_program_address(
        [b'metadata', bytes(METADATA_PROGRAM_ID), bytes(mint_key)],
        METADATA_PROGRAM_ID
    )[0]


def get_edition(mint_key: Pubkey):
    return Pubkey.find_program_address(
        [b'metadata', bytes(METADATA_PROGRAM_ID), bytes(mint_key), b"edition"],
        METADATA_PROGRAM_ID
    )[0]


def create_associated_token_account_instruction(associated_token_account, payer, wallet_address, token_mint_address):
    keys = [
        AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
        AccountMeta(pubkey=associated_token_account, is_signer=False, is_writable=True),
        AccountMeta(pubkey=wallet_address, is_signer=False, is_writable=False),
        AccountMeta(pubkey=token_mint_address, is_signer=False, is_writable=False),
        AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
    ]
    return Instruction(accounts=keys, program_id=ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID, data=b'')


def create_metadata_instruction_data(name: str, symbol: str, uri='', fee=0):
    assert len(name) <= MetadataLimit.MaxNameLen
    assert len(symbol) <= MetadataLimit.MaxSymbolLen
    assert len(uri) <= MetadataLimit.MaxUriLen

    return CreateInstruction.build(dict(
        args=dict(
            asset_data=dict(
                name=name,
                symbol=symbol,
                uri=uri,
                seller_fee_basis_points=fee,
                primary_sale_happened=False,
                is_mutable=True,
                token_standard=TokenStandardType.Fungible,
                creators=None,
                collection=None,
                uses=None,
                collection_details=None,
                rule_set=None
            ),
            decimals=None,
            print_supply=None
        )
    ))
    # return CreateMetadataV3Instruction.build(dict(
    #     args=dict(
    #         data=dict(
    #             name=name,
    #             symbol=symbol,
    #             uri=uri,
    #             seller_fee_basis_points=fee,
    #             creators=None,
    #             collection=None,
    #             uses=None,
    #         ),
    #         is_mutable=True,
    #         collection_details=None
    #     )
    # ))


def create_metadata_instruction(data, update_authority, mint_key, mint_authority_key, payer):
    metadata_account = get_metadata_account(mint_key)
    master_edition_account = get_edition(mint_key)
    keys = [
        AccountMeta(pubkey=metadata_account, is_signer=False, is_writable=True),
        AccountMeta(pubkey=master_edition_account, is_signer=False, is_writable=True),
        AccountMeta(pubkey=mint_key, is_signer=False, is_writable=False),
        AccountMeta(pubkey=mint_authority_key, is_signer=True, is_writable=False),
        AccountMeta(pubkey=payer, is_signer=True, is_writable=False),
        AccountMeta(pubkey=update_authority, is_signer=False, is_writable=False),
        AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
        AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False)
    ]
    return Instruction(accounts=keys, program_id=METADATA_PROGRAM_ID, data=data)


def get_metadata(client, mint_key):
    metadata_account = get_metadata_account(mint_key)
    data = base64.b64decode(client.get_account_info(metadata_account)['result']['value']['data'][0])

    metadata = MetadataAccount.parse(data)

    def _strip_utf8(value) -> str:
        return bytes(value).decode("utf-8").strip("\x00")

    object.__setattr__(metadata.data, "name", _strip_utf8(metadata.data.name))
    object.__setattr__(metadata.data, "symbol", _strip_utf8(metadata.data.symbol))
    object.__setattr__(metadata.data, "uri", _strip_utf8(metadata.data.uri))

    if metadata.data.creators:
        creators = [base58.b58encode(creator) for creator in metadata.data.creators]
        object.__setattr__(metadata.data, "creators", creators)

    return metadata
