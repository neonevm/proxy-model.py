from __future__ import annotations

import math
import random

from typing import Union, Optional

from eth_keys import keys as neon_keys
from eth_keys.datatypes import to_checksum_address
from sha3 import keccak_256

from .utils.utils import cached_method, cached_property
from .constants import EVM_PROGRAM_ID
from .solana_tx import SolPubKey


class NeonAddress:
    def __init__(self, data: Union[str, bytes, neon_keys.PrivateKey], chain_id: Optional[int]):
        private_key = None

        if isinstance(data, neon_keys.PrivateKey):
            private_key = data.to_bytes()
            address = data.public_key.to_canonical_address()
        elif isinstance(data, str):
            address = bytes.fromhex(data[2:])
        else:
            assert isinstance(data, bytes)
            address = data

        self._chain_id = chain_id or 0
        self._address = address
        self._private_key = private_key

    @staticmethod
    def from_raw(data: InNeonAddress, chain_id: Optional[int] = None) -> Optional[NeonAddress]:
        if not data:
            return None
        elif isinstance(data, NeonAddress):
            if chain_id is None or data.chain_id == chain_id:
                return data
            else:
                NeonAddress(data.private_key, chain_id)
        return NeonAddress(data, chain_id)

    @staticmethod
    def random() -> NeonAddress:
        data = bytearray([random.randint(0, 255) for _ in range(32)])
        private_key = neon_keys.PrivateKey(bytes(data))
        return NeonAddress(private_key, None)

    @staticmethod
    def from_private_key(pk_data: bytes, chain_id: Optional[int] = None) -> NeonAddress:
        private_key = neon_keys.PrivateKey(pk_data[:32])
        return NeonAddress(private_key, chain_id)

    @property
    def chain_id(self) -> int:
        return self._chain_id

    def to_bytes(self) -> bytes:
        return self._address

    @cached_property
    def address(self) -> str:
        return '0x' + self._address.hex()

    @cached_property
    def checksum_address(self) -> str:
        return to_checksum_address(self._address)

    @cached_property
    def private_key(self) -> neon_keys.PrivateKey:
        assert self._private_key is not None
        return neon_keys.PrivateKey(self._private_key)

    def __str__(self) -> str:
        return self.address

    def __repr__(self):
        return self.__str__()

    def __bytes__(self) -> bytes:
        return self._address

    @cached_method
    def __hash__(self):
        return hash(self._address)

    def __eq__(self, other):
        return isinstance(other, NeonAddress) and self._address == other._address


InNeonAddress = Union[None, str, bytes, neon_keys.PublicKey, neon_keys.PrivateKey, NeonAddress]


def neon_account_with_seed(base_address: SolPubKey, seed: bytes) -> SolPubKey:
    seed_str = str(seed, 'utf8')
    result = SolPubKey.create_with_seed(base_address, seed_str, EVM_PROGRAM_ID)
    return result


def perm_account_seed(prefix: bytes, resource_id: int) -> bytes:
    aid = resource_id.to_bytes(math.ceil(resource_id.bit_length() / 8), 'big')
    seed_base = prefix + aid
    seed = keccak_256(seed_base).hexdigest()[:32]
    return bytes(seed, 'utf8')
