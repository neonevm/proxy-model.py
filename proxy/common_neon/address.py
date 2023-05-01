from __future__ import annotations

import math
import random

from typing import Tuple, Union

from sha3 import keccak_256

from eth_keys import keys as neon_keys

from ..common_neon.solana_tx import SolPubKey
from ..common_neon.constants import ACCOUNT_SEED_VERSION
from ..common_neon.environment_data import EVM_LOADER_ID


class NeonAddress:
    def __init__(self, data: Union[str, bytes], private: neon_keys.PrivateKey = None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random() -> NeonAddress:
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for _ in range(64)]))
        pk = neon_keys.PrivateKey(data)
        return NeonAddress(pk.public_key.to_canonical_address(), pk)

    @staticmethod
    def from_private_key(pk_data: bytes) -> NeonAddress:
        pk = neon_keys.PrivateKey(pk_data[:32])
        return NeonAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x' + self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self):
        return self.data

    def __hash__(self):
        return hash(self.data)

    def __eq__(self, other):
        return self.data == other.data

    def __ne__(self, other):
        return self.data != other.data


def account_with_seed(base_address: SolPubKey, seed: bytes) -> SolPubKey:
    seed_str = str(seed, 'utf8')
    result = SolPubKey.create_with_seed(base_address, seed_str, SolPubKey.from_string(EVM_LOADER_ID))
    return result


def perm_account_seed(prefix: bytes, resource_id: int) -> bytes:
    aid = resource_id.to_bytes(math.ceil(resource_id.bit_length() / 8), 'big')
    seed_base = prefix + aid
    seed = keccak_256(seed_base).hexdigest()[:32]
    return bytes(seed, 'utf8')


def neon_2program(neon: Union[NeonAddress, str, bytes]) -> Tuple[SolPubKey, int]:
    if isinstance(neon, NeonAddress):
        neon = bytes(neon)
    elif isinstance(neon, str):
        if neon[0:2] == '0x':
            neon = neon[2:]
        neon = bytes.fromhex(neon)

    seed = [ACCOUNT_SEED_VERSION, neon]
    (pda, nonce) = SolPubKey.find_program_address(seed, SolPubKey.from_string(EVM_LOADER_ID))
    return pda, nonce
