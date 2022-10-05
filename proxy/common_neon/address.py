from __future__ import annotations

import random
import sha3
import math

from typing import Tuple

from eth_keys import keys as eth_keys
from hashlib import sha256

from .solana_transaction import SolPubKey
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.constants import ACCOUNT_SEED_VERSION


class EthereumAddress:
    def __init__(self, data, private: eth_keys.PrivateKey = None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random() -> EthereumAddress:
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for _ in range(64)]))
        pk = eth_keys.PrivateKey(data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    @staticmethod
    def from_private_key(pk_data: bytes) -> EthereumAddress:
        pk = eth_keys.PrivateKey(pk_data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x'+self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self): return self.data


def accountWithSeed(base_address: SolPubKey, seed: bytes) -> SolPubKey:
    result = SolPubKey(sha256(bytes(base_address) + bytes(seed) + bytes(SolPubKey(EVM_LOADER_ID))).digest())
    return result


def permAccountSeed(prefix: bytes, resource_id: int) -> bytes:
    aid = resource_id.to_bytes(math.ceil(resource_id.bit_length() / 8), 'big')
    seed_base = prefix + aid
    seed = sha3.keccak_256(seed_base).hexdigest()[:32]
    return bytes(seed, 'utf8')


def ether2program(ether) -> Tuple[SolPubKey, int]:
    if isinstance(ether, EthereumAddress):
        ether = bytes(ether)
    elif isinstance(ether, str):
        if ether[0:2] == '0x':
            ether = ether[2:]
        ether = bytes.fromhex(ether)

    seed = [ACCOUNT_SEED_VERSION, ether]
    (pda, nonce) = SolPubKey.find_program_address(seed, SolPubKey(EVM_LOADER_ID))
    return pda, nonce
