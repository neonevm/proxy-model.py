import logging
from hashlib import sha256
from typing import NamedTuple
from solana.publickey import PublicKey
from eth_keys import keys as eth_keys
from construct import Bytes, Int8ul
from construct import Struct as cStruct
from spl.token.instructions import get_associated_token_address

from proxy.environment import ETH_TOKEN_MINT_ID
from proxy.environment import neon_cli


ACCOUNT_SEED_VERSION=b'\1'


ACCOUNT_INFO_LAYOUT = cStruct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "code_account" / Bytes(32),
    "is_rw_blocked" / Int8ul,
    "rw_blocked_acc" / Bytes(32),
    "eth_token_account" / Bytes(32),
    "ro_blocked_cnt" / Int8ul,
)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def accountWithSeed(base, seed, program):
    # logger.debug(type(base), str(base), type(seed), str(seed), type(program), str(program))
    result = PublicKey(sha256(bytes(base) + bytes(seed) + bytes(program)).digest())
    logger.debug('accountWithSeed %s', str(result))
    return result


def ether2program(ether, program_id, base):
    if isinstance(ether, str):
        if ether.startswith('0x'):
            ether = ether[2:]
    else:
        ether = ether.hex()
    output = neon_cli().call("create-program-address", ether)
    items = output.rstrip().split(' ')
    return (items[0], int(items[1]))


def getTokenAddr(account):
    return get_associated_token_address(PublicKey(account), ETH_TOKEN_MINT_ID)


class AccountInfo(NamedTuple):
    ether: eth_keys.PublicKey
    trx_count: int
    code_account: PublicKey

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.ether, cont.trx_count, PublicKey(cont.code_account))
