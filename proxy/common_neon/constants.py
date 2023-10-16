import os

from solders.system_program import ID as _SYS_PROGRAM_ID

from .solana_tx import SolPubKey


ONE_BLOCK_SEC = 0.4
MIN_FINALIZE_SEC = ONE_BLOCK_SEC * 32

COMPUTE_BUDGET_ID = SolPubKey.from_string('ComputeBudget111111111111111111111111111111')
ADDRESS_LOOKUP_TABLE_ID = SolPubKey.from_string('AddressLookupTab1e1111111111111111111111111')
METAPLEX_PROGRAM_ID = SolPubKey.from_string('p1exdMJcjVao65QdewkaZRUnU6VPSXhus9n2GzWfh98')
TOKEN_PROGRAM_ID = SolPubKey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')

EVM_PROGRAM_ID_STR = os.environ.get('EVM_LOADER')
EVM_PROGRAM_ID = SolPubKey.from_string(EVM_PROGRAM_ID_STR)

SYS_PROGRAM_ID = _SYS_PROGRAM_ID

ACCOUNT_SEED_VERSION = b'\3'

LOOKUP_ACCOUNT_TAG = 1
