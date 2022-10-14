from solana.system_program import SYS_PROGRAM_ID as _SYS_PROGRAM_ID

from ..common_neon.solana_transaction import SolPubKey

KECCAK_PROGRAM_ID = SolPubKey("KeccakSecp256k11111111111111111111111111111")
INCINERATOR_ID = SolPubKey("1nc1nerator11111111111111111111111111111111")
SYSVAR_INSTRUCTION_ID = SolPubKey("Sysvar1nstructions1111111111111111111111111")
COMPUTE_BUDGET_ID = SolPubKey("ComputeBudget111111111111111111111111111111")
ADDRESS_LOOKUP_TABLE_ID = SolPubKey('AddressLookupTab1e1111111111111111111111111')
SYS_PROGRAM_ID = _SYS_PROGRAM_ID

ACCOUNT_SEED_VERSION = b'\2'

EMPTY_HOLDER_TAG = 0         # TAG_EMPTY
NEON_ACCOUNT_TAG = 11        # TAG_ACCOUNT_V3
ACTIVE_HOLDER_TAG = 22       # TAG_STATE
FINALIZED_HOLDER_TAG = 31    # TAG_FINALIZED_STATE
HOLDER_TAG = 51              # TAG_HOLDER

LOOKUP_ACCOUNT_TAG = 1
