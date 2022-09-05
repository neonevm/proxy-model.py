import os
from decimal import Decimal
from solana.publickey import PublicKey

SOLANA_URL = os.environ.get("SOLANA_URL", "http://localhost:8899")
PP_SOLANA_URL = os.environ.get("PP_SOLANA_URL", SOLANA_URL)
EVM_LOADER_ID = os.environ.get("EVM_LOADER")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "0.5"))
CONFIRMATION_CHECK_DELAY = float(os.environ.get("NEON_CONFIRMATION_CHECK_DELAY", "0.1"))
CONTINUE_COUNT_FACTOR = int(os.environ.get("CONTINUE_COUNT_FACTOR", "3"))
TIMEOUT_TO_RELOAD_NEON_CONFIG = int(os.environ.get("TIMEOUT_TO_RELOAD_NEON_CONFIG", "3600"))

MEMPOOL_CAPACITY = int(os.environ.get("MEMPOOL_CAPACITY", 4096))
MINIMAL_GAS_PRICE = os.environ.get("MINIMAL_GAS_PRICE", None)
if MINIMAL_GAS_PRICE is not None:
    MINIMAL_GAS_PRICE = int(MINIMAL_GAS_PRICE)*10**9
EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
LOG_NEON_CLI_DEBUG = os.environ.get("LOG_NEON_CLI_DEBUG", "NO") == "YES"
USE_EARLIEST_BLOCK_IF_0_PASSED = os.environ.get("USE_EARLIEST_BLOCK_IF_0_PASSED", "NO") == "YES"
RETRY_ON_FAIL = int(os.environ.get("RETRY_ON_FAIL", "10"))
RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION = max(int(os.environ.get("RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION", "1000")), 1)
FUZZING_BLOCKHASH = os.environ.get("FUZZING_BLOCKHASH", "NO") == "YES"
CONFIRM_TIMEOUT = max(int(os.environ.get("CONFIRM_TIMEOUT", 10)), 10)
INDEXER_PARALLEL_REQUEST_COUNT = int(os.environ.get("INDEXER_PARALLEL_REQUEST_COUNT", 10))
INDEXER_POLL_COUNT = int(os.environ.get("INDEXER_POLL_COUNT", 1000))
START_SLOT = os.environ.get('START_SLOT', 0)
INDEXER_RECEIPTS_COUNT_LIMIT = int(os.environ.get("INDEXER_RECEIPTS_COUNT_LIMIT", "1000"))
FINALIZED = os.environ.get('FINALIZED', 'finalized')
CONFIRMED = os.environ.get('CONFIRMED', 'confirmed')
CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", 60))
SKIP_CANCEL_TIMEOUT = int(os.environ.get("SKIP_CANCEL_TIMEOUT", 1000))
HOLDER_TIMEOUT = int(os.environ.get("HOLDER_TIMEOUT", "216000"))  # 1 day by default
HOLDER_SIZE = int(os.environ.get("HOLDER_SIZE", "131072")) # 128*1024
ACCOUNT_PERMISSION_UPDATE_INT = int(os.environ.get("ACCOUNT_PERMISSION_UPDATE_INT", 60 * 5))
PERM_ACCOUNT_LIMIT = max(int(os.environ.get("PERM_ACCOUNT_LIMIT", 2)), 2)
OPERATOR_FEE = Decimal(os.environ.get("OPERATOR_FEE", "0.1"))
GAS_PRICE_SUGGESTED_PCT = Decimal(os.environ.get("GAS_PRICE_SUGGEST_PCT", "0.01"))
NEON_PRICE_USD = Decimal('0.25')
INDEXER_LOG_SKIP_COUNT = int(os.environ.get("INDEXER_LOG_SKIP_COUNT", 1000))
RECHECK_RESOURCE_LIST_INTERVAL = int(os.environ.get('RECHECK_RESOURCE_LIST_INTERVAL', 60))
MIN_OPERATOR_BALANCE_TO_WARN = max(int(os.environ.get("MIN_OPERATOR_BALANCE_TO_WARN", 9000000000)), 9000000000)
MIN_OPERATOR_BALANCE_TO_ERR = max(int(os.environ.get("MIN_OPERATOR_BALANCE_TO_ERR", 1000000000)), 1000000000)
SKIP_PREFLIGHT = os.environ.get("SKIP_PREFLIGHT", "NO") == "YES"
CONTRACT_EXTRA_SPACE = int(os.environ.get("CONTRACT_EXTRA_SPACE", 2048))
EVM_STEP_COUNT = int(os.environ.get("EVM_STEP_COUNT", 750))  # number of evm-steps, performed by one iteration
MAX_EVM_STEPS_TO_EXECUTE = int(os.environ.get("MAX_EVM_STEPS_TO_EXECUTE", 500000))
ENABLE_PRIVATE_API = os.environ.get("ENABLE_PRIVATE_API", "NO") == "YES"
GATHER_STATISTICS = os.environ.get("GATHER_STATISTICS", "NO") == "YES"
ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID = os.environ.get("ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID", "NO") == "YES"
LOG_FULL_OBJECT_INFO = os.environ.get("LOG_FULL_OBJECT_INFO", "NO") == "YES"
PYTH_MAPPING_ACCOUNT = os.environ.get("PYTH_MAPPING_ACCOUNT", None)
if PYTH_MAPPING_ACCOUNT is not None:
    PYTH_MAPPING_ACCOUNT = PublicKey(PYTH_MAPPING_ACCOUNT)
