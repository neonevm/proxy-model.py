import os

SOLANA_URL = os.environ.get("SOLANA_URL", "http://localhost:8899")

EVM_LOADER_ID = os.environ.get("EVM_LOADER")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "2.5"))
CONFIRMATION_CHECK_DELAY = float(os.environ.get("NEON_CONFIRMATION_CHECK_DELAY", "0.1"))
TIMEOUT_TO_RELOAD_NEON_CONFIG = int(os.environ.get("TIMEOUT_TO_RELOAD_NEON_CONFIG", "3600"))


LOG_NEON_CLI_DEBUG = os.environ.get("LOG_NEON_CLI_DEBUG", "NO") == "YES"
RETRY_ON_FAIL = int(os.environ.get("RETRY_ON_FAIL", "10"))
RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION = max(int(os.environ.get("RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION", "1000")), 1)
FUZZING_BLOCKHASH = os.environ.get("FUZZING_BLOCKHASH", "NO") == "YES"
CONFIRM_TIMEOUT = max(int(os.environ.get("CONFIRM_TIMEOUT", 10)), 10)
CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", 60))
SKIP_CANCEL_TIMEOUT = int(os.environ.get("SKIP_CANCEL_TIMEOUT", 1000))
HOLDER_TIMEOUT = int(os.environ.get("HOLDER_TIMEOUT", "216000"))  # 1 day by default


INDEXER_LOG_SKIP_COUNT = int(os.environ.get("INDEXER_LOG_SKIP_COUNT", 1000))
SKIP_PREFLIGHT = os.environ.get("SKIP_PREFLIGHT", "NO") == "YES"
MAX_EVM_STEPS_TO_EXECUTE = int(os.environ.get("MAX_EVM_STEPS_TO_EXECUTE", 500000))
GATHER_STATISTICS = os.environ.get("GATHER_STATISTICS", "NO") == "YES"
LOG_FULL_OBJECT_INFO = os.environ.get("LOG_FULL_OBJECT_INFO", "NO") == "YES"
