import os

SOLANA_URL = os.environ.get("SOLANA_URL", "http://localhost:8899")

EVM_LOADER_ID = os.environ.get("EVM_LOADER")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "2.5"))

LOG_NEON_CLI_DEBUG = os.environ.get("LOG_NEON_CLI_DEBUG", "NO") == "YES"
RETRY_ON_FAIL = int(os.environ.get("RETRY_ON_FAIL", "10"))
CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", 60))
SKIP_CANCEL_TIMEOUT = int(os.environ.get("SKIP_CANCEL_TIMEOUT", 1000))
HOLDER_TIMEOUT = int(os.environ.get("HOLDER_TIMEOUT", "216000"))  # 1 day by default

INDEXER_LOG_SKIP_COUNT = int(os.environ.get("INDEXER_LOG_SKIP_COUNT", 1000))
MAX_EVM_STEPS_TO_EXECUTE = int(os.environ.get("MAX_EVM_STEPS_TO_EXECUTE", 500000))
GATHER_STATISTICS = os.environ.get("GATHER_STATISTICS", "NO") == "YES"
LOG_FULL_OBJECT_INFO = os.environ.get("LOG_FULL_OBJECT_INFO", "NO") == "YES"
