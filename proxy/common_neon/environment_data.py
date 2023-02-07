import os

EVM_LOADER_ID = os.environ.get("EVM_LOADER")
LOG_FULL_OBJECT_INFO = os.environ.get("LOG_FULL_OBJECT_INFO", "NO") == "YES"
