import os

from proxy.common_neon.config import Config


class FuzzConfig(Config):
    def get_perm_account_start(self) -> int:
        return os.getpid()

    def get_perm_account_limit(self) -> int:
        return 1
