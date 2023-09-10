from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor


class MPExecutorBaseTask:
    def __init__(self, config: Config):
        self._config = config
        self._solana = SolInteractor(config)
