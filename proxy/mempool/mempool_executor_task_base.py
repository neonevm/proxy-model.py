import logging

from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor


LOG = logging.getLogger(__name__)


class MPExecutorBaseTask:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana
