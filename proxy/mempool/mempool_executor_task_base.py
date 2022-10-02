from logged_groups import logged_group

from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.errors import log_error


@logged_group("neon.MemPool")
class MPExecutorBaseTask:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana

    def _on_exception(self, text: str, err: BaseException) -> None:
        log_error(self, text, err)
