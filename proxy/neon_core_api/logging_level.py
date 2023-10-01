
import logging

from singleton_decorator import singleton

from ..common_neon.utils.utils import cached_property


LOG = logging.getLogger(__name__)


@singleton
class NeonCoreApiLoggingLevel:
    _LOG_LEVEL = {
        logging.CRITICAL: 'off',
        logging.ERROR: 'error',
        logging.WARNING: 'warn',
        logging.INFO: 'info',
        logging.DEBUG: 'debug',
        logging.NOTSET: 'warn'
    }

    @cached_property
    def level(self) -> str:
        level = LOG.getEffectiveLevel()
        return self._LOG_LEVEL.get(level, 'warn')
