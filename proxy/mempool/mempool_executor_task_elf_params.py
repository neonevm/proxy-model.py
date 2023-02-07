import logging
from typing import Optional, Dict

from ..common_neon.elf_params import ElfParams

from .mempool_api import MPElfParamDictRequest
from .mempool_executor_task_base import MPExecutorBaseTask


LOG = logging.getLogger(__name__)


class MPExecutorElfParamsTask(MPExecutorBaseTask):
    def read_elf_param_dict(self, mp_req: MPElfParamDictRequest) -> Optional[Dict[str, str]]:
        try:
            elf_params = ElfParams()
            elf_params.set_elf_param_dict(mp_req.elf_param_dict)
            elf_params.read_elf_param_dict_from_net(self._config)
            return elf_params.elf_param_dict
        except BaseException as exc:
            LOG.error('Failed to read elf params', exc_info=exc)
            return None
