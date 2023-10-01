import logging
from typing import Optional

from .mempool_api import MPElfParamDictRequest, MPElfParamDictResult
from .mempool_executor_task_base import MPExecutorBaseTask


LOG = logging.getLogger(__name__)


class MPExecutorElfParamsTask(MPExecutorBaseTask):
    def read_elf_param_dict(self, mp_req: MPElfParamDictRequest) -> Optional[MPElfParamDictResult]:
        try:

            last_deployed_slot, elf_param_dict = self._core_api_client.read_elf_params(mp_req.last_deployed_slot)
            return MPElfParamDictResult(last_deployed_slot=last_deployed_slot, elf_param_dict=elf_param_dict)
        except BaseException as exc:
            LOG.error('Failed to read elf params', exc_info=exc)
            return None
