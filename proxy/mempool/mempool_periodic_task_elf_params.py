from typing import Dict

from ..common_neon.constants import ONE_BLOCK_SEC

from .executor_mng import MPExecutorMng
from .mempool_api import MPElfParamDictRequest
from .mempool_periodic_task import MPPeriodicTaskLoop

from ..common_neon.elf_params import ElfParams


class MPElfParamDictTaskLoop(MPPeriodicTaskLoop[MPElfParamDictRequest, Dict[str, str]]):
    _default_sleep_sec = ONE_BLOCK_SEC * 16

    def __init__(self, executor_mng: MPExecutorMng) -> None:
        super().__init__(name='elf-params', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)

    def _submit_request(self) -> None:
        mp_req = MPElfParamDictRequest(req_id=self._generate_req_id(), elf_param_dict=ElfParams().elf_param_dict)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPElfParamDictRequest) -> None:
        pass

    async def _process_result(self, _: MPElfParamDictRequest, mp_res: Dict[str, str]) -> None:
        ElfParams().set_elf_param_dict(mp_res)
