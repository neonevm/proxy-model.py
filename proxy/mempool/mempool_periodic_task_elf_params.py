from typing import Dict

from ..common_neon.elf_params import ElfParams

from .mempool_api import IMPExecutor, MPElfParamDictRequest
from .mempool_periodic_task import MPPeriodicTaskLoop


class MPElfParamDictTaskLoop(MPPeriodicTaskLoop[MPElfParamDictRequest, Dict[str, str]]):
    def __init__(self, executor: IMPExecutor) -> None:
        super().__init__(name='elf-params', sleep_time=4.0, executor=executor)

    def _submit_request(self) -> None:
        mp_req = MPElfParamDictRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPElfParamDictRequest) -> None:
        pass

    def _process_result(self, _: MPElfParamDictRequest, mp_res: Dict[str, str]) -> None:
        ElfParams().set_elf_param_dict(mp_res)
