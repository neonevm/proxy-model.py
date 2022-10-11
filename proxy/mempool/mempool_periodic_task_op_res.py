from typing import List

from ..common_neon.elf_params import ElfParams

from .mempool_api import IMPExecutor, MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_periodic_task import MPPeriodicTaskLoop
from .operator_resource_mng import OpResMng


class MPInitOpResTaskLoop(MPPeriodicTaskLoop[MPOpResInitRequest, MPOpResInitResult]):
    _default_sleep_time = 4.0

    def __init__(self, executor: IMPExecutor, op_res_mng: OpResMng) -> None:
        super().__init__(name='op-res-init', sleep_time=self._check_sleep_time, executor=executor)
        self._op_res_mng = op_res_mng
        self._disabled_resource_list: List[str] = []

    def _submit_request(self) -> None:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return

        if len(self._disabled_resource_list) == 0:
            self._disabled_resource_list = self._op_res_mng.get_disabled_resource_list()
        if len(self._disabled_resource_list) == 0:
            return

        resource = self._disabled_resource_list.pop()
        if len(self._disabled_resource_list) == 0:
            self._sleep_time = self._default_sleep_time
        else:
            self._sleep_time = self._check_sleep_time
        mp_req = MPOpResInitRequest(
            req_id=self._generate_req_id(),
            elf_param_dict=elf_params.elf_param_dict,
            resource_ident=resource
        )
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPOpResInitRequest) -> None:
        pass

    def _process_result(self, mp_req: MPOpResInitRequest, mp_res: MPOpResInitResult) -> None:
        if mp_res.code == MPOpResInitResultCode.Success:
            self._op_res_mng.enable_resource(mp_req.resource_ident)
