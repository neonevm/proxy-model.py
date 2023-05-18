from .executor_mng import MPExecutorMng
from .mempool_api import MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_periodic_task import MPPeriodicTaskLoop
from .operator_resource_mng import OpResMng

from ..common_neon.elf_params import ElfParams


class MPInitOpResTaskLoop(MPPeriodicTaskLoop[MPOpResInitRequest, MPOpResInitResult]):
    _default_sleep_sec = MPPeriodicTaskLoop._one_block_sec * 16

    def __init__(self, executor_mng: MPExecutorMng, op_res_mng: OpResMng) -> None:
        super().__init__(name='op-res-init', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)
        self._op_res_mng = op_res_mng

    def _submit_request(self) -> None:
        elf_params = ElfParams()
        if not elf_params.has_params():
            return

        resource = self._op_res_mng.get_disabled_resource()
        if resource is None:
            self._sleep_sec = self._default_sleep_sec
            return
        else:
            self._sleep_sec = self._check_sleep_sec
        mp_req = MPOpResInitRequest(
            req_id=self._generate_req_id(),
            elf_param_dict=elf_params.elf_param_dict,
            res_ident=resource
        )
        self._submit_request_to_executor(mp_req)

    def _process_error(self, mp_req: MPOpResInitRequest) -> None:
        self._op_res_mng.disable_resource(mp_req.res_ident)

    async def _process_result(self, mp_req: MPOpResInitRequest, mp_res: MPOpResInitResult) -> None:
        if mp_res.code == MPOpResInitResultCode.Success:
            self._op_res_mng.enable_resource(mp_req.res_ident)
        else:
            self._op_res_mng.disable_resource(mp_req.res_ident)
