from ..common_neon.elf_params import ElfParams

from ..mempool.mempool_api import MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask
from ..mempool.operator_resource_mng import OpResInfo, OpResInit


class MPExecutorOpResTask(MPExecutorBaseTask):
    def init_op_res(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        ElfParams().set_elf_param_dict(mp_op_res_req.elf_param_dict)
        resource = OpResInfo.from_ident(mp_op_res_req.resource_ident)
        try:
            OpResInit(self._config, self._solana).init_resource(resource)
            return MPOpResInitResult(code=MPOpResInitResultCode.Success)
        except BaseException as exc:
            self.error(f'Failed to init operator resource tx {resource}.', exc_info=exc)
            return MPOpResInitResult(code=MPOpResInitResultCode.Failed)
