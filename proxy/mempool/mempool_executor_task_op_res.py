from ..common_neon.elf_params import ElfParams
from ..common_neon.operator_secret_mng import OpSecretMng

from .mempool_api import MPOpResGetListResult, MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_executor_task_base import MPExecutorBaseTask
from .operator_resource_mng import OpResInfo, OpResInit, OpResIdentListBuilder


class MPExecutorOpResTask(MPExecutorBaseTask):
    def get_op_res_list(self) -> MPOpResGetListResult:
        try:
            secret_list = OpSecretMng(self._config).read_secret_list()
            res_ident_list = OpResIdentListBuilder(self._config).build_resource_list(secret_list)
            return MPOpResGetListResult(res_ident_list=res_ident_list)
        except BaseException as exc:
            self.error(f'Failed to read secret list', exc_info=exc)
            return MPOpResGetListResult(res_ident_list=[])

    def init_op_res(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        ElfParams().set_elf_param_dict(mp_op_res_req.elf_param_dict)
        resource = OpResInfo.from_ident(mp_op_res_req.res_ident)
        try:
            OpResInit(self._config, self._solana).init_resource(resource)
            return MPOpResInitResult(code=MPOpResInitResultCode.Success)
        except BaseException as exc:
            self.error(f'Failed to init operator resource tx {resource}.', exc_info=exc)
            return MPOpResInitResult(code=MPOpResInitResultCode.Failed)
