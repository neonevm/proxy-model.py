import logging
from typing import List

from .mempool_api import MPOpResGetListResult, MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_executor_task_base import MPExecutorBaseTask
from .operator_resource_mng import OpResInfo, OpResInit, OpResIdentListBuilder

from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.operator_secret_mng import OpSecretMng
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.errors import RescheduleError

from ..statistic.data import NeonOpResListData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


class MPExecutorOpResTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor, stat_client: ProxyStatClient):
        super().__init__(config, solana)
        self._stat_client = stat_client

    def get_op_res_list(self) -> MPOpResGetListResult:
        try:
            secret_list = OpSecretMng(self._config).read_secret_list()
            res_ident_list = OpResIdentListBuilder(self._config).build_resource_list(secret_list)

            sol_account_list: List[str] = []
            neon_account_list: List[str] = []

            for res_ident in res_ident_list:
                op_info = OpResInfo.from_ident(res_ident)
                sol_account_list.append(str(op_info.public_key))
                neon_account_list.append(str(op_info.neon_address))

            stat = NeonOpResListData(
                sol_account_list=sol_account_list,
                neon_account_list=neon_account_list
            )
            self._stat_client.commit_op_res_list(stat)

            return MPOpResGetListResult(res_ident_list=res_ident_list)

        except BaseException as exc:
            LOG.error(f'Failed to read secret list', exc_info=exc)
            return MPOpResGetListResult(res_ident_list=[])

    def init_op_res(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        ElfParams().set_elf_param_dict(mp_op_res_req.elf_param_dict)
        resource = OpResInfo.from_ident(mp_op_res_req.res_ident)
        try:
            OpResInit(self._config, self._solana).init_resource(resource)
            return MPOpResInitResult(MPOpResInitResultCode.Success)

        except RescheduleError as exc:
            LOG.debug(f'Rescheduling init of operator resource {resource}: {str(exc)}')
            return MPOpResInitResult(MPOpResInitResultCode.Reschedule)

        except BaseException as exc:
            LOG.error(f'Failed to init operator resource tx {resource}', exc_info=exc)
            return MPOpResInitResult(MPOpResInitResultCode.Failed)
