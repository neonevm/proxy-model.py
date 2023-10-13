from ..common_neon.evm_config import EVMConfig

from .executor_mng import MPExecutorMng
from .mempool_api import MPOpResGetListRequest, MPOpResGetListResult
from .mempool_periodic_task import MPPeriodicTaskLoop
from .operator_resource_mng import OpResMng


class MPOpResGetListTaskLoop(MPPeriodicTaskLoop[MPOpResGetListRequest, MPOpResGetListResult]):
    _normal_recheck_sleep_sec = 5 * 60
    _bad_recheck_sleep_sec = 1

    def __init__(self, executor_mng: MPExecutorMng, op_res_mng: OpResMng) -> None:
        super().__init__(name='op-res-get-list', sleep_sec=self._bad_recheck_sleep_sec, executor_mng=executor_mng)
        self._op_res_mng = op_res_mng

    def _submit_request(self) -> None:
        evm_config = EVMConfig()
        if not evm_config.has_config():
            self._sleep_sec = self._bad_recheck_sleep_sec
            return

        mp_req = MPOpResGetListRequest(req_id=self._generate_req_id(), evm_config_data=evm_config.evm_config_data)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, mp_req: MPOpResGetListRequest) -> None:
        self._sleep_sec = self._bad_recheck_sleep_sec

    async def _process_result(self, mp_req: MPOpResGetListRequest, mp_res: MPOpResGetListResult) -> None:
        self._op_res_mng.init_resource_list(mp_res.res_info_list)
        if len(mp_res.res_info_list) == 0:
            self._sleep_sec = self._bad_recheck_sleep_sec
        else:
            self._sleep_sec = self._normal_recheck_sleep_sec

            # let's think that an executor can process a tx for 2 blocks
            limit = max(int(self._op_res_mng.resource_cnt / 2), 1)
            await self._executor_mng.set_executor_cnt(limit)
