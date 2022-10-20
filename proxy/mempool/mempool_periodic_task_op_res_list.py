from .executor_mng import MPExecutorMng
from .mempool_api import MPOpResGetListRequest, MPOpResGetListResult
from .mempool_periodic_task import MPPeriodicTaskLoop
from .operator_resource_mng import OpResMng


class MPOpResGetListTaskLoop(MPPeriodicTaskLoop[MPOpResGetListRequest, MPOpResGetListResult]):
    _normal_recheck_sleep_time = 5 * 60
    _bad_recheck_sleep_time = 1

    def __init__(self, executor_mng: MPExecutorMng, op_res_mng: OpResMng) -> None:
        super().__init__(name='op-res-get-list', sleep_time=self._bad_recheck_sleep_time, executor_mng=executor_mng)
        self._op_res_mng = op_res_mng

    def _submit_request(self) -> None:
        mp_req = MPOpResGetListRequest(req_id=self._generate_req_id())
        self._submit_request_to_executor(mp_req)

    def _process_error(self, mp_req: MPOpResGetListRequest) -> None:
        self._sleep_time = self._bad_recheck_sleep_time

    async def _process_result(self, mp_req: MPOpResGetListRequest, mp_res: MPOpResGetListResult) -> None:
        self._op_res_mng.init_resource_list(mp_res.res_ident_list)
        if len(mp_res.res_ident_list) == 0:
            self._sleep_time = self._bad_recheck_sleep_time
        else:
            self._sleep_time = self._normal_recheck_sleep_time
            await self._executor_mng.set_executor_cnt(self._op_res_mng.resource_cnt)
