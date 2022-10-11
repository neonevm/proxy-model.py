from typing import List, Type, Callable, cast

from ..common_neon.sorted_queue import SortedQueue

from ..mempool.mempool_api import IMPExecutor, MPRequest, MPRequestType, MPALTInfo, MPALTListResult
from ..mempool.mempool_api import MPGetALTList, MPDeactivateALTListRequest, MPCloseALTListRequest
from ..mempool.operator_resource_mng import OpResMng
from ..mempool.mempool_periodic_task import MPPeriodicTaskLoop


class MPFreeALTQueueTaskLoop(MPPeriodicTaskLoop[MPRequest, MPALTListResult]):
    _freeing_depth = 512 + 32

    def __init__(self, executor: IMPExecutor, op_res_mng: OpResMng) -> None:
        super().__init__(name='alt', sleep_time=30, executor=executor)
        self._op_res_mng = op_res_mng
        self._iteration = 0
        self._block_height = 0
        self._deactivate_alt_queue = self._new_queue(lambda a: cast(int, a.last_extended_slot))
        self._close_alt_queue = self._new_queue(lambda a: a.deactivation_slot)

    @staticmethod
    def _new_queue(lt_key_func: Callable[[MPALTInfo], int]) -> SortedQueue[MPALTInfo, int, str]:
        return SortedQueue[MPALTInfo, int, str](lt_key_func=lt_key_func, eq_key_func=lambda a: a.table_account)

    def _submit_request(self) -> None:
        if self._iteration == 0:
            self._submit_get_list_request()
        elif self._iteration == 1:
            self._submit_deactivate_list_request()
        else:
            self._submit_close_list_request()
            self._iteration = -1
        self._iteration += 1

    def _submit_get_list_request(self) -> None:
        op_key_list = self._op_res_mng.get_signer_list()
        mp_req = MPGetALTList(req_id=self._generate_req_id('get-alt'), operator_key_list=op_key_list)
        self._submit_request_to_executor(mp_req)

    def _submit_free_list_request(self, queue, mp_req_type: Type) -> None:
        block_height = max(self._block_height - self._freeing_depth, 0)
        alt_info_list: List[MPALTInfo] = []
        for alt_info in queue:
            if alt_info.block_height > block_height:
                break
            alt_info_list.append(alt_info)

        if len(alt_info_list) == 0:
            return

        mp_req = mp_req_type(req_id=self._generate_req_id('free-alt'),  alt_info_list=alt_info_list)
        self._submit_request_to_executor(mp_req)

    def _submit_deactivate_list_request(self) -> None:
        self._submit_free_list_request(self._deactivate_alt_queue, MPDeactivateALTListRequest)

    def _submit_close_list_request(self) -> None:
        self._submit_free_list_request(self._close_alt_queue, MPCloseALTListRequest)

    def _process_error(self, _: MPALTListResult) -> None:
        pass

    def _process_result(self, mp_req: MPRequest, mp_res: MPALTListResult) -> None:
        self._block_height = mp_res.block_height
        if mp_req.type == MPRequestType.GetALTList:
            self._process_get_list_result(mp_res)
        elif mp_req.type == MPRequestType.DeactivateALTList:
            self._process_deactivate_list_result(mp_res)
        elif mp_req.type == MPRequestType.CloseALTList:
            self._process_close_list_result(mp_res)

    def _process_get_list_result(self, mp_res: MPALTListResult) -> None:
        self._deactivate_alt_queue.clear()
        self._close_alt_queue.clear()
        for alt_info in mp_res.alt_info_list:
            if alt_info.is_deactivated():
                self._close_alt_queue.add(alt_info)
            else:
                self._deactivate_alt_queue.add(alt_info)

        if (len(self._close_alt_queue) > 0) or (len(self._deactivate_alt_queue) > 0):
            self.debug(
                f'deactivate ALT queue: {len(self._deactivate_alt_queue)}, '
                f'close ALT queue: {len(self._close_alt_queue)}'
            )

    @staticmethod
    def _clear_queue(queue, mp_res: MPALTListResult) -> None:
        for alt_info in mp_res.alt_info_list:
            pos = queue.find(alt_info)
            if pos is not None:
                queue.pop(alt_info)

    def _process_deactivate_list_result(self, mp_res: MPALTListResult) -> None:
        self._clear_queue(self._deactivate_alt_queue, mp_res)

    def _process_close_list_result(self, mp_res: MPALTListResult) -> None:
        self._clear_queue(self._close_alt_queue, mp_res)
