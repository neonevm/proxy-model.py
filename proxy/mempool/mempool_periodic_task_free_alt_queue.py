import logging

from typing import List, Type, Callable, Dict, cast

from .executor_mng import MPExecutorMng
from .mempool_api import (
    MPGetALTList, MPDeactivateALTListRequest, MPCloseALTListRequest,
    MPRequest, MPRequestType, MPALTAddress, MPALTInfo, MPALTListResult
)
from .mempool_periodic_task import MPPeriodicTaskLoop
from .sorted_queue import SortedQueue

from ..common_neon.config import Config
from ..common_neon.operator_resource_mng import OpResMng
from ..common_neon.solana_alt import ALTAddress


LOG = logging.getLogger(__name__)


class MPFreeALTQueueTaskLoop(MPPeriodicTaskLoop[MPRequest, MPALTListResult]):
    _default_sleep_sec = 15

    def __init__(self, config: Config, executor_mng: MPExecutorMng, op_res_mng: OpResMng) -> None:
        super().__init__(name='alt', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)
        self._config = config
        self._op_res_mng = op_res_mng
        self._iteration = 0
        self._block_height = 0
        self._deactivate_alt_queue = self._new_queue(lambda a: cast(int, a.last_extended_slot))
        self._close_alt_queue = self._new_queue(lambda a: a.deactivation_slot)
        self._new_alt_address_list: List[MPALTAddress] = list()
        self._alt_address_dict: Dict[str, bytes] = dict()

    def add_alt_address_list(self, alt_address_list: List[ALTAddress], secret: bytes) -> None:
        for alt_address in alt_address_list:
            info = MPALTAddress(alt_address.table_account, secret)
            self._new_alt_address_list.append(info)

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
        secret_list = self._op_res_mng.get_secret_list()
        mp_req = MPGetALTList(
            req_id=self._generate_req_id('get-alt'),
            secret_list=secret_list,
            alt_address_list=[MPALTAddress(key, value) for key, value in self._alt_address_dict.items()]
        )
        self._submit_request_to_executor(mp_req)

    def _submit_free_list_request(self, queue, mp_req_type: Type) -> None:
        block_height = max(self._block_height - self._config.alt_freeing_depth, 0)
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

    async def _process_result(self, mp_req: MPRequest, mp_res: MPALTListResult) -> None:
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
        self._alt_address_dict.clear()

        for alt_info in mp_res.alt_info_list:
            self._alt_address_dict[alt_info.table_account] = alt_info.operator_key
            if alt_info.is_deactivated():
                self._close_alt_queue.add(alt_info)
            else:
                self._deactivate_alt_queue.add(alt_info)

        for alt_address in self._new_alt_address_list:
            self._alt_address_dict[alt_address.table_account] = alt_address.secret

        if (len(self._close_alt_queue) > 0) or (len(self._deactivate_alt_queue) > 0):
            LOG.debug(
                f'deactivate ALT queue: {len(self._deactivate_alt_queue)}, '
                f'close ALT queue: {len(self._close_alt_queue)}'
            )

    @staticmethod
    def _clear_queue(queue, mp_res: MPALTListResult) -> None:
        for alt_info in mp_res.alt_info_list:
            pos = queue.find(alt_info)
            if pos is not None:
                queue.pop_tx(alt_info)

    def _process_deactivate_list_result(self, mp_res: MPALTListResult) -> None:
        self._clear_queue(self._deactivate_alt_queue, mp_res)

    def _process_close_list_result(self, mp_res: MPALTListResult) -> None:
        self._clear_queue(self._close_alt_queue, mp_res)
