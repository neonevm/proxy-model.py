from __future__ import annotations

import dataclasses
import logging
import math

from collections import deque
from datetime import datetime
from typing import Optional, List, Dict, Deque, Set

from ..common_neon.config import Config
from ..common_neon.operator_resource_info import OpResInfo

from ..statistic.data import NeonOpResStatData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class OpResUsedTime:
    res_info: OpResInfo

    last_used_time: int = 0
    used_cnt: int = 0
    neon_sig: str = ''

    def __str__(self) -> str:
        return str(self.res_info)

    def __hash__(self) -> int:
        return hash(self.res_info)

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, OpResUsedTime) and
            other.res_info == self.res_info
        )

    def set_last_used_time(self, value: int) -> None:
        object.__setattr__(self, 'used_cnt', self.used_cnt + 1)
        object.__setattr__(self, 'last_used_time', value)

    def set_neon_sig(self, value: str) -> None:
        assert len(value) > 0
        object.__setattr__(self, 'neon_sig', value)

    def reset_neon_sig(self) -> None:
        object.__setattr__(self, 'neon_sig', '')


class OpResMng:
    def __init__(self, config: Config, stat_client: ProxyStatClient):
        self._secret_list: List[bytes] = []
        self._res_info_set: Set[OpResInfo] = set()
        self._free_res_info_list: Deque[OpResUsedTime] = deque()
        self._used_res_info_dict: Dict[str, OpResUsedTime] = dict()
        self._disabled_res_info_list: Deque[OpResInfo] = deque()
        self._checked_res_info_set: Set[OpResInfo] = set()
        self._stat_client = stat_client
        self._config = config
        self._last_check_time = 0

    def init_resource_list(self, res_info_list: List[OpResInfo]) -> None:
        old_res_cnt = self.resource_cnt

        new_info_set: Set[OpResInfo] = set(res_info_list)
        rm_info_set: Set[OpResInfo] = self._res_info_set.difference(new_info_set)
        add_info_set: Set[OpResInfo] = new_info_set.difference(self._res_info_set)

        if (len(rm_info_set) == 0) and (len(add_info_set) == 0):
            LOG.debug(f'Same resource list')
            return

        self._free_res_info_list = deque([res for res in self._free_res_info_list if res.res_info not in rm_info_set])
        self._disabled_res_info_list = deque([res for res in self._disabled_res_info_list if res not in rm_info_set])
        self._checked_res_info_set = {res for res in self._checked_res_info_set if res not in rm_info_set}

        for res_info in rm_info_set:
            LOG.debug(f'Remove resource {res_info}')
            self._res_info_set.discard(res_info)
        for res_info in add_info_set:
            LOG.debug(f'Add resource {res_info}')
            self._disabled_res_info_list.append(res_info)
            self._res_info_set.add(res_info)

        self._secret_list: List[bytes] = [pk for pk in {res.private_key for res in self._res_info_set}]

        if old_res_cnt != self.resource_cnt != 0:
            LOG.debug(f'Change number of resources from {old_res_cnt} to {self.resource_cnt}')
        self._commit_stat()

    @property
    def resource_cnt(self) -> int:
        return len(self._res_info_set)

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _get_resource_impl(self, neon_sig: str) -> Optional[OpResUsedTime]:
        res_used_time = self._used_res_info_dict.get(neon_sig, None)
        if res_used_time is not None:
            LOG.debug(f'Reuse resource {res_used_time} for tx {neon_sig}')
            return res_used_time

        if len(self._free_res_info_list) > 0:
            res_used_time = self._free_res_info_list.popleft()
            self._used_res_info_dict[neon_sig] = res_used_time
            res_used_time.set_neon_sig(neon_sig)
            LOG.debug(f'Use resource {res_used_time} for tx {neon_sig}')
            self._commit_stat()
            return res_used_time

        return None

    def _pop_used_resource(self, neon_sig: str) -> Optional[OpResUsedTime]:
        res_used_time = self._used_res_info_dict.pop(neon_sig, None)
        if (res_used_time is None) or (res_used_time.res_info not in self._res_info_set):
            LOG.debug(f'Skip resource {str(res_used_time)} for tx {neon_sig}')
            return None

        self._commit_stat()

        res_used_time.reset_neon_sig()
        return res_used_time

    def get_resource(self, neon_sig: str) -> Optional[OpResInfo]:
        res_used_time = self._get_resource_impl(neon_sig)
        if res_used_time is None:
            return None

        now = self._get_current_time()
        res_used_time.set_last_used_time(now)

        return res_used_time.res_info

    def update_resource(self, neon_sig: str) -> None:
        res_used_time = self._used_res_info_dict.get(neon_sig, None)
        if res_used_time is not None:
            LOG.debug(f'Update time for resource {res_used_time}')
            now = self._get_current_time()
            res_used_time.set_last_used_time(now)

    def release_resource(self, neon_sig: str) -> Optional[OpResInfo]:
        res_used_time = self._pop_used_resource(neon_sig)
        if res_used_time is None:
            return None

        recheck_cnt = self._config.recheck_resource_after_uses_cnt
        if res_used_time.used_cnt > recheck_cnt:
            LOG.debug(f'Recheck resource {res_used_time} by counter')
            self._disabled_res_info_list.append(res_used_time.res_info)
        else:
            LOG.debug(f'Release resource {res_used_time}')
            self._free_res_info_list.append(res_used_time)
        self._commit_stat()

        return res_used_time.res_info

    def disable_resource(self, res_info: OpResInfo) -> None:
        LOG.debug(f'Disable resource {res_info}')
        self._checked_res_info_set.discard(res_info)
        self._disabled_res_info_list.append(res_info)
        self._commit_stat()

    def enable_resource(self, res_info: OpResInfo) -> None:
        if res_info not in self._res_info_set:
            LOG.debug(f'Skip resource {res_info}')
            return

        LOG.debug(f'Enable resource {res_info}')
        self._checked_res_info_set.discard(res_info)
        self._free_res_info_list.append(OpResUsedTime(res_info=res_info))
        self._commit_stat()

    def get_secret_list(self) -> List[bytes]:
        return self._secret_list

    def _check_used_resource_list(self) -> None:
        now = self._get_current_time()
        recheck_sec = self._config.recheck_used_resource_sec
        check_time = now - recheck_sec

        if self._last_check_time > check_time:
            return

        self._last_check_time = now
        for neon_sig, res_used_time in list(self._used_res_info_dict.items()):
            if res_used_time.last_used_time > check_time:
                continue

            res_used_time = self._pop_used_resource(neon_sig)
            if res_used_time is None:
                continue

            LOG.debug(f'Recheck resource {res_used_time} by time usage')
            self._disabled_res_info_list.append(res_used_time.res_info)

    def get_disabled_resource(self) -> Optional[OpResInfo]:
        if len(self._disabled_res_info_list) == 0:
            return None

        res_info = self._disabled_res_info_list.popleft()
        LOG.debug(f'Recheck resource {res_info}')
        self._checked_res_info_set.add(res_info)

        self._commit_stat()
        return res_info

    def _commit_stat(self) -> None:
        stat = NeonOpResStatData(
            secret_cnt=len(self._secret_list),
            total_res_cnt=len(self._res_info_set),
            free_res_cnt=len(self._free_res_info_list),
            used_res_cnt=len(self._used_res_info_dict),
            disabled_res_cnt=len(self._disabled_res_info_list)
        )
        self._stat_client.commit_op_res_stat(stat)
