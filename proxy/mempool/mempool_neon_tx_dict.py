import math
import time

from collections import deque
from dataclasses import dataclass
from typing import Dict, Deque, Union, Optional

from ..common_neon.config import Config
from ..common_neon.errors import EthereumError
from ..common_neon.utils.neon_tx_info import NeonTxInfo


class MPTxDict:
    @dataclass(frozen=True)
    class _Item:
        last_time: int
        neon_tx: NeonTxInfo
        error: Optional[EthereumError]

    def __init__(self, config: Config):
        self._neon_tx_dict: Dict[str, MPTxDict._Item] = {}
        self._neon_tx_queue: Deque[MPTxDict._Item] = deque()
        self.clear_time_sec: int = config.mempool_cache_life_sec

    def __contains__(self, neon_sig: str) -> bool:
        return neon_sig in self._neon_tx_dict

    @staticmethod
    def _get_time() -> int:
        return math.ceil(time.time())

    def done_tx(self, neon_tx_info: NeonTxInfo, exc: Optional[BaseException]) -> None:
        if neon_tx_info.sig in self._neon_tx_dict:
            return

        now = self._get_time()
        error = EthereumError(str(exc)) if exc is not None else None

        item = MPTxDict._Item(last_time=now, neon_tx=neon_tx_info, error=error)
        self._neon_tx_queue.append(item)
        self._neon_tx_dict[neon_tx_info.sig] = item

    def get_tx(self, neon_sig: str) -> Union[NeonTxInfo, EthereumError, None]:
        item = self._neon_tx_dict.get(neon_sig, None)
        if item is None:
            return item
        if item.error is not None:
            return item.error
        return item.neon_tx

    def clear(self) -> None:
        if len(self._neon_tx_queue) == 0:
            return

        last_time = max(self._get_time() - self.clear_time_sec, 0)
        while (len(self._neon_tx_queue) > 0) and (self._neon_tx_queue[0].last_time < last_time):
            item = self._neon_tx_queue.popleft()
            self._neon_tx_dict.pop(item.neon_tx.sig, None)
