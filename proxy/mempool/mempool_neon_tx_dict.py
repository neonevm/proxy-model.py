import math
import time

from collections import deque
from dataclasses import dataclass
from typing import Dict, Deque, Union, Optional

from ..common_neon.errors import EthereumError
from ..common_neon.eth_proto import NeonTx
from ..common_neon.config import Config


class MPTxDict:
    @dataclass(frozen=True)
    class _Item:
        last_time: int
        neon_tx: NeonTx
        error: Optional[EthereumError]

    def __init__(self, config: Config):
        self._neon_tx_dict: Dict[str, MPTxDict._Item] = {}
        self._neon_tx_queue: Deque[MPTxDict._Item] = deque()
        self.clear_time_sec: int = config.mempool_cache_life_sec

    @staticmethod
    def _get_time() -> int:
        return math.ceil(time.time())

    def add(self, neon_tx: NeonTx, exc: Optional[BaseException]) -> None:
        if neon_tx.hex_tx_sig in self._neon_tx_dict:
            return

        now = self._get_time()
        error = EthereumError(str(exc)) if exc is not None else None

        item = MPTxDict._Item(last_time=now, neon_tx=neon_tx, error=error)
        self._neon_tx_queue.append(item)
        self._neon_tx_dict[neon_tx.hex_tx_sig] = item

    def get(self, neon_sig: str) -> Union[NeonTx, EthereumError, None]:
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
            self._neon_tx_dict.pop(item.neon_tx.hex_tx_sig, None)
