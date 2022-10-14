from typing import Dict, Deque, Union, Tuple
from collections import deque

import time
import math

from ..common_neon.errors import EthereumError
from ..common_neon.eth_proto import NeonTx


class MPTxDict:
    def __init__(self):
        self._neon_tx_dict: Dict[str, Union[NeonTx, EthereumError]] = {}
        self._neon_tx_queue: Deque[Tuple[int, str]] = deque()

    @staticmethod
    def _get_time() -> int:
        return math.ceil(time.time())

    def add(self, tx: NeonTx) -> None:
        now = self._get_time()
        self._neon_tx_queue.append(now, tx.hash_signed())

    def get(self, sig: str) -> Union[NeonTx, EthereumError, None]:
        pass
