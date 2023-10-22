from __future__ import annotations

import math
import time
import asyncio

from collections import deque
from dataclasses import dataclass
from typing import Dict, Deque, Union, Optional, Tuple, Final

from ..common_neon.config import Config
from ..common_neon.address import NeonAddress
from ..common_neon.errors import EthereumError
from ..common_neon.utils.neon_tx_info import NeonTxInfo

from .mempool_api import MPNeonTxResult, MPTxRequest


class MPTxDict:
    @dataclass(frozen=True)
    class _Item:
        last_time: int
        neon_tx: NeonTxInfo
        chain_id: int
        error: Optional[EthereumError]

    def __init__(self, config: Config):
        self._neon_tx_dict: Dict[str, MPTxDict._Item] = {}
        self._neon_tx_queue: Deque[MPTxDict._Item] = deque()
        self._clear_time_sec: Final[int] = config.mempool_cache_life_sec

    def __contains__(self, neon_sig: str) -> bool:
        return neon_sig in self._neon_tx_dict

    @staticmethod
    def _sender_nonce(tx: Union[_Item, Tuple[NeonAddress, int]]) -> str:
        if isinstance(tx, MPTxDict._Item):
            sender_addr, chain_id, tx_nonce = tx.neon_tx.addr, tx.chain_id, tx.neon_tx.nonce
        else:
            sender_addr, chain_id, tx_nonce = tx[0].address, tx[0].chain_id, tx[1]
        return f'{sender_addr}:{chain_id}:{tx_nonce}'

    @staticmethod
    def _get_time() -> int:
        return math.ceil(time.time())

    def done_tx(self, tx: MPTxRequest, exc: Optional[BaseException]) -> None:
        if tx.neon_tx_info.sig in self._neon_tx_dict:
            return

        now = self._get_time()
        error = EthereumError(str(exc)) if exc is not None else None

        item = MPTxDict._Item(last_time=now, neon_tx=tx.neon_tx_info, chain_id=tx.chain_id, error=error)
        self._neon_tx_queue.append(item)
        self._neon_tx_dict[tx.neon_tx_info.sig] = item
        self._neon_tx_dict[self._sender_nonce(item)] = item

    def get_tx_by_hash(self, neon_sig: str) -> MPNeonTxResult:
        return self._get_tx(self._neon_tx_dict.get(neon_sig, None))

    def get_tx_by_sender_nonce(self, sender_addr: NeonAddress, tx_nonce: int) -> MPNeonTxResult:
        return self._get_tx(self._neon_tx_dict.get(self._sender_nonce((sender_addr, tx_nonce)), None))

    def _get_tx(self, item: Optional[MPTxDict._Item]) -> MPNeonTxResult:
        if item is None:
            return item
        if item.error is not None:
            return item.error
        return item.neon_tx

    def clear(self) -> None:
        if len(self._neon_tx_queue) == 0:
            return

        last_time = max(self._get_time() - self._clear_time_sec, 0)
        while (len(self._neon_tx_queue) > 0) and (self._neon_tx_queue[0].last_time < last_time):
            item = self._neon_tx_queue.popleft()
            self._neon_tx_dict.pop(item.neon_tx.sig, None)
            self._neon_tx_dict.pop(self._sender_nonce(item), None)

    async def sleep(self) -> None:
        await asyncio.sleep(self._clear_time_sec)
