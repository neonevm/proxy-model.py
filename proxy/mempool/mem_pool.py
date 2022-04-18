import asyncio
import os

from logged_groups import logged_group
from concurrent.futures import ProcessPoolExecutor
import time

from ..common_neon.data import NeonTxData


@logged_group("neon.MemPool")
class MemPool:

    POOL_PROC_COUNT = 8

    def __init__(self):
        self._pool = ProcessPoolExecutor(self.POOL_PROC_COUNT)
        self._event_loop = asyncio.get_event_loop()

    def send_raw_transaction(self, neon_tx_data: NeonTxData):
        self._pool.submit(MemPool._send_raw_transaction_impl, neon_tx_data)

    @staticmethod
    def _send_raw_transaction_impl(neon_tx_data: NeonTxData) -> bool:
        pid = os.getpid()
        print(f"PID: {pid}, neon_tx_data: {neon_tx_data}")
        time.sleep(0.1)
        return True
