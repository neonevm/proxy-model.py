import asyncio
from logged_groups import logged_group
from concurrent.futures import ProcessPoolExecutor
import time

from ..common_neon.data import NeonTxData


@logged_group("neon.MemPool")
class MemPool:

    POOL_PROC_COUNT = 8

    def __init__(self):
        self._pool = None
        self._tx_queue = asyncio.Queue()
        self._pool = ProcessPoolExecutor(self.POOL_PROC_COUNT)
        self._neon_tx_futures = set()
        self._event_loop = asyncio.get_event_loop()
        self._event_loop.create_task(self.do_mempool_stuff())
        self._send_tx_futures = list()

    def on_eth_send_raw_transaction(self, neon_tx_data: NeonTxData):
        self._tx_queue.put_nowait(neon_tx_data)

    @staticmethod
    def on_eth_send_raw_transaction_impl(neon_tx_data: NeonTxData) -> bool:
        time.sleep(0.1)
        return True

    async def do_mempool_stuff(self):
        with self._pool as pool:
            while True:
                try:
                    neon_tx_data = await self._tx_queue.get()
                    pool.submit(MemPool.on_eth_send_raw_transaction_impl, neon_tx_data)
                except Exception as err:
                    print(f"Failed to submit neon tx onto the mempool worker: {err}")

