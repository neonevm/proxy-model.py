from logged_groups import logged_group
from concurrent.futures import ProcessPoolExecutor

from ..common_neon.config import IConfig

from .mempool_api import MemPoolTxRequest
from .mempool_tx_executor import MemPoolTxExecutor


@logged_group("neon.MemPool")
class MemPool:

    POOL_PROC_COUNT = 8

    def __init__(self, config: IConfig):
        self._pool = ProcessPoolExecutor(self.POOL_PROC_COUNT)
        self._tx_executor = MemPoolTxExecutor(config)

    def send_raw_transaction(self, mempool_tx_request: MemPoolTxRequest) -> bool:
        try:
           self._pool.submit(MemPool._send_raw_transaction_impl, mempool_tx_request)
        except Exception as err:
            print(f"Failed enqueue mempool_tx_request into the worker pool: {err}")
            return False
        return True

    @staticmethod
    def _send_raw_transaction_impl(mempool_tx_request: MemPoolTxRequest) -> bool:
        print(f"mempool_tx_request: {mempool_tx_request}")
        return True
