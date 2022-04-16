from logged_groups import logged_group
from multiprocessing import Pool, Queue
import queue

from ..common_neon.data import NeonTxData


@logged_group("neon.MemPool")
class MemPool:

    POOL_PROC_COUNT = 3
    TX_QUEUE_TIMEOUT_SEC = 0.04
    BREAK_PROC_INVOCATION = 0

    def __init__(self):
        self._pool = None
        self._tx_queue = Queue()

    def _process_init(self):
        self._pool = Pool(processes=self.POOL_PROC_COUNT)

    def on_eth_send_raw_transaction(self, neon_tx_data: NeonTxData):
        self._tx_queue.put(neon_tx_data)

    def error_callback(self, error):
        self.error("Failed to invoke on worker process: ", error)

    def on_eth_send_raw_transaction_callback(self, result):
        self.debug(f"Processing result: {result}")

    @staticmethod
    def _on_eth_send_raw_transaction_impl(neon_tx_data: NeonTxData) -> bool:
        return True

    def do_extras(self):
        pass

    def __getstate__(self):
        self_dict = self.__dict__.copy()
        del self_dict['_pool']
        return self_dict

    def __setstate__(self, state):
        self.__dict__.update(state)

    def run(self):
        self._process_init()
        while True:
            try:
                if not self._process_queue():
                    break
            except queue.Empty:
                self.do_extras()

    def _process_queue(self) -> bool:
        neon_tx_data = self._tx_queue.get(block=True, timeout=self.TX_QUEUE_TIMEOUT_SEC)
        if neon_tx_data == self.BREAK_PROC_INVOCATION:
            return False
        self._pool.apply_async(MemPool._on_eth_send_raw_transaction_impl, (neon_tx_data, ), callback=self.on_eth_send_raw_transaction_callback, error_callback=self.error_callback)
        return True
